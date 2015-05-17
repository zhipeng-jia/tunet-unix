/*
The MIT License (MIT)

Copyright (c) 2015 Zhipeng Jia

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include "tunet.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/md5.h>

struct challenge_request
{
    int64_t type;      
    int64_t user_id;
    char    user_name[40];
};

struct challenge_response
{
    int64_t       type;
    int64_t       user_id;
    unsigned char challenge[16];
    char          padding[16];
};

int udp_request(const char* host_ip, int port, void* request, size_t request_len, void* response_buffer, size_t buffer_len)
{
    int s;
    if ((s = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
        return -1;
    
    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_addr.s_addr = inet_addr(host_ip);
    to.sin_family = AF_INET;
    to.sin_port = htons(port);

    if (connect(s, (struct sockaddr*)&to, sizeof(to)) == -1)
        return -1;

    if (send(s, request, request_len, 0) == -1)
        return -1;

    int res_len;
    if ((res_len = recv(s, response_buffer, buffer_len, 0)) == -1)
        return -1;

    close(s);
    return res_len;
}

#define MAX_HTTP_HEADER_ENTRY_LEN 150
#define BUFFER_LEN 10000

struct http_header_entry
{
    char header[MAX_HTTP_HEADER_ENTRY_LEN + 1];
    char content[MAX_HTTP_HEADER_ENTRY_LEN + 1];
};

int http_request(const char* host_ip, int port, const char* method, const char* path,
                 const struct http_header_entry* request_header, size_t request_header_len,
                 void* request_body, size_t request_body_len,
                 struct http_header_entry* response_header, size_t* response_header_len, size_t response_header_max_len,
                 void* response_body, size_t* response_body_len, size_t response_body_max_len)
{
    int s;
    if ((s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
        return -1;
    
    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_addr.s_addr = inet_addr(host_ip);
    to.sin_family = AF_INET;
    to.sin_port = htons(port);

    if (connect(s, (struct sockaddr*)&to, sizeof(to)) == -1)
        return -1;

    char* buffer = (char*)malloc(BUFFER_LEN);
    char* current_pos = buffer;
    int write_count;

    write_count = sprintf(current_pos, "%s %s HTTP/1.0\r\n", method, path);
    if (write_count < 0)
    {
        free(buffer);
        return -1;
    }
    current_pos += write_count;

    int i;
    for (i = 0; i < request_header_len; i ++)
    {
        write_count = sprintf(current_pos, "%s: %s\r\n", request_header[i].header, request_header[i].content);
        if (write_count < 0)
        {
            free(buffer);
            return -1;
        }
        current_pos += write_count;
    }

    write_count = sprintf(current_pos, "\r\n");
    if (write_count < 0)
    {
        free(buffer);
        return -1;
    }
    current_pos += write_count;

    if (request_body_len > 0)
        memcpy(current_pos, request_body, request_body_len);

    size_t request_len = current_pos - buffer + request_body_len;
    if (send(s, buffer, request_len, 0) == -1)
    {
        free(buffer);
        return -1;
    }

    int res_len = 0;
    while (1)
    {
        int ret = recv(s, buffer + res_len, BUFFER_LEN - res_len, 0);
        if (ret == 0)
            break;
        if (ret == -1)
        {
            free(buffer);
            return -1;
        }
        res_len += ret;
        if (res_len == BUFFER_LEN)
        {
            free(buffer);
            return -1;
        }
    }

    current_pos = buffer;
    int first = 1;
    int code;
    *response_header_len = 0;
    while (1)
    {
        char* eof = strstr(current_pos, "\r\n");
        char* line = (char*)malloc(eof - current_pos + 1);
        strncpy(line, current_pos, eof - current_pos);
        line[eof - current_pos] = '\0';
        current_pos = eof + 2;

        if (first)
        {
            char tmp[11];
            sscanf(line, "%s%d", tmp, &code);
            first = 0;
        }
        else
        {
            if (strlen(line) == 0)
            {
                free(line);
                break;
            }

            if (*response_header_len == response_header_max_len)
            {
                free(line);
                free(buffer);
                return -1;
            }
            struct http_header_entry* entry = response_header + *response_header_len;
            *response_header_len += 1;
            memset(entry, 0, sizeof(struct http_header_entry));

            char* colon = strstr(line, ": ");
            if (colon - line > MAX_HTTP_HEADER_ENTRY_LEN || strlen(colon + 2) > MAX_HTTP_HEADER_ENTRY_LEN)
            {
                free(line);
                free(buffer);
                return -1;
            }
            strncpy(entry->header, line, colon - line);
            strcpy(entry->content, colon + 2);
        }

        free(line);
    }

    *response_body_len = res_len - (current_pos - buffer);

    if (*response_body_len > response_body_max_len)
    {
        free(buffer);
        return -1;
    }
    memcpy(response_body, current_pos, *response_body_len);

    free(buffer);
    return code;
}

int acquire_challenge(const char* user_name, struct challenge_response* response)
{
    struct challenge_request req;
    memset(&req, 0, sizeof(req));
    req.type = -100;
    req.user_id = -1;
    strcpy(req.user_name, user_name);

    char buffer[100];
    int res_len;
    if ((res_len = udp_request("166.111.8.120", 3335, &req, sizeof(req), buffer, sizeof(buffer))) == -1)
        return -1;
    if (res_len != sizeof(struct challenge_response))
        return -1;

    memcpy(response, buffer, sizeof(struct challenge_response));
    if (response->type != -101)
        return -1;

    return 0;
}

void hex_md5(const unsigned char* source, int len, char* dest)
{
    unsigned char buffer[16];
    MD5(source, len, buffer);
    int i;
    for (i = 0; i < 16; i ++)
        sprintf(dest + i * 2, "%02x", buffer[i]);
}

int64_t parse_int64t(const char* source, char end_char)
{
    int64_t ret = 0;
    while (*source != end_char)
    {
        ret = ret * 10 + (*source - '0');
        source ++;
    }
    return ret;
}

int login(const char* user_name, const char* password)
{
    struct challenge_response res;

    if (acquire_challenge(user_name, &res) == -1)
        return -1;

    unsigned char buffer[49];
    buffer[0] = (unsigned char)(res.user_id & 255);
    hex_md5((unsigned char*)password, strlen(password), (char*)buffer + 1);
    memcpy(buffer + 33, res.challenge, 16);
    char password_md5[33];
    hex_md5(buffer, 49, password_md5);
    password_md5[32] = '\0';

    char req_body[100];
    size_t req_body_len;
    req_body_len = sprintf(req_body, "username=%s&password=%s&chap=1", user_name, password_md5);

    struct http_header_entry res_header[20];
    size_t res_header_len;
    char res_buffer[1000];
    size_t size;

    struct http_header_entry req_header[3] = {
        { "Host", "166.111.8.120:3333" },
        { "Content-Type", "application/x-www-form-urlencoded" },
        { "Content-Length", "" }
    };
    sprintf(req_header[2].content, "%d", (int)req_body_len);

    int code;
    if ((code = http_request("166.111.8.120", 3333, "POST", "/cgi-bin/do_login",
                             req_header, 3, req_body, req_body_len,
                             res_header, &res_header_len, 20, res_buffer, &size, 1000)) == -1)
        return -1;

    res_buffer[size] = '\0';

    if (strcmp(res_buffer, "password_error") == 0)
        return 1;

    if (!('0' <= res_buffer[0] && res_buffer[0] <= '9'))
        return -1;

    return 0;
}

int check_online(int64_t* login_id, int64_t* usage)
{
    char req_body[100];
    size_t req_body_len;
    req_body_len = sprintf(req_body, "action=check_online");

    struct http_header_entry res_header[20];
    size_t res_header_len;
    char res_buffer[1000];
    size_t size;

    struct http_header_entry req_header[3] = {
        { "Host", "166.111.8.120:3333" },
        { "Content-Type", "application/x-www-form-urlencoded" },
        { "Content-Length", "" }
    };
    sprintf(req_header[2].content, "%d", (int)req_body_len);

    int code;
    if ((code = http_request("166.111.8.120", 3333, "POST", "/cgi-bin/do_login",
                             req_header, 3, req_body, req_body_len,
                             res_header, &res_header_len, 20, res_buffer, &size, 1000)) == -1)
        return -1;

    res_buffer[size] = '\0';
    if (strlen(res_buffer) == 0)
        return -1;

    if (login_id != NULL)
        *login_id = parse_int64t(res_buffer, ',');
    char* next = strstr(res_buffer, ",");
    next = strstr(next + 1, ",");
    if (usage != NULL)
        *usage = parse_int64t(next + 1, ',');

    return 0;
}

struct query_request
{
    int64_t uid4;
    int64_t uid6;
    char    padding[40];
};

struct query_response
{
    int64_t uid4;
    int64_t uid6;
    int64_t balance_in;
    int64_t balance_out;
    int64_t free_in;
    int64_t free_out;
};

int query_usage(int64_t* month_usage, int64_t* current_in, int64_t* current_out)
{
    int64_t login_id;
    if (check_online(&login_id, month_usage) == -1)
        return -1;

    struct query_request req;
    memset(&req, 0, sizeof(req));
    req.uid4 = login_id;
    req.uid6 = ((int64_t)1 << 32) - 1;

    char buffer[100];
    int res_len;
    if ((res_len = udp_request("166.111.8.120", 3335, &req, sizeof(req), buffer, sizeof(buffer))) == -1)
        return -1;
    if (res_len != sizeof(struct query_response))
        return -1;

    struct query_response res;
    memcpy(&res, buffer, sizeof(struct query_response));

    if (current_in != NULL)
        *current_in = res.balance_in;
    if (current_out != NULL)
        *current_out = res.balance_out;

    return 0;
}
