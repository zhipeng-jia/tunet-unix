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

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include "tunet.h"

void bytes_to_human_string(int64_t bytes, char* dest)
{
    if (bytes < 1024)
        sprintf(dest, "%d bytes", (int)bytes);
    else if ((bytes >> 10) < 1024)
        sprintf(dest, "%.2lf KiB", (double)bytes / 1024);
    else if ((bytes >> 20) < 1024)
        sprintf(dest, "%.2lf MiB", (double)bytes / 1024 / 1024);
    else
        sprintf(dest, "%.2lf GiB", (double)bytes / 1024 / 1024 / 1024);
}

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        printf("Usage: %s <command> [argument]\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "login") == 0)
    {
        if (argc < 3)
        {
            printf("Please provide user name!\n");
            return -1;
        }
        char prompt[31];
        sprintf(prompt, "Enter password for %s: ", argv[2]);
        char* passwd = getpass(prompt);
        int ret = login(argv[2], passwd);
        if (ret == 1)
            printf("Incorrect password!\n");
        else if (ret == -1)
            printf("Login failed. Please try again later.\n");
        else
            printf("Login successful!\n");
    }
    else if (strcmp(argv[1], "query") == 0)
    {
        int64_t month_usage;
        int64_t current_in;
        int64_t current_out;
        if (query(&month_usage, &current_in, &current_out) == -1)
        {
            printf("Query failed. Please try again later.\n");
        }
        else
        {
            char buf[31];
            bytes_to_human_string(month_usage, buf);
            printf("Month usage: %s\n", buf);
            bytes_to_human_string(current_in, buf);
            printf("Current in: %s\n", buf);
            bytes_to_human_string(current_out, buf);
            printf("Current out: %s\n", buf);
        }
    }

    return 0;
}
