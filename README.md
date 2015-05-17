# tunet-unix
C implementation of Win32 TUNet protocol that works on Unix-like systems

Needs OpenSSL (for MD5 calculation). Normally, your system 
already contains it.

I have tested it on OS X Yosemite (10.10.3) and Arch Linux (4.0.2-1-ARCH).

If you want to include tunet-unix in your project, add `tunet.h` and 
`tunet.c` to your project. See `tunet.h` for available functions.

### Usage
~~~Shell
make
cd build
./tunet login jzp13
./tunet usage
~~~
