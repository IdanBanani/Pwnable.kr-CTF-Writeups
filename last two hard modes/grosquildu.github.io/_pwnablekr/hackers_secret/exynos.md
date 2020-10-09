---
layout: page
title: pwnable.kr - exynos
file_path: exynos
category: pwnablekr
subcategory: hackers_secret
tags: [writeup, pwn, pwnablekr]
---

We have access to QEMU box with ARM cpu and setuid binary - `exynos-mem`.

Only one function inside the binary:
```c
int main(int argc, char const *argv[])
{
    if(argc < 4) {
        printf("usage : exynos-mem [phyaddr] [bytesize] [mode(R/W-0/1)]\n");
        return 0;
    }

    int devmem_fd = open("/dev/mem", 2);

    int phyaddr = atoi(argv[1]);
    int bytesize = atoi(argv[]);
    int mode = atoi(argv[3]);

    lseek(devmem_fd, phyaddr, 0);

    char *buf = malloc(bytesize);
    int result = 0;

    if(mode == 0) {
        read(devmem_fd, buf, bytesize);
        result = write(1, buf, bytesize);
    } else {
        if(mode == 1) {
            read(0, buf, bytesize);
            result = write(devmem_fd, buf, bytesize);
        } else {
            fwrite("wrong mode. 0:read, 1:write\n", 1, 0x1c);
        }
    }

    fprintf(stderr, "processed %d bytes\n", result);

    return 0;
}
```

It allows us to read/write to special `/dev/mem` file, that is to access physical memory.

Searching for `exynos exploit` quickly yields [xda-developers](https://forum.xda-developers.com/showthread.php?t=2048511) site with exploit for samsung phones which suffered from exactly the same vuln as we have here - the kernel memory was readable and writable via `/dev/exynos-mem` device.

There is an exploit code provided in C, but because it's time consuming to write cross-process communication in C, I decided to repeat all exploit steps in the shell.

