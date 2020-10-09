---
layout: page
title: pwnable.kr - syscall
file_path: syscall
category: pwnablekr
subcategory: rookiss
tags: [writeup, pwn, pwnablekr]
---

Kernel exploitation task.

Memory layout is (from dmesg):
```
Memory: 57292K/112640K available (3579K kernel code, 166K rwdata, 1020K rodata, 203K init, 138K bss, 55348K reserved)
Virtual kernel memory layout:
    vector  : 0xffff0000 - 0xffff1000   (   4 kB)
    fixmap  : 0xfff00000 - 0xfffe0000   ( 896 kB)
    vmalloc : 0x87000000 - 0xff000000   (1920 MB)
    lowmem  : 0x80000000 - 0x86e00000   ( 110 MB)
    modules : 0x7f000000 - 0x80000000   (  16 MB)
      .text : 0x80008000 - 0x80485f40   (4600 kB)
      .init : 0x80486000 - 0x804b8c80   ( 204 kB)
      .data : 0x804ba000 - 0x804e3b20   ( 167 kB)
       .bss : 0x804e3b20 - 0x805065d0   ( 139 kB)
```

Some important symbols:
```
/ $ cat /proc/kallsyms | grep commit_creds
8003f56c T commit_creds
/ $ cat /proc/kallsyms | grep prepare_creds
8003f44c T prepare_creds
```

The vulnerability is in a custom kernel module (`m.ko`). The module adds a new syscall which allows us to convert letters to uppercase equivalent. That gives us an obvious write-what-where primitive inside the kernel. 

The only limitation concerns payload content (`what` part). It may not contains nullbytes nor lowercase letters.

So the plan is to first write small shellcode that allows us to bypass the restriction (`write_what_where` variable in the exploit code). We can write it to arbitrary location (address) that won't break the kernel and then overwrite the new syscall (`sys_upper`) function pointer (SYS_CALL_TABLE+NR_SYS_UNUSED) with the shellcode.

Then we repeat the process, but with a shellcode that will prepare and commit creds giving us the root.

