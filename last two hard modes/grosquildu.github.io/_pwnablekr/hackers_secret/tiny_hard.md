---
layout: page
title: pwnable.kr - tiny hard
file_path: tiny_hard
category: pwnablekr
subcategory: hackers_secret
tags: [writeup, pwn, pwnablekr]
---


Checksec:
```
Arch:     i386-32-little
RELRO:    No RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
```

Almost the same code as in [tiny](/pwnablekr/hackers_secret/tiny/) task.
```asm
0x8048074  58                   pop    eax
0x8048075  5a                   pop    edx
0x8048076  8b 12                mov    edx,DWORD PTR [edx]
0x8048078  81 ec 00 10 00 00    sub    esp,0x1000
0x804807e  ff d2                call   edx
```

We can't easily use stack here (because of `sub esp,0x1000`).