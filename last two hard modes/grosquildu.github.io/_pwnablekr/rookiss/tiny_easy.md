---
layout: page
title: pwnable.kr - tiny easy
file_path: tiny_easy
category: pwnablekr
subcategory: rookiss
tags: [writeup, pwn, pwnablekr]
---


Checksec:
```
Arch:     i386-32-little
RELRO:    No RELRO
Stack:    No canary found
NX:       NX disabled
PIE:      No PIE (0x8048000)
```

The binary is, surprisingly, tiny:
```asm
08048054  58        POP EAX
08048055  5a        POP EDX
08048056  8b 12     MOV EDX,dword ptr [EDX]
08048058  ff d2     CALL EDX
```

Also, this is a local privilege escalation challenge.

What is one the stack in such a tiny program?

```asm
00:0000│ esp  0xffff9c20 ◂— 0x3
01:0004│      0xffff9c24 —▸ 0xffff9ebe ◂— 0x6d6f682f ('/hom')
02:0008│      0xffff9c28 —▸ 0xffff9f08 ◂— 0x41414141 ('AAAA')
03:000c│      0xffff9c2c —▸ 0xffff9f0d ◂— 0x42424242 ('BBBB')
04:0010│      0xffff9c30 ◂— 0x0
05:0014│      0xffff9c34 —▸ 0xffff9f12 ◂— 0x5f474458 ('XDG_')
```

So, there is argc, then argv, then zero (end of argv), then env.
Since it's a local task, we can controll all of these.

What we may do is:
  * place shellcode in env (with nopesleed)
  * put some stack adress in argv[0]. If we hit correct address, we will jump somewhere into nopesleed and the shellcode will execute

Easy, we just need to bruteforce 3 bytes.

