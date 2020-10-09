---
layout: page
title: pwnable.kr - tiny
file_path: tiny
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

Same code as in [tiny easy](/pwnablekr/rookiss/tiny_easy/) task.
```asm
08048074  58        POP EAX
08048075  5a        POP EDX
08048076  8b 12     MOV EDX,dword ptr [EDX]
08048078  ff d2     CALL EDX
0804807a  00 00     ADD byte ptr [EAX],AL
```

Just this time there is NX bit, so shellcode in the stack won't do the job. 

At the beginning let me note that the solutions presented here may no longer works - it strongly depends on kernel version. However adding a bit of bruteforcing to the exploit below may works (or may not ;) ).

There are two tricks we may use:
  * [ulimit](https://www.exploit-db.com/exploits/39669)
  * vdso memory page for gadgets

The ulimit is a system command to check and set user limits. In older systems setting stack limit to "unlimited" resulted in stabilization of addresses (stack, vdso and other memory pages were allocated at constant addresses). That effectively means ASLR bypass.

Note that currently pwnable.kr system is patched, so the trick with ulimit won't work. Binary may be exploited the same way as `tiny_hard` however.

Assuming the system is old, the ASLR is bypassed and we may use code from vdso section.

At `__vdso_clock_gettime+88` there are some popping gadgets:
```
0x555575c8 <__vdso_clock_gettime+88>:   add    esp,0x3c
0x555575cb <__vdso_clock_gettime+91>:   pop    ebx
0x555575cc <__vdso_clock_gettime+92>:   pop    esi
0x555575cd <__vdso_clock_gettime+93>:   pop    edi
0x555575ce <__vdso_clock_gettime+94>:   pop    ebp
0x555575cf <__vdso_clock_gettime+95>:   ret 
```

Also on the stack there already is a pointer to `__kernel_vsyscall` which do some pushing and then executes `sysenter`.

So if we set the stack correctly, we can setup registers (and therefore arguments) as we want and jump to the `sysenter`. Setting `eax` register (`sysenter` index - what syscall we will call) can be done by creating argv array of desired size - the size will be popped into eax in the binary.

