---
layout: page
title: pwnable.kr - echo1
file_path: echo1
category: pwnablekr
subcategory: rookiss
tags: [writeup, pwn, pwnablekr]
---


Checksec:
```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX disabled
PIE:      No PIE (0x400000)
RWX:      Has RWX segments
```

Running binary:
```
hey, what's your name? : test

- select echo type -
- 1. : BOF echo
- 2. : FSB echo
- 3. : UAF echo
- 4. : exit
> 1
hello test
some_input
some_input

goodbye test

- select echo type - ...
```

We give name and then there is menu with only first option working - Buffer OverFlow.

First 4-th bytes of the name lands at constant address `0x6020a0 <id>`.

The code of "BOF echo":
```c
__int64 echo1()
{
  char s[32]; // [rsp+0h] [rbp-20h]

  func_array->print_hello(func_array);
  get_input(s, 0x80);
  puts(s);
  func_array->print_goodbye(func_array, 0x80);
  return 0LL;
}
```

As there are no security contermeasures the challenge is straight-forward:

* as the name give an asm code that will jump to a shellcode (`jmp rsp`)
* in echo1 function overwrite RIP with `<id>` address (first bytes of the name - they are executable)
* `jmp rsp` will execute
* at RSP there will be input we gave in `get_input`
* so we give the shellcode there

