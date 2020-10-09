---
layout: page
title: pwnable.kr - echo2
file_path: echo2
category: pwnablekr
subcategory: rookiss
tags: [writeup, pwn, pwnablekr]
---


Same as echo1, except we got Format String Bug and Use-After-Free instead of BOF.

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
> 2
hello test
%x.%x
521548d0.abc46350

goodbye test

- select echo type - ...
```

Here's the vulnerable UAF function:

```c
__int64 echo3()
{
  char *s; // ST08_8

  func_array->print_hello(func_array);
  s = (char *)malloc(0x20uLL);
  get_input(s, 0x20);
  puts(s);
  free(s);
  func_array->print_goodbye(func_array, 0x20LL);
  return 0LL;
}
```

At the beginning of `main` function there is `func_array` allocation:
```c
struct struct_func_array
{
  char name[24];
  void (__fastcall *print_hello)(void *);
  void (__fastcall *print_goodbye)(void *, signed __int64);
};

func_array = malloc(0x28uLL);
func_array->print_hello = (void (__fastcall *)(void *))greetings;
func_array->print_goodbye = (void (__fastcall *)(void *, signed __int64))byebye;
printf("hey, what's your name? : ", 0LL);
__isoc99_scanf("%24s", &name);
func_array->name = name;
```

Main function loop:
```c
do {
    while ( 1 ) {
        while ( 1 ) {
            puts("\n- select echo type -");
            puts("- 1. : BOF echo");
            puts("- 2. : FSB echo");
            puts("- 3. : UAF echo");
            puts("- 4. : exit");
            printf("> ", v3);
            v3 = &v6;
            __isoc99_scanf("%d", &v6);
            getchar();
            if ( v6 > 3 )
            break;
            ((void (__fastcall *)(const char *, unsigned int *))func[v6 - 1])("%d", &v6);
        }
        if ( v6 == 4 )
        break;
        puts("invalid menu");
    }
    cleanup();
    printf("Are you sure you want to exit? (y/n)", &v6);
    v6 = getchar();
} while ( v6 != 'y' );
puts("bye");
```

```c
void cleanup()
{
  free(func_array);
}
```

To exploit UAF, we can call `cleanup` (`func_array` ptr will be freed and but into fastbin/tcache) and then `echo3` (`malloc` will return `func_ptr` and we wil overwrite pointers to `greetings` and `byebye`).

Last thing is to place shellcode somewhere (I used first 24 bytes send in `echo3`) and get address of it.

We can get the address in two ways:
* making additional malloc before `cleanup`. As `func_array` chunk will get freed, its first bytes (`func_array->name`) will be overwritten with pointer to next free chunk and we can leak that when `greetings` function will be called. It is a bit unreliable though, because heap offsets depends on libc version.
* use FMB, easily and reliably

