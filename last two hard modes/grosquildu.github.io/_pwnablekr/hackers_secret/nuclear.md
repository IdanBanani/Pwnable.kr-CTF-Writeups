---
layout: page
title: pwnable.kr - nuclear
file_path: nuclear
category: pwnablekr
subcategory: hackers_secret
tags: [writeup, pwn, pwnablekr]
---

### Overwiew

Checksec:
```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

Running binary:
```sh
- select menu -
- 1. : help
- 2. : nuke
- 3. : exit
> 1
ayudame!

- select menu -
- 1. : help
- 2. : nuke
- 3. : exit
> 2
give me an URL! : localhost
launch nuke for localhost
PING 127.0.0.1 (127.0.0.1): 56 data bytes
64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0,073 ms
--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 packets received, 0% packet loss
round-trip min/avg/max/stddev = 0,073/0,073/0,073/0,000 ms
PING 127.0.0.1 (127.0.0.1): 56 data bytes
64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0,052 ms
--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 packets received, 0% packet loss
round-trip min/avg/max/stddev = 0,052/0,052/0,052/0,000 ms

- select menu -
- 1. : help
- 2. : nuke
- 3. : exit
> 3
are you sure you want to exit?(y/n)nope
good choice. don\'t give up and pwn this

- select menu -
- 1. : help
- 2. : nuke
- 3. : exit
> 3
are you sure you want to exit?(y/n)y
bye
```

Two main features are:
* nuking hosts. We can `ping` sites.
* exiting. We can exit. We can also not exit.

Lets decompile the binary.

Main:
```c
int main() {
    int menu_input;
    int i;
    char url [257];
    long cookie;

    ...

    g_buf = malloc(0x404);
    g_buf2 = (undefined8 *)malloc(1000);

    ...

    func_array = (code **)malloc(0x18);
    func_array[0] = help;
    func_array[1] = nuke;
    func_array[2] = bye;
    free(g_buf2);
    menu_input = 0;
    i = 0;
    do {
        puts("\n- select menu -");
        puts("- 1. : help");
        puts("- 2. : nuke");
        puts("- 3. : exit");
        printf("> ");
        __isoc99_scanf("%d",&menu_input);
        getchar();
        if (menu_input == 2) {
            memset(url, 0, 0x100);
            printf("give me an URL! : ");
            __isoc99_scanf("%2048s",url);
            (*func_array[1])(url);
        }
        else if (menu_input == 3) {
            (*func_array[2])();
        } else if (menu_input == 1) {
            (*func_array[0])();
        } else {
            puts("invalid menu");
        }
    } while (i++ < 0xb);
}
```

There are two global pointers to malloced memory (later used in `nuke` function) and an array with pointers to functions. So the heap setup is:
```c
0x603000 PREV_INUSE {  -> g_buf
  prev_size = 0, 
  size = 1041, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x603410 PREV_INUSE {  -> g_buf2 (freed)
  prev_size = 0, 
  size = 1009, 
  fd = 0x7ffff7dd3f38 <main_arena+1080>, 
  bk = 0x7ffff7dd3f38 <main_arena+1080>, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x603800 {             -> func_array
  prev_size = 1008, 
  size = 32, 
  fd = 0x4009b4 <help>, 
  bk = 0x400a5b <nuke>, 
  fd_nextsize = 0x4009c9 <bye>, 
  bk_nextsize = 0x411
}
0x603820 PREV_INUSE {  -> top chunk
  prev_size = 4196809, 
  size = 133089, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
```

Theres also buffer overflow on call to `scanf` with `url`, but not exploitable because of presence of stack canary.

Bye function:
```c
void bye(void) {
    char *confirmation;

    printf("are you sure you want to exit?(y/n)");
    confirmation = (char *)malloc(0x3000);
    __isoc99_scanf("%3000s", confirmation);
    if (strncmp(confirmation, "y", 1) == 0) {
        puts("bye");
        exit(0);
    }
    puts("good choice. don\'t give up and pwn this");
    return 0;
}
```

No bugs here, but the function allows us to malloc large chunks and write to them.

Nuke function:
```c
void nuke(char *url) {
    char *pcVar2;
    hostent ret;
    hostent *result;
    int h_errnop;
    char cmd[17];
    long cookie;

    ...

    gethostbyname_r(url, &ret, g_buf, 0x404, &result, &h_errnop);
    if (result == (hostent *)0x0) {
        puts("invalid url");
        pcVar2 = (char *)0x0;
    }
    else {
        printf("launch nuke for %s\n", result->h_name);
        while (pcVar2 = *result->h_addr_list, pcVar2 != (char *)0x0) {
          addr = *(undefined8 *)*result->h_addr_list;
          memset(cmd, 0, 0x10);
          pcVar2 = inet_ntoa(SUB84(addr,0));
          sprintf((char *)cmd, "ping -w 1 -c 1 %s\n", pcVar2);
          system((char *)cmd);
          result->h_addr_list++;
        }
    }
    ...
}
```

The `gethostbyname_r` with our input is the most important part here. Then there is only ip to string conversion and `ping` execution with `system` (no command injection here as far as I know). Why `gethostbyname_r` is important? Lets check provided libc version:

```sh
➜ ./libc.nuclear.so 
GNU C Library (Ubuntu EGLIBC 2.15-0ubuntu10.5) stable release version 2.15, by Roland McGrath et al.
Copyright (C) 2012 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.
Compiled by GNU CC version 4.6.3.
Compiled on a Linux 3.2.50 system on 2013-09-30.
```

Pretty old. An vulnerable to [CVE-2015-0235](https://www.qualys.com/2015/01/27/cve-2015-0235/GHOST-CVE-2015-0235.txt) (so called GHOST).

### Environment

Before we go into exploitation, some stuff needs to be done. Firstly, provided libc is libc.so.5. On modern systems it is libc.so.6. We have to patch the binary so we can use LD_PRELOAD.

Secondly, correct ld.so have to be used. That means running the binary like (nuclear_libc6 is the patched binary):
```sh
LD_PRELOAD=./libc.nuclear.so ./ld.nuclear.so ./nuclear_libc6
```

Alternatively we could make another patch in the binary, changing `/lib64/ld-linux-x86-64.so.2` to `./ld.nuclear.so`.

For heap debugging it is useful to compile libc with debug symbols. Since the libc is old some changes to `configure` script were needed (allowing newer make and gcc version to be used).

Now everything should works and should be debugable. Except the fact that calls to `system` crashes. But thats not really important for exploit development.

### Exploitation

The bug is well described in the advisory linked. tldr; it allows us to write past the `g_buf` (this is some temporary buffer used internally by gethostbyname_r) with 4 (or 8) bytes. Looking at the heap layout, that means we can overwrite `g_buf2->size` field.

Where do we go from here?

