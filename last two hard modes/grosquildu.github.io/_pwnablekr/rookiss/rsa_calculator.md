---
layout: page
title: pwnable.kr - rsa calculator
file_path: rsa_calculator
category: pwnablekr
subcategory: rookiss
tags: [writeup, pwn, pwnablekr]
---


Checksec:
```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX disabled
PIE:      No PIE (0x400000)
RWX:      Has RWX segments
```

Running binary:
```
- Buggy RSA Calculator -


- select menu -
- 1. : set key pair
- 2. : encrypt
- 3. : decrypt
- 4. : help
- 5. : exit
> 4
- this is a buggy RSA calculator service
- to show the concept, we also provide tiny encryption service as well
- there are *multiple exploitable bugs* in this service.
- you better patch them all :)

```

Main function:
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  bool limit_reached; // dl
  int menu_input; // [rsp+Ch] [rbp-4h]

  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 1, 0LL);
  puts("- Buggy RSA Calculator -\n");
  func[0] = (__int64)set_key;
  func[1] = (__int64)RSA_encrypt;
  func[2] = (__int64)RSA_decrypt;
  func[3] = (__int64)help;
  func[4] = (__int64)myexit;
  pwnable_best = "pwnable.krisbest";
  system_func = (__int64)system;
  menu_input = 0;
  while ( 1 )
  {
    puts("\n- select menu -");
    puts("- 1. : set key pair");
    puts("- 2. : encrypt");
    puts("- 3. : decrypt");
    puts("- 4. : help");
    puts("- 5. : exit");
    printf("> ");
    __isoc99_scanf("%d", &menu_input);
    if ( (unsigned int)(menu_input + 1) > 6 )
      break;
    ((void (__fastcall *)(const char *, int *))func[menu_input - 1])("%d", &menu_input);
    limit_reached = g_try++ > 10;
    if ( limit_reached )
    {
      puts("this is demo version");
      exit(0);
    }
  }
  puts("invalid menu");
  return 0;
}
```

First bug: `menu_input` can be -1 or 0 resulting in `func` array underflow.

Set key function looks ok. It just gets key params as unsigned ints, validate them, compute some other params and save them all in global section. Only validation part is not super restrictid:
```c
if ( e < phi && d < phi && d * e % phi != 1 )
{
    puts("wrong parameters for key generation");
    exit(0);
}
```

Encryption:
```c
__int64 RSA_encrypt()
{
  __int64 result; // rax
  bool v1; // dl
  int v2; // eax
  int *v3; // [rsp+0h] [rbp-1430h]
  unsigned int data_len; // [rsp+Ch] [rbp-1424h]
  int data_counter; // [rsp+10h] [rbp-1420h]
  int i; // [rsp+14h] [rbp-141Ch]
  int v7; // [rsp+18h] [rbp-1418h]
  char one_char; // [rsp+1Fh] [rbp-1411h]
  char encrypted_result[4096]; // [rsp+20h] [rbp-1410h]
  char plaintext[1032]; // [rsp+1020h] [rbp-410h]
  unsigned __int64 cookie; // [rsp+1428h] [rbp-8h]

  cookie = __readfsqword(0x28u);
  if ( is_set )
  {
    data_len = 0;
    printf("how long is your data?(max=1024) : ");
    __isoc99_scanf("%d", &data_len);
    if ( data_len <= 0x400 )
    {
      data_counter = 0;
      fgetc(stdin);
      puts("paste your plain text data");
      while ( 1 )
      {
        if ( data_len == 0 )
          break;
        data_len--;
        v7 = fread(&one_char, 1uLL, 1uLL, stdin);
        if ( !v7 )
          exit(0);
        if ( one_char == '\n' )
          break;
        plaintext[data_counter++] = one_char;
      }
      memcpy(g_pbuf, plaintext, data_counter);
      for ( i = 0; i < data_counter; ++i )
      {
        g_ebuf[i] = encrypt(g_pbuf[i], (unsigned int *)pub);  // <--- bug1
      }
      memset(encrypted_result, 0, 0x400uLL);
      for ( i = 0; 4 * data_counter > i; ++i )   // <--- bug2
        sprintf(&encrypted_result[2 * i], "%02x", *((unsigned __int8 *)g_ebuf + i));
      puts("-encrypted result (hex encoded) -");
      puts(encrypted_result);
      result = 0LL;
    }
    else
    {
      puts("data length exceeds buffer size");
      result = 0LL;
    }
  }
  else
  {
    puts("set RSA key first");
    result = 0LL;
  }
  return result;
}
```

Variables:
* `int g_ebuf[256]` (global encryption buf)
* `char g_pbuf[1024]` (global plaintext buf)
* `int data_counter` is at most 1024

Bug1 is that `g_ebuf` will overflow (256 vs 1024). Bug2 is that `encrypted_result` will overflow (and is not fully zeroed). In general, `data_counter` should count words (4 bytes) instead of bytes. Also note that it doesn't implement real RSA, encryption is done byte-by-byte.

Decryption function:
```c
__int64 RSA_decrypt()
{
  __int64 result; // rax
  bool v1; // dl
  char *v2; // rdx
  unsigned __int8 *v3; // rsi
  char v4; // al
  int v5; // [rsp+Ch] [rbp-634h]
  int data_counter; // [rsp+10h] [rbp-630h]
  int i; // [rsp+14h] [rbp-62Ch]
  int j; // [rsp+18h] [rbp-628h]
  int v9; // [rsp+1Ch] [rbp-624h]
  char v10; // [rsp+20h] [rbp-620h]
  char v11; // [rsp+21h] [rbp-61Fh]
  char v12; // [rsp+22h] [rbp-61Eh]
  char one_char; // [rsp+2Fh] [rbp-611h]
  char ciphertext_hex[1024]; // [rsp+30h] [rbp-610h]
  char ciphertext[520]; // [rsp+430h] [rbp-210h]
  unsigned __int64 cookie; // [rsp+638h] [rbp-8h]

  cookie = __readfsqword(0x28u);
  if ( is_set )
  {
    data_len = 0;
    printf("how long is your data?(max=1024) : ");
    __isoc99_scanf("%d", &data_len);
    if ( data_len <= 1024 )
    {
      data_counter = 0;
      fgetc(stdin);
      puts("paste your hex encoded data");
      while ( 1 )
      {
        if ( data_len == 0 )
          break;
        data_len--;
        v9 = fread(&one_char, 1uLL, 1uLL, stdin);
        if ( !v9 )
          exit(0);
        if ( one_char == '\n' )
          break;
        ciphertext_hex[data_counter++] = one_char;
      }
      memset(ciphertext, 0, 512uLL);
      i = 0;
      j = 0;
      while ( 2 * data_counter > i )  // <--- Bug1
      {
        __isoc99_sscanf(&ciphertext_hex[i], "%02x", &ciphertext[j++]);
        i += 2;
      }
      memcpy(g_ebuf, ciphertext, data_counter);  // <--- Bug2
      for ( i = 0; data_counter / 8 > i; ++i )   // <--- Bug3
      {
        g_pbuf[i] = decrypt((unsigned int)g_ebuf[i], pri);
      }
      g_pbuf[i] = 0;
      puts("- decrypted result -");
      printf(g_pbuf);  // <--- Bug4
      putchar('\n');
      result = 0LL;
    }
    else
    {
      puts("data length exceeds buffer size");
      result = 0LL;
    }
  }
  else
  {
    puts("set RSA key first");
    result = 0LL;
  }
  return result;
}
```

Bugs:
* 1: in the loop with `sscanf` with "%02x": it is two-times too long.
* 2: `ciphertext` is 512 bytes long, but `memcpy` may copy up to 1024 bytes
* 3: `data_counter / 8` should be `data_counter / 4`
* 4: format string bug

We can go with bug1 in encryption function (`g_ebuf` overflow). Globals layout is:
```c
.bss:00000000006020E0 ; int g_ebuf[256]
.bss:00000000006020E0 g_ebuf          dd 100h dup(?)
.bss:00000000006020E0 
.bss:00000000006024E0                 public is_set
.bss:00000000006024E0 is_set          dd ?
.bss:00000000006024E0                  
.bss:00000000006024E4                 align 20h
.bss:0000000000602500                 public func
.bss:0000000000602500 ; __int64 func[5]
.bss:0000000000602500 func            dq 5 dup(?)
.bss:0000000000602500 
.bss:0000000000602528 ; char pwnable_best[16]
.bss:0000000000602528 pwnable_best    db 10h dup(?)
.bss:0000000000602528 
.bss:0000000000602538 system_func     dq ?
```

So we need 256 + 1 + 7 bytes of padding and then pointer to shellcode (for example). Main drawback is that the pointer have to be "encrypted". That is we need to send some x, such that pow(x, e, n) == address. For that we may use `dsks` function from CryptoAttacks (it's "Duplicate-Signature Key Selection" attack described in cryptopals set8). Another thing: program treats params as signed ints, so care should be taken not to overflow anything.

The shellcode may be placed in `g_pbuf`. As we have `system` address in global section, the shellcode just needs to set args and jump to it.

