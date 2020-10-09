---
layout: page
title: pwnable.kr - loveletter
file_path: loveletter
category: pwnablekr
subcategory: rookiss
tags: [writeup, pwn, pwnablekr]
---


Simple binary with invalid string manipulation.

Checksec:
```
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
```

Running binary:
```
./loveletter » ./loveletter
♥ My lover'buf name is : gros
♥ Whatever happens, I'll protect her...
♥ Impress her upon my memory...
♥ Her name echos in my mind...
I love gros very much!
```

Reversing the app shows that the last line of output is printed via call to `system` with argument like `"echo I love " + user_input + " very much!"`.

```c
int main(int argc, const char **argv, const char **envp)
{
  char buf[256]; // [esp+10h] [ebp-114h]
  size_t prolog_size; // [esp+110h] [ebp-14h]
  size_t epilog_size; // [esp+114h] [ebp-10h]
  size_t input_size; // [esp+118h] [ebp-Ch]
  unsigned int cookie; // [esp+11Ch] [ebp-8h]

  cookie = __readgsdword(0x14u);

  memset(loveletter, 0, 0x100u);
  epilog_size = strlen(epilog);
  prolog_size = strlen(prolog);
  printf("♥ My lover'buf name is : ");

  fgets(buf, 256, stdin);
  if ( buf[strlen(buf) - 1] == '\n' )
    buf[strlen(buf) - 1] = '\0';

  puts("♥ Whatever happens, I'll protect her...");
  protect(buf);
  input_size = strlen(buf);

  puts("♥ Impress her upon my memory...");
  memcpy(loveletter + idx, prolog, prolog_size);
  idx += prolog_size;
  memcpy(loveletter + idx, buf, input_size);
  idx += input_size;
  memcpy(loveletter + idx, epilog, epilog_size);
  idx += epilog_size;

  puts("♥ Her name echos in my mind...");
  system(loveletter);
  return __readgsdword(0x14u) ^ cookie;
}
```

Nothing bad here. Lets check `protect` function.

```c
unsigned int protect(const char *name)
{
  size_t v1; // ebx
  size_t v2; // eax
  size_t i; // [esp+1Ch] [ebp-12Ch]
  size_t j; // [esp+20h] [ebp-128h]
  char bad_chars[23]; // [esp+25h] [ebp-123h]
  char dest[256]; // [esp+3Ch] [ebp-10Ch]
  unsigned int cookie; // [esp+13Ch] [ebp-Ch]

  cookie = __readgsdword(0x14u);
  strcpy(bad_chars, "#&;`'\"|*?~<>^()[]{}$\\,");
  for ( i = 0; i < strlen(name); ++i )
  {
    for ( j = 0; j < strlen(bad_chars); ++j )
    {
      if ( name[i] == bad_chars[j] )
      {
        strcpy(dest, &name[i + 1]);
        *(_DWORD *)&name[i] = 0xA599E2;
        v1 = strlen(dest);
        v2 = strlen(name);
        memcpy((void *)&name[v2], dest, v1);
      }
    }
  }
  return __readgsdword(0x14u) ^ cookie;
}
```

Now, here we have the bug.

