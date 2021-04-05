## Given Code:
```c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

char *f1(char *src)
{
    uint8_t len = strlen(src) + 1;
    char *dst = (char *)malloc(len * sizeof(char));
    memcpy(++dst, src, strlen(src)); 
    // str[strlen(src)] = '\0'; // a mistake i guess
    dst[strlen(src)] = '\0';
    return dst;
}

int f2(char *a)
{
    if (!a)
        return 0;
  
    if (a[0] == 'H' && a[1] == 'e')
        return 1;

    free(a);     
	return 0;
}

int main(int argc, const char *argv[]){
    char *copy = f1(argv[1])

    // ...snipped...
    f2(copy);
    memcpy(copy,argv[2],1);
    // ...snipped...
    free(copy);
    // ...snipped...
    return 0;
}
```

## Lets inspect the bugs first:

### **f1()**:

------------

```c 
uint8_t len = strlen(src) + 1;`
```
- Only input string `(argv[1])` with length<256 (2^8) will give an expected behaviour - Otherwise we will have **integer overflow**

- Also - This might be confusing later because it takes in account space for the '\0' too

>This would mainly affect the next line:

```c 
char *dst = (char *)malloc(len * sizeof(char));
```

in the case mentioned above (**int overflow**), we will ask for and manage less dynamic space than what we will attemp to write to in the **following line**:

```c 
memcpy(++dst, src, strlen(src));
```
- dst[0] will stay a garbage value (might be NULL)
This will affect whoever uses the return value -dst pointer,
we can only call free on the addr returned from malloc (original dst)
otherwise- we will get runtime error when trying to free

- 3rd arg should be len. 
  Because in the case mentioned above of overflow we will write  to the heap more data than what we requested in malloc 
  
  **Effect** : Heap corruption (So we can basically inject to the heap whatever we would like.

```c
 dst[strlen(src)] = '\0'
```
BUG: It simply doesn't place the NULL char where expected due to 
modifying local var **dst** (++dst) in the previous line (a +1 offset)

------------

### **f2()**:

------------
```c
if (a[0] == 'H' && a[1] == 'e')
```
Possible BUG: Not checking strlen(a):

 ```c 
 free(a);
 return 0;
 ```

 - we won't be able to know if a was freed or not because we use the same return value (0) for two different cases 
- This will result in a **double free** later in **main()** (**Undefined behaviour**)
------------
## Main():
```c
memcpy(copy,argv[2],1);
```
copy might have been freed in the previous call to f2()  
Which might result in runtime error (It's a  **"Use after free"**)

------------

## One possible fix for the Code :
```c
#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX_LEN 255

char* f1(char* src)
{
    uint8_t len = MIN(strlen(src), MAX_LEN);
    char* dst = (char*)malloc((len + 1) * sizeof(char));
    if (!dst)
        exit(-1);

    memcpy(dst, src, len); 
    dst[len] = '\0'; 
    return dst;
}

int f2(char* a)
{
    if (!a)
        return 0;

    if (strlen(a) > 2)
        if (a[0] == 'H' && a[1] == 'e')
            return 1;

    return 0; 
}

int main(int argc, const char* argv[]) {
    if (argc < 3)
        exit(-1);

    char* copy = f1(argv[1]);
    // ...snipped...
    if(!copy)
    	exit(-1); //add perror or use errno
	
    f2(copy);
    memcpy(copy, argv[2], 1); 
    // ...snipped...
    free(copy); 
    // ...snipped...
    return 0;
}
```
------
## Vulnerablities and Exploits : TBC
Basically we would like to accomplish one of the following:
**Depending on the mitigations enabled and the rest of the snipped code**
- Manipulate the code execution flow to our injected code/shellcode  
(Here the user can only play with the heap content.  
overriding return addresses on the stack seems to be not possible here. 
Maybe we can also manipulate records in the GOT/PLT.
- Look for places in the rest of code for system calls like system()/excev()
- Possible UAF (If after freeing a memory location, a program does not clear the pointer to that memory,
  an attacker can use the error to hack the program.)
