---
layout: page
title: pwnable.kr - combabo calculator
file_path: combabo_calculator
category: pwnablekr
subcategory: hackers_secret
tags: [writeup, pwn, pwnablekr]
---


### Overwiew

Checksec:
```
Arch:     i386-32-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
FORTIFY:  Enabled
```

readme:
```
connect to port 9030 (nc 0 9030). the 'combabo_calculator' binary will be executed under combabo_calculator_pwn privilege.
pwn it and get a shell and read the flag.
* binary is not provided for this challenge (source code, Makefile is provided instead).
* this challenge uses the given 'combabo.so.6' as LIBC (this is libc-dependant challenge)
* challenge author: hdarwin (hdarwin89@gmail.com)
```

We are given full source code (C++), makefile and libc.
As we can see, binary will be compiled for 32 bits architectures and will have all protections enabled.

Libc version is 2.23 and that means its pretty old (every heap exploitation technique should works).

The binary provides simple interactive shell/calculator:
```c
combabo calculator
>>> 1+1
2
>>> a = 2*2+5
9
>>> a
9
>>> a + 123
132
>>> b = "tttt"
tttt
>>> c = "yyyy"
yyyy
>>> b = c
yyyy
>>> b
yyyy
>>>
>>> a = 500
does not support integer bigger than 256
>>> b = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
does not support string longer than 256
>>> 
```

It implements simple arithmetic (+, -, *, /, brackets), strings and variables assignments.

Program's main loop looks like this:
```cpp
shared_ptr<Lexer>lexer(new Lexer(input));
shared_ptr<Parser>parser(new Parser(lexer));
shared_ptr<Calc>calc(new Calc());
calc->interpret(parser->parse());
```

Pretty standard interpreter code.

Lexer parses one line of input at the time and tokenizes it. Tokens struct is:
```cpp
enum struct T:char { END, INT, PLUS, MINUS, MUL, DIV, LP, RP, ID, ASSIGN, EXIT, UPLUS, STR, UMINUS };

typedef struct Token {
    char* checksum;
    char* str;
    union {
        int size;
        int value;
    };
    T type;
    Token(T type) : type(type) {};
    Token(T type, int value) : value(value), type(type) {};
    Token(T type, char* str) : checksum(str), str(str), size(strlen(str)), type(type) {};
    ~Token() { if (type == T::ID || type == T::STR) free(str); }
} *pToken;
using sToken = shared_ptr<Token>;
```

The most important token types are: ID (variables identifiers), STR (strings, use `str` and `size`), INT (numbers, use `value`).

Lexer limits length of strings and value of int to 256.

No bugs in that part, maybe except the fact that we can create INT token with value greater than 256 simply using arithmetic.

```c
>>> a = 256*4
1024
```

Next part of the interpreter is Parser. On initialization it just reads the first token (using Lexer). `parse()` method creates Abstract Syntax Tree (AST).

`Calc->interpreter` traverse (visits) the AST. During the visit, global table with variables is modified. Result of the visit is printed into the standard output.

The table is implemented as single linked list:
```cpp
static struct Symbol {
    char* id;
    sToken token;
    Symbol* next;
    Symbol(){};
    Symbol(char *str, sToken token) : token(token) {
        id = (char*) calloc(strlen(str) + 1, 1);
        if (!id) throw "Internal Error";
        strcpy(id, str);
    };
} SymTab;
```

Printing is done with functions below:
```cpp
void print(char *s, int n) {
    if (n != fwrite(s, 1, n, stdout)) exit(0);
}

void print(int n) {
    printf("%d", n);
}

void print(sToken result) {
    if (result->checksum != result->str) {
        print((char*)"EXIT", 4);
        exit(0);
    };
    if (result->size > 4) print(result->str, 4);
    else print(result->str, result->size);
}
```

The checksum check is here, most likely, to hinder exploitation process. Also note that at most 4 bytes may be printed.


### Bugs

First of all, some not really useful bugs:

* null pointer checks are missing in some places and thus we may easily crash the program
    ```c
    >>> (/*)
    [1]    15000 segmentation fault  ./combabo_calculator
    ```

* not strict variables ID comparison in `visitID` function
    ```cpp
    sToken Calc::visitId(sNode node) {
        fprintf(stderr, "visitId for '%s'\n", node->token->str);
        sToken result = nullptr;
        auto symbol = &SymTab;
        while (symbol->next != &SymTab) {
            symbol = symbol->next;
            if (!strncmp(node->token->str, symbol->id, strlen(symbol->id))) {
                result = symbol->token;
                fprintf(stderr, "visitId found: "); result->dump(); fprintf(stderr, "\n");
                break;
            }
        };
        return result;
    };
    ```

    Some we can do something like:
    ```c
    >>> a = "a"
    a
    >>> aaaaaaaaa
    a
    >>> xa
    Symbol Error
    >>> 
    ```

* signedness in print function
    ```cpp
    if (result->size > 4) print(result->str, 4);
    else print(result->str, result->size);
    ```

    `result->size` is of type `int`, so if we can set it to something negative it will bypass the check. However, in such case it will break on later `fwrite`.

Now for something useful. Check out the `visitAssign` method:
```cpp
sToken Calc::visitAssign(sNode node) {
    auto var = node->children[0];
    auto value = visitor(node->children[1]);
    if (var->token->type != T::ID || !value) throw "Syntax Error";
    if (auto variable = visitId(var)) {
        if (variable->type == T::STR && value->type == T::STR) {
            if (variable->size < value->size) variable->str = (char*)realloc(variable->str, value->size + 1);
            if (!variable->str) throw "Internal Error";
            variable->checksum = variable->str;
            variable->size = strlen(variable->str);
            strcpy(variable->str, value->str);
        } else if (variable->type == T::INT && value->type == T::STR) variable->value = atoi(value->str);
        else variable->value = value->value;
    } else {
        auto symbol = &SymTab;
        while (symbol->next != &SymTab) symbol = symbol->next;
        symbol->next = new Symbol(var->token->str, value);
        symbol->next->next = &SymTab;
    }
    return value;
};
```

It is our sweet spot:
* bug1: we may change string size
    ```cpp
    else variable->value = value->value;
    ```

    It occurs when left hand token is variable of type STR and right is INT.
    Due to the fact that value and size are in one union.

    ```c
    >>> a = "abcd"
    abcd
    >>> a
    abcd
    >>> a = 2
    2
    >>> a
    ab
    ```

* bug2: follows from bug1, we may use `realloc` as `malloc` and `free` function

    Since `value->size` is under our full control, setting it to `-1` will cause `realloc` to call `free`. Setting `variable->str` to `NULL` will cause `realloc` to call `malloc` with size of our choosing. To set `str` to `NULL` we may just free it (since the result of free/realloc is assigned to the `str`).

* bug3: incorrect `variable->size`
    ```cpp
    variable->size = strlen(variable->str);
    strcpy(variable->str, value->str);
    ```
    Because `strlen` is called before `strcpy`

* bug4: heap overflow
    
    Same code as in bug3. See that strcpy?

And there is one more in `Lexer::nToken`:
```cpp
pToken Lexer::nToken() {
    // cout << "nToken: '" << input << "' " << pos << "\n";
    while (input[pos] == ' ') pos++;
    if (pos == input.length()) return new Token(T::END);  // bug3 uninitialized Token 
    if (isdigit(input[pos])) return readDigit();
    if (isalpha(input[pos])) return readId();
    if (input[pos] == '+') return new Token(T::PLUS, input[pos++]);
    if (input[pos] == '-') return new Token(T::MINUS, input[pos++]);
    if (input[pos] == '*') return new Token(T::MUL, input[pos++]);
    if (input[pos] == '/') return new Token(T::DIV, input[pos++]);
    if (input[pos] == '(') return new Token(T::LP, input[pos++]);
    if (input[pos] == ')') return new Token(T::RP, input[pos++]);
    if (input[pos] == '"') return readStr();
    if (input[pos] == '=') return new Token(T::ASSIGN, input[pos++]);
    throw "Lexer Error";
};
```

Fields of `T::END` token are not initialized.


### Exploitation

The plan is simple:
* leak libc address
* convert heap overflow to arbitrary write
* overwrite some hook in libc (like `__free_hook`) with `system`
* call it with "/bin/sh" string

