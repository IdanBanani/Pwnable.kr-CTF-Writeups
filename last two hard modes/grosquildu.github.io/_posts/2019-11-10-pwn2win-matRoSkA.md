---
layout: post
title: pwn2win 2019 - matRoSkA
category: writeups
tags: [crypto]
use_math: true
---

tldr; common factorization methods (close primes, pollard's p-1) with quirks

Description (definitely overlong):
```
The Organization is suspecting our activity in 2019. To stop us, the conglomerate has sent two Squads for this year. Our team has intercepted the communication between the two Squads that are working cooperatively. During the analysis of the intercepted data, our experts identified the parameters of an encrypted communication. However, they could not retrieve the original message. We are sending the binary, collected from one of the hacked Organization servers, used to encrypt the message and the parameteres identified by our team. Can you help us with this task?
```

Task source code: [here]({{"/assets/posts/2019-11-10-pwn2win-matRoSkA/matroska.tar.gz"}})

We are given stripped ELF binary, three modules and a ciphertext.

The binary was rather simple. The only obstacle during the reverse engineering was usage of GMP library with stripped function names. We had to guess what math functions do.

After the RE process, we get following pseudo-code (GMP function names are only descriptive, not the real ones):

```c
init();  // read flag, get random from /dev/urandom
mp_make_bigint(&e);
mp_from_int(&e, rsa_e);

// generate n1
mp_make_bigint(&p1); mp_make_bigint(&q1); mp_make_bigint(&n1); mp_make_bigint(&v12);
do
    gen_n1(&p1, &q1);
while ( !check_p_q(&p1, &q1, &n1, &v12) );

// generate n2
mp_make_bigint(&p1); mp_make_bigint(&q2); mp_make_bigint(&n2); mp_make_bigint(&v16);
do {
    do
      gen_n2(&p2, &q2);
    while ( !check_p_q(&p2, &q2, &n2, &v16) );
} while ( !mp_cmp(&n2, &n1) );

// generate n3
mp_make_bigint(&p3); mp_make_bigint(&q3); mp_make_bigint(&n3); mp_make_bigint(&v20);
do {
    do
      gen_n3(&p3, &q3);
    while ( !check_p_q(&p3, &q3, &n3, &v20) );
} while ( !mp_cmp(&n3, &n2) );

// encrypt flag
mp_make_bigint(&v21);
mp_make_bigint(&v22);
mp_make_bigint(&v23);
mp_make_bigint(&c3);
flag_content = alloca(16 * ((flag_size + 15LL) / 0x10uLL));
flag_fd = fopen("flag.txt", "r");
if ( !flag_fd ) {
    puts("Error opening file!");
    exit(1);
}
flag_real_size = fread(flag_content, 1uLL, flag_size, flag_fd);
close(flag_fd);
mp_from_string(&v21, flag_content, flag_real_size);
mp_powmod(&n1, &e, &v21, &v22);
mp_powmod(&n2, &e, &v22, &v23);
mp_powmod(&n3, &e, &v23, &c3);
printf("n1 = %Zd \n", &n1);
printf("n2 = %Zd \n", &n2);
printf("n3 = %Zd \n", &n3);
printf("c3 = %Zd \n", &c3);
```

And code of the n-generating functions, in python for easier reading:
```python
def gen_n1(e):
    small_prime_product = 1
    tmp_small_prime = 2
    for _ in range(39):
        small_prime_product *= tmp_small_prime
        tmp_small_prime = next_prime(tmp_small_prime)

    while 1:
        y = getRandomNBitInteger(37)
        k = getRandomNBitInteger(62)
        p = y * small_prime_product
        a = pow(e, k, small_prime_product)
        p += a
        if is_prime(p):
            break

    while 1:
        z = getRandomNBitInteger(37)
        l = getRandomNBitInteger(62)
        q = z * small_prime_product
        b = pow(e, l, small_prime_product)
        q += b
        if is_prime(q):
            break

    return p, q

def gen_n2():
    prime_256 = next_prime(getRandomNBitInteger(256))

    while 1:
        p = getRandomNBitInteger(1024-256)
        p *= prime_256
        p += 1
        if is_prime(p):
            break

    q = prime_256
    while 1:
        while 1:
            q *= getRandomNBitInteger(25)
            if int(gmpy2.log2(q)) >= 1024:
                break
        q += 1
        if is_prime(q):
            break
        q = prime_256

    return p, q

def gen_n3():
    primes_base = getRandomNBitInteger(int(1024))
    k = getRandomNBitInteger(int(8)) + 1
    l = getRandomNBitInteger(int(8)) + 1

    p3 = primes_base * k
    p3 += getRandomNBitInteger(int(512))
    p3 = next_prime(p3)

    q3 = primes_base * l
    q3 += getRandomNBitInteger(int(512))
    q3 = next_prime(q3)

    return p3, q3
```

Lets do it from the last one.

#### n3
In simple terms we have:

$$\begin{eqnarray}
X = rand(1024) \nonumber \\
p = next\_prime(X * rand(8) + rand(512)) \nonumber \\
q = next\_prime(X * rand(8) + rand(512)) \nonumber
\end{eqnarray}$$

The primes differs only by the lowest 512 bits and some small, 8 bits random numbers.

The idea is to use [coppersmith's method](https://github.com/mimoo/RSA-and-LLL-attacks/raw/master/survey_final.pdf) for finding small roots to find out the random 512 bits. For that we write equation:

$$ q' + x \equiv 0 \mod q $$

where $q'$ is a lower bound of $q$'s most significant bytes and $x$ is the small root we want to find.

To get $q'$ we just need to compute square root of n: $q' = \sqrt{\frac{n}{k*l}}$

$k$ and $l$ are small and can be found by exhaustive search.

Now, using coppersmith's method, we can solve abowe equation. In Sage:
```python
def crack_n3(n3):
    print('start n3')
    for k in range(37, 256):  # k == 37
        print('k: {}'.format(k))
        for l in range(k, 256):
            q_approx = l*isqrt(n3 / (k*l)) - (2**512)

            F.<x> = PolynomialRing(Zmod(n3), implementation='NTL')
            f = q_approx + x
            roots = f.small_roots(X=2**512, beta=0.5)
            if len(roots) > 0:
                q_approx = int(q_approx)
                print('found roots: {}'.format(roots))
                print('q_approx = {}\nk = {}\nl = {}'.format(hex(q_approx), k, l))
                q_lsb = int(roots[0])
                q = q_approx + q_lsb
                if (n3 % q == 0) and (q != 0) and (q != n3):
                    print('q = {}'.format(hex(q)))
                    return q
```

Result:
```
k = 37
l = 133
q = 0x764dd277b33382d68999d846a34da1628f061f00bd3763b0542a49c16243e97556e03af4a7cae94bfc2b86e19b2be704148e3f76bb7bb947e60d434c5014e5eaed5abe9216088c4dfaf12a8763e063b3f101af9336ee56288119e375b10db7e3dce3a367bf0e8e48e683136c800fe2992b4eb5b0bb53c12907b0004ba52e878fdf
```

#### n2
We have:

$$\begin{eqnarray}
X = next\_prime(rand(256)) \nonumber \\
SM = rand(25)*rand(25)*...*rand(25) \nonumber \\
p = X * rand(768) + 1 \nonumber \\
q = X * SM + 1 \nonumber
\end{eqnarray}$$

$q-1$ is product of $X$ and some small numbers (so it's about 1024 bits long).

That is perfect setup for [Pollard's p-1 factorization method](https://en.wikipedia.org/wiki/Pollard%27s_p_%E2%88%92_1_algorithm).
It works when $p-1$ is $B$-powersmooth (that is $p-1 = \prod{x^v}$ and ${x_i}^{v_i} < B$ for all $i$).

Below short explanation:

Euler's theorem states that if $p$ is prime then: ${a}^{p-1} \equiv 1 \mod p$

We can extend it to: ${a}^{k*(p-1)} \equiv 1 \mod p$, where $k$ is arbitrary number.

Now assume that $p-1$ is $B$-powersmooth. If we generate number $R$ which is product of all integers smaller than $B$, we have $R = k*(p-1)$. So then ${a}^{R} \equiv 1 \mod p$ and $p \mid gcd({a}^{R}-1, n)$. If $gcd({a}^{R}-1, n) < n$, then it is nontrivial factor of $n$.

The problem with challenge's $q-1$ is that it contains one big factor. To overcome it lets observe that:

$$\begin{eqnarray}
n = p*q = X^2*rand(768)*SM + X*rand(768) + X*SM + 1 = \nonumber \\
= X * (X*rand(768)*SM + rand(768) + SM) + 1  \nonumber \\
\nonumber \\
n - 1 = X * some\_integer \nonumber
\end{eqnarray}$$

Multiplying $R$ with $n-1$ allows us to apply Pollard's algorithm. The code is:

```python
def pollard_P_1(n, b):
    n = mpz(n)
    a = mpz(2)  # needs to be coprime with n
    j = mpz(2)

    # mix in the X
    a = pow(a, n-1, n)

    # small factors
    for i in range(100):
        print('i: {}'.format(i))
        for _ in range(b//100):
            a = pow(a,j,n)
            j += 1

        p = gcd(a-1, n)
        if 1 < p < n:
            print('p = {}'.format(hex(int(p))))
            return p

    return 0        
```

Result:
```
i: 96
p = 0x25fd4675be08b14e7b8bfc5262cde30d6c93ecce4475eb47bcca98fbb731419aaf9409c89261eb3c83ae32e879e76df2a131eb56faa12f6498df3f1298cba4e93513075960b978e580cf9a29ff28a46b1594693b89f648362b45f5a2719a122685cc588e80ea4dd26a2c57c2cbc10f0826071c29a75f2f06de5aab77e80000001
```

#### n1

The simplest one.

$$\begin{eqnarray}
X = \prod\limits_{0 < i \leq 39}{p_i} \nonumber \\
p = X*rand(37) + pow(e,rand(62),X) \nonumber \\
q = X*rand(37) + pow(e,rand(62),X) \nonumber
\end{eqnarray}$$

$X$ is product of first 39 primes (220 bits long).

The attack for modules like these is known as ROCA and is described in the paper ["The Return of Coppersmith’s attack: Practical Factorization of Widely Used RSA Moduli"](https://acmccs.github.io/papers/p1631-nemecA.pdf).

It exhausively searches for $rand(62)$ and use Coppersmith’s method to compute $rand(37)$ (with optimizations to make the search feasible).

We can find implementation of the attack [at github](https://github.com/brunoproduit/roca). At the time of writing, it contains some bugs that needs to be fixed before running the code.

Result:
```
[+] Importing key
[+] Key is vulnerable
[+] RSA-512 key
[+] N = 2125209526085245945732482728702623686197712133854349939369696816130429780891151917614366683932632273604344349646900287227444428216389612979866274616090861
[+] c' = 416436
[+] Time for 1 coppersmith iteration: 0.03 seconds
[+] Estimated (worst case) time needed for the attack: 20 minutes and 5.51 seconds
[+] p, q: 23108848859761668859858848404388842601614330403044222438215478025096936520609, 91965183509671546346840964269567349085149625152928968672361592141360802234829
```


#### flag

Finally we can decrypt the flag:  
CTF-BR{s0_many_ways_to_generate_shitty_primes_and_weak_RSA}.
