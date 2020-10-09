---
layout: post
title: JHtC4BSK barsa
category: writeups
tags: [crypto]
---

Crypto ctf challenge for JHtC team.

[Source code]({{ "/assets/posts/2017-10-20-jhtc4bsk-barsa/barsa_source.zip" }})

![barsa main page]({{ "/assets/posts/2017-10-20-jhtc4bsk-barsa/barsa1.png" }})

The page have two standard functionalities: user registration and logging in. After playing with them for a while we can see that authentication is based on "auth" cookie, which contains two long numbers separated by dash. Next thing to check is html source.

![barsa html code]({{ "/assets/posts/2017-10-20-jhtc4bsk-barsa/barsa2.png" }})

After not looking at robots.txt, we do not get encrypted zip file with challenge's source code.

```
src/static » unzip -l do_not_look_at_me.zip
Archive:  do_not_look_at_me.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  2017-10-10 19:32   src_tmp/
     6729  2017-10-10 19:32   src_tmp/CryptoLib.pyc
        6  2017-10-10 19:32   src_tmp/the_password_cant_be_and_is_not_whisky.txt
     6477  2017-10-10 19:32   src_tmp/app.py
        0  2017-10-10 19:32   src_tmp/static/
       89  2017-10-10 19:32   src_tmp/static/robots.txt
        0  2017-10-10 19:32   src_tmp/static/images/
  1011600  2017-10-10 19:32   src_tmp/static/images/mp3.gif
   495751  2017-10-10 19:32   src_tmp/static/images/mp4.gif
   136100  2017-10-10 19:32   src_tmp/static/images/mp.jpg
   735548  2017-10-10 19:32   src_tmp/static/images/flag.gif
  2051627  2017-10-10 19:32   src_tmp/static/images/mp6.gif
   858532  2017-10-10 19:32   src_tmp/static/images/mp5.gif
     1156  2017-10-10 19:32   src_tmp/static/images/favicon.png
   122004  2017-10-10 19:32   src_tmp/static/images/mp1.gif
   198105  2017-10-10 19:32   src_tmp/static/images/mp7.gif
   489136  2017-10-10 19:32   src_tmp/static/images/mp2.gif
        0  2017-10-10 19:32   src_tmp/static/css/
     5849  2017-10-10 19:32   src_tmp/static/css/style.css
     7797  2017-10-10 19:32   src_tmp/static/css/normalize.css
        0  2017-10-10 19:32   src_tmp/templates/
      411  2017-10-10 19:32   src_tmp/templates/login.html
      420  2017-10-10 19:32   src_tmp/templates/register.html
     1950  2017-10-10 19:32   src_tmp/templates/layout.html
      184  2017-10-10 19:32   src_tmp/templates/index.html
---------                     -------
  6129471                     25 files
```

Since the password is not whisky, we do not decrypt it and... meh

After reading sources it's clear that our task is to login as admin.
It can be achieved by creating proper auth cookie of the form: E(enc_key,'admin')--S(sig_key,sha256(E(enc_key,'admin'))),
where E is pure rsa encryption function with enc_key and S is rsa signing function with sig_key

Only thing we know about enc_key and sig_key is public exponent e (equals to 65537). Let's find theirs modules.
Register two accounts (m1, m2) and get corresponding ciphertexts. Then we have:
```
m1**e == c1 % n
m2**e == c2 % n

m1**e - c1 == k*n
m2**e - c2 == k'*n

n ~= gcd(k*n, k'*n) == gcd(m1**e - c1, m2**e - c2)
```
n is enc_key modulus.
Note that after computing gcd of two values, we may get z*n, where z should be small, not exactly n. We can try gcd with another plain/cipher pair or trivial division until we find exact value.

For sig_key modulus we do similarly (it will take longer to compute it though):
```
s1**e - sha256(c1) == k2*n2
s2**e - sha256(c2) == k2'*n2
n2 ~= gcd(s1**e - sha256(c1), s2**e - sha256(c2))
```

Now we can easily compute first part of the cookie. For the second one, we need sig_key private exponent.
If we look at key generation function, we can notice that it's a bit strange.
Actually, it is a backdoored version of rsa key generation (for details see https://eprint.iacr.org/2002/183.pdf)

Algorithm:

```python
seed = 476283116406539741845175463956657874046958850596520333086272652099928678076182181180321  # backdoor_modulus
k = 1024
e = 65537
e_backdoor = 17
while True:
    p = random_nbit_prime(k/2)
    if gcd(e, p-1) == 1 and int(bin(p)[:k/4+32],2) < seed:
        break
qv = random_nbit_prime(k/2)
nv = p*qv
t = bin(nv)[:k/8]
u = bin(pi(seed, int(bin(p)[:k/4+32],2)))
u = '0'*(k/4+32 - len(u)) + u
l = bin(nv)[-(5*k)/8 + 32:]
n = int(t + u + l, 2)
q = n/p + 1 - ((n/p)%2)
while gcd(e, q-1) > 1 or not is_prime(q):
    m = random_nbit_integer(k/8-40)
    m += (1+(m%2)) / 2
    q = q^m
    n = p*q
d = modinv(e, (p-1)*(n/p-1))
```

Some bits on n equals to encrypted most significant bits of p. More precisely:
```
bin(n)[k/8:(3*k)/8 + 32] == bin(pi(int(bin(p)[:288],2)))
where pi(x) = pow(x, e_backdoor, seed)
```

pi funtion encrypts 288 msb of sig_key's p.

Only way we can decrypt it, is by finding backoor's private key, so finding factorization of seed.
We can use variety of methods and most of them should quickly find, that seed is a square number.
So we compute d_backdoor and msb of p.

Now, according to [Coppersmith's theorem (section 4.5)](https://crypto.stanford.edu/~dabo/papers/RSA-survey.pdf#page=11), we can recover whole p and so whole sig_key

Finally, create cookie and get the flag. Full scripts below.

solve.py
```python
#!/usr/bin/env python

import requests
from gmpy import gcd, invert, mpz, sqrt
from hashlib import sha256
from random import randint
import subprocess

print "Start"
url = 'http://jhtc4bsk.jhtc.pl:30902/'
seed = 476283116406539741845175463956657874046958850596520333086272652099928678076182181180321
e = 65537
enc_key = {}
sig_key = {}

#get keys modules
m = {}
auth = {}
c = {}
s = {}
c_hash = {}
for x in xrange(3):
    m[x] = 'gros23_huehue'+str(x)+str(randint(1,10000)) #have to be unique
    password = 'trolololo'
    auth[x] = requests.post(url+'register', data={'username':m[x], 'password':password}).cookies['auth']

    m[x] = mpz(m[x].encode('hex'), 16)
    c[x], s[x] = auth[x].split('--')
    c_hash[x] = mpz(sha256(c[x].decode('hex')).hexdigest(), 16)
    c[x] = mpz(c[x], 16)
    s[x] = mpz(s[x], 16)

enc_key['n'] = gcd(gcd(pow(m[1], e) - c[1], pow(m[2], e) - c[2]), pow(m[0], e) - c[0])
print "Encryption key modulus:", enc_key['n']
sig_key['n'] = gcd(gcd(pow(s[1], e) - c_hash[1], pow(s[2], e) - c_hash[2]), pow(s[0], e)- c_hash[0])
print "Signin key modulus:", sig_key['n']

#get private key of backdoor, seed == backdoor_modulus
e_backdoor = 17
p_backdoor = sqrt(seed)
d_backdoor = invert(e_backdoor,(p_backdoor-1)*p_backdoor)

#get 288 most significant bits of p
k = 1024
p_msb = bin(sig_key['n'])[2:][k/8:(3*k)/8 + 32]

#decrypt 288 msb of p
p_msb = pow(int(p_msb,2), d_backdoor, seed)
print "Signin key 288 msb of p:", bin(p_msb)[2:]

#compute whole p
p = mpz(subprocess.check_output(['sage', './partial_p.sage', str(sig_key['n']), str(p_msb)]))
print "Signin key p:", p
assert sig_key['n']%p == 0

#compute d
q = sig_key['n'] / p
sig_key['d'] = invert(mpz(e), mpz((p-1)*(q-1)))
print "Signin key d:", sig_key['d']

#cook cookie
m = int('admin'.encode('hex'), 16)
c = pow(m, e, enc_key['n'])
c = hex(c)[2:].strip('L')
s = pow(int(sha256(c.decode('hex')).hexdigest(),16), sig_key['d'], sig_key['n'])
s = hex(s)[2:].strip('L')
admin_cookie = c+'--'+s
print "Cookie:", admin_cookie

#get flag
resp = requests.get(url, cookies={'auth': admin_cookie})
print resp.text
```

partial_p.sage
```python
#!/usr/bin/env sage
import sys

if len(sys.argv) < 2:
    print "Usage: ./partial_p n p_msb"
    sys.exit(1)

n = Integer(sys.argv[1])
p_msb = Integer(sys.argv[2])

pbits = p_msb.nbits()
p_msb = p_msb*2^(512-pbits)
PR.<x> = PolynomialRing(Zmod(n))
f = p_msb + x
#print '{} MSB bits of p is known'.format(pbits)

x0 = f.small_roots(X=2^(512-pbits), beta=0.4)[0]
print x0 + p_msb
```