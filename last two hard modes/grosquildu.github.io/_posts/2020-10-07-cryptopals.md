---
layout: post
title: cryptopals solutions
category: writeups
tags: [crypto]
---

For archival purposes, I am uploading solutions for [the great cryptopals challenges](https://cryptopals.com/).

Solutions can be found [here]({{ "/assets/posts/2020-10-07-cryptopals/cryptopals.tar.gz.gpg" }}) - they are password protected and the password is the subject for email for ninth problem in set 8 ("Shackling the ..." thing without quotes).

They were written in python2, nothing fancy. May not work with python3.

Some of the missing solutions may be found inside my [CryptoAttacks](https://github.com/GrosQuildu/CryptoAttacks) repo.

Missing:

* set 2
    * 14 Byte-at-a-time ECB decryption (Harder)
* set 3
    * 22 Crack an MT19937 seed
    * 23 Clone an MT19937 RNG from its output
    * 24 Create the MT19937 stream cipher and break it
* set 4
    * 31 Implement and break HMAC-SHA1 with an artificial timing leak
    * 32 Break HMAC-SHA1 with a slightly less artificial timing leak
* set 5
    * 36 Implement Secure Remote Password (SRP)
    * 37 Break SRP with a zero key
    * 38 Offline dictionary attack on simplified SRP
* set 6
    * 47 Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)
    * 48 Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case)
* set 7
* set 8
    * only SageMath: 62 Key-Recovery Attacks on ECDSA with Biased Nonces
    * only SageMath: 64 Key-Recovery Attacks on GCM with a Truncated MAC

PS. I can't get the ninth challenge from set 8. If someone is willing to share it - please PM me.
