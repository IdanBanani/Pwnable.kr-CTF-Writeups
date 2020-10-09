---
layout: post
title: CTFZone quals 2018 - WhateverNote
category: writeups
tags: [crypto]
---

tldr; BREACH attack on TLS1.2 with AES GCM (HTTP level compression)

Description:
```
Mr. Evil stores some secret information on WhateverNote (https://crypto-03.v7frkwrfyhsjtbpfcppnu.ctfz.one/).
We found that he uses service nc crypto-03-sync.v7frkwrfyhsjtbpfcppnu.ctfz.one 1337 to sync his notes.
Can you help us to get his secret?
```

On the web page we can register, login, create notes (title, body and category: one of "work","study","personal"), view them by category (/?category=personal) and display one, specific note (/note/yisvqHsknTyAKNuFng2-0A==).

Last functionality is the most interesting one, because access to any note is not authorized. You just need to know the url.

That base64 (urlsafe) encoded something that works as note id seems to be encrypted data (length is always 16 bytes), but I wasn't able to do anything worthwhile with it. So lack of authorization seems to be the only bug in the web page.

Now for the 1337 service:
```
➜ nc crypto-03-sync.v7frkwrfyhsjtbpfcppnu.ctfz.one 1337

-------------------------------
Welcome to sync notes service!

-------------------------------
Options:
    [S]ync notes
    [Q]uit
-> S
Enter the category you want to sync: work

[DEBUG] client -> server
16030100be010000ba030374954334629fc30cc71272c24d9b239b97c2d04c6d54143059ab3b1abdc6aac2000020c02fc030c02bc02ccca8cca9c013c009c014c00a009c009d002f0035c012000a0100007100000031002f00002c736f636b6574732f31393864363435362d666435302d343166382d396639332d663262333439653339396332000500050100000000000a000a0008001d001700180019000b00020100000d0012001004010403050105030601060302010203ff0100010000120000
[DEBUG] server -> client
1603030059020000550303db7c2bd4bfb57bfa2758e53d543d388474a087df6c9cc881b4b37e187507f86d20d56f58c63996071521d51c955aed6ab0d4a214bf4d0f216b6359cd5ae5b95028c03000000dff01000100000b000403000102160303030c0b000308000305000302308202fe308201e6020900e4eff34a0174bb39300d06092a864886f70d01010b05003041310b3009060355040613025255310f300d06035504080c064d6f73636f77310f300d06035504070c064d6f77636f773110300e060355040a0c0742492e5a4f4e45301e170d3138303532313134343330315a170d3139303532313134343330315a3041310b3009060355040613025255310f300d06035504080c064d6f73636f77310f300d06035504070c064d6f77636f773110300e060355040a0c0742492e5a4f4e4530820122300d06092a864886f70d01010105000382010f003082010a0282010100aba17601fd9e8d502f3e7329ede40ce6c14e707dc832aa3919d6ed33ced054569b61c233a47f39c0fdde21d4842f4ebb514c73a67a628875f8fe3af8c174691066e0608c2e8e9688beddf8554d500ea1177dd3edd8261d2a2a4e35ea88a27dd697da4058c6e0853d724abf0550dfe8fb9c685a6196dfd279ca475d27887903339bbffc6df779cf384f1e0aa7ab4f8815d6b8c47f3666d6f3d64d8b06e4fa0f8d2562e66dc4254f68dc94cd05f27e8ea7b0d4318e69627f32063ee3f139e79de6681a8d826211c6ef10f15a8f4f017ccdc57a21a909d0a16776c03cfd6b3204cad5ef4cf621a41c2b153e4d1693bcce6acd13f9688b2ff84a73a4df8dbb5ca5f30203010001300d06092a864886f70d01010b050003820101002159475134a99b5fcda4f8417fd2027438ccad42b67a12b43564f70c775a951cf31ae061b7c58fcb5489e52ba2fbd136e44582e1e368160210fe020a8a6d7daab6d0017e7d7e1623ba8cdc9d8b3c4e31b130742412707d47762a36a32524257d855548e0835f36d19eb981d7a85bbd4364b07ff8d6a79f70775cfc89fe8bfbcac1d2e97b57bbb7cff8797b450234998bea8210f080c834a8ecac8fde10ca45f160228c7629e1ecf3eb6e51bbfec39750216f892e5e42adcba3a838e920b56265e81722c0e3799f0673bf52d68822e49ed0e8298b3a38f45a919b8aa87f257a1e25d771c6ce4fe949ef10caad8d3650f47228cd6059c5c3713edbc99c4fb24a8e160303012c0c00012803001d204bf3db4f6202a3952d560ba08f48f27418dc0cda505d1fb195a07eec654d423006010100336a6a10a4b5a12607838cd456eb9461e8a0828e05ed29da217db8e6199531877e374f0c15445d725b9b6ba9415cbd17db44fefcb78b51028306e773dd3fa66e3482d9bf72fe326bc0c055123f0ef0c0fc07f41117ef4a05e75ddb2faf2b4c9e043130ac0e6112b83b6a1c444838214480409b2f2a175730d76c7e81a724953be0645380ab9e796e1511f6011dd72b4518c9bd054f1f9c2f8446d5d807c5ddc6cd2fde8ed48b22cb439a698e5c04e2222aae8a38ea10f9d5a004b7fefec7c471422f2fed7ca95060fc57ad4f74d6574f412b181a2098d4991ea6cc06d589cf5a27f776c3e51718134463c0efb4bdf8d40208ca9e4c8dcfa59c159ebdff14b4c416030300040e000000
[DEBUG] client -> server
16030300251000002120d4fc5c1af06573443228f2427b918e851b2b07ffeda29ddd3103d2cdf42146001403030001011603030028000000000000000085833fad30ef690f156dc89d2d3377af173463111e40960e53001759c32f6059
[DEBUG] server -> client
1403030001011603030028a5b5666f9470855a745996678941943c2822d62ee1cc10bf2ca4dc0d3e021474c3c9a2e3f0e21f78
[DEBUG] client -> server
170303032300000000000000017bfaead992af1ff4bbb54d318802c7f842eddde877380300a42942d391c4fa17de3c740c78cc97ca676c6e97e241edff9b6e463c7f1586e92eb015d4675d17ed0db8149916872902e39977b95973823d2f848e333944dbcc2724b127ea2f66964bd52ab2f324960723b576930a01e56b17d9b0f8d14d6c99e1e5b15a7e61cd8d6a7fb733c0013be447a62d0fcac396de54af5e7e6bfb2645678279f7b269c2a113cdb4db087c7f1605112d39776a086445f8f929ecd79b6acdfb9ce4fa72251ef6da7ae0884a6aca255fc44f4b3884c9fbab75d6124830fe9fc0a8fa5b56d2f2f99aba5437ed9685e16ba7ed6a0e81568cdb3a9a08ea6b337c8b9440a041d4904b0f873e1e28f874cff91d4543267014276cc025d785f911c226a8b1b304d88f5815a02f1e228f855d456cf190045dc769e08ec9bc22927a49faaa79208e57d302e741fdb26fb5bce55db2fd724a02682ee3eca046ec72e7e5feff0d02b0545822c39877e463ec46fb53be4aca61a416b60801fca783850732f10cb348d80088155be009cd0e656f024865cf34ab35362b60d488e8c705ffad700c9831a310c2c0e78ca20c2473b1c71a0697258275aa42943546d8d4cc455002de980d88fa339adcf4b575c04939cc5749a47e1df591da7c7294a5083d823d5e0a2dc7538399a67f1e7fe7cdc16853be760ef5c757198fcd85558e5100738082614528b573f19dff975cf4b7ae835ec6b7085430b83ea9e580de78467732d92e1d0783b58b31950c8dfba6370bc3cc3ad7146b15fdecc0c6d3413ff11942d643a31cda4836a887a7d102a93c044ffcb43031e0a760495396e6725fbcc027a1edf71bd374933496c78abfeef437f2835b52a2c28463a725434360774279d857a66e7c39b67cbf561e67003d048cc01909a59081d28ab93093e7993dddcb85d8e57eb36c407a5ee681d05140cec965c537b8da98e840ef7bc1c0bf53971b430999f1e6d2a4dd67c774033d4925dc39241529e747de92fb15fbba8bb7dd93b5fc357daef28ffa33fb8af0992d776b77624e3f0372e36ecbc20da5331dd0c3f7ec3ff1a19be056fca00319ab03b3f0950522439f26aeff071bf7564434b0ff72ec10f9
[DEBUG] server -> client
170303043da5b5666f9470855b34fd45e8b8128578b1521fa21c1cb2ea5ef5f3919f6494418da1ca076a336044cc3294da928d2e98cd91b0fa61ed74b62b283228c3c6b657048461c3f9060e7f894d2d01434f72512b9833da1eda64ed3522788ba06b18086b33344d1fa5f51633144a3ae3672aa38a3850976d8e581539a2bdbaaeff4cc13478c2c2d129b8bac7a82ef1012b99880974ec9895e9af9118193651552a6bbfa2ed184ef35915cfb845b62fe80de1e6ec0f16ad0df906807a4796c76cea91492b1f7d40211f6709ee03b0a9dd3ddda251169b64aae1577e9e1c12adffc684ae157bbcc7e81f6d406d617ddbfd4b57b9a8813cb868dffc99baacd87f92f4abdcc266e5a5511682ad39f32cfe72e84915066a597c44b73377a9e36b51022e376f70a61877acfc30e6a3b1d2524de6586cdb5e32b3183d5e1714ca885b7cdde075991859beddf48cd4e74dd0e9b0d7cade807d42a3fc2b0209f19b5f57e61c047eace19cf91cfe7036929e5c46b09b4e2725b0ae5fa97a645cc3e7cfa7b6979109a1c9dce03af049e9e1c6138e299b125a140b400ab727f57179f17fbbc824e6e8328872003aed0bb2be212235a05390087e8f5ab1045782b75fd4304c342d604b9c5c29bff2a877e1fe71df0456a348b1923ef8d01e6e2fcea2d24dc5edf0758ab74423cfadc526ec83be5a016a600bdb32f33f046ba6eb0fffe18299223e9d21a364ac33f16c3e6382ee33690f6abe9f469fb0a09afbed432d1026cb96437aa03b896f49a4da9c187023a41dcd957ca1d78a54cfb079efcf4e286bcf9e1d3a4167a8c15bd6ca910183d292db4db5e61182e1059c6c26428606c215d98e2aa2c352ec54facee03f4e277364962292796119ab5aac85143b6dee271c9f3c7fea3ba347a70233063bd06a48ebda08261d38eccbabb55d9c5ee76f2914079ef721c394676bb7eb9e7e70aa6a27f8afdcbdd0a103675e94f4f5a13c9fd519dfe34e05289f6921f19dc6a1471225b91ec28ee9f556eba958c52a11c9eaa63c4c623aa492ee9adb27031bc05b40789683e277e338affde494d06bc2c7a75978e74cc92eabed43572bcff41d52803d825ead7c9e7f15600f0671c5eb68a2fe281c0b494f8d7773634fb4fce188ac931ed751fb76c81a67780f62acd4e19d5f5e5cd82b6567ba3a49aa15dbca90aa8b90ec0c50525bc67a46301e12a2c45b1a5681ccdd8dda6ee1e72c3ee85ec419abc77d506cc528f28a128f06bb2aba57d8fddef925ee20500177a5363bb3e20baa1d7a4e8bec85ef1fe8a12f9de3f98523a00453781fdaf3e085f6a43fbf0ce5529482b18fd96d458b1c5791acdf885e02f75b159bfbd507b17097d11da7dbbbe608a79047dbbf5335e647dc8468e6994c7d14121e2f975d84fc53f6237e3c586f133409e12f6a90b76dab649ba5a310c33277f9e5c818a93b7154e2e5e6dcff56e6610640c80b0dfdb35bb9e2ab6f81c16e1e9a41252ce0e3ce3dedf35461a2e0b48e7c694971a27c03556f4c976ed91392c6
1 note synced

Options:
    [S]ync notes
    [Q]uit
-> 
```

(Output from the service may not be exact, as the challenge was down when I was writing the writeup).

So we have hexdump of communication between Mr. Evil and the server. If we specify category as "work", 1 note gets synced. If as "personal" or "study", no notes are synced and for non-existent categories 1 note is synced.

Length of one before last hex data depends on our input (category) in one-to-one relationship.

At that point I was stuck for a while, as I couldn't find out what the communication protocol was. Until my teammate remarked that it is TLS session. Shame on me for not spotting it.

As we know what the data is, we can dump conversation to a file and import it to wireshark:
```python
def get_connection():
    return remote('crypto-03-sync.v7frkwrfyhsjtbpfcppnu.ctfz.one', 1337)

def one_sync(s, sync_type):
    s.recvuntil('-> ')
    s.sendline('S')
    s.recvuntil('Enter the category you want to sync: ')
    s.sendline(sync_type)

    data = []
    for i in range(6):
        s.recvuntil('[DEBUG] ')
        s.recvuntil('\n')
        data.append(unhexlify(s.recvuntil('\n')[:-1]))

    synced_no = s.recvuntil(' note synced').split(' ')[0]
    return data, synced_no

def get_sync_pcap():
    s = get_connection()

    for i in range(2):
        data, synced_no = one_sync(s, 'A'*i)
        with open('dump.hex', 'wb') as f:
            for d in data:
                with open('dump_tmp.raw', 'wb') as dump_tmp:
                    dump_tmp.write(d)
                dhex = subprocess.check_output(['xxd','-g','1','dump_tmp.raw'])
                print(dhex)
                f.write(dhex + '\n')

        subprocess.call(['rm', 'dump_tmp.raw'])
        subprocess.call(['text2pcap','-T','1337,7331', 'dump.hex', 'out'+str(i)+'.pcap'])

    s.close()

if __name__ == '__main__':
    get_sync_pcap()
```

In wireshark, click File > Import from HexDump. Chose "dump.hex" file and encapsulation TCP with whatever ports. Decode data as SSL.

```
➜ tshark -r out0.pcap 
register simpleai protocol for port: 10001
    1   0.000000     10.1.1.1 → 10.2.2.2     SSL 249 Client Hello
    2   0.000001     10.1.1.1 → 10.2.2.2     TLSv1.2 1247 Server Hello, Certificate, Server Key Exchange, Server Hello Done
    3   0.000002     10.1.1.1 → 10.2.2.2     TLSv1.2 147 Client Key Exchange, Change Cipher Spec, Hello Request, Hello Request
    4   0.000003     10.1.1.1 → 10.2.2.2     TLSv1.2 105 Change Cipher Spec, Encrypted Handshake Message
    5   0.000004     10.1.1.1 → 10.2.2.2     TLSv1.2 362 Application Data
    6   0.000005     10.1.1.1 → 10.2.2.2     TLSv1.2 1082 Application Data
```

It is request/response to the web page (GET https://crypto-03.v7frkwrfyhsjtbpfcppnu.ctfz.one/?category={our_input}).

Cipher suite used: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384. I supposed that breaking either ECDHE, RSA or GCM is pointless. So I played with the service, until I noticed that not only length of the client request (last but one packet) depends on our input one-to-one, but also the length of server response (only if the category we send is not valid though).

If we look at the webpage html code, it will explain the dependency:
```html
<section class="container">
    <h1>Notes</h1>
        <blockquote class="">Category &#34;NOTEXISTING&#34; doesn&#39;t exist</blockquote>
    
        <article>
            <h2><a href="/note/QdHMruTAFBAxRT7ACTimMg==">&lt;&gt;&#39;&#34;</a></h2>
            <a href="/?category=personal" class="category personal">personal</a>
            <p>&lt;&gt;&#39;&#34; ...</p>
        </article>
    
        <article>
            <h2><a href="/note/ubJM-UnVlDHbLIP7N0oyRw==">www ${2*3} %{4*5} {0:x}</a></h2>
            <a href="/?category=work" class="category work">work</a>
            <p>www ${2*3} %{4*5} {0:x} ...</p>
        </article>
    
        <article>
            <h2><a href="/note/6YG4Jnk5DT0gNzk7BNB0WQ==">AAAAAAAAAAAAAAAAAAAAAAAAAAXXXXXXXXXXXXXXX</a></h2>
            <a href="/?category=personal" class="category personal">personal</a>
            <p>AAAAAAAAAAAAAAAAAAAAAAAAAAXXXXXXXXXXXXXXXAAAAAAAAAAAAAAAAAAAAAAAAAAXXXXXXXXXXXXXXX ...</p>
        </article>
    
        <article>
            <h2><a href="/note/yisvqHsknTyAKNuFng2-0A==">test1</a></h2>
            <a href="/?category=personal" class="category personal">personal</a>
            <p>www ...</p>
        </article>
    
</section>
```

"NOTEXISTING" is category parameter value.

Now the attack is quite obvious. We need to use BREACH attack to get Mr. Evil note id from encrypted communication. To do that we send to the service two categories: "/note/#&$@x" and "/note/x#&$@" (where x is in [a-zA-Z0-9_-=]), observe last packet length and if the length for first category is lower that for the second, we have found first char of Mr. Evil's note id. We can continue untill we get whole id.

For better explanation how it works google "breach attack".

Quick and ugly function to solve the challenge:
```python
def get_resp_note():
    s = get_connection()

    stuff = '#&$@'
    found_all = ''
    alphabet = string.letters+string.digits+'-_='
    while True:
        for payload in alphabet:
            data, synced_no = one_sync(s, found_all+payload+stuff)
            data2, synced_no2 = one_sync(s, found_all+stuff+payload)
            length_first, length_second = len(data[-1]), len(data2[-1])
            print(found_all+payload, length_first, length_second)

            if length_first < length_second:
                found_all += payload
                print('Found', found_all)
                break

    s.close()
```

As I wrote it almost at the end of the ctf (get the flag 15 minutes after the end of the event), it is very slow an buggy. But with some human interaction it will work.