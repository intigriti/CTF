[COMMUNITY WRITEUP](https://github.com/Franc-Zar/CTFsWriteups/blob/main/1337-Intigriti-CTF/crypto/share-it-part-2/share_it.md)

#### solve.py

```py
import requests
import base64
import json
from pwn import xor
import binascii

host = 'http://localhost:1337'

orig_pt = b'{"username": "012", "first_name": "345", "last_name": "6789abc", "admin": false}'

r = requests.post(f'{host}/register', data={"username": "bla",
                                            "first_name": "lel", "last_name": "hihi123"}, allow_redirects=False)

token = json.loads(base64.b64decode(r.cookies['token']))
c = base64.b64decode(token['user_dict'])

# extra space since "true" is one char less than "false"
c_new_bytes = xor(xor(orig_pt[-16:], b' "admin": true }'), c[-16*3:-16*2])
c_new = c[:-16*3] + c_new_bytes + c[-16*2:]
token['user_dict'] = base64.b64encode(c_new).decode()

token_cookie = base64.b64encode(json.dumps(
    token).encode()).decode()
r = requests.get(f'{host}', cookies={'token': token_cookie})

mod_pt = r.text[16:-1].encode().decode(
    'unicode_escape').encode('raw_unicode_escape')

c_new_bytes = xor(
    xor(mod_pt[-16*2:-16*1], orig_pt[-16*2:-16*1]), c_new[-16*4:-16*3])
c_new = c_new[:-16*4] + c_new_bytes + c_new[-16*3:]
token['user_dict'] = base64.b64encode(c_new).decode()

token_cookie = base64.b64encode(json.dumps(
    token).encode()).decode()
r = requests.get(f'{host}', cookies={'token': token_cookie})

mod_pt = r.text[16:-1].encode().decode(
    'unicode_escape').encode('raw_unicode_escape')

c_new_bytes = xor(
    xor(mod_pt[-16*3:-16*2], orig_pt[-16*3:-16*2]), c_new[-16*5:-16*4])
c_new = c_new[:-16*5] + c_new_bytes + c_new[-16*4:]
token['user_dict'] = base64.b64encode(c_new).decode()

token_cookie = base64.b64encode(json.dumps(
    token).encode()).decode()
r = requests.get(f'{host}', cookies={'token': token_cookie})

mod_pt = r.text[16:-1].encode().decode(
    'unicode_escape').encode('raw_unicode_escape')

c_new_bytes = xor(
    xor(mod_pt[-16*4:-16*3], orig_pt[-16*4:-16*3]), c_new[-16*6:-16*5])
c_new = c_new[:-16*6] + c_new_bytes + c_new[-16*5:]
token['user_dict'] = base64.b64encode(c_new).decode()


print("Calculating IV...")

token_cookie = base64.b64encode(json.dumps(
    token).encode()).decode()
r = requests.get(f'{host}?debug_iv={"0"*32}', cookies={'token': token_cookie})

mod_pt = r.text[16:-1].encode().decode(
    'unicode_escape').encode('raw_unicode_escape')

target = b'{"username":"AAA'

iv = xor(mod_pt[:16], target)

print("token:", token_cookie)
print("IV:", binascii.hexlify(iv))
```
