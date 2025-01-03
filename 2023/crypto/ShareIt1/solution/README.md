[COMMUNITY WRITEUP](https://github.com/Franc-Zar/CTFsWriteups/blob/main/1337-Intigriti-CTF/crypto/share-it-part-1/share_it.md)

#### solve.py

```py
import base64
from pwn import xor
import json

token = json.loads(base64.b64decode(input("Paste token: ")))
iv = base64.b64decode(token['iv'])

new_iv = xor(xor(b'{"admin": false,', b'{"admin": true, '), iv)

token['iv'] = base64.b64encode(new_iv).decode()

print('New token with modified IV:', base64.b64encode(
    json.dumps(token).encode()).decode())
```
