from pwn import *
from Crypto.Util.number import *
import time

context.log_level = "DEBUG"

SIZE = 32

conn = connect("localhost", 1337)
conn.recvuntil(b"n=")
n = int(conn.recvuntil(b"\n").strip().decode())
conn.recvuntil(b"e=")
e = int(conn.recvuntil(b"\n").strip().decode())
conn.recvuntil(b"ck=")
ck = int(conn.recvuntil(b"\n").strip().decode())

start = time.time()
meetinthemiddle = {}
for i in range(1, 2**(SIZE//2+2)):
    z = pow(i, e, n)
    meetinthemiddle[(ck*inverse(z, n)) % n] = i

k = -1
for i in range(1, 2**(SIZE//2+2)):
    if pow(i, e, n) in meetinthemiddle:
        k = i*meetinthemiddle[pow(i, e, n)]
        print(f"Found {k=}")
        break

print(time.time()-start)

if k == -1:
    print("Key not found, restart script")
    conn.close()
    exit()

conn.send(str(k).encode()+b"\n")
conn.interactive()
