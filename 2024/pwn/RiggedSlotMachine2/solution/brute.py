from pwn import *


# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


# Binary filename
exe = './rigged_slot2'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'info'

for i in range(100):
    # Start program
    io = start()

    balance = 100  # Starting balance

    io.sendlineafter(b':', b'cat')  # Name input
    io.recvlines(3)
    io.sendline(b'10')  # $10 bet

    count = 1  # How many bets?

    while (balance > 0):
        try:
            io.sendlineafter(b':', str(10).encode())
            # Get the current balance
            io.recvuntil(b'Current Balance: ')
            balance = int(io.recvline().decode()[1:].strip('\n'))
            info('balance: ' + str(balance))
            count += 1
        except:
            # Game over
            info('total bets placed: ' + str(count))
            break
