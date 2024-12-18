from pwn import *
import random


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

# Start program
io = start()

balance = 100  # Starting balance

io.sendlineafter(b':', b'cat')  # Name input
io.recvlines(3)
io.sendline(b'1')  # Start with $1 bet

count = 1  # How many bets?
random_bet = random.randint(1, 99)  # Start with a random bet

while (balance > 0):
    try:
        # Place a random bet
        info('placing bet: ' + str(random_bet))
        io.sendlineafter(b':', str(random_bet).encode())
        # Get the current balance
        io.recvuntil(b'Current Balance: ')
        balance = int(io.recvline().decode()[1:].strip('\n'))
        info('balance: ' + str(balance))
        # Pick a new random bet
        random_bet = random.randint(1, balance)
        if random_bet > 100:
            random_bet = random_bet % 100
        count += 1
    except:
        # Game over
        info('total bets placed: ' + str(count))
        exit(0)
