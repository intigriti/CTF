from pwn import *
from gen_solve import make_solve_script

context.log_level = "DEBUG"

p = remote("127.0.0.1", 1351)

solve = make_solve_script().encode()
p.sendlineafter(b"Be careful what you wish for: ", solve)

p.interactive()
