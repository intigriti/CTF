If you run `file` command you can see its lua bytecode. Find a decompiler. We used `unluac`. After decompiling, we get an obfuscated lua file. So now we need to reverse the obfuscated file. We can do different things. We printed the opcodes and based on that we looked at interesting opcodes. If we run the chall its some flagchecker. Flag length is 39 chars. We can see the check in the code aswell. In opcode `61` it returns `n[e[2]]`. The opcode is called almost at the end before the wrong flag response of the binary. If we print that value we see 39 times `false`. So lets change the first char to `I` and we indeed see the first value is changed to true. Based on this we can bruteforce the flag.

[FULL OFFICIAL WRITEUP](https://github.com/D13David/ctf-writeups/blob/main/1337uplive/rev/lua/README.md)