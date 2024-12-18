#!/usr/bin/env python3
from pwn import *


def gcm_solver(messages: list[str], forge: bytes):
    return subprocess.check_output(["./target/release/solve", "-m", *messages[:3], "-f", forge.hex()])


def xor_last(ciphertext: bytes):
    return ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])


def connect():
    # p = process("../conversationalist/app/target/release/conversationalist")
    p = remote("localhost", 1337)

    p.recvline()

    messages = []
    while line := p.recvline().strip():
        messages.append(line.decode().split(" ")[1])

    info(f"Received {len(messages)} messages")

    return p, messages


p, messages = connect()

ciphertext = bytes.fromhex(messages[0].split(":")[1])
# Alter the message slightly to let the application echo the plaintext
ciphertext = xor_last(ciphertext)
# Forge tag using nonce-reuse attack
tagged = gcm_solver(messages, ciphertext)
info(f"Before:  {messages[0]}")
info(f"Altered: {tagged.decode()}")

p.sendlineafter(b"> ", tagged)

# Receive plaintext response, XOR last byte back to original
p.recvuntil(b"You said: ")
plaintext = safeeval.const(p.recvline()).encode()
plaintext = xor_last(plaintext)
info(f"Leaked plaintext: {plaintext}")

p.close()

p, messages = connect()

ciphertext = bytes.fromhex(messages[0].split(":")[1])

# We will receive the same message again, now knowing the plaintext
keystream = xor(ciphertext, plaintext)
# With the keystream known, we can encrypt a plaintext to a ciphertext, and then tag it
target_plaintext = b"Give me the flag"
target_ciphertext = xor(target_plaintext, keystream, cut="left")
info(f"Target ciphertext: {target_ciphertext.hex()} ({target_plaintext!r})")

tagged = gcm_solver(messages, target_ciphertext)
info(f"Forged flag message: {tagged.decode()}")
p.sendlineafter(b"> ", tagged)

# Application will now send the flag encrypted
p.recvuntil(b"< ")
flag_ciphertext = p.recvline().decode().split(":")[1]
flag_ciphertext = bytes.fromhex(flag_ciphertext)
# We can simply decrypt it with the known keystream
flag = xor(flag_ciphertext, keystream, cut="left")
print(flag)

p.close()
