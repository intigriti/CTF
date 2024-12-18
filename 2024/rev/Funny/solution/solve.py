import marshal
import dis
import sys

assert tuple(sys.version_info)[:3] == (3, 13, 0), "This challenge was compiled on python3.13, so this solver only works if you run it on that same version"

try:
    with open("./challenge.pyc", "rb") as f:
        # skip the metadata and dump the code object
        f.seek(16)
        code = marshal.load(f)
except FileNotFoundError:
    print("put challenge.pyc in the same diectory as this solver")
    exit()

# uncomment to dump the disassembly of the code obj
# with open("disasm.txt", "w") as file:
#     dis.dis(code, file=file)
# exit()

# positional information is stored in co_positions
positions = list(code.co_positions())

# you can check manually to see all the names are between lines 24-30, so allocate 7 rows each of a massive length to store the source
rows = [bytearray(b" " * 0x1000) for _ in range(7)]

for i, pos in enumerate(positions):
    # ignore any positional info that is blank or isnt between lines 24-30
    start_lineno, end_lineno, start_pos, end_pos = pos
    if start_lineno is None or not (24 <= start_lineno <= 30):
        continue

    # each instruction in python is 2 bytes with the first byte being the opcode and second one being the operand
    insn = code.co_code[i*2:i*2+2]
    opcode, operand = insn[0], insn[1]

    # we only care about the LOAD_NAME instructions
    if opcode != dis.opmap['LOAD_NAME']:
        continue

    assert start_lineno == end_lineno # should always pass in this case
    idx = start_lineno - 24

    # the operand holds the index of the name in co_names
    src = code.co_names[operand] + ";"
    assert len(src) == end_pos - start_pos + 1

    rows[idx][start_pos:end_pos] = src.encode()

# dump the key
with open("out_key.txt", "w") as file:
    for row in rows:
        file.write(row.rstrip().decode() + "\n")

print("ascii art output to out_key.txt")
# P05IT1ON4L_INF0RM4TION_1S_GR34T_

# a bit overkill, you can just hardcode the iv positions once you decrypt the message
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
msg = unpad(AES.new(code.co_consts[12], AES.MODE_CBC, code.co_consts[13]).decrypt(code.co_consts[11]), AES.block_size)
iv_positions = eval(msg.decode().split("\n")[5])

# dump the iv
iv = "".join(chr(rows[y][x]) for x, y in iv_positions)
print(f"{iv = !s}")