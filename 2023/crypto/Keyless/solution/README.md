[FULL VIDEO WRITEUP](https://youtu.be/CsyQFzTJ09w?t=600)

#### solve.py

```py
def decrypt(encrypted_message):
    decrypted_message = ""
    for char in encrypted_message:
        c_reverse = ord(char) ^ 23
        b_reverse = (c_reverse + 7) // 3
        a_reverse = (b_reverse - 5) ^ 42
        decrypted_char = (a_reverse - 10) // 2
        decrypted_message += chr(decrypted_char)
    return decrypted_message

with open("flag.txt.enc", "r") as file:
    encrypted_flag = file.read()

decrypted_flag = decrypt(encrypted_flag)
print(decrypted_flag)
```
