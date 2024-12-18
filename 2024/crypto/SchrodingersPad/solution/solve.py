import socket
import binascii


# Step 3a: Reverse "alive" transformation
def reverse_modify_alive(ciphertext):
    modified = bytearray(ciphertext)
    for i in range(len(modified)):
        modified[i] = ((modified[i] ^ 0xAC) >> 1) & 0xFF
    return bytes(modified)


# Step 3b: Reverse "dead" transformation
def reverse_modify_dead(ciphertext):
    modified = bytearray(ciphertext)
    for i in range(len(modified)):
        modified[i] ^= 0xCA
        modified[i] = ((modified[i] << 1) | (modified[i] >> 7)) & 0xFF
    return bytes(modified)


# XOR operation to combine decrypted data with known plaintext
def xor_bytes(data1, data2):
    return bytes([b1 ^ b2 for b1, b2 in zip(data1, data2)])


# Step 1 & 2: Connect to the server, send plaintext, and receive encrypted data
def interact_with_server(server_ip, server_port, plaintext):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((server_ip, server_port))

    # Receive initial message and extract the secret message (c1)
    welcome_message = s.recv(4096).decode()
    print(welcome_message)

    try:
        encrypted_hex = welcome_message.split(
            "Encrypted (cat state=ERROR! 'cat not in box'): ")[-1].strip().split()[0]
        if len(encrypted_hex) % 2 != 0:
            encrypted_hex = encrypted_hex[:-1]
        c1 = binascii.unhexlify(encrypted_hex)
    except (IndexError, binascii.Error) as e:
        print(f"Error extracting the secret message: {e}")
        s.close()
        return None, None, None

    # Send plaintext (m2) to the server
    s.send(plaintext.encode())

    # Receive encrypted data (c2) and cat state
    try:
        response = s.recv(1024).decode().strip()
        print(response)
        cat_state = response.split("Encrypted (cat state=")[-1].split("): ")[0]
        encrypted_hex = response.split(
            "Encrypted (cat state=")[-1].split("): ")[1]
        if len(encrypted_hex) % 2 != 0:
            encrypted_hex = encrypted_hex[:-1]
        c2 = binascii.unhexlify(encrypted_hex)
    except (IndexError, binascii.Error) as e:
        print(f"Error extracting the encrypted response: {e}")
        s.close()
        return None, None, None

    s.close()
    return c1, c2, cat_state


# Main decryption process
def decrypt():
    server_ip = 'localhost'
    server_port = 1337

    # Step 1: Prepare the known 160-byte plaintext (m2)
    m2 = 'The sun dipped below the horizon, painting the sky in hues of pink and orange, as a cool breeze rustled through the trees, signaling the end of a peaceful day.'

    # Step 2: Get the encrypted secret message (c1) and response (c2) from the server
    c1, c2, cat_state = interact_with_server(server_ip, server_port, m2)

    if c1 is None or c2 is None or cat_state is None:
        print("Failed to retrieve or process data from the server.")
        return

    # Step 3: Reverse the transformation on c2 based on the cat state
    decrypted_c2 = reverse_modify_alive(
        c2) if cat_state == "alive" else reverse_modify_dead(c2)

    # Step 4: XOR c1 and c2 to get m1 ^ m2
    m1_xor_m2 = xor_bytes(c1, decrypted_c2)

    # Step 5: XOR the result with m2 to recover m1
    recovered_m1 = xor_bytes(m1_xor_m2, m2.encode())

    # Print the recovered secret message (m1)
    print(
        f"\nRecovered secret message (m1): {recovered_m1.decode(errors='ignore')}\n")


if __name__ == "__main__":
    decrypt()
