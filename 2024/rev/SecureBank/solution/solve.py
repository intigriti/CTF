def obscure_key(key):
    key ^= 0xA5A5A5A5
    # Make sure it stays within 32 bits
    key = (key << 3) & 0xFFFFFFFF | (key >> 29)
    key *= 0x1337
    key &= 0xFFFFFFFF  # Keep it within 32-bit unsigned integer bounds
    key ^= 0x5A5A5A5A
    return key


def generate_2fa_code(pin):
    key = pin * 0xBEEF
    key &= 0xFFFFFFFF  # Ensure it's 32-bit
    code = key

    for i in range(10):
        key = obscure_key(key)
        code ^= key
        code = (code << 5) & 0xFFFFFFFF | (
            code >> 27)  # Rotate and ensure 32 bits
        code += (key >> (i % 5)) ^ (key << (i % 7))
        code &= 0xFFFFFFFF  # Keep it within 32-bit unsigned integer bounds

    code &= 0xFFFFFF  # Ensure the 2FA code is 24 bits (6 digits)
    return code


if __name__ == "__main__":
    pin = 1337  # The superadmin PIN
    expected_code = generate_2fa_code(pin)
    print(f"Expected 2FA Code: {expected_code}")
