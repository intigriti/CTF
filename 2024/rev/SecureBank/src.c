#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SUPERADMIN_PIN 1337
#define FLAG "INTIGRITI{fake_flag}"

void banner() {
    printf("****************************************\n");
    printf("*         Welcome to SecureBank        *\n");
    printf("*    Your trusted partner in security  *\n");
    printf("****************************************\n\n");
}

void login_message() {
    printf("========================================\n");
    printf("=   SecureBank Superadmin Login System =\n");
    printf("========================================\n\n");
}

unsigned int obscure_key(unsigned int key) {
    key ^= 0xA5A5A5A5;
    key = (key << 3) | (key >> 29);
    key *= 0x1337;
    key ^= 0x5A5A5A5A;
    return key;
}

unsigned int generate_2fa_code(unsigned int pin) {
    unsigned int key = pin * 0xBEEF;
    unsigned int code = key;
    
    for (int i = 0; i < 10; i++) {
        key = obscure_key(key);
        code ^= key;
        code = (code << 5) | (code >> 27);
        code += (key >> (i % 5)) ^ (key << (i % 7));
    }

    code &= 0xFFFFFF;
    return code;
}

void validate_2fa_code(unsigned int input_code, unsigned int expected_code) {
    if (input_code == expected_code) {
        printf("Access Granted! Welcome, Superadmin!\n");
        printf("Here is your flag: %s\n", FLAG);
    } else {
        printf("Access Denied! Incorrect 2FA code.\n");
    }
}

int main() {
    unsigned int pin, input_code, generated_code;

    banner();
    login_message();

    // PIN Verification
    printf("Enter superadmin PIN: ");
    scanf("%u", &pin);

    if (pin != SUPERADMIN_PIN) {
        printf("Access Denied! Incorrect PIN.\n");
        return 1;
    }

    // 2FA Code Generation and Validation
    generated_code = generate_2fa_code(pin);
    printf("Enter your 2FA code: ");
    scanf("%u", &input_code);

    validate_2fa_code(input_code, generated_code);

    return 0;
}
