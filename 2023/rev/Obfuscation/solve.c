// gcc solve.c -o solve
#include <stdio.h>
#include <stdlib.h>

int arr[] = {42, 77, 3, 8, 69, 86, 60, 99, 50, 76, 15, 14, 41, 87, 45, 61, 16, 50, 20, 5, 13, 33, 62, 70, 70, 77, 28, 85, 82, 26, 28, 32, 56, 22, 21, 48, 38, 42, 98, 20, 44, 66, 21, 55, 98, 17, 20, 93, 99, 54, 21, 43, 80, 99, 64, 98, 55, 3, 95, 16, 56, 62, 42, 83, 72, 23, 71, 61, 90, 14, 33, 45, 84, 25, 24, 96, 74, 2, 1, 92, 25, 33, 36, 6, 26, 14, 37, 33, 100, 3, 30, 1, 31, 31, 86, 92, 61, 86, 81, 38};

void deobfuscate(char *enc) {
    for (int i = 0; i < 24; ++i) {
        enc[i] ^= 0x1337 ^ arr[i % sizeof(arr)];
    }
}

int main(void)
{
    FILE *fp;
    char *enc = NULL;

    fp = fopen("output", "rb");
    if (fp == NULL) {
        perror("Error opening file");
        return -1;
    }

    enc = (char *)malloc(24);
    if (enc == NULL) {
        perror("Memory allocation error");
        fclose(fp);
        return -1;
    }

    fgets(enc, 24, fp);
    fclose(fp);

    deobfuscate(enc);
    printf("%s\n", enc);
    free(enc);
    return 0;
}