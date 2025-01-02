#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);

    char *mats[] = {
        "1. Cozy Carpet Mat - $10",
        "2. Wooden Plank Mat - $15",
        "3. Fuzzy Shag Mat - $20",
        "4. Rubberized Mat - $12",
        "5. Luxury Velvet Mat - $25",
        "6. Mysterious Flag Mat - $1337"
    };

    char buf[128];
    char flag[64];
    char *flag_ptr = flag;

    gid_t gid = getegid();
    setresgid(gid, gid, gid);

    FILE *file = fopen("flag.txt", "r");
    if (file == NULL) {
        printf("You have a flag.txt, right??\n");
        exit(0);
    }

    puts("Welcome to the Floor Mat store! It's kind of like heaven.. for mats.\n\nPlease choose from our currently available floor mats\n\nNote: Out of stock items have been temporarily delisted\n");

    printf("Please select a floor mat:\n\n");
    for (int i = 0; i < 5; i++) {
        printf("%s\n", mats[i]);
    }

    int choice;
    printf("\nEnter your choice:\n");
    scanf("%d", &choice);

    if (choice < 1 || choice > 6) {
        printf("Invalid choice!\n\n");
        exit(1);
    }

    int matIndex = choice - 1;

    while (getchar() != '\n');

    if (matIndex == 5) {
        fgets(flag, sizeof(flag), file);
    }

    printf("\nPlease enter your shipping address:\n");

    fgets(buf, sizeof(buf), stdin);

    printf("\nYour floor mat will be shipped to:\n\n");

    printf(buf);

    return 0;
}
