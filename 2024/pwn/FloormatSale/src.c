#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

int employee = 0;

void employee_access() {
    if (employee != 0) {
        char flag[64];
        FILE *f = fopen("flag.txt", "r");
        if (f == NULL) {
            printf("Flag File is Missing. Problem is Misconfigured, please contact an Admin if you are running this on the shell server.\n");
            exit(0);
        }
        fgets(flag, sizeof(flag), f);
        printf("Exclusive Employee-only Mat will be delivered to: %s\n", flag);
        fclose(f);
    } else {
        printf("\nAccess Denied: You are not an employee!\n");
    }
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);

    char *mats[] = {
        "1. Cozy Carpet Mat - $10",
        "2. Wooden Plank Mat - $15",
        "3. Fuzzy Shag Mat - $20",
        "4. Rubberized Mat - $12",
        "5. Luxury Velvet Mat - $25",
        "6. Exclusive Employee-only Mat - $9999"
    };

    char buf[256];

    gid_t gid = getegid();
    setresgid(gid, gid, gid);

    puts("Welcome to the Floor Mat Mega Sale!\n\nPlease choose from our currently available floor mats:\n");

    printf("Please select a floor mat:\n\n");
    for (int i = 0; i < 6; i++) {
        printf("%s\n", mats[i]);
    }

    int choice;
    printf("\nEnter your choice:\n");
    scanf("%d", &choice);

    if (choice < 1 || choice > 6) {
        printf("Invalid choice!\n\n");
        exit(1);
    }

    while (getchar() != '\n');

    printf("\nPlease enter your shipping address:\n");
    fgets(buf, sizeof(buf), stdin);

    printf("\nYour floor mat will be shipped to:\n\n");
    printf(buf);

    if (choice == 6) {
        employee_access();
    }

    return 0;
}
