#include <stdio.h>

void cheat_mode(long key1, long key2)
{
    if (key1 == 0x2323232323232323 && key2 == 0x4242424242424242)
    {
        printf("CHEAT MODE ACTIVATED!\n");
        printf("You now have access to secret developer tools...\n\n");

        FILE *file = fopen("flag.txt", "r");
        if (file == NULL)
        {
            printf("Error: Could not open flag.txt\n");
            return;
        }
        char flag[64];
        if (fgets(flag, sizeof(flag), file) != NULL)
        {
            printf("FLAG: %s\n", flag);
        }
        fclose(file);
    }
    else
    {
        printf("Unauthorized access detected! Returning to main menu...\n\n");
    }
}

void enter_cheatcode()
{
    char code[16];

    printf("Enter your cheatcode:\n");
    gets(code);
    printf("Checking cheatcode: %s!\n", code);
}

void explore_forest()
{
    printf("You are walking through a dark forest...\n");
    printf("I don't think there's any flags around here...\n\n");
}

void battle_dragon()
{
    printf("You encounter a ferocious dragon!\n");
    printf("But it's too strong for you...\n");
    printf("Only if you had some kind of cheat...\n\n");
}

void show_main_menu()
{
    printf("*****************************\n");
    printf("*       Retro2Win Game      *\n");
    printf("*****************************\n");
    printf("1. Explore the Forest\n");
    printf("2. Battle the Dragon\n");
    printf("3. Quit\n\n");
    printf("Select an option:\n");
}


int main()
{
    int choice;

    while (1)
    {
        show_main_menu();
        scanf("%d", &choice);
        getchar(); 

        switch (choice)
        {
            case 1:
                explore_forest();
                break;
            case 2:
                battle_dragon();
                break;
            case 3:
                printf("Quitting game...\n");
                return 0;
            case 1337:
                enter_cheatcode();
                break;
            default:
                printf("Invalid choice! Please select a valid option.\n");
        }
    }

    return 0;
}
