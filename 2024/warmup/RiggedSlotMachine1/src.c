#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h> 
#include <signal.h>

#define MAX_BET 100
#define JACKPOT_THRESHOLD 133742

void handle_alarm(int sig) {
    printf("\nSlot machine overheating, please try again later!\n");
    exit(0);
}

void setup_alarm(int seconds) {
    signal(SIGALRM, handle_alarm);
    alarm(seconds);
}

void payout(int *balance) {
    if (*balance > JACKPOT_THRESHOLD) {
        char flag[64];
        FILE *f = fopen("flag.txt", "r");
        if (f == NULL) {
            printf("Flag File is Missing. Problem is Misconfigured, please contact an Admin if you are running this on the shell server.\n");
            exit(0);
        }
        fgets(flag, sizeof(flag), f);
        printf("Congratulations! You've won the jackpot! Here is your flag: %s\n", flag);
        fclose(f);
        exit(-1);
    } else {
        printf("You can't withdraw money until you win the jackpot!\n");
        exit(-1);
    }
}

void play(int bet, int *balance) {
    int outcome = rand() % 100;
    int multiplier;

    if (outcome == 0) {
        multiplier = 100;  // Jackpot multiplier
    } else if (outcome < 10) {
        multiplier = 5;  // Large win multiplier
    } else if (outcome < 15) {
        multiplier = 3;  // Medium win multiplier
    } else if (outcome < 20) {
        multiplier = 2;  // Small win multiplier
    } else if (outcome < 30) {
        multiplier = 1;  // No win, no loss
    }else{
        multiplier = 0; // Lose it all :(
    }

    int result = bet * multiplier; // Award bet

    result -= bet;  // Deduct the initial bet

    if (result > 0) {
        printf("You won $%d!\n", result);
    } else if (result < 0) {
        printf("You lost $%d.\n", -result);
    } else {
        printf("No win, no loss this time.\n");
    }

    *balance += result;
    printf("Current Balance: $%d\n", *balance);

    if (*balance <= 0) {
        printf("You're out of money! Game over!\n");
        exit(0);
    }
}

void clear_input() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    gid_t gid = getegid();
    setresgid(gid, gid, gid);

    srand(time(NULL));
    setup_alarm(180); // Don't let the them play all day

    int balance = 100; // $100 free

    printf("Welcome to the Rigged Slot Machine!\n");
    printf("You start with $100. Can you beat the odds?\n");

    while (1) {
        int bet = 0;
        printf("\nEnter your bet amount (up to $%d per spin): ", MAX_BET);
        int result = scanf("%d", &bet);

        if (result != 1) {
            printf("Invalid input! Please enter a numeric value.\n");
            clear_input();
            continue;
        } else if (bet <= 0 || bet > MAX_BET) {
            printf("Invalid bet amount! Please bet an amount between $1 and $%d.\n", MAX_BET);
            continue;
        } else if (bet > balance) {
            printf("You cannot bet more than your current balance of $%d!\n", balance);
            continue;
        }

        // Play the bet
        play(bet, &balance);

        // If the player earns a set amount, trigger auto-payout
        if (balance > JACKPOT_THRESHOLD) {
            payout(&balance);
        }
    }

    return 0;
}
