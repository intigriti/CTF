#include <stdio.h>
#include <stdlib.h> 
#include <string.h>

struct notes {
    char note[150];
};

struct notes *notepad[10];

void setup(){
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
} 

void banner(){
    printf("     __      _         ___          _         ____  \n");
    printf("  /\\ \\ \\___ | |_ ___  / _ \\__ _  __| | /\\   /\\___ \\ \n");
    printf(" /  \\/ / _ \\| __/ _ \\/ /_)/ _` |/ _` | \\ \\ / / __) |\n");
    printf("/ /\\  / (_) | ||  __/ ___/ (_| | (_| |  \\ V / / __/ \n");
    printf("\\_\\ \\/ \\___/ \\__\\___\\/    \\__,_|\\__,_|   \\_/ |_____|\n");
    printf("                                                    \n");
}

void createNote(){
    unsigned int idx;
    char n[150];

    printf("Choose the index to store your note(0-9)\n");
    printf("> ");
    scanf("%d", &idx);
    
    if(idx >= 10) {
        printf("Wrong index!");
        exit(0);
    }
    if(notepad[idx]!=NULL){
        printf("Note already exists!");
        exit(0);
    }

    notepad[idx] = malloc(sizeof(struct notes));
    if (notepad[idx]==NULL){
        printf("[X] Something went wrong!, Try again!");
        exit(0);
    }
    printf("Add your note:\n");
    printf("> ");
    scanf("%149s", n);
    strcpy(notepad[idx]->note, n); 
}   

void viewNote(){
    unsigned int idx;

    printf("Choose the index of your note you want to view\n");
    printf("> ");
    scanf("%d", &idx);
    
    if(idx >= 10) {
        printf("Wrong index!");
        exit(0);
    }

    if(notepad[idx]==NULL){
        printf("Note is empty at the index %d", idx);
        exit(0);
    }

    printf(notepad[idx]->note);
} 

void removeNote(){
    unsigned int idx;

    printf("Choose the index of your note you want to remove\n");
    printf("> ");
    scanf("%d", &idx);
    
    if(idx >= 10) {
        printf("Wrong index!");
        exit(0);
    }

    if(notepad[idx]==NULL){
        printf("Note is already empty!");
        exit(0);
    }
    free(notepad[idx]);
    notepad[idx] = 0;
} 

void menu(){
    printf("\n\nChoose an option!\n");
    printf("[*] 1. Create a note\n[*] 2. View the note\n[*] 3. Remove the note\n[*] 4. Exit\n");
    printf("> ");
}

void main() {
    setup();
    banner();
    printf("Welcome to the notepad service v2!\n");
    while (1){
        menu();
        unsigned int choice;
        scanf("%d", &choice);
        switch(choice){
            case 1:
                createNote();
                break;
            case 2:
                viewNote();
                break;
            case 3:
                removeNote();
                break;
            case 4:
                printf("See you next time, bye!\n");
                exit(0);
            default:
                printf("[X] Wrong choice\n");
                exit(0);
            }
    }
}
