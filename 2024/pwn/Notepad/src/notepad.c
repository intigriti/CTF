// gcc -fstack-protector-all -Wl,-z,relro,-z,now chall.c -o chall

#include <stdio.h>
#include <stdlib.h> 
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

struct notes {
    char *note;
};

struct notes *notepad[5];

void setup(){
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
}

void banner(){
    printf("     __      _         ___          _ \n");
    printf("  /\\ \\ \\___ | |_ ___  / _ \\__ _  __| |\n");
    printf(" /  \\/ / _ \\| __/ _ \\/ /_)/ _` |/ _` |\n");
    printf("/ /\\  / (_) | ||  __/ ___/ (_| | (_| |\n");
    printf("\\_\\ \\/ \\___/ \\__\\___\\/    \\__,_|\\__,_|\n");
    printf("                                      \n");
} 

void createNote(){
    unsigned int idx;
    unsigned long size;

    printf("Choose the index to store your note(0-9)\n");   
    printf("> ");
    scanf("%d", &idx);
    
    if(idx >= 5) {
        printf("Wrong index!");
        exit(0);
    }
    if(notepad[idx]!=NULL){
        printf("Note is already there, remove it before overwriting it!");
        exit(0);
    }
    printf("How large you want the note to be?\n");
    printf("> ");
    scanf("%ld", &size);

    notepad[idx] = malloc(size);
    if (notepad[idx]==NULL){
        printf("[X] Something went wrong!, Try again!");
        exit(0);
    }
    printf("Add your note:\n");
    printf("> ");
    char *p = (char *)notepad[idx];
    p[read(0, notepad[idx], size) - 1] = 0;
}   

void viewNote(){
    unsigned int idx;

    printf("Choose the index of your note you want to view\n");
    printf("> ");
    scanf("%d", &idx);
    
    if(idx >= 5) {
        printf("Wrong index!");
        exit(0);
    }

    if(notepad[idx]==NULL){
        printf("Note is empty at the index %d", idx);
        exit(0);
    }

    puts(notepad[idx]);
} 

void editNote(){
    unsigned int idx;

    printf("Choose the index of your note you want to edit\n");
    printf("> ");
    scanf("%d", &idx);

    if(idx >= 5) {
        printf("Wrong index!");
        exit(0);
    }

    if(notepad[idx]==NULL){
        printf("Note is empty at the index %d", idx);
        exit(0);
    }

    printf("Your changes:\n");
    printf("> ");
    read(0, notepad[idx], 0x100);
}

void removeNote(){
    unsigned int idx;

    printf("Choose the index of your note you want to remove\n");
    printf("> ");
    scanf("%d", &idx);
    
    if(idx >= 5) {
        printf("Wrong index!");
        exit(0);
    }

    if(notepad[idx]==NULL){
        printf("Note is already empty!");
        exit(0);
    }
    free(notepad[idx]);
} 

int key = 0;

void secretNote() {
    int fd;
    ssize_t bytesRead;
    char buffer[1024];

    if (key == 0xcafebabe) {
        fd = open("flag", O_RDONLY);
        if (fd == -1) {
            perror("flag not found! If this happened on the server, contact the author please!");
            exit(1);
        }

        while ((bytesRead = read(fd, buffer, sizeof(buffer))) > 0) {
            write(STDOUT_FILENO, buffer, bytesRead);
        }
        if (bytesRead == -1) {
            perror("Error reading the file");
            close(fd);
            exit(1);
        }
        close(fd);
        exit(0);
    } else {
        printf("You don't have access!\n");
        exit(-1);
    }
}

void menu(){
    printf("\n\nChoose an option!\n");
    printf("[*] 1. Create a note\n[*] 2. View the note\n[*] 3. Edit the note\n[*] 4. Remove the note\n[*] 5. View the secret note\n[*] 6. Exit\n");
    printf("> ");
}

void main() {
    setup();
    banner();
    printf("Welcome to the notepad service!\n");
    printf("Here a gift: %p\n", &main);
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
                editNote();
                break;
            case 4:
                removeNote();
                break;
            case 5:
                secretNote();
                break;
            case 6:
                printf("See you next time, bye!\n");
                exit(0);
            default:
                printf("[X] Wrong choice\n");
                exit(0);
            }
    }
}