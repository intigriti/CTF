#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct Drone {
    int id;
    char *status;
    void (*start_route)(struct Drone *);
    void (*end_route)(struct Drone *);
} Drone;

Drone *fleet[10];
char *flight_data = NULL;

void print_drone_manual() {
    FILE *file = fopen("drone_manual.txt", "r");
    if (file == NULL) {
        printf("Error: Unable to access drone manual.\n");
        return;
    }
    char ch;
    while ((ch = fgetc(file)) != EOF) {
        putchar(ch);
    }
    fclose(file);
}

void start_route(Drone *d) {
    printf("Drone %d starting its route.\n", d->id);
}

void end_route(Drone *d) {
    printf("Drone %d ending its route.\n", d->id);
    free(d);
}

void deploy_drone() {
    for (int i = 0; i < 10; i++) {
        if (fleet[i] == NULL) {
            fleet[i] = (Drone *)malloc(sizeof(Drone));
            fleet[i]->id = i + 1;
            fleet[i]->status = "ready";
            fleet[i]->start_route = start_route;
            fleet[i]->end_route = end_route;
            printf("Drone %d deployed and ready for a route.\n", fleet[i]->id);
            return;
        }
    }
    printf("Error: No available slots for new drones.\n");
}

void retire_drone() {
    int id;
    printf("Enter drone ID to retire: ");
    scanf("%d", &id);

    if (id > 0 && id <= 10 && fleet[id - 1] != NULL) {
        printf("Freeing drone memory at %p\n", (void*)fleet[id - 1]);
        fleet[id - 1]->end_route(fleet[id - 1]);
        printf("Drone %d retired.\n", id);
    } else {
        printf("Error: Drone not found.\n");
    }
}

void enter_drone_route() {
    flight_data = (char *)malloc(sizeof(Drone));
    printf("Allocated route buffer at %p\n", (void*)flight_data);
    printf("Enter the drone route data: ");
    scanf("%63s", flight_data);
    printf("Drone route data recorded.\n");
}

void start_drone_route() {
    int id;
    printf("Enter drone ID to start its route: ");
    scanf("%d", &id);

    if (id > 0 && id <= 10 && fleet[id - 1] != NULL) {
        fleet[id - 1]->start_route(fleet[id - 1]);
    } else {
        printf("Error: Drone not found.\n");
    }
}

void menu() {
    printf("\nDrone Fleet Control System\n");
    printf("1. Deploy drone\n");
    printf("2. Retire drone\n");
    printf("3. Start drone route\n");
    printf("4. Enter drone route\n");
    printf("5. Exit\n");
    printf("Choose an option: ");
}

int main() {
    int choice;

    while (1) {
        menu();
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                deploy_drone();
                break;
            case 2:
                retire_drone();
                break;
            case 3:
                start_drone_route();
                break;
            case 4:
                enter_drone_route();
                break;
            case 5:
                exit(0);
            default:
                printf("Invalid option. Try again.\n");
        }
    }
    return 0;
}
