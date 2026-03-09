#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int auth = 0;

void win(void) {
    puts("FLAG{format_string_write}");
    fflush(stdout);
    exit(0);
}

int main(void) {
    char name[200];
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("Name:");
    if (!fgets(name, sizeof(name), stdin)) {
        return 1;
    }
    name[strcspn(name, "\r\n")] = '\0';
    printf(name);
    puts("");

    if (auth == 0x1337) {
        win();
    }
    puts("Try again");
    return 0;
}
