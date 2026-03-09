#include <stdio.h>
#include <string.h>

int main(void) {
    char buf[64] = {0};
    puts("Say the course code:");
    if (!fgets(buf, sizeof(buf), stdin)) {
        return 1;
    }
    buf[strcspn(buf, "\r\n")] = '\0';
    if (strcmp(buf, "COSC269") == 0) {
        puts("WIN");
        return 0;
    }
    puts("Nope");
    return 1;
}
