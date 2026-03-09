#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win(void) {
    puts("FLAG{stack_overflow_win}");
    fflush(stdout);
    exit(0);
}

void vuln(void) {
    char buf[64];
    puts("Overflow me:");
    read(0, buf, 256);
    puts("Done");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    return 0;
}
