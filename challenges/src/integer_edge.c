#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    uint32_t x = 0;
    puts("Give me a number (uint32):");
    if (scanf("%u", &x) != 1) {
        return 1;
    }

    int32_t s = (int32_t)x;
    if (s < 0 && s + 100 == 42) {
        puts("FLAG{integer_wraparound_path}");
        return 0;
    }
    puts("No win");
    return 1;
}
