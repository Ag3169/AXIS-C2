#include "includes.h"
#include "rand.h"

static uint32_t x, y, z, w;

void rand_init(void) {
    x = time(NULL);
    y = getpid() ^ getppid();
    z = clock();
    w = z ^ y;
}

uint32_t rand_next(void) {
    uint32_t t = x ^ (x << 11);
    x = y; y = z; z = w;
    w = w ^ (w >> 19) ^ t ^ (t >> 8);
    return w;
}

void rand_str(char *str, int len) {
    for (int i = 0; i < len; i++) {
        str[i] = rand_next() % (0x7E - 0x20 + 1) + 0x20;
    }
}

void rand_alpha_str(char *str, int len) {
    char alpha[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    int alpha_len = sizeof(alpha) - 1;
    
    for (int i = 0; i < len; i++) {
        str[i] = alpha[rand_next() % alpha_len];
    }
}
