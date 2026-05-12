#include <stdint.h>
#include <string.h>

static uint8_t LUT[256];
static uint8_t INV_LUT[256];

static inline uint8_t rol8(uint8_t v, int s) {
    return (v << s) | (v >> (8 - s));
}

void init_lut(void) {
    for (int i = 0; i < 256; i++) {
        int ones = __builtin_popcount(i);
        uint8_t v;
        if (ones > 4)
            v = rol8(i, 5);
        else if (ones < 4)
            v = rol8(i, 3);
        else
            v = i;
        LUT[i] = v;
        INV_LUT[v] = i;
    }
}

static inline void transpose8(uint8_t *x) {
    uint64_t t = ((uint64_t)x[0] << 0)  |
                 ((uint64_t)x[1] << 8)  |
                 ((uint64_t)x[2] << 16) |
                 ((uint64_t)x[3] << 24) |
                 ((uint64_t)x[4] << 32) |
                 ((uint64_t)x[5] << 40) |
                 ((uint64_t)x[6] << 48) |
                 ((uint64_t)x[7] << 56);
    uint64_t s;
    s = (t ^ (t >> 7)) & 0x00AA00AA00AA00AAULL; t ^= s ^ (s << 7);
    s = (t ^ (t >> 14)) & 0x0000CCCC0000CCCCULL; t ^= s ^ (s << 14);
    s = (t ^ (t >> 28)) & 0x00000000F0F0F0F0ULL; t ^= s ^ (s << 28);
    x[0] = (t >> 0)  & 0xFF;
    x[1] = (t >> 8)  & 0xFF;
    x[2] = (t >> 16) & 0xFF;
    x[3] = (t >> 24) & 0xFF;
    x[4] = (t >> 32) & 0xFF;
    x[5] = (t >> 40) & 0xFF;
    x[6] = (t >> 48) & 0xFF;
    x[7] = (t >> 56) & 0xFF;
}

static void x_pass(uint8_t cube[64]) {
    for (int i = 0; i < 64; i++) cube[i] = LUT[cube[i]];
}
static void x_pass_inv(uint8_t cube[64]) {
    for (int i = 0; i < 64; i++) cube[i] = INV_LUT[cube[i]];
}

static void transpose_xy(uint8_t cube[64]) {
    uint8_t tmp[8];
    for (int z = 0; z < 8; z++) {
        for (int i = 0; i < 8; i++) tmp[i] = cube[z * 8 + i];
        transpose8(tmp);
        for (int i = 0; i < 8; i++) cube[z * 8 + i] = tmp[i];
    }
}

static void transpose_xz(uint8_t cube[64]) {
    uint8_t tmp[8];
    for (int y = 0; y < 8; y++) {
        for (int z = 0; z < 8; z++) tmp[z] = cube[y * 8 + z];
        transpose8(tmp);
        for (int z = 0; z < 8; z++) cube[y * 8 + z] = tmp[z];
    }
}

static void mix512(uint8_t cube[64]) {
    x_pass(cube);
    transpose_xy(cube);
    x_pass(cube);
    transpose_xy(cube);
    transpose_xz(cube);
    x_pass(cube);
    transpose_xz(cube);
}

static void unmix512(uint8_t cube[64]) {
    transpose_xz(cube);
    x_pass_inv(cube);
    transpose_xz(cube);
    transpose_xy(cube);
    x_pass_inv(cube);
    transpose_xy(cube);
    x_pass_inv(cube);
}

static void xor_key(uint8_t *block, const uint8_t *key) {
    for (int i = 0; i < 64; i++) block[i] ^= key[i];
}

void encrypt_block(const uint8_t plain[64], const uint8_t key[64], uint8_t cipher[64]) {
    memcpy(cipher, plain, 64);
    for (int round = 0; round < 3; round++) {
        xor_key(cipher, key);
        mix512(cipher);
    }
}

void decrypt_block(const uint8_t cipher[64], const uint8_t key[64], uint8_t plain[64]) {
    memcpy(plain, cipher, 64);
    for (int round = 0; round < 3; round++) {
        unmix512(plain);
        xor_key(plain, key);
    }
}
