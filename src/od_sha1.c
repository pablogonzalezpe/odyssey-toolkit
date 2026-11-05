#define _POSIX_C_SOURCE 200809L

#include "od_sha1.h"
#include <string.h>

static uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

static void sha1_process_block(const uint8_t block[64], uint32_t state[5]) {
    uint32_t w[80];
    uint32_t a, b, c, d, e;
    int i;

    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (i = 16; i < 80; i++) {
        w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3]; e = state[4];

    for (i = 0; i < 80; i++) {
        uint32_t f, k, temp;
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }
        temp = rotl32(a, 5) + f + e + k + w[i];
        e = d; d = c; c = rotl32(b, 30); b = a; a = temp;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
}

void od_sha1(const uint8_t *data, size_t len, uint8_t out[20]) {
    uint32_t state[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    uint8_t block[64];
    size_t i;
    uint64_t total_bits = (uint64_t)len * 8;

    while (len >= 64) {
        sha1_process_block(data, state);
        data += 64;
        len -= 64;
    }

    memset(block, 0, 64);
    memcpy(block, data, len);
    block[len] = 0x80;

    if (len >= 56) {
        sha1_process_block(block, state);
        memset(block, 0, 64);
    }

    for (i = 0; i < 8; i++) {
        block[56 + i] = (uint8_t)(total_bits >> (56 - i * 8));
    }
    sha1_process_block(block, state);

    for (i = 0; i < 5; i++) {
        out[i * 4]     = (uint8_t)(state[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(state[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(state[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(state[i]);
    }
}
