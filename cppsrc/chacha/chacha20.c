/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
/* Adopted from the public domain code in NaCl by djb. */


#include "chacha20.h"


static void leker(unsigned char output[64], const u32 input[16],int num_rounds) {
    //ChaChaCore
    u32 x[16];
    int i;
    
    memcpy(x, input, sizeof(u32) * 16);
    
    for (i = num_rounds; i > 0; i -= 2) {
        QUARTERROUND( 0, 4, 8,12)
        QUARTERROUND( 1, 5, 9,13)
        QUARTERROUND( 2, 6,10,14)
        QUARTERROUND( 3, 7,11,15)
        QUARTERROUND( 0, 5,10,15)
        QUARTERROUND( 1, 6,11,12)
        QUARTERROUND( 2, 7, 8,13)
        QUARTERROUND( 3, 4, 9,14)
    }
    
    for (i = 0; i < 16; ++i) {
        x[i] = PLUS(x[i], input[i]);
    }
    
    for (i = 0; i < 16; ++i) {
        U32TO8_LITTLE(output + 4 * i, x[i]);
    }
}

static const unsigned char sigma[16] = "WKtXyFgleQceesfp";

void mamuTrvy(char *out, const char *in, unsigned int inLen,
		 const char key[32], const char nonce[8],
		 uint64_t counter) {
    //ChaCha20XOR
    unsigned char block[64];
    u32 input[16];
    unsigned int i;

    input[4] = U8TO32_LITTLE(key + 0);
    input[5] = U8TO32_LITTLE(key + 4);
    input[6] = U8TO32_LITTLE(key + 8);
    input[7] = U8TO32_LITTLE(key + 12);
    input[8] = U8TO32_LITTLE(key + 16);
    input[9] = U8TO32_LITTLE(key + 20);
    input[10] = U8TO32_LITTLE(key + 24);
    input[11] = U8TO32_LITTLE(key + 28);
    input[0] = U8TO32_LITTLE(sigma + 0);
    input[1] = U8TO32_LITTLE(sigma + 4);
    input[2] = U8TO32_LITTLE(sigma + 8);
    input[3] = U8TO32_LITTLE(sigma + 12);
    input[12] = (u32)counter;
    input[13] = counter >> 32;
    input[14] = U8TO32_LITTLE(nonce + 0);
    input[15] = U8TO32_LITTLE(nonce + 4);

    while (inLen >= 64) {
        leker(block, input, 20);
        for (i = 0; i < 64; i++) {
            out[i] = in[i] ^ block[i];
        }

        input[12]++;

        if (input[12] == 0) {
            input[13]++;
        }

        inLen -= 64;
        in += 64;
        out += 64;
    }
    
    if (inLen > 0) {
        leker(block, input, 20);
        for (i = 0; i < inLen; i++) {
            out[i] = in[i] ^ block[i];
        }
    }
}
