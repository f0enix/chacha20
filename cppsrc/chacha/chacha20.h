/*
 * chacha20.h - header file for ChaCha20 implementation.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
// github.com/Matchstic/Distributed-Classes/tree/master/Distributed%20Classes/Crypto/chacha
#ifndef FREEBL_CHACHA20_H_
#define FREEBL_CHACHA20_H_
#define CHACHA_IV_SIZE 8
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "ecrypt-portable.h"
#include "base64.h"

#ifdef __cplusplus
extern "C" {
#endif


#define ROTATE(v, c) ROTL32((v), (c))
#define XOR(v, w) ((v) ^ (w))
#define PLUS(x, y) ((x) + (y))
     
#define QUARTERROUND(a,b,c,d) \
  x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]),16); \
  x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]),12); \
  x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]), 8); \
  x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]), 7);

/* ChaCha20XOR encrypts |inLen| bytes from |in| with the given key and
 * nonce and writes the result to |out|, which may be equal to |in|. The
 * initial block counter is specified by |counter|. */
extern void mamuTrvy( char *out,
                        const char *in, unsigned int inLen,
                        const  char key[32],
                        const char nonce[8],
                        uint64_t counter);

#define encryptChacha(plainText, key, iv)({\
    size_t bufsize = strlen(plainText);\
    char * buf = (char*)malloc(bufsize);\
    mamuTrvy(buf, plainText, bufsize, key, iv, 0);\
    int outLen;\
    char* base64Encoded = base64(buf, (int)bufsize, &outLen);\
    base64Encoded;\
})

#define decryptChacha(encryptedText, key, iv)({\
    int bufsize;\
    unsigned char* decoded = unbase64(encryptedText, (int)strlen(encryptedText), &bufsize);\
    char* buf = (char*)malloc(bufsize+1);\
    memset(buf, '\0', bufsize+1);\
    mamuTrvy(buf, (char*)decoded, bufsize, key, iv, 0);\
    free(decoded);\
    buf;\
})

#ifdef __cplusplus
}
#endif
#endif  /* FREEBL_CHACHA20_H_ */
