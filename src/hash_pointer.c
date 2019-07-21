#include "hash_pointer.h"
#include <stdio.h>

int calc_sha256(unsigned char hash[SHA256_DIGEST_LENGTH], void *base, size_t len) {
    int ret;
    SHA256_CTX ctx;
    if (base == NULL || len == 0) {
        return -1;
    }

    if ((ret = SHA256_Init(&ctx)) < 0) {
        return ret;
    }
    if ((ret = SHA256_Update(&ctx, base, len)) < 0) {
        return ret;
    }
    if ((ret = SHA256_Final((unsigned char *) hash, &ctx)) < 0) {
        return ret;
    }

    return 0;
}