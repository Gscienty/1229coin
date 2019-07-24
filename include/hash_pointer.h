#ifndef _1229_COIN_HASH_POINTER_H
#define _1229_COIN_HASH_POINTER_H

#include <stddef.h>
#include <openssl/sha.h>

typedef struct hash_pointer_s hash_pointer_t;
struct hash_pointer_s {
    unsigned char hash[64];
};

#define hptr_hash(p) ((p)->hash)

int hash_pointer_calc_sha256(unsigned char hash[64], const void *base, const size_t len);

#endif
