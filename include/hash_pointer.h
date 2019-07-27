#ifndef _1229_COIN_HASH_POINTER_H
#define _1229_COIN_HASH_POINTER_H

#include "define.h"
#include <stddef.h>
#include <openssl/sha.h>

extern char BYTE_2_CHAR[];

typedef struct hash_pointer_s hash_pointer_t;
struct hash_pointer_s {
    unsigned char hash[SHA256_DIGEST_LENGTH];
};

int hash_pointer_calc_sha256(hash_pointer_t *hptr, const objcontent_t *cnt);

int hash_pointer_write(unsigned char *buf, const hash_pointer_t *hptr);

#define hptr_hash(p) ((p)->hash)
#define hptr_ichar_1st(p, i) (BYTE_2_CHAR[(hptr_hash(p)[i] & 0x0F)])
#define hptr_ichar_2nd(p, i) (BYTE_2_CHAR[(hptr_hash(p)[i] & 0xF0) >> 4])

#endif
