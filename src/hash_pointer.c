#include "hash_pointer.h"

char BYTE_2_CHAR[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

int hash_pointer_calc_sha256(hash_pointer_t *hptr, const objcontent_t *cnt) {
    int ret;
    SHA256_CTX ctx;
    if (hptr == NULL || cnt == NULL) {
        return -1;
    }

    if ((ret = SHA256_Init(&ctx)) < 0) {
        return ret;
    }
    if ((ret = SHA256_Update(&ctx, cnt->buf, cnt->len)) < 0) {
        return ret;
    }
    if ((ret = SHA256_Final((unsigned char *) hptr->hash, &ctx)) < 0) {
        return ret;
    }

    return 0;
}
