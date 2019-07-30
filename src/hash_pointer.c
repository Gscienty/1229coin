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

int hash_pointer_write(unsigned char *buf, const hash_pointer_t *hptr) {
    size_t i;
    size_t off = 0;
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        buf[off++] = hptr_ichar_1st(hptr, i);
        buf[off++] = hptr_ichar_2nd(hptr, i);
    }

    return 0;
}

int hash_pointer_read(hash_pointer_t *hptr, unsigned char *buf) {
    size_t off = 0;
    size_t h_off = 0;
    for (; off < SHA256_DIGEST_LENGTH * 2; ) {
        hptr_hash(hptr)[h_off++] = CHAR_2_BYTE(buf[off]) | (CHAR_2_BYTE(buf[off + 1]) << 4);
        off += 2;
    }

    return 0;
}
