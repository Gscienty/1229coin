#include "block.h"
#include <memory.h>

static int blk_save_func(void *blk_ptr, const char *base);

static int blk_load_func(void *blk_ptr, const char *base, const unsigned char hash[SHA256_DIGEST_LENGTH]);

int blk_init(block_t *bptr) {
    if (bptr == NULL) {
        return -1;
    }

    bptr->hdr.version = _1229_COIN_VERSION;
    memset(bptr->hdr.p_hptr.hash, 0, SHA256_DIGEST_LENGTH);
    memset(bptr->hdr.m_hptr.hash, 0, SHA256_DIGEST_LENGTH);
    memset(bptr->hdr.nonce, 0, _1229_COIN_NONCE_LEN);
    bptr->hdr.hard_lv = 0;
    
    lnk_hdr_init(&bptr->tx_lnkhptr);

    bptr->save_func = blk_save_func;

    return 0;
}

static int blk_save_func(void *blk_ptr, const char *base) {
    block_t *blk = (block_t *) blk_ptr;

    // TODO

    return 0;
}

static int blk_load_func(void *blk_ptr, const char *base, const unsigned char hash[SHA256_DIGEST_LENGTH]) {
    block_t *blk = (block_t *) blk_ptr;

    // TODO

    return 0;
}
