#ifndef _1229_BLOCK_H
#define _1229_BLOCK_H

#include "hash_pointer.h"
#include "link.h"
#include "define.h"

typedef struct block_hdr_s block_hdr_t;
struct block_hdr_s {
    unsigned int version;
    hash_pointer_t p_hptr;
    hash_pointer_t m_hptr;
    unsigned int hard_lv;
    unsigned char nonce[_1229_COIN_NONCE_LEN];
};

typedef struct block_s block_t;
struct block_s {
    hash_pointer_t hptr;

    block_hdr_t hdr;
    link_t tx_lnkhptr;

    save_node_fptr save_func;
    load_node_fptr load_func;
};

int blk_init(block_t *bptr);

#endif
