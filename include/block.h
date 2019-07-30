#ifndef _1229_BLOCK_H
#define _1229_BLOCK_H

#include "hash_pointer.h"
#include "link.h"
#include "define.h"
#include <time.h>

typedef struct block_hdr_s block_hdr_t;
struct block_hdr_s {
    unsigned int version;
    time_t ts;
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

typedef struct block_tx_s block_tx_t;
struct block_tx_s {
    link_t lnk;
    hash_pointer_t hptr;
};

#define blk_hptr(p) (&(((block_t *) (p))->hptr))
#define blk_hdr(p) (&(((block_t *) (p))->hdr))
#define blk_tx(p) (&(((block_t *) (p))->tx_lnkhptr))
#define blk_save(p, b) ((((block_t *) (p))->save_func) ((const void *) (p), (const void *) (b)))
#define blk_load(p, b, h) ((((block_t *) (p))->load_func) ((void *) (p), (const void *) (b), (const void *) (h)))

int blk_init(block_t *bptr);

#endif
