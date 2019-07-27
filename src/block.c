#include "hash_pointer.h"
#include "objfs.h"
#include "block.h"
#include <memory.h>
#include <malloc.h>

static int blk_save_func(const void *blk_ptr, const void *repo);

static int blk_load_func(void *blk_ptr, const void *repo, const void *hash);

int blk_init(block_t *bptr) {
    if (bptr == NULL) {
        return -1;
    }

    bptr->hdr.version = _1229_COIN_VERSION;
    memset(hptr_hash(&blk_hdr(bptr)->p_hptr), 0, SHA256_DIGEST_LENGTH);
    memset(hptr_hash(&blk_hdr(bptr)->m_hptr), 0, SHA256_DIGEST_LENGTH);
    memset(blk_hdr(bptr)->nonce, 0, _1229_COIN_NONCE_LEN);
    bptr->hdr.hard_lv = 0;
    
    lnk_hdr_init(blk_tx(bptr));

    bptr->save_func = blk_save_func;
    bptr->load_func = blk_load_func;

    return 0;
}

static int blk_save_func(const void *blk, const void *repo) {
    size_t tx_count = 0;
    objcontent_t cnt;
    link_t *tx_itr;
    size_t off = 0;
    size_t i;
    block_tx_t *btx = NULL;
    cnt.len = 4 * 2 // version
        + 1
        + SHA256_DIGEST_LENGTH * 2  // p_hptr
        + 1
        + SHA256_DIGEST_LENGTH * 2  // m_hptr
        + 1
        + 4 * 2 // hard_lv
        + 1
        + _1229_COIN_NONCE_LEN * 2  // nonce;
        + 1;

    for (tx_itr = lnk_next(blk_tx(blk)); tx_itr != blk_tx(blk); tx_itr = lnk_next(tx_itr)) {
        tx_count++;
    }
    cnt.len += tx_count * (SHA256_DIGEST_LENGTH * 2 + 1);

    cnt.buf = (unsigned char *) malloc(cnt.len);
    if (cnt.buf == NULL) {
        return -1;
    }

    sprintf((char *) cnt.buf, "%08X\n", blk_hdr(blk)->version);
    off = 9;

    hash_pointer_write(cnt.buf + off, &blk_hdr(blk)->p_hptr);
    off += SHA256_DIGEST_LENGTH * 2;
    cnt.buf[off++] = '\n';
    hash_pointer_write(cnt.buf + off, &blk_hdr(blk)->m_hptr);
    off += SHA256_DIGEST_LENGTH * 2;
    cnt.buf[off++] = '\n';

    sprintf((char *) (cnt.buf + off), "%08X\n", blk_hdr(blk)->hard_lv);
    off += 9;

    for (i = 0; i < _1229_COIN_NONCE_LEN; i++) {
        cnt.buf[off++] = BYTE_2_CHAR[blk_hdr(blk)->nonce[i] & 0x0F];
        cnt.buf[off++] = BYTE_2_CHAR[(blk_hdr(blk)->nonce[i] & 0xF0) >> 4];
    }
    cnt.buf[off++] = '\n';
    for (tx_itr = lnk_next(blk_tx(blk)); tx_itr != blk_tx(blk); tx_itr = lnk_next(tx_itr)) {
        btx = cast(tx_itr, block_tx_t, lnk);
        hash_pointer_write(cnt.buf + off, &btx->hptr);
        off += SHA256_DIGEST_LENGTH * 2;
        cnt.buf[off++] = '\n';
    }

    hash_pointer_calc_sha256(blk_hptr(blk), &cnt);
    return objsroot_loose_put(&cnt, (objsroot_t *) repo, blk_hptr(blk));
}

static int blk_load_func(void *blk, const void *repo, const void *hash) {
    objcontent_t cnt;
    if (objsroot_loose_fatch(&cnt, (const objsroot_t *) repo, (const hash_pointer_t *) hash) != 0) {
        return -1;
    }
    memcpy(blk_hptr(blk)->hash, ((const hash_pointer_t *) hash)->hash, SHA256_DIGEST_LENGTH); 

    return 0;
}
