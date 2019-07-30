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

    time(&blk_hdr(bptr)->ts);

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
        + 8 * 2 // timestamp
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

    sprintf((char *) cnt.buf, "%016lX\n", blk_hdr(blk)->ts);
    off += 17;

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
    unsigned char c1st = 0;
    unsigned char c2nd = 0;
    size_t off = 0;
    size_t i;
    int h_off = 3;
    block_tx_t *btx;
    if (objsroot_loose_fatch(&cnt, (const objsroot_t *) repo, (const hash_pointer_t *) hash) != 0) {
        return -1;
    }
    memcpy(blk_hptr(blk)->hash, ((const hash_pointer_t *) hash)->hash, SHA256_DIGEST_LENGTH); 

    for (h_off = 3; h_off >= 0; h_off--) {
        c1st = cnt.buf[off + (3 - h_off) * 2];
        c2nd = cnt.buf[off + (3 - h_off) * 2 + 1];
        ((unsigned char *) &blk_hdr(blk)->version)[h_off] = (CHAR_2_BYTE(c1st) << 4) | CHAR_2_BYTE(c2nd);
    }
    off += 9;

    for (h_off = 7; h_off >= 0; h_off--) {
        c1st = cnt.buf[off + (7 - h_off) * 2];
        c2nd = cnt.buf[off + (7 - h_off) * 2 + 1];
        ((unsigned char *) &blk_hdr(blk)->version)[h_off] = (CHAR_2_BYTE(c1st) << 4) | CHAR_2_BYTE(c2nd);
    }
    off += 17;

    hash_pointer_read(&blk_hdr(blk)->p_hptr, cnt.buf + off);
    off += SHA256_DIGEST_LENGTH * 2 + 1;

    hash_pointer_read(&blk_hdr(blk)->m_hptr, cnt.buf + off);
    off += SHA256_DIGEST_LENGTH * 2 + 1;

    for (h_off = 3; h_off >= 0; h_off--) {
        c1st = cnt.buf[off + (3 - h_off) * 2];
        c2nd = cnt.buf[off + (3 - h_off) * 2 + 1];
        ((unsigned char *) &blk_hdr(blk)->hard_lv)[h_off] = (CHAR_2_BYTE(c1st) << 4) | CHAR_2_BYTE(c2nd);
    }
    off += 9;

    for (i = 0; i < _1229_COIN_NONCE_LEN; i++) {
        blk_hdr(blk)->nonce[i] = CHAR_2_BYTE(cnt.buf[off + i * 2]) | (CHAR_2_BYTE(cnt.buf[off + i * 2 + 1]) << 4);
    }
    off += _1229_COIN_NONCE_LEN * 2 + 1;

    for (; off < cnt.len; off += SHA256_DIGEST_LENGTH * 2 + 1) {
        btx = (block_tx_t *) malloc(sizeof(block_tx_t));
        if (btx == NULL) {
            return -1;
        }
        lnk_insert_before(blk_tx(blk), &btx->lnk);
        hash_pointer_read(&btx->hptr, cnt.buf + off);
    }

    return 0;
}
