#include "merkle_tree.h"
#include <memory.h>
#include <malloc.h>

int merkle_tree_node_parent_calc_sha256(merkle_tree_node_t *parent,
                                        const hash_pointer_t *left_hptr,
                                        const hash_pointer_t *right_hptr) {
    objcontent_t cnt = { };
    unsigned char msg[2 * SHA256_DIGEST_LENGTH] = { 0 };
    cnt.buf = msg;
    cnt.len = 2 * SHA256_DIGEST_LENGTH;
    if (parent == NULL || left_hptr == NULL || right_hptr == NULL) {
        return -1;
    }

    memcpy(hptr_hash(mtn_lft(parent)), hptr_hash(left_hptr), SHA256_DIGEST_LENGTH);
    memcpy(hptr_hash(mtn_rgt(parent)), hptr_hash(right_hptr), SHA256_DIGEST_LENGTH);

    memcpy(msg, hptr_hash(mtn_lft(parent)), SHA256_DIGEST_LENGTH);
    memcpy(msg + SHA256_DIGEST_LENGTH, hptr_hash(mtn_rgt(parent)), SHA256_DIGEST_LENGTH);

    return hash_pointer_calc_sha256(mtn_hptr(parent), &cnt);
}

int merkle_tree_proof_of_inclusion(const objcontent_t *cnt, const link_t *path_hdr) {
    merkle_tree_proof_path_node_t *target = NULL;
    merkle_tree_proof_path_node_t *bro;
    unsigned char mid_msg[SHA256_DIGEST_LENGTH * 2];
    hash_pointer_t hash;
    objcontent_t mid_cnt;
    mid_cnt.buf = mid_msg;
    mid_cnt.len = SHA256_DIGEST_LENGTH * 2;

    hash_pointer_calc_sha256(&hash, cnt);
    bro = cast_lnk_next(path_hdr, merkle_tree_proof_path_node_t, lnk);

    while (lnk_next(&bro->lnk) != path_hdr) {
        target = cast_lnk_next(mtproof_lnk(bro), merkle_tree_proof_path_node_t, lnk);

        if (mtproof_lrflag(bro) == 0) {
            memcpy(mid_msg, hptr_hash(mtproof_hptr(bro)), SHA256_DIGEST_LENGTH);
            memcpy(mid_msg + SHA256_DIGEST_LENGTH, hash.hash, SHA256_DIGEST_LENGTH);
        }
        else {
            memcpy(mid_msg, hash.hash, SHA256_DIGEST_LENGTH);
            memcpy(mid_msg + SHA256_DIGEST_LENGTH, hptr_hash(mtproof_hptr(bro)), SHA256_DIGEST_LENGTH);
        }

        hash_pointer_calc_sha256(&hash, &mid_cnt);

        if (memcmp(hash.hash, hptr_hash(mtproof_hptr(target)), SHA256_DIGEST_LENGTH) != 0) {
            return 0;
        }
    }

    return 1;
}
