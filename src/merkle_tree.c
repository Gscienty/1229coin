#include "merkle_tree.h"
#include <memory.h>
#include <malloc.h>

int merkle_tree_node_parent_calc_sha256(merkle_tree_node_t *parent,
                                        const hash_pointer_t *left_hptr,
                                        const hash_pointer_t *right_hptr) {
    unsigned char msg[2 * SHA256_DIGEST_LENGTH] = { 0 };
    if (parent == NULL || left_hptr == NULL || right_hptr == NULL) {
        return -1;
    }

    memcpy(parent->left.hash, left_hptr->hash, SHA256_DIGEST_LENGTH);
    memcpy(parent->right.hash, right_hptr->hash, SHA256_DIGEST_LENGTH);

    memcpy(msg, parent->left.hash, SHA256_DIGEST_LENGTH);
    memcpy(msg + SHA256_DIGEST_LENGTH, parent->right.hash, SHA256_DIGEST_LENGTH);

    return hash_pointer_calc_sha256(parent->hptr.hash, msg, 2 * SHA256_DIGEST_LENGTH);
}

int merkle_tree_proof_of_inclusion(const void *msg, const size_t msg_len,
                                   const link_t *path_hdr)
{
    merkle_tree_proof_path_node_t *target = NULL;
    merkle_tree_proof_path_node_t *bro;
    unsigned char mid_msg[SHA256_DIGEST_LENGTH * 2];
    unsigned char hash[SHA256_DIGEST_LENGTH];

    hash_pointer_calc_sha256(hash, msg, msg_len);
    bro = cast_lnk_next(path_hdr, merkle_tree_proof_path_node_t, lnk);

    while (lnk_next(&bro->lnk) != path_hdr) {
        target = cast_lnk_next(&bro->lnk, merkle_tree_proof_path_node_t, lnk);

        if (bro->lr_flag == 0) {
            memcpy(mid_msg, bro->hptr.hash, SHA256_DIGEST_LENGTH);
            memcpy(mid_msg + SHA256_DIGEST_LENGTH, hash, SHA256_DIGEST_LENGTH);
        }
        else {
            memcpy(mid_msg, hash, SHA256_DIGEST_LENGTH);
            memcpy(mid_msg + SHA256_DIGEST_LENGTH, bro->hptr.hash, SHA256_DIGEST_LENGTH);
        }

        hash_pointer_calc_sha256(hash, mid_msg, SHA256_DIGEST_LENGTH * 2);

        if (memcmp(hash, target->hptr.hash, SHA256_DIGEST_LENGTH) != 0) {
            return 0;
        }
    }

    return 1;
}
