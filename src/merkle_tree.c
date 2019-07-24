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

    return hash_pointer_calc_sha256(parent->node.hash, msg, 2 * SHA256_DIGEST_LENGTH);
}

int merkle_tree_proof_of_inclusion(const void *msg, const size_t msg_len,
                                   const unsigned char lr_flag[], const hash_pointer_t path[],
                                   const size_t path_len)
{
    size_t i;
    unsigned char mid_msg[SHA256_DIGEST_LENGTH * 2];
    unsigned char hash[SHA256_DIGEST_LENGTH];
    hash_pointer_calc_sha256(hash, msg, msg_len);

    for (i = 1; i < path_len; i++) {
        if (lr_flag[i - 1] == 0) {
            memcpy(mid_msg, path[i - 1].hash, SHA256_DIGEST_LENGTH);
            memcpy(mid_msg + SHA256_DIGEST_LENGTH, hash, SHA256_DIGEST_LENGTH);
        }
        else {
            memcpy(mid_msg, hash, SHA256_DIGEST_LENGTH);
            memcpy(mid_msg + SHA256_DIGEST_LENGTH, path[i - 1].hash, SHA256_DIGEST_LENGTH);
        }

        hash_pointer_calc_sha256(hash, mid_msg, SHA256_DIGEST_LENGTH * 2);

        if (memcmp(hash, path[i].hash, SHA256_DIGEST_LENGTH) != 0) {
            return 0;
        }
    }

    return 1;
}
