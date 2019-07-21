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
