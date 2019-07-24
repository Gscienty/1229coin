#ifndef _1229_COIN_MERKLE_TREE_H
#define _1229_COIN_MERKLE_TREE_H

#include "hash_pointer.h"
#include "link.h"

typedef struct merkle_tree_node_s merkle_tree_node_t;
struct merkle_tree_node_s {
    hash_pointer_t hptr;

    hash_pointer_t left;
    hash_pointer_t right;
};

typedef struct merkle_tree_proof_path_node_s merkle_tree_proof_path_node_t;
struct merkle_tree_proof_path_node_s {
    link_t lnk;

    hash_pointer_t hptr;
    unsigned char lr_flag;
};

int merkle_tree_node_parent_calc_sha256(merkle_tree_node_t *parent,
                                        const hash_pointer_t *left_hptr,
                                        const hash_pointer_t *right_hptr);

int merkle_tree_proof_of_inclusion(const void *msg, const size_t msg_len,
                                   const link_t *path_hdr);

#endif
