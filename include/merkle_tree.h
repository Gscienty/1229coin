#ifndef _1229_COIN_MERKLE_TREE_H
#define _1229_COIN_MERKLE_TREE_H

#include "hash_pointer.h"

typedef struct merkle_tree_node_s merkle_tree_node_t;
struct merkle_tree_node_s {
    hash_pointer_t node;
    hash_pointer_t left;
    hash_pointer_t right;
};

int merkle_tree_node_parent_calc_sha256(merkle_tree_node_t *parent,
                                        const hash_pointer_t *left_hptr,
                                        const hash_pointer_t *right_hptr);

#endif