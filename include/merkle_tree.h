#ifndef _1229_COIN_MERKLE_TREE_H
#define _1229_COIN_MERKLE_TREE_H

#include "hash_pointer.h"
#include "link.h"
#include "define.h"

typedef struct merkle_tree_node_s merkle_tree_node_t;
struct merkle_tree_node_s {
    hash_pointer_t hptr;

    hash_pointer_t left;
    hash_pointer_t right;

    save_node_fptr save_func;
    load_node_fptr load_func;

    link_t ctor_lnk;
};

int merkle_tree_init(merkle_tree_node_t *n);

#define mtn_hptr(p) (&((merkle_tree_node_t *) (p))->hptr)
#define mtn_lft(p) (&((merkle_tree_node_t *) (p))->left)
#define mtn_rgt(p) (&((merkle_tree_node_t *) (p))->right)
#define mtn_save(p, b) ((((merkle_tree_node_t *) (p))->save_func) ((void *) (p), (const void *) (b)))
#define mtn_load(p, b, h) ((((merkle_tree_node_t *) (p))->load_func) ((void *) (p), (const void *) (b), (const void *) (h)))

typedef struct merkle_tree_proof_path_node_s merkle_tree_proof_path_node_t;
struct merkle_tree_proof_path_node_s {
    link_t lnk;

    hash_pointer_t hptr;
    unsigned char lr_flag;
};

#define mtproof_hptr(p) (&(p)->hptr)
#define mtproof_lrflag(p) ((p)->lr_flag)
#define mtproof_lnk(p) (&(p)->lnk)

int merkle_tree_node_parent_calc_sha256(merkle_tree_node_t *parent,
                                        const hash_pointer_t *left_hptr,
                                        const hash_pointer_t *right_hptr);

int merkle_tree_proof_of_inclusion(const objcontent_t *cnt, const link_t *path_hdr);

typedef struct merkle_tree_ctor_node_lnk_s merkle_tree_ctor_node_lnk_t;
struct merkle_tree_ctor_node_lnk_s {
    link_t lnk;
    int is_leaf;
    link_t *target;
};

#endif
