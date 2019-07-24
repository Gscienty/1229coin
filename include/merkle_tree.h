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
};

#define mtn_hptr(p) (&(p)->hptr)
#define mtn_lft(p) (&(p)->left)
#define mtn_rgt(p) (&(p)->right)
#define mtn_save(p, b) (((p)->save_func) ((void *) (p), (const char *) (b)))
#define mtn_load(p, b, h) (((p)->load_func) ((void *) (p), (const char *) (b), (const unsigned char *) (h)))

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

int merkle_tree_proof_of_inclusion(const void *msg, const size_t msg_len,
                                   const link_t *path_hdr);

#endif
