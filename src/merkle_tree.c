#include "merkle_tree.h"
#include "block.h"
#include "objfs.h"
#include <memory.h>
#include <malloc.h>

static int merkle_tree_save(const void *mtn, const void *repo);
static int merkle_tree_load(void *mtn, const void *repo, const void *hash);

int merkle_tree_init(merkle_tree_node_t *n) {
    mtn_ctor_queue(n)->is_leaf = 0;
    mtn_ctor_queue(n)->target = NULL;

    n->save_func = merkle_tree_save;
    n->load_func = merkle_tree_load;

    return 0;
}

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

int merkle_tree_ctor_queue_init(link_t *queue, link_t *tx_lnkhptr) {
    if (queue == NULL || tx_lnkhptr == NULL) {
        return -1;
    }
    link_t *tx = NULL;
    merkle_tree_ctor_node_queue_t *qnode = NULL;

    for (tx = lnk_next(tx_lnkhptr); tx != tx_lnkhptr; tx = lnk_next(tx)) {
        qnode = (merkle_tree_ctor_node_queue_t *) malloc(sizeof(merkle_tree_ctor_node_queue_t));
        if (qnode == NULL) {
            return -2;
        }
        qnode->is_leaf = 1;
        qnode->target = tx;

        lnk_insert_before(queue, &qnode->queue_lnk);
    }

    return 0;
}

int merkle_tree_ctor(hash_pointer_t *mtroot, link_t *queue, objsroot_t *repo) {
    merkle_tree_node_t *node;
    merkle_tree_ctor_node_queue_t *lft = NULL;
    merkle_tree_ctor_node_queue_t *rgt = NULL;
    merkle_tree_ctor_node_queue_t *rmn = NULL;
    int pop_count = 0;
    if (mtroot == NULL || queue == NULL) {
        return -1;
    }

    while (lnk_next(queue) != queue) {
        pop_count = 0;
        lft = cast_lnk_prev(queue, merkle_tree_ctor_node_queue_t, queue_lnk);
        if (lft->is_leaf) {
            if (lnk_prev(lnk_prev(queue)) == queue) {
                pop_count = 1;
                rgt = lft;
            }
            else {
                rgt = cast_lnk_prev(lnk_prev(queue), merkle_tree_ctor_node_queue_t, queue_lnk);
                if (!rgt->is_leaf) {
                    pop_count = 1;
                    rgt = lft;
                }
                else {
                    pop_count = 2;
                }
            }
        }
        else {
            if (lnk_prev(lnk_prev(queue)) == queue) {
                break;
            }
            rgt = cast_lnk_prev(lnk_prev(queue), merkle_tree_ctor_node_queue_t, queue_lnk);
            pop_count = 2;
        }

        node = (merkle_tree_node_t *) malloc(sizeof(merkle_tree_node_t));
        if (node == NULL) {
            goto failure;
        }
        merkle_tree_init(node);
        lnk_insert_after(queue, &mtn_ctor_queue(node)->queue_lnk);

        if (lft->is_leaf) {
            memcpy(hptr_hash(mtn_lft(node)), hptr_hash(&cast(lft->target, block_tx_t, lnk)->hptr), SHA256_DIGEST_LENGTH);
            memcpy(hptr_hash(mtn_rgt(node)), hptr_hash(&cast(rgt->target, block_tx_t, lnk)->hptr), SHA256_DIGEST_LENGTH);
        }
        else {
            mtn_save(cast(lft, merkle_tree_node_t, ctor_qlnk), repo);
            mtn_save(cast(rgt, merkle_tree_node_t, ctor_qlnk), repo);

            memcpy(hptr_hash(mtn_lft(node)), hptr_hash(&cast(lft, merkle_tree_node_t, ctor_qlnk)->hptr), SHA256_DIGEST_LENGTH);
            memcpy(hptr_hash(mtn_rgt(node)), hptr_hash(&cast(rgt, merkle_tree_node_t, ctor_qlnk)->hptr), SHA256_DIGEST_LENGTH);
        }

        while (pop_count--) {
            lnk_remove(lnk_next(queue));
        }

        if (lft->is_leaf) {
            if (lft == rgt) {
                free(lft);
            }
            else {
                free(lft);
                free(rgt);
            }
        }
        else {
           free(cast(lft, merkle_tree_node_t, ctor_qlnk)); 
           free(cast(rgt, merkle_tree_node_t, ctor_qlnk)); 
        }
    }

    if (lnk_prev(queue) == queue) {
        goto failure;
    }

    mtn_save(cast_lnk_prev(queue, merkle_tree_node_t, ctor_qlnk), repo);
    memcpy(hptr_hash(mtroot), hptr_hash(mtn_hptr(cast_lnk_prev(queue, merkle_tree_node_t, ctor_qlnk))), SHA256_DIGEST_LENGTH);
    free(cast_lnk_prev(queue, merkle_tree_node_t, ctor_qlnk));

    return 0;
failure:
    while (lnk_next(queue) != queue) {
        rmn = cast_lnk_next(queue, merkle_tree_ctor_node_queue_t, queue_lnk);
        lnk_remove(lnk_next(queue));

        if (rmn->is_leaf) {
            free(rmn);
        }
        else {
            free(cast(rmn, merkle_tree_node_t, ctor_qlnk));
        }
    }
    return -1;
}

static int merkle_tree_save(const void *mtn, const void *repo) {
    if (mtn == NULL || repo == NULL) {
        return -1;
    }

    objcontent_t cnt;
    size_t off = 0;
    cnt.len = SHA256_DIGEST_LENGTH * 2 
        + 1
        + SHA256_DIGEST_LENGTH * 2;
    cnt.buf = (unsigned char *) malloc(cnt.len);
    if (cnt.buf == NULL) {
        return -1;
    }

    hash_pointer_write(cnt.buf + off, mtn_lft(mtn));
    off += SHA256_DIGEST_LENGTH * 2;
    cnt.buf[off++] = '\n';

    hash_pointer_write(cnt.buf + off, mtn_rgt(mtn));
    off += SHA256_DIGEST_LENGTH * 2;

    hash_pointer_calc_sha256(mtn_hptr(mtn), &cnt);
    objsroot_loose_put(&cnt, (objsroot_t *) repo, mtn_hptr(mtn));

    free(cnt.buf);
    return 0;
}

static int merkle_tree_load(void *mtn, const void *repo, const void *hash) {
    if (mtn == NULL || repo == NULL || hash == NULL) {
        return -1;
    }
    int ret;
    int off = 0;
    objcontent_t cnt;

    if ((ret = objsroot_loose_fatch(&cnt, (objsroot_t *) repo, (hash_pointer_t *) hash)) < 0) {
        return ret;
    }
    memcpy(hptr_hash(mtn_hptr(mtn)), hptr_hash(hash), SHA256_DIGEST_LENGTH);
    hash_pointer_read(mtn_lft(mtn), cnt.buf + off);
    off += SHA256_DIGEST_LENGTH * 2 + 1;
    hash_pointer_read(mtn_rgt(mtn), cnt.buf + off);

    free(cnt.buf);
    return 0;
}
