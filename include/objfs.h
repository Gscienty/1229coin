#ifndef _1229_COIN_NODEFS_H
#define _1229_COIN_NODEFS_H

#include <stddef.h>
#include <hash_pointer.h>
#include "define.h"

typedef struct objsroot_s objsroot_t;
struct objsroot_s {
    char *root_dir;
    char *loose_objs_dir;
};

int objsroot_init(objsroot_t *root, char *basedir);

int objsroot_createrepo(objsroot_t *root);

int objsroot_loose_fatch(objcontent_t *cnt, const objsroot_t *root, const hash_pointer_t *hptr);

int objsroot_loose_put(objcontent_t *cnt, const objsroot_t *root, const hash_pointer_t *hptr);

#endif
