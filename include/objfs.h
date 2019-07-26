#ifndef _1229_COIN_NODEFS_H
#define _1229_COIN_NODEFS_H

#include <stddef.h>
#include <hash_pointer.h>

typedef struct objsroot_s objsroot_t;
struct objsroot_s {
    char *root_dir;
    char *loose_objs_dir;
};

typedef struct objcontent_s objcontent_t;
struct objcontent_s {
    unsigned char *buf;
    size_t len;
};

int objsroot_init(objsroot_t *root, char *basedir);

int objsroot_createrepo(objsroot_t *root);

int objsroot_loose_fatch(objcontent_t *cnt, objsroot_t *root, hash_pointer_t *hptr);

#endif
