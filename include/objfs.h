#ifndef _1229_COIN_NODEFS_H
#define _1229_COIN_NODEFS_H

#include <stddef.h>

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

#endif
