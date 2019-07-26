#include "objfs.h"
#include <stddef.h>
#include <malloc.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

int objsroot_init(objsroot_t *root, char *basedir) {
    size_t basedir_len = 0;
    size_t loosedir_len = 0;
    if (root == NULL || basedir == NULL) {
        return -1;
    }
    root->loose_objs_dir = NULL;
    root->root_dir = NULL;

    basedir_len = strlen(basedir) + 1;
    root->root_dir = (char *) malloc(basedir_len);
    if (root->root_dir == NULL) {
        goto failure;
    }
    memcpy(root->root_dir, basedir, basedir_len);

    loosedir_len = basedir_len - 1 + strlen("/objects") + 1;
    root->loose_objs_dir = (char *) malloc(loosedir_len);
    if (root->loose_objs_dir == NULL) {
        goto failure;
    }
    memcpy(root->loose_objs_dir, basedir, basedir_len);
    memcpy(root->loose_objs_dir + basedir_len - 1, "/objects", strlen("/objects") + 1);

    return 0;

failure:
    if (root->root_dir != NULL) {
        free(root->root_dir);
    }
    if (root->loose_objs_dir != NULL) {
        free(root->loose_objs_dir);
    }
    return -1;
}

int objsroot_createrepo(objsroot_t *root) {
    if (root == NULL) {
        return -1;
    }
    if (access(root->root_dir, F_OK) != 0) {
        if (mkdir(root->root_dir, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) != 0) {
            return -2;
        }
    }
    if (access(root->loose_objs_dir, F_OK) != 0) {
        if (mkdir(root->loose_objs_dir, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) != 0) {
            return -2;
        }
    }
    return 0;
}

