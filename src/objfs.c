#include "objfs.h"
#include <stddef.h>
#include <malloc.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

static int loose_objfile_path(char *obj_path, objsroot_t *root, hash_pointer_t *hptr, size_t base_size);

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

int objsroot_loose_fatch(objcontent_t *cnt, objsroot_t *root, hash_pointer_t *hptr) {
    size_t loose_objfs_base_size = 0;
    char *obj_path = NULL;
    int objfs = 0;
    if (cnt == NULL || root == NULL || hptr == NULL) {
        return -1;
    }
    loose_objfs_base_size = strlen(root->loose_objs_dir);
    obj_path = (char *) malloc(loose_objfs_base_size + SHA256_DIGEST_LENGTH * 2 + 3);
    if (obj_path == NULL) {
        goto failure;
    }
    if (loose_objfile_path(obj_path, root, hptr, loose_objfs_base_size) != 0) {
        goto failure;
    }
    if (access(obj_path, F_OK) != 0) {
        goto failure;
    }
    if ((objfs = open(obj_path, O_RDONLY)) <= 0) {
        goto failure;
    }

    lseek(objfs, 0, SEEK_END);
    cnt->len = lseek(objfs, 0, SEEK_CUR);
    lseek(objfs, 0, SEEK_SET);
    cnt->buf = (unsigned char *) malloc(cnt->len);
    if (cnt->buf == NULL) {
        goto failure;
    }
    read(objfs, cnt->buf, cnt->len);

    free(obj_path);
    close(objfs);
    return 0;
failure:
    if (obj_path == NULL) {
        free(obj_path);
    }
    if (objfs > 0) {
        close(objfs);
    }
    return -1;
}

static int loose_objfile_path(char *obj_path, objsroot_t *root, hash_pointer_t *hptr, size_t base_size) {
    size_t off = 0;
    size_t hptr_off;
    memcpy(obj_path, root->loose_objs_dir, base_size);
    obj_path[base_size] = '/';
    off = base_size + 1;
    obj_path[off++] = hptr_ichar_1st(hptr, 0);
    obj_path[off++] = hptr_ichar_2nd(hptr, 0);
    obj_path[off++] = '/';

    for (hptr_off = 1; hptr_off < SHA256_DIGEST_LENGTH; hptr_off++) {
        obj_path[off++] = hptr_ichar_1st(hptr, hptr_off);
        obj_path[off++] = hptr_ichar_2nd(hptr, hptr_off);
    }

    obj_path[off] = 0;

    return 0;
}
