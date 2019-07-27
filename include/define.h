#ifndef _1229_COIN_DEFINE_H
#define _1229_COIN_DEFINE_H

#include <openssl/sha.h>

#define _1229_COIN_VERSION 0x01000000
#define _1229_COIN_NONCE_LEN 40

#define cast(p, s, m) ((s *) (((char *) p) - ((char *) &(((s *) 0)->m))))

typedef int (*save_node_fptr) (const void *node_ptr, const void *base);
typedef int (*load_node_fptr) (void *node_ptr, const void *base, const void *hash);

typedef struct objcontent_s objcontent_t;
struct objcontent_s {
    unsigned char *buf;
    size_t len;
};


#endif
