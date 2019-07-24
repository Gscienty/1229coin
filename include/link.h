#ifndef _1229_LINK_H
#define _1229_LINK_H

#include <stddef.h>
#include "define.h"

typedef struct link_s link_t;
struct link_s {
    link_t *prev;
    link_t *next;
};

#define lnk_next(p) ((p)->next)
#define lnk_prev(p) ((p)->prev)
#define cast_lnk_next(p, s, m) (cast(lnk_next((p)), s, m))
#define cast_lnk_prev(p, s, m) (cast(lnk_prev((p)), s, m))
#define lnk_header_init(p) \
    ({  \
        (p)->next = (p); \
        (p)->prev = (p); \
     })

#endif
