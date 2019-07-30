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
#define lnk_hdr_init(p) \
    ({  \
        (p)->next = (p); \
        (p)->prev = (p); \
     })

#define lnk_insert_common(p, n, ins, ins_ref) \
    ({ \
        (n)->ins = (p)->ins; \
        (n)->ins_ref = (p); \
        (p)->ins->ins_ref = (n); \
        (p)->ins = (n); \
     })

#define lnk_insert_after(p, n) lnk_insert_common(p, n, next, prev)
#define lnk_insert_before(p, n) lnk_insert_common(p, n, prev, next)

#define lnk_remove(p) \
    ({ \
        (p)->next = (p)->next->next; \
        (p)->prev = (p)->prev->prev; \
     })

#endif
