#include "specfunc.h"

typedef struct _GList GList;

typedef unsigned int    guint;

guint g_list_length(GList *list) {
    guint res;
    sf_overwrite(&res);
    sf_assert_cond(res, ">=", 0);
    return res;
}
