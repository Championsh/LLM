#include "specfunc.h"

// int catclose(nl_catd);
// char *catgets(nl_catd, int, int, const char *);

int catopen(const char *fname, int flag) {
    sf_tocttou_access(fname);
}
