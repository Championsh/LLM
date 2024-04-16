#include "specfunc.h"

struct utmp *getutxent(void) {
    struct utmp *res;
    sf_overwrite(&res);
    sf_set_possible_null(res);
    return res;
}

struct utmp *getutxid(struct utmp *ut) {
    struct utmp *res;
    sf_overwrite(&res);
    sf_use(ut);
    sf_set_possible_null(res);
    return res;
}

struct utmp *getutxline(struct utmp *ut) {
    struct utmp *res;
    sf_overwrite(&res);
    sf_use(ut);
    sf_set_possible_null(res);
    return res;
}

struct utmp *pututxline(struct utmp *ut) {
    struct utmp *res;
    sf_overwrite(&res);
    sf_use(ut);
    sf_set_possible_null(res);
    return res;
}

// void setutxent(void);
// void endutxent(void);

void utmpxname(const char *file) {
    sf_tocttou_access(file);
}
