#include "specfunc.h"

struct utmp *getutent(void) {
    struct utmp *res;
    sf_overwrite(&res);
    sf_set_possible_null(res);
    return res;
}

struct utmp *getutid(struct utmp *ut) {
    struct utmp *res;
    sf_overwrite(&res);
    sf_use(ut);
    sf_set_possible_null(res);
    return res;
}

struct utmp *getutline(struct utmp *ut) {
    struct utmp *res;
    sf_overwrite(&res);
    sf_use(ut);
    sf_set_possible_null(res);
    return res;
}

struct utmp *pututline(struct utmp *ut) {
    struct utmp *res;
    sf_overwrite(&res);
    sf_use(ut);
    sf_set_possible_null(res);
    return res;
}

// void setutent(void);
// void endutent(void);

void utmpname(const char *file) {
    sf_tocttou_access(file);
}
