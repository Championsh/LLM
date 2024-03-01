#include "specfunc.h"

// char *gettext(const char *msgid);
// char *dgettext(const char *domainname, const char *msgid);

char *textdomain(const char *domainname) {
    char *res;
    sf_overwrite(&res);
    sf_set_alloc_possible_null(res);//no memory for string allocation
    return res;
}

char *bindtextdomain(const char *domainname, const char *dirname) {
    sf_tocttou_access(dirname);

    char *res;
    sf_overwrite(&res);
    sf_set_alloc_possible_null(res);//no memory for string allocation
    return res;
}
