// Non standard library NSPR:
// Netscape Portable Runtime (NSPR) provides a platform-neutral API for system
// level and libc like functions.  The API is used in the Mozilla clients and
// many of Red Hat's, Sun's, and other software offerings.
#include "specfunc.h"

struct PRFileDesc {
    int stub;
};

int PR_fprintf(struct PRFileDesc* stream, const char *format, ...) {
    struct PRFileDesc derefStream = *stream;
    char d1 = *format;
    sf_use_format(format);

    sf_fun_does_not_update_vargs(2);
}

int PR_snprintf(char *str, size_t size, const char *format, ...) {
    char d1 = *str;
    char d2 = *format;
    sf_use_format(format);

    sf_fun_does_not_update_vargs(3);
}
