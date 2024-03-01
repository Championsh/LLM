#include "specfunc.h"

struct utimbuf;

int utime(const char *path, const struct utimbuf *times) {
    sf_tocttou_access(path);
}
