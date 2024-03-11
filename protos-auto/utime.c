#include "specfunc.h"

struct utimbuf;

int utime(const char *path, const struct utimbuf *times);
