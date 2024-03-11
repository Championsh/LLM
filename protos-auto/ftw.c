#include "specfunc.h"

struct stat;

int ftw(const char *path,
        int (*fn)(const char *, const struct stat *ptr, int flag),
        int ndirs);

int ftw64(const char *path,
        int (*fn)(const char *, const struct stat *ptr, int flag),
        int ndirs);

struct FTW;

int nftw(const char *path,
         int (*fn)(const char *, const struct stat *, int, struct FTW *),
         int fd_limit, int flags);

int nftw64(const char *path,
         int (*fn)(const char *, const struct stat *, int, struct FTW *),
         int fd_limit, int flags);