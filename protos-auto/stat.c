#include "specfunc.h"

 
 
#define restrict

int chmod(const char *fname, int mode);

int fchmod(int fd, mode_t mode)
;

struct stat;

int lstat(const char *restrict fname, struct stat *restrict st);

int lstat64(const char *restrict fname, struct stat *restrict st);

int fstat(int fd, struct stat *restrict st);

int mkdir(const char *fname, int mode);

int mkfifo(const char *fname, int mode);

int mknod(const char *fname, int mode, int dev);

int stat(const char *restrict fname, struct stat *restrict st);

int stat64(const char *restrict fname, struct stat *restrict st);

 
