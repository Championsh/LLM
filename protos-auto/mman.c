#include "specfunc.h"

void *mmap(void *addr, size_t len, int prot, int flags,
int fildes, off_t off);

int munmap(void *addr, size_t len);
