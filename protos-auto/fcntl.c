 
 
 
 
 
 
#define O_CREAT 0x40
#include "specfunc.h"

int creat(const char *name, mode_t mode);

int creat64(const char *name, mode_t mode);


int fcntl(int fd, int cmd, ...);

int open(const char *name, int flags, ...);

int open64(const char *name, int flags, ...);

 
 
 
