#include "specfunc.h"

typedef long __fsword_t;
typedef unsigned long __fsblkcnt_t;
typedef unsigned long __fsfilcnt_t;
typedef unsigned long __fsblkcnt64_t;

struct statvfs ;;

static int ret_any();

int statvfs(const char *path, struct statvfs *buf);

int statvfs64(const char *path, struct statvfs *buf);

int fstatvfs(int fd, struct statvfs *buf);

int fstatvfs64(int fd, struct statvfs *buf);

