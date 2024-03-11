#include "specfunc.h"

typedef long __fsword_t;
typedef unsigned long __fsblkcnt_t;
typedef unsigned long __fsfilcnt_t;
typedef unsigned long __fsblkcnt64_t;
typedef struct __fsid_t ; __fsid_t;

struct statfs ;;

static int ret_any();

int statfs(const char *path, struct statfs *buf);

int statfs64(const char *path, struct statfs *buf);

int fstatfs(int fd, struct statfs *buf);

int fstatfs64(int fd, struct statfs *buf);
