#include "specfunc.h"

typedef long __fsword_t;
typedef unsigned long __fsblkcnt_t;
typedef unsigned long __fsfilcnt_t;
typedef unsigned long __fsblkcnt64_t;
typedef struct __fsid_t { int __val[2]; } __fsid_t;

struct statfs {
    __fsword_t f_type;
    __fsword_t f_bsize;
#ifndef __USE_FILE_OFFSET64
    __fsblkcnt_t f_blocks;
    __fsblkcnt_t f_bfree;
    __fsblkcnt_t f_bavail;
    __fsfilcnt_t f_files;
    __fsfilcnt_t f_ffree;
#else
    __fsblkcnt64_t f_blocks;
    __fsblkcnt64_t f_bfree;
    __fsblkcnt64_t f_bavail;
    __fsfilcnt64_t f_files;
    __fsfilcnt64_t f_ffree;
#endif
    __fsid_t f_fsid;
    __fsword_t f_namelen;
    __fsword_t f_frsize;
    __fsword_t f_flags;
    __fsword_t f_spare[4];
};

static int ret_any() {
    int x;
    sf_overwrite(&x);
    return x;
}

int statfs(const char *path, struct statfs *buf){
    sf_bitinit(buf);
    sf_tocttou_check(path);
    sf_bitinit(buf);

    sf_password_set(buf->f_type);
    sf_password_set(buf->f_bsize);
    sf_password_set(buf->f_blocks);
    sf_password_set(buf->f_bfree);
    sf_password_set(buf->f_bavail);
    sf_password_set(buf->f_files);
    sf_password_set(buf->f_ffree);
    sf_password_set(&(buf->f_fsid));
    sf_password_set(buf->f_namelen);
    sf_password_set(buf->f_frsize);
    sf_password_set(buf->f_flags);
    sf_password_set(buf->f_spare);
    return ret_any();
}

int statfs64(const char *path, struct statfs *buf){
    return statfs(path, buf);
}

int fstatfs(int fd, struct statfs *buf) {
    sf_bitinit(buf);
    sf_bitinit(buf);

    sf_password_set(buf->f_type);
    sf_password_set(buf->f_bsize);
    sf_password_set(buf->f_blocks);
    sf_password_set(buf->f_bfree);
    sf_password_set(buf->f_bavail);
    sf_password_set(buf->f_files);
    sf_password_set(buf->f_ffree);
    sf_password_set(&(buf->f_fsid));
    sf_password_set(buf->f_namelen);
    sf_password_set(buf->f_frsize);
    sf_password_set(buf->f_flags);
    sf_password_set(buf->f_spare);
    return ret_any();
}

int fstatfs64(int fd, struct statfs *buf) {
    return fstatfs(fd, buf);
}
