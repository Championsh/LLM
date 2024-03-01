#include "specfunc.h"

typedef long __fsword_t;
typedef unsigned long __fsblkcnt_t;
typedef unsigned long __fsfilcnt_t;
typedef unsigned long __fsblkcnt64_t;

struct statvfs {
    unsigned long int f_bsize;
    unsigned long int f_frsize;
#ifndef __USE_FILE_OFFSET64
    __fsblkcnt_t f_blocks;
    __fsblkcnt_t f_bfree;
    __fsblkcnt_t f_bavail;
    __fsfilcnt_t f_files;
    __fsfilcnt_t f_ffree;
    __fsfilcnt_t f_favail;
#else
    __fsblkcnt64_t f_blocks;
    __fsblkcnt64_t f_bfree;
    __fsblkcnt64_t f_bavail;
    __fsfilcnt64_t f_files;
    __fsfilcnt64_t f_ffree;
    __fsfilcnt64_t f_favail;
#endif
    unsigned long int f_fsid;
#ifdef _STATVFSBUF_F_UNUSED
    int __f_unused;
#endif
    unsigned long int f_flag;
    unsigned long int f_namemax;
    int __f_spare[6];
};

static int ret_any() {
    int x;
    sf_overwrite(&x);
    return x;
}

int statvfs(const char *path, struct statvfs *buf) {
    sf_bitinit(buf);
    sf_tocttou_check(path);
    sf_bitinit(buf);

    sf_password_set(buf->f_bsize);
    sf_password_set(buf->f_frsize);
    sf_password_set(buf->f_blocks);
    sf_password_set(buf->f_bfree);
    sf_password_set(buf->f_bavail);
    sf_password_set(buf->f_files);
    sf_password_set(buf->f_ffree);
    sf_password_set(buf->f_favail);
    sf_password_set(buf->f_fsid);
    sf_password_set(buf->f_flag);
    sf_password_set(buf->f_namemax);
    sf_password_set(buf->__f_spare);
    return ret_any();
}

int statvfs64(const char *path, struct statvfs *buf) {
    return statvfs(path, buf);
}

int fstatvfs(int fd, struct statvfs *buf) {
    sf_bitinit(buf);
    sf_bitinit(buf);

    sf_password_set(buf->f_bsize);
    sf_password_set(buf->f_frsize);
    sf_password_set(buf->f_blocks);
    sf_password_set(buf->f_bfree);
    sf_password_set(buf->f_bavail);
    sf_password_set(buf->f_files);
    sf_password_set(buf->f_ffree);
    sf_password_set(buf->f_favail);
    sf_password_set(buf->f_fsid);
    sf_password_set(buf->f_flag);
    sf_password_set(buf->f_namemax);
    sf_password_set(buf->__f_spare);
    return ret_any();
}

int fstatvfs64(int fd, struct statvfs *buf) {
    return fstatvfs(fd, buf);
}

