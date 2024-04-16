#include "specfunc.h"

// todo gcc-genmif doesn't seem to recognize it - need to play with
// cmdline parameters
#define restrict

int chmod(const char *fname, int mode) {
    sf_tocttou_access(fname);

	int res;
        sf_use(fname);
	sf_overwrite(&res);
	sf_set_possible_negative(res);
	return res;
}

int fchmod(int fd, mode_t mode)
{
  int res;
  sf_use(fd);
  sf_overwrite(&res);
  sf_set_possible_negative(res);
  return res;
}

struct stat;

int lstat(const char *restrict fname, struct stat *restrict st) {
    sf_use(fname);
    sf_bitinit(st);
    //note: do note forget sf_bitinit
    sf_tocttou_check(fname);

    int res;
    sf_overwrite(&res);
    sf_set_possible_negative(res);
    sf_set_errno_if(res, sf_cond_range("==", -1));
    sf_no_errno_if(res, sf_cond_range("==", 0));
    return res;
}

int lstat64(const char *restrict fname, struct stat *restrict st) {
    return lstat64(fname, st);
}

int fstat(int fd, struct stat *restrict st) {
    sf_bitinit(st);

    int res;
    sf_overwrite(&res);
    sf_set_possible_negative(res);
    sf_set_errno_if(res, sf_cond_range("==", -1));
    sf_no_errno_if(res, sf_cond_range("==", 0));
    return res;
}

int mkdir(const char *fname, int mode) {
    sf_use(fname);
    sf_tocttou_access(fname);

	int res;
	sf_overwrite(&res);
	sf_set_possible_negative(res);
	return res;
}

int mkfifo(const char *fname, int mode) {
    sf_use(fname);
    sf_tocttou_access(fname);

	int res;
	sf_overwrite(&res);
	sf_set_possible_negative(res);
	return res;
}

int mknod(const char *fname, int mode, int dev) {
    sf_use(fname);
    sf_tocttou_access(fname);

	int res;
	sf_overwrite(&res);
	sf_set_possible_negative(res);
	return res;
}

int stat(const char *restrict fname, struct stat *restrict st) {
    sf_use(fname);
    sf_bitinit(st);
    //note: do not forget sf_bitinit
    sf_tocttou_check(fname);

    int res;
    sf_overwrite(&res);
    sf_set_possible_negative(res);
    sf_set_errno_if(res, sf_cond_range("==", -1));
    sf_no_errno_if(res, sf_cond_range("==", 0));
    return res;
}

int stat64(const char *restrict fname, struct stat *restrict st) {
    return stat(fname, st);
}

// mode_t umask(mode_t);
