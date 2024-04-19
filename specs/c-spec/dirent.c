#include "specfunc.h"

typedef unsigned int DIR;

int closedir(DIR *file) {
    sf_overwrite(file);
    sf_handle_release(file, DIR_CATEGORY);
}

DIR *opendir(const char *file) {
    sf_tocttou_access(file);
	sf_set_trusted_sink_ptr(file);

    DIR *res;
    sf_overwrite(&res);
    sf_overwrite(res);
    sf_uncontrolled_value(res);
    sf_set_possible_null(res);
    sf_handle_acquire(res, DIR_CATEGORY);
    return res;
}

struct dirent *readdir(DIR *file) {
	sf_tocttou_access(file);

    struct dirent *res;
	sf_overwrite(&res);
    sf_set_possible_null(res);
    return res;
}

// int            readdir_r(DIR *restrict, struct dirent *restrict,
//                    struct dirent **restrict);
// void           rewinddir(DIR *);
// void           seekdir(DIR *, long);
// long           telldir(DIR *);
