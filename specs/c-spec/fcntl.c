// FIXME: Don't include the header here because it's a header of a build system
// not a system where svace is run; also it breaks building on cygwin (where
// svace clang compiler can't find this header as it doesn't know the system
// header folder).  Set it to the value used in Linux but note that Cygwin and
// Mingw has different values - review when we have these targets.
// #include <fcntl.h>
#define O_CREAT 0x40
#include "specfunc.h"

int creat(const char *name, mode_t mode) {
    char d1 = *name;
    sf_tocttou_access(name);
    int x;
    sf_overwrite(&x);
    sf_overwrite_int_as_ptr(x);
    sf_uncontrolled_value(x);
    sf_set_possible_negative(x);
    sf_handle_acquire_int_as_ptr(x, HANDLE_FILE_CATEGORY);
    sf_not_acquire_if_less_int_as_ptr(x, x, 2);
    sf_lib_arg_type(x, "StdioHandlerCategory");
    return x;
}

int creat64(const char *name, mode_t mode) {
    return creat(name, mode);
}


int fcntl(int fd, int cmd, ...) {
    sf_set_must_be_positive(fd);
    sf_lib_arg_type(fd, "StdioHandlerCategory");

    sf_fun_does_not_update_vargs(2);

    int x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    sf_assert_cond(x, ">=", -1);
    return x;
}

int open(const char *name, int flags, ...) {
    char c = *name;//TODO: is it really dereference its argument?
    sf_set_trusted_sink_ptr(name);
    sf_tocttou_access(name);

    sf_setval_O_CREAT(O_CREAT);
    sf_fun_does_not_update_vargs(2);

    int x;
    sf_overwrite(&x);
	sf_overwrite_int_as_ptr(x);
	sf_uncontrolled_value(x);
    sf_set_possible_negative(x);
	sf_handle_acquire_int_as_ptr(x, HANDLE_FILE_CATEGORY);
	sf_not_acquire_if_less_int_as_ptr(x, x, 3);
	sf_lib_arg_type(x, "StdioHandlerCategory");
    return x;
}

int open64(const char *name, int flags, ...) {
    char c = *name;//TODO: is it really dereference its argument?
    sf_set_trusted_sink_ptr(name);
    sf_tocttou_access(name);

    //sf_setval_O_CREAT(O_CREAT);

    int x;
    sf_overwrite(&x);
    sf_overwrite_int_as_ptr(x);
    sf_uncontrolled_value(x);
    sf_set_possible_negative(x);
    sf_handle_acquire_int_as_ptr(x, HANDLE_FILE_CATEGORY);
    sf_not_acquire_if_less_int_as_ptr(x, x, 2);
    sf_lib_arg_type(x, "StdioHandlerCategory");
    return x;
}

/*int read(int handle, void *buffer, int nbyte) {
    int res;
    sf_assert_cond(res, "<=", nbyte);
    return res;
}
*/
// int posix_fadvise(int, off_t, off_t, int);
// int posix_fallocate(int, off_t, off_t);
