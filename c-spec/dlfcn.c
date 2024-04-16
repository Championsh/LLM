#include "specfunc.h"

int dlclose(void *handle) {
    sf_overwrite(handle);
    sf_handle_release(handle, DL_CATEGORY);
}

// char *dlerror(void);

void *dlopen(const char *file, int mode) {
    sf_tocttou_access(file);
	sf_set_trusted_sink_ptr(file);

    void *res;
    sf_overwrite(&res);
    sf_overwrite(res);
    sf_set_possible_null(res);
    sf_uncontrolled_ptr(res);
    sf_handle_acquire(res, DL_CATEGORY);
	sf_not_acquire_if_eq(res, mode, RTLD_NOLOAD);
    return res;
}

void *dlsym(void *handle, const char *symbol) {
    void *res;
    sf_overwrite(&res);
    sf_set_possible_null(res);
    return res;
}
