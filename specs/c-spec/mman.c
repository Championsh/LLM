#include "specfunc.h"

void *mmap(void *addr, size_t len, int prot, int flags,
int fildes, off_t off) {
	sf_set_trusted_sink_int(len);

	void *res;
	sf_overwrite(&res);
	sf_overwrite(res);
	sf_uncontrolled_ptr(res);
	sf_handle_acquire(res, MMAP_CATEGORY);
	sf_not_acquire_if_less(res, res, 1);
	return res;
}

int munmap(void *addr, size_t len) {
	char deref = *((char *)addr);

	sf_must_not_be_release(addr);
	sf_set_trusted_sink_int(len);

	sf_handle_release(addr, MMAP_CATEGORY);

	int res;
	sf_overwrite(&res);
	sf_must_be_checked(res);
	return res;
}
