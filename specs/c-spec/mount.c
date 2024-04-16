#include "specfunc.h"

int mount(const char *source, const char *target, const char *filesystemtype,
          unsigned long mountflags, const void *data) {
    sf_tocttou_access(source);
    sf_tocttou_access(target);

	sf_set_trusted_sink_ptr(source);
	sf_set_trusted_sink_ptr(target);
}

int umount(const char *target) {
    sf_tocttou_access(target);
	sf_set_trusted_sink_ptr(target);
}

// int umount2(const char *target, int flags);
