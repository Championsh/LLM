#include "specfunc.h"

struct addrinfo;

int getaddrinfo(const char *node,
                const char *service,
                const struct addrinfo *hints,
                struct addrinfo **res) {
    sf_overwrite(res);
	sf_handle_acquire(*res, GETADDRINFO_CATEGORY);

	int code;
    sf_overwrite(&code);
	sf_overwrite_int_as_ptr(code);
	sf_set_possible_negative(code);
	sf_not_acquire_if_greater(*res, code, 0);
	sf_not_acquire_if_less(*res, code, 0);
    return code;
}

void freeaddrinfo(struct addrinfo *res) {
    sf_overwrite(res);
    sf_handle_release(res, GETADDRINFO_CATEGORY);
}
