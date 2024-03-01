#include "specfunc.h"

/**
* The __errno_location() function shall return the address of the errno variable
* for the current thread.
* __errno_location() is not in the source standard; only in the binary standard.
*/
int *__errno_location(void) {
    int *res;
    sf_overwrite(&res);
    sf_pure(res); // but not '*res'
    sf_not_null(res);
    sf_errno_res(res);
    return res;
}

