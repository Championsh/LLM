#include "specfunc.h"

/**
* __ctype_b_loc -- accessor function for __ctype_b array for ctype functions
* The __ctype_b_loc() function shall return a pointer into an array of
* characters in the current locale that contains characteristics for each
* character in the current character set.
* The array shall contain a total of 384 characters, and can be indexed with
* any signed or unsigned char (i.e. with an index value between -128 and 255).
* If the application is multithreaded, the array shall be local to the current
* thread.
* This interface is not in the source standard; only in the binary standard.
*/
const unsigned short **__ctype_b_loc(void) {
    const unsigned short **res;
    sf_overwrite(&res);
    sf_not_null(res);
    return res;
}