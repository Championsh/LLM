#include "specfunc.h"

#define return_PURE(ARG) \
    int res; \
    sf_overwrite(&res); \
    sf_pure(res, ARG); \
    return res \


int isalnum(int c) {
    sf_set_trusted_sink_char(c);//TODO: remove 1 of 2 lines
    return_PURE(c);
}

int isalpha(int c) {
    sf_set_trusted_sink_char(c);
    return_PURE(c);
}

int isascii(int c) {
    sf_set_trusted_sink_char(c);
    return_PURE(c);
}

int isblank(int c) {
    sf_set_trusted_sink_char(c);
    return_PURE(c);
}

int iscntrl(int c) {
    sf_set_trusted_sink_char(c);
    return_PURE(c);
}

int isdigit(int c) {
    sf_set_trusted_sink_char(c);
    int res = c >= '0' && c <= '9';
    sf_pure(res, c);
    return res;
}

int isgraph(int c) {
    sf_set_trusted_sink_char(c);
    return_PURE(c);
}

int islower(int c) {
    sf_set_trusted_sink_char(c);
    return_PURE(c);
}

int isprint(int c) {
    sf_set_trusted_sink_char(c);
    return_PURE(c);
}

int ispunct(int c) {
    sf_set_trusted_sink_char(c);
    return_PURE(c);
}

int isspace(int c) {
    sf_set_trusted_sink_char(c);
    return_PURE(c);
}

int isupper(int c) {
    sf_set_trusted_sink_char(c);
    return_PURE(c);
}

int isxdigit(int c) {
    sf_set_trusted_sink_char(c);
    return_PURE(c);
}

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
