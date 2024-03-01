#include "specfunc.h"

#define va_list void *

//note: The err(), verr(), errx(), and verrx() functions do not return, but exit with
//the value of the argument eval.

void err(int eval, const char *fmt, ...) {
    sf_use_format(fmt);

    sf_terminate_path();
}

void verr(int eval, const char *fmt, va_list args) {
    sf_use_format(fmt);

    sf_terminate_path();
}

void errx(int eval, const char *fmt, ...) {
    sf_use_format(fmt);

    sf_terminate_path();
}

void verrx(int eval, const char *fmt, va_list args) {
    sf_use_format(fmt);

    sf_terminate_path();
}

void warn(const char *fmt, ...) {
    sf_use_format(fmt);
}

void vwarn(const char *fmt, va_list args) {
    sf_use_format(fmt);
}

void warnx(const char *fmt, ...) {
    sf_use_format(fmt);
}

void vwarnx(const char *fmt, va_list args) {
    sf_use_format(fmt);
}
