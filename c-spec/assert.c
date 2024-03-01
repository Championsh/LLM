#include "specfunc.h"

// some old compilation
void __assert_fail(const char *assertion, const char *file,
                   unsigned int line, const char *function) {
    sf_terminate_path();
}

// gcc 4.1.1 on mingw
void _assert(const char *a, const char *b, int c) {
    sf_terminate_path();
}

void __promise(int exp) {
    if(!exp) {
        sf_terminate_path();
    }
}
