#include "specfunc.h"

int isalnum(int c) {
    sf_set_trusted_sink_char(c);
    int res;
    sf_overwrite(&res);
    sf_pure(res, c);
    return res;
}

int isalpha(int c) {
    sf_set_trusted_sink_char(c);
    int res;
    sf_overwrite(&res);
    sf_pure(res, c);
    return res;
}

int isascii(int c) {
    sf_set_trusted_sink_char(c);
    int res;
    sf_overwrite(&res);
    sf_pure(res, c);
    return res;
}

int isblank(int c) {
    sf_set_trusted_sink_char(c);
    int res;
    sf_overwrite(&res);
    sf_pure(res, c);
    return res;
}

int iscntrl(int c) {
    sf_set_trusted_sink_char(c);
    int res;
    sf_overwrite(&res);
    sf_pure(res, c);
    return res;
}

int isdigit(int c) {
    sf_set_trusted_sink_char(c);
    int res = c >= '0' && c <= '9';
    sf_pure(res, c);
    return res;
}

int isgraph(int c) {
    sf_set_trusted_sink_char(c);
    int res;
    sf_overwrite(&res);
    sf_pure(res, c);
    return res;
}

int islower(int c) {
    sf_set_trusted_sink_char(c);
    int res;
    sf_overwrite(&res);
    sf_pure(res, c);
    return res;
}

int isprint(int c) {
    sf_set_trusted_sink_char(c);
    int res;
    sf_overwrite(&res);
    sf_pure(res, c);
    return res;
}

int ispunct(int c) {
    sf_set_trusted_sink_char(c);
    int res;
    sf_overwrite(&res);
    sf_pure(res, c);
    return res;
}

int isspace(int c) {
    sf_set_trusted_sink_char(c);
    int res;
    sf_overwrite(&res);
    sf_pure(res, c);
    return res;
}

int isupper(int c) {
    sf_set_trusted_sink_char(c);
    int res;
    sf_overwrite(&res);
    sf_pure(res, c);
    return res;
}

int isxdigit(int c) {
    sf_set_trusted_sink_char(c);
    int res;
    sf_overwrite(&res);
    sf_pure(res, c);
    return res;
}