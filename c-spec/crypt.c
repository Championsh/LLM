#include "specfunc.h"

char *crypt(const char *key, const char *salt) {
    sf_password_use(key);
    sf_password_use(salt);
}

char *crypt_r(const char *key, const char *salt, struct crypt_data *data) {
    sf_password_use(key);
    sf_password_use(salt);
}

void setkey(const char *key) {
    sf_password_use(key);
}

void setkey_r(const char *key, struct crypt_data *data) {
    sf_password_use(key);
}

int ecb_crypt(char *key, char *data, unsigned datalen, unsigned mode) {
    sf_password_use(key);
}

int cbc_crypt(char *key, char *data, unsigned datalen, unsigned mode, char *ivec) {
    sf_password_use(key);
    sf_password_use(ivec);
}

void des_setparity(char *key) {
    sf_password_use(key);
}

void passwd2des(char *passwd, char *key) {
    sf_password_use(key);
    sf_password_use(passwd);
}

int xencrypt(char *secret, char *passwd) {
    sf_password_use(secret);
    sf_password_use(passwd);
}

int xdecrypt(char *secret, char *passwd) {
    sf_password_use(secret);
    sf_password_use(passwd);
}
