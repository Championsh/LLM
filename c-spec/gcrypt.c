#include "specfunc.h"

typedef int gcry_error_t;
typedef int gcry_cipher_hd_t;
typedef int gcry_md_hd_t;

gcry_error_t gcry_cipher_setkey(gcry_cipher_hd_t h , const void *key , size_t l) {
    sf_password_use(key);
}

gcry_error_t gcry_cipher_setiv (gcry_cipher_hd_t h, const void *key, size_t l) {
    sf_password_use(key);
}

gcry_error_t gcry_cipher_setctr (gcry_cipher_hd_t h, const void *ctr, size_t l) {
    sf_password_use(ctr);
}

gcry_error_t gcry_cipher_authenticate (gcry_cipher_hd_t h, const void *abuf, size_t abuflen) {
    sf_password_use(abuf);
}

gcry_error_t gcry_cipher_checktag (gcry_cipher_hd_t h, const void *tag, size_t taglen) {
    sf_password_use(tag);
}

gcry_error_t gcry_md_setkey (gcry_md_hd_t h, const void *key, size_t keylen) {
    sf_password_use(key);
}
