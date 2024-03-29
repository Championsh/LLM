#include "specfunc.h"

typedef struct sha256_state_st SHA256_CTX;
typedef struct sha512_state_st SHA512_CTX;
typedef unsigned char uint8_t;

#define SHA256_DIGEST_LENGTH 32
#define SHA384_DIGEST_LENGTH 48
#define SHA512_DIGEST_LENGTH 64

int SHA256_Init(SHA256_CTX *sha) {
    sf_overwrite(sha);

    int res;
    sf_overwrite(&res);
    return res;
}

int SHA256_Update(SHA256_CTX *sha, const void *data, size_t len) {
    sf_overwrite(sha);

    int res;
    sf_overwrite(&res);
    return res;
}

int SHA256_Final(uint8_t out[SHA256_DIGEST_LENGTH], SHA256_CTX *sha) {
    sf_overwrite(sha);

    int res;
    sf_overwrite(&res);
    return res;
}


int SHA384_Init(SHA512_CTX *sha) {
    sf_overwrite(sha);

    int res;
    sf_overwrite(&res);
    return res;
}
int SHA384_Update(SHA512_CTX *sha, const void *data, size_t len) {
    sf_overwrite(sha);

    int res;
    sf_overwrite(&res);
    return res;
}

int SHA384_Final(uint8_t out[SHA384_DIGEST_LENGTH], SHA512_CTX *sha) {
    sf_overwrite(sha);

    int res;
    sf_overwrite(&res);
    return res;
}


int SHA512_Init(SHA512_CTX *sha) {
    sf_overwrite(sha);

    int res;
    sf_overwrite(&res);
    return res;
}
int SHA512_Update(SHA512_CTX *sha, const void *data, size_t len) {
    sf_overwrite(sha);

    int res;
    sf_overwrite(&res);
    return res;
}
int SHA512_Final(uint8_t out[SHA512_DIGEST_LENGTH], SHA512_CTX *sha) {
    sf_overwrite(sha);

    int res;
    sf_overwrite(&res);
    return res;
}

