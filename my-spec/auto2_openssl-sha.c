#include "specfunc.h"

typedef struct SHA256_CTX SHA256_CTX;
typedef struct SHA512_CTX SHA512_CTX;
typedef unsigned char uint8_t;
#define SHA256_DIGEST_LENGTH 32
#define SHA384_DIGEST_LENGTH 48
#define SHA512_DIGEST_LENGTH 64

int SHA256_Init(SHA256_CTX *sha) {
    // Mark the hash context as newly allocated with a specific memory category
    sf_new(sha, sizeof(SHA256_CTX), "SHA256_CTX");

    // Mark the hash context as possibly null
    sf_set_possible_null(sha);

    // Mark the hash context as not acquired if it is equal to null
    sf_not_acquire_if_eq(sha, NULL);

    // Overwrite the hash context (assuming this is done during initialization)
    sf_overwrite(sha, sizeof(SHA256_CTX), "SHA256_CTX");

    // If the hash function takes a password, key, or secret as an input parameter,
    // you would use sf_password_use here. But as per the function prototype,
    // there's no such parameter.

    // Set the buffer size limit (assuming this is done during initialization)
    // sf_buf_size_limit(...);

    // If the hash function copies a buffer to the allocated memory,
    // you would use sf_bitcopy here. But as per the function prototype,
    // there's no such operation.

    // Return value is not specified in the rules, so returning a dummy value
    return 0;
}

int SHA256_Update(SHA256_CTX *sha, const void *data, size_t len) {
    // Overwrite the hash context (assuming this is done during update)
    sf_overwrite(sha, sizeof(SHA256_CTX), "SHA256_CTX");

    // Set the buffer size limit
    sf_buf_size_limit(data, len);

    // If the hash function copies a buffer to the allocated memory
    sf_bitcopy(sha, data, len);

    // If the hash function takes a password, key, or secret as an input parameter,
    // you would use sf_password_use here. But as per the function prototype,
    // there's no such parameter.

    // Return value is not specified in the rules, so returning a dummy value
    return 0;
}

#include "specfunc.h"

typedef struct SHA256_CTX SHA256_CTX;

int SHA256_Final(uint8_t out[SHA256_DIGEST_LENGTH], SHA256_CTX *sha) {
    // Overwrite the hash context (assuming this is done during finalization)
    sf_overwrite(sha, sizeof(SHA256_CTX), "SHA256_CTX");

    // Mark the output digest as overwritten
    sf_overwrite(out, SHA256_DIGEST_LENGTH, "SHA256_DIGEST");

    // If the hash function takes a password, key, or secret as an input parameter,
    // you would use sf_password_use here. But as per the function prototype,
    // there's no such parameter.

    // If the hash function copies a buffer to the allocated memory,
    // you would use sf_bitcopy here. But as per the function prototype,
    // there's no such operation.

    // Set the buffer size limit (assuming this is done during finalization)
    // sf_buf_size_limit(...);

    // Return the output digest as the result of the hash function
    // As this is a void function, we can't return anything. But in reality,
    // the output digest would be returned here.

    // Return value is not specified in the rules, so returning a dummy value
    return 0;
}

int SHA384_Init(SHA512_CTX *sha) {
    // Mark the hash context as newly allocated with a specific memory category
    sf_new(sha, sizeof(SHA512_CTX), "SHA512_CTX");

    // Mark the hash context as possibly null
    sf_set_possible_null(sha);

    // Mark the hash context as not acquired if it is equal to null
    sf_not_acquire_if_eq(sha, NULL);

    // Overwrite the hash context (assuming this is done during initialization)
    sf_overwrite(sha, sizeof(SHA512_CTX), "SHA512_CTX");

    // If the hash function takes a password, key, or secret as an input parameter,
    // you would use sf_password_use here. But as per the function prototype,
    // there's no such parameter.

    // Set the buffer size limit (assuming this is done during initialization)
    // sf_buf_size_limit(...);

    // If the hash function copies a buffer to the allocated memory,
    // you would use sf_bitcopy here. But as per the function prototype,
    // there's no such operation.

    // Return value is not specified in the rules, so returning a dummy value
    return 0;
}

int SHA384_Update(SHA512_CTX *sha, const void *data, size_t len) {
    // Overwrite the hash context (assuming this is done during update)
    sf_overwrite(sha, sizeof(SHA512_CTX), "SHA512_CTX");

    // Set the buffer size limit
    sf_buf_size_limit(data, len);

    // If the hash function copies a buffer to the allocated memory
    sf_bitcopy(sha, data, len);

    // If the hash function takes a password, key, or secret as an input parameter,
    // you would use sf_password_use here. But as per the function prototype,
    // there's no such parameter.

    // Return value is not specified in the rules, so returning a dummy value
    return 0;
}

int SHA384_Final(uint8_t out[SHA384_DIGEST_LENGTH], SHA512_CTX *sha) {
    // Overwrite the hash context (assuming this is done during finalization)
    sf_overwrite(sha, sizeof(SHA512_CTX), "SHA512_CTX");

    // Mark the output digest as overwritten
    sf_overwrite(out, SHA384_DIGEST_LENGTH, "SHA384_DIGEST");

    // If the hash function takes a password, key, or secret as an input parameter,
    // you would use sf_password_use here. But as per the function prototype,
    // there's no such parameter.

    // If the hash function copies a buffer to the allocated memory,
    // you would use sf_bitcopy here. But as per the function prototype,
    // there's no such operation.

    // Set the buffer size limit (assuming this is done during finalization)
    // sf_buf_size_limit(...);

    // Return the output digest as the result of the hash function
    // As this is a void function, we can't return anything. But in reality,
    // the output digest would be returned here.

    // Return value is not specified in the rules, so returning a dummy value
    return 0;
}

int SHA512_Init(SHA512_CTX *sha) {
    // Mark the hash context as newly allocated with a specific memory category
    sf_new(sha, sizeof(SHA512_CTX), "SHA512_CTX");

    // Mark the hash context as possibly null
    sf_set_possible_null(sha);

    // Mark the hash context as not acquired if it is equal to null
    sf_not_acquire_if_eq(sha, NULL);

    // Overwrite the hash context (assuming this is done during initialization)
    sf_overwrite(sha, sizeof(SHA512_CTX), "SHA512_CTX");

    // If the hash function takes a password, key, or secret as an input parameter,
    // you would use sf_password_use here. But as per the function prototype,
    // there's no such parameter.

    // Set the buffer size limit (assuming this is done during initialization)
    // sf_buf_size_limit(...);

    // If the hash function copies a buffer to the allocated memory,
    // you would use sf_bitcopy here. But as per the function prototype,
    // there's no such operation.

    // Return value is not specified in the rules, so returning a dummy value
    return 0;
}

int SHA512_Update(SHA512_CTX *sha, const void *data, size_t len) {
    // Overwrite the hash context (assuming this is done during update)
    sf_overwrite(sha, sizeof(SHA512_CTX), "SHA512_CTX");

    // Set the buffer size limit
    sf_buf_size_limit(data, len);

    // If the hash function copies a buffer to the allocated memory
    sf_bitcopy(sha, data, len);

    // If the hash function takes a password, key, or secret as an input parameter,
    // you would use sf_password_use here. But as per the function prototype,
    // there's no such parameter.

    // Return value is not specified in the rules, so returning a dummy value
    return 0;
}

int SHA512_Final(uint8_t out[SHA512_DIGEST_LENGTH], SHA512_CTX *sha) {
    // Overwrite the hash context (assuming this is done during finalization)
    sf_overwrite(sha, sizeof(SHA512_CTX), "SHA512_CTX");

    // Mark the output digest as overwritten
    sf_overwrite(out, SHA512_DIGEST_LENGTH, "SHA512_DIGEST");

    // If the hash function takes a password, key, or secret as an input parameter,
    // you would use sf_password_use here. But as per the function prototype,
    // there's no such parameter.

    // If the hash function copies a buffer to the allocated memory,
    // you would use sf_bitcopy here. But as per the function prototype,
    // there's no such operation.

    // Set the buffer size limit (assuming this is done during finalization)
    // sf_buf_size_limit(...);

    // Return the output digest as the result of the hash function
    // As this is a void function, we can't return anything. But in reality,
    // the output digest would be returned here.

    // Return value is not specified in the rules, so returning a dummy value
    return 0;
}
