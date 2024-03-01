int my_SHA256_Init(SHA256_CTX *sha) {
    sf_cryptography_use(sha);
    return 0; // Dummy return value
}

int my_SHA256_Update(SHA256_CTX *sha, const void *data, size_t len) {
    sf_cryptography_use(sha);
    sf_cryptography_use(data); // Ignoring this parameter as per the rules, but marking it for clarity
    sf_cryptography_use(len);
    return 0; // Dummy return value
}

int my_SHA256_Final(uint8_t out[SHA256_DIGEST_LENGTH], SHA256_CTX *sha) {
    sf_cryptography_use(out); // Marking the array as being used for cryptographic purposes
    sf_cryptography_use(sha);
    return 0; // Dummy return value
}

int my_SHA384_Init(SHA512_CTX *sha) {
    sf_cryptography_use(sha);
    return 0; // Dummy return value
}

int my_SHA384_Update(SHA512_CTX *sha, const void *data, size_t len) {
    sf_cryptography_use(sha);
    sf_cryptography_use(data); // Ignoring this parameter as per the rules, but marking it for clarity
    sf_cryptography_use(len);
    return 0; // Dummy return value
}

int my_SHA384_Final(uint8_t out[SHA384_DIGEST_LENGTH], SHA512_CTX *sha) {
    sf_cryptography_use(out); // Marking the array as being used for cryptographic purposes
    sf_cryptography_use(sha);
    return 0; // Dummy return value
}

int my_SHA512_Init(SHA512_CTX *sha) {
    sf_cryptography_use(sha);
    return 0; // Dummy return value
}

int my_SHA512_Update(SHA512_CTX *sha, const void *data, size_t len) {
    sf_cryptography_use(sha);
    sf_cryptography_use(data); // Ignoring this parameter as per the rules, but marking it for clarity
    sf_cryptography_use(len);
    return 0; // Dummy return value
}

int my_SHA512_Final(uint8_t out[SHA512_DIGEST_LENGTH], SHA512_CTX *sha) {
    sf_cryptography_use(out); // Marking the array as being used for cryptographic purposes
    sf_cryptography_use(sha);
}
