int SHA256_Init(SHA256_CTX *sha);
int SHA256_Update(SHA256_CTX *sha, const void *data, size_t len);
int SHA256_Final(uint8_t out[SHA256_DIGEST_LENGTH], SHA256_CTX *sha);
int SHA384_Init(SHA512_CTX *sha);
int SHA384_Update(SHA512_CTX *sha, const void *data, size_t len);
int SHA384_Final(uint8_t out[SHA384_DIGEST_LENGTH], SHA512_CTX *sha);
int SHA512_Init(SHA512_CTX *sha);
int SHA512_Update(SHA512_CTX *sha, const void *data, size_t len);
int SHA512_Final(uint8_t out[SHA512_DIGEST_LENGTH], SHA512_CTX *sha);



