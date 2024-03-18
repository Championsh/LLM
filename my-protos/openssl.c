int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int cmd, int p1, void *p2);
int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx);
X509_STORE_CTX *X509_STORE_CTX_new(void);
int X509_STORE_CTX_init(X509_STORE_CTX *ctx, X509_STORE *trust_store, X509 *target, STACK_OF(X509) *untrusted);
int X509_STORE_CTX_get1_issuer(X509 **issuer, X509_STORE_CTX *ctx, X509 *x);
void X509_STORE_CTX_free(X509_STORE_CTX *ctx);



