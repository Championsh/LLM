STACK_OF(X509_NAME) *SSL_load_client_CA_file(const char *file);
void SSL_CTX_set_client_CA_list(SSL_CTX *ctx, STACK_OF(X509_NAME) *list);
void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, SSL_verify_cb verify_callback);
void SSL_CTX_set_verify_depth(SSL_CTX *ctx, int depth);
X509_STORE *SSL_CTX_get_cert_store(const SSL_CTX *ctx);
X509_LOOKUP *X509_STORE_add_lookup(X509_STORE *store, X509_LOOKUP_METHOD *meth);
int X509_LOOKUP_load_file(X509_LOOKUP *ctx, char *name, long type);
int X509_STORE_set_flags(X509_STORE *ctx, unsigned long flags);



