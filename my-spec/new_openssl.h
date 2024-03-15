#include "specfunc.h"

#include <stddef.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

typedef int (*pem_password_cb)(char *buf, int size, int rwflag, void *userdata);
#define STACK_OF(TYPE)TYPE

typedef int (*SSL_verify_cb)(int ok, X509_STORE_CTX *ctx);
typedef struct X509_LOOKUP_METHOD_st X509_LOOKUP_METHOD;
typedef struct X509_LOOKUP_st X509_LOOKUP;
typedef struct ossl_lib_ctx_st OSSL_LIB_CTX;

int EVP_CIPHER_CTX_reset(EVP_CIPHER_CTX *ctx) {
    // Mark the context as possibly null
    sf_set_possible_null(ctx);

    // Mark the context as overwritten
    sf_overwrite(ctx);

    return 0;
}

void *OPENSSL_malloc(size_t num) {
    // The OPENSSL_malloc function does not handle any password, key, or bit initialization
    // So, there is no need to use sf_password_use, sf_bitinit, sf_password_set functions here.

    // However, the memory allocated by OPENSSL_malloc may be used to store sensitive data,
    // so we need to mark this memory to ensure it is properly handled.
    // Since we have the size of the allocated memory and the real function behavior is not needed,
    // we can use sf_overwrite function to mark the allocated memory without actually implementing it.

    void *ptr = NULL; // No need to actually allocate memory
    sf_overwrite(&ptr);
    sf_overwrite(&num);
    return ptr;
}

void OPENSSL_free(void *addr) {
    // The OPENSSL_free function does not handle any password, key, or bit initialization
    // So, there is no need to use sf_password_use, sf_bitinit, sf_password_set functions here.

    // However, the memory being freed by OPENSSL_free may have contained sensitive data,
    // so we need to mark this memory to ensure it is properly handled before being freed.
    // Since we have the address of the memory to be freed and the real function behavior is not needed,
    // we can use sf_overwrite function to mark the memory without actually implementing it.

    sf_overwrite(addr);
}

void EVP_MD_CTX_free(EVP_MD_CTX *ctx) {
    // The EVP_MD_CTX_free function does not handle any password, key, or bit initialization
    // So, there is no need to use sf_password_use, sf_bitinit, sf_password_set functions here.

    // However, the EVP_MD_CTX structure may contain sensitive data,
    // so we need to mark this data to ensure it is properly handled before being freed.
    // Since we have the address of the EVP_MD_CTX structure and the real function behavior is not needed,
    // we can use sf_overwrite function to mark the structure without actually implementing it.

    sf_overwrite(ctx);
}

ENGINE *ENGINE_by_id(const char *id) {
    sf_set_trusted_sink_ptr(id);
    ENGINE *engine = NULL;
    sf_overwrite(&engine);
    sf_new(engine, MALLOC_CATEGORY);
    sf_set_possible_null(engine);
    sf_not_acquire_if_eq(engine, engine, 0);
    return engine;
}

EVP_PKEY *ENGINE_load_private_key(ENGINE *e, const char *key_id, UI_METHOD *ui_method, void *callback_data) {
    sf_set_trusted_sink_ptr(e);
    sf_set_trusted_sink_ptr(key_id);
    sf_set_trusted_sink_ptr(ui_method);
    sf_set_trusted_sink_ptr(callback_data);
    EVP_PKEY *pkey = NULL;
    sf_overwrite(&pkey);
    sf_new(pkey, MALLOC_CATEGORY);
    sf_set_possible_null(pkey);
    sf_not_acquire_if_eq(pkey, pkey, 0);
    sf_password_use(key_id);
    return pkey;
}

int ENGINE_free(ENGINE *e) {
    sf_set_trusted_sink_ptr(e);
    sf_delete(e, MALLOC_CATEGORY);
    return 0;
}

BIO *BIO_new_mem_buf(const void *buf, int len) {
    sf_set_trusted_sink_ptr(buf);
    sf_set_trusted_sink_int(len);
    BIO *bio = NULL;
    sf_overwrite(&bio);
    sf_new(bio, MALLOC_CATEGORY);
    sf_set_possible_null(bio);
    sf_not_acquire_if_eq(bio, bio, 0);
    sf_buf_size_limit(bio, len);
    sf_bitcopy(bio, buf);
    return bio;
}

EVP_PKEY *PEM_read_bio_PrivateKey_ex(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u, OSSL_LIB_CTX *libctx, const char *propq) {
    sf_set_trusted_sink_ptr(bp);
    sf_set_trusted_sink_ptr(x);
    sf_set_trusted_sink_ptr(cb);
    sf_set_trusted_sink_ptr(u);
    sf_set_trusted_sink_ptr(libctx);
    sf_set_trusted_sink_ptr(propq);
    EVP_PKEY *pkey = NULL;
    sf_overwrite(&pkey);
    sf_new(pkey, MALLOC_CATEGORY);
    sf_set_possible_null(pkey);
    sf_not_acquire_if_eq(pkey, pkey, 0);
    sf_password_use(propq);
    return pkey;
}

int SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str) {
    sf_set_trusted_sink_ptr(ctx);
    sf_set_trusted_sink_ptr(str);
    sf_buf_stop_at_null(str);
    return 0;
}

uint64_t SSL_CTX_set_options(SSL_CTX *ctx, uint64_t options) {
    sf_set_trusted_sink_ptr(ctx);
    sf_set_trusted_sink_int(options);
    return 0;
}

void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, SSL_verify_cb verify_callback) {
    sf_set_trusted_sink_ptr(ctx);
    sf_set_trusted_sink_int(mode);
    sf_set_trusted_sink_ptr(verify_callback);
}

void SSL_CTX_set_verify_depth(SSL_CTX *ctx, int depth) {
    sf_set_trusted_sink_ptr(ctx);
    sf_set_trusted_sink_int(depth);
}

int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile, const char *CApath) {
    sf_set_trusted_sink_ptr(ctx);
    sf_set_trusted_sink_ptr(CAfile);
    sf_set_trusted_sink_ptr(CApath);
    sf_tocttou_access(CAfile);
    sf_tocttou_access(CApath);
    return 0;
}

STACK_OF(X509_NAME) *SSL_load_client_CA_file(const char *file) {
    sf_set_trusted_sink_ptr(file);
    sf_tocttou_access(file);

    STACK_OF(X509_NAME) *sk = NULL;
    sf_overwrite(&sk);
    sf_new(sk, MALLOC_CATEGORY);
    sf_set_possible_null(sk);
    sf_not_acquire_if_eq(sk, sk, 0);

    // Load the file and add the X509_NAME objects to the stack
    // ...

    return sk;
}

void SSL_CTX_set_client_CA_list(SSL_CTX *ctx, STACK_OF(X509_NAME) *list) {
    sf_set_trusted_sink_ptr(ctx);
    sf_set_trusted_sink_ptr(list);

    sf_overwrite(ctx->client_CA);
    sf_delete(ctx->client_CA, MALLOC_CATEGORY);

    ctx->client_CA = list;
    sf_new(ctx->client_CA, MALLOC_CATEGORY);
    sf_set_possible_null(ctx->client_CA);
}

void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, SSL_verify_cb verify_callback) {
    sf_set_trusted_sink_ptr(ctx);
    sf_set_trusted_sink_int(mode);
    sf_set_trusted_sink_ptr(verify_callback);

    sf_overwrite(&ctx->verify_mode);
    sf_overwrite(&ctx->verify_callback);

    ctx->verify_mode = mode;
    ctx->verify_callback = verify_callback;
}

void SSL_CTX_set_verify_depth(SSL_CTX *ctx, int depth) {
    sf_set_trusted_sink_ptr(ctx);
    sf_set_trusted_sink_int(depth);

    sf_overwrite(&ctx->verify_depth);

    ctx->verify_depth = depth;
}

X509_STORE *SSL_CTX_get_cert_store(const SSL_CTX *ctx) {
    sf_set_trusted_sink_ptr(ctx);

    X509_STORE *store = NULL;
    sf_overwrite(&store);
    sf_new(store, MALLOC_CATEGORY);
    sf_set_possible_null(store);
    sf_not_acquire_if_eq(store, store, 0);

    store = ctx->cert_store;

    return store;
}

X509_LOOKUP *X509_STORE_add_lookup(X509_STORE *store, X509_LOOKUP_METHOD *meth) {
    sf_set_trusted_sink_ptr(store);
    sf_set_trusted_sink_ptr(meth);

    X509_LOOKUP *lookup = NULL;
    sf_overwrite(&lookup);
    sf_new(lookup, MALLOC_CATEGORY);
    sf_set_possible_null(lookup);
    sf_not_acquire_if_eq(lookup, lookup, 0);

    // Add the lookup method to the store
    // ...

    return lookup;
}

int X509_LOOKUP_load_file(X509_LOOKUP *ctx, char *name, long type) {
    sf_set_trusted_sink_ptr(ctx);
    sf_set_trusted_sink_ptr(name);
    sf_set_trusted_sink_int(type);

    sf_tocttou_access(name);

    int ret = 0;
    sf_overwrite(&ret);

    // Load the file using the specified lookup method
    // ...

    return ret;
}

int X509_STORE_set_flags(X509_STORE *ctx, unsigned long flags) {
    sf_set_trusted_sink_ptr(ctx);
    sf_set_trusted_sink_int(flags);

    sf_overwrite(&ctx->flags);

    ctx->flags = flags;

    return 1;
}

