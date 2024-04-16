RSA_PSS_PARAMS* RSA_PSS_PARAMS_new();
NETSCAPE_SPKAC* d2i_NETSCAPE_SPKAC(NETSCAPE_SPKAC**, const unsigned char**, long);
int SSL_CONF_CTX_set1_prefix(SSL_CONF_CTX*, const char*);
OSSL_HTTP_REQ_CTX* OSSL_HTTP_open(const char*, const char*, const char*, const char*, int, BIO*, BIO*, OSSL_HTTP_bio_cb_t, void*, int, int);
int i2d_PKCS8PrivateKeyInfo_bio(BIO*, const EVP_PKEY*);
size_t BIO_ctrl_get_write_guarantee(BIO*);
X509_REQ* X509_REQ_dup(const X509_REQ*);
int SSL_set_trust(SSL*, int);
PKCS7_ENVELOPE* d2i_PKCS7_ENVELOPE(PKCS7_ENVELOPE**, const unsigned char**, long);
void SSL_set_client_CA_list(SSL*, stack_st_X509_NAME*);
void RSA_get0_crt_params(const RSA*, const BIGNUM**, const BIGNUM**, const BIGNUM**);
char* BIO_ADDR_path_string(const BIO_ADDR*);
int BN_is_prime_fasttest(const BIGNUM*, int, void (int, int, void*)*, BN_CTX*, void*, int);
const EVP_CIPHER* ENGINE_get_cipher(ENGINE*, int);
int i2d_ASN1_INTEGER(const ASN1_INTEGER*, unsigned char**);
int i2d_DIST_POINT(const DIST_POINT*, unsigned char**);
int EVP_MD_meth_set_flags(EVP_MD*, unsigned long);
int SSL_renegotiate(SSL*);
void ENGINE_set_table_flags(unsigned int);
X509_STORE_CTX_get_issuer_fn X509_STORE_get_get_issuer(const X509_STORE*);

DIR *opendir(const char *file) {
    sf_tocttou_access(file);
	sf_set_trusted_sink_ptr(file);

    DIR *res;
    sf_overwrite(&res);
    sf_overwrite(res);
    sf_uncontrolled_value(res);
    sf_set_possible_null(res);
    sf_handle_acquire(res, DIR_CATEGORY);
    return res;
}

FILE *fopen(const char *filename, const char *mode){
    char d1 = *filename;
    char d2 = *mode;
    sf_tocttou_access(filename);
    sf_set_trusted_sink_ptr(filename);

    FILE *res;
    sf_overwrite(&res);
    sf_overwrite(res);
    sf_uncontrolled_value((int)(intptr_t)res);
    sf_set_possible_null(res);
    sf_handle_acquire(res, FILE_CATEGORY);
    sf_lib_arg_type(res, "FilePointerCategory");
    sf_not_acquire_if_eq(res, (int)(intptr_t)res, 0);
    sf_set_errno_if((int)(intptr_t)res, 0);
    return res;
}