int i2b_PVK_bio_ex(BIO*, const EVP_PKEY*, int, pem_password_cb*, void*, OSSL_LIB_CTX*, const char*);
X509_STORE_CTX_check_policy_fn X509_STORE_get_check_policy(const X509_STORE*);
int EVP_PKEY_encrypt(EVP_PKEY_CTX*, unsigned char*, size_t*, const unsigned char*, size_t);
int X509_NAME_add_entry(X509_NAME*, const X509_NAME_ENTRY*, int, int);
int PKCS5_pbe_set0_algor_ex(X509_ALGOR*, int, int, const unsigned char*, int, OSSL_LIB_CTX*);
int SSL_CTX_add_server_custom_ext(SSL_CTX*, unsigned int, custom_ext_add_cb, custom_ext_free_cb, void*, custom_ext_parse_cb, void*);
const SSL_METHOD* TLS_method();
const BIO_METHOD* BIO_s_mem();
const char* SSL_state_string(const SSL*);
BIO* BIO_pop(BIO*);
ENGINE_DIGESTS_PTR ENGINE_get_digests(const ENGINE*);
int PEM_write_DHxparams(FILE*, const DH*);
int BIO_closesocket(int);
void OSSL_HTTP_REQ_CTX_free(OSSL_HTTP_REQ_CTX*);
long SSL_SESSION_get_time(const SSL_SESSION*);
int PEM_write_bio_RSAPrivateKey(BIO*, const RSA*, const EVP_CIPHER*, const unsigned char*, int, pem_password_cb*, void*);
int PEM_write_X509_REQ(FILE*, const X509_REQ*);
void* ASN1_TYPE_unpack_sequence(const ASN1_ITEM*, const ASN1_TYPE*);
int UI_add_error_string(UI*, const char*);
const EVP_CIPHER* EVP_aria_192_ccm();
PKCS8_PRIV_KEY_INFO* d2i_PKCS8_PRIV_KEY_INFO(PKCS8_PRIV_KEY_INFO**, const unsigned char**, long);
int i2d_PKCS7_bio(BIO*, const PKCS7*);
int X509_get_ext_by_NID(const X509*, int, int);
const EVP_CIPHER* EVP_des_cbc();
const EVP_CIPHER* EVP_aria_128_gcm();
SRTP_PROTECTION_PROFILE* SSL_get_selected_srtp_profile(SSL*);
char* X509_VERIFY_PARAM_get0_host(X509_VERIFY_PARAM*, int);
const ASN1_OBJECT* NAMING_AUTHORITY_get0_authorityId(const NAMING_AUTHORITY*);
OSSL_PARAM OSSL_PARAM_construct_utf8_string(const char*,  char*, size_t);
int X509_VERIFY_PARAM_set_inh_flags(X509_VERIFY_PARAM*, uint32_t);
const EVP_CIPHER* EVP_bf_ecb();
int (DSA*)* DSA_meth_get_finish(const DSA_METHOD*);
int ASN1_INTEGER_set_uint64(ASN1_INTEGER*, uint64_t);
int i2d_PKCS7_ENVELOPE(const PKCS7_ENVELOPE*, unsigned char**);
void EVP_RAND_free(EVP_RAND*);
int EVP_PKEY_CTX_set0_dh_kdf_oid(EVP_PKEY_CTX*, ASN1_OBJECT*);
int ENGINE_register_all_complete();
const OSSL_PARAM* EVP_CIPHER_settable_ctx_params(const EVP_CIPHER*);
int BN_BLINDING_convert_ex(BIGNUM*, BIGNUM*, BN_BLINDING*, BN_CTX*);
CTLOG* CTLOG_new(EVP_PKEY*, const char*);