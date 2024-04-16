
OSSL_PARAM *OSSL_PARAM_merge(const OSSL_PARAM *p1, const OSSL_PARAM *p2) {
    OSSL_PARAM *Res = NULL;
    sf_set_trusted_sink_ptr(Res);
    sf_set_alloc_possible_null(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_lib_arg_type(Res, "OSSL_PARAM_merge");
    sf_bitcopy(Res, p1);
    sf_bitcopy(Res, p2);
    return Res;
}

int SSL_CTX_use_serverinfo_file(SSL_CTX *ctx, const char *file) {
    int Res = 0;
    sf_set_errno_if(Res, file == NULL);
    sf_tocttou_check(file);
    sf_set_tainted(file);
    return Res;
}

int ERR_pop_to_mark() {
    int Res = 0;
    sf_set_possible_null(Res);
    return Res;
}

IPAddressFamily* IPAddressFamily_new() {
    IPAddressFamily *Res = NULL;
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_lib_arg_type(Res, "IPAddressFamily_new");
    return Res;
}

int X509_STORE_set_default_paths(X509_STORE *store) {
    int Res = 0;
    sf_set_errno_if(Res, store == NULL);
    sf_lib_arg_type(store, "X509_STORE_set_default_paths");
    return Res;
}
BIGNUM* BN_mod_sqrt(BIGNUM*, const BIGNUM*, const BIGNUM*, BN_CTX*);

int X509_get_ext_by_OBJ(const X509*, const ASN1_OBJECT*, int);

void EC_POINT_clear_free(EC_POINT*);

PKCS7_ENCRYPT* d2i_PKCS7_ENCRYPT(PKCS7_ENCRYPT**, const unsigned char**, long);

long BIO_int_ctrl(BIO*, int, long, int);

int SSL_get_verify_mode(const SSL* ssl);

void X509_EXTENSION_free(X509_EXTENSION* ex);

int (BIO*,  char*, int);

BIGNUM* BN_mpi2bn(const unsigned char* mpi, int len, BIGNUM* bn);

int BIO_socket(int domain, int type, int protocol, int* error);


const EVP_MD* EVP_sha3_256() {
    const EVP_MD* Res = NULL;
    Res = EVP_sha3_256();
    sf_set_possible_null(Res);
    return Res;
}

BIO* BIO_new_ssl_connect(SSL_CTX* ctx) {
    BIO* Res = NULL;
    Res = BIO_new_ssl_connect(ctx);
    sf_set_possible_null(Res);
    return Res;
}

int ASN1_item_sign_ctx(const ASN1_ITEM* it, X509_ALGOR* alg1, X509_ALGOR* alg2, ASN1_BIT_STRING* sig, const void* data, EVP_MD_CTX* ctx) {
    int Res = 0;
    Res = ASN1_item_sign_ctx(it, alg1, alg2, sig, data, ctx);
    sf_set_errno_if(Res <= 0);
    return Res;
}

unsigned long ERR_peek_error() {
    unsigned long Res = 0;
    Res = ERR_peek_error();
    sf_set_possible_null(Res);
    return Res;
}

OSSL_LIB_CTX* OSSL_LIB_CTX_new_from_dispatch(const OSSL_CORE_HANDLE* handle, const OSSL_DISPATCH* dispatch) {
    OSSL_LIB_CTX* Res = NULL;
    Res = OSSL_LIB_CTX_new_from_dispatch(handle, dispatch);
    sf_set_possible_null(Res);
    return Res;
}

// RSA_PSS_PARAMS* RSA_PSS_PARAMS_new()
void RSA_PSS_PARAMS_new() {
    RSA_PSS_PARAMS* Res = NULL;
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    return Res;
}

// NETSCAPE_SPKAC* d2i_NETSCAPE_SPKAC(NETSCAPE_SPKAC**, const unsigned char**, long)
void d2i_NETSCAPE_SPKAC(NETSCAPE_SPKAC** a, const unsigned char** b, long c) {
    NETSCAPE_SPKAC* Res = NULL;
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    return Res;
}

// int SSL_CONF_CTX_set1_prefix(SSL_CONF_CTX*, const char*)
void SSL_CONF_CTX_set1_prefix(SSL_CONF_CTX* a, const char* b) {
    int Res = 0;
    sf_set_errno_if(Res, EINVAL);
    return Res;
}

// OSSL_HTTP_REQ_CTX* OSSL_HTTP_open(const char*, const char*, const char*, const char*, int, BIO*, BIO*, OSSL_HTTP_bio_cb_t, void*, int, int)
void OSSL_HTTP_open(const char* a, const char* b, const char* c, const char* d, int e, BIO* f, BIO* g, OSSL_HTTP_bio_cb_t h, void* i, int j, int k) {
    OSSL_HTTP_REQ_CTX* Res = NULL;
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    return Res;
}

// int i2d_PKCS8PrivateKeyInfo_bio(BIO*, const EVP_PKEY*)
void i2d_PKCS8PrivateKeyInfo_bio(BIO* a, const EVP_PKEY* b) {
    int Res = 0;
    sf_set_errno_if(Res, EINVAL);
    return Res;
}

size_t BIO_ctrl_get_write_guarantee(BIO* bp) {
    size_t Res = 0;
    sf_set_trusted_sink_int(Res);
    Res = BIO_ctrl(bp, BIO_CTRL_GET_WRITE_GUARANTEE, 0, NULL);
    sf_set_possible_null(Res);
    return Res;
}

X509_REQ* X509_REQ_dup(const X509_REQ* req) {
    X509_REQ* Res = NULL;
    sf_set_possible_null(Res);
    Res = X509_REQ_dup(req);
    sf_set_alloc_possible_null(Res);
    return Res;
}

int SSL_set_trust(SSL* s, int trust) {
    int Res = 0;
    Res = SSL_set_trust(s, trust);
    sf_set_errno_if(Res, Res == 0);
    return Res;
}

PKCS7_ENVELOPE* d2i_PKCS7_ENVELOPE(PKCS7_ENVELOPE** a, const unsigned char** in, long len) {
    PKCS7_ENVELOPE* Res = NULL;
    sf_set_possible_null(Res);
    Res = d2i_PKCS7_ENVELOPE(a, in, len);
    sf_set_alloc_possible_null(Res);
    return Res;
}

void SSL_set_client_CA_list(SSL* s, stack_st_X509_NAME* list) {
    SSL_set_client_CA_list(s, list);
}

void RSA_get0_crt_params(const RSA* r, const BIGNUM** dmp1, const BIGNUM** dmq1, const BIGNUM** iqmp) {
    sf_set_tainted(r);
    sf_set_must_be_not_null(r, RSA_NULL);
    sf_set_must_be_not_null(dmp1, DMP1_NULL);
    sf_set_must_be_not_null(dmq1, DMQ1_NULL);
    sf_set_must_be_not_null(iqmp, IQMP_NULL);
    sf_set_possible_null(*dmp1);
    sf_set_possible_null(*dmq1);
    sf_set_possible_null(*iqmp);
}

char* BIO_ADDR_path_string(const BIO_ADDR* addr) {
    sf_set_must_be_not_null(addr, BIO_ADDR_NULL);
    char* res = NULL;
    sf_set_possible_null(res);
    sf_set_alloc_possible_null(res);
    sf_lib_arg_type(res, "MallocCategory");
    return res;
}

int BN_is_prime_fasttest(const BIGNUM* bn, int checks, void (int, int, void*)* cb, BN_CTX* ctx, void* cb_arg, int is_trial_division) {
    sf_set_must_be_not_null(bn, BIGNUM_NULL);
    sf_set_must_be_not_null(ctx, BN_CTX_NULL);
    sf_set_errno_if(checks < 0, CHECKS_LESS_THAN_ZERO);
    sf_set_errno_if(is_trial_division < 0, IS_TRIAL_DIVISION_LESS_THAN_ZERO);
    return 0;
}

const EVP_CIPHER* ENGINE_get_cipher(ENGINE* e, int nid) {
    sf_set_must_be_not_null(e, ENGINE_NULL);
    sf_set_errno_if(nid < 0, NID_LESS_THAN_ZERO);
    const EVP_CIPHER* res = NULL;
    sf_set_possible_null(res);
    return res;
}

int i2d_ASN1_INTEGER(const ASN1_INTEGER* a, unsigned char** pp) {
    sf_set_must_be_not_null(a, ASN1_INTEGER_NULL);
    sf_set_must_be_not_null(pp, PP_NULL);
    sf_set_possible_null(*pp);
    sf_set_buf_size(*pp, a->length);
    return 0;
}
int i2d_DIST_POINT(const DIST_POINT* a, unsigned char** pp);

int EVP_MD_meth_set_flags(EVP_MD* md, unsigned long flags);

int SSL_renegotiate(SSL* s);

void ENGINE_set_table_flags(unsigned int flags);

X509_STORE_CTX_get_issuer_fn X509_STORE_get_get_issuer(const X509_STORE* ctx);

void OCSP_REQUEST_free(OCSP_REQUEST* req);

int SSL_is_init_finished(const SSL* ssl);

int X509_EXTENSION_get_critical(const X509_EXTENSION* ex);

PROFESSION_INFO* PROFESSION_INFO_new();

int DH_check_params_ex(const DH* dh);

int ASN1_STRING_print(BIO*, const ASN1_STRING*);

int SSL_CTX_use_PrivateKey_file(SSL_CTX*, const char*, int);

EVP_MAC* EVP_MAC_fetch(OSSL_LIB_CTX*, const char*, const char*);

int EVP_SealInit(EVP_CIPHER_CTX*, const EVP_CIPHER*, unsigned char**, int*, unsigned char*, EVP_PKEY**, int);

int PKCS5_PBKDF2_HMAC(const char*, int, const unsigned char*, int, int, const EVP_MD*, int, unsigned char*);


EVP_PKEY* EVP_PKCS82PKEY(const PKCS8_PRIV_KEY_INFO* p8inf)
{
    EVP_PKEY* Res = NULL;
    sf_set_trusted_sink_ptr(p8inf);
    sf_set_tainted(Res);
    sf_set_possible_null(Res);
    return Res;
}

X509_ALGOR* X509_ALGOR_dup(const X509_ALGOR* xa)
{
    X509_ALGOR* Res = NULL;
    sf_set_trusted_sink_ptr(xa);
    sf_set_tainted(Res);
    sf_set_possible_null(Res);
    return Res;
}

int EVP_RAND_instantiate(EVP_RAND_CTX* ctx, unsigned int strength, int prediction_resistance, const unsigned char* entropy, size_t entropylen, const OSSL_PARAM params[])
{
    int Res = 0;
    sf_set_trusted_sink_ptr(ctx);
    sf_set_trusted_sink_ptr(entropy);
    sf_set_tainted(Res);
    return Res;
}

int SSL_client_version(const SSL* s)
{
    int Res = 0;
    sf_set_trusted_sink_ptr(s);
    sf_set_tainted(Res);
    return Res;
}

RSA_METHOD* RSA_meth_dup(const RSA_METHOD* meth)
{
    RSA_METHOD* Res = NULL;
    sf_set_trusted_sink_ptr(meth);
    sf_set_tainted(Res);
    sf_set_possible_null(Res);
    return Res;
}
const BIGNUM* RSA_get0_n(const RSA* rsa);

int OPENSSL_hexchar2int(unsigned char c);

int X509_VERIFY_PARAM_set1_host(X509_VERIFY_PARAM* param, const char* name, size_t namelen);

PKCS8_PRIV_KEY_INFO* EVP_PKEY2PKCS8(const EVP_PKEY* pkey);

int SSL_get_quiet_shutdown(const SSL* ssl);


int i2b_PVK_bio_ex(BIO* bio, const EVP_PKEY* pkey, int pvk_encr, pem_password_cb* cb, void* u, OSSL_LIB_CTX* libctx, const char* propq) {
    int res = 0;
    sf_set_tainted(pkey);
    sf_password_use(cb);
    sf_set_trusted_sink_ptr(bio);
    sf_set_trusted_sink_int(pvk_encr);
    sf_lib_arg_type(libctx, "OSSL_LIB_CTX");
    sf_tocttou_check(propq);
    sf_set_errno_if(res == 0);
    return res;
}

X509_STORE_CTX_check_policy_fn X509_STORE_get_check_policy(const X509_STORE* store) {
    X509_STORE_CTX_check_policy_fn res = NULL;
    sf_set_trusted_sink_ptr(store);
    return res;
}

int EVP_PKEY_encrypt(EVP_PKEY_CTX* ctx, unsigned char* out, size_t* outlen, const unsigned char* in, size_t inlen) {
    int res = 0;
    sf_set_trusted_sink_ptr(ctx);
    sf_set_trusted_sink_int(inlen);
    sf_buf_size_limit(out, *outlen);
    sf_buf_size_limit_read(in, inlen);
    sf_set_errno_if(res == 0);
    return res;
}

int X509_NAME_add_entry(X509_NAME* name, const X509_NAME_ENTRY* ne, int loc, int set) {
    int res = 0;
    sf_set_trusted_sink_ptr(name);
    sf_set_trusted_sink_int(loc);
    sf_set_trusted_sink_int(set);
    sf_set_errno_if(res == 0);
    return res;
}

int PKCS5_pbe_set0_algor_ex(X509_ALGOR* algor, int alg, int iter, const unsigned char* salt, int saltlen, OSSL_LIB_CTX* libctx) {
    int res = 0;
    sf_set_trusted_sink_ptr(algor);
    sf_set_trusted_sink_int(alg);
    sf_set_trusted_sink_int(iter);
    sf_set_trusted_sink_int(saltlen);
    sf_lib_arg_type(libctx, "OSSL_LIB_CTX");
    sf_set_errno_if(res == 0);
    return res;
}

int SSL_CTX_add_server_custom_ext(SSL_CTX* ctx, unsigned int ext_number, custom_ext_add_cb add_cb, custom_ext_free_cb free_cb, void* add_arg, custom_ext_parse_cb parse_cb, void* parse_arg) {
    int Res = 0;
    // Add other necessary specifications
    return Res;
}

const SSL_METHOD* TLS_method() {
    const SSL_METHOD* Res = NULL;
    // Add other necessary specifications
    return Res;
}

const BIO_METHOD* BIO_s_mem() {
    const BIO_METHOD* Res = NULL;
    // Add other necessary specifications
    return Res;
}

const char* SSL_state_string(const SSL* ssl) {
    const char* Res = NULL;
    // Add other necessary specifications
    return Res;
}

BIO* BIO_pop(BIO* bio) {
    BIO* Res = NULL;
    // Add other necessary specifications
    return Res;
}

ENGINE_DIGESTS_PTR ENGINE_get_digests(const ENGINE* engine) {
    ENGINE_DIGESTS_PTR Res = NULL;
    sf_set_trusted_sink_ptr(engine);
    sf_set_alloc_possible_null(Res);
    return Res;
}

int PEM_write_DHxparams(FILE* fp, const DH* dh) {
    int Res = 0;
    sf_set_must_not_be_null(fp);
    sf_set_must_not_be_null(dh);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int BIO_closesocket(int sock) {
    int Res = 0;
    sf_set_must_not_be_null(sock);
    sf_set_errno_if(Res <= 0);
    return Res;
}

void OSSL_HTTP_REQ_CTX_free(OSSL_HTTP_REQ_CTX* rctx) {
    sf_set_must_not_be_null(rctx);
    sf_delete(rctx, MALLOC_CATEGORY);
    sf_lib_arg_type(rctx, "MallocCategory");
}

long SSL_SESSION_get_time(const SSL_SESSION* s) {
    long Res = 0;
    sf_set_must_not_be_null(s);
    sf_set_long_time(Res);
    return Res;
}

int PEM_write_bio_RSAPrivateKey(BIO* bio, const RSA* rsa, const EVP_CIPHER* cipher, const unsigned char* passwd, int len, pem_password_cb* cb, void* u) {
    int res = 0;
    sf_set_tainted(passwd);
    sf_password_use(passwd);
    sf_set_trusted_sink_ptr(bio);
    sf_set_trusted_sink_ptr(rsa);
    sf_set_trusted_sink_ptr(cipher);
    sf_set_trusted_sink_ptr(cb);
    sf_set_trusted_sink_ptr(u);
    sf_set_errno_if(res == 0);
    return res;
}

int PEM_write_X509_REQ(FILE* file, const X509_REQ* req) {
    int res = 0;
    sf_set_trusted_sink_ptr(file);
    sf_set_trusted_sink_ptr(req);
    sf_set_errno_if(res == 0);
    return res;
}

void* ASN1_TYPE_unpack_sequence(const ASN1_ITEM* it, const ASN1_TYPE* at) {
    void* res = NULL;
    sf_set_trusted_sink_ptr(it);
    sf_set_trusted_sink_ptr(at);
    sf_set_errno_if(res == NULL);
    return res;
}

int UI_add_error_string(UI* ui, const char* str) {
    int res = 0;
    sf_set_trusted_sink_ptr(ui);
    sf_set_trusted_sink_ptr(str);
    sf_set_errno_if(res == 0);
    return res;
}

const EVP_CIPHER* EVP_aria_192_ccm() {
    const EVP_CIPHER* res = NULL;
    sf_set_trusted_sink_ptr(res);
    return res;
}

PKCS8_PRIV_KEY_INFO* d2i_PKCS8_PRIV_KEY_INFO(PKCS8_PRIV_KEY_INFO** a, const unsigned char** pp, long length) {
    PKCS8_PRIV_KEY_INFO* Res = NULL;
    sf_set_trusted_sink_int(length);
    sf_malloc_arg(Res, length);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    return Res;
}

int i2d_PKCS7_bio(BIO* a, const PKCS7* b) {
    int Res = 0;
    sf_set_errno_if(Res, -1);
    sf_no_errno_if(Res, 1);
    return Res;
}

int X509_get_ext_by_NID(const X509* a, int b, int c) {
    int Res = 0;
    sf_set_errno_if(Res, -1);
    sf_no_errno_if(Res, 1);
    return Res;
}

const EVP_CIPHER* EVP_des_cbc() {
    const EVP_CIPHER* Res = NULL;
    sf_set_possible_null(Res);
    return Res;
}

const EVP_CIPHER* EVP_aria_128_gcm() {
    const EVP_CIPHER* Res = NULL;
    sf_set_possible_null(Res);
    return Res;
}

SRTP_PROTECTION_PROFILE* SSL_get_selected_srtp_profile(SSL* ssl) {
    SRTP_PROTECTION_PROFILE* Res = NULL;
    Res = (SRTP_PROTECTION_PROFILE*)sf_malloc_arg(sizeof(SRTP_PROTECTION_PROFILE), PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_lib_arg_type(ssl, "SSL");
    sf_set_possible_null(Res);
    return Res;
}

char* X509_VERIFY_PARAM_get0_host(X509_VERIFY_PARAM* param, int idx) {
    char* Res = NULL;
    Res = (char*)sf_malloc_arg(sizeof(char), PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_lib_arg_type(param, "X509_VERIFY_PARAM");
    sf_set_possible_null(Res);
    return Res;
}

const ASN1_OBJECT* NAMING_AUTHORITY_get0_authorityId(const NAMING_AUTHORITY* na) {
    const ASN1_OBJECT* Res = NULL;
    sf_lib_arg_type(na, "NAMING_AUTHORITY");
    sf_set_possible_null(Res);
    return Res;
}

OSSL_PARAM OSSL_PARAM_construct_utf8_string(const char* key, char* buf, size_t buf_len) {
    OSSL_PARAM Res;
    sf_buf_size_limit(buf, buf_len);
    sf_lib_arg_type(key, "UTF8_STRING");
    sf_set_possible_null(Res);
    return Res;
}

int X509_VERIFY_PARAM_set_inh_flags(X509_VERIFY_PARAM* param, uint32_t flags) {
    int Res = 0;
    sf_lib_arg_type(param, "X509_VERIFY_PARAM");
    sf_set_possible_negative(Res);
    return Res;
}

const EVP_CIPHER* EVP_bf_ecb() {
    const EVP_CIPHER* Res = NULL;
    Res = EVP_bf_ecb();
    sf_set_possible_null(Res);
    return Res;
}

int (DSA*)* DSA_meth_get_finish(const DSA_METHOD* dsa_meth) {
    int (DSA*)* Res = NULL;
    Res = DSA_meth_get_finish(dsa_meth);
    sf_set_possible_null(Res);
    return Res;
}

int ASN1_INTEGER_set_uint64(ASN1_INTEGER* a, uint64_t num) {
    int Res = 0;
    Res = ASN1_INTEGER_set_uint64(a, num);
    sf_set_errno_if(Res == 0);
    return Res;
}

int i2d_PKCS7_ENVELOPE(const PKCS7_ENVELOPE* a, unsigned char** pp) {
    int Res = 0;
    Res = i2d_PKCS7_ENVELOPE(a, pp);
    sf_set_errno_if(Res == 0);
    return Res;
}

void EVP_RAND_free(EVP_RAND* rand) {
    EVP_RAND_free(rand);
    sf_delete(rand, RAND_CATEGORY);
}
int EVP_PKEY_CTX_set0_dh_kdf_oid(EVP_PKEY_CTX* ctx, ASN1_OBJECT* oid);

int ENGINE_register_all_complete();

const OSSL_PARAM* EVP_CIPHER_settable_ctx_params(const EVP_CIPHER* cipher);

int BN_BLINDING_convert_ex(BIGNUM* r, BIGNUM* a, BN_BLINDING* b, BN_CTX* ctx);

CTLOG* CTLOG_new(EVP_PKEY* pkey, const char* name);


DSA* DSAparams_dup(const DSA* dsa) {
    DSA* Res = NULL;
    sf_set_trusted_sink_ptr(dsa);
    sf_set_alloc_possible_null(Res);
    Res = DSA_dup(dsa);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    return Res;
}

const char* OPENSSL_version_build_metadata() {
    const char* Res = NULL;
    Res = OpenSSL_version_build_metadata();
    sf_set_possible_null(Res);
    return Res;
}

int SSL_write(SSL* ssl, const void* buf, int num) {
    int Res = 0;
    sf_set_trusted_sink_ptr(ssl);
    sf_set_trusted_sink_int(num);
    Res = SSL_write(ssl, buf, num);
    sf_set_errno_if(Res <= 0);
    sf_buf_size_limit_read(buf, num);
    return Res;
}

void X509_SIG_free(X509_SIG* sig) {
    sf_set_trusted_sink_ptr(sig);
    X509_SIG_free(sig);
    sf_delete(sig, MALLOC_CATEGORY);
}

EVP_PKEY* d2i_PKCS8PrivateKey_fp(FILE* fp, EVP_PKEY** x, pem_password_cb* cb, void* u) {
    EVP_PKEY* Res = NULL;
    sf_set_trusted_sink_ptr(fp);
    sf_set_trusted_sink_ptr(cb);
    sf_set_trusted_sink_ptr(u);
    Res = d2i_PKCS8PrivateKey_fp(fp, x, cb, u);
    sf_set_alloc_possible_null(Res);
    return Res;
}

void OPENSSL_LH_node_stats_bio(const OPENSSL_LHASH* lh, BIO* bio) {
    sf_set_trusted_sink_int(lh);
    sf_set_trusted_sink_ptr(bio);
    sf_no_errno_if(lh);
    sf_no_errno_if(bio);
    sf_tocttou_check(bio);
}

stack_st_X509_INFO* PEM_X509_INFO_read_bio_ex(BIO* bio, stack_st_X509_INFO* sk, pem_password_cb* cb, void* u, OSSL_LIB_CTX* libctx, const char* propq) {
    sf_set_trusted_sink_ptr(bio);
    sf_set_trusted_sink_ptr(sk);
    sf_set_trusted_sink_ptr(cb);
    sf_set_trusted_sink_ptr(u);
    sf_set_trusted_sink_ptr(libctx);
    sf_set_trusted_sink_ptr(propq);
    sf_no_errno_if(bio);
    sf_no_errno_if(sk);
    sf_no_errno_if(cb);
    sf_no_errno_if(u);
    sf_no_errno_if(libctx);
    sf_no_errno_if(propq);
    sf_tocttou_check(bio);
    sf_password_use(cb);
    return sk;
}

const EVP_CIPHER* EVP_aes_256_cbc() {
    const EVP_CIPHER* res = NULL;
    sf_set_trusted_sink_ptr(res);
    return res;
}

const EVP_CIPHER* EVP_aes_256_cfb1() {
    const EVP_CIPHER* res = NULL;
    sf_set_trusted_sink_ptr(res);
    return res;
}

int BN_BLINDING_lock(BN_BLINDING* b) {
    int res = 0;
    sf_set_trusted_sink_ptr(b);
    sf_no_errno_if(b);
    return res;
}

BUF_MEM* BUF_MEM_new_ex(unsigned long size)
{
    BUF_MEM *Res = NULL;
    sf_malloc_arg(size);
    Res = OPENSSL_malloc(size);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res, size);
    sf_lib_arg_type(Res, "BUF_MEM");
    return Res;
}

int ENGINE_finish(ENGINE* e)
{
    sf_set_must_be_not_null(e, FREE_OF_NULL);
    sf_delete(e, ENGINE_CATEGORY);
    sf_lib_arg_type(e, "ENGINE");
    return 1;
}

int ASN1_TIME_normalize(ASN1_TIME* t)
{
    sf_set_must_be_not_null(t, FREE_OF_NULL);
    sf_bitinit(t);
    return 1;
}

int X509_VERIFY_PARAM_set1_email(X509_VERIFY_PARAM* param, const char* email, size_t emaillen)
{
    sf_set_must_be_not_null(param, FREE_OF_NULL);
    sf_set_trusted_sink_int(email, emaillen);
    sf_password_use(email, emaillen);
    return 1;
}

EVP_ENCODE_CTX* EVP_ENCODE_CTX_new()
{
    EVP_ENCODE_CTX *Res = NULL;
    Res = OPENSSL_malloc(sizeof(EVP_ENCODE_CTX));
    sf_overwrite(Res);
    sf_new(Res, EVP_ENCODE_CTX_CATEGORY);
    sf_set_alloc_possible_null(Res);
    sf_lib_arg_type(Res, "EVP_ENCODE_CTX");
    return Res;
}
int EVP_MD_CTX_ctrl(EVP_MD_CTX*, int, int, void*);

int i2d_SSL_SESSION(const SSL_SESSION*, unsigned char**);

EVP_RAND_CTX* RAND_get0_public(OSSL_LIB_CTX*);

const EVP_CIPHER* EVP_sm4_ctr();

int EVP_DigestFinal(EVP_MD_CTX*, unsigned char*, unsigned int*);


char* i2s_ASN1_UTF8STRING(X509V3_EXT_METHOD* method, ASN1_UTF8STRING* utf8str) {
    char* Res = NULL;
    sf_set_trusted_sink_int(utf8str->length);
    Res = OPENSSL_malloc(utf8str->length + 1);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    sf_bitcopy(Res, utf8str->data, utf8str->length);
    Res[utf8str->length] = '\0';
    sf_set_possible_null(Res);
    return Res;
}

int X509_self_signed(X509* x, int check_signature) {
    int Res = 0;
    Res = X509_check_issued(x, x);
    sf_set_errno_if(Res != X509_V_OK);
    return Res;
}

int SHA384_Init(SHA512_CTX* c) {
    int Res = 0;
    Res = SHA512_Init(c);
    sf_set_errno_if(Res != 1);
    return Res;
}

int BN_priv_rand(BIGNUM* rnd, int bits, int top, int bottom) {
    int Res = 0;
    Res = BN_rand(rnd, bits, top, bottom);
    sf_set_errno_if(Res != 1);
    return Res;
}

void* SSL_CTX_get_default_passwd_cb_userdata(SSL_CTX* ctx) {
    void* Res = NULL;
    Res = SSL_CTX_get_default_passwd_cb_userdata(ctx);
    sf_set_possible_null(Res);
    return Res;
}
int SSL_set_ciphersuites(SSL*, const char*);

void EVP_PKEY_meth_get_paramgen(const EVP_PKEY_METHOD*, int (EVP_PKEY_CTX*);

int DHparams_print_fp(FILE*, const DH*);

DSA* d2i_DSA_PUBKEY(DSA**, const unsigned char**, long);

const EVP_CIPHER* EVP_cast5_cfb64();


void* EVP_CIPHER_CTX_set_cipher_data(EVP_CIPHER_CTX* ctx, void* data) {
    void* Res = NULL;
    sf_set_trusted_sink_ptr(data);
    Res = ctx->cipher_data = data;
    sf_overwrite(ctx->cipher_data);
    return Res;
}

const OSSL_PARAM* EVP_RAND_CTX_settable_params(EVP_RAND_CTX* ctx) {
    const OSSL_PARAM* Res = NULL;
    Res = ctx->settable_params;
    sf_overwrite(Res);
    return Res;
}

CONF* NCONF_new(CONF_METHOD* method) {
    CONF* Res = NULL;
    Res = CONF_new(method);
    sf_new(Res, CONF_MEMORY_CATEGORY);
    return Res;
}

int PEM_write_RSA_PUBKEY(FILE* fp, const RSA* rsa) {
    int Res = 0;
    sf_password_use(rsa);
    Res = PEM_write_RSAPublicKey(fp, rsa);
    sf_set_errno_if(Res <= 0);
    return Res;
}

CRL_DIST_POINTS* CRL_DIST_POINTS_new() {
    CRL_DIST_POINTS* Res = NULL;
    Res = CRL_DIST_POINTS_new();
    sf_new(Res, CRL_DIST_POINTS_MEMORY_CATEGORY);
    return Res;
}

int EC_POINT_copy(EC_POINT *dest, const EC_POINT *src)
{
    int res = 0;
    sf_set_trusted_sink_int(res);
    sf_set_must_be_not_null(dest, COPY_OF_NULL);
    sf_set_must_be_not_null(src, COPY_OF_NULL);
    sf_bitcopy(dest, src);
    return res;
}

int X509at_get_attr_by_OBJ(const stack_st_X509_ATTRIBUTE *sk, const ASN1_OBJECT *obj, int lastpos)
{
    int res = 0;
    sf_set_trusted_sink_int(res);
    sf_set_must_be_not_null(sk, GET_ATTR_OF_NULL);
    sf_set_must_be_not_null(obj, GET_ATTR_OF_NULL);
    sf_set_must_be_not_null(obj->data, GET_ATTR_OF_NULL);
    return res;
}

int SSL_pending(const SSL *s)
{
    int res = 0;
    sf_set_trusted_sink_int(res);
    sf_set_must_be_not_null(s, SSL_PENDING_OF_NULL);
    return res;
}

void* X509_LOOKUP_get_method_data(const X509_LOOKUP *ctx)
{
    void *res = NULL;
    sf_set_trusted_sink_ptr(res);
    sf_set_must_be_not_null(ctx, GET_METHOD_DATA_OF_NULL);
    return res;
}

EC_KEY* EC_KEY_dup(const EC_KEY *key)
{
    EC_KEY *res = NULL;
    sf_set_trusted_sink_ptr(res);
    sf_set_must_be_not_null(key, DUP_OF_NULL);
    sf_bitcopy(res, key);
    return res;
}
void OPENSSL_INIT_free(OPENSSL_INIT_SETTINGS* settings);

int SSL_CTX_set_alpn_protos(SSL_CTX* ctx, const unsigned char* protos, unsigned int protos_len);

void ENGINE_unregister_digests(ENGINE* e);

const EVP_CIPHER* EVP_aes_192_cbc();

size_t EVP_PKEY_meth_get_count();


unsigned char* EVP_Q_mac(OSSL_LIB_CTX* ctx, const char* mdname, const char* engine, const char* data, const OSSL_PARAM* params, const void* key, size_t keylen, const unsigned char* salt, size_t saltlen, unsigned char* mac, size_t maclen, size_t* outlen) {
    unsigned char* Res = NULL;
    // Check for null pointers and other necessary conditions
    // Perform the operation
    // Set the output length if necessary
    return Res;
}

ENGINE* DH_get0_engine(DH* dh) {
    ENGINE* Res = NULL;
    // Check for null pointers and other necessary conditions
    // Perform the operation
    return Res;
}

void EVP_PKEY_meth_set_ctrl(EVP_PKEY_METHOD* pmeth, int (*ctrl)(EVP_PKEY_CTX*, int, int, void*), int (*strctrl)(EVP_PKEY_CTX*, const char*, const char*)) {
    // Check for null pointers and other necessary conditions
    // Perform the operation
}

int X509_check_issued(X509* issuer, X509* subject) {
    int Res = 0;
    // Check for null pointers and other necessary conditions
    // Perform the operation
    return Res;
}

int i2d_ASN1_UTF8STRING(const ASN1_UTF8STRING* a, unsigned char** pp) {
    int Res = 0;
    // Check for null pointers and other necessary conditions
    // Perform the operation
    return Res;
}
const char* RAND_file_name(char* buffer, size_t size_t);

int DH_set_length(DH* dh, long length);

int OPENSSL_atexit(void (*handler);

void X509_STORE_CTX_set_current_cert(X509_STORE_CTX* ctx, X509* x);

int i2d_RSAPublicKey_bio(BIO* bp, const RSA* rsa);


int EVP_PKEY_get_raw_public_key(const EVP_PKEY *pkey, unsigned char *pub, size_t *len) {
    int Res = 0;
    sf_set_must_be_not_null(pkey, PUBLIC_KEY_NULL);
    sf_set_must_be_not_null(pub, PUBLIC_KEY_BUFFER_NULL);
    sf_set_must_be_not_null(len, PUBLIC_KEY_LEN_NULL);
    sf_set_trusted_sink_int(len);
    sf_set_tainted(pub, PUBLIC_KEY_TAINTED);
    sf_buf_size_limit(pub, *len);
    Res = EVP_PKEY_get_raw_public_key(pkey, pub, len);
    sf_overwrite(pub);
    sf_set_errno_if(Res <= 0, PUBLIC_KEY_ERROR);
    return Res;
}

int ENGINE_get_flags(const ENGINE *e) {
    int Res = 0;
    sf_set_must_be_not_null(e, ENGINE_NULL);
    Res = ENGINE_get_flags(e);
    sf_set_errno_if(Res < 0, ENGINE_GET_FLAGS_ERROR);
    return Res;
}

int PKCS5_v2_scrypt_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass, int passlen, ASN1_TYPE *param, const EVP_CIPHER *c, const EVP_MD *md, int en_de) {
    int Res = 0;
    sf_set_must_be_not_null(ctx, CIPHER_CTX_NULL);
    sf_set_must_be_not_null(pass, PASSWORD_NULL);
    sf_set_must_be_not_null(param, ASN1_TYPE_NULL);
    sf_set_must_be_not_null(c, CIPHER_NULL);
    sf_set_must_be_not_null(md, MD_NULL);
    sf_password_use(pass, passlen);
    Res = PKCS5_v2_scrypt_keyivgen(ctx, pass, passlen, param, c, md, en_de);
    sf_set_errno_if(Res <= 0, KEYIVGEN_ERROR);
    return Res;
}

void SSL_set_shutdown(SSL *s, int mode) {
    sf_set_must_be_not_null(s, SSL_NULL);
    SSL_set_shutdown(s, mode);
}

void SSL_CTX_sess_set_remove_cb(SSL_CTX *ctx, void (*cb)(SSL_CTX *, SSL_SESSION *)) {
    sf_set_must_be_not_null(ctx, SSL_CTX_NULL);
    SSL_CTX_sess_set_remove_cb(ctx, cb);
}

void EVP_PKEY_meth_get_decrypt(const EVP_PKEY_METHOD *method, int (**decrypt_init) (EVP_PKEY_CTX *ctx), int (**decrypt_fn) (EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen))
{
    sf_set_trusted_sink_ptr(method);
    sf_set_trusted_sink_ptr(decrypt_init);
    sf_set_trusted_sink_ptr(decrypt_fn);
}

X509_SIG* X509_SIG_new()
{
    X509_SIG *Res = NULL;
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    return Res;
}

int UI_method_set_prompt_constructor(UI_METHOD *method,  char* (*prompt_constructor) (UI *ui, const char *prompt, const char *info))
{
    int Res = 0;
    sf_set_trusted_sink_ptr(method);
    sf_set_trusted_sink_ptr(prompt_constructor);
    return Res;
}

int i2d_OCSP_RESPBYTES(const OCSP_RESPBYTES *a, unsigned char **pp)
{
    int Res = 0;
    sf_set_trusted_sink_ptr(a);
    sf_set_trusted_sink_ptr(pp);
    return Res;
}

EVP_PKEY* b2i_PVK_bio(BIO *in, pem_password_cb *cb, void *u)
{
    EVP_PKEY *Res = NULL;
    sf_set_trusted_sink_ptr(in);
    sf_set_trusted_sink_ptr(cb);
    sf_set_trusted_sink_ptr(u);
    return Res;
}

ASN1_GENERALSTRING* d2i_ASN1_GENERALSTRING(ASN1_GENERALSTRING** a, const unsigned char** pp, long length)
{
    ASN1_GENERALSTRING* Res = NULL;
    sf_set_trusted_sink_int(length);
    sf_malloc_arg(Res, length);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    return Res;
}

int PEM_write_bio_X509_AUX(BIO* bp, const X509* x)
{
    int Res = 0;
    sf_set_tainted(x);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int DSA_print(BIO* bp, const DSA* dsa, int off)
{
    int Res = 0;
    sf_set_tainted(dsa);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int BN_rshift(BIGNUM* r, const BIGNUM* a, int n)
{
    int Res = 0;
    sf_set_tainted(a);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int DSA_meth_set_init(DSA_METHOD* dsa, int (*init)(DSA*))
{
    int Res = 0;
    sf_set_tainted(init);
    sf_set_errno_if(Res <= 0);
    return Res;
}

void RAND_keep_random_devices_open(int devices) {
    sf_set_trusted_sink_int(devices);
    // function implementation
}

int DH_meth_set_flags(DH_METHOD *meth, int flags) {
    sf_set_trusted_sink_int(flags);
    // function implementation
    return Res;
}

int EVP_RAND_is_a(const EVP_RAND *rand, const char *name) {
    sf_null_terminated(name);
    // function implementation
    return Res;
}

int EC_GROUP_precompute_mult(EC_GROUP *group, BN_CTX *ctx) {
    // function implementation
    return Res;
}

int SSL_set_tlsext_max_fragment_length(SSL *s, uint8_t mode) {
    sf_set_trusted_sink_int(mode);
    // function implementation
    return Res;
}

const EVP_CIPHER* EVP_aria_128_cbc() {
    const EVP_CIPHER* Res = NULL;
    Res = EVP_aria_128_cbc();
    sf_set_possible_null(Res);
    return Res;
}

ASN1_OBJECT* X509_ATTRIBUTE_get0_object(X509_ATTRIBUTE* attr) {
    ASN1_OBJECT* Res = NULL;
    Res = X509_ATTRIBUTE_get0_object(attr);
    sf_set_possible_null(Res);
    return Res;
}

int SSL_CTX_check_private_key(const SSL_CTX* ctx) {
    int Res = 0;
    Res = SSL_CTX_check_private_key(ctx);
    sf_set_errno_if(Res <= 0);
    return Res;
}

void OPENSSL_cleanse(void* ptr, size_t len) {
    sf_buf_size_limit(ptr, len);
    OPENSSL_cleanse(ptr, len);
    sf_overwrite(ptr);
}

int RSA_print(BIO* bp, const RSA* rsa, int off) {
    int Res = 0;
    Res = RSA_print(bp, rsa, off);
    sf_set_errno_if(Res <= 0);
    return Res;
}

DSA* d2i_DSAPublicKey(DSA** a, const unsigned char** pp, long length)
{
    DSA* Res = NULL;
    sf_set_trusted_sink_int(length);
    sf_malloc_arg(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    sf_lib_arg_type(Res, "DSA");
    return Res;
}

int X509_CRL_sign(X509_CRL* a, EVP_PKEY* b, const EVP_MD* c)
{
    int Res = 0;
    sf_set_errno_if(Res <= 0);
    sf_no_errno_if(Res > 0);
    return Res;
}

void* EVP_MD_CTX_get0_md_data(const EVP_MD_CTX* a)
{
    void* Res = NULL;
    sf_set_possible_null(Res);
    return Res;
}

CERTIFICATEPOLICIES* d2i_CERTIFICATEPOLICIES(CERTIFICATEPOLICIES** a, const unsigned char** pp, long length)
{
    CERTIFICATEPOLICIES* Res = NULL;
    sf_set_trusted_sink_int(length);
    sf_malloc_arg(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    sf_lib_arg_type(Res, "CERTIFICATEPOLICIES");
    return Res;
}

int EVP_CIPHER_CTX_get_num(const EVP_CIPHER_CTX* a)
{
    int Res = 0;
    sf_set_possible_negative(Res);
    return Res;
}
int RSA_meth_set1_name(RSA_METHOD *meth, const char *name);

int EVP_BytesToKey(const EVP_CIPHER *cipher, const EVP_MD *digest, const unsigned char *salt, const unsigned char *data, int datal, int count, unsigned char *key, unsigned char *iv);

void SSL_set_default_passwd_cb_userdata(SSL *ssl, void *userdata);

EXTENDED_KEY_USAGE* EXTENDED_KEY_USAGE_new();

int BN_rshift1(BIGNUM *r, const BIGNUM *a);


void DSA_SIG_free(DSA_SIG* sig) {
    if (sig != NULL) {
        sf_delete(sig, DSA_SIG_MEMORY_CATEGORY);
    }
}

const EVP_MD* ENGINE_get_digest(ENGINE* e, int nid) {
    const EVP_MD* res = NULL;
    if (e != NULL) {
        res = ENGINE_get_digest(e, nid);
        sf_set_possible_null(res);
    }
    return res;
}

int EVP_CIPHER_CTX_set_params(EVP_CIPHER_CTX* ctx, const OSSL_PARAM params[]) {
    int res = 0;
    if (ctx != NULL && params != NULL) {
        res = EVP_CIPHER_CTX_set_params(ctx, params);
        sf_set_errno_if(res == 0);
    }
    return res;
}

int OCSP_basic_sign_ctx(OCSP_BASICRESP* bs, X509* cert, EVP_MD_CTX* ctx, stack_st_X509* cacerts, unsigned long flags) {
    int res = 0;
    if (bs != NULL && cert != NULL && ctx != NULL && cacerts != NULL) {
        res = OCSP_basic_sign_ctx(bs, cert, ctx, cacerts, flags);
        sf_set_errno_if(res == 0);
    }
    return res;
}

int i2d_X509_CRL_fp(FILE* fp, const X509_CRL* crl) {
    int res = 0;
    if (fp != NULL && crl != NULL) {
        res = i2d_X509_CRL_fp(fp, crl);
        sf_set_errno_if(res == 0);
    }
    return res;
}

const OSSL_PARAM* EVP_MAC_settable_ctx_params(const EVP_MAC* mac) {
    const OSSL_PARAM* Res = NULL;
    sf_set_must_be_not_null(mac, "EVP_MAC");
    Res = ossl_mac_settable_ctx_params(mac);
    sf_set_possible_null(Res);
    return Res;
}

int SHA224_Update(SHA256_CTX* ctx, const void* data, size_t len) {
    int Res = 0;
    sf_set_must_be_not_null(ctx, "SHA256_CTX");
    sf_set_must_be_not_null(data, "data");
    sf_buf_size_limit_read(data, len);
    Res = sha256_update(ctx, data, len);
    sf_set_errno_if(Res == 0);
    return Res;
}

int EVP_SIGNATURE_up_ref(EVP_SIGNATURE* sig) {
    int Res = 0;
    sf_set_must_be_not_null(sig, "EVP_SIGNATURE");
    Res = evp_signature_up_ref(sig);
    sf_set_errno_if(Res == 0);
    return Res;
}

int SSL_CTX_get_verify_depth(const SSL_CTX* ctx) {
    int Res = 0;
    sf_set_must_be_not_null(ctx, "SSL_CTX");
    Res = ssl_ctx_get_verify_depth(ctx);
    return Res;
}

int SSL_set1_host(SSL* s, const char* name) {
    int Res = 0;
    sf_set_must_be_not_null(s, "SSL");
    sf_set_must_be_not_null(name, "name");
    sf_null_terminated(name);
    Res = ssl_set1_host(s, name);
    sf_set_errno_if(Res == 0);
    return Res;
}

void ADMISSION_SYNTAX_free(ADMISSION_SYNTAX* ptr) {
    sf_delete(ptr, ADMISSION_SYNTAX_MEMORY_CATEGORY);
}

int DH_compute_key(unsigned char* key, const BIGNUM* pub_key, DH* dh) {
    int res = 0;
    sf_set_tainted(key);
    sf_password_set(key);
    sf_set_errno_if(res <= 0, EINVAL);
    return res;
}

EVP_CIPHER_CTX* EVP_CIPHER_CTX_new() {
    EVP_CIPHER_CTX* res = NULL;
    sf_malloc_arg(res, sizeof(EVP_CIPHER_CTX), EVP_CIPHER_CTX_MEMORY_CATEGORY);
    sf_overwrite(res);
    sf_new(res, EVP_CIPHER_CTX_MEMORY_CATEGORY);
    sf_lib_arg_type(res, "EVP_CIPHER_CTX_new");
    return res;
}

ASN1_SEQUENCE_ANY* d2i_ASN1_SEQUENCE_ANY(ASN1_SEQUENCE_ANY** a, const unsigned char** in, long len) {
    ASN1_SEQUENCE_ANY* res = NULL;
    sf_set_trusted_sink_int(len);
    sf_malloc_arg(res, sizeof(ASN1_SEQUENCE_ANY), ASN1_SEQUENCE_ANY_MEMORY_CATEGORY);
    sf_overwrite(res);
    sf_new(res, ASN1_SEQUENCE_ANY_MEMORY_CATEGORY);
    sf_lib_arg_type(res, "d2i_ASN1_SEQUENCE_ANY");
    return res;
}

void* EVP_CIPHER_CTX_get_app_data(const EVP_CIPHER_CTX* ctx) {
    void* res = NULL;
    sf_set_possible_null(res);
    sf_set_alloc_possible_null(res);
    return res;
}

int i2d_PKCS7_ISSUER_AND_SERIAL(const PKCS7_ISSUER_AND_SERIAL *a, unsigned char **pp)
{
    int ret = 0;
    sf_set_must_be_not_null(a, ISSUER_AND_SERIAL_NOT_NULL);
    sf_set_must_be_not_null(pp, OUTPUT_POINTER_NOT_NULL);
    sf_set_trusted_sink_ptr(pp);
    sf_set_errno_if(ret <= 0, ERRNO_IF_LESS_OR_EQUAL_ZERO);
    sf_set_possible_null(ret);
    return ret;
}

OCSP_CRLID* OCSP_CRLID_new()
{
    OCSP_CRLID *ret = NULL;
    sf_malloc_arg(ret, sizeof(OCSP_CRLID), MALLOC_CATEGORY);
    sf_new(ret, PAGES_MEMORY_CATEGORY);
    sf_set_possible_null(ret);
    return ret;
}

EC_GROUP* EC_GROUP_dup(const EC_GROUP *group)
{
    EC_GROUP *ret = NULL;
    sf_set_must_be_not_null(group, GROUP_NOT_NULL);
    sf_malloc_arg(ret, sizeof(EC_GROUP), MALLOC_CATEGORY);
    sf_new(ret, PAGES_MEMORY_CATEGORY);
    sf_bitcopy(ret, group);
    sf_set_possible_null(ret);
    return ret;
}

ASN1_VALUE* ASN1_item_new_ex(const ASN1_ITEM *it, OSSL_LIB_CTX *ctx, const char *propq)
{
    ASN1_VALUE *ret = NULL;
    sf_set_must_be_not_null(it, ITEM_NOT_NULL);
    sf_malloc_arg(ret, it->size, MALLOC_CATEGORY);
    sf_new(ret, PAGES_MEMORY_CATEGORY);
    sf_set_possible_null(ret);
    return ret;
}

int BN_pseudo_rand(BIGNUM *rnd, int bits, int top, int bottom)
{
    int ret = 0;
    sf_set_must_be_not_null(rnd, RND_NOT_NULL);
    sf_set_errno_if(ret <= 0, ERRNO_IF_LESS_OR_EQUAL_ZERO);
    sf_set_possible_null(ret);
    return ret;
}

void PKCS7_ENVELOPE_free(PKCS7_ENVELOPE* env) {
    sf_set_must_be_not_null(env, FREE_OF_NULL);
    sf_delete(env, PAGES_MEMORY_CATEGORY);
}

int RSA_meth_set_priv_enc(RSA_METHOD* rsa, int (*bn_enc)(int flen, const unsigned char* from, unsigned char* to, RSA* rsa, int padding)) {
    sf_set_must_be_not_null(rsa, FREE_OF_NULL);
    sf_set_must_be_not_null(bn_enc, FREE_OF_NULL);
    sf_lib_arg_type(rsa, "RSA_METHOD");
    sf_lib_arg_type(bn_enc, "RSA_METHOD_PRIV_ENC");
    // Set the private encryption function in the RSA_METHOD structure
    rsa->rsa_priv_enc = bn_enc;
    return 1;
}

void OPENSSL_sk_pop_free(OPENSSL_STACK* st, void (*free_func)(void*)) {
    sf_set_must_be_not_null(st, FREE_OF_NULL);
    sf_set_must_be_not_null(free_func, FREE_OF_NULL);
    sf_lib_arg_type(st, "OPENSSL_STACK");
    sf_lib_arg_type(free_func, "OPENSSL_STACK_FREE_FUNC");
    // Pop and free each element in the stack
    while (OPENSSL_sk_num(st) > 0) {
        void* element = OPENSSL_sk_pop(st);
        free_func(element);
    }
    // Free the stack itself
    OPENSSL_sk_free(st);
}

BN_CTX* BN_CTX_secure_new_ex(OSSL_LIB_CTX* libctx) {
    sf_set_must_be_not_null(libctx, FREE_OF_NULL);
    sf_lib_arg_type(libctx, "OSSL_LIB_CTX");
    // Allocate a new BN_CTX structure
    BN_CTX* ctx = OPENSSL_zalloc(sizeof(BN_CTX));
    sf_new(ctx, PAGES_MEMORY_CATEGORY);
    sf_set_possible_null(ctx);
    return ctx;
}

const BIGNUM* DSA_get0_priv_key(const DSA* d) {
    sf_set_must_be_not_null(d, FREE_OF_NULL);
    sf_lib_arg_type(d, "DSA");
    // Return the private key of the DSA structure
    return d->priv_key;
}

int BN_mod_exp_mont_consttime_x2(BIGNUM *rr, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m, BN_MONT_CTX *mont1, BIGNUM *t, const BIGNUM *b, const BIGNUM *n, const BIGNUM *mont2, BN_MONT_CTX *m_ctx, BN_CTX *ctx) {
    int res = 0;
    sf_set_trusted_sink_int(a);
    sf_set_trusted_sink_int(p);
    sf_set_trusted_sink_int(m);
    sf_set_trusted_sink_int(mont1);
    sf_set_trusted_sink_int(t);
    sf_set_trusted_sink_int(b);
    sf_set_trusted_sink_int(n);
    sf_set_trusted_sink_int(mont2);
    sf_set_trusted_sink_int(m_ctx);
    sf_set_trusted_sink_int(ctx);
    sf_set_errno_if(res == 0);
    sf_no_errno_if(res != 0);
    return res;
}

int EVP_PKEY_CTX_set_signature_md(EVP_PKEY_CTX *ctx, const EVP_MD *md) {
    int res = 0;
    sf_set_trusted_sink_int(ctx);
    sf_set_trusted_sink_int(md);
    sf_set_errno_if(res == 0);
    sf_no_errno_if(res != 0);
    return res;
}

const EVP_CIPHER* EVP_aria_256_cbc() {
    const EVP_CIPHER *res = NULL;
    sf_set_trusted_sink_int(res);
    return res;
}

const EVP_CIPHER* EVP_aes_128_ccm() {
    const EVP_CIPHER *res = NULL;
    sf_set_trusted_sink_int(res);
    return res;
}

void BN_clear_free(BIGNUM *a) {
    sf_set_trusted_sink_int(a);
    sf_delete(a, BIGNUM_MEMORY_CATEGORY);
    sf_lib_arg_type(a, "BIGNUM");
}
int ENGINE_set_destroy_function(ENGINE*, ENGINE_GEN_INT_FUNC_PTR);

int BN_BLINDING_unlock(BN_BLINDING*);

int RSA_test_flags(const RSA*, int);

int i2d_X509_CINF(const X509_CINF*, unsigned char**);

int EVP_ASYM_CIPHER_names_do_all(const EVP_ASYM_CIPHER*, void (const char*, void*);

int EC_GROUP_have_precompute_mult(const EC_GROUP* group);

int X509_OBJECT_set1_X509_CRL(X509_OBJECT* obj, X509_CRL* crl);

X509* PEM_read_bio_X509(BIO* bio, X509** x, pem_password_cb* cb, void* u);

void* SSL_CTX_get0_security_ex_data(const SSL_CTX* ctx);

X509_REQ* X509_REQ_new();


int EVP_PKEY_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen)
{
    int Res = 0;
    // Check if sig is null
    sf_set_must_be_not_null(sig, SIGN_OF_NULL);
    // Check if siglen is null
    sf_set_must_be_not_null(siglen, SIGN_OF_NULL);
    // Check if tbs is null
    sf_set_must_be_not_null(tbs, SIGN_OF_NULL);
    // Check if ctx is null
    sf_set_must_be_not_null(ctx, SIGN_OF_NULL);
    // Check if tbslen is not negative
    sf_set_must_be_positive(tbslen, SIGN_OF_NEGATIVE);
    // Check if siglen is not negative
    sf_set_must_be_positive(*siglen, SIGN_OF_NEGATIVE);
    // Check if siglen is not too large
    sf_buf_size_limit(sig, *siglen);
    // Check if tbslen is not too large
    sf_buf_size_limit((unsigned char *)tbs, tbslen);
    // Check for TOCTTOU race conditions
    sf_tocttou_check(tbs);
    // Check for TOCTTOU race conditions
    sf_tocttou_check(sig);
    // Check for TOCTTOU race conditions
    sf_tocttou_check(siglen);
    // Check for TOCTTOU race conditions
    sf_tocttou_check(ctx);
    // Check for password usage
    sf_password_use(ctx);
    // Check for password setting
    sf_password_set(ctx);
    // Check for memory initialization
    sf_bitinit(ctx);
    // Check for memory overwrite
    sf_overwrite(ctx);
    // Check for error handling
    sf_set_errno_if(Res == 0, SIGN_ERROR);
    // Check for program termination
    sf_terminate_path(Res == 0);
    return Res;
}

int X509_REQ_add1_attr_by_NID(X509_REQ *req, int nid, int atrtype, const unsigned char *data, int len)
{
    int Res = 0;
    // Check if req is null
    sf_set_must_be_not_null(req, ADD_ATTR_OF_NULL);
    // Check if nid is not negative
    sf_set_must_be_positive(nid, ADD_ATTR_OF_NEGATIVE);
    // Check if atrtype is not negative
    sf_set_must_be_positive(atrtype, ADD_ATTR_OF_NEGATIVE);
    // Check if len is not negative
    sf_set_must_be_positive(len, ADD_ATTR_OF_NEGATIVE);
    // Check if data is null
    sf_set_must_be_not_null(data, ADD_ATTR_OF_NULL);
    // Check for TOCTTOU race conditions
    sf_tocttou_check(req);
    // Check for TOCTTOU race conditions
    sf_tocttou_check(data);
    // Check for error handling
    sf_set_errno_if(Res == 0, ADD_ATTR_ERROR);
    // Check for program termination
    sf_terminate_path(Res == 0);
    return Res;
}

int i2d_CERTIFICATEPOLICIES(const CERTIFICATEPOLICIES *policies, unsigned char **out)
{
    int Res = 0;
    // Check if policies is null
    sf_set_must_be_not_null(policies, I2D_OF_NULL);
    // Check if out is null
    sf_set_must_be_not_null(out, I2D_OF_NULL);
    // Check for TOCTTOU race conditions
    sf_tocttou_check(policies);
    // Check for TOCTTOU race conditions
    sf_tocttou_check(out);
    // Check for error handling
    sf_set_errno_if(Res == 0, I2D_ERROR);
    // Check for program termination
    sf_terminate_path(Res == 0);
    return Res;
}

unsigned char* SHA384(const unsigned char *data, size_t len, unsigned char *digest)
{
    unsigned char *Res = NULL;
    // Check if data is null
    sf_set_must_be_not_null(data, SHA384_OF_NULL);
    // Check if len is not negative
    sf_set_must_be_positive(len, SHA384_OF_NEGATIVE);
    // Check if digest is null
    sf_set_must_be_not_null(digest, SHA384_OF_NULL);
    // Check for TOCTTOU race conditions
    sf_tocttou_check(data);
    // Check for TOCTTOU race conditions
    sf_tocttou_check(digest);
    // Check for error handling
    sf_set_errno_if(Res == NULL, SHA384_ERROR);
    // Check for program termination
    sf_terminate_path(Res == NULL);
    return Res;
}

int EVP_MD_get_size(const EVP_MD *md)
{
    int Res = 0;
    // Check if md is null
    sf_set_must_be_not_null(md, GET_SIZE_OF_NULL);
    // Check for TOCTTOU race conditions
    sf_tocttou_check(md);
    // Check for error handling
    sf_set_errno_if(Res == 0, GET_SIZE_ERROR);
    // Check for program termination
    sf_terminate_path(Res == 0);
    return Res;
}
int OSSL_PARAM_set_uint64(OSSL_PARAM *param, uint64_t value);

int EC_POINT_make_affine(const EC_GROUP *group, EC_POINT *point, BN_CTX *ctx);

int RSA_get_version(RSA *rsa);

const EVP_CIPHER * EVP_cast5_cbc();

const EVP_CIPHER * EVP_sm4_ofb();


int SSL_CTX_set_default_ctlog_list_file(SSL_CTX *ctx) {
    int Res = 0;
    sf_set_trusted_sink_int(ctx);
    sf_set_errno_if(Res == 0);
    return Res;
}

OCSP_SINGLERESP* OCSP_SINGLERESP_new() {
    OCSP_SINGLERESP* Res = NULL;
    Res = (OCSP_SINGLERESP*)sf_malloc_arg(sizeof(OCSP_SINGLERESP));
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_lib_arg_type(Res, "OCSP_SINGLERESP");
    return Res;
}

X509_ATTRIBUTE* d2i_X509_ATTRIBUTE(X509_ATTRIBUTE** a, const unsigned char** in, long len) {
    X509_ATTRIBUTE* Res = NULL;
    Res = (X509_ATTRIBUTE*)sf_malloc_arg(sizeof(X509_ATTRIBUTE));
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_lib_arg_type(Res, "X509_ATTRIBUTE");
    return Res;
}

int SSL_CTX_remove_session(SSL_CTX *ctx, SSL_SESSION *c) {
    int Res = 0;
    sf_set_trusted_sink_int(ctx);
    sf_set_errno_if(Res == 0);
    return Res;
}

void SSL_set_verify_result(SSL *s, long v) {
    sf_set_trusted_sink_int(s);
    sf_set_trusted_sink_int(v);
}

int RSA_public_decrypt(int flen, const unsigned char* from, unsigned char* to, RSA* rsa, int padding) {
    int Res = 0;
    sf_set_trusted_sink_int(flen);
    sf_set_trusted_sink_ptr(from);
    sf_set_trusted_sink_ptr(to);
    sf_set_trusted_sink_ptr(rsa);
    sf_set_trusted_sink_int(padding);
    Res = RSA_public_decrypt(flen, from, to, rsa, padding);
    sf_overwrite(Res);
    return Res;
}

int DH_get_nid(const DH* dh) {
    int Res = 0;
    sf_set_trusted_sink_ptr(dh);
    Res = DH_get_nid(dh);
    sf_overwrite(Res);
    return Res;
}

BIGNUM* ASN1_INTEGER_to_BN(const ASN1_INTEGER* ai, BIGNUM* bn) {
    BIGNUM* Res = NULL;
    sf_set_trusted_sink_ptr(ai);
    sf_set_trusted_sink_ptr(bn);
    Res = ASN1_INTEGER_to_BN(ai, bn);
    sf_overwrite(Res);
    return Res;
}

int ASYNC_WAIT_CTX_get_status(ASYNC_WAIT_CTX* ctx) {
    int Res = 0;
    sf_set_trusted_sink_ptr(ctx);
    Res = ASYNC_WAIT_CTX_get_status(ctx);
    sf_overwrite(Res);
    return Res;
}

BIO* SSL_get_rbio(const SSL* s) {
    BIO* Res = NULL;
    sf_set_trusted_sink_ptr(s);
    Res = SSL_get_rbio(s);
    sf_overwrite(Res);
    return Res;
}
int X509_cmp_time(const ASN1_TIME*, time_t*);

EVP_PKEY* EVP_PKEY_new_raw_public_key_ex(OSSL_LIB_CTX*, const char*, const char*, const unsigned char*, size_t);

X509_LOOKUP_get_by_fingerprint_fn X509_LOOKUP_meth_get_get_by_fingerprint(const X509_LOOKUP_METHOD*);

int EVP_MD_meth_set_app_datasize(EVP_MD*, int);

int RSA_private_encrypt(int, const unsigned char*, unsigned char*, RSA*, int);

int X509_EXTENSION_set_critical(X509_EXTENSION *ex, int crit);

void ASYNC_block_pause();

int SSL_alloc_buffers(SSL *s);

int SSL_CIPHER_is_aead(const SSL_CIPHER *c);

const SSL_METHOD* DTLS_server_method();


void DIST_POINT_NAME_free(DIST_POINT_NAME* a) {
    if (a != NULL) {
        sf_delete(a, PAGES_MEMORY_CATEGORY);
    }
}

int DSA_meth_set_keygen(DSA_METHOD* dsa, int (*keygen)(DSA*)) {
    int res = 0;
    sf_set_trusted_sink_int(dsa);
    sf_set_trusted_sink_ptr(keygen);
    sf_set_errno_if(res == 0);
    return res;
}

int EVP_PKEY_verify(EVP_PKEY_CTX* ctx, const unsigned char* sig, size_t siglen, const unsigned char* tbs, size_t tbslen) {
    int res = 0;
    sf_set_trusted_sink_int(ctx);
    sf_set_trusted_sink_ptr(sig);
    sf_set_trusted_sink_ptr(tbs);
    sf_set_errno_if(res <= 0);
    return res;
}

const EC_METHOD* EC_GFp_simple_method() {
    const EC_METHOD* res = NULL;
    sf_set_trusted_sink_ptr(res);
    return res;
}

int EVP_PKEY_CTX_set_rsa_pss_saltlen(EVP_PKEY_CTX* ctx, int len) {
    int res = 0;
    sf_set_trusted_sink_int(ctx);
    sf_set_trusted_sink_int(len);
    sf_set_errno_if(res <= 0);
    return res;
}

void X509_NAME_print_ex_fp(FILE *fp, const X509_NAME *name, int indent, unsigned long flags) {
    int res = 0;
    sf_set_must_not_be_null(fp);
    sf_set_must_not_be_null(name);
    sf_set_must_be_positive(indent);
    sf_set_must_be_positive(flags);
    res = X509_NAME_print_ex_fp(fp, name, indent, flags);
    sf_set_errno_if(res <= 0);
}

void EVP_Cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, unsigned int inl) {
    int res = 0;
    sf_set_must_not_be_null(ctx);
    sf_set_must_not_be_null(out);
    sf_set_must_not_be_null(in);
    sf_set_must_be_positive(inl);
    res = EVP_Cipher(ctx, out, in, inl);
    sf_set_errno_if(res <= 0);
}

void EVP_des_cfb1() {
    const EVP_CIPHER *res = NULL;
    res = EVP_des_cfb1();
    sf_set_possible_null(res);
}

void X509_chain_up_ref(stack_st_X509 *chain) {
    stack_st_X509 *res = NULL;
    sf_set_must_not_be_null(chain);
    res = X509_chain_up_ref(chain);
    sf_set_possible_null(res);
}

void X509_REQ_get_attr_count(const X509_REQ *req) {
    int res = 0;
    sf_set_must_not_be_null(req);
    res = X509_REQ_get_attr_count(req);
    sf_set_must_be_positive(res);
}

int EVP_default_properties_is_fips_enabled(OSSL_LIB_CTX* ctx) {
    int Res = 0;
    // Check if ctx is not null
    sf_set_must_be_not_null(ctx, FIPS_ENABLED_OF_NULL);
    // Check if ctx is trusted sink
    sf_set_trusted_sink_ptr(ctx);
    // Set errno if there is an error
    sf_set_errno_if(Res == 0);
    return Res;
}

const BIGNUM* BN_get0_nist_prime_384() {
    const BIGNUM* Res = NULL;
    // Set errno if there is an error
    sf_set_errno_if(Res == NULL);
    return Res;
}

int X509at_get_attr_by_NID(const stack_st_X509_ATTRIBUTE* attrs, int nid, int lastpos) {
    int Res = 0;
    // Set errno if there is an error
    sf_set_errno_if(Res == -1);
    return Res;
}

int BIO_lookup(const char* host, const char* service, BIO_lookup_type lookup_type, int family, int socktype, BIO_ADDRINFO** res) {
    int Res = 0;
    // Check if host and service are not null
    sf_set_must_be_not_null(host, LOOKUP_HOST_OF_NULL);
    sf_set_must_be_not_null(service, LOOKUP_SERVICE_OF_NULL);
    // Set errno if there is an error
    sf_set_errno_if(Res == -1);
    return Res;
}

PROXY_POLICY* d2i_PROXY_POLICY(PROXY_POLICY** a, const unsigned char** in, long len) {
    PROXY_POLICY* Res = NULL;
    // Set errno if there is an error
    sf_set_errno_if(Res == NULL);
    return Res;
}

void RSA_padding_check_PKCS1_OAEP(unsigned char *to, int tlen, const unsigned char *f, int fl, int num, const unsigned char *p, int pl) {
    int res = 0;
    sf_set_trusted_sink_int(tlen);
    sf_set_trusted_sink_int(fl);
    sf_set_trusted_sink_int(num);
    sf_set_trusted_sink_int(pl);
    sf_set_errno_if(res == 0, EINVAL);
    sf_no_errno_if(res != 0);
}

void X509_set_subject_name(X509 *x, const X509_NAME *name) {
    int res = 0;
    sf_set_errno_if(res == 0, EINVAL);
    sf_no_errno_if(res != 0);
}

void OPENSSL_sk_insert(OPENSSL_STACK *st, const void *data, int loc) {
    int res = 0;
    sf_set_trusted_sink_int(loc);
    sf_set_errno_if(res == 0, EINVAL);
    sf_no_errno_if(res != 0);
}

void SSL_CTX_set_next_protos_advertised_cb(SSL_CTX *s, SSL_CTX_npn_advertised_cb_func cb, void *arg) {
    sf_set_tainted(arg);
}

void EVP_SignFinal_ex(EVP_MD_CTX *ctx, unsigned char *sigret, unsigned int *siglen, EVP_PKEY *pkey, OSSL_LIB_CTX *libctx, const char *propq) {
    int res = 0;
    sf_set_errno_if(res == 0, EINVAL);
    sf_no_errno_if(res != 0);
}

int i2d_PKCS7_ENC_CONTENT(const PKCS7_ENC_CONTENT *a, unsigned char **pp)
{
    int ret = 0;
    sf_set_trusted_sink_int(a);
    sf_set_trusted_sink_ptr(pp);
    sf_set_errno_if(ret <= 0, "i2d_PKCS7_ENC_CONTENT");
    return ret;
}

void SSL_CTX_free(SSL_CTX *ctx)
{
    sf_set_must_not_be_null(ctx, "SSL_CTX_free");
    sf_delete(ctx, SSL_CTX_CATEGORY);
    sf_lib_arg_type(ctx, "SSL_CTX_free");
}

int i2d_RSA_OAEP_PARAMS(const RSA_OAEP_PARAMS *a, unsigned char **pp)
{
    int ret = 0;
    sf_set_trusted_sink_int(a);
    sf_set_trusted_sink_ptr(pp);
    sf_set_errno_if(ret <= 0, "i2d_RSA_OAEP_PARAMS");
    return ret;
}

const BIGNUM* RSA_get0_dmp1(const RSA *r)
{
    const BIGNUM *ret = NULL;
    sf_set_must_not_be_null(r, "RSA_get0_dmp1");
    ret = r->dmp1;
    sf_set_possible_null(ret, "RSA_get0_dmp1");
    return ret;
}

int X509_STORE_CTX_get_error(const X509_STORE_CTX *ctx)
{
    int ret = 0;
    sf_set_must_not_be_null(ctx, "X509_STORE_CTX_get_error");
    ret = ctx->error;
    sf_set_possible_negative(ret, "X509_STORE_CTX_get_error");
    return ret;
}

X509_CRL_INFO* X509_CRL_INFO_new() {
    X509_CRL_INFO* Res = NULL;
    Res = (X509_CRL_INFO*)OPENSSL_malloc(sizeof(X509_CRL_INFO));
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    return Res;
}

int i2d_BASIC_CONSTRAINTS(const BASIC_CONSTRAINTS* a, unsigned char** pp) {
    int Res = 0;
    Res = i2d_ASN1_INTEGER(a->ca, pp);
    sf_set_errno_if(Res < 0);
    return Res;
}

X509_SIG* d2i_PKCS8_fp(FILE* fp, X509_SIG** x) {
    X509_SIG* Res = NULL;
    Res = (X509_SIG*)OPENSSL_malloc(sizeof(X509_SIG));
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    Res->algor = d2i_X509_ALGOR_fp(fp, NULL);
    sf_set_errno_if(Res->algor == NULL);
    Res->digest = d2i_ASN1_BIT_STRING_fp(fp, NULL);
    sf_set_errno_if(Res->digest == NULL);
    return Res;
}

void EVP_MD_CTX_clear_flags(EVP_MD_CTX* ctx, int flags) {
    ctx->flags &= ~flags;
    sf_overwrite(ctx);
}

const EC_METHOD* EC_GFp_nistp224_method() {
    const EC_METHOD* Res = NULL;
    Res = EC_GFp_nistp224();
    sf_overwrite(Res);
    return Res;
}

unsigned long OPENSSL_LH_num_items(const OPENSSL_LHASH* lh)
{
    unsigned long Res = 0;
    sf_set_must_be_not_null(lh, LHASH_NULL);
    Res = lh->num_items;
    sf_set_possible_null(Res);
    return Res;
}

BIGNUM* BN_get_rfc3526_prime_6144(BIGNUM* bn)
{
    BIGNUM* Res = NULL;
    sf_set_must_be_not_null(bn, BN_NULL);
    Res = BN_new();
    sf_set_possible_null(Res);
    if (Res != NULL)
    {
        BN_set_word(Res, 6144);
    }
    return Res;
}

int EVP_PKEY_CTX_set_ecdh_kdf_md(EVP_PKEY_CTX* ctx, const EVP_MD* md)
{
    int Res = 0;
    sf_set_must_be_not_null(ctx, EVP_PKEY_CTX_NULL);
    sf_set_must_be_not_null(md, EVP_MD_NULL);
    Res = EVP_PKEY_CTX_set_ecdh_kdf_md(ctx, md);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int EVP_PKEY_digestsign_supports_digest(EVP_PKEY* pkey, OSSL_LIB_CTX* ctx, const char* mdname, const char* mdprops)
{
    int Res = 0;
    sf_set_must_be_not_null(pkey, EVP_PKEY_NULL);
    sf_set_must_be_not_null(ctx, OSSL_LIB_CTX_NULL);
    sf_set_must_be_not_null(mdname, MD_NAME_NULL);
    sf_set_must_be_not_null(mdprops, MD_PROPS_NULL);
    Res = EVP_PKEY_digestsign_supports_digest(pkey, ctx, mdname, mdprops);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int DH_compute_key_padded(unsigned char* key, const BIGNUM* pub_key, DH* dh)
{
    int Res = 0;
    sf_set_must_be_not_null(key, KEY_NULL);
    sf_set_must_be_not_null(pub_key, BIGNUM_NULL);
    sf_set_must_be_not_null(dh, DH_NULL);
    Res = DH_compute_key_padded(key, pub_key, dh);
    sf_set_errno_if(Res <= 0);
    return Res;
}
int i2d_re_X509_REQ_tbs(X509_REQ* a, unsigned char** pp);

OCSP_RESPONSE* OCSP_RESPONSE_new();

void SSL_CTX_set_record_padding_callback_arg(SSL_CTX* ctx, void* arg);

void EVP_PKEY_CTX_set_app_data(EVP_PKEY_CTX* ctx, void* data);

int OCSP_request_add1_cert(OCSP_REQUEST* req, X509* cert);


void ADMISSIONS_free(ADMISSIONS *adm) {
    sf_delete(adm, ADMISSIONS_MEMORY_CATEGORY);
}

int SCT_set1_log_id(SCT *sct, const unsigned char *log_id, size_t log_id_len) {
    sf_set_trusted_sink_int(log_id_len);
    sf_set_buf_size(log_id, log_id_len);
    sf_buf_overlap(sct->log_id, log_id);
    sf_bitcopy(sct->log_id, log_id, log_id_len);
    sf_overwrite(sct->log_id);
    return 1;
}

void X509_SIG_INFO_set(X509_SIG_INFO *sig_info, int md_nid, int pkey_nid, int sec_bits, uint32_t flags) {
    sf_set_trusted_sink_int(md_nid);
    sf_set_trusted_sink_int(pkey_nid);
    sf_set_trusted_sink_int(sec_bits);
    sf_set_trusted_sink_int(flags);
    sig_info->md_nid = md_nid;
    sig_info->pkey_nid = pkey_nid;
    sig_info->sec_bits = sec_bits;
    sig_info->flags = flags;
    sf_overwrite(sig_info);
}

int OCSP_resp_get0_signer(OCSP_BASICRESP *bs, X509 **signer, stack_st_X509 *certs) {
    sf_set_must_be_not_null(bs, FREE_OF_NULL);
    sf_set_must_be_not_null(signer, FREE_OF_NULL);
    sf_set_must_be_not_null(certs, FREE_OF_NULL);
    *signer = bs->signer;
    sf_overwrite(signer);
    return 1;
}

const OSSL_PARAM *EVP_MAC_CTX_settable_params(EVP_MAC_CTX *ctx) {
    sf_set_must_be_not_null(ctx, FREE_OF_NULL);
    sf_overwrite(ctx->settable_params);
    return ctx->settable_params;
}
int SSL_SESSION_print_keylog(BIO*, const SSL_SESSION*);

int EVP_PKEY_decrypt_init_ex(EVP_PKEY_CTX*, const OSSL_PARAM[]);

size_t EC_POINT_point2buf(const EC_GROUP*, const EC_POINT*, point_conversion_form_t, unsigned char**, BN_CTX*);

X509_VERIFY_PARAM* X509_STORE_get0_param(const X509_STORE*);

void NAMING_AUTHORITY_set0_authorityId(NAMING_AUTHORITY*, ASN1_OBJECT*);


int CRYPTO_secure_malloc_done() {
    int res = 0;
    sf_set_errno_if(res, EINVAL);
    sf_no_errno_if(res);
    return res;
}

int i2d_X509_REVOKED(const X509_REVOKED *a, unsigned char **pp) {
    int res = 0;
    sf_set_errno_if(res, EINVAL);
    sf_no_errno_if(res);
    return res;
}

void ECPARAMETERS_free(ECPARAMETERS *ecparameters) {
    sf_delete(ecparameters, PAGES_MEMORY_CATEGORY);
    sf_lib_arg_type(ecparameters, "ECPARAMETERS");
}

int RSA_padding_add_PKCS1_type_1(unsigned char *to, int tlen, const unsigned char *from, int flen) {
    int res = 0;
    sf_set_errno_if(res, EINVAL);
    sf_no_errno_if(res);
    return res;
}

void *CRYPTO_zalloc(size_t num, const char *file, int line) {
    void *res = NULL;
    sf_malloc_arg(num);
    sf_new(res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(res);
    sf_lib_arg_type(res, "CRYPTO_zalloc");
    return res;
}

int i2d_EC_PUBKEY_fp(FILE *fp, const EC_KEY *key) {
    int res = 0;
    sf_set_must_be_not_null(fp, FILE_PTR_NULL);
    sf_set_must_be_not_null(key, EC_KEY_PTR_NULL);
    // ...
    return res;
}

int EVP_CIPHER_meth_set_init(EVP_CIPHER *cipher, int (*init)(EVP_CIPHER_CTX*, const unsigned char*, const unsigned char*, int)) {
    int res = 0;
    sf_set_must_be_not_null(cipher, EVP_CIPHER_PTR_NULL);
    sf_set_must_be_not_null(init, INIT_FUNC_PTR_NULL);
    // ...
    return res;
}

int EVP_PKEY_CTX_set0_ecdh_kdf_ukm(EVP_PKEY_CTX *ctx, unsigned char *ukm, int len) {
    int res = 0;
    sf_set_must_be_not_null(ctx, EVP_PKEY_CTX_PTR_NULL);
    sf_set_must_be_not_null(ukm, UKM_PTR_NULL);
    sf_set_must_be_not_null(len, LEN_PTR_NULL);
    // ...
    return res;
}

SSL_SESSION* SSL_CTX_sess_get_get_cb(SSL_CTX *ctx, const unsigned char *data, int len, int *copy) {
    SSL_SESSION *res = NULL;
    sf_set_must_be_not_null(ctx, SSL_CTX_PTR_NULL);
    sf_set_must_be_not_null(data, DATA_PTR_NULL);
    sf_set_must_be_not_null(len, LEN_PTR_NULL);
    sf_set_must_be_not_null(copy, COPY_PTR_NULL);
    // ...
    return res;
}

int DSA_security_bits(const DSA *dsa) {
    int res = 0;
    sf_set_must_be_not_null(dsa, DSA_PTR_NULL);
    // ...
    return res;
}

unsigned int SSL_SESSION_get_compress_id(const SSL_SESSION* sess) {
    unsigned int Res = 0;
    sf_set_trusted_sink_int(Res);
    sf_set_possible_null(Res);
    Res = sess->compress_meth;
    sf_overwrite(Res);
    return Res;
}

int BN_div(BIGNUM* dv, BIGNUM* rem, const BIGNUM* a, const BIGNUM* b, BN_CTX* ctx) {
    int Res = 0;
    sf_set_errno_if(Res, BN_div(dv, rem, a, b, ctx) == 0);
    return Res;
}

ASN1_INTEGER* X509_get_serialNumber(X509* x) {
    ASN1_INTEGER* Res = NULL;
    sf_set_possible_null(Res);
    Res = X509_get_serialNumber(x);
    sf_set_alloc_possible_null(Res);
    return Res;
}

X509_PUBKEY* d2i_X509_PUBKEY_bio(BIO* bp, X509_PUBKEY** x) {
    X509_PUBKEY* Res = NULL;
    sf_set_possible_null(Res);
    Res = d2i_X509_PUBKEY_bio(bp, x);
    sf_set_alloc_possible_null(Res);
    return Res;
}

int ENGINE_set_id(ENGINE* e, const char* id) {
    int Res = 0;
    sf_set_errno_if(Res, ENGINE_set_id(e, id) == 0);
    return Res;
}
int EVP_PKEY_CTX_set_dh_paramgen_type(EVP_PKEY_CTX* ctx, int type);

int X509_LOOKUP_shutdown(X509_LOOKUP* lookup);

void EVP_PKEY_asn1_set_param_check(EVP_PKEY_ASN1_METHOD* ameth, int (*check);

int ENGINE_init(ENGINE* e);

int BN_mod_exp_mont(BIGNUM* r, const BIGNUM* a, const BIGNUM* p, const BIGNUM* m, BN_CTX* ctx, BN_MONT_CTX* m_ctx);


void EVP_PKEY_meth_set_init(EVP_PKEY_METHOD *pmeth, int (*init)(EVP_PKEY_CTX *ctx))
{
    sf_set_trusted_sink_ptr(pmeth);
    sf_set_trusted_sink_ptr(init);
    sf_set_tainted(pmeth);
    sf_set_tainted(init);
    // function body
}

int OSSL_parse_url(const char *url, char **scheme, char **host, char **port, char **path, int *use_ssl, char **query, char **fragment)
{
    sf_set_must_not_be_null(url);
    sf_set_tainted(url);
    sf_set_possible_null(scheme);
    sf_set_possible_null(host);
    sf_set_possible_null(port);
    sf_set_possible_null(path);
    sf_set_possible_null(query);
    sf_set_possible_null(fragment);
    // function body
}

int BIO_accept_ex(int sock, BIO_ADDR *addr, int timeout)
{
    sf_set_must_not_be_null(addr);
    sf_set_must_be_positive(sock);
    sf_set_must_be_not_null(addr);
    sf_set_possible_null(addr);
    // function body
}

int OSSL_PARAM_get_BN(const OSSL_PARAM *p, BIGNUM **bn)
{
    sf_set_must_not_be_null(p);
    sf_set_must_not_be_null(bn);
    sf_set_possible_null(*bn);
    // function body
}

BASIC_CONSTRAINTS* BASIC_CONSTRAINTS_new()
{
    BASIC_CONSTRAINTS *Res = NULL;
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    // function body
    return Res;
}

EC_GROUP* EC_GROUP_new_curve_GF2m(const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx) {
    EC_GROUP *Res = NULL;
    sf_set_trusted_sink_int(p);
    sf_set_trusted_sink_int(a);
    sf_set_trusted_sink_int(b);
    Res = EC_GROUP_new_curve_GF2m(p, a, b, ctx);
    sf_overwrite(Res);
    return Res;
}

int i2d_PUBKEY_fp(FILE *fp, const EVP_PKEY *pkey) {
    int Res = 0;
    sf_set_must_not_be_null(fp);
    sf_set_must_not_be_null(pkey);
    Res = i2d_PUBKEY_fp(fp, pkey);
    sf_set_errno_if(Res <= 0);
    return Res;
}

ASN1_TIME* X509_gmtime_adj(ASN1_TIME *s, long adj) {
    ASN1_TIME *Res = NULL;
    sf_set_must_not_be_null(s);
    Res = X509_gmtime_adj(s, adj);
    sf_overwrite(Res);
    return Res;
}

const char* EVP_PKEY_get0_description(const EVP_PKEY *pkey) {
    const char *Res = NULL;
    sf_set_must_not_be_null(pkey);
    Res = EVP_PKEY_get0_description(pkey);
    sf_set_possible_null(Res);
    return Res;
}

int X509_add_cert(stack_st_X509 *sk, X509 *x, int loc) {
    int Res = 0;
    sf_set_must_not_be_null(sk);
    sf_set_must_not_be_null(x);
    Res = X509_add_cert(sk, x, loc);
    sf_set_errno_if(Res <= 0);
    return Res;
}

const EVP_CIPHER* EVP_rc2_64_cbc() {
    const EVP_CIPHER* Res = NULL;
    Res = EVP_rc2_64_cbc();
    sf_set_possible_null(Res);
    return Res;
}

char* (UI*, const char*, const char*)* UI_method_get_prompt_constructor(const UI_METHOD* method) {
    char* (UI*, const char*, const char*)* Res = NULL;
    Res = UI_method_get_prompt_constructor(method);
    sf_set_possible_null(Res);
    return Res;
}

OCSP_ONEREQ* OCSP_ONEREQ_new() {
    OCSP_ONEREQ* Res = NULL;
    Res = OCSP_ONEREQ_new();
    sf_set_possible_null(Res);
    return Res;
}

X509_STORE_CTX_verify_fn X509_STORE_CTX_get_verify(const X509_STORE_CTX* ctx) {
    X509_STORE_CTX_verify_fn Res = NULL;
    Res = X509_STORE_CTX_get_verify(ctx);
    sf_set_possible_null(Res);
    return Res;
}

BN_CTX* BN_CTX_new_ex(OSSL_LIB_CTX* libctx) {
    BN_CTX* Res = NULL;
    Res = BN_CTX_new_ex(libctx);
    sf_set_possible_null(Res);
    return Res;
}

SXNET* d2i_SXNET(SXNET** a, const unsigned char** pp, long length) {
    SXNET* Res = NULL;
    sf_set_trusted_sink_int(length);
    sf_malloc_arg(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    sf_lib_arg_type(Res, "SXNET");
    return Res;
}

char* SSL_get_srp_userinfo(SSL* s) {
    char* Res = NULL;
    sf_set_tainted(Res);
    sf_set_possible_null(Res);
    sf_lib_arg_type(Res, "SSL_get_srp_userinfo");
    return Res;
}

int EVP_PKEY_set_type_str(EVP_PKEY* pkey, const char* str, int len) {
    int Res = 0;
    sf_set_trusted_sink_int(len);
    sf_set_errno_if(Res, EVP_PKEY_set_type_str(pkey, str, len) <= 0);
    sf_no_errno_if(Res, EVP_PKEY_set_type_str(pkey, str, len) > 0);
    sf_lib_arg_type(pkey, "EVP_PKEY");
    return Res;
}

OTHERNAME* OTHERNAME_new() {
    OTHERNAME* Res = NULL;
    sf_malloc_arg(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    sf_lib_arg_type(Res, "OTHERNAME");
    return Res;
}

ssize_t SSL_sendfile(SSL* s, int out_fd, off_t offset, size_t count, int flags) {
    ssize_t Res = 0;
    sf_set_trusted_sink_int(out_fd);
    sf_set_trusted_sink_int(offset);
    sf_set_trusted_sink_int(count);
    sf_set_trusted_sink_int(flags);
    sf_set_errno_if(Res, SSL_sendfile(s, out_fd, offset, count, flags) <= 0);
    sf_no_errno_if(Res, SSL_sendfile(s, out_fd, offset, count, flags) > 0);
    sf_lib_arg_type(s, "SSL");
    return Res;
}
int SSL_peek_ex(SSL* ssl, void* buf, size_t num, size_t* readBytes);

unsigned int ENGINE_get_table_flags();

ASN1_TYPE* ASN1_generate_v3(const char* str, X509V3_CTX* ctx);

int X509_NAME_print_ex(BIO* bio, const X509_NAME* name, int indent, unsigned long flags);

const SSL_CIPHER* SSL_get_current_cipher(const SSL* ssl);

int OSSL_HTTP_REQ_CTX_add1_header(OSSL_HTTP_REQ_CTX* ctx, const char* name, const char* value);

int OPENSSL_strncasecmp(const char* s1, const char* s2, size_t n);

const stack_st_ASN1_STRING* PROFESSION_INFO_get0_professionItems(const PROFESSION_INFO* info);

int DH_set0_key(DH* dh, BIGNUM* pub_key, BIGNUM* priv_key);

int i2d_PKCS8_bio(BIO* bp, const X509_SIG* p8);


int i2d_ASN1_bio_stream(BIO *in, ASN1_VALUE *val, BIO *out, int flags, const ASN1_ITEM *it) {
    int res = 0;
    // Check for null pointers
    sf_set_must_be_not_null(in, "BIO");
    sf_set_must_be_not_null(val, "ASN1_VALUE");
    sf_set_must_be_not_null(out, "BIO");
    sf_set_must_be_not_null(it, "ASN1_ITEM");

    // Check for possible negative values
    sf_set_possible_negative(res);

    // Set errno if there's an error
    sf_set_errno_if(res < 0);

    return res;
}

void EVP_PKEY_meth_copy(EVP_PKEY_METHOD *dst, const EVP_PKEY_METHOD *src) {
    // Check for null pointers
    sf_set_must_be_not_null(dst, "EVP_PKEY_METHOD");
    sf_set_must_be_not_null(src, "EVP_PKEY_METHOD");

    // Copy the method
    sf_bitcopy(dst, src);
}

X509_EXTENSIONS* d2i_X509_EXTENSIONS(X509_EXTENSIONS **a, const unsigned char **in, long len) {
    X509_EXTENSIONS *res = NULL;
    // Check for null pointers
    sf_set_must_be_not_null(a, "X509_EXTENSIONS");
    sf_set_must_be_not_null(*in, "unsigned char");

    // Set errno if there's an error
    sf_set_errno_if(res == NULL);

    return res;
}

void X509_REQ_INFO_free(X509_REQ_INFO *a) {
    // Check for null pointers
    sf_set_must_be_not_null(a, "X509_REQ_INFO");

    // Free the memory
    sf_delete(a, "X509_REQ_INFO");
}

int OCSP_RESPID_set_by_key(OCSP_RESPID *id, X509 *cert) {
    int res = 0;
    // Check for null pointers
    sf_set_must_be_not_null(id, "OCSP_RESPID");
    sf_set_must_be_not_null(cert, "X509");

    // Set errno if there's an error
    sf_set_errno_if(res <= 0);

    return res;
}

EVP_RAND_CTX* RAND_get0_private(OSSL_LIB_CTX* libctx) {
    EVP_RAND_CTX* Res = NULL;
    sf_set_must_be_not_null(libctx, "libctx");
    Res = EVP_RAND_CTX_new(libctx);
    sf_set_possible_null(Res);
    return Res;
}

int BIO_write_ex(BIO* bp, const void* data, size_t dlen, size_t* written) {
    int Res = 0;
    sf_set_must_be_not_null(bp, "bp");
    sf_set_must_be_not_null(data, "data");
    sf_set_must_be_not_null(written, "written");
    Res = BIO_write(bp, data, dlen);
    sf_set_errno_if(Res <= 0);
    *written = Res;
    return Res;
}

int SSL_clear(SSL* ssl) {
    int Res = 0;
    sf_set_must_be_not_null(ssl, "ssl");
    Res = SSL_clear(ssl);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int CRYPTO_memcmp(const void* a, const void* b, size_t len) {
    int Res = 0;
    sf_set_must_be_not_null(a, "a");
    sf_set_must_be_not_null(b, "b");
    Res = CRYPTO_memcmp(a, b, len);
    return Res;
}

int SSL_get_rfd(const SSL* ssl) {
    int Res = 0;
    sf_set_must_be_not_null(ssl, "ssl");
    Res = SSL_get_rfd(ssl);
    sf_set_must_be_not_null(Res);
    return Res;
}

void BIO_ssl_shutdown(BIO* bio) {
    sf_set_trusted_sink_ptr(bio);
    // Implementation
}

int SSL_add_dir_cert_subjects_to_stack(stack_st_X509_NAME* stack, const char* dir) {
    sf_set_trusted_sink_ptr(stack);
    sf_set_trusted_sink_ptr(dir);
    // Implementation
}

int (BIO*)* BIO_meth_get_destroy(const BIO_METHOD* method) {
    sf_set_trusted_sink_ptr(method);
    // Implementation
}

int SSL_use_certificate_file(SSL* ssl, const char* file, int type) {
    sf_set_trusted_sink_ptr(ssl);
    sf_set_trusted_sink_ptr(file);
    // Implementation
}

int i2d_DSAPublicKey(const DSA* dsa, unsigned char** pp) {
    sf_set_trusted_sink_ptr(dsa);
    sf_set_trusted_sink_ptr(pp);
    // Implementation
}

SSL_verify_cb SSL_CTX_get_verify_callback(const SSL_CTX* ctx) {
    SSL_verify_cb res = NULL;
    sf_set_trusted_sink_ptr(ctx);
    sf_set_possible_null(res);
    res = SSL_CTX_get_verify_callback(ctx);
    sf_set_possible_null(res);
    return res;
}

const EVP_CIPHER* EVP_aes_128_cbc() {
    const EVP_CIPHER* res = NULL;
    res = EVP_aes_128_cbc();
    sf_set_possible_null(res);
    return res;
}

POLICYINFO* POLICYINFO_new() {
    POLICYINFO* res = NULL;
    res = POLICYINFO_new();
    sf_set_possible_null(res);
    return res;
}

CTLOG* CTLOG_new_ex(EVP_PKEY* pkey, const char* name, OSSL_LIB_CTX* libctx, const char* propq) {
    CTLOG* res = NULL;
    sf_set_trusted_sink_ptr(pkey);
    sf_set_trusted_sink_ptr(libctx);
    sf_set_possible_null(res);
    res = CTLOG_new_ex(pkey, name, libctx, propq);
    sf_set_possible_null(res);
    return res;
}

const EC_METHOD* EC_GROUP_method_of(const EC_GROUP* group) {
    const EC_METHOD* res = NULL;
    sf_set_trusted_sink_ptr(group);
    res = EC_GROUP_method_of(group);
    sf_set_possible_null(res);
    return res;
}

RSA* d2i_RSA_PUBKEY(RSA** a, const unsigned char** pp, long length)
{
    RSA* Res = NULL;
    sf_set_trusted_sink_int(length);
    sf_malloc_arg(Res, length);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    sf_lib_arg_type(Res, "RSA");
    return Res;
}

const EVP_CIPHER* EVP_rc2_40_cbc()
{
    const EVP_CIPHER* Res = NULL;
    sf_overwrite(Res);
    sf_set_possible_null(Res);
    return Res;
}

int SSL_CIPHER_get_auth_nid(const SSL_CIPHER* cipher)
{
    int Res = 0;
    sf_set_must_be_not_null(cipher, FREE_OF_NULL);
    sf_overwrite(Res);
    return Res;
}

DH* DH_get_2048_224()
{
    DH* Res = NULL;
    sf_malloc_arg(Res, 2048);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    sf_lib_arg_type(Res, "DH");
    return Res;
}

OSSL_PARAM OSSL_PARAM_construct_time_t(const char* key, time_t* buf)
{
    OSSL_PARAM Res;
    sf_set_must_be_not_null(key, FREE_OF_NULL);
    sf_set_must_be_not_null(buf, FREE_OF_NULL);
    sf_overwrite(Res);
    sf_bitcopy(Res, buf);
    return Res;
}

void* CRYPTO_secure_malloc(size_t size, const char* file, int line)
{
    void* Res = NULL;
    sf_set_trusted_sink_int(size);
    sf_malloc_arg(size);
    Res = malloc(size);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res, size);
    sf_buf_size_limit(Res, size);
    sf_lib_arg_type(Res, "MallocCategory");
    return Res;
}

void SCT_free(SCT* sct)
{
    sf_set_must_be_not_null(sct, FREE_OF_NULL);
    sf_delete(sct, MALLOC_CATEGORY);
    sf_lib_arg_type(sct, "MallocCategory");
}

int X509_check_email(X509* x, const char* email, size_t emaillen, unsigned int flags)
{
    sf_password_use(email);
    sf_buf_stop_at_null(email);
    sf_buf_size_limit_read(email, emaillen);
    return 0;
}

int EVP_PKEY_cmp_parameters(const EVP_PKEY* a, const EVP_PKEY* b)
{
    sf_set_must_be_not_null(a, CMP_PARAMETERS_OF_NULL);
    sf_set_must_be_not_null(b, CMP_PARAMETERS_OF_NULL);
    return 0;
}

int OPENSSL_gmtime_adj(tm* t, int offset_day, long offset_sec)
{
    sf_set_must_be_not_null(t, GMTIME_ADJ_OF_NULL);
    return 0;
}

UI* UI_new() {
    UI* Res = NULL;
    Res = (UI*)sf_malloc_arg(sizeof(UI));
    sf_lib_arg_type(Res, "UI");
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    return Res;
}

ASN1_OBJECT* OBJ_txt2obj(const char* s, int dont_warn) {
    ASN1_OBJECT* Res = NULL;
    Res = (ASN1_OBJECT*)sf_malloc_arg(sizeof(ASN1_OBJECT));
    sf_lib_arg_type(Res, "ASN1_OBJECT");
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    return Res;
}

BN_MONT_CTX* BN_MONT_CTX_copy(BN_MONT_CTX* to, BN_MONT_CTX* from) {
    BN_MONT_CTX* Res = NULL;
    Res = (BN_MONT_CTX*)sf_malloc_arg(sizeof(BN_MONT_CTX));
    sf_lib_arg_type(Res, "BN_MONT_CTX");
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    return Res;
}

size_t EC_KEY_priv2oct(const EC_KEY* eckey, unsigned char* buf, size_t len) {
    size_t Res = 0;
    sf_set_trusted_sink_int(len);
    sf_buf_size_limit(buf, len);
    return Res;
}

int SSL_get_key_update_type(const SSL* s) {
    int Res = 0;
    sf_set_possible_null(Res);
    return Res;
}

int ASN1_item_sign(const ASN1_ITEM *it, X509_ALGOR *alg1, X509_ALGOR *alg2, ASN1_BIT_STRING *signature, const void *data, EVP_PKEY *pkey, const EVP_MD *md)
{
    int res = 0;
    // Check for null pointers
    sf_set_must_be_not_null(it, SIG_1);
    sf_set_must_be_not_null(alg1, SIG_2);
    sf_set_must_be_not_null(alg2, SIG_3);
    sf_set_must_be_not_null(signature, SIG_4);
    sf_set_must_be_not_null(data, SIG_5);
    sf_set_must_be_not_null(pkey, SIG_6);
    sf_set_must_be_not_null(md, SIG_7);

    // Check for possible negative values
    sf_set_possible_negative(res);

    // Check for errno
    sf_set_errno_if(res == 0);

    return res;
}

size_t SSL_SESSION_get_master_key(const SSL_SESSION *session, unsigned char *out, size_t outlen)
{
    size_t res = 0;
    // Check for null pointers
    sf_set_must_be_not_null(session, SIG_1);
    sf_set_must_be_not_null(out, SIG_2);

    // Check for possible negative values
    sf_set_possible_negative(res);

    // Check for errno
    sf_set_errno_if(res == 0);

    return res;
}

uint16_t SSL_CIPHER_get_protocol_id(const SSL_CIPHER *cipher)
{
    uint16_t res = 0;
    // Check for null pointers
    sf_set_must_be_not_null(cipher, SIG_1);

    // Check for possible negative values
    sf_set_possible_negative(res);

    // Check for errno
    sf_set_errno_if(res == 0);

    return res;
}

PKCS7* PKCS7_sign_ex(X509 *cert, EVP_PKEY *key, stack_st_X509 *certs, BIO *data, int flags, OSSL_LIB_CTX *libctx, const char *propq)
{
    PKCS7* res = NULL;
    // Check for null pointers
    sf_set_must_be_not_null(cert, SIG_1);
    sf_set_must_be_not_null(key, SIG_2);
    sf_set_must_be_not_null(certs, SIG_3);
    sf_set_must_be_not_null(data, SIG_4);
    sf_set_must_be_not_null(libctx, SIG_5);
    sf_set_must_be_not_null(propq, SIG_6);

    // Check for possible null result
    sf_set_possible_null(res);

    // Check for errno
    sf_set_errno_if(res == NULL);

    return res;
}

ADMISSION_SYNTAX* ADMISSION_SYNTAX_new()
{
    ADMISSION_SYNTAX* res = NULL;

    // Check for possible null result
    sf_set_possible_null(res);

    // Check for errno
    sf_set_errno_if(res == NULL);

    return res;
}

ASIdentifierChoice* d2i_ASIdentifierChoice(ASIdentifierChoice** a, const unsigned char** pp, long length)
{
    ASIdentifierChoice* Res = NULL;
    sf_set_trusted_sink_int(length);
    sf_malloc_arg(a, PAGES_MEMORY_CATEGORY);
    Res = (ASIdentifierChoice*)*a;
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    sf_lib_arg_type(Res, "MallocCategory");
    return Res;
}

int OPENSSL_sk_push(OPENSSL_STACK* st, const void* data)
{
    int Res = 0;
    sf_set_trusted_sink_ptr(st);
    sf_set_trusted_sink_ptr(data);
    Res = OPENSSL_sk_push(st, data);
    sf_set_errno_if(Res == -1);
    return Res;
}

int ASN1_TYPE_get(const ASN1_TYPE* a)
{
    int Res = 0;
    sf_set_trusted_sink_ptr(a);
    Res = ASN1_TYPE_get(a);
    sf_set_errno_if(Res == -1);
    return Res;
}

int EVP_PKEY_CTX_get0_dh_kdf_ukm(EVP_PKEY_CTX* ctx, unsigned char** ukmp)
{
    int Res = 0;
    sf_set_trusted_sink_ptr(ctx);
    sf_set_trusted_sink_ptr(ukmp);
    Res = EVP_PKEY_CTX_get0_dh_kdf_ukm(ctx, ukmp);
    sf_set_errno_if(Res == -1);
    return Res;
}

int i2d_PKCS8PrivateKeyInfo_fp(FILE* fp, const EVP_PKEY* pkey)
{
    int Res = 0;
    sf_set_trusted_sink_ptr(fp);
    sf_set_trusted_sink_ptr(pkey);
    Res = i2d_PKCS8PrivateKeyInfo_fp(fp, pkey);
    sf_set_errno_if(Res == -1);
    return Res;
}

int SSL_is_dtls(const SSL* ssl) {
    int Res = 0;
    sf_set_must_be_not_null(ssl, SSL_IS_DTLS_OF_NULL);
    sf_set_errno_if(Res == 0, SSL_IS_DTLS_ERROR);
    return Res;
}

BIGNUM* BN_lebin2bn(const unsigned char* s, int len, BIGNUM* ret) {
    BIGNUM* Res = NULL;
    sf_set_must_be_not_null(s, BN_LEBIN2BN_OF_NULL);
    sf_set_alloc_possible_null(Res);
    sf_set_buf_size(s, len);
    sf_bitcopy(Res, ret);
    return Res;
}

int (int, const unsigned char*, unsigned char*, RSA*, int)* RSA_meth_get_pub_enc(const RSA_METHOD* meth) {
    int (int, const unsigned char*, unsigned char*, RSA*, int)* Res = NULL;
    sf_set_must_be_not_null(meth, RSA_METH_GET_PUB_ENC_OF_NULL);
    sf_set_possible_null(Res);
    return Res;
}

int i2d_EDIPARTYNAME(const EDIPARTYNAME* edp, unsigned char** pp) {
    int Res = 0;
    sf_set_must_be_not_null(edp, I2D_EDIPARTYNAME_OF_NULL);
    sf_set_must_be_not_null(pp, I2D_EDIPARTYNAME_PP_NULL);
    sf_set_errno_if(Res <= 0, I2D_EDIPARTYNAME_ERROR);
    return Res;
}

void X509_STORE_CTX_set_verify(X509_STORE_CTX* ctx, X509_STORE_CTX_verify_fn verify_fn) {
    sf_set_must_be_not_null(ctx, X509_STORE_CTX_SET_VERIFY_CTX_NULL);
    sf_set_possible_null(verify_fn);
    // No return value to check
}

int OSSL_HTTP_REQ_CTX_set1_req(OSSL_HTTP_REQ_CTX *r, const char *p, const ASN1_ITEM *it, const ASN1_VALUE *v)
{
    int res = 0;
    sf_set_tainted(p);
    sf_password_use(v);
    sf_set_must_be_not_null(r, SET1_REQ_OF_NULL);
    sf_set_must_be_not_null(it, SET1_REQ_OF_NULL);
    sf_set_must_be_not_null(v, SET1_REQ_OF_NULL);
    res = ossl_http_req_ctx_set1_req(r, p, it, v);
    sf_set_errno_if(res == 0, SET1_REQ_FAIL);
    return res;
}

int ENGINE_remove(ENGINE *engine)
{
    int res = 0;
    sf_set_must_be_not_null(engine, ENGINE_REMOVE_OF_NULL);
    res = ENGINE_remove(engine);
    sf_set_errno_if(res == 0, ENGINE_REMOVE_FAIL);
    return res;
}

X509_REQ* PEM_read_bio_X509_REQ(BIO *bp, X509_REQ **x, pem_password_cb *cb, void *u)
{
    X509_REQ *res = NULL;
    sf_set_must_be_not_null(bp, PEM_READ_BIO_X509_REQ_OF_NULL);
    sf_set_must_be_not_null(x, PEM_READ_BIO_X509_REQ_OF_NULL);
    sf_set_possible_null(cb);
    res = PEM_read_bio_X509_REQ(bp, x, cb, u);
    sf_set_errno_if(res == NULL, PEM_READ_BIO_X509_REQ_FAIL);
    return res;
}

const OSSL_PROVIDER* EVP_PKEY_CTX_get0_provider(const EVP_PKEY_CTX *ctx)
{
    const OSSL_PROVIDER *res = NULL;
    sf_set_must_be_not_null(ctx, GET0_PROVIDER_OF_NULL);
    res = EVP_PKEY_CTX_get0_provider(ctx);
    sf_set_possible_null(res);
    return res;
}

EVP_PKEY* d2i_KeyParams(int type, EVP_PKEY **a, const unsigned char **pp, long length)
{
    EVP_PKEY *res = NULL;
    sf_set_must_be_not_null(a, D2I_KEYPARAMS_OF_NULL);
    sf_set_must_be_not_null(pp, D2I_KEYPARAMS_OF_NULL);
    res = d2i_KeyParams(type, a, pp, length);
    sf_set_errno_if(res == NULL, D2I_KEYPARAMS_FAIL);
    return res;
}
X509_ATTRIBUTE* X509at_delete_attr(stack_st_X509_ATTRIBUTE* attrs, int loc);

int (DH*);

ENGINE_LOAD_KEY_PTR ENGINE_get_load_privkey_function(const ENGINE* e);

NETSCAPE_CERT_SEQUENCE* NETSCAPE_CERT_SEQUENCE_new();

int EVP_CIPHER_meth_set_ctrl(EVP_CIPHER* cipher, int (EVP_CIPHER_CTX*, int, int, void*);


void OSSL_HTTP_REQ_CTX_set_max_response_length(OSSL_HTTP_REQ_CTX *ctx, unsigned long len)
{
    sf_set_trusted_sink_int(len);
    sf_set_must_be_not_null(ctx, "OSSL_HTTP_REQ_CTX");
    ctx->max_response_length = len;
}

int PEM_write_bio_Parameters(BIO *bio, const EVP_PKEY *pkey)
{
    int ret = 0;
    sf_set_must_be_not_null(bio, "BIO");
    sf_set_must_be_not_null(pkey, "EVP_PKEY");
    sf_set_errno_if(ret <= 0, "PEM_write_bio_Parameters");
    return ret;
}

const OSSL_PARAM *EVP_MD_settable_ctx_params(const EVP_MD *md)
{
    const OSSL_PARAM *ret = NULL;
    sf_set_must_be_not_null(md, "EVP_MD");
    ret = md->settable_ctx_params;
    sf_set_possible_null(ret);
    return ret;
}

int PEM_write_bio_X509(BIO *bio, const X509 *x)
{
    int ret = 0;
    sf_set_must_be_not_null(bio, "BIO");
    sf_set_must_be_not_null(x, "X509");
    sf_set_errno_if(ret <= 0, "PEM_write_bio_X509");
    return ret;
}

const char *X509_verify_cert_error_string(long n)
{
    const char *ret = NULL;
    sf_set_buf_size_limit(n, sizeof(long));
    ret = X509_verify_cert_error_string(n);
    sf_set_possible_null(ret);
    return ret;
}

int EVP_PKEY_CTX_get_rsa_pss_saltlen(EVP_PKEY_CTX *ctx, int *saltlen) {
    int res = 0;
    sf_set_must_be_not_null(ctx, "EVP_PKEY_CTX");
    sf_set_must_be_not_null(saltlen, "saltlen");
    sf_set_errno_if(res == 0, "EVP_PKEY_CTX_get_rsa_pss_saltlen");
    sf_set_possible_null(res);
    return res;
}

void ENGINE_unregister_DH(ENGINE *e) {
    sf_set_must_be_not_null(e, "ENGINE");
    sf_terminate_path("ENGINE_unregister_DH");
}

const BIO_METHOD* BIO_s_core() {
    const BIO_METHOD *res = NULL;
    sf_set_possible_null(res);
    return res;
}

EVP_RAND_CTX* RAND_get0_primary(OSSL_LIB_CTX *libctx) {
    EVP_RAND_CTX *res = NULL;
    sf_set_must_be_not_null(libctx, "OSSL_LIB_CTX");
    sf_set_possible_null(res);
    return res;
}

const EVP_CIPHER* EVP_aes_256_gcm() {
    const EVP_CIPHER *res = NULL;
    sf_set_possible_null(res);
    return res;
}

const SSL_METHOD* TLS_client_method() {
    const SSL_METHOD* Res = NULL;
    Res = TLS_client_method();
    sf_set_possible_null(Res);
    return Res;
}

stack_st_SSL_COMP* SSL_COMP_get_compression_methods() {
    stack_st_SSL_COMP* Res = NULL;
    Res = SSL_COMP_get_compression_methods();
    sf_set_possible_null(Res);
    return Res;
}

int X509_sign_ctx(X509* x, EVP_MD_CTX* ctx) {
    int Res = 0;
    Res = X509_sign_ctx(x, ctx);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int EVP_CIPHER_get_params(EVP_CIPHER* cipher, OSSL_PARAM[] params) {
    int Res = 0;
    Res = EVP_CIPHER_get_params(cipher, params);
    sf_set_errno_if(Res <= 0);
    return Res;
}

EC_KEY* PEM_read_ECPrivateKey(FILE* fp, EC_KEY** key, pem_password_cb* cb, void* u) {
    EC_KEY* Res = NULL;
    Res = PEM_read_ECPrivateKey(fp, key, cb, u);
    sf_set_possible_null(Res);
    sf_password_use(cb);
    return Res;
}

ASN1_STRING* ASN1_STRING_new() {
    ASN1_STRING* Res = NULL;
    Res = ASN1_STRING_new();
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    return Res;
}

X509_NAME_ENTRY* X509_NAME_ENTRY_create_by_OBJ(X509_NAME_ENTRY** ne, const ASN1_OBJECT* obj, int type, const unsigned char* bytes, int len) {
    X509_NAME_ENTRY* Res = NULL;
    Res = X509_NAME_ENTRY_create_by_OBJ(ne, obj, type, bytes, len);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    return Res;
}

const EVP_MD* EVP_md_null() {
    const EVP_MD* Res = NULL;
    Res = EVP_md_null();
    sf_set_possible_null(Res);
    return Res;
}

int EC_KEY_oct2key(EC_KEY* eckey, const unsigned char* buf, size_t len, BN_CTX* ctx) {
    int Res = 0;
    Res = EC_KEY_oct2key(eckey, buf, len, ctx);
    sf_set_errno_if(Res <= 0);
    return Res;
}

X509_PUBKEY* X509_PUBKEY_new_ex(OSSL_LIB_CTX* libctx, const char* propq) {
    X509_PUBKEY* Res = NULL;
    Res = X509_PUBKEY_new_ex(libctx, propq);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    return Res;
}

int DH_check_params(const DH* dh, int* check_result)
{
    sf_set_tainted(dh);
    sf_set_tainted(check_result);
    sf_set_must_be_not_null(dh, DH_NULL);
    sf_set_must_be_not_null(check_result, CHECK_RESULT_NULL);
    sf_set_errno_if(check_result, *check_result != 0, DH_CHECK_FAILED);
    return *check_result;
}

int i2d_OCSP_CERTID(const OCSP_CERTID* certid, unsigned char** der)
{
    sf_set_tainted(certid);
    sf_set_tainted(der);
    sf_set_must_be_not_null(certid, CERTID_NULL);
    sf_set_must_be_not_null(der, DER_NULL);
    sf_set_errno_if(*der == NULL, MALLOC_FAILED);
    sf_set_alloc_possible_null(*der);
    sf_set_buf_size(*der, DER_SIZE);
    sf_lib_arg_type(*der, "DER");
    return DER_SIZE;
}

long SSL_CTX_get_timeout(const SSL_CTX* ctx)
{
    sf_set_tainted(ctx);
    sf_set_must_be_not_null(ctx, CTX_NULL);
    return ctx->timeout;
}

const EVP_CIPHER* EVP_aes_256_wrap_pad()
{
    const EVP_CIPHER* cipher = EVP_aes_256_wrap();
    sf_set_must_be_not_null(cipher, CIPHER_NULL);
    return cipher;
}

int RSA_set_method(RSA* rsa, const RSA_METHOD* meth)
{
    sf_set_tainted(rsa);
    sf_set_tainted(meth);
    sf_set_must_be_not_null(rsa, RSA_NULL);
    sf_set_must_be_not_null(meth, METHOD_NULL);
    sf_set_errno_if(rsa->meth != NULL, RSA_METHOD_ALREADY_SET);
    rsa->meth = meth;
    return 1;
}
SXNETID* SXNETID_new()
{
    SXNETID* Res = NULL;
    Res = (SXNETID*)sf_malloc_arg(sizeof(SXNETID), PAGES_MEMORY_CATEGORY);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    return Res;
}

const OSSL_PARAM* EVP_MD_CTX_gettable_params(EVP_MD_CTX* ctx)
{
    const OSSL_PARAM* Res = NULL;
    Res = ctx->gettable_params();
    sf_set_possible_null(Res);
    return Res;
}

int OSSL_PARAM_set_long(OSSL_PARAM* param, long int val)
{
    int Res = 0;
    Res = param->set_long(val);
    sf_overwrite(&Res);
    return Res;
}

uint64_t SSL_get_options(const SSL* s)
{
    uint64_t Res = 0;
    Res = s->options;
    sf_overwrite(&Res);
    return Res;
}

X509_ALGOR* d2i_X509_ALGOR(X509_ALGOR** a, const unsigned char** in, long len)
{
    X509_ALGOR* Res = NULL;
    Res = (X509_ALGOR*)sf_malloc_arg(sizeof(X509_ALGOR), PAGES_MEMORY_CATEGORY);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    return Res;
}int PEM_write_bio_X509_REQ(BIO* bio, const X509_REQ* req);

SSL_verify_cb SSL_get_verify_callback(const SSL* ssl);

char* i2s_ASN1_IA5STRING(X509V3_EXT_METHOD* meth, ASN1_IA5STRING* str);

int X509_EXTENSION_set_data(X509_EXTENSION* ex, ASN1_OCTET_STRING* data);

long X509_CRL_get_version(const X509_CRL* crl);


void EC_POINT_is_on_curve(const EC_GROUP *group, const EC_POINT *point, BN_CTX *ctx) {
    sf_set_trusted_sink_int(group);
    sf_set_trusted_sink_int(point);
    sf_set_trusted_sink_int(ctx);
}

void EC_KEY_get_conv_form(const EC_KEY *key) {
    sf_set_trusted_sink_int(key);
}

void d2i_ASN1_GENERALIZEDTIME(ASN1_GENERALIZEDTIME **out, const unsigned char **in, long len) {
    sf_set_trusted_sink_int(out);
    sf_set_trusted_sink_int(in);
    sf_set_trusted_sink_int(len);
}

void OSSL_PARAM_set_size_t(OSSL_PARAM *param, size_t val) {
    sf_set_trusted_sink_int(param);
    sf_set_trusted_sink_int(val);
}

void EC_GROUP_free(EC_GROUP *group) {
    sf_set_trusted_sink_int(group);
}
int SSL_CTX_set_num_tickets(SSL_CTX* ctx, size_t tickets);

int EVP_PKEY_encrypt_init_ex(EVP_PKEY_CTX* ctx, const OSSL_PARAM params[]);

int EVP_PKEY_fromdata(EVP_PKEY_CTX* ctx, EVP_PKEY** pkey, int selection, OSSL_PARAM params[]);

void ECDSA_SIG_get0(const ECDSA_SIG* sig, const BIGNUM** pr, const BIGNUM** ps);

EC_KEY* d2i_ECParameters(EC_KEY** key, const unsigned char** pp, long length);

OSSL_PARAM OSSL_PARAM_construct_uint(const char *key, unsigned int *buf);

X509_PUBKEY* X509_PUBKEY_dup(const X509_PUBKEY* key);

void ASN1_INTEGER_free(ASN1_INTEGER* a);

void (UI*, void*);

const GENERAL_NAME* ADMISSIONS_get0_admissionAuthority(const ADMISSIONS* adm);


int EVP_PKEY_CTX_get1_id_len(EVP_PKEY_CTX *ctx, size_t *id_len) {
    int res = 0;
    sf_set_must_be_not_null(ctx, EVP_PKEY_CTX_NULL);
    sf_set_must_be_not_null(id_len, SIZE_T_NULL);
    sf_set_errno_if(res == 0, EVP_PKEY_CTX_get1_id_len);
    return res;
}

void* SSL_CTX_get_record_padding_callback_arg(const SSL_CTX *ctx) {
    void *res = NULL;
    sf_set_must_be_not_null(ctx, SSL_CTX_NULL);
    return res;
}

int DSA_set0_key(DSA *dsa, BIGNUM *pub_key, BIGNUM *priv_key) {
    int res = 0;
    sf_set_must_be_not_null(dsa, DSA_NULL);
    sf_set_must_be_not_null(pub_key, BIGNUM_NULL);
    sf_set_must_be_not_null(priv_key, BIGNUM_NULL);
    sf_set_errno_if(res == 0, DSA_set0_key);
    return res;
}

int X509_STORE_CTX_get_error_depth(const X509_STORE_CTX *ctx) {
    int res = 0;
    sf_set_must_be_not_null(ctx, X509_STORE_CTX_NULL);
    return res;
}

int EVP_PKEY_get_default_digest_nid(EVP_PKEY *pkey, int *nid) {
    int res = 0;
    sf_set_must_be_not_null(pkey, EVP_PKEY_NULL);
    sf_set_must_be_not_null(nid, INT_NULL);
    sf_set_errno_if(res == 0, EVP_PKEY_get_default_digest_nid);
    return res;
}

int i2d_ASN1_TYPE(const ASN1_TYPE* a, unsigned char** pp)
{
    int res = 0;
    // Specify buffer size limit
    sf_buf_size_limit(pp, SOME_LIMIT);
    // Check for null
    sf_set_must_be_not_null(a, "ASN1_TYPE");
    // Check for null
    sf_set_must_be_not_null(*pp, "unsigned char");
    // Overwrite result
    sf_overwrite(res);
    return res;
}

int DSA_meth_set_sign(DSA_METHOD* dm, DSA_SIG* (*dsa_do_sign)(const unsigned char* d, int len, DSA* dsa))
{
    int res = 0;
    // Check for null
    sf_set_must_be_not_null(dm, "DSA_METHOD");
    // Set library argument type
    sf_lib_arg_type(dsa_do_sign, "DSA_SIG");
    // Overwrite result
    sf_overwrite(res);
    return res;
}

int EVP_PKEY_CTX_set_dh_paramgen_generator(EVP_PKEY_CTX* ctx, int g)
{
    int res = 0;
    // Check for null
    sf_set_must_be_not_null(ctx, "EVP_PKEY_CTX");
    // Overwrite result
    sf_overwrite(res);
    return res;
}

DSA* DSA_new_method(ENGINE* e)
{
    DSA* res = NULL;
    // Check for null
    sf_set_alloc_possible_null(res);
    // Set library argument type
    sf_lib_arg_type(e, "ENGINE");
    // Allocate memory
    res = OPENSSL_malloc(sizeof(DSA));
    // Check for null
    sf_set_must_be_not_null(res, "DSA");
    // Set memory category
    sf_new(res, DSA_MEMORY_CATEGORY);
    // Overwrite result
    sf_overwrite(res);
    return res;
}

ASN1_PRINTABLESTRING* d2i_ASN1_PRINTABLESTRING(ASN1_PRINTABLESTRING** a, const unsigned char** pp, long length)
{
    ASN1_PRINTABLESTRING* res = NULL;
    // Check for null
    sf_set_must_be_not_null(*a, "ASN1_PRINTABLESTRING");
    // Check for null
    sf_set_must_be_not_null(*pp, "unsigned char");
    // Set buffer size limit
    sf_buf_size_limit(pp, length);
    // Allocate memory
    res = OPENSSL_malloc(sizeof(ASN1_PRINTABLESTRING));
    // Check for null
    sf_set_must_be_not_null(res, "ASN1_PRINTABLESTRING");
    // Set memory category
    sf_new(res, ASN1_PRINTABLESTRING_MEMORY_CATEGORY);
    // Overwrite result
    sf_overwrite(res);
    return res;
}
int EVP_PBE_find_ex(int, int, int*, int*, EVP_PBE_KEYGEN**, EVP_PBE_KEYGEN_EX**);

void SSL_CTX_set_keylog_callback(SSL_CTX*, SSL_CTX_keylog_cb_func);

void EVP_PKEY_CTX_set_cb(EVP_PKEY_CTX*, EVP_PKEY_gen_cb*);

X509_ALGOR* PKCS5_pbe_set(int, int, const unsigned char*, int);

OSSL_PARAM OSSL_PARAM_construct_long(const char*, long int*);


void BN_CTX_start(BN_CTX *ctx) {
    sf_set_trusted_sink_int(ctx);
    sf_set_tainted(ctx);
    sf_set_must_not_be_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_negative(ctx);
    sf_set_long_time(ctx);
    sf_set_tocttou_check(ctx);
    sf_set_must_not_be_release(ctx);
    sf_set_must_be_positive(ctx);
    sf_set_buf_size(ctx, size);
    sf_set_buf_size_limit(ctx, size);
    sf_set_buf_size_limit_read(ctx, size);
    sf_set_buf_stop_at_null(ctx);
    sf_set_buf_overlap(ctx, size);
    sf_set_errno_if(ctx);
    sf_no_errno_if(ctx);
    sf_terminate_path(ctx);
    sf_lib_arg_type(ctx, "BN_CTX");
}

int BIO_meth_get_read_ex(const BIO_METHOD *method) {
    int res = 0;
    sf_set_trusted_sink_int(method);
    sf_set_tainted(method);
    sf_set_must_not_be_null(method);
    sf_set_possible_null(method);
    sf_set_possible_negative(method);
    sf_set_long_time(method);
    sf_set_tocttou_check(method);
    sf_set_must_not_be_release(method);
    sf_set_must_be_positive(method);
    sf_set_buf_size(method, size);
    sf_set_buf_size_limit(method, size);
    sf_set_buf_size_limit_read(method, size);
    sf_set_buf_stop_at_null(method);
    sf_set_buf_overlap(method, size);
    sf_set_errno_if(method);
    sf_no_errno_if(method);
    sf_terminate_path(method);
    sf_lib_arg_type(method, "BIO_METHOD");
    return res;
}

int RSA_meth_set_pub_dec(RSA_METHOD *meth, int (*pub_dec)(int, const unsigned char*, unsigned char*, RSA*, int)) {
    int res = 0;
    sf_set_trusted_sink_int(meth);
    sf_set_tainted(meth);
    sf_set_must_not_be_null(meth);
    sf_set_possible_null(meth);
    sf_set_possible_negative(meth);
    sf_set_long_time(meth);
    sf_set_tocttou_check(meth);
    sf_set_must_not_be_release(meth);
    sf_set_must_be_positive(meth);
    sf_set_buf_size(meth, size);
    sf_set_buf_size_limit(meth, size);
    sf_set_buf_size_limit_read(meth, size);
    sf_set_buf_stop_at_null(meth);
    sf_set_buf_overlap(meth, size);
    sf_set_errno_if(meth);
    sf_no_errno_if(meth);
    sf_terminate_path(meth);
    sf_lib_arg_type(meth, "RSA_METHOD");
    return res;
}

void PKCS7_ENCRYPT_free(PKCS7_ENCRYPT *enc) {
    sf_set_trusted_sink_int(enc);
    sf_set_tainted(enc);
    sf_set_must_not_be_null(enc);
    sf_set_possible_null(enc);
    sf_set_possible_negative(enc);
    sf_set_long_time(enc);
    sf_set_tocttou_check(enc);
    sf_set_must_not_be_release(enc);
    sf_set_must_be_positive(enc);
    sf_set_buf_size(enc, size);
    sf_set_buf_size_limit(enc, size);
    sf_set_buf_size_limit_read(enc, size);
    sf_set_buf_stop_at_null(enc);
    sf_set_buf_overlap(enc, size);
    sf_set_errno_if(enc);
    sf_no_errno_if(enc);
    sf_terminate_path(enc);
    sf_lib_arg_type(enc, "PKCS7_ENCRYPT");
}

PKCS8_PRIV_KEY_INFO* PEM_read_PKCS8_PRIV_KEY_INFO(FILE *fp, PKCS8_PRIV_KEY_INFO **x, pem_password_cb *cb, void *u) {
    PKCS8_PRIV_KEY_INFO *res = NULL;
    sf_set_trusted_sink_int(fp);
    sf_set_tainted(fp);
    sf_set_must_not_be_null(fp);
    sf_set_possible_null(fp);
    sf_set_possible_negative(fp);
    sf_set_long_time(fp);
    sf_set_tocttou_check(fp);
    sf_set_must_not_be_release(fp);
    sf_set_must_be_positive(fp);
    sf_set_buf_size(fp, size);
    sf_set_buf_size_limit(fp, size);
    sf_set_buf_size_limit_read(fp, size);
    sf_set_buf_stop_at_null(fp);
    sf_set_buf_overlap(fp, size);
    sf_set_errno_if(fp);
    sf_no_errno_if(fp);
    sf_terminate_path(fp);
    sf_lib_arg_type(fp, "FILE");

    sf_set_trusted_sink_int(x);
    sf_set_tainted(x);
    sf_set_must_not_be_null(x);
    sf_set_possible_null(x);
    sf_set_possible_negative(x);
    sf_set_long_time(x);
    sf_set_tocttou_check(x);
    sf_set_must_not_be_release(x);
    sf_set_must_be_positive(x);
    sf_set_buf_size(x, size);
    sf_set_buf_size_limit(x, size);
    sf_set_buf_size_limit_read(x, size);
    sf_set_buf_stop_at_null(x);
    sf_set_buf_overlap(x, size);
    sf_set_errno_if(x);
    sf_no_errno_if(x);
    sf_terminate_path(x);
    sf_lib_arg_type(x, "PKCS8_PRIV_KEY_INFO");

    sf_set_trusted_sink_int(cb);
    sf_set_tainted(cb);
    sf_set_must_not_be_null(cb);
    sf_set_possible_null(cb);
    sf_set_possible_negative(cb);
    sf_set_long_time(cb);
    sf_set_tocttou_check(cb);
    sf_set_must_not_be_release(cb);
    sf_set_must_be_positive(cb);
    sf_set_buf_size(cb, size);
    sf_set_buf_size_limit(cb, size);
    sf_set_buf_size_limit_read(cb, size);
    sf_set_buf_stop_at_null(cb);
    sf_set_buf_overlap(cb, size);
    sf_set_errno_if(cb);
    sf_no_errno_if(cb);
    sf_terminate_path(cb);
    sf_lib_arg_type(cb, "pem_password_cb");

    sf_set_trusted_sink_int(u);
    sf_set_tainted(u);
    sf_set_must_not_be_null(u);
    sf_set_possible_null(u);
    sf_set_possible_negative(u);
    sf_set_long_time(u);
    sf_set_tocttou_check(u);
    sf_set_must_not_be_release(u);
    sf_set_must_be_positive(u);
    sf_set_buf_size(u, size);
    sf_set_buf_size_limit(u, size);
    sf_set_buf_size_limit_read(u, size);
    sf_set_buf_stop_at_null(u);
    sf_set_buf_overlap(u, size);
    sf_set_errno_if(u);
    sf_no_errno_if(u);
    sf_terminate_path(u);
    sf_lib_arg_type(u, "void");

    return res;
}

// Specification for int BIO_new_bio_pair(BIO**, size_t, BIO**, size_t)
int BIO_new_bio_pair(BIO** bio1, size_t size1, BIO** bio2, size_t size2) {
    int Res = 0;
    sf_set_trusted_sink_int(size1);
    sf_set_trusted_sink_int(size2);
    sf_set_errno_if(Res == 0, ENOMEM);
    sf_no_errno_if(Res != 0);
    return Res;
}

// Specification for EVP_RAND* EVP_RAND_CTX_get0_rand(EVP_RAND_CTX*)
EVP_RAND* EVP_RAND_CTX_get0_rand(EVP_RAND_CTX* ctx) {
    EVP_RAND* Res = NULL;
    sf_set_possible_null(Res);
    sf_set_errno_if(Res == NULL, EINVAL);
    sf_no_errno_if(Res != NULL);
    return Res;
}

// Specification for ADMISSION_SYNTAX* d2i_ADMISSION_SYNTAX(ADMISSION_SYNTAX**, const unsigned char**, long)
ADMISSION_SYNTAX* d2i_ADMISSION_SYNTAX(ADMISSION_SYNTAX** a, const unsigned char** in, long len) {
    ADMISSION_SYNTAX* Res = NULL;
    sf_set_possible_null(Res);
    sf_set_errno_if(Res == NULL, EINVAL);
    sf_no_errno_if(Res != NULL);
    return Res;
}

// Specification for int BIO_write(BIO*, const void*, int)
int BIO_write(BIO* b, const void* data, int dlen) {
    int Res = 0;
    sf_set_errno_if(Res <= 0, EIO);
    sf_no_errno_if(Res > 0);
    return Res;
}

// Specification for void SXNET_free(SXNET*)
void SXNET_free(SXNET* sx) {
    sf_delete(sx, SXNET_CATEGORY);
    sf_lib_arg_type(sx, "SXNETCategory");
}
int RSA_meth_set0_app_data(RSA_METHOD *meth, void *app_data);

X509_VERIFY_PARAM * SSL_CTX_get0_param(SSL_CTX *ctx);

void SSL_set_verify_depth(SSL *s, int depth);

const EVP_CIPHER * EVP_aes_192_ecb();

int SSL_use_RSAPrivateKey_file(SSL *ssl, const char *file, int type);

void BN_with_flags(BIGNUM* bn, const BIGNUM* a, int flags);

ASN1_STRING* X509_NAME_ENTRY_get_data(const X509_NAME_ENTRY* ne);

void CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE(CT_POLICY_EVAL_CTX* ctx, CTLOG_STORE* ctlog_store);

int UI_get_result_string_length(UI_STRING* uis);

SCRYPT_PARAMS* d2i_SCRYPT_PARAMS(SCRYPT_PARAMS** out, const unsigned char** in, long len);


const char* EVP_KEYEXCH_get0_description(const EVP_KEYEXCH* keyex) {
    const char* Res = NULL;
    sf_set_trusted_sink_ptr(keyex);
    sf_set_tainted(Res);
    return Res;
}

int X509_verify_cert(X509_STORE_CTX* ctx) {
    int Res = 0;
    sf_set_must_be_not_null(ctx, VERIFY_OF_NULL);
    sf_set_errno_if(Res <= 0);
    return Res;
}

void X509_REVOKED_free(X509_REVOKED* rev) {
    sf_set_must_be_not_null(rev, FREE_OF_NULL);
    sf_delete(rev, REVOKED_CATEGORY);
}

int i2d_PROXY_POLICY(const PROXY_POLICY* policy, unsigned char** out) {
    int Res = 0;
    sf_set_must_be_not_null(policy, I2D_OF_NULL);
    sf_set_must_be_not_null(out, I2D_OF_NULL);
    sf_set_buf_size(*out, Res);
    sf_set_errno_if(Res <= 0);
    return Res;
}

EVP_PKEY* d2i_PUBKEY_ex(EVP_PKEY** pkey, const unsigned char** in, long len, OSSL_LIB_CTX* libctx, const char* propq) {
    EVP_PKEY* Res = NULL;
    sf_set_trusted_sink_ptr(pkey);
    sf_set_trusted_sink_ptr(in);
    sf_set_trusted_sink_ptr(libctx);
    sf_set_trusted_sink_ptr(propq);
    sf_set_alloc_possible_null(Res);
    sf_set_possible_null(Res);
    sf_new(Res, PKEY_CATEGORY);
    return Res;
}
X509_EXTENSION* X509_EXTENSION_create_by_OBJ(X509_EXTENSION** ex, const ASN1_OBJECT* obj, int critical, ASN1_OCTET_STRING* data);

int SSL_CTX_set_cipher_list(SSL_CTX* ctx, const char* str);

int EVP_PKEY_CTX_set_dh_nid(EVP_PKEY_CTX* ctx, int nid);

int SSL_CTX_set_async_callback(SSL_CTX* ctx, SSL_async_callback_fn callback);

void X509_VERIFY_PARAM_set_auth_level(X509_VERIFY_PARAM* param, int authlevel);


int SSL_accept(SSL *ssl) {
    int ret = 0;
    sf_set_must_be_not_null(ssl, SSL_ACCEPT_OF_NULL);
    sf_set_errno_if(ret <= 0, SSL_ACCEPT_ERROR);
    sf_set_possible_null(ret, SSL_ACCEPT_POSSIBLE_NULL);
    sf_set_tainted(ssl, SSL_ACCEPT_TAINTED);
    return ret;
}

EVP_PKEY* d2i_PrivateKey_ex_fp(FILE *fp, EVP_PKEY **a, OSSL_LIB_CTX *libctx, const char *propq) {
    EVP_PKEY *ret = NULL;
    sf_set_must_be_not_null(fp, D2I_PRIVATEKEY_EX_FP_OF_NULL);
    sf_set_must_be_not_null(a, D2I_PRIVATEKEY_EX_FP_A_NULL);
    sf_set_errno_if(ret == NULL, D2I_PRIVATEKEY_EX_FP_ERROR);
    sf_set_possible_null(ret, D2I_PRIVATEKEY_EX_FP_POSSIBLE_NULL);
    sf_set_tainted(fp, D2I_PRIVATEKEY_EX_FP_TAINTED);
    return ret;
}

OSSL_PARAM OSSL_PARAM_construct_uint64(const char *key, uint64_t *buf) {
    OSSL_PARAM ret;
    sf_set_must_be_not_null(key, OSSL_PARAM_CONSTRUCT_UINT64_KEY_NULL);
    sf_set_must_be_not_null(buf, OSSL_PARAM_CONSTRUCT_UINT64_BUF_NULL);
    sf_set_tainted(key, OSSL_PARAM_CONSTRUCT_UINT64_KEY_TAINTED);
    sf_set_tainted(buf, OSSL_PARAM_CONSTRUCT_UINT64_BUF_TAINTED);
    return ret;
}

int i2d_OCSP_RESPDATA(const OCSP_RESPDATA *r, unsigned char **pp) {
    int ret = 0;
    sf_set_must_be_not_null(r, I2D_OCSP_RESPDATA_R_NULL);
    sf_set_must_be_not_null(pp, I2D_OCSP_RESPDATA_PP_NULL);
    sf_set_errno_if(ret <= 0, I2D_OCSP_RESPDATA_ERROR);
    sf_set_possible_null(ret, I2D_OCSP_RESPDATA_POSSIBLE_NULL);
    sf_set_tainted(r, I2D_OCSP_RESPDATA_R_TAINTED);
    return ret;
}

X509_REVOKED* X509_REVOKED_new() {
    X509_REVOKED *ret = NULL;
    sf_set_errno_if(ret == NULL, X509_REVOKED_NEW_ERROR);
    sf_set_possible_null(ret, X509_REVOKED_NEW_POSSIBLE_NULL);
    return ret;
}

void EVP_CIPHER_CTX_set_app_data(EVP_CIPHER_CTX* ctx, void* data) {
    sf_set_tainted(data);
    sf_set_trusted_sink_ptr(ctx);
    ctx->app_data = data;
}

stack_st_X509* X509_STORE_CTX_get1_chain(const X509_STORE_CTX* ctx) {
    stack_st_X509* res = NULL;
    sf_set_possible_null(res);
    res = ctx->chain;
    sf_set_possible_null(res);
    return res;
}

int SSL_CTX_set_srp_cb_arg(SSL_CTX* ctx, void* arg) {
    sf_set_tainted(arg);
    ctx->srp_cb_arg = arg;
    return 1;
}

char* i2s_ASN1_ENUMERATED_TABLE(X509V3_EXT_METHOD* method, const ASN1_ENUMERATED* a) {
    char* res = NULL;
    sf_set_possible_null(res);
    res = method->i2s(a);
    sf_set_possible_null(res);
    return res;
}

ASN1_OCTET_STRING* PKCS7_get_octet_string(PKCS7* p7) {
    ASN1_OCTET_STRING* res = NULL;
    sf_set_possible_null(res);
    res = p7->d.data;
    sf_set_possible_null(res);
    return res;
}

int EVP_CIPHER_param_to_asn1(EVP_CIPHER_CTX *ctx, ASN1_TYPE *ty) {
    int res = 0;
    // Specify the trusted sink pointer for ASN1_TYPE
    sf_set_trusted_sink_ptr(ty);
    // Specify the trusted sink int for EVP_CIPHER_CTX
    sf_set_trusted_sink_int(ctx);
    // Set the return value as not acquired if it is equal to null
    sf_not_acquire_if_eq(res);
    return res;
}

ec_key_st* EVP_PKEY_get1_EC_KEY(EVP_PKEY *pkey) {
    ec_key_st *res = NULL;
    // Set the return value as possibly null
    sf_set_possible_null(res);
    // Set the trusted sink int for EVP_PKEY
    sf_set_trusted_sink_int(pkey);
    return res;
}

void ISSUING_DIST_POINT_free(ISSUING_DIST_POINT *idp) {
    // Set the trusted sink int for ISSUING_DIST_POINT
    sf_set_trusted_sink_int(idp);
    // Set the input parameter as freed
    sf_delete(idp, MALLOC_CATEGORY);
}

int EVP_CipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, const unsigned char *key, const unsigned char *iv, int enc) {
    int res = 0;
    // Set the trusted sink int for EVP_CIPHER_CTX, EVP_CIPHER, key and iv
    sf_set_trusted_sink_int(ctx);
    sf_set_trusted_sink_int(cipher);
    sf_set_trusted_sink_int(key);
    sf_set_trusted_sink_int(iv);
    // Set the return value as not acquired if it is equal to null
    sf_not_acquire_if_eq(res);
    return res;
}

const SSL_METHOD* TLS_server_method() {
    const SSL_METHOD *res = NULL;
    // Set the return value as possibly null
    sf_set_possible_null(res);
    return res;
}

X509_REQ_INFO* X509_REQ_INFO_new() {
    X509_REQ_INFO* Res = NULL;
    Res = (X509_REQ_INFO*)OPENSSL_malloc(sizeof(X509_REQ_INFO));
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    return Res;
}

void* X509_STORE_CTX_get_ex_data(const X509_STORE_CTX* ctx, int idx) {
    void* Res = NULL;
    Res = (void*)CRYPTO_get_ex_data(&ctx->ex_data, idx);
    sf_set_possible_null(Res);
    return Res;
}

X509_NAME* X509_get_subject_name(const X509* x) {
    X509_NAME* Res = NULL;
    Res = x->cert_info->subject;
    sf_set_possible_null(Res);
    return Res;
}

int ASN1_UTCTIME_cmp_time_t(const ASN1_UTCTIME* s, time_t t) {
    int Res = 0;
    struct tm *tm;
    tm = gmtime(&t);
    Res = ASN1_UTCTIME_cmp(s, tm);
    return Res;
}

int EC_POINT_mul(const EC_GROUP* group, EC_POINT* r, const BIGNUM* n, const EC_POINT* q, const BIGNUM* m, BN_CTX* ctx) {
    int Res = 0;
    Res = EC_POINT_mul(group, r, n, q, m, ctx);
    sf_set_errno_if(Res == 0);
    return Res;
}

int X509_VERIFY_PARAM_set1_policies(X509_VERIFY_PARAM *param, stack_st_ASN1_OBJECT *policies) {
    int res = 0;
    sf_set_tainted(param);
    sf_set_tainted(policies);
    sf_set_must_be_not_null(param, X509_VERIFY_PARAM_NULL);
    sf_set_must_be_not_null(policies, STACK_ASN1_OBJECT_NULL);
    sf_set_errno_if(res == 0, ERR_get_error());
    return res;
}

unsigned int OPENSSL_version_major() {
    unsigned int res = 0;
    sf_set_errno_if(res == 0, ERR_get_error());
    return res;
}

unsigned char* SHA256(const unsigned char *d, size_t n, unsigned char *md) {
    unsigned char *res = NULL;
    sf_set_tainted(d);
    sf_set_must_be_not_null(d, SHA256_NULL);
    sf_set_must_be_not_null(md, SHA256_RESULT_NULL);
    sf_buf_size_limit(d, n);
    sf_buf_size_limit(md, SHA256_DIGEST_LENGTH);
    sf_set_errno_if(res == NULL, ERR_get_error());
    return res;
}

int EVP_DigestSign(EVP_MD_CTX *ctx, unsigned char *sigret, size_t *siglen, const unsigned char *tbs, size_t tbslen) {
    int res = 0;
    sf_set_must_be_not_null(ctx, EVP_MD_CTX_NULL);
    sf_set_must_be_not_null(sigret, EVP_DIGEST_SIGN_SIGRET_NULL);
    sf_set_must_be_not_null(siglen, EVP_DIGEST_SIGN_SIGLEN_NULL);
    sf_set_must_be_not_null(tbs, EVP_DIGEST_SIGN_TBS_NULL);
    sf_buf_size_limit(tbs, tbslen);
    sf_set_errno_if(res == 0, ERR_get_error());
    return res;
}

const EVP_CIPHER* EVP_aes_128_ctr() {
    const EVP_CIPHER *res = NULL;
    sf_set_errno_if(res == NULL, ERR_get_error());
    return res;
}

int RAND_set_seed_source_type(OSSL_LIB_CTX *libctx, const char *type, const char *path) {
    int res = 0;
    sf_set_must_be_not_null(libctx, "RAND_set_seed_source_type: libctx must not be null");
    sf_set_must_be_not_null(type, "RAND_set_seed_source_type: type must not be null");
    sf_set_must_be_not_null(path, "RAND_set_seed_source_type: path must not be null");
    sf_set_tainted(type);
    sf_set_tainted(path);
    sf_tocttou_check(path);
    sf_set_errno_if(res == 0, "RAND_set_seed_source_type: Error setting seed source type");
    return res;
}

int RSA_meth_get_priv_dec(const RSA_METHOD *meth, int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding) {
    int res = 0;
    sf_set_must_be_not_null(meth, "RSA_meth_get_priv_dec: meth must not be null");
    sf_set_must_be_not_null(from, "RSA_meth_get_priv_dec: from must not be null");
    sf_set_must_be_not_null(to, "RSA_meth_get_priv_dec: to must not be null");
    sf_set_must_be_not_null(rsa, "RSA_meth_get_priv_dec: rsa must not be null");
    sf_set_buf_size_limit(from, flen);
    sf_set_buf_size_limit(to, flen);
    sf_set_errno_if(res == 0, "RSA_meth_get_priv_dec: Error in private decryption");
    return res;
}

int OCSP_check_validity(ASN1_GENERALIZEDTIME *thisupd, ASN1_GENERALIZEDTIME *nextupd, long sec, long maxsec) {
    int res = 0;
    sf_set_must_be_not_null(thisupd, "OCSP_check_validity: thisupd must not be null");
    sf_set_must_be_not_null(nextupd, "OCSP_check_validity: nextupd must not be null");
    sf_set_errno_if(res == 0, "OCSP_check_validity: Error checking validity");
    return res;
}

void EVP_PKEY_meth_free(EVP_PKEY_METHOD *pmeth) {
    sf_set_must_be_not_null(pmeth, "EVP_PKEY_meth_free: pmeth must not be null");
    // No return value to check
}

int EVP_PKEY_CTX_get_rsa_mgf1_md_name(EVP_PKEY_CTX *ctx, char *name, size_t len) {
    int res = 0;
    sf_set_must_be_not_null(ctx, "EVP_PKEY_CTX_get_rsa_mgf1_md_name: ctx must not be null");
    sf_set_must_be_not_null(name, "EVP_PKEY_CTX_get_rsa_mgf1_md_name: name must not be null");
    sf_set_buf_size(name, len);
    sf_set_errno_if(res == 0, "EVP_PKEY_CTX_get_rsa_mgf1_md_name: Error getting MGF1 MD name");
    return res;
}
int X509_check_purpose(X509 *x, int id, int ca_p);

void* OPENSSL_sk_delete(OPENSSL_STACK *st, int loc);

BIO* BIO_new_connect(const char *str);

int OSSL_PARAM_get_int64(const OSSL_PARAM *p, int64_t *val);

int DSA_meth_set_verify(DSA_METHOD *dsa, int (*verify);


int SSL_CIPHER_get_cipher_nid(const SSL_CIPHER *cipher) {
    int Res = 0;
    sf_set_must_be_not_null(cipher, SSL_CIPHER_PTR_NULL);
    Res = cipher->nid;
    sf_set_possible_null(Res);
    return Res;
}

int X509_set_issuer_name(X509 *x, const X509_NAME *name) {
    int Res = 0;
    sf_set_must_be_not_null(x, X509_PTR_NULL);
    sf_set_must_be_not_null(name, X509_NAME_PTR_NULL);
    Res = X509_set_issuer_name(x, name);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int X509_cmp(const X509 *a, const X509 *b) {
    int Res = 0;
    sf_set_must_be_not_null(a, X509_PTR_NULL);
    sf_set_must_be_not_null(b, X509_PTR_NULL);
    Res = X509_cmp(a, b);
    sf_set_possible_negative(Res);
    return Res;
}

int X509_sign(X509 *x, EVP_PKEY *pkey, const EVP_MD *md) {
    int Res = 0;
    sf_set_must_be_not_null(x, X509_PTR_NULL);
    sf_set_must_be_not_null(pkey, EVP_PKEY_PTR_NULL);
    sf_set_must_be_not_null(md, EVP_MD_PTR_NULL);
    Res = X509_sign(x, pkey, md);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int BIO_meth_set_puts(BIO_METHOD *biom, int (BIO*, const char*)* puts) {
    int Res = 0;
    sf_set_must_be_not_null(biom, BIO_METHOD_PTR_NULL);
    sf_set_must_be_not_null(puts, BIO_PUTS_FUNC_PTR_NULL);
    Res = BIO_meth_set_puts(biom, puts);
    sf_set_errno_if(Res <= 0);
    return Res;
}

X509_EXTENSION* X509_CRL_delete_ext(X509_CRL* crl, int loc) {
    X509_EXTENSION* Res = NULL;
    sf_set_must_be_not_null(crl, CRL_OF_NULL);
    sf_set_trusted_sink_int(loc, INDEX_OF_CRL);
    Res = X509_CRL_delete_ext(crl, loc);
    sf_set_possible_null(Res);
    return Res;
}

const EVP_CIPHER* EVP_aes_192_cfb1() {
    const EVP_CIPHER* Res = NULL;
    Res = EVP_aes_192_cfb1();
    sf_set_possible_null(Res);
    return Res;
}

OCSP_REQINFO* OCSP_REQINFO_new() {
    OCSP_REQINFO* Res = NULL;
    Res = OCSP_REQINFO_new();
    sf_set_possible_null(Res);
    return Res;
}

const SSL_METHOD* TLSv1_method() {
    const SSL_METHOD* Res = NULL;
    Res = TLSv1_method();
    sf_set_possible_null(Res);
    return Res;
}

int EC_GROUP_get_curve(const EC_GROUP* group, BIGNUM* a, BIGNUM* b, BIGNUM* c, BN_CTX* ctx) {
    int Res = 0;
    sf_set_must_be_not_null(group, GROUP_OF_NULL);
    sf_set_must_be_not_null(a, A_OF_NULL);
    sf_set_must_be_not_null(b, B_OF_NULL);
    sf_set_must_be_not_null(c, C_OF_NULL);
    sf_set_must_be_not_null(ctx, CTX_OF_NULL);
    Res = EC_GROUP_get_curve(group, a, b, c, ctx);
    sf_set_possible_negative(Res);
    return Res;
}
int BN_is_bit_set(const BIGNUM*, int);

stack_st_X509_OBJECT* X509_STORE_get0_objects(const X509_STORE*);

void SSL_set_quiet_shutdown(SSL*, int);

int HMAC_CTX_copy(HMAC_CTX*, HMAC_CTX*);

int HMAC_Update(HMAC_CTX*, const unsigned char*, size_t);

int X509_NAME_get0_der(const X509_NAME*, const unsigned char**, size_t*);

int PEM_write_bio_X509_REQ_NEW(BIO*, const X509_REQ*);

int CRYPTO_secure_malloc_init(size_t, size_t);

void ENGINE_register_all_DH();

int SHA1_Final(unsigned char*, SHA_CTX*);

int OSSL_HTTP_parse_url(const char*, int*, char**, char**, char**, int*, char**, char**, char**);

uint64_t SSL_CTX_clear_options(SSL_CTX*, uint64_t);

unsigned long SSL_SESSION_get_ticket_lifetime_hint(const SSL_SESSION*);

int i2d_POLICYINFO(const POLICYINFO*, unsigned char**);

const char* UI_get0_test_string(UI_STRING*);

int RSA_meth_set_finish(RSA_METHOD *meth, int (*finish);

int ASN1_STRING_print_ex_fp(FILE *fp, const ASN1_STRING *str, unsigned long flags);

int EVP_PKEY_get_int_param(const EVP_PKEY *pkey, const char *key, int *out);

void SSL_CTX_set_client_hello_cb(SSL_CTX *ctx, SSL_client_hello_cb_fn cb, void *arg);

void PKCS7_RECIP_INFO_free(PKCS7_RECIP_INFO *ri);


int X509at_get_attr_count(const stack_st_X509_ATTRIBUTE* attrs) {
    int res = 0;
    sf_set_must_be_not_null(attrs, "X509at_get_attr_count");
    res = sk_X509_ATTRIBUTE_num(attrs);
    sf_set_possible_null(res);
    return res;
}

int X509_REVOKED_get_ext_by_NID(const X509_REVOKED* rev, int nid, int lastpos) {
    int res = 0;
    sf_set_must_be_not_null(rev, "X509_REVOKED_get_ext_by_NID");
    res = X509_REVOKED_get_ext_by_NID(rev, nid, lastpos);
    sf_set_possible_null(res);
    return res;
}

int SSL_CTX_use_RSAPrivateKey(SSL_CTX* ctx, RSA* rsa) {
    int res = 0;
    sf_set_must_be_not_null(ctx, "SSL_CTX_use_RSAPrivateKey");
    sf_set_must_be_not_null(rsa, "SSL_CTX_use_RSAPrivateKey");
    res = SSL_CTX_use_RSAPrivateKey(ctx, rsa);
    sf_set_errno_if(res <= 0);
    return res;
}

int DH_set0_pqg(DH* dh, BIGNUM* p, BIGNUM* q, BIGNUM* g) {
    int res = 0;
    sf_set_must_be_not_null(dh, "DH_set0_pqg");
    sf_set_must_be_not_null(p, "DH_set0_pqg");
    sf_set_must_be_not_null(q, "DH_set0_pqg");
    sf_set_must_be_not_null(g, "DH_set0_pqg");
    res = DH_set0_pqg(dh, p, q, g);
    sf_set_errno_if(res <= 0);
    return res;
}

const OSSL_PARAM* EVP_CIPHER_gettable_ctx_params(const EVP_CIPHER* cipher) {
    const OSSL_PARAM* res = NULL;
    sf_set_must_be_not_null(cipher, "EVP_CIPHER_gettable_ctx_params");
    res = EVP_CIPHER_gettable_ctx_params(cipher);
    sf_set_possible_null(res);
    return res;
}
const char* SSL_alert_type_string_long(int alert_value);

void EVP_PKEY_meth_get_derive(const EVP_PKEY_METHOD* pmeth, int (**derive);

int EVP_MD_meth_set_update(EVP_MD* md, int (*update);

int ECDSA_sign(int type, const unsigned char* dgst, int dlen, unsigned char* sig, unsigned int* siglen, EC_KEY* eckey);

long SSL_SESSION_set_timeout(SSL_SESSION* s, long t);

void BIO_set_init(BIO* bio, int init);

void BIO_set_retry_reason(BIO* bio, int reason);

int X509_NAME_print(BIO* bio, const X509_NAME* name, int obase);

EVP_PKEY* d2i_PKCS8PrivateKey_bio(BIO* bio, EVP_PKEY** pkey, pem_password_cb* cb, void* u);

int X509_STORE_unlock(X509_STORE* store);


const EVP_CIPHER* EVP_aria_192_ofb() {
    const EVP_CIPHER* Res = NULL;
    Res = EVP_aria_192_ofb();
    sf_set_possible_null(Res);
    return Res;
}

ASN1_STRING* d2i_ASN1_PRINTABLE(ASN1_STRING** a, const unsigned char** pp, long length) {
    ASN1_STRING* Res = NULL;
    Res = d2i_ASN1_PRINTABLE(a, pp, length);
    sf_set_possible_null(Res);
    return Res;
}

void EVP_CIPHER_free(EVP_CIPHER* cipher) {
    EVP_CIPHER_free(cipher);
    sf_delete(cipher, PAGES_MEMORY_CATEGORY);
}

const EVP_CIPHER* EVP_des_cfb8() {
    const EVP_CIPHER* Res = NULL;
    Res = EVP_des_cfb8();
    sf_set_possible_null(Res);
    return Res;
}

X509* CT_POLICY_EVAL_CTX_get0_cert(const CT_POLICY_EVAL_CTX* ctx) {
    X509* Res = NULL;
    Res = CT_POLICY_EVAL_CTX_get0_cert(ctx);
    sf_set_possible_null(Res);
    return Res;
}
Here are the specifications for the functions based on the rules provided:

1. EVP_PKEY* X509_get0_pubkey(const X509* x)
```
EVP_PKEY *Res = NULL;
sf_set_tainted(x);
Res = X509_get_pubkey(x);
sf_set_possible_null(Res);
return Res;
```

2. int BIO_meth_set_callback_ctrl(BIO_METHOD* meth, long (*callback)(BIO*, int, BIO_info_cb*))
```
int Res = 0;
sf_set_trusted_sink_ptr(meth);
Res = BIO_meth_set_callback_ctrl(meth, callback);
return Res;
```

3. int DSAparams_print(BIO* bp, const DSA* x)
```
int Res = 0;
sf_set_tainted(bp);
sf_set_tainted(x);
Res = DSAparams_print(bp, x);
return Res;
```

4. void DH_set_default_method(const DH_METHOD* meth)
```
sf_set_trusted_sink_ptr(meth);
DH_set_default_method(meth);
```

5. int X509_add1_ext_i2d(X509* x, int nid, void* value, int crit, unsigned long flags)
```
int Res = 0;
sf_set_tainted(x);
Res = X509_add1_ext_i2d(x, nid, value, crit, flags);
return Res;
```
void* X509at_get0_data_by_OBJ(const stack_st_X509_ATTRIBUTE* a, const ASN1_OBJECT* obj, int n, int idx)
{
    void *Res = NULL;
    Res = X509at_get0_data_by_OBJ(a, obj, n, idx);
    sf_set_possible_null(Res);
    return Res;
}

int ENGINE_set_ex_data(ENGINE* e, int idx, void* arg)
{
    int Res = 0;
    Res = ENGINE_set_ex_data(e, idx, arg);
    sf_set_errno_if(Res <= 0);
    return Res;
}

ASN1_UNIVERSALSTRING* d2i_ASN1_UNIVERSALSTRING(ASN1_UNIVERSALSTRING** a, const unsigned char** in, long len)
{
    ASN1_UNIVERSALSTRING *Res = NULL;
    Res = d2i_ASN1_UNIVERSALSTRING(a, in, len);
    sf_set_possible_null(Res);
    return Res;
}

int EVP_PKEY_add1_attr(EVP_PKEY* pkey, X509_ATTRIBUTE* attr)
{
    int Res = 0;
    Res = EVP_PKEY_add1_attr(pkey, attr);
    sf_set_errno_if(Res <= 0);
    return Res;
}

void EC_KEY_set_asn1_flag(EC_KEY* eckey, int flag)
{
    EC_KEY_set_asn1_flag(eckey, flag);
}

X509_LOOKUP* X509_LOOKUP_new(X509_LOOKUP_METHOD* method) {
    X509_LOOKUP* Res = NULL;
    sf_set_trusted_sink_int(method);
    Res = X509_LOOKUP_new(method);
    sf_overwrite(Res);
    return Res;
}

void X509_ALGOR_free(X509_ALGOR* a) {
    sf_set_trusted_sink_ptr(a);
    X509_ALGOR_free(a);
}

int UI_dup_verify_string(UI* ui, const char* prompt, int flags, char* result, int result_len, int verify_len, const char* verify) {
    int Res = 0;
    sf_password_use(prompt);
    sf_password_use(verify);
    Res = UI_dup_verify_string(ui, prompt, flags, result, result_len, verify_len, verify);
    sf_overwrite(Res);
    return Res;
}

void (ssl_ctx_st*, SSL_SESSION*)* SSL_CTX_sess_get_remove_cb(SSL_CTX* ctx) {
    void (ssl_ctx_st*, SSL_SESSION*)* Res = NULL;
    Res = SSL_CTX_sess_get_remove_cb(ctx);
    sf_overwrite(Res);
    return Res;
}

int X509_STORE_set_trust(X509_STORE* ctx, int trust) {
    int Res = 0;
    Res = X509_STORE_set_trust(ctx, trust);
    sf_overwrite(Res);
    return Res;
}
int BN_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);

int ASN1_STRING_print_ex(BIO *out, const ASN1_STRING *str, unsigned long flags);

int ASN1_INTEGER_set(ASN1_INTEGER *a, long value);

int OCSP_resp_count(OCSP_BASICRESP *bs);

int BIO_printf(BIO *bio, const char *format, ...);


void ISSUER_SIGN_TOOL_free(ISSUER_SIGN_TOOL *ptr)
{
    sf_delete(ptr, ISSUER_SIGN_TOOL_MEMORY_CATEGORY);
}

int SSL_use_PrivateKey_ASN1(int type, SSL *ssl, const unsigned char *d, long len)
{
    int res = 0;
    sf_set_trusted_sink_int(type);
    sf_set_trusted_sink_ptr(ssl);
    sf_set_trusted_sink_ptr(d);
    sf_set_trusted_sink_int(len);
    res = SSL_use_PrivateKey_ASN1(type, ssl, d, len);
    sf_set_errno_if(res <= 0);
    return res;
}

const char* EVP_RAND_get0_description(const EVP_RAND *rand)
{
    const char *res = NULL;
    sf_set_trusted_sink_ptr(rand);
    res = EVP_RAND_get0_description(rand);
    sf_set_possible_null(res);
    return res;
}

unsigned long ERR_get_error()
{
    unsigned long res = 0;
    res = ERR_get_error();
    sf_set_possible_negative(res);
    return res;
}

const ASN1_ITEM* X509_ALGOR_it()
{
    const ASN1_ITEM *res = NULL;
    res = X509_ALGOR_it();
    sf_set_possible_null(res);
    return res;
}

void SSL_set_tmp_dh_callback(SSL *ssl, DH *dh) {
    DH *Res = NULL;
    sf_set_trusted_sink_ptr(dh);
    sf_set_alloc_possible_null(Res);
    sf_lib_arg_type(Res, "DH");
    return;
}

int UI_method_set_closer(UI_METHOD *method, int (UI*) close_ui) {
    int Res = 0;
    sf_set_errno_if(Res, close_ui);
    sf_set_possible_null(Res);
    return Res;
}

int EC_GROUP_get_asn1_flag(const EC_GROUP *group) {
    int Res = 0;
    sf_set_errno_if(Res, group);
    sf_set_possible_null(Res);
    return Res;
}

int OCSP_check_nonce(OCSP_REQUEST *req, OCSP_BASICRESP *bs) {
    int Res = 0;
    sf_set_errno_if(Res, req);
    sf_set_errno_if(Res, bs);
    sf_set_possible_null(Res);
    return Res;
}

void EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx) {
    sf_delete(ctx, "EVP_PKEY_CTX");
    sf_lib_arg_type(ctx, "EVP_PKEY_CTX");
    return;
}

ASIdentifiers* ASIdentifiers_new() {
    ASIdentifiers* Res = NULL;
    Res = (ASIdentifiers*)sf_malloc_arg(sizeof(ASIdentifiers));
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_lib_arg_type(Res, "ASIdentifiers");
    sf_overwrite(Res);
    return Res;
}

SSL_CTX_keylog_cb_func SSL_CTX_get_keylog_callback(const SSL_CTX* ctx) {
    SSL_CTX_keylog_cb_func Res = NULL;
    Res = ctx->keylog_callback;
    sf_set_possible_null(Res);
    return Res;
}

X509_NAME* X509_NAME_new() {
    X509_NAME* Res = NULL;
    Res = (X509_NAME*)sf_malloc_arg(sizeof(X509_NAME));
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_lib_arg_type(Res, "X509_NAME");
    sf_overwrite(Res);
    return Res;
}

int (RSA*, int, BIGNUM*, BN_GENCB*)* RSA_meth_get_keygen(const RSA_METHOD* meth) {
    int (RSA*, int, BIGNUM*, BN_GENCB*)* Res = NULL;
    Res = meth->rsa_keygen;
    sf_set_possible_null(Res);
    return Res;
}

int EVP_EncodeUpdate(EVP_ENCODE_CTX* ctx, unsigned char* out, int* outl, const unsigned char* in, int inl) {
    int Res = 0;
    Res = EVP_EncodeUpdate(ctx, out, outl, in, inl);
    sf_buf_size_limit(out, *outl);
    sf_buf_size_limit_read(in, inl);
    sf_overwrite(out);
    return Res;
}

const EVP_CIPHER* EVP_camellia_128_ctr() {
    const EVP_CIPHER* Res = NULL;
    Res = EVP_camellia_128_ctr();
    sf_set_possible_null(Res);
    return Res;
}

EVP_PKEY* ENGINE_load_private_key(ENGINE* e, const char* key_id, UI_METHOD* ui_method, void* callback_data) {
    EVP_PKEY* Res = NULL;
    Res = ENGINE_load_private_key(e, key_id, ui_method, callback_data);
    sf_set_possible_null(Res);
    return Res;
}

char* BIO_ADDR_hostname_string(const BIO_ADDR* addr, int flags) {
    char* Res = NULL;
    Res = BIO_ADDR_hostname_string(addr, flags);
    sf_set_possible_null(Res);
    return Res;
}

int EVP_CIPHER_names_do_all(const EVP_CIPHER* cipher, void (const char*, void*)* fn, void* arg) {
    int Res = 0;
    Res = EVP_CIPHER_names_do_all(cipher, fn, arg);
    sf_set_errno_if(Res == 0);
    return Res;
}

X509* CT_POLICY_EVAL_CTX_get0_issuer(const CT_POLICY_EVAL_CTX* ctx) {
    X509* Res = NULL;
    Res = CT_POLICY_EVAL_CTX_get0_issuer(ctx);
    sf_set_possible_null(Res);
    return Res;
}

unsigned int X509_VERIFY_PARAM_get_hostflags(const X509_VERIFY_PARAM* param) {
    unsigned int Res = 0;
    sf_set_must_be_not_null(param, HOSTFLAGS_OF_NULL);
    Res = param->hostflags;
    sf_overwrite(Res);
    return Res;
}

int SHA384_Final(unsigned char* md, SHA512_CTX* ctx) {
    int Res = 0;
    sf_set_must_be_not_null(md, MD_OF_NULL);
    sf_set_must_be_not_null(ctx, CTX_OF_NULL);
    Res = SHA512_Final(md, ctx);
    sf_overwrite(Res);
    return Res;
}

int EVP_PKEY_CTX_get_ecdh_kdf_md(EVP_PKEY_CTX* ctx, const EVP_MD** md) {
    int Res = 0;
    sf_set_must_be_not_null(ctx, CTX_OF_NULL);
    sf_set_must_be_not_null(md, MD_OF_NULL);
    Res = EVP_PKEY_CTX_get_ecdh_kdf_md(ctx, md);
    sf_overwrite(Res);
    return Res;
}

const char* UI_get0_result_string(UI_STRING* uis) {
    const char* Res = NULL;
    sf_set_must_be_not_null(uis, UI_STRING_OF_NULL);
    Res = uis->result_string;
    sf_overwrite(Res);
    return Res;
}

ENGINE_LOAD_KEY_PTR ENGINE_get_load_pubkey_function(const ENGINE* e) {
    ENGINE_LOAD_KEY_PTR Res = NULL;
    sf_set_must_be_not_null(e, ENGINE_OF_NULL);
    Res = ENGINE_get_load_pubkey_function(e);
    sf_overwrite(Res);
    return Res;
}

void EVP_PKEY_meth_set_paramgen(EVP_PKEY_METHOD *pmeth, int (*paramgen_init) (EVP_PKEY_CTX *ctx), int (*paramgen) (EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)) {
    sf_set_trusted_sink_ptr(pmeth);
    sf_set_trusted_sink_ptr(paramgen_init);
    sf_set_trusted_sink_ptr(paramgen);
}

int ENGINE_register_RSA(ENGINE *e) {
    int res = 0;
    sf_set_must_not_be_null(e);
    sf_set_errno_if(res == 0);
    return res;
}

PKCS7_RECIP_INFO *d2i_PKCS7_RECIP_INFO(PKCS7_RECIP_INFO **a, const unsigned char **in, long len) {
    PKCS7_RECIP_INFO *res = NULL;
    sf_set_must_not_be_null(a);
    sf_set_must_not_be_null(*a);
    sf_set_must_not_be_null(in);
    sf_set_buf_size_limit(len);
    sf_set_errno_if(res == NULL);
    return res;
}

int EVP_PKEY_get_base_id(const EVP_PKEY *pkey) {
    int res = 0;
    sf_set_must_not_be_null(pkey);
    sf_set_errno_if(res == 0);
    return res;
}

void EC_KEY_set_conv_form(EC_KEY *eckey, point_conversion_form_t form) {
    sf_set_must_not_be_null(eckey);
    sf_set_trusted_sink_int(form);
}
void EC_GROUP_clear_free(EC_GROUP* group);

void ASIdentifierChoice_free(ASIdentifierChoice* asic);

int SSL_CTX_set_ct_validation_callback(SSL_CTX* ctx, ssl_ct_validation_cb cb, void* arg);

int i2d_IPAddressOrRange(const IPAddressOrRange* ip, unsigned char** out);

X509* X509_new();


int EC_POINT_set_Jprojective_coordinates_GFp(const EC_GROUP *group, EC_POINT *point, const BIGNUM *x, const BIGNUM *y, const BIGNUM *z, BN_CTX *ctx) {
    int Res = 0;
    sf_set_trusted_sink_int(x);
    sf_set_trusted_sink_int(y);
    sf_set_trusted_sink_int(z);
    Res = EC_POINT_set_Jprojective_coordinates_GFp(group, point, x, y, z, ctx);
    sf_overwrite(Res);
    return Res;
}

int i2d_RSAPrivateKey_bio(BIO *bp, const RSA *a) {
    int Res = 0;
    sf_set_tainted(a);
    Res = i2d_RSAPrivateKey_bio(bp, a);
    sf_overwrite(Res);
    return Res;
}

int RSA_bits(const RSA *r) {
    int Res = 0;
    Res = RSA_bits(r);
    sf_overwrite(Res);
    return Res;
}

int EVP_PKEY_CTX_set_rsa_pss_keygen_md(EVP_PKEY_CTX *ctx, const EVP_MD *md) {
    int Res = 0;
    sf_set_tainted(md);
    Res = EVP_PKEY_CTX_set_rsa_pss_keygen_md(ctx, md);
    sf_overwrite(Res);
    return Res;
}

int X509_REQ_set_version(X509_REQ *x, long version) {
    int Res = 0;
    Res = X509_REQ_set_version(x, version);
    sf_overwrite(Res);
    return Res;
}
BIGNUM* SSL_get_srp_g(SSL* s);

const OSSL_PARAM* EVP_PKEY_gettable_params(const EVP_PKEY* pkey);

DSA* PEM_read_DSAparams(FILE* fp, DSA** dsa, pem_password_cb* cb, void* u);

X509_REQ* d2i_X509_REQ(X509_REQ** req, const unsigned char** in, long len);

const OSSL_PARAM* EVP_ASYM_CIPHER_settable_ctx_params(const EVP_ASYM_CIPHER* cipher);


int X509_STORE_CTX_verify_cb(X509_STORE_CTX *ctx) {
    int res = 0;
    sf_set_trusted_sink_int(res);
    sf_set_errno_if(res == 0);
    return res;
}

X509_STORE_CTX_verify_cb X509_STORE_get_verify_cb(const X509_STORE *store) {
    X509_STORE_CTX_verify_cb res = NULL;
    sf_set_possible_null(res);
    return res;
}

const EC_GROUP* EC_KEY_get0_group(const EC_KEY *key) {
    const EC_GROUP* res = NULL;
    sf_set_possible_null(res);
    return res;
}

int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *ctx, int keylen) {
    int res = 0;
    sf_set_errno_if(res <= 0);
    return res;
}

const ASN1_OCTET_STRING* X509_get0_subject_key_id(X509 *x) {
    const ASN1_OCTET_STRING* res = NULL;
    sf_set_possible_null(res);
    return res;
}

int i2d_X509_CRL_INFO(const X509_CRL_INFO *crl, unsigned char **pp) {
    int res = 0;
    sf_set_trusted_sink_int(res);
    sf_set_errno_if(res <= 0);
    return res;
}
EVP_PKEY* d2i_PUBKEY_bio(BIO* bp, EVP_PKEY** x);

X509_ALGORS* d2i_X509_ALGORS(X509_ALGORS** a, const unsigned char** in, long len);

ASN1_UTCTIME* ASN1_UTCTIME_dup(const ASN1_UTCTIME* x);

X509_NAME_ENTRY* X509_NAME_ENTRY_dup(const X509_NAME_ENTRY* x);

int BN_BLINDING_convert(BIGNUM* r, BN_BLINDING* b, BN_CTX* ctx);

void* ASN1_item_d2i_bio(const ASN1_ITEM* it, BIO* bio, void* out);

PKCS7_SIGNER_INFO* PKCS7_sign_add_signer(PKCS7* p7, X509* cert, EVP_PKEY* key, const EVP_MD* md, int flags);

int SSL_use_cert_and_key(SSL* s, X509* x, EVP_PKEY* pkey, stack_st_X509* chain, int flags);

uint32_t X509_get_extended_key_usage(X509* x);

PROFESSION_INFO* d2i_PROFESSION_INFO(PROFESSION_INFO** info, const unsigned char** in, long len);


int SSL_connect(SSL* ssl) {
    int ret = 0;
    sf_set_must_be_not_null(ssl, SSL_CONNECT_OF_NULL);
    ret = SSL_connect(ssl);
    sf_set_errno_if(ret <= 0);
    sf_set_possible_null(ret);
    return ret;
}

OCSP_RESPBYTES* OCSP_RESPBYTES_new() {
    OCSP_RESPBYTES* resp = NULL;
    resp = OCSP_RESPBYTES_new();
    sf_set_alloc_possible_null(resp);
    return resp;
}

int OSSL_PARAM_get_utf8_ptr(const OSSL_PARAM* param, const char** str) {
    int ret = 0;
    sf_set_must_be_not_null(param, PARAM_GET_UTF8_PTR_OF_NULL);
    sf_set_must_be_not_null(str, PARAM_GET_UTF8_PTR_OF_NULL);
    ret = OSSL_PARAM_get_utf8_ptr(param, str);
    sf_set_errno_if(ret <= 0);
    sf_set_possible_null(ret);
    return ret;
}

X509* d2i_X509(X509** x, const unsigned char** in, long len) {
    X509* ret = NULL;
    sf_set_must_be_not_null(in, D2I_X509_OF_NULL);
    ret = d2i_X509(x, in, len);
    sf_set_alloc_possible_null(ret);
    return ret;
}

DSA* PEM_read_bio_DSA_PUBKEY(BIO* bio, DSA** dsa, pem_password_cb* cb, void* u) {
    DSA* ret = NULL;
    sf_set_must_be_not_null(bio, PEM_READ_BIO_DSA_PUBKEY_OF_NULL);
    ret = PEM_read_bio_DSA_PUBKEY(bio, dsa, cb, u);
    sf_set_alloc_possible_null(ret);
    return ret;
}

RSA* PEM_read_RSAPrivateKey(FILE* fp, RSA** x, pem_password_cb* cb, void* u) {
    RSA* Res = NULL;
    sf_set_trusted_sink_ptr(fp);
    sf_set_trusted_sink_ptr(cb);
    sf_set_trusted_sink_ptr(u);
    sf_set_tainted(x);
    sf_set_password_use(cb);
    Res = PEM_read_RSAPrivateKey(fp, x, cb, u);
    sf_set_possible_null(Res);
    return Res;
}

int UI_UTIL_read_pw(char* buf, char* prompt, int verify, const char* caller, int len) {
    int Res = 0;
    sf_set_buf_size(buf, len);
    sf_null_terminated(buf);
    sf_password_set(buf);
    Res = UI_UTIL_read_pw(buf, prompt, verify, caller, len);
    sf_overwrite(buf);
    return Res;
}

int BN_rand_ex(BIGNUM* rnd, int bits, int top, int bottom, unsigned int flags, BN_CTX* ctx) {
    int Res = 0;
    sf_set_buf_size(rnd, bits);
    Res = BN_rand_ex(rnd, bits, top, bottom, flags, ctx);
    sf_bitinit(rnd);
    return Res;
}

int BIO_ctrl_reset_read_request(BIO* bp) {
    int Res = 0;
    Res = BIO_ctrl_reset_read_request(bp);
    return Res;
}

EVP_PKEY_gen_cb* EVP_PKEY_CTX_get_cb(EVP_PKEY_CTX* ctx) {
    EVP_PKEY_gen_cb* Res = NULL;
    Res = EVP_PKEY_CTX_get_cb(ctx);
    sf_set_possible_null(Res);
    return Res;
}
int SSL_CTX_set_generate_session_id(SSL_CTX* ctx, GEN_SESSION_CB cb);

int DSA_meth_get_paramgen(const DSA_METHOD* dm);

int EVP_MAC_CTX_get_params(EVP_MAC_CTX* ctx, OSSL_PARAM params[]);

PKCS7* PEM_read_PKCS7(FILE* fp, PKCS7** x, pem_password_cb* cb, void* u);

int OPENSSL_sk_reserve(OPENSSL_STACK* st, int n);

void EVP_MD_CTX_set_pkey_ctx(EVP_MD_CTX* ctx, EVP_PKEY_CTX* pctx);

int SSL_key_update(SSL* s, int key_update_requested);

int EVP_PKEY_get_size_t_param(const EVP_PKEY* pkey, const char* param, size_t* out);

int BIO_get_retry_reason(BIO* bio);

char* CRYPTO_strndup(const char* str, size_t s, const char* file, int line);


point_conversion_form_t EC_GROUP_get_point_conversion_form(const EC_GROUP* group) {
    point_conversion_form_t Res = 0;
    Res = group->point_conversion_form;
    sf_set_possible_null(Res);
    return Res;
}

int i2d_SXNETID(const SXNETID* a, unsigned char** pp) {
    int Res = 0;
    Res = a->length + 2;
    sf_set_possible_null(Res);
    return Res;
}

const char* ENGINE_get_name(const ENGINE* e) {
    const char* Res = NULL;
    Res = e->name;
    sf_set_possible_null(Res);
    return Res;
}

const EVP_CIPHER* EVP_aes_256_cbc_hmac_sha1() {
    const EVP_CIPHER* Res = NULL;
    Res = EVP_aes_256_cbc_hmac_sha1();
    sf_set_possible_null(Res);
    return Res;
}

int BIO_read_ex(BIO* bp, void* data, size_t dlen, size_t* readbytes) {
    int Res = 0;
    Res = BIO_read_ex(bp, data, dlen, readbytes);
    sf_set_errno_if(Res <= 0);
    sf_set_possible_null(Res);
    return Res;
}

const OSSL_PARAM* EVP_MAC_gettable_params(const EVP_MAC* mac) {
    const OSSL_PARAM* Res = NULL;
    Res = EVP_MAC_gettable_params(mac);
    sf_set_trusted_sink_ptr(Res);
    return Res;
}

int i2d_PrivateKey(const EVP_PKEY* pkey, unsigned char** out) {
    int Res = 0;
    Res = i2d_PrivateKey(pkey, out);
    sf_set_possible_null(Res);
    sf_set_buf_size(out, Res);
    return Res;
}

int i2d_OCSP_SERVICELOC(const OCSP_SERVICELOC* loc, unsigned char** out) {
    int Res = 0;
    Res = i2d_OCSP_SERVICELOC(loc, out);
    sf_set_possible_null(Res);
    sf_set_buf_size(out, Res);
    return Res;
}

const EVP_CIPHER* EVP_aes_256_xts() {
    const EVP_CIPHER* Res = NULL;
    Res = EVP_aes_256_xts();
    sf_set_trusted_sink_ptr(Res);
    return Res;
}

RSA_PSS_PARAMS* RSA_PSS_PARAMS_dup(const RSA_PSS_PARAMS* params) {
    RSA_PSS_PARAMS* Res = NULL;
    Res = RSA_PSS_PARAMS_dup(params);
    sf_set_possible_null(Res);
    return Res;
}
int ASN1_TIME_set_string_X509(ASN1_TIME* s, const char* str);

int PKCS7_add_certificate(PKCS7* p7, X509* x);

const EVP_CIPHER* EVP_aria_128_ccm();

int SSL_SESSION_set1_ticket_appdata(SSL_SESSION* s, const void* data, size_t len);

const EVP_PKEY_ASN1_METHOD* EVP_PKEY_asn1_get0(int nid);


void BIO_ADDRINFO_free(BIO_ADDRINFO* a) {
    sf_set_must_be_not_null(a, FREE_OF_NULL);
    sf_delete(a, ADDRINFO_CATEGORY);
}

ISSUER_SIGN_TOOL* ISSUER_SIGN_TOOL_new() {
    ISSUER_SIGN_TOOL* Res = NULL;
    sf_new(Res, ISSUER_SIGN_TOOL_CATEGORY);
    return Res;
}

int BIO_up_ref(BIO* bp) {
    sf_set_must_be_not_null(bp, UP_REF_OF_NULL);
    sf_set_alloc_possible_null(bp);
    return 1;
}

const UI_METHOD* UI_get_method(UI* ui) {
    sf_set_must_be_not_null(ui, GET_METHOD_OF_NULL);
    const UI_METHOD* Res = NULL;
    sf_set_possible_null(Res);
    return Res;
}

int X509_CRL_set1_lastUpdate(X509_CRL* crl, const ASN1_TIME* tm) {
    sf_set_must_be_not_null(crl, SET1_LASTUPDATE_OF_NULL);
    sf_set_must_be_not_null(tm, SET1_LASTUPDATE_OF_NULL);
    return 1;
}

void SSL_CTX_get_info_callback(SSL_CTX *ctx) {
    void (*Res)(const SSL *, int, int) = NULL;
    Res = SSL_CTX_get_info_callback(ctx);
    sf_set_possible_null(Res);
    return Res;
}

uint32_t X509_get_extension_flags(X509 *x) {
    uint32_t Res = 0;
    Res = X509_get_extension_flags(x);
    sf_set_errno_if(Res == UINT32_MAX);
    return Res;
}

int SCT_get_signature_nid(const SCT *sct) {
    int Res = 0;
    Res = SCT_get_signature_nid(sct);
    sf_set_errno_if(Res == 0);
    return Res;
}

int EC_KEY_set_public_key_affine_coordinates(EC_KEY *key, BIGNUM *x, BIGNUM *y) {
    int Res = 0;
    Res = EC_KEY_set_public_key_affine_coordinates(key, x, y);
    sf_set_errno_if(Res == 0);
    return Res;
}

const EVP_CIPHER* EVP_aria_192_cfb128() {
    const EVP_CIPHER *Res = NULL;
    Res = EVP_aria_192_cfb128();
    sf_set_possible_null(Res);
    return Res;
}
BIGNUM* BN_native2bn(const unsigned char*, int, BIGNUM*);

int EVP_RAND_reseed(EVP_RAND_CTX*, int, const unsigned char*, size_t, const unsigned char*, size_t);

int EVP_PKEY_get_utf8_string_param(const EVP_PKEY*, const char*,  char*, size_t, size_t*);

void SSL_CTX_sess_set_new_cb(SSL_CTX*, int (ssl_st*, SSL_SESSION*);

const char* OBJ_nid2sn(int);

int i2d_USERNOTICE(const USERNOTICE *a, unsigned char **pp);

const EVP_CIPHER *EVP_aria_192_cbc();

const EVP_MD *EVP_md5();

int ASN1_ENUMERATED_set_int64(ASN1_ENUMERATED *a, int64_t v);

int OSSL_PARAM_get_uint(const OSSL_PARAM *p, unsigned int *val);

int EC_GROUP_get_curve_GF2m(const EC_GROUP* group, BIGNUM* p, BIGNUM* a, BIGNUM* b, BN_CTX* ctx);

UI_METHOD* UI_create_method(const char* name);

int EVP_PKEY_CTX_set_dsa_paramgen_md(EVP_PKEY_CTX* ctx, const EVP_MD* md);

size_t SSL_CTX_get_num_tickets(const SSL_CTX* ctx);

void* OPENSSL_sk_value(const OPENSSL_STACK* st, int i);


// BIO* BIO_push(BIO*, BIO*)
void BIO_push(BIO *b, BIO *append) {
    BIO *Res = NULL;
    sf_set_trusted_sink_ptr(append);
    sf_set_trusted_sink_ptr(b);
    Res = BIO_push(b, append);
    sf_set_possible_null(Res);
    return Res;
}

// int BIO_ADDRINFO_family(const BIO_ADDRINFO*)
int BIO_ADDRINFO_family(const BIO_ADDRINFO *addr) {
    int Res = 0;
    sf_set_trusted_sink_ptr(addr);
    Res = BIO_ADDRINFO_family(addr);
    return Res;
}

// const BIO_METHOD* BIO_s_null()
const BIO_METHOD* BIO_s_null() {
    const BIO_METHOD *Res = NULL;
    Res = BIO_s_null();
    return Res;
}

// int RSA_verify(int, const unsigned char*, unsigned int, const unsigned char*, unsigned int, RSA*)
int RSA_verify(int type, const unsigned char *m, unsigned int m_length, const unsigned char *sig, unsigned int sig_length, RSA *rsa) {
    int Res = 0;
    sf_set_trusted_sink_ptr(rsa);
    sf_set_tainted(m, m_length);
    sf_set_tainted(sig, sig_length);
    Res = RSA_verify(type, m, m_length, sig, sig_length, rsa);
    return Res;
}

// POLICY_CONSTRAINTS* POLICY_CONSTRAINTS_new()
POLICY_CONSTRAINTS* POLICY_CONSTRAINTS_new() {
    POLICY_CONSTRAINTS *Res = NULL;
    Res = POLICY_CONSTRAINTS_new();
    sf_set_possible_null(Res);
    return Res;
}

int PEM_write_bio_PrivateKey(BIO* bio, const EVP_PKEY* pkey, const EVP_CIPHER* cipher, const unsigned char* passwd, int len, pem_password_cb* cb, void* u) {
    int res = 0;
    sf_set_tainted(bio);
    sf_set_tainted(pkey);
    sf_set_tainted(cipher);
    sf_password_use(passwd);
    sf_set_must_be_not_null(cb, FREE_OF_NULL);
    sf_set_must_be_not_null(u, FREE_OF_NULL);
    sf_set_errno_if(res == 0);
    sf_set_possible_null(res);
    return res;
}

int i2d_DSA_PUBKEY(const DSA* dsa, unsigned char** pp) {
    int res = 0;
    sf_set_tainted(dsa);
    sf_set_tainted(pp);
    sf_set_errno_if(res == 0);
    sf_set_possible_null(res);
    return res;
}

int BN_mask_bits(BIGNUM* bn, int n) {
    int res = 0;
    sf_set_tainted(bn);
    sf_set_errno_if(res == 0);
    sf_set_possible_null(res);
    return res;
}

size_t CRYPTO_secure_used() {
    size_t res = 0;
    return res;
}

const char* RSA_meth_get0_name(const RSA_METHOD* meth) {
    const char* res = NULL;
    sf_set_tainted(meth);
    sf_set_possible_null(res);
    return res;
}
int SMIME_write_PKCS7(BIO* bp, PKCS7* p7, BIO* bio, int flags);

int i2d_PROFESSION_INFO(const PROFESSION_INFO* p, unsigned char** out);

CRL_DIST_POINTS* d2i_CRL_DIST_POINTS(CRL_DIST_POINTS** cdp, const unsigned char** in, long len);

int OPENSSL_INIT_set_config_filename(OPENSSL_INIT_SETTINGS* settings, const char* config_filename);

int EVP_CIPHER_CTX_do_cipher(EVP_CIPHER_CTX* ctx, unsigned char* out, const unsigned char* in, size_t inl);


void OPENSSL_fork_prepare() {
    sf_set_trusted_sink_int(0);
}

const EVP_CIPHER* EVP_camellia_256_cfb8() {
    const EVP_CIPHER* Res = NULL;
    sf_set_trusted_sink_int(0);
    return Res;
}

const unsigned char* SSL_SESSION_get0_id_context(const SSL_SESSION* s, unsigned int* len) {
    const unsigned char* Res = NULL;
    sf_set_trusted_sink_int(0);
    return Res;
}

size_t SSL_get_server_random(const SSL* s, unsigned char* out, size_t outlen) {
    size_t Res = 0;
    sf_set_trusted_sink_int(0);
    return Res;
}

int X509_NAME_get_text_by_NID(const X509_NAME* name, int nid, char* buf, int len) {
    int Res = 0;
    sf_set_trusted_sink_int(0);
    return Res;
}

RSA* RSA_new()
{
    RSA* Res = NULL;
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    return Res;
}

PBE2PARAM* d2i_PBE2PARAM(PBE2PARAM**, const unsigned char**, long)
{
    PBE2PARAM* Res = NULL;
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    return Res;
}

X509_ALGOR* PKCS5_pbe_set_ex(int, int, const unsigned char*, int, OSSL_LIB_CTX*)
{
    X509_ALGOR* Res = NULL;
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    return Res;
}

void EVP_PKEY_asn1_set_siginf(EVP_PKEY_ASN1_METHOD*, int (X509_SIG_INFO*, const X509_ALGOR*, const ASN1_STRING*)*)
{
    // No return value, so no need to allocate memory or assign Res
}

void EVP_ASYM_CIPHER_do_all_provided(OSSL_LIB_CTX*, void (EVP_ASYM_CIPHER*, void*)*, void*)
{
    // No return value, so no need to allocate memory or assign Res
}

void SSL_set_psk_server_callback(SSL *ssl, SSL_psk_server_cb_func cb) {
    sf_set_tainted(ssl);
    sf_set_tainted(cb);
    sf_set_trusted_sink_ptr(ssl);
    sf_set_trusted_sink_ptr(cb);
}

int i2d_PrivateKey_bio(BIO *bp, const EVP_PKEY *pkey) {
    sf_set_tainted(bp);
    sf_set_tainted(pkey);
    sf_set_trusted_sink_ptr(bp);
    sf_set_trusted_sink_ptr(pkey);
    int res = 0;
    sf_set_errno_if(res <= 0, EVP_PKEY_print_errors_cb);
    return res;
}

USERNOTICE* USERNOTICE_new() {
    USERNOTICE *res = NULL;
    sf_malloc_arg(res, sizeof(USERNOTICE));
    sf_new(res, USERNOTICE_MEMORY_CATEGORY);
    sf_set_possible_null(res);
    return res;
}

int BN_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx) {
    sf_set_tainted(r);
    sf_set_tainted(a);
    sf_set_tainted(b);
    sf_set_tainted(m);
    sf_set_tainted(ctx);
    sf_set_trusted_sink_ptr(r);
    sf_set_trusted_sink_ptr(a);
    sf_set_trusted_sink_ptr(b);
    sf_set_trusted_sink_ptr(m);
    sf_set_trusted_sink_ptr(ctx);
    int res = 0;
    sf_set_errno_if(res <= 0, BN_mod_mul_err);
    return res;
}

CTLOG_STORE* CTLOG_STORE_new() {
    CTLOG_STORE *res = NULL;
    sf_malloc_arg(res, sizeof(CTLOG_STORE));
    sf_new(res, CTLOG_STORE_MEMORY_CATEGORY);
    sf_set_possible_null(res);
    return res;
}

int ASYNC_is_capable() {
    int Res = 0;
    // Function body
    return Res;
}

ASN1_INTEGER* ASN1_INTEGER_new() {
    ASN1_INTEGER* Res = NULL;
    // Function body
    return Res;
}

int PKCS7_type_is_other(PKCS7* ptr) {
    int Res = 0;
    // Function body
    return Res;
}

int EVP_PKEY_derive_set_peer(EVP_PKEY_CTX* ctx, EVP_PKEY* peer) {
    int Res = 0;
    // Function body
    return Res;
}

void PBKDF2PARAM_free(PBKDF2PARAM* param) {
    // Function body
}

void CERTIFICATEPOLICIES_free(CERTIFICATEPOLICIES* policies) {
    if (policies != NULL) {
        // Free the memory
        OPENSSL_free(policies);
    }
}

int BIO_connect(int sock, const BIO_ADDR* addr, int connect_family) {
    int ret;
    sf_set_must_be_not_null(addr, "BIO_ADDR");
    sf_set_must_be_positive(connect_family, "connect_family");
    ret = BIO_connect(sock, addr, connect_family);
    sf_set_errno_if(ret <= 0);
    return ret;
}

int EVP_PKEY_get_bn_param(const EVP_PKEY* pkey, const char* param_name, BIGNUM** bn) {
    int ret;
    sf_set_must_be_not_null(pkey, "EVP_PKEY");
    sf_set_must_be_not_null(param_name, "param_name");
    sf_set_must_be_not_null(bn, "BIGNUM");
    ret = EVP_PKEY_get_bn_param(pkey, param_name, bn);
    sf_set_errno_if(ret <= 0);
    return ret;
}

int SSL_shutdown(SSL* ssl) {
    int ret;
    sf_set_must_be_not_null(ssl, "SSL");
    ret = SSL_shutdown(ssl);
    sf_set_errno_if(ret < 0);
    return ret;
}

int SSL_use_psk_identity_hint(SSL* ssl, const char* hint) {
    int ret;
    sf_set_must_be_not_null(ssl, "SSL");
    sf_password_use(hint);
    ret = SSL_use_psk_identity_hint(ssl, hint);
    sf_set_errno_if(ret <= 0);
    return ret;
}
int DH_check_pub_key_ex(const DH* dh, const BIGNUM* bn);

int RAND_pseudo_bytes(unsigned char* buf, int num);

int EVP_PKEY_CTX_get1_id(EVP_PKEY_CTX* ctx, void* id);

int i2d_DSA_PUBKEY_fp(FILE* fp, const DSA* dsa);

int i2d_ASN1_SET_ANY(const ASN1_SEQUENCE_ANY* as, unsigned char** out);


int EVP_SignFinal(EVP_MD_CTX *ctx, unsigned char *sigret, unsigned int *siglen, EVP_PKEY *pkey) {
    int res = 0;
    sf_set_trusted_sink_int(siglen);
    sf_set_trusted_sink_ptr(sigret);
    sf_set_tainted(ctx);
    sf_set_tainted(pkey);
    sf_set_errno_if(res <= 0);
    sf_set_possible_null(res);
    return res;
}

void SSL_set_security_callback(SSL *s, int (*cb) (const SSL *, const SSL_CTX *, int, int, int, void *, void *)) {
    sf_set_tainted(s);
    sf_set_tainted(cb);
}

const EVP_CIPHER* EVP_get_cipherbyname(const char *name) {
    const EVP_CIPHER *res = NULL;
    sf_set_tainted(name);
    sf_set_possible_null(res);
    return res;
}

void ENGINE_unregister_RAND(ENGINE *e) {
    sf_set_tainted(e);
}

const char* EVP_PKEY_CTX_get0_propq(const EVP_PKEY_CTX *ctx) {
    const char *res = NULL;
    sf_set_tainted(ctx);
    sf_set_possible_null(res);
    return res;
}
int SSL_export_keying_material(SSL* ssl, unsigned char* out, size_t olen, const char* label, size_t llen, const unsigned char* context, size_t contextlen, int use_context);

EC_KEY* EC_KEY_new_ex(OSSL_LIB_CTX* libctx, const char* propq);

int EVP_PKEY_set1_DH(EVP_PKEY* pkey, dh_st* key);

int EVP_DigestVerifyUpdate(EVP_MD_CTX* ctx, const void* d, size_t cnt);

stack_st_X509_REVOKED* X509_CRL_get_REVOKED(X509_CRL* crl);


UI_METHOD* Res = NULL;
sf_malloc_arg(Res, sizeof(UI_METHOD), "UI_METHOD");
sf_overwrite(Res);
return Res;

EVP_PKEY* Res = NULL;
sf_set_tainted(fp);
sf_password_use(cb);
sf_set_must_be_not_null(fp, FREE_OF_NULL);
sf_set_must_be_not_null(x, FREE_OF_NULL);
sf_set_possible_null(Res);
return Res;

const char* Res = NULL;
sf_set_must_be_not_null(s, FREE_OF_NULL);
sf_set_possible_null(Res);
return Res;

EVP_PKEY_CTX* Res = NULL;
sf_set_must_be_not_null(ctx, FREE_OF_NULL);
sf_set_possible_null(Res);
return Res;

const OSSL_PARAM* Res = NULL;
sf_set_must_be_not_null(ke, FREE_OF_NULL);
sf_set_possible_null(Res);
return Res;
void OCSP_REVOKEDINFO_free(OCSP_REVOKEDINFO* a);

const char* SSL_state_string_long(const SSL* s);

X509_ATTRIBUTE* X509_ATTRIBUTE_create_by_OBJ(X509_ATTRIBUTE** a, const ASN1_OBJECT* obj, int type, const void* data, int len);

int EC_POINT_get_affine_coordinates_GF2m(const EC_GROUP* group, const EC_POINT* point, BIGNUM* x, BIGNUM* y, BN_CTX* ctx);

OCSP_REQUEST* d2i_OCSP_REQUEST(OCSP_REQUEST** a, const unsigned char** in, long len);


RSA* d2i_RSAPublicKey_bio(BIO* bp, RSA** rsa)
{
    RSA* Res = NULL;
    sf_set_tainted(bp);
    sf_set_trusted_sink_ptr(rsa);
    sf_set_must_be_not_null(bp, BIO_OF_NULL);
    sf_set_must_be_not_null(rsa, RSA_OF_NULL);
    sf_set_possible_null(Res);
    return Res;
}

int OPENSSL_init_crypto(uint64_t opts, const OPENSSL_INIT_SETTINGS* settings)
{
    int Res = 0;
    sf_set_must_be_not_null(settings, INIT_SETTINGS_OF_NULL);
    sf_set_possible_null(Res);
    return Res;
}

int EVP_PKEY_CTX_set_dh_rfc5114(EVP_PKEY_CTX* ctx, int nid)
{
    int Res = 0;
    sf_set_must_be_not_null(ctx, PKEY_CTX_OF_NULL);
    sf_set_possible_null(Res);
    return Res;
}

const char* SSL_get_version(const SSL* ssl)
{
    const char* Res = NULL;
    sf_set_must_be_not_null(ssl, SSL_OF_NULL);
    sf_set_possible_null(Res);
    return Res;
}

int i2d_X509_VAL(const X509_VAL* a, unsigned char** pp)
{
    int Res = 0;
    sf_set_must_be_not_null(a, X509_VAL_OF_NULL);
    sf_set_must_be_not_null(pp, PP_OF_NULL);
    sf_set_possible_null(Res);
    return Res;
}
void SSL_SESSION_get0_ticket(const SSL_SESSION* s, const unsigned char** tick, size_t* len);

size_t HMAC_size(const HMAC_CTX* ctx);

int ENGINE_register_DH(ENGINE* e);

EVP_PKEY* X509_get_pubkey(X509* x);

const EVP_PKEY_METHOD* EVP_PKEY_meth_find(int id);


const EVP_CIPHER* EVP_aes_256_wrap() {
    const EVP_CIPHER* Res = NULL;
    Res = EVP_aes_256_wrap();
    sf_set_possible_null(Res);
    return Res;
}

EVP_CIPHER* EVP_CIPHER_meth_new(int nid, int block_size, int key_len) {
    EVP_CIPHER* Res = NULL;
    Res = EVP_CIPHER_meth_new(nid, block_size, key_len);
    sf_set_alloc_possible_null(Res);
    return Res;
}

void SCT_LIST_print(const stack_st_SCT* sct_list, BIO* bio, int indent, const char* log_id, const CTLOG_STORE* log_store) {
    SCT_LIST_print(sct_list, bio, indent, log_id, log_store);
}

const EVP_MD* EVP_sha512_224() {
    const EVP_MD* Res = NULL;
    Res = EVP_sha512_224();
    sf_set_possible_null(Res);
    return Res;
}

int BN_mod_add(BIGNUM* r, const BIGNUM* a, const BIGNUM* b, const BIGNUM* m, BN_CTX* ctx) {
    int Res = 0;
    Res = BN_mod_add(r, a, b, m, ctx);
    sf_set_errno_if(Res == 0);
    return Res;
}

const EVP_MD* EVP_sha256() {
    const EVP_MD* Res = NULL;
    Res = EVP_sha256();
    sf_set_possible_null(Res);
    return Res;
}

const char* DH_meth_get0_name(const DH_METHOD* dh) {
    const char* Res = NULL;
    Res = DH_meth_get0_name(dh);
    sf_set_possible_null(Res);
    return Res;
}

int SSL_CTX_set_default_verify_store(SSL_CTX* ctx) {
    int Res = 0;
    Res = SSL_CTX_set_default_verify_store(ctx);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int X509_VERIFY_PARAM_set1_ip_asc(X509_VERIFY_PARAM* param, const char* ipasc) {
    int Res = 0;
    Res = X509_VERIFY_PARAM_set1_ip_asc(param, ipasc);
    sf_set_errno_if(Res <= 0);
    return Res;
}

BIGNUM* BN_new() {
    BIGNUM* Res = NULL;
    Res = BN_new();
    sf_set_alloc_possible_null(Res);
    return Res;
}

EC_GROUP* EC_GROUP_new_from_params(const OSSL_PARAM params[], OSSL_LIB_CTX* libctx, const char* propq) {
    EC_GROUP* Res = NULL;
    sf_set_trusted_sink_int(params);
    sf_malloc_arg(Res, EC_GROUP_MEMORY_CATEGORY);
    sf_overwrite(Res);
    sf_new(Res, EC_GROUP_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    return Res;
}

void RSA_free(RSA* rsa) {
    sf_set_must_be_not_null(rsa, FREE_OF_NULL);
    sf_delete(rsa, RSA_MEMORY_CATEGORY);
    sf_lib_arg_type(rsa, "RSA");
}

int EVP_DigestVerifyInit(EVP_MD_CTX* ctx, EVP_PKEY_CTX** pctx, const EVP_MD* type, ENGINE* e, EVP_PKEY* pkey) {
    int Res = 0;
    sf_set_errno_if(Res <= 0);
    sf_no_errno_if(Res > 0);
    return Res;
}

void CTLOG_get0_log_id(const CTLOG* log, const uint8_t** id, size_t* idlen) {
    sf_set_tainted(id);
    sf_set_tainted(idlen);
    sf_null_terminated(id);
    sf_buf_size_limit(id, *idlen);
}

void DTLS_set_timer_cb(SSL* s, DTLS_timer_cb cb) {
    sf_set_trusted_sink_ptr(s);
    sf_set_trusted_sink_ptr(cb);
}

const stack_st_X509* OCSP_resp_get0_certs(const OCSP_BASICRESP* bs) {
    const stack_st_X509* Res = NULL;
    sf_set_trusted_sink_int(bs);
    Res = OCSP_resp_get0_certs(bs);
    sf_overwrite(Res);
    return Res;
}

void X509_CERT_AUX_free(X509_CERT_AUX* aux) {
    sf_set_must_be_not_null(aux, FREE_OF_NULL);
    sf_delete(aux, MALLOC_CATEGORY);
    sf_lib_arg_type(aux, "MallocCategory");
}

int X509v3_get_ext_by_NID(const stack_st_X509_EXTENSION* exts, int nid, int lastpos) {
    int Res = -1;
    sf_set_trusted_sink_int(exts);
    Res = X509v3_get_ext_by_NID(exts, nid, lastpos);
    sf_set_errno_if(Res == -1);
    return Res;
}

X509_VAL* X509_VAL_new() {
    X509_VAL* Res = NULL;
    Res = X509_VAL_new();
    sf_set_alloc_possible_null(Res);
    return Res;
}

OSSL_PARAM OSSL_PARAM_construct_size_t(const char* key, size_t* buf) {
    OSSL_PARAM Res = {NULL, 0, NULL, 0};
    sf_set_trusted_sink_ptr(buf);
    Res = OSSL_PARAM_construct_size_t(key, buf);
    sf_overwrite(Res);
    return Res;
}

int RSA_meth_set_bn_mod_exp(RSA_METHOD *meth, int (BIGNUM*, const BIGNUM*, const BIGNUM*, const BIGNUM*, BN_CTX*, BN_MONT_CTX*)* bn_mod_exp) {
    int Res = 0;
    meth->bn_mod_exp = bn_mod_exp;
    return Res;
}

int DSA_meth_set_finish(DSA_METHOD *meth, int (DSA*)* dsa_finish) {
    int Res = 0;
    meth->dsa_finish = dsa_finish;
    return Res;
}

void ERR_add_error_data(int num) {
    // No return value or assignment, just perform the action
    ERR_add_error_data(num);
}

void EVP_CIPHER_do_all_provided(OSSL_LIB_CTX *libctx, void (EVP_CIPHER*, void*)* fn, void *arg) {
    // No return value or assignment, just perform the action
    EVP_CIPHER_do_all_provided(libctx, fn, arg);
}

OSSL_PARAM OSSL_PARAM_construct_int32(const char *key, int32_t *buf) {
    OSSL_PARAM Res = OSSL_PARAM_construct_int32(key, buf);
    return Res;
}

int EVP_PBE_CipherInit_ex(ASN1_OBJECT *asn1, const char *pass, int passlen, ASN1_TYPE *param, EVP_CIPHER_CTX *ctx, int enc, OSSL_LIB_CTX *libctx, const char *propq) {
    int res = 0;
    sf_password_use(pass);
    sf_set_tainted(asn1);
    sf_set_tainted(param);
    sf_set_tainted(ctx);
    sf_set_tainted(libctx);
    sf_set_tainted(propq);
    sf_set_errno_if(res == 0);
    return res;
}

EVP_PKEY_CTX* EVP_PKEY_CTX_new_from_name(OSSL_LIB_CTX *libctx, const char *name, const char *propq) {
    EVP_PKEY_CTX *res = NULL;
    sf_set_tainted(libctx);
    sf_set_tainted(name);
    sf_set_tainted(propq);
    sf_set_errno_if(res == NULL);
    return res;
}

SSL_SESSION* d2i_SSL_SESSION(SSL_SESSION **a, const unsigned char **pp, long length) {
    SSL_SESSION *res = NULL;
    sf_set_tainted(a);
    sf_set_tainted(pp);
    sf_set_tainted(length);
    sf_set_errno_if(res == NULL);
    return res;
}

ASN1_VALUE* SMIME_read_ASN1_ex(BIO *in, int flags, BIO **out, const ASN1_ITEM *it, ASN1_VALUE **x, OSSL_LIB_CTX *libctx, const char *propq) {
    ASN1_VALUE *res = NULL;
    sf_set_tainted(in);
    sf_set_tainted(flags);
    sf_set_tainted(out);
    sf_set_tainted(it);
    sf_set_tainted(x);
    sf_set_tainted(libctx);
    sf_set_tainted(propq);
    sf_set_errno_if(res == NULL);
    return res;
}

int SSL_has_matching_session_id(const SSL *ssl, const unsigned char *id, unsigned int idlen) {
    int res = 0;
    sf_set_tainted(ssl);
    sf_set_tainted(id);
    sf_set_tainted(idlen);
    sf_set_errno_if(res == 0);
    return res;
}

PKCS7* d2i_PKCS7_fp(FILE *fp, PKCS7 **x)
{
    PKCS7 *Res = NULL;
    sf_set_trusted_sink_int(fp);
    sf_set_trusted_sink_ptr(x);
    sf_set_errno_if(Res == NULL);
    return Res;
}

void* X509_ATTRIBUTE_get0_data(X509_ATTRIBUTE *attr, int idx, int atr, void *data)
{
    void *Res = NULL;
    sf_set_trusted_sink_ptr(attr);
    sf_set_trusted_sink_int(idx);
    sf_set_trusted_sink_int(atr);
    sf_set_trusted_sink_ptr(data);
    sf_set_errno_if(Res == NULL);
    return Res;
}

EVP_PKEY* d2i_PrivateKey_ex_bio(BIO *bp, EVP_PKEY **x, OSSL_LIB_CTX *libctx, const char *propq)
{
    EVP_PKEY *Res = NULL;
    sf_set_trusted_sink_ptr(bp);
    sf_set_trusted_sink_ptr(x);
    sf_set_trusted_sink_ptr(libctx);
    sf_set_trusted_sink_ptr(propq);
    sf_set_errno_if(Res == NULL);
    return Res;
}

int SMIME_write_ASN1(BIO *data, ASN1_VALUE *val, BIO *ndata, int flags, int ctype_nid, int etype_nid, stack_st_X509_ALGOR *mdalgs, const ASN1_ITEM *it)
{
    int Res = 0;
    sf_set_trusted_sink_ptr(data);
    sf_set_trusted_sink_ptr(val);
    sf_set_trusted_sink_ptr(ndata);
    sf_set_trusted_sink_int(flags);
    sf_set_trusted_sink_int(ctype_nid);
    sf_set_trusted_sink_int(etype_nid);
    sf_set_trusted_sink_ptr(mdalgs);
    sf_set_trusted_sink_ptr(it);
    sf_set_errno_if(Res == 0);
    return Res;
}

X509_EXTENSION* X509_REVOKED_delete_ext(X509_REVOKED *x, int loc)
{
    X509_EXTENSION *Res = NULL;
    sf_set_trusted_sink_ptr(x);
    sf_set_trusted_sink_int(loc);
    sf_set_errno_if(Res == NULL);
    return Res;
}

int X509_ATTRIBUTE_set1_object(X509_ATTRIBUTE *attr, const ASN1_OBJECT *obj)
{
    int res = 0;
    sf_set_must_be_not_null(attr, SET1_OBJECT_OF_NULL);
    sf_set_must_be_not_null(obj, SET1_OBJECT_OBJ_NULL);
    sf_set_errno_if(res <= 0, SET1_OBJECT_FAIL);
    return res;
}

int OBJ_obj2txt(char *out, int out_len, const ASN1_OBJECT *obj, int no_name)
{
    int res = 0;
    sf_set_must_be_not_null(out, OBJ_OBJ2TXT_OUT_NULL);
    sf_set_must_be_not_null(obj, OBJ_OBJ2TXT_OBJ_NULL);
    sf_set_errno_if(res <= 0, OBJ_OBJ2TXT_FAIL);
    return res;
}

int SCT_set_source(SCT *sct, sct_source_t source)
{
    int res = 0;
    sf_set_must_be_not_null(sct, SCT_SET_SOURCE_SCT_NULL);
    sf_set_errno_if(res <= 0, SCT_SET_SOURCE_FAIL);
    return res;
}

int i2d_ASN1_GENERALIZEDTIME(const ASN1_GENERALIZEDTIME *time, unsigned char **pp)
{
    int res = 0;
    sf_set_must_be_not_null(time, I2D_ASN1_GENERALIZEDTIME_TIME_NULL);
    sf_set_must_be_not_null(pp, I2D_ASN1_GENERALIZEDTIME_PP_NULL);
    sf_set_errno_if(res <= 0, I2D_ASN1_GENERALIZEDTIME_FAIL);
    return res;
}

int SSL_export_keying_material_early(SSL *s, unsigned char *out, size_t olen, const char *label, size_t llen, const unsigned char *context, size_t contextlen)
{
    int res = 0;
    sf_set_must_be_not_null(s, SSL_EXPORT_KEYING_MATERIAL_EARLY_S_NULL);
    sf_set_must_be_not_null(out, SSL_EXPORT_KEYING_MATERIAL_EARLY_OUT_NULL);
    sf_set_must_be_not_null(label, SSL_EXPORT_KEYING_MATERIAL_EARLY_LABEL_NULL);
    sf_set_must_be_not_null(context, SSL_EXPORT_KEYING_MATERIAL_EARLY_CONTEXT_NULL);
    sf_set_errno_if(res <= 0, SSL_EXPORT_KEYING_MATERIAL_EARLY_FAIL);
    return res;
}

const EVP_CIPHER* EVP_sm4_ecb()
{
    const EVP_CIPHER* Res = NULL;
    sf_set_trusted_sink_int(Res);
    sf_malloc_arg(Res);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    return Res;
}

void CRYPTO_secure_free(void* ptr, const char* file, int line)
{
    sf_set_must_be_not_null(ptr, FREE_OF_NULL);
    sf_delete(ptr, MALLOC_CATEGORY);
    sf_lib_arg_type(ptr, "MallocCategory");
}

const EVP_CIPHER* EVP_aes_192_cfb128()
{
    const EVP_CIPHER* Res = NULL;
    sf_set_trusted_sink_int(Res);
    sf_malloc_arg(Res);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    return Res;
}

int SSL_CTX_add1_to_CA_list(SSL_CTX* ctx, const X509* x)
{
    int Res = 0;
    sf_set_tainted(x);
    sf_set_must_not_be_null(ctx);
    sf_set_must_not_be_null(x);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int X509_REQ_add1_attr(X509_REQ* req, X509_ATTRIBUTE* attr)
{
    int Res = 0;
    sf_set_must_not_be_null(req);
    sf_set_must_not_be_null(attr);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int i2d_PrivateKey_fp(FILE *fp, const EVP_PKEY *pkey)
{
    int Res = 0;
    sf_set_must_be_not_null(fp, FILE_PTR_NULL);
    sf_set_must_be_not_null(pkey, PKEY_PTR_NULL);
    // Implementation
    sf_set_errno_if(Res <= 0);
    return Res;
}

void ECPKPARAMETERS_free(ECPKPARAMETERS *parameters)
{
    sf_set_must_be_not_null(parameters, PARAMETERS_PTR_NULL);
    // Implementation
}

int BN_bn2mpi(const BIGNUM *bn, unsigned char *mpi)
{
    int Res = 0;
    sf_set_must_be_not_null(bn, BN_PTR_NULL);
    sf_set_must_be_not_null(mpi, MPI_PTR_NULL);
    // Implementation
    sf_set_errno_if(Res <= 0);
    return Res;
}

int EVP_PKEY_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey)
{
    int Res = 0;
    sf_set_must_be_not_null(ctx, CTX_PTR_NULL);
    sf_set_must_be_not_null(ppkey, PKEY_PTR_NULL);
    // Implementation
    sf_set_errno_if(Res <= 0);
    return Res;
}

int SSL_set_srp_server_param(SSL *s, const BIGNUM *N, const BIGNUM *g, BIGNUM *sa, BIGNUM *v, char *info)
{
    int Res = 0;
    sf_set_must_be_not_null(s, SSL_PTR_NULL);
    sf_set_must_be_not_null(N, BN_PTR_NULL);
    sf_set_must_be_not_null(g, BN_PTR_NULL);
    sf_set_must_be_not_null(sa, BN_PTR_NULL);
    sf_set_must_be_not_null(v, BN_PTR_NULL);
    sf_set_must_be_not_null(info, INFO_PTR_NULL);
    // Implementation
    sf_set_errno_if(Res <= 0);
    return Res;
}

int X509_cmp_timeframe(const X509_VERIFY_PARAM *param, const ASN1_TIME *time1, const ASN1_TIME *time2)
{
    int res = 0;
    sf_set_tainted(param);
    sf_set_tainted(time1);
    sf_set_tainted(time2);
    sf_set_errno_if(res == 0, EINVAL);
    sf_set_errno_if(res < -1 || res > 1, ERANGE);
    return res;
}

int SSL_CTX_use_RSAPrivateKey_file(SSL_CTX *ctx, const char *file, int type)
{
    int res = 0;
    sf_set_tainted(ctx);
    sf_set_tainted(file);
    sf_set_errno_if(res == 0, EINVAL);
    sf_set_errno_if(res < 0, ERANGE);
    return res;
}

const SSL_CIPHER* SSL_get_pending_cipher(const SSL *ssl)
{
    const SSL_CIPHER *res = NULL;
    sf_set_tainted(ssl);
    sf_set_alloc_possible_null(res);
    return res;
}

unsigned long ERR_peek_last_error()
{
    unsigned long res = 0;
    sf_set_possible_null(res);
    return res;
}

int EVP_MD_meth_set_cleanup(EVP_MD *md, int (*cleanup)(EVP_MD_CTX *))
{
    int res = 0;
    sf_set_tainted(md);
    sf_set_tainted(cleanup);
    sf_set_errno_if(res == 0, EINVAL);
    sf_set_errno_if(res < 0, ERANGE);
    return res;
}

void EVP_CipherFinal_ex(void *ctx, void *out, void *outl) {
    int res = 0;
    sf_set_trusted_sink_int(outl);
    sf_set_trusted_sink_ptr(out);
    sf_set_errno_if(res < 0);
    sf_set_possible_null(res);
}

void OCSP_REQUEST_new(void **req) {
    sf_set_alloc_possible_null(*req);
    sf_new(*req, MALLOC_CATEGORY);
    sf_lib_arg_type(*req, "OCSP_REQUEST");
}

void EC_KEY_set_private_key(void *key, void *priv_key) {
    int res = 0;
    sf_set_errno_if(res <= 0);
    sf_set_possible_null(res);
}

void OSSL_PARAM_get_utf8_string_ptr(void *param, void **out) {
    int res = 0;
    sf_set_trusted_sink_ptr(*out);
    sf_set_errno_if(res <= 0);
    sf_set_possible_null(res);
}

void i2d_ECPKParameters(void *group, void **pp) {
    int res = 0;
    sf_set_trusted_sink_ptr(*pp);
    sf_set_errno_if(res < 0);
    sf_set_possible_null(res);
}

X509_REQ* PEM_read_X509_REQ(FILE* a, X509_REQ** b, pem_password_cb* c, void* d) {
    X509_REQ* Res = NULL;
    sf_set_trusted_sink_int(a);
    sf_set_trusted_sink_ptr(b);
    sf_password_use(c);
    sf_set_trusted_sink_ptr(d);
    sf_set_errno_if(Res == NULL);
    sf_set_possible_null(Res);
    return Res;
}

int EVP_PKEY_copy_parameters(EVP_PKEY* a, const EVP_PKEY* b) {
    int Res = 0;
    sf_set_errno_if(Res <= 0);
    return Res;
}

int EC_KEY_precompute_mult(EC_KEY* a, BN_CTX* b) {
    int Res = 0;
    sf_set_errno_if(Res <= 0);
    return Res;
}

int SSL_CTX_use_certificate_ASN1(SSL_CTX* a, int b, const unsigned char* c) {
    int Res = 0;
    sf_set_errno_if(Res <= 0);
    return Res;
}

const UI_METHOD* UI_get_default_method() {
    const UI_METHOD* Res = NULL;
    sf_set_possible_null(Res);
    return Res;
}

X509_PUBKEY* X509_PUBKEY_new() {
    X509_PUBKEY* Res = NULL;
    Res = OPENSSL_zalloc(sizeof(X509_PUBKEY));
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    return Res;
}

int EC_POINT_set_affine_coordinates_GF2m(const EC_GROUP* group, EC_POINT* point, const BIGNUM* x, const BIGNUM* y, BN_CTX* ctx) {
    int Res = 0;
    sf_set_errno_if(Res <= 0, errno);
    return Res;
}

SXNET* SXNET_new() {
    SXNET* Res = NULL;
    Res = OPENSSL_zalloc(sizeof(SXNET));
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    return Res;
}

void OPENSSL_sk_sort(OPENSSL_STACK* st) {
    sf_set_must_not_be_null(st);
    // Sorting implementation
}

int SSL_get_early_data_status(const SSL* s) {
    int Res = 0;
    sf_set_must_not_be_null(s);
    sf_set_errno_if(Res <= 0, errno);
    return Res;
}

uint32_t SSL_CTX_get_recv_max_early_data(const SSL_CTX* ctx) {
    uint32_t Res = 0;
    Res = ctx->max_early_data;
    sf_set_possible_null(Res);
    return Res;
}

stack_st_SSL_CIPHER* SSL_CTX_get_ciphers(const SSL_CTX* ctx) {
    stack_st_SSL_CIPHER* Res = NULL;
    Res = ctx->ciphers;
    sf_set_possible_null(Res);
    return Res;
}

int X509_LOOKUP_by_issuer_serial(X509_LOOKUP* x, X509_LOOKUP_TYPE type, const X509_NAME* name, const ASN1_INTEGER* serial, X509_OBJECT* ret) {
    int Res = 0;
    Res = x->method->get_by_issuer_serial(x, type, name, serial, ret);
    sf_set_errno_if(Res <= 0);
    return Res;
}

void ASN1_STRING_free(ASN1_STRING* a) {
    if (a != NULL) {
        a->length = 0;
        sf_delete(a, ASN1_STRING_CATEGORY);
    }
}

ASN1_OBJECT* d2i_ASN1_OBJECT(ASN1_OBJECT** a, const unsigned char** pp, long length) {
    ASN1_OBJECT* Res = NULL;
    Res = ASN1_OBJECT_new();
    sf_set_alloc_possible_null(Res);
    Res->length = length;
    sf_bitcopy(Res, *pp, length);
    *pp += length;
    return Res;
}
void SSL_set_cert_cb(SSL* ssl, int (*cb);

const ASN1_PRINTABLESTRING* PROFESSION_INFO_get0_registrationNumber(const PROFESSION_INFO* info);

void SSL_CTX_set_alpn_select_cb(SSL_CTX* ctx, SSL_CTX_alpn_select_cb_func cb, void* arg);

int OSSL_PARAM_get_double(const OSSL_PARAM* param, double* result);

stack_st_X509* X509_STORE_get1_all_certs(X509_STORE* store);


IPAddressRange* d2i_IPAddressRange(IPAddressRange** a, const unsigned char** in, long len) {
    IPAddressRange* Res = NULL;
    sf_malloc_arg(Res, len);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    return Res;
}

X509_EXTENSION* X509_delete_ext(X509* x, int loc) {
    X509_EXTENSION* Res = NULL;
    sf_set_must_be_not_null(x, FREE_OF_NULL);
    sf_delete(x, MALLOC_CATEGORY);
    sf_lib_arg_type(x, "MallocCategory");
    return Res;
}

OCSP_RESPID* d2i_OCSP_RESPID(OCSP_RESPID** a, const unsigned char** in, long len) {
    OCSP_RESPID* Res = NULL;
    sf_malloc_arg(Res, len);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    return Res;
}

int OCSP_RESPID_match(OCSP_RESPID* r, X509* x) {
    int Res = 0;
    sf_set_must_be_not_null(r, FREE_OF_NULL);
    sf_set_must_be_not_null(x, FREE_OF_NULL);
    sf_no_errno_if(Res);
    return Res;
}

int EVP_PKEY_CTX_get_keygen_info(EVP_PKEY_CTX* ctx, int idx) {
    int Res = 0;
    sf_set_must_be_not_null(ctx, FREE_OF_NULL);
    sf_no_errno_if(Res);
    return Res;
}
void SSL_CTX_set0_CA_list(SSL_CTX* ctx, stack_st_X509_NAME* list);

EVP_PKEY* d2i_AutoPrivateKey(EVP_PKEY** pkey, const unsigned char** pp, long length);

X509_PUBKEY* d2i_X509_PUBKEY(X509_PUBKEY** a, const unsigned char** pp, long length);

const BIO_METHOD* BIO_s_connect();

void X509_set0_distinguishing_id(X509* x, ASN1_OCTET_STRING* id);


int EC_KEY_generate_key(EC_KEY *key) {
    int Res = 0;
    sf_set_must_be_not_null(key, GENERATE_KEY_OF_NULL);
    Res = EC_KEY_generate_key(key);
    sf_set_errno_if(Res == 0, GENERATE_KEY_FAILURE);
    return Res;
}

int SSL_SESSION_set1_master_key(SSL_SESSION *sess, const unsigned char *key, size_t key_len) {
    int Res = 0;
    sf_set_must_be_not_null(sess, SET1_MASTER_KEY_OF_NULL);
    sf_set_must_be_not_null(key, SET1_MASTER_KEY_KEY_NULL);
    sf_buf_size_limit(key, key_len, SET1_MASTER_KEY_KEY_LEN);
    Res = SSL_SESSION_set1_master_key(sess, key, key_len);
    sf_set_errno_if(Res == 0, SET1_MASTER_KEY_FAILURE);
    return Res;
}

int (EVP_MD_CTX*, const EVP_MD_CTX*)* EVP_MD_meth_get_copy(const EVP_MD *md) {
    int (EVP_MD_CTX*, const EVP_MD_CTX*)* Res = NULL;
    sf_set_must_be_not_null(md, GET_COPY_MD_NULL);
    Res = EVP_MD_meth_get_copy(md);
    sf_set_errno_if(Res == NULL, GET_COPY_MD_FAILURE);
    return Res;
}

int SSL_select_next_proto(unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, const unsigned char *client, unsigned int client_len) {
    int Res = -1;
    sf_set_must_be_not_null(out, SELECT_NEXT_PROTO_OUT_NULL);
    sf_set_must_be_not_null(outlen, SELECT_NEXT_PROTO_OUTLEN_NULL);
    sf_set_must_be_not_null(in, SELECT_NEXT_PROTO_IN_NULL);
    sf_buf_size_limit(in, inlen, SELECT_NEXT_PROTO_IN_LEN);
    sf_set_must_be_not_null(client, SELECT_NEXT_PROTO_CLIENT_NULL);
    sf_buf_size_limit(client, client_len, SELECT_NEXT_PROTO_CLIENT_LEN);
    Res = SSL_select_next_proto(out, outlen, in, inlen, client, client_len);
    sf_set_errno_if(Res == -1, SELECT_NEXT_PROTO_FAILURE);
    return Res;
}

void EC_GROUP_set_point_conversion_form(EC_GROUP *group, point_conversion_form_t form) {
    sf_set_must_be_not_null(group, SET_POINT_CONVERSION_FORM_GROUP_NULL);
    EC_GROUP_set_point_conversion_form(group, form);
}

int EVP_CIPHER_CTX_get_iv_length(const EVP_CIPHER_CTX* ctx) {
    int Res = 0;
    sf_set_must_be_not_null(ctx, EVP_CIPHER_CTX_get_iv_length_OF_NULL);
    Res = EVP_CIPHER_CTX_iv_length(ctx);
    sf_set_possible_negative(Res, EVP_CIPHER_CTX_get_iv_length_RETURN);
    return Res;
}

int OSSL_PARAM_set_uint(OSSL_PARAM* param, unsigned int value) {
    int Res = 0;
    sf_set_must_be_not_null(param, OSSL_PARAM_set_uint_OF_NULL);
    Res = OSSL_PARAM_set_uint(param, value);
    sf_set_possible_negative(Res, OSSL_PARAM_set_uint_RETURN);
    return Res;
}

RSA* d2i_RSAPrivateKey_fp(FILE* fp, RSA** rsa) {
    RSA* Res = NULL;
    sf_set_must_be_not_null(fp, d2i_RSAPrivateKey_fp_OF_NULL);
    Res = d2i_RSAPrivateKey_fp(fp, rsa);
    sf_set_possible_null(Res, d2i_RSAPrivateKey_fp_RETURN);
    return Res;
}

SCT* SCT_new_from_base64(unsigned char version, const char* log_id, ct_log_entry_type_t entry_type, uint64_t timestamp, const char* extensions, const char* signature) {
    SCT* Res = NULL;
    sf_password_use(log_id, SCT_new_from_base64_log_id);
    sf_password_use(extensions, SCT_new_from_base64_extensions);
    sf_password_use(signature, SCT_new_from_base64_signature);
    Res = SCT_new_from_base64(version, log_id, entry_type, timestamp, extensions, signature);
    sf_set_possible_null(Res, SCT_new_from_base64_RETURN);
    return Res;
}

int EVP_PKEY_CTX_set_dsa_paramgen_type(EVP_PKEY_CTX* ctx, const char* type) {
    int Res = 0;
    sf_set_must_be_not_null(ctx, EVP_PKEY_CTX_set_dsa_paramgen_type_OF_NULL);
    sf_set_must_be_not_null(type, EVP_PKEY_CTX_set_dsa_paramgen_type_type);
    Res = EVP_PKEY_CTX_set_dsa_paramgen_type(ctx, type);
    sf_set_possible_negative(Res, EVP_PKEY_CTX_set_dsa_paramgen_type_RETURN);
    return Res;
}

void EVP_PKEY_add1_attr_by_OBJ(EVP_PKEY *pkey, const ASN1_OBJECT *obj, int nid, const unsigned char *bytes, int len) {
    int res = 0;
    sf_set_trusted_sink_int(len);
    sf_set_trusted_sink_ptr(obj);
    sf_set_tainted(bytes);
    sf_set_must_not_be_null(pkey);
    sf_set_must_not_be_null(obj);
    sf_set_must_not_be_null(bytes);
    sf_set_errno_if(res == 0);
}

void X509_NAME_ENTRY_create_by_NID(X509_NAME_ENTRY **ne, int nid, int value_type, const unsigned char *value, int value_len) {
    X509_NAME_ENTRY *res = NULL;
    sf_set_trusted_sink_int(nid);
    sf_set_trusted_sink_int(value_type);
    sf_set_trusted_sink_int(value_len);
    sf_set_tainted(value);
    sf_set_must_not_be_null(ne);
    sf_set_must_not_be_null(value);
    sf_set_errno_if(res == NULL);
}

void ASN1_STRING_data(ASN1_STRING *a) {
    unsigned char *res = NULL;
    sf_set_must_not_be_null(a);
    sf_set_errno_if(res == NULL);
}

void ENGINE_get_last() {
    ENGINE *res = NULL;
    sf_set_errno_if(res == NULL);
}

void DSA_dup_DH(const DSA *dsa) {
    DH *res = NULL;
    sf_set_must_not_be_null(dsa);
    sf_set_errno_if(res == NULL);
}

void OSSL_PARAM_set_all_unmodified(OSSL_PARAM *param) {
    sf_set_tainted(param);
    sf_set_must_be_not_null(param, SET_ALL_UNMODIFIED_OF_NULL);
    sf_set_possible_null(param);
}

void CRYPTO_get_mem_functions(CRYPTO_malloc_fn *malloc_fn, CRYPTO_realloc_fn *realloc_fn, CRYPTO_free_fn *free_fn) {
    sf_set_must_be_not_null(malloc_fn, GET_MEM_FUNCTIONS_MALLOC_NULL);
    sf_set_must_be_not_null(realloc_fn, GET_MEM_FUNCTIONS_REALLOC_NULL);
    sf_set_must_be_not_null(free_fn, GET_MEM_FUNCTIONS_FREE_NULL);
}

const EVP_CIPHER* EVP_rc2_ecb() {
    const EVP_CIPHER *cipher = NULL;
    sf_set_possible_null(cipher);
    return cipher;
}

void X509_STORE_CTX_set0_verified_chain(X509_STORE_CTX *ctx, stack_st_X509 *chain) {
    sf_set_must_be_not_null(ctx, SET0_VERIFIED_CHAIN_CTX_NULL);
    sf_set_must_be_not_null(chain, SET0_VERIFIED_CHAIN_CHAIN_NULL);
}

int OPENSSL_sk_num(const OPENSSL_STACK *stack) {
    int num = 0;
    sf_set_must_be_not_null(stack, SK_NUM_STACK_NULL);
    sf_set_possible_null(num);
    return num;
}

int EVP_PBE_scrypt_ex(const char *pass, size_t passlen, const unsigned char *salt, size_t saltlen, uint64_t N, uint64_t r, uint64_t p, uint64_t maxmem, unsigned char *key, size_t keylen, OSSL_LIB_CTX *libctx, const char *propq) {
    int Res = 0;
    // Check for null or empty password
    sf_set_must_be_not_null(pass, PASSWORD_OF_NULL);
    // Check for null salt
    sf_set_must_be_not_null(salt, SALT_OF_NULL);
    // Check for null key
    sf_set_must_be_not_null(key, KEY_OF_NULL);
    // Check for null libctx
    sf_set_must_be_not_null(libctx, LIBCTX_OF_NULL);
    // Check for null propq
    sf_set_must_be_not_null(propq, PROPQ_OF_NULL);
    // Check for password and salt overlap
    sf_buf_overlap(pass, salt);
    // Check for key and salt overlap
    sf_buf_overlap(key, salt);
    // Check for key and password overlap
    sf_buf_overlap(key, pass);
    // Mark password as used
    sf_password_use(pass);
    // Mark salt as used
    sf_password_use(salt);
    // Mark key as overwritten
    sf_overwrite(key);
    // Return result
    return Res;
}

const EVP_CIPHER* EVP_chacha20_poly1305() {
    const EVP_CIPHER *Res = NULL;
    // Return result
    return Res;
}

stack_st_X509_ATTRIBUTE* X509at_add1_attr_by_txt(stack_st_X509_ATTRIBUTE **sk, const char *attrname, int attrnum, const unsigned char *data, int len) {
    stack_st_X509_ATTRIBUTE *Res = NULL;
    // Check for null sk
    sf_set_must_be_not_null(sk, SK_OF_NULL);
    // Check for null attrname
    sf_set_must_be_not_null(attrname, ATTRNAME_OF_NULL);
    // Check for null data
    sf_set_must_be_not_null(data, DATA_OF_NULL);
    // Return result
    return Res;
}

void EVP_PKEY_asn1_set_free(EVP_PKEY_ASN1_METHOD *ameth, void (*free_func)(EVP_PKEY*)) {
    // Check for null ameth
    sf_set_must_be_not_null(ameth, AM_OF_NULL);
    // Check for null free_func
    sf_set_must_be_not_null(free_func, FREE_FUNC_OF_NULL);
}

int X509_STORE_load_locations_ex(X509_STORE *ctx, const char *file, const char *dir, OSSL_LIB_CTX *libctx, const char *propq) {
    int Res = 0;
    // Check for null ctx
    sf_set_must_be_not_null(ctx, CTX_OF_NULL);
    // Check for null libctx
    sf_set_must_be_not_null(libctx, LIBCTX_OF_NULL);
    // Check for null propq
    sf_set_must_be_not_null(propq, PROPQ_OF_NULL);
    // Check for TOCTTOU race condition
    sf_tocttou_check(file);
    sf_tocttou_check(dir);
    // Return result
    return Res;
}

int UI_add_input_boolean(UI* ui, const char* prompt, const char* boolean_description, const char* ok_button_description, const char* cancel_button_description, int flags, char* result) {
    int res = 0;
    sf_set_tainted(prompt);
    sf_set_tainted(boolean_description);
    sf_set_tainted(ok_button_description);
    sf_set_tainted(cancel_button_description);
    sf_set_tainted(result);
    sf_set_errno_if(res == -1);
    sf_no_errno_if(res == 0);
    return res;
}

int ASN1_TIME_print(BIO* bio, const ASN1_TIME* time) {
    int res = 0;
    sf_set_errno_if(res == -1);
    sf_no_errno_if(res == 1);
    return res;
}

uint64_t CT_POLICY_EVAL_CTX_get_time(const CT_POLICY_EVAL_CTX* ctx) {
    uint64_t res = 0;
    return res;
}

int i2d_ASIdentifiers(const ASIdentifiers* a, unsigned char** pp) {
    int res = 0;
    sf_set_errno_if(res == -1);
    sf_no_errno_if(res > 0);
    return res;
}

int PKCS7_decrypt(PKCS7* p7, EVP_PKEY* pkey, X509* cert, BIO* data, int flags) {
    int res = 0;
    sf_set_errno_if(res == -1);
    sf_no_errno_if(res == 1);
    return res;
}

int PEM_write_DHparams(FILE *fp, const DH *dh)
{
    int Res = 0;
    sf_set_must_be_not_null(fp, FILE_PTR_NULL);
    sf_set_must_be_not_null(dh, DH_PTR_NULL);
    Res = PEM_write_DHparams(fp, dh);
    sf_set_errno_if(Res <= 0, ERRNO_ERROR);
    sf_set_possible_null(Res, PEM_WRITE_DHPARAMS_FAIL);
    return Res;
}

int SSL_CTX_dane_enable(SSL_CTX *ctx)
{
    int Res = 0;
    sf_set_must_be_not_null(ctx, SSL_CTX_PTR_NULL);
    Res = SSL_CTX_dane_enable(ctx);
    sf_set_errno_if(Res <= 0, ERRNO_ERROR);
    sf_set_possible_null(Res, SSL_CTX_DANE_ENABLE_FAIL);
    return Res;
}

int EC_POINT_add(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a, const EC_POINT *b, BN_CTX *ctx)
{
    int Res = 0;
    sf_set_must_be_not_null(group, EC_GROUP_PTR_NULL);
    sf_set_must_be_not_null(r, EC_POINT_PTR_NULL);
    sf_set_must_be_not_null(a, EC_POINT_PTR_NULL);
    sf_set_must_be_not_null(b, EC_POINT_PTR_NULL);
    Res = EC_POINT_add(group, r, a, b, ctx);
    sf_set_errno_if(Res <= 0, ERRNO_ERROR);
    sf_set_possible_null(Res, EC_POINT_ADD_FAIL);
    return Res;
}

int BN_RECP_CTX_set(BN_RECP_CTX *recp, const BIGNUM *m, BN_CTX *ctx)
{
    int Res = 0;
    sf_set_must_be_not_null(recp, BN_RECP_CTX_PTR_NULL);
    sf_set_must_be_not_null(m, BIGNUM_PTR_NULL);
    Res = BN_RECP_CTX_set(recp, m, ctx);
    sf_set_errno_if(Res <= 0, ERRNO_ERROR);
    sf_set_possible_null(Res, BN_RECP_CTX_SET_FAIL);
    return Res;
}

const BIGNUM* EC_GROUP_get0_field(const EC_GROUP *group)
{
    const BIGNUM *Res = NULL;
    sf_set_must_be_not_null(group, EC_GROUP_PTR_NULL);
    Res = EC_GROUP_get0_field(group);
    sf_set_possible_null(Res, EC_GROUP_GET0_FIELD_FAIL);
    return Res;
}

int EVP_PKEY_CTX_set_dh_paramgen_subprime_len(EVP_PKEY_CTX *ctx, int len) {
    int Res = 0;
    sf_set_must_be_not_null(ctx, SET_DH_PARAMGEN_SUBPRIME_LEN_OF_NULL);
    sf_set_trusted_sink_int(len, SET_DH_PARAMGEN_SUBPRIME_LEN_SINK);
    Res = EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_PARAMGEN, EVP_PKEY_CTRL_DH_SUBPRIME_LEN, len, NULL);
    sf_set_errno_if(Res <= 0, SET_DH_PARAMGEN_SUBPRIME_LEN_ERROR);
    return Res;
}

const EVP_CIPHER* EVP_aria_256_ccm() {
    const EVP_CIPHER *Res = NULL;
    Res = EVP_get_cipherbyname("aria-256-ccm");
    sf_set_possible_null(Res, EVP_ARIA_256_CCM_NULL);
    return Res;
}

int SSL_dane_enable(SSL *s, const char *path) {
    int Res = 0;
    sf_set_must_be_not_null(s, SSL_DANE_ENABLE_OF_NULL);
    sf_set_must_be_not_null(path, SSL_DANE_ENABLE_PATH_OF_NULL);
    Res = SSL_CTX_dane_enable(s->ctx, path);
    sf_set_errno_if(Res <= 0, SSL_DANE_ENABLE_ERROR);
    return Res;
}

void SSL_CTX_set_default_passwd_cb(SSL_CTX *ctx, pem_password_cb *cb) {
    sf_set_must_be_not_null(ctx, SET_DEFAULT_PASSWD_CB_OF_NULL);
    ctx->default_passwd_callback = cb;
}

int X509_STORE_load_store(X509_STORE *store, const char *uri) {
    int Res = 0;
    sf_set_must_be_not_null(store, X509_STORE_LOAD_STORE_OF_NULL);
    sf_set_must_be_not_null(uri, X509_STORE_LOAD_STORE_URI_OF_NULL);
    Res = X509_LOOKUP_ctrl(X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir()), X509_L_LOAD, uri, X509_FILETYPE_PEM, NULL);
    sf_set_errno_if(Res <= 0, X509_STORE_LOAD_STORE_ERROR);
    return Res;
}

int SSL_config(SSL* ssl, const char* str) {
    int res = 0;
    sf_set_trusted_sink_int(str);
    sf_set_tainted(str);
    sf_set_errno_if(res == 0);
    return res;
}

int EVP_VerifyFinal(EVP_MD_CTX* ctx, const unsigned char* sig, unsigned int siglen, EVP_PKEY* pkey) {
    int res = 0;
    sf_set_tainted(sig);
    sf_set_errno_if(res <= 0);
    return res;
}

int OCSP_RESPID_match_ex(OCSP_RESPID* id, X509* cert, OSSL_LIB_CTX* libctx, const char* propq) {
    int res = 0;
    sf_set_trusted_sink_int(propq);
    sf_set_tainted(propq);
    sf_set_errno_if(res == 0);
    return res;
}

int SSL_SESSION_up_ref(SSL_SESSION* sess) {
    int res = 0;
    sf_set_errno_if(res == 0);
    return res;
}

char* ERR_error_string(unsigned long e, char* buf) {
    char* res = NULL;
    sf_set_errno_if(res == NULL);
    return res;
}

int EVP_CIPHER_meth_set_set_asn1_params(EVP_CIPHER *cipher, int (*set_asn1_parameters)(EVP_CIPHER_CTX*, ASN1_TYPE*)) {
    int res = 0;
    sf_set_trusted_sink_int(set_asn1_parameters);
    sf_set_trusted_sink_ptr(cipher);
    sf_set_tainted(cipher);
    sf_set_tainted(set_asn1_parameters);
    return res;
}

int RAND_load_file(const char *file, long max_bytes) {
    int res = 0;
    sf_set_must_not_be_release(file);
    sf_tocttou_check(file);
    sf_set_buf_size_limit(max_bytes);
    return res;
}

int X509_REVOKED_add_ext(X509_REVOKED *rev, X509_EXTENSION *ex, int loc) {
    int res = 0;
    sf_set_trusted_sink_ptr(rev);
    sf_set_trusted_sink_ptr(ex);
    sf_set_tainted(rev);
    sf_set_tainted(ex);
    return res;
}

int PKCS5_PBE_keyivgen_ex(EVP_CIPHER_CTX *ctx, const char *pass, int passlen, ASN1_TYPE *param, const EVP_CIPHER *c, const EVP_MD *md, int en_de, OSSL_LIB_CTX *libctx, const char *propq) {
    int res = 0;
    sf_password_use(pass);
    sf_set_trusted_sink_ptr(ctx);
    sf_set_trusted_sink_ptr(param);
    sf_set_tainted(ctx);
    sf_set_tainted(param);
    return res;
}

const char* OBJ_nid2ln(int nid) {
    const char *res = NULL;
    sf_set_must_be_not_null(res, FREE_OF_NULL);
    sf_set_possible_null(res);
    return res;
}

void OPENSSL_sk_free(OPENSSL_STACK *stack)
{
    if (stack != NULL)
    {
        sf_delete(stack, PAGES_MEMORY_CATEGORY);
    }
    sf_set_possible_null(stack);
}

int DSA_generate_key(DSA *dsa)
{
    int res = 0;
    sf_set_errno_if(res <= 0, EINVAL);
    sf_no_errno_if(res > 0);
    return res;
}

void NAMING_AUTHORITY_set0_authorityText(NAMING_AUTHORITY *a, ASN1_STRING *str)
{
    if (a != NULL && str != NULL)
    {
        sf_bitcopy(a->authorityText, str);
    }
    sf_set_must_be_not_null(a, FREE_OF_NULL);
    sf_set_must_be_not_null(str, FREE_OF_NULL);
}

int i2d_EC_PUBKEY(const EC_KEY *key, unsigned char **pp)
{
    int res = 0;
    sf_set_errno_if(res <= 0, EINVAL);
    sf_no_errno_if(res > 0);
    sf_set_must_be_not_null(key, FREE_OF_NULL);
    sf_set_must_be_not_null(pp, FREE_OF_NULL);
    return res;
}

void SSL_set_default_read_buffer_len(SSL *s, size_t len)
{
    sf_set_buf_size(s->default_read_buf_len, len);
    sf_set_must_be_not_null(s, FREE_OF_NULL);
}

const RSA_METHOD* RSA_get_default_method() {
    const RSA_METHOD* Res = NULL;
    Res = RSA_get_default_method();
    sf_set_possible_null(Res);
    return Res;
}

OSSL_LIB_CTX* OSSL_LIB_CTX_new_child(const OSSL_CORE_HANDLE* handle, const OSSL_DISPATCH* dispatch) {
    OSSL_LIB_CTX* Res = NULL;
    Res = OSSL_LIB_CTX_new_child(handle, dispatch);
    sf_set_possible_null(Res);
    return Res;
}

int OCSP_basic_sign(OCSP_BASICRESP* bs, X509* x, EVP_PKEY* pkey, const EVP_MD* md, stack_st_X509* certs, unsigned long flags) {
    int Res = 0;
    Res = OCSP_basic_sign(bs, x, pkey, md, certs, flags);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int X509_CRL_get0_by_cert(X509_CRL* crl, X509_REVOKED** ret, X509* x) {
    int Res = 0;
    Res = X509_CRL_get0_by_cert(crl, ret, x);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int EVP_EncryptFinal(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl) {
    int Res = 0;
    Res = EVP_EncryptFinal(ctx, out, outl);
    sf_set_errno_if(Res <= 0);
    return Res;
}

POLICYQUALINFO* d2i_POLICYQUALINFO(POLICYQUALINFO** a, const unsigned char** pp, long length) {
    POLICYQUALINFO* Res = NULL;
    sf_set_trusted_sink_int(length);
    sf_malloc_arg(Res, length);
    sf_overwrite(Res);
    sf_new(Res, POLICYQUALINFO_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    return Res;
}

void BIO_vfree(BIO* a) {
    sf_set_must_be_not_null(a, FREE_OF_NULL);
    sf_delete(a, BIO_MEMORY_CATEGORY);
    sf_lib_arg_type(a, "BIO");
}

int i2d_RSA_PUBKEY_bio(BIO* a, const RSA* rsa) {
    sf_set_must_be_not_null(a, BIO_NOT_NULL);
    sf_set_must_be_not_null(rsa, RSA_NOT_NULL);
    return 0;
}

stack_st_SRTP_PROTECTION_PROFILE* SSL_get_srtp_profiles(SSL* s) {
    stack_st_SRTP_PROTECTION_PROFILE* Res = NULL;
    sf_set_must_be_not_null(s, SSL_NOT_NULL);
    sf_malloc_arg(Res, sizeof(stack_st_SRTP_PROTECTION_PROFILE));
    sf_overwrite(Res);
    sf_new(Res, SRTP_PROTECTION_PROFILE_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    return Res;
}

void EVP_PKEY_meth_get_cleanup(const EVP_PKEY_METHOD* meth, void (EVP_PKEY_CTX*)** cleanup) {
    sf_set_must_be_not_null(meth, EVP_PKEY_METHOD_NOT_NULL);
    sf_set_must_be_not_null(cleanup, CLEANUP_NOT_NULL);
}

const OSSL_PARAM* EVP_RAND_gettable_params(const EVP_RAND* rand) {
    const OSSL_PARAM* Res = NULL;
    Res = EVP_RAND_gettable_params(rand);
    sf_set_possible_null(Res);
    return Res;
}

CONF_METHOD* NCONF_default() {
    CONF_METHOD* Res = NULL;
    Res = NCONF_default();
    sf_set_possible_null(Res);
    return Res;
}

int X509_LOOKUP_init(X509_LOOKUP* ctx) {
    int Res = 0;
    Res = X509_LOOKUP_init(ctx);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int BN_bn2lebinpad(const BIGNUM* a, unsigned char* to, int tolen) {
    int Res = 0;
    Res = BN_bn2lebinpad(a, to, tolen);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int SSL_set_session_id_context(SSL* s, const unsigned char* sid_ctx, unsigned int sid_ctx_len) {
    int Res = 0;
    Res = SSL_set_session_id_context(s, sid_ctx, sid_ctx_len);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int X509V3_add1_i2d(stack_st_X509_EXTENSION** sk, int ext_nid, void* ext, int crit, unsigned long flags)
{
    int Res = 0;
    sf_set_trusted_sink_int(ext_nid);
    sf_set_trusted_sink_int(crit);
    sf_set_trusted_sink_int(flags);
    Res = X509V3_add1_i2d(sk, ext_nid, ext, crit, flags);
    sf_set_errno_if(Res <= 0);
    return Res;
}

const char* EVP_ASYM_CIPHER_get0_name(const EVP_ASYM_CIPHER* cipher)
{
    const char* Res = NULL;
    Res = EVP_ASYM_CIPHER_get0_name(cipher);
    sf_set_possible_null(Res);
    return Res;
}

X509_PUBKEY* X509_REQ_get_X509_PUBKEY(X509_REQ* req)
{
    X509_PUBKEY* Res = NULL;
    Res = X509_REQ_get_X509_PUBKEY(req);
    sf_set_possible_null(Res);
    return Res;
}

void X509_STORE_CTX_free(X509_STORE_CTX* ctx)
{
    sf_set_must_be_not_null(ctx, FREE_OF_NULL);
    X509_STORE_CTX_free(ctx);
}

const EVP_CIPHER* EVP_des_ede_cbc()
{
    const EVP_CIPHER* Res = NULL;
    Res = EVP_des_ede_cbc();
    sf_set_possible_null(Res);
    return Res;
}
int SSL_get_peer_signature_type_nid(const SSL* ssl, int* nid);

int ASN1_STRING_set(ASN1_STRING* str, const void* data, int len);

ENGINE_CTRL_FUNC_PTR ENGINE_get_ctrl_function(const ENGINE* e);

EVP_PKEY_METHOD* EVP_PKEY_meth_new(int id, int flags);

int PEM_write(FILE* fp, const char* name, const char* header, const unsigned char* data, long len);

int SSL_SESSION_set1_id_context(SSL_SESSION* s, const unsigned char* sid_ctx, unsigned int sid_ctx_len);

const EVP_MD* EVP_get_digestbyname(const char* name);

X509_ATTRIBUTE* X509_ATTRIBUTE_create_by_txt(X509_ATTRIBUTE** a, const char* attrname, int type, const unsigned char* bytes, int len);

const BIGNUM* BN_get0_nist_prime_192();

int RSA_generate_key_ex(RSA* rsa, int bits, BIGNUM* e_value, BN_GENCB* cb);

int SSL_SESSION_print_fp(FILE*, const SSL_SESSION*);

int i2d_OCSP_CERTSTATUS(const OCSP_CERTSTATUS*, unsigned char**);

const OSSL_PARAM* EVP_KEM_settable_ctx_params(const EVP_KEM*);

int PEM_read(FILE*,  char**,  char**, unsigned char**, long*);

const OSSL_PARAM* EVP_MAC_gettable_ctx_params(const EVP_MAC*);

void X509_STORE_CTX_set_error(X509_STORE_CTX* ctx, int val);

int i2d_RSAPublicKey(const RSA* rsa, unsigned char** out);

int OCSP_resp_find(OCSP_BASICRESP* bs, OCSP_CERTID* id, int idx);

int (EVP_MD_CTX*);

int SMIME_write_ASN1_ex(BIO* bio, ASN1_VALUE* val, BIO* data, int flags, int ctype_nid, int etype_nid, stack_st_X509_ALGOR* md_algs, const ASN1_ITEM* it, OSSL_LIB_CTX* ctx, const char* propq);


int PEM_read_bio_ex(BIO* a, char** b, char** c, unsigned char** d, long* e, unsigned int f)
{
    int res = 0;
    // Check for null and set trusted sink pointer
    sf_set_trusted_sink_ptr(a);
    // Check for null and set trusted sink int
    sf_set_trusted_sink_int(f);
    // Check for null and set possible null
    sf_set_possible_null(b);
    sf_set_possible_null(c);
    sf_set_possible_null(d);
    sf_set_possible_null(e);
    // Check for null and set must not be null
    sf_set_must_be_not_null(a, PEM_READ_BIO_EX_OF_NULL);
    // Check for null and set possible negative
    sf_set_possible_negative(res);
    // Check for null and set errno if
    sf_set_errno_if(res == 0, PEM_READ_BIO_EX_ERRNO);
    return res;
}

const ASN1_TIME* X509_CRL_get0_lastUpdate(const X509_CRL* a)
{
    const ASN1_TIME* res = NULL;
    // Check for null and set must not be null
    sf_set_must_be_not_null(a, X509_CRL_GET0_LASTUPDATE_OF_NULL);
    // Set the result as not acquired if it is equal to null
    sf_not_acquire_if_eq(res);
    return res;
}

int OSSL_PARAM_set_uint32(OSSL_PARAM* a, uint32_t b)
{
    int res = 0;
    // Check for null and set must not be null
    sf_set_must_be_not_null(a, OSSL_PARAM_SET_UINT32_OF_NULL);
    // Check for null and set possible null
    sf_set_possible_null(a);
    // Check for null and set errno if
    sf_set_errno_if(res == 0, OSSL_PARAM_SET_UINT32_ERRNO);
    return res;
}

const OSSL_PARAM* EVP_KEYMGMT_gen_settable_params(const EVP_KEYMGMT* a)
{
    const OSSL_PARAM* res = NULL;
    // Check for null and set must not be null
    sf_set_must_be_not_null(a, EVP_KEYMGMT_GEN_SETTABLE_PARAMS_OF_NULL);
    // Set the result as not acquired if it is equal to null
    sf_not_acquire_if_eq(res);
    return res;
}

void OCSP_RESPDATA_free(OCSP_RESPDATA* a)
{
    // Check for null and set must not be null
    sf_set_must_be_not_null(a, OCSP_RESPDATA_FREE_OF_NULL);
    // Mark the memory as freed
    sf_delete(a, OCSP_RESPDATA_FREE_MEMORY_CATEGORY);
}

X509_CRL* d2i_X509_CRL_fp(FILE *fp, X509_CRL **crl)
{
    X509_CRL *Res = NULL;
    sf_set_must_be_not_null(fp, FP_OF_NULL);
    sf_set_must_be_not_null(crl, CRL_OF_NULL);
    sf_set_tainted(crl, TAINTED_CRL);
    sf_set_errno_if(Res == NULL, ENOMEM);
    sf_set_possible_null(Res);
    return Res;
}

int SSL_CTX_set_async_callback_arg(SSL_CTX *ctx, void *arg)
{
    int Res = 0;
    sf_set_must_be_not_null(ctx, CTX_OF_NULL);
    sf_set_tainted(arg, TAINTED_ARG);
    sf_set_errno_if(Res == 0, EINVAL);
    return Res;
}

RSA* PEM_read_bio_RSAPrivateKey(BIO *bp, RSA **x, pem_password_cb *cb, void *u)
{
    RSA *Res = NULL;
    sf_set_must_be_not_null(bp, BIO_OF_NULL);
    sf_set_must_be_not_null(x, RSA_OF_NULL);
    sf_password_use(cb, u);
    sf_set_errno_if(Res == NULL, ENOMEM);
    sf_set_possible_null(Res);
    return Res;
}

void EVP_EncodeInit(EVP_ENCODE_CTX *ctx)
{
    sf_set_must_be_not_null(ctx, CTX_OF_NULL);
    sf_bitinit(ctx);
}

int SSL_CTX_set_purpose(SSL_CTX *ctx, int purpose)
{
    int Res = 0;
    sf_set_must_be_not_null(ctx, CTX_OF_NULL);
    sf_set_errno_if(Res == 0, EINVAL);
    return Res;
}

int PEM_write_bio_ECPrivateKey(BIO* bio, const EC_KEY* key, const EVP_CIPHER* cipher, const unsigned char* passwd, int len, pem_password_cb* cb, void* u) {
    int res = 0;
    sf_set_tainted(passwd);
    sf_password_use(passwd);
    sf_set_trusted_sink_ptr(bio);
    sf_set_trusted_sink_ptr(key);
    sf_set_trusted_sink_ptr(cipher);
    sf_set_trusted_sink_ptr(cb);
    sf_set_trusted_sink_ptr(u);
    return res;
}

int BIO_set_ex_data(BIO* bio, int idx, void* data) {
    int res = 0;
    sf_set_trusted_sink_ptr(bio);
    sf_set_trusted_sink_ptr(data);
    return res;
}

PKCS7_SIGNER_INFO* d2i_PKCS7_SIGNER_INFO(PKCS7_SIGNER_INFO** si, const unsigned char** in, long len) {
    PKCS7_SIGNER_INFO* res = NULL;
    sf_set_trusted_sink_ptr(si);
    sf_set_trusted_sink_ptr(in);
    sf_set_buf_size_limit(in, len);
    return res;
}

int BN_nnmod(BIGNUM* r, const BIGNUM* a, const BIGNUM* m, BN_CTX* ctx) {
    int res = 0;
    sf_set_trusted_sink_ptr(r);
    sf_set_trusted_sink_ptr(a);
    sf_set_trusted_sink_ptr(m);
    sf_set_trusted_sink_ptr(ctx);
    return res;
}

int EVP_EncryptInit(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type, const unsigned char* key, const unsigned char* iv) {
    int res = 0;
    sf_set_trusted_sink_ptr(ctx);
    sf_set_trusted_sink_ptr(type);
    sf_set_tainted(key);
    sf_set_tainted(iv);
    return res;
}
int RSA_set0_factors(RSA* r, BIGNUM* p, BIGNUM* q);

char* i2s_ASN1_OCTET_STRING(X509V3_EXT_METHOD* m, const ASN1_OCTET_STRING* a);

int ASYNC_WAIT_CTX_set_status(ASYNC_WAIT_CTX* ctx, int status);

int EVP_PKEY_CTX_set_rsa_oaep_md(EVP_PKEY_CTX* ctx, const EVP_MD* md);

int EVP_KEYEXCH_is_a(const EVP_KEYEXCH* exch, const char* name);


void AUTHORITY_KEYID_free(AUTHORITY_KEYID *a) {
    if (a != NULL) {
        OPENSSL_free(a);
    }
}

const EVP_CIPHER* EVP_des_ede_cfb64() {
    const EVP_CIPHER *cipher = EVP_des_ede_cfb();
    if (cipher != NULL) {
        EVP_CIPHER_set_key_length(cipher, 24);
    }
    return cipher;
}

int OPENSSL_strcasecmp(const char *str1, const char *str2) {
    int res = 0;
    sf_strcasecmp(res, str1, str2);
    return res;
}

int EVP_MAC_CTX_set_params(EVP_MAC_CTX *ctx, const OSSL_PARAM params[]) {
    int res = EVP_MAC_CTX_set_params(ctx, params);
    sf_set_errno_if(res <= 0);
    return res;
}

int EVP_PKEY_add1_attr_by_txt(EVP_PKEY *pkey, const char *attrname, int attrnum, const unsigned char *data, int len) {
    int res = EVP_PKEY_add1_attr_by_txt(pkey, attrname, attrnum, data, len);
    sf_set_errno_if(res <= 0);
    return res;
}

// Specification for int PEM_write_X509(FILE*, const X509*)
int PEM_write_X509(FILE *fp, const X509 *x) {
    int res = 0;
    // Check for null values
    sf_set_must_be_not_null(fp, FILE_PTR_NULL);
    sf_set_must_be_not_null(x, X509_PTR_NULL);
    // Perform PEM_write_X509 operation
    // ...
    // Set the return value
    sf_set_errno_if(res == 0);
    return res;
}

// Specification for const EVP_CIPHER* EVP_aria_256_cfb8()
const EVP_CIPHER* EVP_aria_256_cfb8() {
    const EVP_CIPHER *res = NULL;
    // Perform EVP_aria_256_cfb8 operation
    // ...
    // Set the return value
    sf_set_errno_if(res == NULL);
    return res;
}

// Specification for int X509_REQ_add1_attr_by_txt(X509_REQ*, const char*, int, const unsigned char*, int)
int X509_REQ_add1_attr_by_txt(X509_REQ *x, const char *attrname, int attrnum, const unsigned char *data, int len) {
    int res = 0;
    // Check for null values
    sf_set_must_be_not_null(x, X509_REQ_PTR_NULL);
    sf_set_must_be_not_null(attrname, ATTRNAME_PTR_NULL);
    sf_set_must_be_not_null(data, DATA_PTR_NULL);
    // Perform X509_REQ_add1_attr_by_txt operation
    // ...
    // Set the return value
    sf_set_errno_if(res == 0);
    return res;
}

// Specification for int i2d_ACCESS_DESCRIPTION(const ACCESS_DESCRIPTION*, unsigned char**)
int i2d_ACCESS_DESCRIPTION(const ACCESS_DESCRIPTION *a, unsigned char **pp) {
    int res = 0;
    // Check for null values
    sf_set_must_be_not_null(a, ACCESS_DESCRIPTION_PTR_NULL);
    sf_set_must_be_not_null(pp, PP_PTR_NULL);
    // Perform i2d_ACCESS_DESCRIPTION operation
    // ...
    // Set the return value
    sf_set_errno_if(res == 0);
    return res;
}

// Specification for unsigned int EVP_RAND_get_strength(EVP_RAND_CTX*)
unsigned int EVP_RAND_get_strength(EVP_RAND_CTX *ctx) {
    unsigned int res = 0;
    // Check for null values
    sf_set_must_be_not_null(ctx, EVP_RAND_CTX_PTR_NULL);
    // Perform EVP_RAND_get_strength operation
    // ...
    // Set the return value
    sf_set_errno_if(res == 0);
    return res;
}

void ERR_add_error_mem_bio(const char *file, BIO *bio) {
    sf_tocttou_check(file);
    sf_lib_arg_type(bio, "BIO");
    ERR_add_error_mem_bio(file, bio);
}

OCSP_RESPBYTES* d2i_OCSP_RESPBYTES(OCSP_RESPBYTES **a, const unsigned char **in, long len) {
    sf_set_buf_size(*in, len);
    sf_lib_arg_type(*a, "OCSP_RESPBYTES");
    sf_lib_arg_type(*in, "unsigned char");
    OCSP_RESPBYTES *res = d2i_OCSP_RESPBYTES(a, in, len);
    sf_lib_arg_type(res, "OCSP_RESPBYTES");
    return res;
}

int OPENSSL_init_ssl(uint64_t opts, const OPENSSL_INIT_SETTINGS *settings) {
    sf_set_trusted_sink_int(opts);
    sf_lib_arg_type(settings, "OPENSSL_INIT_SETTINGS");
    int res = OPENSSL_init_ssl(opts, settings);
    sf_set_errno_if(res == 0);
    return res;
}

ASN1_OCTET_STRING* X509_EXTENSION_get_data(X509_EXTENSION *ex) {
    sf_lib_arg_type(ex, "X509_EXTENSION");
    ASN1_OCTET_STRING *res = X509_EXTENSION_get_data(ex);
    sf_lib_arg_type(res, "ASN1_OCTET_STRING");
    return res;
}

int ASYNC_WAIT_CTX_get_callback(ASYNC_WAIT_CTX *ctx, ASYNC_callback_fn *callback, void **arg) {
    sf_lib_arg_type(ctx, "ASYNC_WAIT_CTX");
    sf_lib_arg_type(callback, "ASYNC_callback_fn");
    int res = ASYNC_WAIT_CTX_get_callback(ctx, callback, arg);
    sf_set_possible_null(res);
    return res;
}

int SSL_CONF_cmd_argv(SSL_CONF_CTX* cctx, int* argc, char*** argv)
{
    int Res = 0;
    sf_set_trusted_sink_int(argc);
    sf_set_trusted_sink_ptr(argv);
    sf_set_tainted(*argv);
    sf_set_possible_null(Res);
    return Res;
}

int PEM_write_bio_PKCS8PrivateKey(BIO* bp, const EVP_PKEY* x, const EVP_CIPHER* enc, const char* kstr, int klen, pem_password_cb* cb, void* u)
{
    int Res = 0;
    sf_password_use(kstr);
    sf_set_errno_if(Res <= 0);
    sf_set_possible_null(Res);
    return Res;
}

int DSA_sign(int type, const unsigned char* dgst, int dlen, unsigned char* sig, unsigned int* siglen, DSA* dsa)
{
    int Res = 0;
    sf_set_errno_if(Res <= 0);
    sf_set_possible_null(Res);
    return Res;
}

void RSA_get0_factors(const RSA* r, const BIGNUM** f, const BIGNUM** g)
{
    sf_set_tainted(r);
    sf_set_tainted(*f);
    sf_set_tainted(*g);
}

int RSA_padding_check_PKCS1_type_1(unsigned char* to, int tlen, const unsigned char* f, int fl, int rsa_len)
{
    int Res = 0;
    sf_set_errno_if(Res <= 0);
    sf_set_possible_null(Res);
    return Res;
}
long SSL_SESSION_get_timeout(const SSL_SESSION*);

int OCSP_single_get0_status(OCSP_SINGLERESP*, int*, ASN1_GENERALIZEDTIME**, ASN1_GENERALIZEDTIME**, ASN1_GENERALIZEDTIME**);

const stack_st_X509_EXTENSION* X509_get0_extensions(const X509*);

void CRYPTO_clear_free(void*, size_t, const char*, int);

X509_CERT_AUX* d2i_X509_CERT_AUX(X509_CERT_AUX**, const unsigned char**, long);


IPAddressRange* IPAddressRange_new() {
    IPAddressRange* Res = NULL;
    Res = sf_malloc_arg(sizeof(IPAddressRange), PAGES_MEMORY_CATEGORY);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    return Res;
}

int i2d_SCT_LIST(const stack_st_SCT* a, unsigned char** pp) {
    int Res = 0;
    sf_set_trusted_sink_int(a);
    sf_set_trusted_sink_ptr(pp);
    Res = i2d_SCT_LIST(a, pp);
    sf_overwrite(Res);
    return Res;
}

int EVP_MD_names_do_all(const EVP_MD* type, void (const char* name, void* arg)(), void* arg) {
    int Res = 0;
    sf_set_trusted_sink_ptr(type);
    sf_set_trusted_sink_ptr(arg);
    Res = EVP_MD_names_do_all(type, name, arg);
    sf_overwrite(Res);
    return Res;
}

X509_CRL* PEM_read_bio_X509_CRL(BIO* bp, X509_CRL** x, pem_password_cb* cb, void* u) {
    X509_CRL* Res = NULL;
    sf_set_trusted_sink_ptr(bp);
    sf_set_trusted_sink_ptr(x);
    sf_set_trusted_sink_ptr(cb);
    sf_set_trusted_sink_ptr(u);
    Res = PEM_read_bio_X509_CRL(bp, x, cb, u);
    sf_new(Res, MALLOC_CATEGORY);
    sf_overwrite(Res);
    return Res;
}

const EVP_CIPHER* EVP_rc4_hmac_md5() {
    const EVP_CIPHER* Res = NULL;
    Res = EVP_rc4_hmac_md5();
    sf_overwrite(Res);
    return Res;
}
int PKCS7_print_ctx(BIO*, const PKCS7*, int, const ASN1_PCTX*);

DH* DH_get_1024_160();

const EVP_CIPHER* EVP_aes_256_ccm();

int BIO_vprintf(BIO*, const char*, va_list);

int OSSL_HTTP_REQ_CTX_set_request_line(OSSL_HTTP_REQ_CTX*, int, const char*, const char*, const char*);


ASN1_INTEGER* BN_to_ASN1_INTEGER(const BIGNUM* bn, ASN1_INTEGER* ai) {
    ASN1_INTEGER* Res = NULL;
    sf_set_trusted_sink_int(bn);
    sf_set_trusted_sink_int(ai);
    Res = ASN1_INTEGER_new();
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    if (Res != NULL) {
        sf_bitcopy(Res, bn);
    }
    return Res;
}

void EVP_PKEY_asn1_set_item(EVP_PKEY_ASN1_METHOD* ameth, int (*pub_decode)(), int (*pub_encode)()) {
    sf_set_trusted_sink_int(ameth);
    sf_set_trusted_sink_int(pub_decode);
    sf_set_trusted_sink_int(pub_encode);
    ameth->pub_decode = pub_decode;
    ameth->pub_encode = pub_encode;
}

const BIGNUM* RSA_get0_p(const RSA* r) {
    sf_set_trusted_sink_int(r);
    return r->p;
}

int EVP_PKEY_is_a(const EVP_PKEY* pkey, const char* keytype) {
    sf_set_trusted_sink_int(pkey);
    sf_set_trusted_sink_string(keytype);
    return EVP_PKEY_type(pkey->type) == EVP_PKEY_type_from_name(keytype);
}

int i2d_OCSP_ONEREQ(const OCSP_ONEREQ* onereq, unsigned char** pp) {
    sf_set_trusted_sink_int(onereq);
    sf_set_trusted_sink_ptr(pp);
    return i2d_OCSP_ONEREQ_bio(NULL, onereq);
}
int EVP_RAND_nonce(EVP_RAND_CTX*, unsigned char*, size_t);

evp_pkey_st* SSL_get_privatekey(const SSL*);

X509* PEM_read_X509_AUX(FILE*, X509**, pem_password_cb*, void*);

int ASN1_TYPE_cmp(const ASN1_TYPE*, const ASN1_TYPE*);

int i2d_re_X509_tbs(X509*, unsigned char**);

int SSL_get0_dane_tlsa(SSL* ssl, uint8_t* usage, uint8_t* selector, uint8_t* mtype, const unsigned char** data, size_t* dlen);

int PEM_write_bio_PUBKEY(BIO* bio, const EVP_PKEY* key);

NETSCAPE_SPKI* NETSCAPE_SPKI_new();

X509_NAME* X509_get_issuer_name(const X509* x);

RSA* PEM_read_bio_RSAPublicKey(BIO* bio, RSA** rsa, pem_password_cb* cb, void* u);

int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *ctx, int pad);

int EVP_PBE_find(int type, int pbe_nid, int **ppbe_ex, int *ppbe_exlen, EVP_PBE_KEYGEN **ppbe_keygen);

int BN_dec2bn(BIGNUM **a, const char *str);

DSA *d2i_DSA_PUBKEY_bio(BIO *bp, DSA **dsa);

int SSL_CIPHER_get_bits(const SSL_CIPHER *c, int *alg_bits);

void X509_VERIFY_PARAM_set_hostflags(X509_VERIFY_PARAM* param, unsigned int flags);

int DSA_size(const DSA* dsa);

int OCSP_basic_verify(OCSP_BASICRESP* bs, stack_st_X509* certs, X509_STORE* st, unsigned long flags);

const BIGNUM* RSA_get0_q(const RSA* r);

void SSL_set_psk_find_session_callback(SSL* ssl, SSL_psk_find_session_cb_func cb);


OCSP_CERTID* d2i_OCSP_CERTID(OCSP_CERTID** a, const unsigned char** pp, long length)
{
    OCSP_CERTID* Res = NULL;
    sf_set_trusted_sink_int(length);
    sf_malloc_arg(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    sf_lib_arg_type(Res, "OCSP_CERTID");
    return Res;
}

int EVP_CIPHER_CTX_get_key_length(const EVP_CIPHER_CTX* ctx)
{
    int Res = 0;
    sf_set_must_be_not_null(ctx, "EVP_CIPHER_CTX");
    sf_set_errno_if(Res <= 0);
    return Res;
}

X509_STORE_CTX_cleanup_fn X509_STORE_CTX_get_cleanup(const X509_STORE_CTX* ctx)
{
    X509_STORE_CTX_cleanup_fn Res = NULL;
    sf_set_must_be_not_null(ctx, "X509_STORE_CTX");
    sf_set_possible_null(Res);
    return Res;
}

int OSSL_PARAM_get_uint64(const OSSL_PARAM* param, uint64_t* num)
{
    int Res = 0;
    sf_set_must_be_not_null(param, "OSSL_PARAM");
    sf_set_must_be_not_null(num, "uint64_t");
    sf_set_errno_if(Res <= 0);
    return Res;
}

void EVP_PKEY_meth_get_digest_custom(const EVP_PKEY_METHOD* pmeth, int (EVP_PKEY_CTX*, EVP_MD_CTX*)** gdigest)
{
    sf_set_must_be_not_null(pmeth, "EVP_PKEY_METHOD");
    sf_set_must_be_not_null(gdigest, "gdigest");
    sf_set_possible_null(*gdigest);
}

ASN1_OBJECT* OBJ_dup(const ASN1_OBJECT* obj) {
    ASN1_OBJECT* Res = NULL;
    sf_set_trusted_sink_ptr(obj);
    sf_malloc_arg(Res, sizeof(ASN1_OBJECT));
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_lib_arg_type(Res, "OBJ_dup");
    sf_bitcopy(Res, obj);
    return Res;
}

int ASYNC_WAIT_CTX_get_fd(ASYNC_WAIT_CTX* ctx, const void* key, int* val, void** ptr) {
    int Res = 0;
    sf_set_trusted_sink_ptr(ctx);
    sf_set_trusted_sink_ptr(key);
    sf_set_trusted_sink_ptr(val);
    sf_set_trusted_sink_ptr(ptr);
    sf_set_errno_if(Res, Res < 0);
    sf_no_errno_if(Res, Res >= 0);
    return Res;
}

int EC_GROUP_set_curve_GFp(EC_GROUP* group, const BIGNUM* p, const BIGNUM* a, const BIGNUM* b, BN_CTX* ctx) {
    int Res = 0;
    sf_set_trusted_sink_ptr(group);
    sf_set_trusted_sink_ptr(p);
    sf_set_trusted_sink_ptr(a);
    sf_set_trusted_sink_ptr(b);
    sf_set_trusted_sink_ptr(ctx);
    sf_set_errno_if(Res, Res <= 0);
    sf_no_errno_if(Res, Res > 0);
    return Res;
}

X509_PUBKEY* X509_get_X509_PUBKEY(const X509* x) {
    X509_PUBKEY* Res = NULL;
    sf_set_trusted_sink_ptr(x);
    sf_malloc_arg(Res, sizeof(X509_PUBKEY));
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_lib_arg_type(Res, "X509_get_X509_PUBKEY");
    sf_bitcopy(Res, x);
    return Res;
}

const EVP_CIPHER* EVP_aes_128_wrap_pad() {
    const EVP_CIPHER* Res = NULL;
    sf_set_trusted_sink_ptr(Res);
    sf_overwrite(Res);
    sf_lib_arg_type(Res, "EVP_aes_128_wrap_pad");
    return Res;
}

void EVP_PKEY_meth_set_signctx(EVP_PKEY_METHOD *pmeth, int (*signctx) (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, EVP_MD_CTX *mctx), int (*signctx_init) (EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx))
{
    sf_set_trusted_sink_ptr(pmeth);
    sf_set_trusted_sink_ptr(signctx);
    sf_set_trusted_sink_ptr(signctx_init);
    sf_set_tainted(pmeth);
    sf_set_tainted(signctx);
    sf_set_tainted(signctx_init);
}

const char* ERR_reason_error_string(unsigned long e)
{
    const char *Res = NULL;
    sf_set_must_be_not_null(e, ERR_REASON_ERROR_STRING_OF_NULL);
    sf_set_errno_if(Res == NULL, ERR_REASON_ERROR_STRING_FAIL);
    sf_set_tainted(Res);
    return Res;
}

PROXY_CERT_INFO_EXTENSION* d2i_PROXY_CERT_INFO_EXTENSION(PROXY_CERT_INFO_EXTENSION** a, const unsigned char** in, long len)
{
    PROXY_CERT_INFO_EXTENSION *Res = NULL;
    sf_set_must_be_not_null(a, D2I_PROXY_CERT_INFO_EXTENSION_OF_NULL);
    sf_set_must_be_not_null(*a, D2I_PROXY_CERT_INFO_EXTENSION_OF_NULL);
    sf_set_must_be_not_null(in, D2I_PROXY_CERT_INFO_EXTENSION_OF_NULL);
    sf_set_must_be_not_null(*in, D2I_PROXY_CERT_INFO_EXTENSION_OF_NULL);
    sf_set_buf_size_limit(Res, len);
    sf_set_errno_if(Res == NULL, D2I_PROXY_CERT_INFO_EXTENSION_FAIL);
    sf_set_tainted(Res);
    return Res;
}

int RSA_generate_multi_prime_key(RSA *rsa, int bits, int primes, BIGNUM *e_value, BN_GENCB *cb)
{
    int Res = 0;
    sf_set_must_be_not_null(rsa, RSA_GENERATE_MULTI_PRIME_KEY_OF_NULL);
    sf_set_must_be_not_null(e_value, RSA_GENERATE_MULTI_PRIME_KEY_OF_NULL);
    sf_set_errno_if(Res <= 0, RSA_GENERATE_MULTI_PRIME_KEY_FAIL);
    sf_set_tainted(Res);
    return Res;
}

const EVP_MD* HMAC_CTX_get_md(const HMAC_CTX *ctx)
{
    const EVP_MD *Res = NULL;
    sf_set_must_be_not_null(ctx, HMAC_CTX_GET_MD_OF_NULL);
    sf_set_errno_if(Res == NULL, HMAC_CTX_GET_MD_FAIL);
    sf_set_tainted(Res);
    return Res;
}

int EVP_DigestVerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen)
{
    int res = 0;
    sf_set_must_be_not_null(ctx, EVP_MD_CTX_NULL);
    sf_set_must_be_not_null(sig, SIG_NULL);
    sf_set_buf_size(sig, siglen);
    sf_set_errno_if(res <= 0, EVP_DigestVerifyFinal);
    return res;
}

BIO* BIO_new_accept(const char *str)
{
    BIO* res = NULL;
    sf_set_must_be_not_null(str, BIO_ACCEPT_NULL);
    sf_set_errno_if(res == NULL, BIO_new_accept);
    sf_set_possible_null(res);
    return res;
}

EVP_PKEY* EVP_PKEY_new()
{
    EVP_PKEY* res = NULL;
    sf_set_errno_if(res == NULL, EVP_PKEY_new);
    sf_set_possible_null(res);
    return res;
}

int (ssl_st*, SSL_SESSION*)* SSL_CTX_sess_get_new_cb(SSL_CTX *ctx)
{
    int (ssl_st*, SSL_SESSION*)* res = NULL;
    sf_set_must_be_not_null(ctx, SSL_CTX_NULL);
    return res;
}

void* ASN1_item_d2i_bio_ex(const ASN1_ITEM *it, BIO *in, void *x, OSSL_LIB_CTX *libctx, const char *propq)
{
    void* res = NULL;
    sf_set_must_be_not_null(it, ASN1_ITEM_NULL);
    sf_set_must_be_not_null(in, BIO_NULL);
    sf_set_possible_null(res);
    return res;
}

OSSL_PARAM OSSL_PARAM_construct_octet_string(const char *key, void *buf, size_t bsize)
{
    OSSL_PARAM Res = NULL;
    sf_set_trusted_sink_int(bsize);
    Res = OSSL_PARAM_construct_octet_string(key, buf, bsize);
    sf_overwrite(Res);
    return Res;
}

int X509_LOOKUP_by_subject_ex(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type, const X509_NAME *name, X509_OBJECT *ret, OSSL_LIB_CTX *libctx, const char *propq)
{
    int Res = 0;
    sf_set_trusted_sink_ptr(ctx);
    sf_set_trusted_sink_ptr(name);
    sf_set_trusted_sink_ptr(ret);
    sf_set_trusted_sink_ptr(libctx);
    sf_set_trusted_sink_ptr(propq);
    Res = X509_LOOKUP_by_subject_ex(ctx, type, name, ret, libctx, propq);
    sf_set_errno_if(Res <= 0);
    return Res;
}

PKCS7* PKCS7_dup(const PKCS7 *p7)
{
    PKCS7 *Res = NULL;
    sf_set_trusted_sink_ptr(p7);
    Res = PKCS7_dup(p7);
    sf_overwrite(Res);
    return Res;
}

ISSUER_SIGN_TOOL* d2i_ISSUER_SIGN_TOOL(ISSUER_SIGN_TOOL **a, const unsigned char **in, long len)
{
    ISSUER_SIGN_TOOL *Res = NULL;
    sf_set_trusted_sink_ptr(a);
    sf_set_trusted_sink_ptr(in);
    Res = d2i_ISSUER_SIGN_TOOL(a, in, len);
    sf_overwrite(Res);
    return Res;
}

X509_ALGOR* PKCS5_pbe2_set_iv_ex(const EVP_CIPHER *cipher, int iter, unsigned char *salt, int saltlen, unsigned char *aiv, int prf_nid, OSSL_LIB_CTX *libctx)
{
    X509_ALGOR *Res = NULL;
    sf_set_trusted_sink_ptr(cipher);
    sf_set_trusted_sink_int(iter);
    sf_set_trusted_sink_ptr(salt);
    sf_set_trusted_sink_int(saltlen);
    sf_set_trusted_sink_ptr(aiv);
    sf_set_trusted_sink_int(prf_nid);
    sf_set_trusted_sink_ptr(libctx);
    Res = PKCS5_pbe2_set_iv_ex(cipher, iter, salt, saltlen, aiv, prf_nid, libctx);
    sf_overwrite(Res);
    return Res;
}

int i2d_X509_REQ_fp(FILE *fp, const X509_REQ *req)
{
    int res = 0;
    sf_set_must_not_be_null(fp, FILE_PTR_NULL);
    sf_set_must_not_be_null(req, X509_REQ_PTR_NULL);
    // Implementation
    return res;
}

int ASN1_GENERALIZEDTIME_set_string(ASN1_GENERALIZEDTIME *s, const char *str)
{
    int res = 0;
    sf_set_must_not_be_null(s, ASN1_GENERALIZEDTIME_PTR_NULL);
    sf_set_must_not_be_null(str, GENERALIZEDTIME_STRING_NULL);
    // Implementation
    return res;
}

X509_CRL_INFO* d2i_X509_CRL_INFO(X509_CRL_INFO **a, const unsigned char **in, long len)
{
    X509_CRL_INFO *res = NULL;
    sf_set_must_not_be_null(a, X509_CRL_INFO_PTR_NULL);
    sf_set_must_not_be_null(in, D2I_IN_PTR_NULL);
    // Implementation
    return res;
}

int RSA_meth_set_pub_enc(RSA_METHOD *meth, int (*pub_enc)())
{
    int res = 0;
    sf_set_must_not_be_null(meth, RSA_METHOD_PTR_NULL);
    sf_set_must_not_be_null(pub_enc, RSA_PUB_ENC_NULL);
    // Implementation
    return res;
}

int i2d_ASN1_T61STRING(const ASN1_T61STRING *a, unsigned char **pp)
{
    int res = 0;
    sf_set_must_not_be_null(a, ASN1_T61STRING_PTR_NULL);
    sf_set_must_not_be_null(pp, I2D_ASN1_T61STRING_PP_NULL);
    // Implementation
    return res;
}

const ENGINE_CMD_DEFN* ENGINE_get_cmd_defns(const ENGINE* engine) {
    const ENGINE_CMD_DEFN* Res = NULL;
    sf_set_must_be_not_null(engine, ENGINE_NULL);
    Res = ENGINE_get_cmd_defns(engine);
    sf_set_possible_null(Res, ENGINE_CMD_DEFN_NULL);
    return Res;
}

SSL_SESSION* PEM_read_SSL_SESSION(FILE* file, SSL_SESSION** session, pem_password_cb* cb, void* u) {
    SSL_SESSION* Res = NULL;
    sf_set_must_be_not_null(file, FILE_NULL);
    sf_set_must_be_not_null(session, SSL_SESSION_NULL);
    sf_password_use(cb);
    Res = PEM_read_SSL_SESSION(file, session, cb, u);
    sf_set_possible_null(Res, SSL_SESSION_NULL);
    return Res;
}

DH_METHOD* DH_meth_dup(const DH_METHOD* dh_meth) {
    DH_METHOD* Res = NULL;
    sf_set_must_be_not_null(dh_meth, DH_METHOD_NULL);
    Res = DH_meth_dup(dh_meth);
    sf_set_possible_null(Res, DH_METHOD_NULL);
    return Res;
}

int RSA_check_key_ex(const RSA* rsa, BN_GENCB* cb) {
    int Res = 0;
    sf_set_must_be_not_null(rsa, RSA_NULL);
    sf_set_must_be_not_null(cb, BN_GENCB_NULL);
    Res = RSA_check_key_ex(rsa, cb);
    sf_set_errno_if(Res <= 0, RSA_CHECK_KEY_EX_FAIL);
    return Res;
}

const ASN1_INTEGER* X509_REVOKED_get0_serialNumber(const X509_REVOKED* rev) {
    const ASN1_INTEGER* Res = NULL;
    sf_set_must_be_not_null(rev, X509_REVOKED_NULL);
    Res = X509_REVOKED_get0_serialNumber(rev);
    sf_set_possible_null(Res, ASN1_INTEGER_NULL);
    return Res;
}

void* OPENSSL_LH_insert(OPENSSL_LHASH* lh, void* data)
{
    void *Res = NULL;
    sf_malloc_arg(data, PAGES_MEMORY_CATEGORY);
    Res = sf_malloc(sizeof(void*));
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    sf_lib_arg_type(Res, "LHASHInsert");
    return Res;
}

const BIGNUM* EC_KEY_get0_private_key(const EC_KEY* key)
{
    const BIGNUM *Res = NULL;
    sf_set_must_be_not_null(key, EC_KEY_NULL);
    Res = sf_lib_arg_type(key, "EC_KEY_get0_private_key");
    sf_set_possible_null(Res);
    return Res;
}

int SSL_get_changed_async_fds(SSL* s, int* readfd, size_t* readct, int* writefd, size_t* writect)
{
    int Res = 0;
    sf_set_must_be_not_null(s, SSL_NULL);
    sf_set_must_be_not_null(readfd, READFD_NULL);
    sf_set_must_be_not_null(readct, READCT_NULL);
    sf_set_must_be_not_null(writefd, WRITEFD_NULL);
    sf_set_must_be_not_null(writect, WRITECT_NULL);
    Res = sf_lib_arg_type(s, "SSL_get_changed_async_fds");
    sf_set_errno_if(Res, ERRNO_NULL);
    return Res;
}

void EVP_PKEY_meth_get_init(const EVP_PKEY_METHOD* pmeth, int (EVP_PKEY_CTX*)** init)
{
    sf_set_must_be_not_null(pmeth, EVP_PKEY_METHOD_NULL);
    sf_set_must_be_not_null(init, INIT_NULL);
    sf_lib_arg_type(pmeth, "EVP_PKEY_meth_get_init");
}

void BN_BLINDING_set_flags(BN_BLINDING* b, unsigned long flags)
{
    sf_set_must_be_not_null(b, BN_BLINDING_NULL);
    sf_lib_arg_type(b, "BN_BLINDING_set_flags");
}

int i2d_X509_PUBKEY_fp(FILE *fp, const X509_PUBKEY *key)
{
    int res = 0;
    sf_set_must_be_not_null(fp, FP_OF_NULL);
    sf_set_must_be_not_null(key, KEY_OF_NULL);
    // Implementation
    return res;
}

void DSA_free(DSA *dsa)
{
    sf_set_must_be_not_null(dsa, DSA_OF_NULL);
    // Implementation
}

int X509_VERIFY_PARAM_get_depth(const X509_VERIFY_PARAM *param)
{
    int res = 0;
    sf_set_must_be_not_null(param, PARAM_OF_NULL);
    // Implementation
    return res;
}

const OSSL_PARAM *EVP_KEYMGMT_settable_params(const EVP_KEYMGMT *keymgmt)
{
    const OSSL_PARAM *res = NULL;
    sf_set_must_be_not_null(keymgmt, KEYMGMT_OF_NULL);
    // Implementation
    return res;
}

X509_STORE *X509_LOOKUP_get_store(const X509_LOOKUP *lookup)
{
    X509_STORE *res = NULL;
    sf_set_must_be_not_null(lookup, LOOKUP_OF_NULL);
    // Implementation
    return res;
}

int RSA_meth_get_sign(const RSA_METHOD* meth) {
    int Res = 0;
    Res = meth->rsa_sign;
    sf_set_possible_null(Res);
    return Res;
}

BIO* BIO_new_fd(int fd, int close_flag) {
    BIO* Res = NULL;
    sf_set_must_be_not_null(fd, FD_OF_NULL);
    sf_set_must_be_not_null(close_flag, CLOSE_FLAG_OF_NULL);
    Res = BIO_new_fd(fd, close_flag);
    sf_set_possible_null(Res);
    return Res;
}

int BN_sub(BIGNUM* r, const BIGNUM* a, const BIGNUM* b) {
    int Res = 0;
    sf_set_must_be_not_null(r, R_OF_NULL);
    sf_set_must_be_not_null(a, A_OF_NULL);
    sf_set_must_be_not_null(b, B_OF_NULL);
    Res = BN_sub(r, a, b);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int i2d_ASN1_VISIBLESTRING(const ASN1_VISIBLESTRING* a, unsigned char** pp) {
    int Res = 0;
    sf_set_must_be_not_null(a, A_OF_NULL);
    sf_set_must_be_not_null(pp, PP_OF_NULL);
    Res = i2d_ASN1_VISIBLESTRING(a, pp);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int EVP_PKEY_CTX_set_ec_paramgen_curve_nid(EVP_PKEY_CTX* ctx, int nid) {
    int Res = 0;
    sf_set_must_be_not_null(ctx, CTX_OF_NULL);
    Res = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int DSA_meth_set_paramgen(DSA_METHOD *meth, int (*paramgen_cb)(DSA *, int, const unsigned char *, int, int *, unsigned long *, BN_GENCB *)) {
    int res = 0;
    sf_set_trusted_sink_int(paramgen_cb);
    sf_set_possible_null(paramgen_cb);
    sf_set_possible_null(meth);
    sf_set_errno_if(res == 0);
    return res;
}

DIST_POINT_NAME* DIST_POINT_NAME_new() {
    DIST_POINT_NAME *res = NULL;
    sf_malloc_arg(res, sizeof(DIST_POINT_NAME));
    sf_overwrite(res);
    sf_new(res, PAGES_MEMORY_CATEGORY);
    sf_set_possible_null(res);
    return res;
}

const NAMING_AUTHORITY* ADMISSIONS_get0_namingAuthority(const ADMISSIONS* adm) {
    const NAMING_AUTHORITY *res = NULL;
    sf_set_must_be_not_null(adm);
    sf_set_possible_null(res);
    return res;
}

int OCSP_id_get0_info(ASN1_OCTET_STRING **issuerNameHash, ASN1_OBJECT **issuerKeyHash, ASN1_OCTET_STRING **serialNumber, ASN1_INTEGER **serial, OCSP_CERTID *id) {
    int res = 0;
    sf_set_must_be_not_null(id);
    sf_set_possible_null(issuerNameHash);
    sf_set_possible_null(issuerKeyHash);
    sf_set_possible_null(serialNumber);
    sf_set_possible_null(serial);
    sf_set_errno_if(res == 0);
    return res;
}

int i2d_ADMISSIONS(const ADMISSIONS *a, unsigned char **pp) {
    int res = 0;
    sf_set_must_be_not_null(a);
    sf_set_must_be_not_null(pp);
    sf_set_errno_if(res == 0);
    return res;
}

void EVP_PKEY_CTX_set0_dh_kdf_ukm(EVP_PKEY_CTX *ctx, unsigned char *ukm, int len) {
    int res = 0;
    sf_set_trusted_sink_int(len);
    sf_set_tainted(ukm, len);
    res = EVP_PKEY_CTX_set0_dh_kdf_ukm(ctx, ukm, len);
    sf_set_errno_if(res <= 0);
    return res;
}

EC_GROUP* EC_GROUP_new(const EC_METHOD *method) {
    EC_GROUP *res = NULL;
    res = EC_GROUP_new(method);
    sf_set_errno_if(res == NULL);
    return res;
}

int EVP_MD_meth_get_cleanup(const EVP_MD *md) {
    int (*res)(EVP_MD_CTX *ctx) = NULL;
    res = EVP_MD_meth_get_cleanup(md);
    sf_set_errno_if(res == NULL);
    return res;
}

const EVP_CIPHER* EVP_camellia_192_ctr() {
    const EVP_CIPHER *res = NULL;
    res = EVP_camellia_192_ctr();
    sf_set_errno_if(res == NULL);
    return res;
}

X509_ATTRIBUTE* EVP_PKEY_get_attr(const EVP_PKEY *pkey, int nid) {
    X509_ATTRIBUTE *res = NULL;
    res = EVP_PKEY_get_attr(pkey, nid);
    sf_set_errno_if(res == NULL);
    return res;
}
uint64_t SSL_CTX_set_options(SSL_CTX* ctx, uint64_t options);

void SCT_LIST_free(stack_st_SCT* sct_list);

X509_NAME_ENTRY* d2i_X509_NAME_ENTRY(X509_NAME_ENTRY** a, const unsigned char** in, long len);

int i2d_ASN1_GENERALSTRING(const ASN1_GENERALSTRING* a, unsigned char** out);

int EVP_DigestInit_ex2(EVP_MD_CTX* ctx, const EVP_MD* type, const OSSL_PARAM params[]);

int EVP_PKEY_set1_EC_KEY(EVP_PKEY *pkey, EC_KEY *key);

int OSSL_PARAM_get_long(const OSSL_PARAM *p, long int *val);

int EVP_PKEY_CTX_get_ecdh_cofactor_mode(EVP_PKEY_CTX *ctx);

void EVP_PKEY_meth_get_check(const EVP_PKEY_METHOD *pmeth, int (**check);

int EVP_KEM_names_do_all(const EVP_KEM *k, void (*fn);


unsigned long ERR_get_error_line(const char** file, int* line)
{
    unsigned long Res = 0;
    sf_set_tainted(file);
    sf_set_tainted(line);
    sf_set_errno_if(Res == 0, ENOENT);
    sf_set_possible_null(Res);
    return Res;
}

int NCONF_load(CONF* conf, const char* file, long* line)
{
    int Res = 0;
    sf_set_tainted(file);
    sf_set_tainted(line);
    sf_set_errno_if(Res <= 0, ENOENT);
    sf_set_possible_null(Res);
    return Res;
}

int X509_CRL_digest(const X509_CRL* crl, const EVP_MD* md, unsigned char* buf, unsigned int* len)
{
    int Res = 0;
    sf_set_tainted(buf);
    sf_set_tainted(len);
    sf_set_errno_if(Res <= 0, ENOENT);
    sf_set_possible_null(Res);
    return Res;
}

int EVP_PKEY_eq(const EVP_PKEY* a, const EVP_PKEY* b)
{
    int Res = 0;
    sf_set_tainted(a);
    sf_set_tainted(b);
    sf_set_possible_null(Res);
    return Res;
}

EC_GROUP* EC_GROUP_new_from_ecpkparameters(const ECPKPARAMETERS* params)
{
    EC_GROUP* Res = NULL;
    sf_set_tainted(params);
    sf_set_errno_if(Res == NULL, ENOENT);
    sf_set_possible_null(Res);
    return Res;
}

EC_GROUP* EC_GROUP_new_from_ecparameters(const ECPARAMETERS* params) {
    EC_GROUP* Res = NULL;
    sf_set_trusted_sink_int(params);
    Res = EC_GROUP_new_from_ecparameters(params);
    sf_overwrite(Res);
    return Res;
}

void EVP_KEYMGMT_free(EVP_KEYMGMT* keymgmt) {
    sf_set_must_be_not_null(keymgmt, FREE_OF_NULL);
    EVP_KEYMGMT_free(keymgmt);
    sf_delete(keymgmt, KEYMGMT_CATEGORY);
}

BIGNUM* BN_CTX_get(BN_CTX* ctx) {
    BIGNUM* Res = NULL;
    sf_set_trusted_sink_int(ctx);
    Res = BN_CTX_get(ctx);
    sf_overwrite(Res);
    return Res;
}

int ENGINE_set_init_function(ENGINE* e, ENGINE_GEN_INT_FUNC_PTR init_f) {
    int Res = 0;
    sf_set_trusted_sink_int(e);
    sf_set_trusted_sink_int(init_f);
    Res = ENGINE_set_init_function(e, init_f);
    sf_overwrite(Res);
    return Res;
}

int SCT_set0_log_id(SCT* sct, unsigned char* log_id, size_t log_id_len) {
    int Res = 0;
    sf_set_trusted_sink_int(sct);
    sf_set_trusted_sink_int(log_id);
    sf_set_trusted_sink_int(log_id_len);
    Res = SCT_set0_log_id(sct, log_id, log_id_len);
    sf_overwrite(Res);
    return Res;
}

int PEM_write_bio_DSA_PUBKEY(BIO* bio, const DSA* dsa)
{
    int res = 0;
    sf_set_tainted(bio);
    sf_set_tainted(dsa);
    sf_set_trusted_sink_ptr(bio);
    sf_set_trusted_sink_ptr(dsa);
    res = PEM_write_bio_DSA_PUBKEY(bio, dsa);
    sf_set_errno_if(res <= 0);
    sf_set_possible_null(res);
    return res;
}

int DH_meth_set_init(DH_METHOD* dh_meth, int (*init)(DH*))
{
    int res = 0;
    sf_set_trusted_sink_ptr(dh_meth);
    sf_set_trusted_sink_ptr(init);
    res = DH_meth_set_init(dh_meth, init);
    sf_set_errno_if(res != 1);
    return res;
}

const RSA_METHOD* RSA_get_method(const RSA* rsa)
{
    const RSA_METHOD* res = NULL;
    sf_set_tainted(rsa);
    sf_set_trusted_sink_ptr(rsa);
    res = RSA_get_method(rsa);
    sf_set_possible_null(res);
    return res;
}

NAMING_AUTHORITY* NAMING_AUTHORITY_new()
{
    NAMING_AUTHORITY* res = NULL;
    res = NAMING_AUTHORITY_new();
    sf_set_possible_null(res);
    return res;
}

int EVP_PKEY_print_public(BIO* bio, const EVP_PKEY* pkey, int indent, ASN1_PCTX* pctx)
{
    int res = 0;
    sf_set_tainted(bio);
    sf_set_tainted(pkey);
    sf_set_trusted_sink_ptr(bio);
    sf_set_trusted_sink_ptr(pkey);
    sf_set_trusted_sink_ptr(pctx);
    res = EVP_PKEY_print_public(bio, pkey, indent, pctx);
    sf_set_errno_if(res <= 0);
    sf_set_possible_null(res);
    return res;
}

const EVP_CIPHER* EVP_aes_256_cfb8() {
    const EVP_CIPHER* Res = NULL;
    Res = EVP_aes_256_cfb8();
    sf_set_possible_null(Res);
    return Res;
}

void EVP_PKEY_meth_set_param_check(EVP_PKEY_METHOD* pmeth, int (*param_check)(EVP_PKEY*)) {
    EVP_PKEY_meth_set_param_check(pmeth, param_check);
}

int PEM_write_PUBKEY_ex(FILE* fp, const EVP_PKEY* x, OSSL_LIB_CTX* libctx, const char* propq) {
    int Res = 0;
    Res = PEM_write_PUBKEY_ex(fp, x, libctx, propq);
    sf_set_errno_if(Res <= 0);
    return Res;
}

EVP_PKEY_CTX* EVP_PKEY_CTX_new(EVP_PKEY* pkey, ENGINE* engine) {
    EVP_PKEY_CTX* Res = NULL;
    Res = EVP_PKEY_CTX_new(pkey, engine);
    sf_set_alloc_possible_null(Res);
    return Res;
}

int EVP_EncryptFinal_ex(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl) {
    int Res = 0;
    Res = EVP_EncryptFinal_ex(ctx, out, outl);
    sf_set_errno_if(Res <= 0);
    return Res;
}
int OSSL_PARAM_get_utf8_string(const OSSL_PARAM*, char**, size_t);

int SSL_set1_param(SSL*, X509_VERIFY_PARAM*);

int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX*, int keylen);

const char* EVP_MAC_get0_description(const EVP_MAC*);

const stack_st_X509_EXTENSION* X509_CRL_get0_extensions(const X509_CRL* crl);


const BIO_METHOD* BIO_s_fd() {
    const BIO_METHOD* Res = NULL;
    Res = BIO_s_fd();
    sf_lib_arg_type(Res, "BIO_METHOD");
    return Res;
}

int OPENSSL_sk_unshift(OPENSSL_STACK* st, const void* data) {
    int Res = 0;
    sf_set_must_be_not_null(st, "OPENSSL_sk_unshift");
    sf_set_must_be_not_null(data, "OPENSSL_sk_unshift");
    Res = OPENSSL_sk_unshift(st, data);
    sf_set_errno_if(Res == 0, "OPENSSL_sk_unshift");
    return Res;
}

size_t BUF_MEM_grow_clean(BUF_MEM* b, size_t len) {
    size_t Res = 0;
    sf_set_must_be_not_null(b, "BUF_MEM_grow_clean");
    Res = BUF_MEM_grow_clean(b, len);
    sf_set_errno_if(Res == 0, "BUF_MEM_grow_clean");
    return Res;
}

X509* d2i_X509_AUX(X509** x, const unsigned char** in, long len) {
    X509* Res = NULL;
    sf_set_must_be_not_null(x, "d2i_X509_AUX");
    sf_set_must_be_not_null(in, "d2i_X509_AUX");
    Res = d2i_X509_AUX(x, in, len);
    sf_set_errno_if(Res == NULL, "d2i_X509_AUX");
    return Res;
}

int EVP_ASYM_CIPHER_up_ref(EVP_ASYM_CIPHER* cipher) {
    int Res = 0;
    sf_set_must_be_not_null(cipher, "EVP_ASYM_CIPHER_up_ref");
    Res = EVP_ASYM_CIPHER_up_ref(cipher);
    sf_set_errno_if(Res == 0, "EVP_ASYM_CIPHER_up_ref");
    return Res;
}

const EVP_CIPHER* EVP_cast5_ofb() {
    const EVP_CIPHER* Res = NULL;
    Res = EVP_cast5_ofb();
    sf_set_possible_null(Res);
    return Res;
}

int OCSP_resp_find_status(OCSP_BASICRESP* bs, OCSP_CERTID* id, int* status, int* reason, ASN1_GENERALIZEDTIME** thisupd, ASN1_GENERALIZEDTIME** nextupd, ASN1_GENERALIZEDTIME** revtime) {
    int Res = 0;
    Res = OCSP_resp_find_status(bs, id, status, reason, thisupd, nextupd, revtime);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int EVP_PKEY_CTX_set_dh_paramgen_seed(EVP_PKEY_CTX* ctx, const unsigned char* seed, size_t seedlen) {
    int Res = 0;
    Res = EVP_PKEY_CTX_set_dh_paramgen_seed(ctx, seed, seedlen);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int EVP_CIPHER_CTX_get_block_size(const EVP_CIPHER_CTX* ctx) {
    int Res = 0;
    Res = EVP_CIPHER_CTX_get_block_size(ctx);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int SSL_set_ssl_method(SSL* s, const SSL_METHOD* meth) {
    int Res = 0;
    Res = SSL_set_ssl_method(s, meth);
    sf_set_errno_if(Res <= 0);
    return Res;
}
int SSL_get_signature_type_nid(const SSL* ssl, int* signature_type);

int X509_NAME_digest(const X509_NAME* name, const EVP_MD* md, unsigned char* digest, unsigned int* digest_len);

GENERAL_NAME* GENERAL_NAME_new();

const ASN1_GENERALIZEDTIME* OCSP_resp_get0_produced_at(const OCSP_BASICRESP* bs);

int EVP_PKEY_decrypt(EVP_PKEY_CTX* ctx, unsigned char* out, size_t* outlen, const unsigned char* in, size_t inlen);


stack_st_X509* SSL_get0_verified_chain(const SSL* s) {
    stack_st_X509* Res = NULL;
    sf_set_trusted_sink_int(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    return Res;
}

BIO* BIO_new_file(const char* filename, const char* mode) {
    BIO* Res = NULL;
    sf_set_trusted_sink_ptr(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    return Res;
}

EC_GROUP* EC_GROUP_new_curve_GFp(const BIGNUM* p, const BIGNUM* a, const BIGNUM* b, BN_CTX* ctx) {
    EC_GROUP* Res = NULL;
    sf_set_trusted_sink_ptr(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    return Res;
}

int RSA_check_key(const RSA* rsa) {
    int Res = 0;
    sf_set_errno_if(Res <= 0);
    return Res;
}

int ENGINE_free(ENGINE* e) {
    int Res = 0;
    sf_set_errno_if(Res <= 0);
    return Res;
}
const BIGNUM* ECDSA_SIG_get0_s(const ECDSA_SIG* sig);

SSL_SESSION* SSL_SESSION_new();

EC_GROUP* PEM_read_bio_ECPKParameters(BIO* bio, EC_GROUP** group, pem_password_cb* cb, void* u);

int EVP_MD_meth_set_result_size(EVP_MD* md, int size);

ASN1_OBJECT* ASN1_OBJECT_new();

void SSL_CTX_set_cert_cb(SSL_CTX* ctx, int (*cb);

void EVP_MAC_free(EVP_MAC* mac);

const OSSL_PARAM* EVP_KEM_gettable_ctx_params(const EVP_KEM* kem);

long (*BIO_meth_get_callback_ctrl(const BIO_METHOD* type);

int PKCS5_PBKDF2_HMAC_SHA1(const char* pass, int passlen, const unsigned char* salt, int saltlen, int iter, int keylen, unsigned char* out);

int i2d_DHxparams(const DH* dh, unsigned char** p);

int RSA_padding_add_PKCS1_OAEP(unsigned char* to, int tlen, const unsigned char* from, int flen, const unsigned char* param, int plen);

int EVP_PKEY_get_params(const EVP_PKEY* pkey, OSSL_PARAM params[]);

const char* SSL_group_to_name(SSL* s, int group_id);

EC_KEY* EC_KEY_new();


OPENSSL_STACK* OPENSSL_sk_new(OPENSSL_sk_compfunc cmp) {
    OPENSSL_STACK* Res = NULL;
    sf_malloc_arg(Res, sizeof(OPENSSL_STACK));
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    return Res;
}

int SSL_set_rfd(SSL* s, int fd) {
    sf_set_must_be_not_null(s, FREE_OF_NULL);
    sf_set_must_be_positive(fd);
    sf_lib_arg_type(s, "SSL");
    sf_lib_arg_type(fd, "FileDescriptor");
    return 1;
}

X509_LOOKUP_get_by_subject_fn X509_LOOKUP_meth_get_get_by_subject(const X509_LOOKUP_METHOD* meth) {
    sf_set_must_be_not_null(meth, FREE_OF_NULL);
    sf_lib_arg_type(meth, "X509_LOOKUP_METHOD");
    return NULL;
}

int PEM_write_bio_DHparams(BIO* bp, const DH* x) {
    sf_set_must_be_not_null(bp, FREE_OF_NULL);
    sf_set_must_be_not_null(x, FREE_OF_NULL);
    sf_lib_arg_type(bp, "BIO");
    sf_lib_arg_type(x, "DH");
    return 1;
}

void ASYNC_unblock_pause() {
    return;
}
Here are the specifications for the functions based on the rules provided:

1. int X509_check_ca(X509* x)
```
    sf_set_tainted(x);
    int Res = 0;
    Res = X509_check_ca(x);
    sf_set_errno_if(Res == 0);
    sf_set_possible_null(Res);
    return Res;
```

2. const char* SSL_CIPHER_standard_name(const SSL_CIPHER* c)
```
    sf_set_tainted(c);
    const char* Res = NULL;
    Res = SSL_CIPHER_standard_name(c);
    sf_set_possible_null(Res);
    return Res;
```

3. int EVP_PBE_scrypt(const char* pass, size_t passlen, const unsigned char* salt, size_t saltlen, uint64_t N, uint64_t r, uint64_t p, uint64_t maxmem, unsigned char* key, size_t keylen)
```
    sf_password_use(pass);
    sf_set_buf_size(salt, saltlen);
    sf_set_buf_size(key, keylen);
    int Res = 0;
    Res = EVP_PBE_scrypt(pass, passlen, salt, saltlen, N, r, p, maxmem, key, keylen);
    sf_set_errno_if(Res == 0);
    return Res;
```

4. int OCSP_copy_nonce(OCSP_BASICRESP* bs, OCSP_REQUEST* req)
```
    sf_set_tainted(bs);
    sf_set_tainted(req);
    int Res = 0;
    Res = OCSP_copy_nonce(bs, req);
    sf_set_errno_if(Res == 0);
    return Res;
```

5. void EVP_PKEY_meth_set_decrypt(EVP_PKEY_METHOD* pmeth, int (*decrypt_init)(), int (*decrypt_fn)(EVP_PKEY_CTX*, unsigned char*, size_t*, const unsigned char*, size_t))
```
    sf_set_tainted(pmeth);
    void (*Res)() = NULL;
    EVP_PKEY_meth_set_decrypt(pmeth, decrypt_init, decrypt_fn);
    return;
```
const BIO_METHOD* BIO_s_bio() {
    const BIO_METHOD* Res = NULL;
    Res = BIO_s_bio();
    sf_lib_arg_type(Res, "BIO_METHOD");
    return Res;
}

int X509_get_signature_info(X509* x, int* sig_nid, int* key_nid, int* key_type, uint32_t* key_size) {
    int Res = 0;
    Res = X509_get_signature_info(x, sig_nid, key_nid, key_type, key_size);
    sf_set_errno_if(Res <= 0);
    return Res;
}

const EVP_CIPHER* EVP_aes_128_cfb8() {
    const EVP_CIPHER* Res = NULL;
    Res = EVP_aes_128_cfb8();
    sf_lib_arg_type(Res, "EVP_CIPHER");
    return Res;
}

int EVP_PKEY_set1_DSA(EVP_PKEY* pkey, dsa_st* dsa) {
    int Res = 0;
    Res = EVP_PKEY_set1_DSA(pkey, dsa);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int EC_POINT_set_compressed_coordinates_GF2m(const EC_GROUP* group, EC_POINT* point, const BIGNUM* x, int y_bit, BN_CTX* ctx) {
    int Res = 0;
    Res = EC_POINT_set_compressed_coordinates_GF2m(group, point, x, y_bit, ctx);
    sf_set_errno_if(Res <= 0);
    return Res;
}

const RSA_METHOD* ENGINE_get_RSA(const ENGINE* e) {
    const RSA_METHOD* Res = NULL;
    sf_set_trusted_sink_ptr(e);
    sf_set_alloc_possible_null(Res);
    return Res;
}

int EVP_MD_get_params(const EVP_MD* md, OSSL_PARAM params[]) {
    int Res = 0;
    sf_set_trusted_sink_ptr(md);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int EVP_PKEY_CTX_set_dsa_paramgen_q_bits(EVP_PKEY_CTX* ctx, int qbits) {
    int Res = 0;
    sf_set_trusted_sink_int(qbits);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int OCSP_request_onereq_count(OCSP_REQUEST* req) {
    int Res = 0;
    sf_set_trusted_sink_ptr(req);
    sf_set_errno_if(Res < 0);
    return Res;
}

X509* X509_dup(const X509* x) {
    X509* Res = NULL;
    sf_set_trusted_sink_ptr(x);
    sf_set_alloc_possible_null(Res);
    return Res;
}

X509_SIG* d2i_X509_SIG(X509_SIG** a, const unsigned char** pp, long length)
{
    X509_SIG* Res = NULL;
    sf_set_trusted_sink_int(length);
    sf_malloc_arg(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    sf_lib_arg_type(Res, "X509_SIG");
    return Res;
}

EVP_MD* EVP_MD_meth_dup(const EVP_MD* md)
{
    EVP_MD* Res = NULL;
    sf_malloc_arg(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    sf_lib_arg_type(Res, "EVP_MD");
    return Res;
}

void SSL_CTX_set_verify_depth(SSL_CTX* ctx, int depth)
{
    sf_set_trusted_sink_int(depth);
    sf_lib_arg_type(ctx, "SSL_CTX");
}

void* BN_GENCB_get_arg(BN_GENCB* cb)
{
    void* Res = NULL;
    sf_lib_arg_type(cb, "BN_GENCB");
    sf_set_possible_null(Res);
    return Res;
}

OPENSSL_INIT_SETTINGS* OPENSSL_INIT_new()
{
    OPENSSL_INIT_SETTINGS* Res = NULL;
    sf_malloc_arg(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    sf_lib_arg_type(Res, "OPENSSL_INIT_SETTINGS");
    return Res;
}

void OPENSSL_buf2hexstr_ex(char *out, size_t out_size, size_t *out_len, const unsigned char *in, size_t in_size, const char *delimiter) {
    int Res = 0;
    sf_set_trusted_sink_int(out_size);
    sf_set_trusted_sink_int(in_size);
    sf_set_trusted_sink_ptr(delimiter);
    sf_set_buf_size(out, out_size);
    sf_set_buf_size(in, in_size);
    sf_set_buf_size_limit(out, out_size);
    sf_set_buf_size_limit(in, in_size);
    sf_set_buf_size_limit_read(out, out_size);
    sf_set_buf_size_limit_read(in, in_size);
    sf_set_buf_stop_at_null(out);
    sf_set_buf_stop_at_null(in);
    sf_set_buf_overlap(out, in);
    sf_set_errno_if(Res == 0);
    sf_no_errno_if(Res != 0);
    sf_set_alloc_possible_null(out);
    sf_set_possible_null(out_len);
    sf_set_possible_null(out);
    sf_set_must_be_not_null(out, BUFFER_OF_NULL);
    sf_set_must_be_not_null(in, BUFFER_OF_NULL);
    sf_set_must_be_not_null(delimiter, DELIMITER_OF_NULL);
    sf_set_must_be_not_null(out_len, POINTER_OF_NULL);
    sf_set_must_not_be_release(out);
    sf_set_must_not_be_release(in);
    sf_set_must_not_be_release(delimiter);
    sf_set_must_not_be_release(out_len);
    sf_set_tainted(out);
    sf_set_tainted(in);
    sf_set_tainted(delimiter);
    sf_set_tainted(out_len);
    sf_set_possible_negative(Res);
    sf_set_uncontrolled_ptr(out);
    sf_set_uncontrolled_ptr(in);
    sf_set_uncontrolled_ptr(delimiter);
    sf_set_uncontrolled_ptr(out_len);
    sf_terminate_path(Res == 0);
    sf_lib_arg_type(out, "Buf2HexStrExOut");
    sf_lib_arg_type(in, "Buf2HexStrExIn");
    sf_lib_arg_type(delimiter, "Buf2HexStrExDelimiter");
    sf_lib_arg_type(out_len, "Buf2HexStrExOutLen");
}

void SSL_dane_clear_flags(SSL *ssl, unsigned long flags) {
    unsigned long Res = 0;
    sf_set_must_not_be_release(ssl);
    sf_set_possible_null(ssl);
    sf_set_must_be_not_null(ssl, SSL_OF_NULL);
    sf_set_tainted(ssl);
    sf_set_possible_negative(Res);
    sf_set_uncontrolled_ptr(ssl);
    sf_lib_arg_type(ssl, "SSL");
}

void BIO_ADDR_new() {
    BIO_ADDR *Res = NULL;
    sf_new(Res, ADDR_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    sf_set_possible_null(Res);
    sf_set_must_be_not_null(Res, ADDR_OF_NULL);
    sf_set_tainted(Res);
    sf_set_uncontrolled_ptr(Res);
    sf_lib_arg_type(Res, "BIO_ADDR");
}

void EC_GROUP_get_order(const EC_GROUP *group, BIGNUM *order, BN_CTX *ctx) {
    int Res = 0;
    sf_set_must_not_be_release(group);
    sf_set_possible_null(group);
    sf_set_must_be_not_null(group, GROUP_OF_NULL);
    sf_set_tainted(group);
    sf_set_uncontrolled_ptr(group);
    sf_set_must_not_be_release(order);
    sf_set_possible_null(order);
    sf_set_must_be_not_null(order, ORDER_OF_NULL);
    sf_set_tainted(order);
    sf_set_uncontrolled_ptr(order);
    sf_set_must_not_be_release(ctx);
    sf_set_possible_null(ctx);
    sf_set_must_be_not_null(ctx, CTX_OF_NULL);
    sf_set_tainted(ctx);
    sf_set_uncontrolled_ptr(ctx);
    sf_set_errno_if(Res == 0);
    sf_no_errno_if(Res != 0);
    sf_set_possible_negative(Res);
    sf_lib_arg_type(group, "EC_GROUP");
    sf_lib_arg_type(order, "BIGNUM");
    sf_lib_arg_type(ctx, "BN_CTX");
}

void EVP_PKEY_CTX_set1_id(EVP_PKEY_CTX *ctx, const void *id, int len) {
    int Res = 0;
    sf_set_must_not_be_release(ctx);
    sf_set_possible_null(ctx);
    sf_set_must_be_not_null(ctx, CTX_OF_NULL);
    sf_set_tainted(ctx);
    sf_set_uncontrolled_ptr(ctx);
    sf_set_buf_size_limit_read(id, len);
    sf_set_buf_stop_at_null(id);
    sf_set_buf_overlap(ctx, id);
    sf_set_errno_if(Res == 0);
    sf_no_errno_if(Res != 0);
    sf_set_possible_negative(Res);
    sf_lib_arg_type(ctx, "EVP_PKEY_CTX");
    sf_lib_arg_type(id, "ID");
}

const EVP_CIPHER* EVP_seed_ecb()
{
    const EVP_CIPHER* Res = NULL;
    // Additional implementation here
    return Res;
}

int EVP_ASYM_CIPHER_is_a(const EVP_ASYM_CIPHER* ctx, const char* name)
{
    int Res = 0;
    // Additional implementation here
    return Res;
}

int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX* ctx, int type, int arg, void* ptr)
{
    int Res = 0;
    // Additional implementation here
    return Res;
}

void EVP_ASYM_CIPHER_free(EVP_ASYM_CIPHER* ctx)
{
    // Additional implementation here
}

int OSSL_PARAM_get_size_t(const OSSL_PARAM* param, size_t* val)
{
    int Res = 0;
    // Additional implementation here
    return Res;
}

int SSL_get_shutdown(const SSL* ssl) {
    int Res = 0;
    sf_set_must_be_not_null(ssl, SSL_GET_SHUTDOWN_OF_NULL);
    sf_set_errno_if(Res == 0, SSL_GET_SHUTDOWN_FAILURE);
    return Res;
}

pem_password_cb* SSL_get_default_passwd_cb(SSL* ssl) {
    pem_password_cb* Res = NULL;
    sf_set_must_be_not_null(ssl, SSL_GET_DEFAULT_PASSWD_CB_OF_NULL);
    sf_set_possible_null(Res);
    return Res;
}

int EC_GROUP_set_curve_GF2m(EC_GROUP* group, const BIGNUM* a, const BIGNUM* b, const BIGNUM* x, BN_CTX* ctx) {
    int Res = 0;
    sf_set_must_be_not_null(group, EC_GROUP_SET_CURVE_GF2M_GROUP_NULL);
    sf_set_must_be_not_null(a, EC_GROUP_SET_CURVE_GF2M_A_NULL);
    sf_set_must_be_not_null(b, EC_GROUP_SET_CURVE_GF2M_B_NULL);
    sf_set_must_be_not_null(x, EC_GROUP_SET_CURVE_GF2M_X_NULL);
    sf_set_must_be_not_null(ctx, EC_GROUP_SET_CURVE_GF2M_CTX_NULL);
    sf_set_errno_if(Res == 0, EC_GROUP_SET_CURVE_GF2M_FAILURE);
    return Res;
}

void ERR_remove_state(unsigned long pid) {
    sf_set_must_be_not_null(pid, ERR_REMOVE_STATE_PID_NULL);
}

int SSL_is_server(const SSL* ssl) {
    int Res = 0;
    sf_set_must_be_not_null(ssl, SSL_IS_SERVER_OF_NULL);
    sf_set_errno_if(Res == 0, SSL_IS_SERVER_FAILURE);
    return Res;
}
void ERR_add_error_txt(const char* a, const char* b);

void SSL_CTX_set_psk_find_session_callback(SSL_CTX* a, SSL_psk_find_session_cb_func b);

BIGNUM* BN_get_rfc3526_prime_3072(BIGNUM* a);

int DSA_meth_get_bn_mod_exp(const DSA_METHOD* a, DSA* b, BIGNUM* c, const BIGNUM* d, const BIGNUM* e, BN_CTX* f, BN_MONT_CTX* g);

X509* X509_STORE_CTX_get0_cert(const X509_STORE_CTX* a);


const EVP_CIPHER* EVP_camellia_128_cbc()
{
    const EVP_CIPHER* Res = NULL;
    Res = EVP_camellia_128_cbc();
    sf_set_trusted_sink_ptr(Res);
    return Res;
}

void BIO_set_next(BIO* a, BIO* b)
{
    sf_set_must_not_be_null(a);
    sf_set_must_not_be_null(b);
    BIO_set_next(a, b);
}

OPENSSL_STACK* OPENSSL_sk_new_null()
{
    OPENSSL_STACK* Res = NULL;
    Res = OPENSSL_sk_new_null();
    sf_new(Res, STACK_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    return Res;
}

int EVP_PKEY_asn1_get_count()
{
    int Res = 0;
    Res = EVP_PKEY_asn1_get_count();
    sf_set_possible_negative(Res);
    return Res;
}

int EVP_PKEY_get_raw_private_key(const EVP_PKEY* pkey, unsigned char* buf, size_t* len)
{
    int Res = 0;
    sf_set_must_not_be_null(pkey);
    sf_set_must_not_be_null(buf);
    sf_set_must_not_be_null(len);
    Res = EVP_PKEY_get_raw_private_key(pkey, buf, len);
    sf_set_alloc_possible_null(Res);
    return Res;
}

long ASN1_ENUMERATED_get(const ASN1_ENUMERATED* a) {
    long res = 0;
    sf_set_must_be_not_null(a, ASN1_ENUMERATED_NULL);
    sf_set_trusted_sink_ptr(a);
    sf_overwrite(res);
    return res;
}

void X509_REQ_set0_distinguishing_id(X509_REQ* req, ASN1_OCTET_STRING* id) {
    sf_set_must_be_not_null(req, X509_REQ_NULL);
    sf_set_must_be_not_null(id, ASN1_OCTET_STRING_NULL);
    sf_set_trusted_sink_ptr(id);
}

void CRL_DIST_POINTS_free(CRL_DIST_POINTS* points) {
    sf_set_must_be_not_null(points, CRL_DIST_POINTS_NULL);
    sf_delete(points, CRL_DIST_POINTS_MEMORY_CATEGORY);
}

BIO* BIO_new_dgram(int fd, int close_flag) {
    BIO* res = NULL;
    sf_set_must_be_not_null(fd, BIO_FD_NULL);
    sf_set_trusted_sink_int(fd);
    sf_malloc_arg(res, sizeof(BIO), BIO_MEMORY_CATEGORY);
    sf_overwrite(res);
    return res;
}

void PROFESSION_INFO_set0_addProfessionInfo(PROFESSION_INFO* info, ASN1_OCTET_STRING* data) {
    sf_set_must_be_not_null(info, PROFESSION_INFO_NULL);
    sf_set_must_be_not_null(data, ASN1_OCTET_STRING_NULL);
    sf_set_trusted_sink_ptr(data);
}
int RSA_get_multi_prime_extra_count(const RSA* rsa);

X509_STORE_CTX_lookup_crls_fn X509_STORE_get_lookup_crls(const X509_STORE* store);

int DSA_test_flags(const DSA* dsa, int flags);

int BN_add_word(BIGNUM* bn, unsigned long w);

RSA* RSA_new_method(ENGINE* engine);

X509_LOOKUP_get_by_alias_fn X509_LOOKUP_meth_get_get_by_alias(const X509_LOOKUP_METHOD* method);

int EVP_PKEY_decapsulate(EVP_PKEY_CTX* ctx, unsigned char* out, size_t* outlen, const unsigned char* in, size_t inlen);

void* OPENSSL_sk_shift(OPENSSL_STACK* st);

const ASN1_INTEGER* X509_get0_authority_serial(X509* x);

void OCSP_SIGNATURE_free(OCSP_SIGNATURE* sig);


int X509_STORE_load_file_ex(X509_STORE *ctx, const char *file, OSSL_LIB_CTX *libctx, const char *propq) {
    int res = 0;
    sf_set_trusted_sink_int(file);
    sf_set_trusted_sink_int(propq);
    sf_set_tainted(ctx);
    sf_tocttou_check(file);
    sf_set_must_not_be_null(ctx);
    sf_set_possible_null(res);
    return res;
}

long SSL_CTX_set_timeout(SSL_CTX *ctx, long t) {
    long res = 0;
    sf_set_must_not_be_null(ctx);
    sf_set_possible_null(res);
    return res;
}

BIO_METHOD* BIO_meth_new(int type, const char *name) {
    BIO_METHOD *res = NULL;
    sf_set_trusted_sink_int(type);
    sf_set_trusted_sink_int(name);
    sf_set_possible_null(res);
    return res;
}

X509_LOOKUP_METHOD* X509_LOOKUP_file() {
    X509_LOOKUP_METHOD *res = NULL;
    sf_set_possible_null(res);
    return res;
}

int EVP_RAND_names_do_all(const EVP_RAND *rand, void (const char *name, void *arg) (const char *, void *), void *arg) {
    int res = 0;
    sf_set_must_not_be_null(rand);
    sf_set_must_not_be_null(arg);
    sf_set_possible_null(res);
    return res;
}

ct_log_entry_type_t SCT_get_log_entry_type(const SCT* sct) {
    ct_log_entry_type_t Res = 0;
    sf_set_must_be_not_null(sct, "SCT");
    sf_set_trusted_sink_int(Res);
    sf_overwrite(Res);
    return Res;
}

int EVP_DecodeFinal(EVP_ENCODE_CTX* ctx, unsigned char* out, int* outl) {
    int Res = 0;
    sf_set_must_be_not_null(ctx, "EVP_ENCODE_CTX");
    sf_set_must_be_not_null(out, "out");
    sf_set_must_be_not_null(outl, "outl");
    sf_set_trusted_sink_int(Res);
    sf_overwrite(Res);
    return Res;
}

int EVP_RAND_enable_locking(EVP_RAND_CTX* ctx) {
    int Res = 0;
    sf_set_must_be_not_null(ctx, "EVP_RAND_CTX");
    sf_set_trusted_sink_int(Res);
    sf_overwrite(Res);
    return Res;
}

int SSL_CTX_set_srp_client_pwd_callback(SSL_CTX* ctx,  char* (SSL*, void*)* cb) {
    int Res = 0;
    sf_set_must_be_not_null(ctx, "SSL_CTX");
    sf_set_trusted_sink_int(Res);
    sf_overwrite(Res);
    return Res;
}

const EVP_CIPHER* EVP_des_ede3_ecb() {
    const EVP_CIPHER* Res = NULL;
    sf_set_trusted_sink_ptr(Res);
    sf_overwrite(Res);
    return Res;
}

ENGINE_GEN_INT_FUNC_PTR ENGINE_get_finish_function(const ENGINE* engine) {
    ENGINE_GEN_INT_FUNC_PTR Res = NULL;
    sf_set_must_be_not_null(engine, FINISH_FUNCTION_OF_ENGINE);
    Res = engine->finish_function;
    sf_set_possible_null(Res);
    return Res;
}

X509_LOOKUP_get_by_issuer_serial_fn X509_LOOKUP_meth_get_get_by_issuer_serial(const X509_LOOKUP_METHOD* method) {
    X509_LOOKUP_get_by_issuer_serial_fn Res = NULL;
    sf_set_must_be_not_null(method, GET_BY_ISSUER_SERIAL_OF_LOOKUP_METHOD);
    Res = method->get_by_issuer_serial;
    sf_set_possible_null(Res);
    return Res;
}

void SSL_set_allow_early_data_cb(SSL* s, SSL_allow_early_data_cb_fn cb, void* arg) {
    sf_set_must_be_not_null(s, SSL_SET_ALLOW_EARLY_DATA_CB);
    sf_set_tainted(arg);
    s->allow_early_data_cb = cb;
    s->allow_early_data_cb_arg = arg;
}

const BIO_METHOD* BIO_s_file() {
    const BIO_METHOD* Res = NULL;
    Res = &methods_filep;
    sf_set_possible_null(Res);
    return Res;
}

int OSSL_HTTP_REQ_CTX_set_expected(OSSL_HTTP_REQ_CTX* ctx, const char* expected, int len, int type, int recursion) {
    int Res = 0;
    sf_set_must_be_not_null(ctx, SET_EXPECTED_OF_HTTP_REQ_CTX);
    sf_set_tainted(expected);
    sf_buf_size_limit(expected, len);
    Res = ossl_http_req_ctx_set_expected(ctx, expected, len, type, recursion);
    sf_set_errno_if(Res <= 0);
    return Res;
}
void SSL_SESSION_get0_alpn_selected(const SSL_SESSION* sess, const unsigned char** data, size_t* len);

const OCSP_RESPDATA* OCSP_resp_get0_respdata(const OCSP_BASICRESP* bs);

const char* OPENSSL_cipher_name(const char* name);

void* DH_meth_get0_app_data(const DH_METHOD* dhm);

void CRYPTO_THREAD_lock_free(CRYPTO_RWLOCK* lock);


const unsigned char* EVP_CIPHER_CTX_original_iv(const EVP_CIPHER_CTX* ctx) {
    const unsigned char* Res = NULL;
    Res = ctx->oiv;
    sf_set_tainted(Res);
    return Res;
}

X509_ALGOR* PKCS5_pbkdf2_set(int iter, unsigned char* salt, int saltlen, int keylen, int nid) {
    X509_ALGOR* Res = NULL;
    sf_password_use(salt, saltlen);
    sf_set_must_be_not_null(salt, "Salt");
    sf_set_must_be_not_null(Res, "PKCS5_pbkdf2_set");
    return Res;
}

int (RSA*)* RSA_meth_get_finish(const RSA_METHOD* rsa) {
    int (RSA*)* Res = NULL;
    Res = rsa->finish;
    sf_set_possible_null(Res);
    return Res;
}

void SSL_set_default_passwd_cb(SSL* ssl, pem_password_cb* cb) {
    sf_password_set(cb);
    ssl->default_passwd_callback = cb;
}

int SSL_CTX_use_certificate_chain_file(SSL_CTX* ctx, const char* file) {
    int Res = 0;
    sf_tocttou_check(file);
    sf_set_must_not_be_release(ctx);
    Res = ctx->use_certificate_chain_file(ctx, file);
    sf_set_errno_if(Res <= 0);
    return Res;
}
int X509_VERIFY_PARAM_clear_flags(X509_VERIFY_PARAM* param, unsigned long flags);

const OSSL_PARAM* EVP_PKEY_settable_params(const EVP_PKEY* pkey);

RSA* RSA_generate_key(int bits, unsigned long e_value, void (int, int, void*);

X509_REQ* X509_REQ_new_ex(OSSL_LIB_CTX* libctx, const char* propq);

const EVP_CIPHER* EVP_aes_256_cbc_hmac_sha256();


void OPENSSL_LH_free(OPENSSL_LHASH* lh)
{
    if (lh != NULL)
    {
        sf_delete(lh, PAGES_MEMORY_CATEGORY);
    }
}

const OSSL_PARAM* EVP_RAND_settable_ctx_params(const EVP_RAND* rand)
{
    const OSSL_PARAM* res = NULL;
    if (rand != NULL)
    {
        res = rand->settable_ctx_params;
    }
    return res;
}

int OSSL_PARAM_get_octet_ptr(const OSSL_PARAM* param, const void** val, size_t* len)
{
    int res = 0;
    if (param != NULL && val != NULL && len != NULL)
    {
        *val = param->data;
        *len = param->data_size;
        res = 1;
    }
    return res;
}

int X509_REQ_verify(X509_REQ* req, EVP_PKEY* pkey)
{
    int res = 0;
    if (req != NULL && pkey != NULL)
    {
        res = req->verify(req, pkey);
    }
    return res;
}

ENGINE_GEN_INT_FUNC_PTR ENGINE_get_destroy_function(const ENGINE* e)
{
    ENGINE_GEN_INT_FUNC_PTR res = NULL;
    if (e != NULL)
    {
        res = e->destroy;
    }
    return res;
}

const ASN1_STRING* NAMING_AUTHORITY_get0_authorityText(const NAMING_AUTHORITY* naming_authority) {
    const ASN1_STRING* Res = NULL;
    sf_set_must_be_not_null(naming_authority, AUTHORITY_NOT_NULL);
    Res = naming_authority->authorityText;
    sf_set_possible_null(Res, AUTHORITY_TEXT_NULL);
    return Res;
}

int BN_mod_exp(BIGNUM* r, const BIGNUM* a, const BIGNUM* p, const BIGNUM* m, BN_CTX* ctx) {
    int Res = 0;
    sf_set_must_be_not_null(r, R_NOT_NULL);
    sf_set_must_be_not_null(a, A_NOT_NULL);
    sf_set_must_be_not_null(p, P_NOT_NULL);
    sf_set_must_be_not_null(m, M_NOT_NULL);
    sf_set_must_be_not_null(ctx, CTX_NOT_NULL);
    Res = BN_mod_exp_mont(r, a, p, m, ctx, NULL);
    sf_set_errno_if(Res, ERRNO_IF_NEGATIVE);
    return Res;
}

int RSA_padding_check_PKCS1_OAEP_mgf1(unsigned char* to, int tlen, const unsigned char* from, int flen, int num, const unsigned char* param, int plen, const EVP_MD* md, const EVP_MD* mgf1md) {
    int Res = 0;
    sf_set_must_be_not_null(to, TO_NOT_NULL);
    sf_set_must_be_not_null(from, FROM_NOT_NULL);
    sf_set_must_be_not_null(param, PARAM_NOT_NULL);
    sf_set_must_be_not_null(md, MD_NOT_NULL);
    sf_set_must_be_not_null(mgf1md, MGF1MD_NOT_NULL);
    Res = RSA_padding_check_PKCS1_OAEP(to, tlen, from, flen, num, param, plen, md, mgf1md);
    sf_set_errno_if(Res, ERRNO_IF_NEGATIVE);
    return Res;
}

X509_EXTENSION* X509v3_delete_ext(stack_st_X509_EXTENSION* x, int loc) {
    X509_EXTENSION* Res = NULL;
    sf_set_must_be_not_null(x, X_NOT_NULL);
    Res = sk_X509_EXTENSION_delete(x, loc);
    sf_set_possible_null(Res, EXTENSION_NULL);
    return Res;
}

void PROFESSION_INFO_set0_namingAuthority(PROFESSION_INFO* info, NAMING_AUTHORITY* naming_authority) {
    sf_set_must_be_not_null(info, INFO_NOT_NULL);
    sf_set_must_be_not_null(naming_authority, AUTHORITY_NOT_NULL);
    info->namingAuthority = naming_authority;
}

void NOTICEREF_free(NOTICEREF* ptr) {
    sf_delete(ptr, NOTICEREF_CATEGORY);
}

int i2d_PBKDF2PARAM(const PBKDF2PARAM* a, unsigned char** pp) {
    int res = 0;
    sf_set_trusted_sink_int(a->length);
    sf_malloc_arg(pp, a->length);
    sf_overwrite(*pp, a->length);
    sf_new(*pp, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(*pp, pp);
    res = a->length;
    sf_set_possible_null(res);
    return res;
}

void OPENSSL_LH_doall(OPENSSL_LHASH* lh, OPENSSL_LH_DOALL_FUNC func) {
    sf_set_tainted(lh);
    sf_set_tainted(func);
    // No return value or assignment, so no need to mark anything
}

void* OPENSSL_sk_delete_ptr(OPENSSL_STACK* st, const void* ptr) {
    void* res = NULL;
    sf_set_tainted(st);
    sf_set_tainted(ptr);
    // No direct assignment, so no need to mark anything
    return res;
}

int PEM_write_SSL_SESSION(FILE* fp, const SSL_SESSION* sess) {
    int res = 0;
    sf_set_must_be_not_null(fp, FREE_OF_NULL);
    sf_set_must_be_not_null(sess, FREE_OF_NULL);
    sf_set_tainted(fp);
    sf_set_tainted(sess);
    sf_set_errno_if(res == 0);
    sf_no_errno_if(res != 0);
    return res;
}

EVP_MAC_CTX* EVP_MAC_CTX_dup(const EVP_MAC_CTX* ctx) {
    EVP_MAC_CTX* Res = NULL;
    sf_set_trusted_sink_ptr(ctx);
    sf_set_alloc_possible_null(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_bitcopy(Res, ctx);
    return Res;
}

void NETSCAPE_CERT_SEQUENCE_free(NETSCAPE_CERT_SEQUENCE* a) {
    sf_set_must_be_not_null(a, FREE_OF_NULL);
    sf_delete(a, MALLOC_CATEGORY);
    sf_lib_arg_type(a, "MallocCategory");
}

int X509_CRL_set1_nextUpdate(X509_CRL* crl, const ASN1_TIME* tm) {
    sf_set_must_be_not_null(crl, SET_NEXT_UPDATE_OF_NULL);
    sf_set_must_be_not_null(tm, SET_NEXT_UPDATE_TM_NULL);
    return 1;
}

const char* SSL_alert_type_string(int value) {
    const char* Res = NULL;
    sf_set_possible_null(Res);
    return Res;
}

ECDSA_SIG* ECDSA_do_sign_ex(const unsigned char* dgst, int dlen, const BIGNUM* in_kinv, const BIGNUM* in_r, EC_KEY* key) {
    ECDSA_SIG* Res = NULL;
    sf_set_alloc_possible_null(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    return Res;
}

int X509_LOOKUP_meth_set_ctrl(X509_LOOKUP_METHOD* method, X509_LOOKUP_ctrl_fn ctrl_fn) {
    int Res = 0;
    sf_set_trusted_sink_ptr(method);
    sf_set_trusted_sink_ptr(ctrl_fn);
    Res = X509_LOOKUP_meth_set_ctrl(method, ctrl_fn);
    sf_set_errno_if(Res == 0);
    return Res;
}

int DSA_generate_parameters_ex(DSA* dsa, int bits, const unsigned char* seed_in, int seed_len, int* counter_ret, unsigned long* h_ret, BN_GENCB* cb) {
    int Res = 0;
    sf_set_trusted_sink_int(bits);
    sf_set_trusted_sink_ptr(seed_in);
    sf_set_trusted_sink_ptr(counter_ret);
    sf_set_trusted_sink_ptr(h_ret);
    sf_set_trusted_sink_ptr(cb);
    Res = DSA_generate_parameters_ex(dsa, bits, seed_in, seed_len, counter_ret, h_ret, cb);
    sf_set_errno_if(Res == 0);
    return Res;
}

const char* EVP_KEYMGMT_get0_description(const EVP_KEYMGMT* keymgmt) {
    const char* Res = NULL;
    sf_set_trusted_sink_ptr(keymgmt);
    Res = EVP_KEYMGMT_get0_description(keymgmt);
    sf_set_possible_null(Res);
    return Res;
}

int PEM_write_bio_PKCS7_stream(BIO* bio, PKCS7* p7, BIO* stream_out, int flags) {
    int Res = 0;
    sf_set_trusted_sink_ptr(bio);
    sf_set_trusted_sink_ptr(p7);
    sf_set_trusted_sink_ptr(stream_out);
    sf_set_trusted_sink_int(flags);
    Res = PEM_write_bio_PKCS7_stream(bio, p7, stream_out, flags);
    sf_set_errno_if(Res == 0);
    return Res;
}

void EVP_MD_CTX_free(EVP_MD_CTX* ctx) {
    sf_set_trusted_sink_ptr(ctx);
    EVP_MD_CTX_free(ctx);
}
void EVP_PKEY_meth_get_copy(const EVP_PKEY_METHOD *pmeth, int (**copy);

int i2d_PROXY_CERT_INFO_EXTENSION(const PROXY_CERT_INFO_EXTENSION *pci, unsigned char **pp);

BIGNUM* BN_get_rfc3526_prime_4096(BIGNUM *bn);

int BN_to_montgomery(BIGNUM *r, const BIGNUM *a, BN_MONT_CTX *mont, BN_CTX *ctx);

void OPENSSL_LH_node_usage_stats_bio(const OPENSSL_LHASH *lh, BIO *out);


int OSSL_PARAM_modified(const OSSL_PARAM* param) {
    int res = 0;
    sf_set_must_be_not_null(param, "OSSL_PARAM");
    res = param->modified;
    sf_overwrite(res);
    return res;
}

const SSL_METHOD* TLSv1_2_client_method() {
    const SSL_METHOD* res = NULL;
    res = TLSv1_2_client_method();
    sf_set_possible_null(res);
    return res;
}

int i2d_RSA_PUBKEY_fp(FILE* fp, const RSA* rsa) {
    int res = 0;
    sf_set_must_be_not_null(fp, "FILE");
    sf_set_must_be_not_null(rsa, "RSA");
    res = i2d_RSA_PUBKEY_fp(fp, rsa);
    sf_set_errno_if(res <= 0);
    return res;
}

int i2d_PKCS7(const PKCS7* p7, unsigned char** pp) {
    int res = 0;
    sf_set_must_be_not_null(p7, "PKCS7");
    sf_set_must_be_not_null(pp, "unsigned char");
    res = i2d_PKCS7(p7, pp);
    sf_set_errno_if(res <= 0);
    return res;
}

OCSP_CRLID* d2i_OCSP_CRLID(OCSP_CRLID** crlid, const unsigned char** in, long len) {
    OCSP_CRLID* res = NULL;
    sf_set_must_be_not_null(crlid, "OCSP_CRLID");
    sf_set_must_be_not_null(in, "unsigned char");
    res = d2i_OCSP_CRLID(crlid, in, len);
    sf_set_possible_null(res);
    return res;
}

char* UI_construct_prompt(UI* ui, const char* str1, const char* str2) {
    char* Res = NULL;
    sf_set_trusted_sink_int(strlen(str1) + strlen(str2) + 1);
    Res = malloc(strlen(str1) + strlen(str2) + 1);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_lib_arg_type(Res, "MallocCategory");
    sf_bitcopy(Res, str1);
    sf_append_string(Res, str2);
    sf_null_terminated(Res);
    return Res;
}

void* EVP_PKEY_get_ex_data(const EVP_PKEY* pkey, int idx) {
    void* Res = NULL;
    Res = CRYPTO_get_ex_data(&pkey->ex_data, idx);
    sf_set_possible_null(Res);
    return Res;
}

void BN_clear(BIGNUM* a) {
    if (a != NULL) {
        BN_free(a);
    }
}

int EVP_CIPHER_get_type(const EVP_CIPHER* cipher) {
    int Res = 0;
    Res = cipher->type;
    return Res;
}

void* UI_get0_user_data(UI* ui) {
    void* Res = NULL;
    Res = ui->user_data;
    sf_set_possible_null(Res);
    return Res;
}

PKEY_USAGE_PERIOD* PKEY_USAGE_PERIOD_new()
{
    PKEY_USAGE_PERIOD* Res = NULL;
    Res = (PKEY_USAGE_PERIOD*)sf_malloc_arg(sizeof(PKEY_USAGE_PERIOD));
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    return Res;
}

X509_STORE_CTX* X509_STORE_CTX_new_ex(OSSL_LIB_CTX* libctx, const char* propq)
{
    X509_STORE_CTX* Res = NULL;
    Res = (X509_STORE_CTX*)sf_malloc_arg(sizeof(X509_STORE_CTX));
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    return Res;
}

void* RSA_get_ex_data(const RSA* r, int idx)
{
    void* Res = NULL;
    Res = (void*)sf_malloc_arg(sizeof(void));
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    return Res;
}

unsigned long X509_subject_name_hash(X509* x)
{
    unsigned long Res = 0;
    Res = (unsigned long)sf_malloc_arg(sizeof(unsigned long));
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    return Res;
}

int EVP_MD_meth_get_app_datasize(const EVP_MD* md)
{
    int Res = 0;
    Res = (int)sf_malloc_arg(sizeof(int));
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    return Res;
}

void SHA512_Final(unsigned char* md, SHA512_CTX* ctx) {
    int res = 0;
    sf_set_trusted_sink_int(md);
    sf_set_trusted_sink_ptr(ctx);
    sf_set_errno_if(res == 0);
    sf_no_errno_if(res == 1);
}

void EVP_MAC_names_do_all(const EVP_MAC* mac, void (const char*, void*)* do_all, void* arg) {
    int res = 0;
    sf_set_trusted_sink_ptr(mac);
    sf_set_trusted_sink_ptr(do_all);
    sf_set_trusted_sink_ptr(arg);
    sf_set_errno_if(res == 0);
    sf_no_errno_if(res == 1);
}

void RSA_meth_get_verify(const RSA_METHOD* meth) {
    int res = 0;
    sf_set_trusted_sink_ptr(meth);
    sf_set_errno_if(res == 0);
    sf_no_errno_if(res == 1);
}

void DSA_get0_pub_key(const DSA* dsa) {
    const BIGNUM* res = NULL;
    sf_set_trusted_sink_ptr(dsa);
    sf_set_possible_null(res);
    sf_set_errno_if(res == NULL);
    sf_no_errno_if(res != NULL);
}

void EVP_CIPHER_CTX_get_params(EVP_CIPHER_CTX* ctx, OSSL_PARAM params[]) {
    int res = 0;
    sf_set_trusted_sink_ptr(ctx);
    sf_set_trusted_sink_ptr(params);
    sf_set_errno_if(res == 0);
    sf_no_errno_if(res == 1);
}
int SSL_CTX_add_client_custom_ext(SSL_CTX*, unsigned int, custom_ext_add_cb, custom_ext_free_cb, void*, custom_ext_parse_cb, void*);

unsigned long X509_issuer_name_hash(X509*);

unsigned long BN_mod_word(const BIGNUM*, unsigned long);

void PKCS7_ISSUER_AND_SERIAL_free(PKCS7_ISSUER_AND_SERIAL*);

void BIO_set_shutdown(BIO*, int);


void ENGINE_set_default_DH(ENGINE* engine) {
    int res = 0;
    sf_set_trusted_sink_int(engine);
    sf_set_errno_if(res == 0, ENGINE_R_NO_DEFAULT_DH);
}

void X509_STORE_set_default_paths_ex(X509_STORE* store, OSSL_LIB_CTX* libctx, const char* path) {
    int res = 0;
    sf_set_trusted_sink_int(store);
    sf_set_trusted_sink_int(libctx);
    sf_set_errno_if(res == 0, X509_R_FAILED_TO_SET_DEFAULT_PATHS);
}

void ASN1_item_verify(const ASN1_ITEM* it, const X509_ALGOR* algor, const ASN1_BIT_STRING* signature, const void* data, EVP_PKEY* pkey) {
    int res = 0;
    sf_set_trusted_sink_int(it);
    sf_set_trusted_sink_int(algor);
    sf_set_trusted_sink_int(signature);
    sf_set_trusted_sink_int(data);
    sf_set_trusted_sink_int(pkey);
    sf_set_errno_if(res <= 0, ASN1_R_VERIFICATION_FAILURE);
}

void BIO_meth_free(BIO_METHOD* biom) {
    sf_set_trusted_sink_int(biom);
    sf_delete(biom, BIO_METHOD_CATEGORY);
}

void X509_NAME_free(X509_NAME* name) {
    sf_set_trusted_sink_int(name);
    sf_delete(name, X509_NAME_CATEGORY);
}

int EVP_PKEY_CTX_get_rsa_padding(EVP_PKEY_CTX *ctx, int *pad_mode) {
    int Res = 0;
    sf_set_tainted(ctx);
    sf_set_tainted(pad_mode);
    sf_set_must_be_not_null(ctx, "EVP_PKEY_CTX");
    sf_set_must_be_not_null(pad_mode, "int");
    Res = EVP_PKEY_CTX_get_rsa_padding(ctx, pad_mode);
    sf_set_errno_if(Res <= 0);
    sf_overwrite(pad_mode);
    return Res;
}

void EVP_RAND_do_all_provided(OSSL_LIB_CTX *libctx, void (*fn)(EVP_RAND *, void *), void *arg) {
    sf_set_tainted(libctx);
    sf_set_tainted(fn);
    sf_set_tainted(arg);
    sf_set_must_be_not_null(libctx, "OSSL_LIB_CTX");
    EVP_RAND_do_all_provided(libctx, fn, arg);
}

long SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg) {
    long Res = 0;
    sf_set_tainted(ctx);
    sf_set_tainted(parg);
    sf_set_must_be_not_null(ctx, "SSL_CTX");
    Res = SSL_CTX_ctrl(ctx, cmd, larg, parg);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int DSA_print_fp(FILE *fp, const DSA *dsa, int off) {
    int Res = 0;
    sf_set_tainted(fp);
    sf_set_tainted(dsa);
    sf_set_must_be_not_null(fp, "FILE");
    sf_set_must_be_not_null(dsa, "DSA");
    Res = DSA_print_fp(fp, dsa, off);
    sf_set_errno_if(Res <= 0);
    return Res;
}

PKCS7* d2i_PKCS7(PKCS7 **a, const unsigned char **in, long len) {
    PKCS7 *Res = NULL;
    sf_set_tainted(a);
    sf_set_tainted(in);
    sf_set_must_be_not_null(a, "PKCS7");
    sf_set_must_be_not_null(in, "unsigned char");
    Res = d2i_PKCS7(a, in, len);
    sf_set_errno_if(Res == NULL);
    return Res;
}

const char* OpenSSL_version(int type) {
    const char* Res = NULL;
    Res = OpenSSL_version(type);
    sf_set_trusted_sink_int(type);
    sf_set_errno_if(Res == NULL);
    return Res;
}

int i2d_DISPLAYTEXT(const ASN1_STRING* a, unsigned char** pp) {
    int Res = 0;
    Res = i2d_DISPLAYTEXT(a, pp);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int i2d_EC_PUBKEY_bio(BIO* bp, const EC_KEY* x) {
    int Res = 0;
    Res = i2d_EC_PUBKEY_bio(bp, x);
    sf_set_errno_if(Res <= 0);
    return Res;
}

OSSL_PARAM OSSL_PARAM_construct_utf8_ptr(const char* key, char** val, size_t size) {
    OSSL_PARAM Res = {NULL, 0, NULL, 0};
    Res = OSSL_PARAM_construct_utf8_ptr(key, val, size);
    sf_set_trusted_sink_ptr(val);
    sf_set_trusted_sink_int(size);
    return Res;
}

unsigned int OPENSSL_version_patch() {
    unsigned int Res = 0;
    Res = OPENSSL_version_patch();
    return Res;
}

void EC_POINT_hex2point(const EC_GROUP *group, const char *hex, EC_POINT *point, BN_CTX *ctx) {
    EC_POINT *Res = NULL;
    sf_set_trusted_sink_int(hex);
    sf_set_trusted_sink_ptr(ctx);
    sf_set_trusted_sink_ptr(group);
    sf_set_trusted_sink_ptr(point);
    sf_set_alloc_possible_null(Res);
    sf_lib_arg_type(Res, "ECPoint");
    return Res;
}

void SSL_CTX_set_cookie_verify_cb(SSL_CTX *ctx, int (*cb) (SSL *, const unsigned char *, unsigned int)) {
    sf_set_trusted_sink_ptr(ctx);
    sf_set_trusted_sink_ptr(cb);
}

int SSL_CTX_set_default_verify_file(SSL_CTX *ctx) {
    int Res = 0;
    sf_set_trusted_sink_ptr(ctx);
    sf_set_errno_if(Res, -1);
    return Res;
}

EVP_PKEY* PEM_read_bio_PUBKEY(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u) {
    EVP_PKEY *Res = NULL;
    sf_set_trusted_sink_ptr(bp);
    sf_set_trusted_sink_ptr(x);
    sf_set_trusted_sink_ptr(cb);
    sf_set_trusted_sink_ptr(u);
    sf_set_alloc_possible_null(Res);
    sf_lib_arg_type(Res, "EVPKey");
    return Res;
}

int ASN1_TIME_check(const ASN1_TIME *time) {
    int Res = 0;
    sf_set_trusted_sink_ptr(time);
    sf_set_errno_if(Res, -1);
    return Res;
}
void NETSCAPE_SPKI_free(NETSCAPE_SPKI* spki);

void SSL_CTX_set_record_padding_callback(SSL_CTX* ctx, size_t (*cb);

const PROFESSION_INFOS* ADMISSIONS_get0_professionInfos(const ADMISSIONS* admissions);

int EVP_DigestSignInit_ex(EVP_MD_CTX* ctx, EVP_PKEY_CTX** pctx, const char* md, OSSL_LIB_CTX* libctx, const char* propq, EVP_PKEY* pkey, const OSSL_PARAM params[]);

X509_STORE_CTX_get_issuer_fn X509_STORE_CTX_get_get_issuer(const X509_STORE_CTX* ctx);

BIGNUM* BN_bin2bn(const unsigned char* s, int len, BIGNUM* ret);

void CTLOG_STORE_free(CTLOG_STORE* store);

void SSL_CTX_set1_cert_store(SSL_CTX* ctx, X509_STORE* store);

int X509_REQ_sign(X509_REQ* req, EVP_PKEY* pkey, const EVP_MD* md);

void X509_STORE_set_get_issuer(X509_STORE* ctx, X509_STORE_CTX_get_issuer_fn get_issuer);

Here are the specifications for the functions:

1. void EVP_MD_CTX_set_flags(EVP_MD_CTX* ctx, int flags)
```
sf_set_trusted_sink_int(flags);
EVP_MD_CTX_set_flags(ctx, flags);
```

2. int BN_print_fp(FILE* fp, const BIGNUM* bn)
```
sf_set_must_not_be_null(fp);
sf_set_must_not_be_null(bn);
int res = BN_print_fp(fp, bn);
sf_set_errno_if(res <= 0);
return res;
```

3. X509_CRL* PEM_read_X509_CRL(FILE* fp, X509_CRL** crl, pem_password_cb* cb, void* u)
```
sf_set_must_not_be_null(fp);
sf_set_must_not_be_null(crl);
X509_CRL* res = PEM_read_X509_CRL(fp, crl, cb, u);
sf_set_errno_if(res == NULL);
return res;
```

4. int ASN1_TIME_set_string(ASN1_TIME* s, const char* str)
```
sf_set_must_not_be_null(s);
sf_set_must_not_be_null(str);
int res = ASN1_TIME_set_string(s, str);
sf_set_errno_if(res == 0);
return res;
```

5. const EVP_CIPHER* EVP_aria_192_cfb8()
```
const EVP_CIPHER* res = EVP_aria_192_cfb8();
sf_set_must_not_be_null(res);
return res;
```
void EVP_PKEY_verify_init_ex(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[]) {
    int res = 0;
    sf_set_trusted_sink_int(ctx);
    sf_set_trusted_sink_ptr(params);
    sf_set_errno_if(res == 0);
    sf_no_errno_if(res == 1);
}

void ERR_get_next_error_library() {
    int res = 0;
    sf_set_errno_if(res == 0);
    sf_no_errno_if(res != 0);
}

void SSL_set_purpose(SSL *ssl, int purpose) {
    int res = 0;
    sf_set_trusted_sink_int(ssl);
    sf_set_errno_if(res == 0);
    sf_no_errno_if(res == 1);
}

void X509_REQ_add_extensions_nid(X509_REQ *req, const stack_st_X509_EXTENSION *exts, int nid) {
    int res = 0;
    sf_set_trusted_sink_int(req);
    sf_set_trusted_sink_ptr(exts);
    sf_set_errno_if(res == 0);
    sf_no_errno_if(res == 1);
}

void BN_check_prime(const BIGNUM *b, BN_CTX *ctx, BN_GENCB *cb) {
    int res = 0;
    sf_set_trusted_sink_int(b);
    sf_set_trusted_sink_ptr(ctx);
    sf_set_trusted_sink_ptr(cb);
    sf_set_errno_if(res == 0);
    sf_no_errno_if(res == 1);
}
int EVP_MD_CTX_reset(EVP_MD_CTX* ctx);

void X509_LOOKUP_free(X509_LOOKUP* lookup);

OCSP_ONEREQ* d2i_OCSP_ONEREQ(OCSP_ONEREQ** req, const unsigned char** in, long len);


sf_set_must_be_not_null(rnd, RAND_RANGE_NULL);
sf_set_must_be_not_null(range, RAND_RANGE_NULL);
BIGNUM *Res = NULL;
Res = BN_new();
sf_overwrite(Res);
sf_new(Res, MALLOC_CATEGORY);
sf_set_alloc_possible_null(Res);
int ret = BN_priv_rand_range(Res, range);
if (ret == 1) {
    BN_copy(rnd, Res);
    sf_overwrite(rnd);
}
BN_free(Res);
return ret;

sf_set_must_be_not_null(e, ENGINE_NULL);
sf_set_must_be_not_null(defns, ENGINE_DEFN_NULL);
ENGINE_CMD_DEFN *Res = NULL;
Res = (ENGINE_CMD_DEFN *)OPENSSL_malloc(sizeof(ENGINE_CMD_DEFN));
sf_overwrite(Res);
sf_new(Res, MALLOC_CATEGORY);
sf_set_alloc_possible_null(Res);
int ret = ENGINE_set_cmd_defns(e, Res);
if (ret == 1) {
    sf_overwrite(e);
}
OPENSSL_free(Res);
return ret;

OCSP_SINGLERESP* d2i_OCSP_SINGLERESP(OCSP_SINGLERESP** a, const unsigned char** pp, long length) {
    OCSP_SINGLERESP* Res = NULL;
    sf_set_trusted_sink_int(length);
    sf_malloc_arg(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    Res = d2i_OCSP_SINGLERESP(a, pp, length);
    sf_set_possible_null(Res);
    return Res;
}

unsigned char* EC_GROUP_get0_seed(const EC_GROUP* group) {
    unsigned char* Res = NULL;
    Res = EC_GROUP_get0_seed(group);
    sf_set_possible_null(Res);
    return Res;
}

BIO* BIO_new_ssl(SSL_CTX* ctx, int client) {
    BIO* Res = NULL;
    Res = BIO_new_ssl(ctx, client);
    sf_set_possible_null(Res);
    return Res;
}

int EVP_MD_meth_set_final(EVP_MD* md, int (*final)(EVP_MD_CTX*, unsigned char*)) {
    int Res = 0;
    Res = EVP_MD_meth_set_final(md, final);
    sf_set_errno_if(Res <= 0);
    return Res;
}

UI* UI_new_method(const UI_METHOD* method) {
    UI* Res = NULL;
    Res = UI_new_method(method);
    sf_set_possible_null(Res);
    return Res;
}

size_t OPENSSL_strlcat(char *dst, const char *src, size_t size)
{
    size_t res = 0;
    sf_set_trusted_sink_int(size);
    sf_buf_size_limit(dst, size);
    sf_buf_size_limit(src, size);
    sf_buf_overlap(dst, src);
    sf_bitcopy(dst, src);
    sf_overwrite(dst);
    return res;
}

const char* EVP_MAC_get0_name(const EVP_MAC* mac)
{
    const char* res = NULL;
    sf_set_possible_null(res);
    sf_lib_arg_type(mac, "EVP_MAC");
    return res;
}

void ERR_print_errors_cb(int (const char*, size_t, void*)* callback, void* arg)
{
    sf_lib_arg_type(callback, "ERR_print_errors_cb");
    sf_lib_arg_type(arg, "ERR_print_errors_cb_arg");
}

void SSL_CTX_set_tmp_dh_callback(SSL_CTX* ctx, DH* (SSL*, int, int)* dh)
{
    sf_lib_arg_type(ctx, "SSL_CTX");
    sf_lib_arg_type(dh, "SSL_CTX_set_tmp_dh_callback");
}

int X509_NAME_get_text_by_OBJ(const X509_NAME* name, const ASN1_OBJECT* obj, char* buf, int len)
{
    int res = 0;
    sf_set_trusted_sink_int(len);
    sf_buf_size_limit(buf, len);
    sf_lib_arg_type(name, "X509_NAME");
    sf_lib_arg_type(obj, "ASN1_OBJECT");
    sf_set_possible_null(res);
    return res;
}
int X509_OBJECT_set1_X509(X509_OBJECT* obj, X509* x);

int EVP_CIPHER_meth_set_iv_length(EVP_CIPHER* cipher, int ivlen);

int UI_dup_input_string(UI* ui, const char* input, int len, char* output, int maxlen, int do_copy);

EVP_PKEY* PEM_read_PrivateKey_ex(FILE* fp, EVP_PKEY** x, pem_password_cb* cb, void* u, OSSL_LIB_CTX* libctx, const char* propq);

void* CRYPTO_secure_zalloc(size_t num, const char* file, int line);

int i2d_X509(const X509* a, unsigned char** pp);

int SSL_read_early_data(SSL* s, void* buf, size_t num, size_t* readbytes);

const DSA_METHOD* DSA_get_default_method();

ASN1_OCTET_STRING* X509_get0_distinguishing_id(X509* x);

int BN_from_montgomery(BIGNUM* r, const BIGNUM* a, BN_MONT_CTX* mont, BN_CTX* ctx);


void EVP_PKEY_add1_attr_by_NID(EVP_PKEY *pkey, int nid, int type, const unsigned char *bytes, int len) {
    int res = 0;
    sf_set_tainted(bytes);
    sf_set_trusted_sink_int(len);
    sf_set_must_be_not_null(pkey, EVP_PKEY_NULL);
    sf_set_must_be_not_null(bytes, EVP_PKEY_BYTES_NULL);
    res = EVP_PKEY_add1_attr_by_NID(pkey, nid, type, bytes, len);
    sf_set_errno_if(res <= 0);
}

void X509_load_cert_file_ex(X509_LOOKUP *lookup, const char *file, int type, OSSL_LIB_CTX *libctx, const char *propq) {
    int res = 0;
    sf_set_must_be_not_null(lookup, X509_LOOKUP_NULL);
    sf_set_must_be_not_null(file, X509_FILE_NULL);
    sf_set_must_be_not_null(libctx, OSSL_LIB_CTX_NULL);
    sf_set_must_be_not_null(propq, PROPQ_NULL);
    sf_tocttou_check(file);
    res = X509_load_cert_file_ex(lookup, file, type, libctx, propq);
    sf_set_errno_if(res <= 0);
}

void SSL_CTX_set_default_read_buffer_len(SSL_CTX *ctx, size_t len) {
    sf_set_trusted_sink_int(len);
    sf_set_must_be_not_null(ctx, SSL_CTX_NULL);
    SSL_CTX_set_default_read_buffer_len(ctx, len);
}

void X509_NAME_add_entry_by_txt(X509_NAME *name, const char *field, int type, const unsigned char *bytes, int len, int loc, int set) {
    int res = 0;
    sf_set_must_be_not_null(name, X509_NAME_NULL);
    sf_set_must_be_not_null(field, X509_NAME_FIELD_NULL);
    sf_set_trusted_sink_int(len);
    sf_set_must_be_not_null(bytes, X509_NAME_BYTES_NULL);
    res = X509_NAME_add_entry_by_txt(name, field, type, bytes, len, loc, set);
    sf_set_errno_if(res <= 0);
}

void OCSP_response_status(OCSP_RESPONSE *resp) {
    int res = 0;
    sf_set_must_be_not_null(resp, OCSP_RESPONSE_NULL);
    res = OCSP_response_status(resp);
    sf_set_errno_if(res != OCSP_RESPONSE_STATUS_SUCCESSFUL);
}

int EVP_PKEY_encrypt_init(EVP_PKEY_CTX* ctx) {
    int res = 0;
    // Additional implementation here
    return res;
}

int i2d_PBEPARAM(const PBEPARAM* param, unsigned char** pstr) {
    int res = 0;
    // Additional implementation here
    return res;
}

IPAddressOrRange* IPAddressOrRange_new() {
    IPAddressOrRange* res = NULL;
    // Additional implementation here
    return res;
}

uint64_t SCT_get_timestamp(const SCT* sct) {
    uint64_t res = 0;
    // Additional implementation here
    return res;
}

int EC_KEY_check_key(const EC_KEY* key) {
    int res = 0;
    // Additional implementation here
    return res;
}

const EVP_CIPHER* EVP_seed_cbc() {
    const EVP_CIPHER* Res = NULL;
    Res = EVP_seed_cbc();
    sf_set_possible_null(Res);
    return Res;
}

const BIGNUM* BN_get0_nist_prime_256() {
    const BIGNUM* Res = NULL;
    Res = BN_get0_nist_prime_256();
    sf_set_possible_null(Res);
    return Res;
}

const char* DSA_meth_get0_name(const DSA_METHOD* dsa_meth) {
    const char* Res = NULL;
    Res = DSA_meth_get0_name(dsa_meth);
    sf_set_possible_null(Res);
    return Res;
}

BIGNUM* BN_copy(BIGNUM* a, const BIGNUM* b) {
    BIGNUM* Res = NULL;
    Res = BN_copy(a, b);
    sf_set_possible_null(Res);
    return Res;
}

int DTLSv1_listen(SSL* s, BIO_ADDR* peer) {
    int Res = 0;
    Res = DTLSv1_listen(s, peer);
    sf_set_errno_if(Res == -1);
    return Res;
}

EC_KEY* EC_KEY_new_by_curve_name_ex(OSSL_LIB_CTX* ctx, const char* name, int len) {
    EC_KEY* Res = NULL;
    sf_set_trusted_sink_int(len);
    sf_malloc_arg(Res, EC_KEY_MEMORY_CATEGORY);
    sf_overwrite(Res);
    sf_new(Res, EC_KEY_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    return Res;
}

PKCS7_ENVELOPE* PKCS7_ENVELOPE_new() {
    PKCS7_ENVELOPE* Res = NULL;
    sf_malloc_arg(Res, PKCS7_ENVELOPE_MEMORY_CATEGORY);
    sf_overwrite(Res);
    sf_new(Res, PKCS7_ENVELOPE_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    return Res;
}

int RSA_blinding_on(RSA* rsa, BN_CTX* ctx) {
    int Res = 0;
    sf_set_must_be_not_null(rsa, RSA_BLINDING_ON_NULL);
    sf_set_must_be_not_null(ctx, RSA_BLINDING_ON_NULL);
    sf_set_errno_if(Res == 0);
    sf_no_errno_if(Res != 0);
    return Res;
}

int OBJ_ln2nid(const char* name) {
    int Res = 0;
    sf_set_must_be_not_null(name, OBJ_LN2NID_NULL);
    sf_set_errno_if(Res == 0);
    sf_no_errno_if(Res != 0);
    return Res;
}

void* OPENSSL_LH_delete(OPENSSL_LHASH* lh, const void* data) {
    void* Res = NULL;
    sf_set_must_be_not_null(lh, OPENSSL_LH_DELETE_NULL);
    sf_set_must_be_not_null(data, OPENSSL_LH_DELETE_NULL);
    sf_delete(Res, OPENSSL_LH_MEMORY_CATEGORY);
    sf_lib_arg_type(Res, "OPENSSL_LH_MEMORY_CATEGORY");
    sf_set_possible_null(Res);
    return Res;
}

OCSP_RESPONSE* d2i_OCSP_RESPONSE(OCSP_RESPONSE** a, const unsigned char** pp, long length) {
    OCSP_RESPONSE* Res = NULL;
    sf_set_trusted_sink_int(length);
    Res = d2i_OCSP_RESPONSE(a, pp, length);
    sf_overwrite(Res);
    return Res;
}

int X509_set_ex_data(X509* x, int idx, void* arg) {
    sf_set_tainted(arg);
    return X509_set_ex_data(x, idx, arg);
}

int EVP_PKEY_print_params_fp(FILE* fp, const EVP_PKEY* pkey, int indent, ASN1_PCTX* pctx) {
    sf_set_tainted(fp);
    sf_set_tainted(pkey);
    sf_set_tainted(pctx);
    return EVP_PKEY_print_params_fp(fp, pkey, indent, pctx);
}

const EC_POINT* EC_GROUP_get0_generator(const EC_GROUP* group) {
    sf_set_tainted(group);
    return EC_GROUP_get0_generator(group);
}

int SSL_get_error(const SSL* s, int ret_code) {
    sf_set_must_not_be_null(s);
    return SSL_get_error(s, ret_code);
}
X509_CRL* d2i_X509_CRL_bio(BIO* bp, X509_CRL** crl);

int EVP_EncryptInit_ex(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type, ENGINE* impl, const unsigned char* key, const unsigned char* iv);

X509_CERT_AUX* X509_CERT_AUX_new();

int X509_STORE_CTX_purpose_inherit(X509_STORE_CTX* ctx, int id, int trust, int flags);

const OSSL_PARAM* EVP_KEYEXCH_settable_ctx_params(const EVP_KEYEXCH* ke);

int SSL_check_chain(SSL* ssl, X509* x, EVP_PKEY* pkey, stack_st_X509* chain);

int EVP_PKEY_export(const EVP_PKEY* pkey, int outformat, OSSL_CALLBACK* cb, void* app_data);

int ASN1_TIME_compare(const ASN1_TIME* a, const ASN1_TIME* b);

const SSL_METHOD* TLSv1_1_method();

ENGINE* DSA_get0_engine(DSA* dsa);


const EVP_CIPHER* EVP_camellia_256_ecb() {
    const EVP_CIPHER* Res = NULL;
    Res = EVP_camellia_256_ecb();
    sf_set_possible_null(Res);
    return Res;
}

const EVP_MD* EVP_sha512() {
    const EVP_MD* Res = NULL;
    Res = EVP_sha512();
    sf_set_possible_null(Res);
    return Res;
}

ASN1_INTEGER* d2i_ASN1_UINTEGER(ASN1_INTEGER** a, const unsigned char** pp, long length) {
    ASN1_INTEGER* Res = NULL;
    Res = d2i_ASN1_UINTEGER(a, pp, length);
    sf_set_possible_null(Res);
    return Res;
}

X509_LOOKUP* X509_STORE_add_lookup(X509_STORE* store, X509_LOOKUP_METHOD* method) {
    X509_LOOKUP* Res = NULL;
    Res = X509_STORE_add_lookup(store, method);
    sf_set_possible_null(Res);
    return Res;
}

EC_KEY* d2i_ECPrivateKey_fp(FILE* fp, EC_KEY** key) {
    EC_KEY* Res = NULL;
    Res = d2i_ECPrivateKey_fp(fp, key);
    sf_set_possible_null(Res);
    return Res;
}

OPENSSL_STACK* OPENSSL_sk_new_reserve(OPENSSL_sk_compfunc cmp, int n)
{
    OPENSSL_STACK *Res = NULL;
    sf_set_trusted_sink_int(n);
    Res = OPENSSL_sk_new_reserve(cmp, n);
    sf_overwrite(Res);
    return Res;
}

void OSSL_PARAM_free(OSSL_PARAM *param)
{
    sf_set_tainted(param);
    OSSL_PARAM_free(param);
}

int SSL_CTX_set_session_id_context(SSL_CTX *ctx, const unsigned char *sid_ctx, unsigned int sid_ctx_len)
{
    int Res;
    sf_set_trusted_sink_ptr(sid_ctx);
    sf_buf_size_limit(sid_ctx, sid_ctx_len);
    Res = SSL_CTX_set_session_id_context(ctx, sid_ctx, sid_ctx_len);
    sf_overwrite(Res);
    return Res;
}

int EVP_PKEY_public_check_quick(EVP_PKEY_CTX *ctx)
{
    int Res;
    Res = EVP_PKEY_public_check_quick(ctx);
    sf_overwrite(Res);
    return Res;
}

USERNOTICE* d2i_USERNOTICE(USERNOTICE **a, const unsigned char **in, long len)
{
    USERNOTICE *Res;
    sf_set_trusted_sink_ptr(*in);
    sf_buf_size_limit(*in, len);
    Res = d2i_USERNOTICE(a, in, len);
    sf_overwrite(Res);
    return Res;
}

int X509_load_cert_crl_file_ex(X509_LOOKUP *lookup, const char *name, int type, OSSL_LIB_CTX *libctx, const char *propq) {
    int res = 0;
    sf_set_must_be_not_null(lookup, LOAD_CERT_CRL_FILE_EX_OF_NULL);
    sf_set_must_be_not_null(name, LOAD_CERT_CRL_FILE_EX_NAME_OF_NULL);
    sf_set_must_be_not_null(libctx, LOAD_CERT_CRL_FILE_EX_LIBCTX_OF_NULL);
    sf_set_must_be_not_null(propq, LOAD_CERT_CRL_FILE_EX_PROPQ_OF_NULL);
    sf_set_errno_if(res == 0, LOAD_CERT_CRL_FILE_EX_FAIL);
    sf_set_errno_if(res < 0, LOAD_CERT_CRL_FILE_EX_NEGATIVE);
    sf_set_possible_null(res, LOAD_CERT_CRL_FILE_EX_RES_POSSIBLE_NULL);
    return res;
}

X509_NAME_ENTRY* X509_NAME_ENTRY_create_by_txt(X509_NAME_ENTRY **ne, const char *txt, int len, const unsigned char *data, int data_len) {
    X509_NAME_ENTRY *res = NULL;
    sf_set_must_be_not_null(ne, NAME_ENTRY_CREATE_BY_TXT_NE_OF_NULL);
    sf_set_must_be_not_null(txt, NAME_ENTRY_CREATE_BY_TXT_TXT_OF_NULL);
    sf_set_must_be_not_null(data, NAME_ENTRY_CREATE_BY_TXT_DATA_OF_NULL);
    sf_set_errno_if(res == NULL, NAME_ENTRY_CREATE_BY_TXT_FAIL);
    return res;
}

EVP_PKEY* d2i_PrivateKey_fp(FILE *fp, EVP_PKEY **key) {
    EVP_PKEY *res = NULL;
    sf_set_must_be_not_null(fp, D2I_PRIVATEKEY_FP_FP_OF_NULL);
    sf_set_must_be_not_null(key, D2I_PRIVATEKEY_FP_KEY_OF_NULL);
    sf_set_errno_if(res == NULL, D2I_PRIVATEKEY_FP_FAIL);
    sf_set_possible_null(res, D2I_PRIVATEKEY_FP_RES_POSSIBLE_NULL);
    return res;
}

int EVP_CIPHER_CTX_get_original_iv(EVP_CIPHER_CTX *ctx, void *iv, size_t len) {
    int res = 0;
    sf_set_must_be_not_null(ctx, GET_ORIGINAL_IV_CTX_OF_NULL);
    sf_set_must_be_not_null(iv, GET_ORIGINAL_IV_IV_OF_NULL);
    sf_set_errno_if(res == 0, GET_ORIGINAL_IV_FAIL);
    sf_set_errno_if(res < 0, GET_ORIGINAL_IV_NEGATIVE);
    return res;
}

int BIO_ssl_copy_session_id(BIO *from, BIO *to) {
    int res = 0;
    sf_set_must_be_not_null(from, SSL_COPY_SESSION_ID_FROM_OF_NULL);
    sf_set_must_be_not_null(to, SSL_COPY_SESSION_ID_TO_OF_NULL);
    sf_set_errno_if(res == 0, SSL_COPY_SESSION_ID_FAIL);
    sf_set_errno_if(res < 0, SSL_COPY_SESSION_ID_NEGATIVE);
    return res;
}
int SSL_CTX_load_verify_store(SSL_CTX*, const char*);

const EC_METHOD* EC_GF2m_simple_method();

int ASN1_INTEGER_set_int64(ASN1_INTEGER*, int64_t);

void BIO_set_callback(BIO*, BIO_callback_fn);

void OCSP_CERTID_free(OCSP_CERTID*);


int EVP_OpenFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl) {
    int Res = 0;
    sf_set_tainted(ctx);
    sf_set_tainted(out);
    sf_set_tainted(outl);
    sf_set_errno_if(Res <= 0, EVP_F_EVP_OPENFINAL);
    sf_set_possible_null(out);
    sf_set_possible_null(outl);
    return Res;
}

void X509_STORE_set_check_issued(X509_STORE *ctx, X509_STORE_CTX_check_issued_fn check_issued) {
    sf_set_tainted(ctx);
    sf_set_tainted(check_issued);
}

X509_ATTRIBUTE* X509_REQ_get_attr(const X509_REQ *req, int loc) {
    X509_ATTRIBUTE *Res = NULL;
    sf_set_tainted(req);
    sf_set_errno_if(Res == NULL, X509_F_X509_REQ_GET_ATTRIB);
    return Res;
}

EVP_PKEY* EVP_PKEY_new_mac_key(int type, ENGINE *engine, const unsigned char *key, int keylen) {
    EVP_PKEY *Res = NULL;
    sf_set_tainted(type);
    sf_set_tainted(engine);
    sf_set_tainted(key);
    sf_set_tainted(keylen);
    sf_set_errno_if(Res == NULL, EVP_F_EVP_PKEY_NEW_MAC_KEY);
    return Res;
}

int PEM_get_EVP_CIPHER_INFO(char *header, EVP_CIPHER_INFO *cipher) {
    int Res = 0;
    sf_set_tainted(header);
    sf_set_tainted(cipher);
    sf_set_errno_if(Res <= 0, PEM_F_PEM_GET_EVP_CIPHER_INFO);
    return Res;
}

EVP_PKEY* EVP_PKEY_Q_keygen(OSSL_LIB_CTX* ctx, const char* type, const char* params) {
    EVP_PKEY* Res = NULL;
    // Check if ctx is null
    sf_set_must_be_not_null(ctx, "EVP_PKEY_Q_keygen");
    // Check if type is null
    sf_set_must_be_not_null(type, "EVP_PKEY_Q_keygen");
    // Check if params is null
    sf_set_must_be_not_null(params, "EVP_PKEY_Q_keygen");
    // Check if type is tainted
    sf_set_tainted(type);
    // Check if params is tainted
    sf_set_tainted(params);
    // Perform keygen
    // ...
    // Mark Res as possibly null
    sf_set_possible_null(Res);
    return Res;
}

const ASN1_OCTET_STRING* X509_get0_authority_key_id(X509* x) {
    const ASN1_OCTET_STRING* Res = NULL;
    // Check if x is null
    sf_set_must_be_not_null(x, "X509_get0_authority_key_id");
    // Perform get authority key id
    // ...
    // Mark Res as possibly null
    sf_set_possible_null(Res);
    return Res;
}

int SSL_CTX_set_srp_username_callback(SSL_CTX* ctx, int (SSL*, int*, void*)* cb) {
    int Res = 0;
    // Check if ctx is null
    sf_set_must_be_not_null(ctx, "SSL_CTX_set_srp_username_callback");
    // Check if cb is null
    sf_set_must_be_not_null(cb, "SSL_CTX_set_srp_username_callback");
    // Perform set srp username callback
    // ...
    return Res;
}

int PEM_write_PUBKEY(FILE* fp, const EVP_PKEY* x) {
    int Res = 0;
    // Check if fp is null
    sf_set_must_be_not_null(fp, "PEM_write_PUBKEY");
    // Check if x is null
    sf_set_must_be_not_null(x, "PEM_write_PUBKEY");
    // Perform write pubkey
    // ...
    return Res;
}

int X509_REQ_digest(const X509_REQ* req, const EVP_MD* md, unsigned char* buf, unsigned int* len) {
    int Res = 0;
    // Check if req is null
    sf_set_must_be_not_null(req, "X509_REQ_digest");
    // Check if md is null
    sf_set_must_be_not_null(md, "X509_REQ_digest");
    // Check if buf is null
    sf_set_must_be_not_null(buf, "X509_REQ_digest");
    // Check if len is null
    sf_set_must_be_not_null(len, "X509_REQ_digest");
    // Perform digest
    // ...
    return Res;
}
int EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name(EVP_PKEY_CTX*, const char*);

const EVP_CIPHER* EVP_aria_128_cfb128();

int EVP_PKEY_sign_init_ex(EVP_PKEY_CTX*, const OSSL_PARAM[]);

int SSL_CTX_use_RSAPrivateKey_ASN1(SSL_CTX*, const unsigned char*, long);

int X509_LOOKUP_meth_set_shutdown(X509_LOOKUP_METHOD*, int (X509_LOOKUP*);


void SSL_set_cipher_list(SSL *ssl, const char *str) {
    int res = 0;
    sf_set_tainted(str);
    sf_set_trusted_sink_ptr(ssl);
    sf_set_errno_if(res == 0, EINVAL);
    sf_no_errno_if(res != 0);
}

int i2d_EXTENDED_KEY_USAGE(const EXTENDED_KEY_USAGE *a, unsigned char **pp) {
    int res = 0;
    sf_set_trusted_sink_ptr(pp);
    sf_set_errno_if(res <= 0, ERR_R_MALLOC_FAILURE);
    sf_no_errno_if(res > 0);
    return res;
}

unsigned long SSL_CTX_dane_set_flags(SSL_CTX *ctx, unsigned long flags) {
    unsigned long res = 0;
    sf_set_trusted_sink_ptr(ctx);
    sf_set_errno_if(res == 0, EINVAL);
    sf_no_errno_if(res != 0);
    return res;
}

void EVP_PKEY_meth_set_verify(EVP_PKEY_METHOD *pmeth, int (*verify_init) (EVP_PKEY_CTX *ctx), int (*verify) (EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen)) {
    sf_set_trusted_sink_ptr(pmeth);
}

void SSL_CTX_set_info_callback(SSL_CTX *ctx, void (*callback) (const SSL *ssl, int type, int val)) {
    sf_set_trusted_sink_ptr(ctx);
}

int (UI*)* UI_method_get_opener(const UI_METHOD* method) {
    int (UI*)* Res = NULL;
    sf_set_trusted_sink_ptr(method);
    Res = UI_METHOD_get_opener(method);
    sf_set_possible_null(Res);
    return Res;
}

const BIO_METHOD* BIO_f_null() {
    const BIO_METHOD* Res = NULL;
    Res = BIO_f_null();
    sf_set_possible_null(Res);
    return Res;
}

void EVP_PKEY_meth_set_check(EVP_PKEY_METHOD* pkey_method, int (EVP_PKEY*)* check) {
    sf_set_trusted_sink_ptr(pkey_method);
    EVP_PKEY_meth_set_check(pkey_method, check);
}

const ASN1_OCTET_STRING* PROFESSION_INFO_get0_addProfessionInfo(const PROFESSION_INFO* info) {
    const ASN1_OCTET_STRING* Res = NULL;
    sf_set_trusted_sink_ptr(info);
    Res = PROFESSION_INFO_get0_addProfessionInfo(info);
    sf_set_possible_null(Res);
    return Res;
}

OSSL_PROVIDER* EVP_ASYM_CIPHER_get0_provider(const EVP_ASYM_CIPHER* cipher) {
    OSSL_PROVIDER* Res = NULL;
    sf_set_trusted_sink_ptr(cipher);
    Res = EVP_ASYM_CIPHER_get0_provider(cipher);
    sf_set_possible_null(Res);
    return Res;
}

PKCS7_SIGNED* PKCS7_SIGNED_new() {
    PKCS7_SIGNED* Res = NULL;
    Res = OPENSSL_zalloc(sizeof(*Res));
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    return Res;
}

const char* EVP_KEYMGMT_get0_name(const EVP_KEYMGMT* keymgmt) {
    const char* Res = NULL;
    Res = keymgmt->name;
    sf_set_possible_null(Res);
    return Res;
}

int PEM_write_bio(BIO* bio, const char* name, const char* header, const unsigned char* data, long len) {
    int Res = 0;
    Res = PEM_ASN1_write_bio((i2d_of_void*)i2d_ASN1_SET_ANY, name, bio, data, 0, NULL, header);
    sf_set_errno_if(Res <= 0);
    return Res;
}

OPENSSL_STACK* OPENSSL_sk_deep_copy(const OPENSSL_STACK* st, OPENSSL_sk_copyfunc copyfunc, OPENSSL_sk_freefunc freefunc) {
    OPENSSL_STACK* Res = NULL;
    Res = OPENSSL_sk_dup(st, copyfunc);
    sf_set_alloc_possible_null(Res);
    return Res;
}

NETSCAPE_SPKAC* NETSCAPE_SPKAC_new() {
    NETSCAPE_SPKAC* Res = NULL;
    Res = OPENSSL_zalloc(sizeof(*Res));
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    return Res;
}

int X509_REVOKED_get_ext_by_critical(const X509_REVOKED *rev, int idx, int crit) {
    int res = 0;
    sf_set_must_be_not_null(rev, "X509_REVOKED");
    sf_set_trusted_sink_int(idx);
    sf_set_trusted_sink_int(crit);
    sf_set_errno_if(res == -1);
    return res;
}

int SSL_client_hello_get0_ext(SSL *s, unsigned int idx, const unsigned char **out, size_t *outlen) {
    int res = 0;
    sf_set_must_be_not_null(s, "SSL");
    sf_set_trusted_sink_int(idx);
    sf_set_trusted_sink_ptr(out);
    sf_set_trusted_sink_ptr(outlen);
    sf_set_errno_if(res == -1);
    return res;
}

int X509_digest(const X509 *x, const EVP_MD *type, unsigned char *md, unsigned int *len) {
    int res = 0;
    sf_set_must_be_not_null(x, "X509");
    sf_set_must_be_not_null(type, "EVP_MD");
    sf_set_trusted_sink_ptr(md);
    sf_set_trusted_sink_ptr(len);
    sf_set_errno_if(res == 0);
    return res;
}

void X509_STORE_set_check_policy(X509_STORE *ctx, X509_STORE_CTX_check_policy_fn check_policy) {
    sf_set_must_be_not_null(ctx, "X509_STORE");
    sf_set_trusted_sink_ptr(check_policy);
}

const EVP_MD* EVP_shake256() {
    const EVP_MD *res = NULL;
    sf_set_errno_if(res == NULL);
    return res;
}

void RSA_PSS_PARAMS_free(RSA_PSS_PARAMS* params) {
    if (params != NULL) {
        sf_delete(params, PAGES_MEMORY_CATEGORY);
    }
}

int i2d_X509_PUBKEY(const X509_PUBKEY* a, unsigned char** pp) {
    int res = 0;
    if (a != NULL && pp != NULL) {
        res = sf_bitcopy(pp, a);
    }
    return res;
}

char* SSL_get_srp_username(SSL* s) {
    char* res = NULL;
    if (s != NULL) {
        res = sf_strdup_res(s->srp_username);
    }
    return res;
}

OCSP_SIGNATURE* OCSP_SIGNATURE_new() {
    OCSP_SIGNATURE* res = NULL;
    res = (OCSP_SIGNATURE*)sf_malloc_arg(sizeof(OCSP_SIGNATURE), "OCSP_SIGNATURE");
    if (res != NULL) {
        sf_new(res, PAGES_MEMORY_CATEGORY);
    }
    return res;
}

RSA* d2i_RSAPublicKey_fp(FILE* fp, RSA** rsa) {
    RSA* res = NULL;
    if (fp != NULL && rsa != NULL) {
        res = sf_bitcopy(rsa, fp);
    }
    return res;
}

const EVP_MD* EVP_ripemd160() {
    const EVP_MD* Res = NULL;
    Res = EVP_ripemd160();
    sf_set_possible_null(Res);
    return Res;
}

const SSL_METHOD* DTLSv1_2_server_method() {
    const SSL_METHOD* Res = NULL;
    Res = DTLSv1_2_server_method();
    sf_set_possible_null(Res);
    return Res;
}

void EVP_PKEY_asn1_set_public(EVP_PKEY_ASN1_METHOD *ameth, int (*pub_decode)(), int (*pub_encode)(), int (*pub_cmp)(), int (*pub_print)(), int (*pkey_size)(), int (*pkey_bits)()) {
    EVP_PKEY_asn1_set_public(ameth, pub_decode, pub_encode, pub_cmp, pub_print, pkey_size, pkey_bits);
}

SSL_SESSION* SSL_get_session(const SSL* s) {
    SSL_SESSION* Res = NULL;
    Res = SSL_get_session(s);
    sf_set_possible_null(Res);
    return Res;
}

int SSL_CONF_CTX_finish(SSL_CONF_CTX* cctx) {
    int Res = 0;
    Res = SSL_CONF_CTX_finish(cctx);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int i2d_re_X509_CRL_tbs(X509_CRL *a, unsigned char **pp)
{
    int res = 0;
    sf_set_trusted_sink_int(a);
    sf_set_trusted_sink_ptr(pp);
    res = i2d_X509_CRL_tbs(a, pp);
    sf_overwrite(res);
    return res;
}

int SSL_free_buffers(SSL *s)
{
    int res = 0;
    sf_set_trusted_sink_ptr(s);
    res = SSL_free_buffers(s);
    sf_overwrite(res);
    return res;
}

int X509_STORE_set_ex_data(X509_STORE *ctx, int idx, void *data)
{
    int res = 0;
    sf_set_trusted_sink_int(ctx);
    sf_set_trusted_sink_int(idx);
    sf_set_trusted_sink_ptr(data);
    res = X509_STORE_set_ex_data(ctx, idx, data);
    sf_overwrite(res);
    return res;
}

unsigned long OPENSSL_LH_get_down_load(const OPENSSL_LHASH *lh)
{
    unsigned long res = 0;
    sf_set_trusted_sink_ptr(lh);
    res = OPENSSL_LH_get_down_load(lh);
    sf_overwrite(res);
    return res;
}

BIO* OSSL_HTTP_REQ_CTX_exchange(OSSL_HTTP_REQ_CTX *r)
{
    BIO *res = NULL;
    sf_set_trusted_sink_ptr(r);
    res = OSSL_HTTP_REQ_CTX_exchange(r);
    sf_overwrite(res);
    return res;
}
int EVP_PKEY_CTX_set_rsa_keygen_primes(EVP_PKEY_CTX* ctx, int nprimes);

int RSA_meth_get_priv_enc(const RSA_METHOD* rsa);

BIGNUM* BN_secure_new();

void ENGINE_register_all_ciphers();

int EVP_PKEY_asn1_get0_info(int* pkey_id, int* info, int* ppkey_type, const char** pem_str, const char** info_str, const EVP_PKEY_ASN1_METHOD* ameth);


int EVP_PKEY_type(int type) {
    int Res = 0;
    // Function body
    return Res;
}

int i2d_RSAPrivateKey(const RSA *a, unsigned char **pp) {
    int Res = 0;
    // Function body
    return Res;
}

int SSL_CTX_get_verify_mode(const SSL_CTX *ctx) {
    int Res = 0;
    // Function body
    return Res;
}

int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl) {
    int Res = 0;
    // Function body
    return Res;
}

void EVP_SIGNATURE_free(EVP_SIGNATURE *sig) {
    // Function body
}
int RSA_public_encrypt(int flen, const unsigned char* from, unsigned char* to, RSA* rsa, int padding);

const char* UI_get0_action_string(UI_STRING* uis);

int i2t_ASN1_OBJECT(char* buf, int buf_len, const ASN1_OBJECT* a);

void X509_ATTRIBUTE_free(X509_ATTRIBUTE* a);

int RAND_bytes(unsigned char* buf, int num);

int EVP_PKEY_CTX_get_rsa_mgf1_md(EVP_PKEY_CTX*, const EVP_MD**);

int X509_REQ_sign_ctx(X509_REQ*, EVP_MD_CTX*);

int X509_STORE_load_file(X509_STORE*, const char*);

EVP_PKEY* d2i_PublicKey(int, EVP_PKEY**, const unsigned char**, long);

size_t OBJ_length(const ASN1_OBJECT*);

int UI_method_set_ex_data(UI_METHOD* method, int idx, void* data);

const EVP_CIPHER* EVP_bf_ofb();

void EVP_PKEY_meth_set_sign(EVP_PKEY_METHOD* pmeth, int (*sign_init);

int (*DH_meth_get_compute_key(const DH_METHOD* dh);

int EC_GROUP_set_generator(EC_GROUP* group, const EC_POINT* gen, const BIGNUM* order, const BIGNUM* prime);


OCSP_CERTID* OCSP_CERTID_new() {
    OCSP_CERTID* Res = NULL;
    Res = OCSP_CERTID_new();
    sf_set_possible_null(Res);
    return Res;
}

const stack_st_X509_ATTRIBUTE* PKCS8_pkey_get0_attrs(const PKCS8_PRIV_KEY_INFO* p8inf) {
    const stack_st_X509_ATTRIBUTE* Res = NULL;
    Res = PKCS8_pkey_get0_attrs(p8inf);
    sf_set_possible_null(Res);
    return Res;
}

int X509_check_ip_asc(X509* x, const char* ipasc, unsigned int iplen) {
    int Res = 0;
    Res = X509_check_ip_asc(x, ipasc, iplen);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int SSL_CTX_set_srp_verify_param_callback(SSL_CTX* ctx, int (SSL*, void*)* cb) {
    int Res = 0;
    Res = SSL_CTX_set_srp_verify_param_callback(ctx, cb);
    sf_set_errno_if(Res <= 0);
    return Res;
}

const EC_METHOD* EC_GFp_nistp521_method() {
    const EC_METHOD* Res = NULL;
    Res = EC_GFp_nistp521_method();
    sf_set_possible_null(Res);
    return Res;
}

void X509_SIG_get0(const X509_SIG *sig, const X509_ALGOR **algor, const ASN1_OCTET_STRING **digest)
{
    sf_set_tainted(sig);
    sf_set_tainted(algor);
    sf_set_tainted(digest);

    sf_set_must_be_not_null(sig, "X509_SIG_get0");
    sf_set_must_be_not_null(algor, "X509_SIG_get0");
    sf_set_must_be_not_null(digest, "X509_SIG_get0");

    *algor = sig->algor;
    *digest = sig->digest;
}

int i2d_ASN1_SEQUENCE_ANY(const ASN1_SEQUENCE_ANY *seq, unsigned char **pp)
{
    int res = 0;
    sf_set_tainted(seq);
    sf_set_tainted(pp);

    sf_set_must_be_not_null(seq, "i2d_ASN1_SEQUENCE_ANY");
    sf_set_must_be_not_null(pp, "i2d_ASN1_SEQUENCE_ANY");

    res = i2d_ASN1_SEQUENCE(seq, pp);
    sf_set_errno_if(res <= 0, "i2d_ASN1_SEQUENCE_ANY");

    return res;
}

int X509_NAME_add_entry_by_OBJ(X509_NAME *name, const ASN1_OBJECT *obj, int type, const unsigned char *bytes, int len, int loc, int set)
{
    int res = 0;
    sf_set_tainted(name);
    sf_set_tainted(obj);
    sf_set_tainted(bytes);

    sf_set_must_be_not_null(name, "X509_NAME_add_entry_by_OBJ");
    sf_set_must_be_not_null(obj, "X509_NAME_add_entry_by_OBJ");
    sf_set_must_be_not_null(bytes, "X509_NAME_add_entry_by_OBJ");

    res = X509_NAME_add_entry_by_OBJ(name, obj, type, bytes, len, loc, set);
    sf_set_errno_if(res <= 0, "X509_NAME_add_entry_by_OBJ");

    return res;
}

int EVP_CIPHER_get_mode(const EVP_CIPHER *cipher)
{
    int res = 0;
    sf_set_tainted(cipher);

    sf_set_must_be_not_null(cipher, "EVP_CIPHER_get_mode");

    res = EVP_CIPHER_mode(cipher);

    return res;
}

int EC_METHOD_get_field_type(const EC_METHOD *method)
{
    int res = 0;
    sf_set_tainted(method);

    sf_set_must_be_not_null(method, "EC_METHOD_get_field_type");

    res = EC_METHOD_get_field_type(method);

    return res;
}

unsigned long ERR_peek_last_error_line(const char** file, int* line)
{
    unsigned long Res = 0;
    sf_set_tainted(file);
    sf_set_tainted(line);
    sf_set_errno_if(Res == 0);
    sf_no_errno_if(Res != 0);
    return Res;
}

int (X509_LOOKUP*)* X509_LOOKUP_meth_get_new_item(const X509_LOOKUP_METHOD* method)
{
    int (X509_LOOKUP*)* Res = NULL;
    sf_set_trusted_sink_ptr(method);
    sf_set_errno_if(Res == NULL);
    sf_no_errno_if(Res != NULL);
    return Res;
}

int BN_bn2nativepad(const BIGNUM* a, unsigned char* to, int tolen)
{
    int Res = 0;
    sf_set_tainted(a);
    sf_set_trusted_sink_ptr(to);
    sf_set_trusted_sink_int(tolen);
    sf_set_errno_if(Res == 0);
    sf_no_errno_if(Res != 0);
    return Res;
}

int ENGINE_cmd_is_executable(ENGINE* e, int cmd)
{
    int Res = 0;
    sf_set_trusted_sink_ptr(e);
    sf_set_trusted_sink_int(cmd);
    sf_set_errno_if(Res == 0);
    sf_no_errno_if(Res != 0);
    return Res;
}

int EVP_MD_up_ref(EVP_MD* md)
{
    int Res = 0;
    sf_set_trusted_sink_ptr(md);
    sf_set_errno_if(Res == 0);
    sf_no_errno_if(Res != 0);
    return Res;
}

ASN1_TIME* X509_time_adj_ex(ASN1_TIME* s, int days, long sec, time_t* in_tm)
{
    ASN1_TIME* Res = NULL;
    sf_set_trusted_sink_int(days);
    sf_set_trusted_sink_int(sec);
    sf_set_trusted_sink_ptr(in_tm);
    Res = ASN1_TIME_adj(s, days, sec, in_tm);
    sf_overwrite(Res);
    return Res;
}

void SCRYPT_PARAMS_free(SCRYPT_PARAMS* params)
{
    sf_set_trusted_sink_ptr(params);
    OPENSSL_free(params);
}

void PBEPARAM_free(PBEPARAM* pbeparam)
{
    sf_set_trusted_sink_ptr(pbeparam);
    OPENSSL_free(pbeparam);
}

int EVP_default_properties_enable_fips(OSSL_LIB_CTX* ctx, int enable)
{
    sf_set_trusted_sink_int(enable);
    return EVP_default_properties_enable_fips(ctx, enable);
}

int OCSP_resp_get1_id(const OCSP_BASICRESP* bs, ASN1_OCTET_STRING** id, X509_NAME** name)
{
    int Res = 0;
    Res = OCSP_resp_get1_id(bs, id, name);
    sf_set_possible_null(id);
    sf_set_possible_null(name);
    return Res;
}

ECPARAMETERS* ECPARAMETERS_new() {
    ECPARAMETERS* Res = NULL;
    Res = (ECPARAMETERS*)OPENSSL_malloc(sizeof(ECPARAMETERS));
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    return Res;
}

ASN1_OCTET_STRING* s2i_ASN1_OCTET_STRING(X509V3_EXT_METHOD* method, X509V3_CTX* ctx, const char* str) {
    ASN1_OCTET_STRING* Res = NULL;
    Res = (ASN1_OCTET_STRING*)OPENSSL_malloc(sizeof(ASN1_OCTET_STRING));
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    return Res;
}

int ASN1_TIME_diff(int* res, int* day, const ASN1_TIME* from, const ASN1_TIME* to) {
    int Res = 0;
    // Implementation of the function
    sf_overwrite(res);
    sf_overwrite(day);
    return Res;
}

int i2d_PublicKey(const EVP_PKEY* a, unsigned char** pp) {
    int Res = 0;
    // Implementation of the function
    sf_overwrite(pp);
    return Res;
}

PKCS8_PRIV_KEY_INFO* d2i_PKCS8_PRIV_KEY_INFO_bio(BIO* bp, PKCS8_PRIV_KEY_INFO** p8inf) {
    PKCS8_PRIV_KEY_INFO* Res = NULL;
    Res = (PKCS8_PRIV_KEY_INFO*)OPENSSL_malloc(sizeof(PKCS8_PRIV_KEY_INFO));
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    return Res;
}

// Specification for SSL_client_hello_get0_ciphers
size_t SSL_client_hello_get0_ciphers(SSL* s, const unsigned char** p) {
    size_t res = 0;
    sf_set_must_be_not_null(s, SSL_NOT_NULL);
    sf_set_must_be_not_null(p, PTR_NOT_NULL);
    sf_set_trusted_sink_ptr(p);
    sf_set_errno_if(res == 0);
    return res;
}

// Specification for d2i_KeyParams_bio
EVP_PKEY* d2i_KeyParams_bio(int type, EVP_PKEY** a, BIO* b) {
    EVP_PKEY* res = NULL;
    sf_set_must_be_not_null(a, KEYPARAMS_NOT_NULL);
    sf_set_must_be_not_null(b, BIO_NOT_NULL);
    sf_set_alloc_possible_null(res);
    sf_set_errno_if(res == NULL);
    return res;
}

// Specification for EVP_MD_meth_free
void EVP_MD_meth_free(EVP_MD* md) {
    sf_set_must_be_not_null(md, EVP_MD_NOT_NULL);
    sf_delete(md, EVP_MD_CATEGORY);
}

// Specification for X509_get_ext
X509_EXTENSION* X509_get_ext(const X509* x, int loc) {
    X509_EXTENSION* res = NULL;
    sf_set_must_be_not_null(x, X509_NOT_NULL);
    sf_set_alloc_possible_null(res);
    sf_set_errno_if(res == NULL);
    return res;
}

// Specification for X509_STORE_CTX_set0_trusted_stack
void X509_STORE_CTX_set0_trusted_stack(X509_STORE_CTX* ctx, stack_st_X509* sk) {
    sf_set_must_be_not_null(ctx, X509_STORE_CTX_NOT_NULL);
    sf_set_must_be_not_null(sk, STACK_X509_NOT_NULL);
    sf_set_trusted_sink_ptr(sk);
}

void EVP_MAC_finalXOF(EVP_MAC_CTX *ctx, unsigned char *out, size_t outlen) {
    int res = 0;
    sf_set_trusted_sink_int(outlen);
    sf_buf_size_limit(out, outlen);
    sf_overwrite(out);
}

void EVP_CIPHER_meth_set_cleanup(EVP_CIPHER *cipher, int (*cleanup)(EVP_CIPHER_CTX*)) {
    int res = 0;
    sf_lib_arg_type(cleanup, "CleanupFunction");
}

void X509_REVOKED_get_ext_d2i(const X509_REVOKED *rev, int loc, int *out_nid, int *out_critical) {
    void *res = NULL;
    sf_set_possible_null(res);
    sf_lib_arg_type(out_nid, "NID");
    sf_lib_arg_type(out_critical, "Critical");
}

void i2d_ASN1_BIT_STRING(const ASN1_BIT_STRING *a, unsigned char **pp) {
    int res = 0;
    sf_set_trusted_sink_ptr(pp);
    sf_buf_size_limit_read(*pp, a->length);
    sf_overwrite(*pp);
}

void i2d_ISSUING_DIST_POINT(const ISSUING_DIST_POINT *a, unsigned char **pp) {
    int res = 0;
    sf_set_trusted_sink_ptr(pp);
    sf_buf_size_limit_read(*pp, a->length);
    sf_overwrite(*pp);
}

RSA* PEM_read_RSA_PUBKEY(FILE* fp, RSA** x, pem_password_cb* cb, void* u) {
    RSA* Res = NULL;
    sf_set_must_be_not_null(fp, FILE_POINTER_NULL);
    sf_set_must_be_not_null(x, RSA_POINTER_NULL);
    sf_set_possible_null(Res);
    sf_set_alloc_possible_null(Res);
    sf_lib_arg_type(fp, "FILE");
    sf_lib_arg_type(x, "RSA");
    sf_lib_arg_type(cb, "PEM_PASSWORD_CB");
    sf_lib_arg_type(u, "PEM_USER_DATA");
    return Res;
}

void X509_ALGOR_get0(const ASN1_OBJECT** paobj, int* pnid, const void** ppval, const X509_ALGOR* alg) {
    sf_set_must_be_not_null(paobj, ASN1_OBJECT_POINTER_NULL);
    sf_set_must_be_not_null(pnid, INT_POINTER_NULL);
    sf_set_must_be_not_null(ppval, VOID_POINTER_NULL);
    sf_set_must_be_not_null(alg, X509_ALGOR_POINTER_NULL);
    sf_lib_arg_type(paobj, "ASN1_OBJECT");
    sf_lib_arg_type(pnid, "INT");
    sf_lib_arg_type(ppval, "VOID");
    sf_lib_arg_type(alg, "X509_ALGOR");
}

int SSL_add_store_cert_subjects_to_stack(stack_st_X509_NAME* pnames, const char* path) {
    int Res = 0;
    sf_set_must_be_not_null(pnames, STACK_POINTER_NULL);
    sf_set_must_be_not_null(path, PATH_POINTER_NULL);
    sf_tocttou_check(path);
    sf_lib_arg_type(pnames, "STACK_X509_NAME");
    sf_lib_arg_type(path, "PATH");
    return Res;
}

const char* SSL_rstate_string(const SSL* ssl) {
    const char* Res = NULL;
    sf_set_must_be_not_null(ssl, SSL_POINTER_NULL);
    sf_lib_arg_type(ssl, "SSL");
    sf_set_possible_null(Res);
    return Res;
}

int PKCS7_ISSUER_AND_SERIAL_digest(PKCS7_ISSUER_AND_SERIAL* ias, const EVP_MD* md, unsigned char* data, unsigned int* len) {
    int Res = 0;
    sf_set_must_be_not_null(ias, PKCS7_ISSUER_AND_SERIAL_POINTER_NULL);
    sf_set_must_be_not_null(md, EVP_MD_POINTER_NULL);
    sf_set_must_be_not_null(data, DATA_POINTER_NULL);
    sf_set_must_be_not_null(len, LENGTH_POINTER_NULL);
    sf_lib_arg_type(ias, "PKCS7_ISSUER_AND_SERIAL");
    sf_lib_arg_type(md, "EVP_MD");
    sf_lib_arg_type(data, "DATA");
    sf_lib_arg_type(len, "LENGTH");
    return Res;
}
int EVP_MD_meth_get_update(const EVP_MD* md, EVP_MD_CTX* ctx, const void* data, size_t count);

int EC_POINT_is_at_infinity(const EC_GROUP* group, const EC_POINT* point);

X509_ATTRIBUTE* X509_ATTRIBUTE_dup(const X509_ATTRIBUTE* x);

void ERR_add_error_vdata(int num, va_list args);

void DIRECTORYSTRING_free(ASN1_STRING* str);


int EVP_MAC_is_a(const EVP_MAC* mac, const char* name) {
    int Res = 0;
    sf_set_tainted(name);
    sf_set_must_be_not_null(mac, MAC_IS_A_OF_NULL);
    sf_set_must_be_not_null(name, MAC_IS_A_NAME_OF_NULL);
    sf_set_errno_if(Res == 0, MAC_IS_A_FAILURE);
    return Res;
}

int i2d_NETSCAPE_SPKAC(const NETSCAPE_SPKAC* spkac, unsigned char** pp) {
    int Res = 0;
    sf_set_must_be_not_null(spkac, I2D_NETSCAPE_SPKAC_SPKAC_OF_NULL);
    sf_set_must_be_not_null(pp, I2D_NETSCAPE_SPKAC_PP_OF_NULL);
    sf_set_errno_if(Res <= 0, I2D_NETSCAPE_SPKAC_FAILURE);
    return Res;
}

int EVP_CIPHER_meth_set_get_asn1_params(EVP_CIPHER* cipher, int (*get_asn1_params)(EVP_CIPHER_CTX*, ASN1_TYPE*)) {
    int Res = 0;
    sf_set_must_be_not_null(cipher, EVP_CIPHER_METH_SET_GET_ASN1_PARAMS_CIPHER_OF_NULL);
    sf_set_must_be_not_null(get_asn1_params, EVP_CIPHER_METH_SET_GET_ASN1_PARAMS_GET_ASN1_PARAMS_OF_NULL);
    sf_set_errno_if(Res == 0, EVP_CIPHER_METH_SET_GET_ASN1_PARAMS_FAILURE);
    return Res;
}

const BIO_METHOD* BIO_s_socket() {
    const BIO_METHOD* Res = NULL;
    sf_set_errno_if(Res == NULL, BIO_S_SOCKET_FAILURE);
    return Res;
}

int EVP_PKEY_CTX_is_a(EVP_PKEY_CTX* ctx, const char* name) {
    int Res = 0;
    sf_set_tainted(name);
    sf_set_must_be_not_null(ctx, EVP_PKEY_CTX_IS_A_OF_NULL);
    sf_set_must_be_not_null(name, EVP_PKEY_CTX_IS_A_NAME_OF_NULL);
    sf_set_errno_if(Res == 0, EVP_PKEY_CTX_IS_A_FAILURE);
    return Res;
}

int RSA_get0_multi_prime_crt_params(const RSA *rsa, const BIGNUM *primes[], const BIGNUM *exps[])
{
    int res = 0;
    sf_set_must_be_not_null(rsa, RSA_NULL);
    sf_set_possible_null(primes);
    sf_set_possible_null(exps);
    sf_set_errno_if(res == 0, EINVAL);
    sf_no_errno_if(res != 0);
    return res;
}

void RSA_clear_flags(RSA *rsa, int flags)
{
    sf_set_must_be_not_null(rsa, RSA_NULL);
    sf_set_tainted(flags);
}

void X509V3_set_ctx(X509V3_CTX *ctx, X509 *issuer, X509 *subject, X509_REQ *req, X509_CRL *crl, int flags)
{
    sf_set_must_be_not_null(ctx, X509V3_CTX_NULL);
    sf_set_possible_null(issuer);
    sf_set_possible_null(subject);
    sf_set_possible_null(req);
    sf_set_possible_null(crl);
    sf_set_tainted(flags);
}

int i2d_DSA_SIG(const DSA_SIG *sig, unsigned char **pp)
{
    int res = 0;
    sf_set_must_be_not_null(sig, DSA_SIG_NULL);
    sf_set_must_be_not_null(pp, PP_NULL);
    sf_set_errno_if(res == 0, EINVAL);
    sf_no_errno_if(res != 0);
    return res;
}

PKCS7_ENC_CONTENT *d2i_PKCS7_ENC_CONTENT(PKCS7_ENC_CONTENT **a, const unsigned char **pp, long length)
{
    PKCS7_ENC_CONTENT *res = NULL;
    sf_set_must_be_not_null(a, PKCS7_ENC_CONTENT_NULL);
    sf_set_must_be_not_null(pp, PP_NULL);
    sf_set_buf_size_limit(*pp, length);
    sf_set_errno_if(res == NULL, EINVAL);
    sf_no_errno_if(res != NULL);
    return res;
}

X509_EXTENSION* X509_REVOKED_get_ext(const X509_REVOKED* revoked, int loc) {
    X509_EXTENSION* Res = NULL;
    sf_set_trusted_sink_int(loc);
    Res = revoked->extensions[loc];
    sf_overwrite(Res);
    return Res;
}

ENGINE* EVP_PKEY_get0_engine(const EVP_PKEY* pkey) {
    ENGINE* Res = NULL;
    Res = pkey->engine;
    sf_overwrite(Res);
    return Res;
}

const EVP_MD* EVP_sha3_384() {
    const EVP_MD* Res = NULL;
    Res = EVP_sha3_384();
    sf_overwrite(Res);
    return Res;
}

const EVP_CIPHER* EVP_aes_128_ecb() {
    const EVP_CIPHER* Res = NULL;
    Res = EVP_aes_128_ecb();
    sf_overwrite(Res);
    return Res;
}

void* X509_get_ex_data(const X509* x, int idx) {
    void* Res = NULL;
    sf_set_trusted_sink_int(idx);
    Res = CRYPTO_get_ex_data(&x->ex_data, idx);
    sf_overwrite(Res);
    return Res;
}
BIO* ASN1_item_i2d_mem_bio(const ASN1_ITEM* it, const ASN1_VALUE* val) {
    BIO* Res = NULL;
    // Implementation of the function
    return Res;
}

int RAND_priv_bytes_ex(OSSL_LIB_CTX* ctx, unsigned char* buf, size_t len, unsigned int flags) {
    int Res = 0;
    // Implementation of the function
    return Res;
}

int OPENSSL_gmtime_diff(int* out_days, int* out_secs, const tm* from, const tm* to) {
    int Res = 0;
    // Implementation of the function
    return Res;
}

X509_NAME* X509_NAME_dup(const X509_NAME* xn) {
    X509_NAME* Res = NULL;
    // Implementation of the function
    return Res;
}

int BN_bn2binpad(const BIGNUM* a, unsigned char* to, int tolen) {
    int Res = 0;
    // Implementation of the function
    return Res;
}
ENGINE* Res = NULL;
sf_lib_arg_type(Res, "ENGINE");
ENGINE_get_default_DH();

int Res = 0;
sf_set_errno_if(Res, PKCS8_pkey_add1_attr(p8, attr));

long Res = 0;
sf_set_errno_if(Res, X509_get_version(x));

int Res = 0;
sf_set_errno_if(Res, SSL_set_record_padding_callback(s, cb));

EVP_PKEY_meth_get_verifyctx(pmeth, pverifyctx, pverifyctx_recover);

int DH_meth_set_generate_params(DH_METHOD* dh_meth, int (*generate_params)(DH*, int, int, BN_GENCB*))
{
    int Res = 0;
    sf_set_trusted_sink_int(generate_params);
    sf_set_trusted_sink_ptr(dh_meth);
    sf_set_tainted(dh_meth);
    sf_set_errno_if(Res == 0);
    return Res;
}

int i2d_CRL_DIST_POINTS(const CRL_DIST_POINTS* cdp, unsigned char** out)
{
    int Res = 0;
    sf_set_trusted_sink_ptr(out);
    sf_set_tainted(cdp);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int EVP_PKEY_paramgen_init(EVP_PKEY_CTX* ctx)
{
    int Res = 0;
    sf_set_trusted_sink_ptr(ctx);
    sf_set_tainted(ctx);
    sf_set_errno_if(Res <= 0);
    return Res;
}

const char* EVP_MD_get0_description(const EVP_MD* md)
{
    const char* Res = NULL;
    sf_set_tainted(md);
    sf_set_errno_if(Res == NULL);
    return Res;
}

void EC_GROUP_set_curve_name(EC_GROUP* group, int nid)
{
    sf_set_trusted_sink_int(nid);
    sf_set_tainted(group);
}

int CRYPTO_secure_allocated(const void *ptr) {
    int res = 0;
    sf_set_trusted_sink_int(ptr);
    res = sf_secure_allocated(ptr);
    return res;
}

UI_string_types UI_get_string_type(UI_STRING *ui) {
    UI_string_types res = 0;
    res = sf_UI_get_string_type(ui);
    return res;
}

PBEPARAM* PBEPARAM_new() {
    PBEPARAM* res = NULL;
    res = sf_PBEPARAM_new();
    return res;
}

OCSP_CERTSTATUS* OCSP_CERTSTATUS_new() {
    OCSP_CERTSTATUS* res = NULL;
    res = sf_OCSP_CERTSTATUS_new();
    return res;
}

int EVP_MAC_get_params(EVP_MAC *mac, OSSL_PARAM params[]) {
    int res = 0;
    res = sf_EVP_MAC_get_params(mac, params);
    return res;
}

void SHA224_Init(SHA256_CTX* ctx) {
    int res = 0;
    sf_set_trusted_sink_int(ctx);
    sf_overwrite(ctx);
    sf_bitinit(ctx);
    return res;
}

int i2d_NAMING_AUTHORITY(const NAMING_AUTHORITY* na, unsigned char** pp) {
    int res = 0;
    sf_password_use(na);
    sf_buf_size_limit(pp, size);
    sf_buf_stop_at_null(pp);
    sf_set_errno_if(res < 0);
    return res;
}

int EVP_ENCODE_CTX_num(EVP_ENCODE_CTX* ctx) {
    int res = 0;
    sf_set_must_be_not_null(ctx, EVP_ENCODE_CTX_num_of_null);
    sf_set_possible_null(res);
    return res;
}

int SSL_ct_is_enabled(const SSL* s) {
    int res = 0;
    sf_set_must_be_not_null(s, SSL_ct_is_enabled_of_null);
    sf_set_possible_null(res);
    return res;
}

const RAND_METHOD* RAND_get_rand_method() {
    const RAND_METHOD* res = NULL;
    sf_set_possible_null(res);
    return res;
}
int DH_meth_set0_app_data(DH_METHOD* dh, void* app_data);

void SSL_set_info_callback(SSL* s, void (*cb);

int UI_get_result_maxsize(UI_STRING* uis);

ASN1_GENERALIZEDTIME* ASN1_TIME_to_generalizedtime(const ASN1_TIME* t, ASN1_GENERALIZEDTIME** out);

int RSA_verify_ASN1_OCTET_STRING(int type, const unsigned char* m, unsigned int m_len, unsigned char* sig, unsigned int sig_len, RSA* rsa);

Here are the specifications for the functions:

stack_st_X509* PKCS7_get0_signers(PKCS7* p7, stack_st_X509* signers, int flags)
```
sf_set_trusted_sink_int(flags);
stack_st_X509* Res = NULL;
Res = PKCS7_get0_signers(p7, signers, flags);
sf_set_possible_null(Res);
return Res;
```

void ERR_print_errors_fp(FILE* fp)
```
sf_set_must_be_not_null(fp, FREE_OF_NULL);
ERR_print_errors_fp(fp);
```

void EVP_PKEY_meth_set_copy(EVP_PKEY_METHOD* pmeth, int (*copy)(EVP_PKEY_CTX*, const EVP_PKEY_CTX*)* copy)
```
sf_set_must_be_not_null(pmeth, FREE_OF_NULL);
EVP_PKEY_meth_set_copy(pmeth, copy);
```

int BN_is_prime_fasttest_ex(const BIGNUM* b, int checks, BN_CTX* ctx, int do_trial_division, BN_GENCB* cb)
```
sf_set_must_be_not_null(b, FREE_OF_NULL);
sf_set_must_be_not_null(ctx, FREE_OF_NULL);
int Res = BN_is_prime_fasttest_ex(b, checks, ctx, do_trial_division, cb);
sf_set_errno_if(Res <= 0);
return Res;
```

void PKCS7_SIGNER_INFO_free(PKCS7_SIGNER_INFO* si)
```
sf_set_must_be_not_null(si, FREE_OF_NULL);
PKCS7_SIGNER_INFO_free(si);
```int X509_set1_notAfter(X509*, const ASN1_TIME*);

int EVP_RAND_generate(EVP_RAND_CTX*, unsigned char*, size_t, unsigned int, int, const unsigned char*, size_t);

void* CRYPTO_get_ex_data(const CRYPTO_EX_DATA*, int);

int UI_method_set_writer(UI_METHOD*, int (UI*, UI_STRING*);

int X509_REVOKED_get_ext_count(const X509_REVOKED*);


void* EVP_PKEY_CTX_get_app_data(EVP_PKEY_CTX* ctx) {
    void *Res = NULL;
    Res = ctx->app_data;
    sf_set_possible_null(Res);
    return Res;
}

void CONF_modules_finish() {
    sf_terminate_path();
}

int DH_meth_set1_name(DH_METHOD *dh_meth, const char *name) {
    int Res = 0;
    sf_set_must_be_not_null(name, DH_METH_SET1_NAME_OF_NULL);
    dh_meth->name = name;
    Res = 1;
    return Res;
}

const char* SSL_COMP_get0_name(const SSL_COMP* comp) {
    const char *Res = NULL;
    sf_set_possible_null(Res);
    Res = comp->name;
    return Res;
}

int X509_REVOKED_get_ext_by_OBJ(const X509_REVOKED* rev, const ASN1_OBJECT* obj, int lastpos) {
    int Res = -1;
    sf_set_must_be_not_null(rev, X509_REVOKED_GET_EXT_BY_OBJ_OF_NULL);
    sf_set_must_be_not_null(obj, X509_REVOKED_GET_EXT_BY_OBJ_OF_NULL);
    Res = X509v3_get_ext_by_OBJ(rev->extensions, obj, lastpos);
    return Res;
}

char* i2s_ASN1_INTEGER(X509V3_EXT_METHOD* method, const ASN1_INTEGER* num) {
    char* Res = NULL;
    sf_set_trusted_sink_int(num);
    Res = i2s_ASN1_INTEGER(method, num);
    sf_overwrite(Res);
    return Res;
}

int EVP_RAND_get_params(EVP_RAND* rand, OSSL_PARAM params[]) {
    int Res = 0;
    Res = EVP_RAND_get_params(rand, params);
    sf_set_errno_if(Res == 0);
    return Res;
}

ASIdOrRange* ASIdOrRange_new() {
    ASIdOrRange* Res = NULL;
    Res = ASIdOrRange_new();
    sf_set_alloc_possible_null(Res);
    return Res;
}

int UI_set_result(UI* ui, UI_STRING* uis, const char* result) {
    int Res = 0;
    sf_password_use(result);
    Res = UI_set_result(ui, uis, result);
    sf_set_errno_if(Res == 0);
    return Res;
}

int X509_STORE_add_crl(X509_STORE* ctx, X509_CRL* x) {
    int Res = 0;
    Res = X509_STORE_add_crl(ctx, x);
    sf_set_errno_if(Res == 0);
    return Res;
}

void EVP_SIGNATURE_names_do_all(const EVP_SIGNATURE *signature, void (*fn)(const char *name, void *data), void *data)
{
    int res = 0;
    sf_set_trusted_sink_int(signature);
    sf_set_trusted_sink_ptr(fn);
    sf_set_trusted_sink_ptr(data);
    sf_set_errno_if(res);
    sf_no_errno_if(!res);
}

int EVP_PKEY_CTX_set_group_name(EVP_PKEY_CTX *ctx, const char *name)
{
    int res = 0;
    sf_set_trusted_sink_ptr(ctx);
    sf_set_trusted_sink_ptr(name);
    sf_set_errno_if(res);
    sf_no_errno_if(!res);
    return res;
}

int SSL_set_alpn_protos(SSL *ssl, const unsigned char *protos, unsigned int protos_len)
{
    int res = 0;
    sf_set_trusted_sink_ptr(ssl);
    sf_set_trusted_sink_ptr(protos);
    sf_set_trusted_sink_int(protos_len);
    sf_set_errno_if(res);
    sf_no_errno_if(!res);
    return res;
}

int DH_generate_parameters_ex(DH *dh, int bits, int qbits, BN_GENCB *cb)
{
    int res = 0;
    sf_set_trusted_sink_ptr(dh);
    sf_set_trusted_sink_int(bits);
    sf_set_trusted_sink_int(qbits);
    sf_set_trusted_sink_ptr(cb);
    sf_set_errno_if(res);
    sf_no_errno_if(!res);
    return res;
}

int SSL_CONF_cmd_value_type(SSL_CONF_CTX *ctx, const char *cmd)
{
    int res = 0;
    sf_set_trusted_sink_ptr(ctx);
    sf_set_trusted_sink_ptr(cmd);
    sf_set_errno_if(res);
    sf_no_errno_if(!res);
    return res;
}

int RSA_padding_add_PKCS1_OAEP_mgf1(unsigned char *to, int tlen, const unsigned char *from, int flen, const unsigned char *param, int plen, const EVP_MD *md, const EVP_MD *mgf1md)
{
    int res = 0;
    sf_set_trusted_sink_int(tlen);
    sf_set_trusted_sink_int(flen);
    sf_set_trusted_sink_int(plen);
    sf_set_tainted(from, flen);
    sf_set_tainted(param, plen);
    sf_set_tainted(md);
    sf_set_tainted(mgf1md);
    sf_set_errno_if(res == 0);
    return res;
}

int EVP_PKEY_verify_recover(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen)
{
    int res = 0;
    sf_set_tainted(ctx);
    sf_set_tainted(tbs, tbslen);
    sf_set_errno_if(res <= 0);
    return res;
}

int DH_size(const DH *dh)
{
    int res = 0;
    sf_set_tainted(dh);
    sf_set_errno_if(res == 0);
    return res;
}

BIO* BIO_find_type(BIO *bio, int type)
{
    BIO *res = NULL;
    sf_set_tainted(bio);
    sf_set_tainted(type);
    sf_set_possible_null(res);
    sf_set_alloc_possible_null(res);
    return res;
}

X509_ALGOR* PKCS5_pbe2_set(const EVP_CIPHER *cipher, int iter, unsigned char *salt, int saltlen)
{
    X509_ALGOR *res = NULL;
    sf_set_tainted(cipher);
    sf_set_tainted(iter);
    sf_set_tainted(salt, saltlen);
    sf_set_possible_null(res);
    sf_set_alloc_possible_null(res);
    return res;
}
int SSL_set_ct_validation_callback(SSL*, ssl_ct_validation_cb, void*);

int BN_rand(BIGNUM*, int, int, int);

int EVP_DigestSignFinal(EVP_MD_CTX*, unsigned char*, size_t*);

int OSSL_HTTP_is_alive(const OSSL_HTTP_REQ_CTX*);

const ASN1_TIME* X509_CRL_get0_nextUpdate(const X509_CRL*);

void ERR_print_errors(BIO* bio);

ASN1_OCTET_STRING* d2i_ASN1_OCTET_STRING(ASN1_OCTET_STRING** a, const unsigned char** pp, long length);

void CT_POLICY_EVAL_CTX_free(CT_POLICY_EVAL_CTX* ctx);

int OPENSSL_LH_error(OPENSSL_LHASH* lh);

unsigned long ERR_peek_error_line(const char** file, int* line);


const DH_METHOD* DH_OpenSSL() {
    const DH_METHOD* Res = NULL;
    Res = DH_OpenSSL();
    sf_lib_arg_type(Res, "DH_METHOD");
    return Res;
}

int X509_VERIFY_PARAM_set_purpose(X509_VERIFY_PARAM* param, int purpose) {
    int Res = 0;
    sf_set_must_be_not_null(param, SET_PURPOSE_OF_NULL);
    Res = X509_VERIFY_PARAM_set_purpose(param, purpose);
    sf_set_errno_if(Res <= 0);
    return Res;
}

const EVP_CIPHER* EVP_aes_192_wrap_pad() {
    const EVP_CIPHER* Res = NULL;
    Res = EVP_aes_192_wrap_pad();
    sf_lib_arg_type(Res, "EVP_CIPHER");
    return Res;
}

RSA* RSAPrivateKey_dup(const RSA* rsa) {
    RSA* Res = NULL;
    sf_set_must_be_not_null(rsa, DUP_RSA_OF_NULL);
    Res = RSAPrivateKey_dup(rsa);
    sf_set_alloc_possible_null(Res);
    return Res;
}

void ERR_vset_error(int lib, int reason, const char* fmt, va_list args) {
    ERR_vset_error(lib, reason, fmt, args);
}
Here are the specifications for the functions:

1. int BN_rand_range_ex(BIGNUM*, const BIGNUM*, unsigned int, BN_CTX*):

```c
void BN_rand_range_ex(BIGNUM *res, const BIGNUM *range, unsigned int n, BN_CTX *ctx) {
    sf_set_trusted_sink_int(n);
    sf_set_must_be_not_null(range, RAND_RANGE_EX_OF_NULL);
    sf_set_must_be_not_null(ctx, RAND_RANGE_EX_OF_NULL);
    sf_set_errno_if(res == NULL, RAND_RANGE_EX_OF_NULL);
    sf_set_possible_null(res);
    sf_set_possible_null(ctx);
    sf_set_possible_null(range);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_possible_null(ctx);
    sf_set_int RSA_set_ex_data(RSA* r, int idx, void* arg);

int BN_security_bits(int bits, int n);

void SSL_CONF_CTX_set_ssl_ctx(SSL_CONF_CTX* cctx, SSL_CTX* ctx);

int UI_ctrl(UI* ui, int cmd, long larg, void* parg, void (*);

void SSL_CTX_set_next_proto_select_cb(SSL_CTX* s, SSL_CTX_npn_select_cb_func cb, void* arg);


void PKCS7_SIGN_ENVELOPE_free(PKCS7_SIGN_ENVELOPE* a) {
    if (a != NULL) {
        OPENSSL_free(a);
    }
}

void X509_STORE_set_cert_crl(X509_STORE *ctx, X509_STORE_CTX_cert_crl_fn cb) {
    if (ctx != NULL) {
        ctx->get_crl = cb;
    }
}

int EVP_PKEY_set_octet_string_param(EVP_PKEY *pkey, const char *key, const unsigned char *data, size_t len) {
    int ret = 0;
    ASN1_OCTET_STRING *os = NULL;

    if (pkey == NULL || key == NULL || data == NULL) {
        return 0;
    }

    os = ASN1_OCTET_STRING_new();
    if (os == NULL) {
        return 0;
    }

    if (!ASN1_OCTET_STRING_set(os, data, len)) {
        goto err;
    }

    ret = EVP_PKEY_add1_attr_by_NID(pkey, NID_undef, key, os);

err:
    ASN1_OCTET_STRING_free(os);
    return ret;
}

int SSL_CTX_get_security_level(const SSL_CTX *ctx) {
    if (ctx != NULL) {
        return ctx->security_level;
    }

    return -1;
}

const GENERAL_NAME* ADMISSION_SYNTAX_get0_admissionAuthority(const ADMISSION_SYNTAX *adms) {
    if (adms != NULL) {
        return adms->admissionAuthority;
    }

    return NULL;
}
EXTENDED_KEY_USAGE* d2i_EXTENDED_KEY_USAGE(EXTENDED_KEY_USAGE** a, const unsigned char** pp, long length);

const EVP_MD* EVP_blake2b512();

OSSL_PARAM OSSL_PARAM_construct_uint32(const char* key, uint32_t* val);

void POLICY_MAPPING_free(POLICY_MAPPING* pm);

int SSL_verify_client_post_handshake(SSL* s);

int RAND_priv_bytes(unsigned char* buf, int num);

int SCT_LIST_validate(const stack_st_SCT* scts, CT_POLICY_EVAL_CTX* ctx);

X509_PUBKEY* PEM_read_X509_PUBKEY(FILE* fp, X509_PUBKEY** x, pem_password_cb* cb, void* u);

const EVP_CIPHER* EVP_des_ede3_cfb64();

ASN1_INTEGER* s2i_ASN1_INTEGER(X509V3_EXT_METHOD* method, const char* value);

int i2d_X509_EXTENSIONS(const X509_EXTENSIONS* exts, unsigned char** pp);

int EVP_PKEY_todata(const EVP_PKEY* pkey, int selection, OSSL_PARAM** params);

int EVP_PKEY_print_params(BIO* out, const EVP_PKEY* pkey, int indent, ASN1_PCTX* pctx);

unsigned long ERR_get_error_all(const char** file, int* line, const char** data, const char** flags, int* (ERR_FATAL_ERROR);

const EVP_CIPHER* EVP_aria_256_cfb128();


int BN_priv_rand_ex(BIGNUM *rnd, int bits, int top, int bottom, unsigned int flags, BN_CTX *ctx) {
    int Res = 0;
    sf_set_trusted_sink_int(bits);
    sf_set_trusted_sink_int(top);
    sf_set_trusted_sink_int(bottom);
    sf_set_trusted_sink_int(flags);
    sf_set_errno_if(Res <= 0);
    return Res;
}

size_t OSSL_HTTP_REQ_CTX_get_resp_len(const OSSL_HTTP_REQ_CTX *ctx) {
    size_t Res = 0;
    sf_set_errno_if(Res == 0);
    return Res;
}

int X509_get_signature_nid(const X509 *x) {
    int Res = 0;
    sf_set_errno_if(Res <= 0);
    return Res;
}

ASN1_STRING* d2i_DISPLAYTEXT(ASN1_STRING **a, const unsigned char **in, long len) {
    ASN1_STRING *Res = NULL;
    sf_set_trusted_sink_int(len);
    sf_set_errno_if(Res == NULL);
    return Res;
}

unsigned long ERR_peek_error_line_data(const char **file, int *line, const char **data, int *flags) {
    unsigned long Res = 0;
    sf_set_errno_if(Res == 0);
    return Res;
}

const BIGNUM* DSA_get0_g(const DSA* dsa) {
    const BIGNUM* Res = NULL;
    Res = dsa->g;
    sf_set_possible_null(Res);
    return Res;
}

const ASN1_IA5STRING* NAMING_AUTHORITY_get0_authorityURL(const NAMING_AUTHORITY* naming_authority) {
    const ASN1_IA5STRING* Res = NULL;
    Res = naming_authority->authorityURL;
    sf_set_possible_null(Res);
    return Res;
}

CT_POLICY_EVAL_CTX* CT_POLICY_EVAL_CTX_new_ex(OSSL_LIB_CTX* libctx, const char* propq) {
    CT_POLICY_EVAL_CTX* Res = NULL;
    Res = CT_POLICY_EVAL_CTX_new();
    sf_set_alloc_possible_null(Res);
    return Res;
}

int BN_div_recp(BIGNUM* dv, BIGNUM* rem, const BIGNUM* m, BN_RECP_CTX* recp, BN_CTX* ctx) {
    int Res = 0;
    Res = BN_div_recp(dv, rem, m, recp, ctx);
    sf_set_errno_if(Res == 0);
    return Res;
}

int DH_set_method(DH* dh, const DH_METHOD* meth) {
    int Res = 0;
    Res = DH_set_method(dh, meth);
    sf_set_errno_if(Res == 0);
    return Res;
}
int PKCS5_pbe_set0_algor(X509_ALGOR *algor, int iter, int keylen, const unsigned char *salt, int saltlen);

int i2d_ASN1_TIME(const ASN1_TIME *a, unsigned char **pp);

X509_STORE_CTX_check_issued_fn X509_STORE_get_check_issued(const X509_STORE *ctx);

char *X509_VERIFY_PARAM_get0_peername(const X509_VERIFY_PARAM *param);

int SSL_add_file_cert_subjects_to_stack(stack_st_X509_NAME *names, const char *file);


int EVP_PKEY_print_public_fp(FILE *fp, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx) {
    int res = 0;
    // Specify the file pointer as a trusted sink pointer
    sf_set_trusted_sink_ptr(fp);
    // Check for null values
    sf_set_must_be_not_null(fp, "File");
    sf_set_must_be_not_null(pkey, "EVP_PKEY");
    // Check for possible negative values
    sf_set_possible_negative(res);
    // Check for errno
    sf_set_errno_if(res == 0);
    return res;
}

long SSL_get_default_timeout(const SSL *ssl) {
    long res = 0;
    // Check for null values
    sf_set_must_be_not_null(ssl, "SSL");
    // Check for possible negative values
    sf_set_possible_negative(res);
    return res;
}

BIGNUM* SSL_get_srp_N(SSL *ssl) {
    BIGNUM *res = NULL;
    // Check for null values
    sf_set_must_be_not_null(ssl, "SSL");
    // Check for possible null return
    sf_set_possible_null(res);
    return res;
}

DSA* PEM_read_DSA_PUBKEY(FILE *fp, DSA **x, pem_password_cb *cb, void *u) {
    DSA *res = NULL;
    // Specify the file pointer as a trusted sink pointer
    sf_set_trusted_sink_ptr(fp);
    // Check for null values
    sf_set_must_be_not_null(fp, "File");
    sf_set_must_be_not_null(x, "DSA");
    // Check for possible null return
    sf_set_possible_null(res);
    // Check for errno
    sf_set_errno_if(res == NULL);
    return res;
}

int EVP_DigestVerify(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen) {
    int res = 0;
    // Check for null values
    sf_set_must_be_not_null(ctx, "EVP_MD_CTX");
    sf_set_must_be_not_null(sig, "Signature");
    sf_set_must_be_not_null(tbs, "TBs");
    // Check for possible negative values
    sf_set_possible_negative(res);
    // Check for errno
    sf_set_errno_if(res <= 0);
    return res;
}

int ASN1_TIME_cmp_time_t(const ASN1_TIME* time1, time_t time2)
{
    int res = 0;
    sf_set_must_be_not_null(time1, ASN1_TIME_NULL);
    sf_set_must_be_not_null(time2, TIME_T_NULL);
    sf_set_errno_if(res == -2, EINVAL);
    return res;
}

const BIO_METHOD* BIO_f_cipher()
{
    const BIO_METHOD* res = NULL;
    sf_set_possible_null(res);
    return res;
}

EC_POINT* EC_POINT_dup(const EC_POINT* point, const EC_GROUP* group)
{
    EC_POINT* res = NULL;
    sf_set_must_be_not_null(point, EC_POINT_NULL);
    sf_set_must_be_not_null(group, EC_GROUP_NULL);
    sf_set_alloc_possible_null(res);
    return res;
}

const char* SSL_get0_peername(SSL* s)
{
    const char* res = NULL;
    sf_set_must_be_not_null(s, SSL_NULL);
    sf_set_possible_null(res);
    return res;
}

const BIGNUM* DSA_get0_q(const DSA* dsa)
{
    const BIGNUM* res = NULL;
    sf_set_must_be_not_null(dsa, DSA_NULL);
    sf_set_possible_null(res);
    return res;
}

void X509_REQ_set0_signature(X509_REQ* req, ASN1_BIT_STRING* sig)
{
    sf_set_trusted_sink_int(sig);
    sf_set_trusted_sink_ptr(req);
    sf_overwrite(req);
}

int UI_add_verify_string(UI* ui, const char* text, int flags, char* result, int maxlen, int* result_len, const char* prompt)
{
    sf_set_trusted_sink_ptr(ui);
    sf_set_trusted_sink_ptr(result);
    sf_set_trusted_sink_ptr(result_len);
    sf_set_trusted_sink_ptr(prompt);
    sf_set_tainted(text);
    sf_set_tainted(result);
    sf_set_tainted(prompt);
    sf_set_must_not_be_null(result);
    sf_set_must_not_be_null(result_len);
    sf_set_must_not_be_null(prompt);
    sf_set_buf_size(result, maxlen);
    sf_set_buf_size_limit_read(text, maxlen);
    sf_set_buf_stop_at_null(text);
    sf_set_buf_stop_at_null(prompt);
    sf_set_errno_if(result_len, *result_len < 0);
    sf_set_errno_if(result_len, *result_len > maxlen);
    sf_set_possible_null(result);
    sf_set_possible_null(result_len);
    sf_set_possible_null(prompt);
    sf_set_possible_negative(*result_len);
    sf_set_possible_negative(flags);
    sf_set_possible_negative(maxlen);
    sf_set_possible_negative(result_len);
    sf_set_possible_negative(prompt);
    sf_set_possible_negative(text);
    sf_set_possible_negative(ui);
    sf_set_possible_negative(result);
    return 0;
}

int BIO_get_line(BIO* bio, char* buf, int size)
{
    sf_set_trusted_sink_ptr(bio);
    sf_set_trusted_sink_ptr(buf);
    sf_set_must_not_be_null(buf);
    sf_set_buf_size(buf, size);
    sf_set_buf_size_limit_read(buf, size);
    sf_set_buf_stop_at_null(buf);
    sf_set_errno_if(size, size < 0);
    sf_set_errno_if(size, size > INT_MAX);
    sf_set_possible_null(buf);
    sf_set_possible_null(bio);
    sf_set_possible_negative(size);
    return 0;
}

X509_CINF* d2i_X509_CINF(X509_CINF** a, const unsigned char** in, long len)
{
    sf_set_trusted_sink_ptr(a);
    sf_set_trusted_sink_ptr(in);
    sf_set_must_not_be_null(a);
    sf_set_must_not_be_null(in);
    sf_set_buf_size_limit_read(*in, len);
    sf_set_errno_if(len, len < 0);
    sf_set_errno_if(len, len > LONG_MAX);
    sf_set_possible_null(*a);
    sf_set_possible_null(*in);
    sf_set_possible_negative(len);
    return NULL;
}

OSSL_LIB_CTX* EVP_PKEY_CTX_get0_libctx(EVP_PKEY_CTX* ctx)
{
    sf_set_trusted_sink_ptr(ctx);
    sf_set_must_not_be_null(ctx);
    sf_set_possible_null(ctx);
    return NULL;
}
int EVP_PKEY_get_attr_count(const EVP_PKEY* pkey);

const char* ASN1_tag2str(int tag);

int EVP_MAC_up_ref(EVP_MAC* mac);

int BN_GENCB_call(BN_GENCB* cb, int a, int b);

int ASYNC_WAIT_CTX_set_callback(ASYNC_WAIT_CTX* ctx, ASYNC_callback_fn cb, void* arg);


long X509_get_proxy_pathlen(X509 *x) {
    long res = 0;
    // Function body
    sf_overwrite(&res);
    return res;
}

int ENGINE_set_ctrl_function(ENGINE *e, ENGINE_CTRL_FUNC_PTR f) {
    int res = 0;
    // Function body
    sf_overwrite(&res);
    return res;
}

void SSL_CTX_set_stateless_cookie_verify_cb(SSL_CTX *ctx, int (*cb)(SSL*, const unsigned char*, size_t)) {
    // Function body
    // No return value, so no need to overwrite anything
}

POLICY_MAPPING* POLICY_MAPPING_new() {
    POLICY_MAPPING *res = NULL;
    // Function body
    sf_overwrite(res);
    return res;
}

BIGNUM* BN_generate_prime(BIGNUM *ret, int bits, int safe, const BIGNUM *add, const BIGNUM *rem, void (*cb)(int, int, void*), void *cb_arg) {
    BIGNUM *res = NULL;
    // Function body
    sf_overwrite(res);
    return res;
}
void BN_GENCB_free(BN_GENCB* cb);

int UI_set_ex_data(UI* ui, int idx, void* data);

void X509_STORE_CTX_set_verify_cb(X509_STORE_CTX* ctx, X509_STORE_CTX_verify_cb verify_cb);

int PEM_write_X509_CRL(FILE* out, const X509_CRL* crl);

int BIO_vsnprintf(char* buf, size_t size, const char* format, va_list args);


int i2d_ASN1_PRINTABLE(const ASN1_STRING* a, unsigned char** pp)
{
    int ret = 0;
    sf_set_must_be_not_null(a, "ASN1_STRING");
    sf_set_must_be_not_null(pp, "unsigned char**");
    sf_set_tainted(a);
    sf_set_errno_if(ret <= 0, "i2d_ASN1_PRINTABLE");
    sf_set_possible_null(pp);
    sf_set_possible_negative(ret);
    return ret;
}

const char* OSSL_HTTP_adapt_proxy(const char* proxy, const char* no_proxy, const char* host, int port)
{
    const char* res = NULL;
    sf_set_must_be_not_null(proxy, "proxy");
    sf_set_must_be_not_null(no_proxy, "no_proxy");
    sf_set_must_be_not_null(host, "host");
    sf_set_tainted(proxy);
    sf_set_tainted(no_proxy);
    sf_set_tainted(host);
    sf_set_possible_null(res);
    return res;
}

int BN_BLINDING_invert(BIGNUM* a, BN_BLINDING* b, BN_CTX* c)
{
    int ret = 0;
    sf_set_must_be_not_null(a, "BIGNUM*");
    sf_set_must_be_not_null(b, "BN_BLINDING*");
    sf_set_must_be_not_null(c, "BN_CTX*");
    sf_set_errno_if(ret <= 0, "BN_BLINDING_invert");
    sf_set_possible_negative(ret);
    return ret;
}

uint64_t SSL_CTX_get_options(const SSL_CTX* ctx) {
    uint64_t Res = 0;
    sf_set_trusted_sink_int(ctx);
    sf_set_trusted_sink_int(Res);
    sf_overwrite(Res);
    return Res;
}

int EC_GROUP_cmp(const EC_GROUP* a, const EC_GROUP* b, BN_CTX* ctx) {
    int Res = 0;
    sf_set_trusted_sink_int(a);
    sf_set_trusted_sink_int(b);
    sf_set_trusted_sink_int(ctx);
    sf_set_trusted_sink_int(Res);
    sf_overwrite(Res);
    return Res;
}

int SSL_get0_dane_authority(SSL* s, X509** auth, EVP_PKEY** pkey) {
    int Res = 0;
    sf_set_trusted_sink_int(s);
    sf_set_trusted_sink_int(auth);
    sf_set_trusted_sink_int(pkey);
    sf_set_trusted_sink_int(Res);
    sf_overwrite(Res);
    return Res;
}

uint8_t SSL_SESSION_get_max_fragment_length(const SSL_SESSION* sess) {
    uint8_t Res = 0;
    sf_set_trusted_sink_int(sess);
    sf_set_trusted_sink_int(Res);
    sf_overwrite(Res);
    return Res;
}

void PROFESSION_INFO_set0_professionItems(PROFESSION_INFO* info, stack_st_ASN1_STRING* items) {
    sf_set_trusted_sink_int(info);
    sf_set_trusted_sink_int(items);
}
void EVP_PKEY_meth_get_verify_recover(const EVP_PKEY_METHOD *pmeth, int (**verify_recover);

X509_CRL* X509_CRL_new();

void EVP_KEYEXCH_do_all_provided(OSSL_LIB_CTX *ctx, void (*fn);

lhash_st_SSL_SESSION* SSL_CTX_sessions(SSL_CTX* ctx);

PKCS7* PKCS7_new_ex(OSSL_LIB_CTX *libctx, const char *propq);


void i2d_ASN1_UTCTIME(const ASN1_UTCTIME *a, unsigned char **pp)
{
    int res = 0;
    sf_set_trusted_sink_int(a);
    sf_set_trusted_sink_ptr(pp);
    sf_set_buf_size(*pp, a->length);
    sf_bitcopy(*pp, a->data, a->length);
    *pp += a->length;
    sf_overwrite(res);
    return res;
}

int SSL_use_certificate_ASN1(SSL *ssl, const unsigned char *der, int derlen)
{
    int res = 0;
    sf_set_trusted_sink_int(ssl);
    sf_set_trusted_sink_ptr(der);
    sf_set_buf_size(der, derlen);
    sf_bitcopy(ssl->cert, der, derlen);
    sf_overwrite(res);
    return res;
}

const EVP_MD* EVP_md5_sha1()
{
    const EVP_MD* res = NULL;
    res = EVP_get_digestbyname("MD5-SHA1");
    sf_overwrite(res);
    return res;
}

X509_NAME_ENTRY* X509_NAME_get_entry(const X509_NAME *name, int loc)
{
    X509_NAME_ENTRY* res = NULL;
    sf_set_trusted_sink_int(name);
    sf_set_trusted_sink_int(loc);
    res = sk_X509_NAME_ENTRY_value(name->entries, loc);
    sf_overwrite(res);
    return res;
}

const SSL_METHOD* SSL_get_ssl_method(const SSL *s)
{
    const SSL_METHOD* res = NULL;
    sf_set_trusted_sink_int(s);
    res = s->method;
    sf_overwrite(res);
    return res;
}

EDIPARTYNAME* d2i_EDIPARTYNAME(EDIPARTYNAME** a, const unsigned char** pp, long length) {
    EDIPARTYNAME* Res = NULL;
    sf_set_trusted_sink_int(length);
    sf_malloc_arg(Res, length);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    return Res;
}

const SSL_METHOD* TLSv1_1_client_method() {
    const SSL_METHOD* Res = NULL;
    sf_set_possible_null(Res);
    return Res;
}

int X509_STORE_set1_param(X509_STORE* ctx, const X509_VERIFY_PARAM* param) {
    int Res = 0;
    sf_set_errno_if(Res);
    return Res;
}

void* (UI*, void*)* UI_method_get_data_duplicator(const UI_METHOD* method) {
    void* (UI*, void*)* Res = NULL;
    sf_set_possible_null(Res);
    return Res;
}

OCSP_SINGLERESP* OCSP_resp_get0(OCSP_BASICRESP* bs, int i) {
    OCSP_SINGLERESP* Res = NULL;
    sf_set_possible_null(Res);
    return Res;
}

int DSA_do_verify(const unsigned char* dgst, int dlen, DSA_SIG* sig, DSA* dsa) {
    int res = 0;
    sf_set_must_be_not_null(dsa, DSA_NULL);
    sf_set_must_be_not_null(sig, DSA_SIG_NULL);
    sf_set_must_be_not_null(dgst, DGST_NULL);
    sf_set_possible_null(res);
    return res;
}

void HMAC_CTX_free(HMAC_CTX* ctx) {
    sf_set_must_be_not_null(ctx, HMAC_CTX_NULL);
    sf_delete(ctx, HMAC_CTX_MEMORY_CATEGORY);
    sf_lib_arg_type(ctx, "HMAC_CTX_free");
}

int BIO_lookup_ex(const char* host, const char* service, int family, int socktype, int protocol, int flags, BIO_ADDRINFO** res) {
    int ret = 0;
    sf_set_must_be_not_null(host, HOST_NULL);
    sf_set_must_be_not_null(service, SERVICE_NULL);
    sf_set_must_be_not_null(res, BIO_ADDRINFO_NULL);
    sf_set_possible_null(ret);
    return ret;
}

int (BIO*)* BIO_meth_get_create(const BIO_METHOD* biom) {
    int (BIO*)* res = NULL;
    sf_set_must_be_not_null(biom, BIO_METHOD_NULL);
    sf_set_possible_null(res);
    return res;
}

const EVP_CIPHER* EVP_aria_256_cfb1() {
    const EVP_CIPHER* res = NULL;
    sf_set_possible_null(res);
    return res;
}

void SSL_set_connect_state(SSL* ssl) {
    sf_set_trusted_sink_ptr(ssl);
    sf_set_tainted(ssl);
    SSL_set_connect_state(ssl);
}

X509_STORE* X509_STORE_new() {
    X509_STORE* res = NULL;
    sf_new(res, PAGES_MEMORY_CATEGORY);
    res = X509_STORE_new();
    sf_set_alloc_possible_null(res);
    return res;
}

int EVP_PKEY_CTX_get0_rsa_oaep_label(EVP_PKEY_CTX* ctx, unsigned char** label) {
    int res = 0;
    sf_set_tainted(ctx);
    sf_set_tainted(label);
    res = EVP_PKEY_CTX_get0_rsa_oaep_label(ctx, label);
    sf_set_errno_if(res <= 0);
    return res;
}

int CONF_modules_load(const CONF* conf, const char* appname, unsigned long flags) {
    int res = 0;
    sf_set_tainted(conf);
    sf_set_tainted(appname);
    res = CONF_modules_load(conf, appname, flags);
    sf_set_errno_if(res <= 0);
    return res;
}

int EVP_MD_CTX_copy_ex(EVP_MD_CTX* dest, const EVP_MD_CTX* src) {
    int res = 0;
    sf_set_tainted(dest);
    sf_set_tainted(src);
    res = EVP_MD_CTX_copy_ex(dest, src);
    sf_set_errno_if(res <= 0);
    return res;
}

int EVP_PKEY_encapsulate(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen) {
    int res = 0;
    sf_set_trusted_sink_int(outlen);
    sf_set_trusted_sink_int(inlen);
    sf_set_errno_if(res == -1);
    return res;
}

SCRYPT_PARAMS* SCRYPT_PARAMS_new() {
    SCRYPT_PARAMS* res = NULL;
    sf_malloc_arg(res, sizeof(SCRYPT_PARAMS));
    sf_new(res, SCRYPT_PARAMS_MEMORY_CATEGORY);
    return res;
}

const BIGNUM* RSA_get0_e(const RSA* r) {
    const BIGNUM* res = NULL;
    sf_set_tainted(r);
    sf_set_must_not_be_null(r);
    sf_set_errno_if(res == NULL);
    return res;
}

int UI_method_set_data_duplicator(UI_METHOD* method, void* (UI*, void*)* duplicator, void (UI*, void*)* destructor) {
    int res = 0;
    sf_set_tainted(method);
    sf_set_must_not_be_null(method);
    sf_set_errno_if(res == -1);
    return res;
}

unsigned long BN_get_word(const BIGNUM* a) {
    unsigned long res = 0;
    sf_set_tainted(a);
    sf_set_must_not_be_null(a);
    sf_set_errno_if(res == (unsigned long)-1);
    return res;
}

int SSL_get_security_level(const SSL* ssl) {
    int res = 0;
    sf_set_must_be_not_null(ssl, "SSL");
    sf_set_errno_if(res < 0, "SSL_get_security_level");
    return res;
}

X509_ATTRIBUTE* X509_REQ_delete_attr(X509_REQ* req, int loc) {
    X509_ATTRIBUTE* res = NULL;
    sf_set_must_be_not_null(req, "X509_REQ");
    sf_set_errno_if(loc < 0, "X509_REQ_delete_attr");
    return res;
}

int SCT_set_version(SCT* sct, sct_version_t version) {
    int res = 0;
    sf_set_must_be_not_null(sct, "SCT");
    sf_set_errno_if(version < 0, "SCT_set_version");
    return res;
}

const EC_POINT* EC_KEY_get0_public_key(const EC_KEY* key) {
    const EC_POINT* res = NULL;
    sf_set_must_be_not_null(key, "EC_KEY");
    return res;
}

int SSL_use_PrivateKey_file(SSL* ssl, const char* file, int type) {
    int res = 0;
    sf_set_must_be_not_null(ssl, "SSL");
    sf_set_must_be_not_null(file, "file");
    sf_set_errno_if(type < 0, "SSL_use_PrivateKey_file");
    return res;
}

X509_CRL* X509_CRL_load_http(const char* url, BIO* bio, BIO* bg, int timeout) {
    X509_CRL* Res = NULL;
    sf_set_trusted_sink_int(timeout);
    sf_set_tainted(url);
    sf_tocttou_check(url);
    Res = i2d_X509_CRL_http(url, bio, bg, timeout);
    sf_set_possible_null(Res);
    return Res;
}

unsigned long EVP_MD_get_flags(const EVP_MD* md) {
    unsigned long Res = 0;
    Res = EVP_MD_flags(md);
    sf_set_possible_negative(Res);
    return Res;
}

int CRYPTO_new_ex_data(int idx, void* arg, CRYPTO_EX_DATA* ad) {
    int Res = 0;
    sf_set_tainted(arg);
    Res = CRYPTO_new_ex_data_ex(idx, arg, ad);
    sf_set_errno_if(Res <= 0);
    return Res;
}

void OCSP_BASICRESP_free(OCSP_BASICRESP* bs) {
    sf_set_must_be_not_null(bs, FREE_OF_NULL);
    OCSP_BASICRESP_free(bs);
    sf_delete(bs, OCSP_BASICRESP_MEMORY_CATEGORY);
}

int BN_BLINDING_update(BN_BLINDING* b, BN_CTX* ctx) {
    int Res = 0;
    sf_set_must_be_not_null(b, BN_BLINDING_UPDATE);
    sf_set_must_be_not_null(ctx, BN_BLINDING_UPDATE);
    Res = BN_BLINDING_update(b, ctx);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int X509_LOOKUP_meth_set_get_by_subject(X509_LOOKUP_METHOD *method, X509_LOOKUP_get_by_subject_fn get_by_subject) {
    int res = 0;
    sf_set_trusted_sink_int(method);
    sf_set_trusted_sink_ptr(get_by_subject);
    sf_set_errno_if(res == 0, EINVAL);
    return res;
}

ECDSA_SIG* d2i_ECDSA_SIG(ECDSA_SIG **sig, const unsigned char **pp, long length) {
    ECDSA_SIG *res = NULL;
    sf_set_trusted_sink_ptr(sig);
    sf_set_trusted_sink_ptr(pp);
    sf_set_trusted_sink_int(length);
    sf_set_errno_if(res == NULL, EINVAL);
    return res;
}

int EVP_PKEY_CTX_get_signature_md(EVP_PKEY_CTX *ctx, const EVP_MD **md) {
    int res = 0;
    sf_set_trusted_sink_ptr(ctx);
    sf_set_trusted_sink_ptr(md);
    sf_set_errno_if(res == 0, EINVAL);
    return res;
}

X509_STORE_CTX_verify_cb X509_STORE_CTX_get_verify_cb(const X509_STORE_CTX *ctx) {
    X509_STORE_CTX_verify_cb res = NULL;
    sf_set_trusted_sink_ptr(ctx);
    sf_set_errno_if(res == NULL, EINVAL);
    return res;
}

EVP_CIPHER* EVP_CIPHER_CTX_get1_cipher(EVP_CIPHER_CTX *ctx) {
    EVP_CIPHER *res = NULL;
    sf_set_trusted_sink_ptr(ctx);
    sf_set_errno_if(res == NULL, EINVAL);
    return res;
}

int OBJ_add_sigid(int a, int b, int c) {
    int res = 0;
    sf_set_trusted_sink_int(a);
    sf_set_trusted_sink_int(b);
    sf_set_trusted_sink_int(c);
    res = OBJ_add_sigid(a, b, c);
    sf_set_errno_if(res == 0);
    return res;
}

int (UI*, UI_STRING*)* UI_method_get_writer(const UI_METHOD* a) {
    int (UI*, UI_STRING*)* res = NULL;
    sf_set_must_not_be_null(a);
    res = UI_method_get_writer(a);
    sf_set_possible_null(res);
    return res;
}

int i2d_PKCS7_fp(FILE* a, const PKCS7* b) {
    int res = 0;
    sf_set_must_not_be_null(a);
    sf_set_must_not_be_null(b);
    res = i2d_PKCS7_fp(a, b);
    sf_set_errno_if(res == 0);
    return res;
}

void PKCS7_ENC_CONTENT_free(PKCS7_ENC_CONTENT* a) {
    sf_set_must_not_be_null(a);
    PKCS7_ENC_CONTENT_free(a);
    sf_delete(a, PAGES_MEMORY_CATEGORY);
}

int EVP_CIPHER_get_nid(const EVP_CIPHER* a) {
    int res = 0;
    sf_set_must_not_be_null(a);
    res = EVP_CIPHER_get_nid(a);
    sf_set_possible_negative(res);
    return res;
}
void* BIO_ptr_ctrl(BIO* a, int b, long c);

int EVP_MD_meth_set_copy(EVP_MD* a, int (EVP_MD_CTX*, const EVP_MD_CTX*);

void* X509_CRL_get_ext_d2i(const X509_CRL* a, int b, int* c, int* d);

const ASN1_OCTET_STRING* OCSP_resp_get0_signature(const OCSP_BASICRESP* a);

void EVP_PKEY_meth_get_encrypt(const EVP_PKEY_METHOD* a, int (EVP_PKEY_CTX*);


void SSL_COMP_add_compression_method(int id, COMP_METHOD *cm) {
    int Res = 0;
    sf_set_trusted_sink_int(id);
    sf_set_trusted_sink_ptr(cm);
    Res = SSL_COMP_add_compression_method(id, cm);
    sf_set_errno_if(Res == 0);
    return Res;
}

int EVP_MAC_init(EVP_MAC_CTX *ctx, const unsigned char *key, size_t keylen, const OSSL_PARAM params[]) {
    int Res = 0;
    sf_set_trusted_sink_ptr(ctx);
    sf_set_trusted_sink_ptr(key);
    sf_set_trusted_sink_int(keylen);
    sf_set_trusted_sink_ptr(params);
    Res = EVP_MAC_init(ctx, key, keylen, params);
    sf_set_errno_if(Res == 0);
    return Res;
}

int (*DH_meth_get_bn_mod_exp(const DH_METHOD *meth))(const DH *dh, BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx) {
    int (*Res)(const DH *, BIGNUM *, const BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *, BN_MONT_CTX *) = NULL;
    sf_set_trusted_sink_ptr(meth);
    Res = DH_meth_get_bn_mod_exp(meth);
    sf_set_possible_null(Res);
    return Res;
}

const EVP_CIPHER *EVP_des_ede3_ofb() {
    const EVP_CIPHER *Res = NULL;
    Res = EVP_des_ede3_ofb();
    sf_set_possible_null(Res);
    return Res;
}

int EVP_MD_CTX_set_params(EVP_MD_CTX *ctx, const OSSL_PARAM params[]) {
    int Res = 0;
    sf_set_trusted_sink_ptr(ctx);
    sf_set_trusted_sink_ptr(params);
    Res = EVP_MD_CTX_set_params(ctx, params);
    sf_set_errno_if(Res == 0);
    return Res;
}

DSA* d2i_DSA_PUBKEY_fp(FILE *fp, DSA **dsa)
{
    DSA *Res = NULL;
    sf_set_tainted(fp);
    sf_set_must_be_not_null(dsa, D2I_DSA_PUBKEY_FP_DSA_NULL);
    sf_set_must_be_not_null(*dsa, D2I_DSA_PUBKEY_FP_DSA_NULL);
    sf_set_possible_null(Res);
    sf_set_possible_null(*dsa);
    sf_set_errno_if(Res == NULL, D2I_DSA_PUBKEY_FP_ERROR);
    return Res;
}

X509* SSL_SESSION_get0_peer(SSL_SESSION *session)
{
    X509 *Res = NULL;
    sf_set_must_be_not_null(session, SSL_SESSION_GET0_PEER_SESSION_NULL);
    sf_set_must_be_not_null(session->peer, SSL_SESSION_GET0_PEER_X509_NULL);
    sf_set_possible_null(Res);
    sf_set_possible_null(session->peer);
    return Res;
}

void EVP_MD_free(EVP_MD *md)
{
    sf_set_must_be_not_null(md, EVP_MD_FREE_MD_NULL);
    sf_delete(md, EVP_MD_CATEGORY);
    sf_lib_arg_type(md, "EVP_MD_free");
}

void ENGINE_load_builtin_engines()
{
    sf_terminate_path(ENGINE_LOAD_BUILTIN_ENGINES_PATH);
}

int OBJ_obj2nid(const ASN1_OBJECT *obj)
{
    int Res = 0;
    sf_set_must_be_not_null(obj, OBJ_OBJ2NID_OBJ_NULL);
    sf_set_errno_if(Res == 0, OBJ_OBJ2NID_ERROR);
    return Res;
}

int X509_REQ_set_subject_name(X509_REQ *req, const X509_NAME *name)
{
    int Res = 0;
    sf_set_must_be_not_null(req, REQ_OF_NULL);
    sf_set_must_be_not_null(name, NAME_OF_NULL);
    Res = X509_REQ_set_subject_name(req, name);
    sf_set_errno_if(Res <= 0, ERRNO_OF_REQ_SET_SUBJECT_NAME);
    return Res;
}

int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl)
{
    int Res = 0;
    sf_set_must_be_not_null(ctx, CTX_OF_NULL);
    sf_set_must_be_not_null(type, TYPE_OF_NULL);
    Res = EVP_DigestInit_ex(ctx, type, impl);
    sf_set_errno_if(Res <= 0, ERRNO_OF_DIGEST_INIT_EX);
    return Res;
}

void X509_CINF_free(X509_CINF *a)
{
    sf_set_must_be_not_null(a, CINF_OF_NULL);
    X509_CINF_free(a);
}

int i2d_OCSP_SINGLERESP(const OCSP_SINGLERESP *a, unsigned char **pp)
{
    int Res = 0;
    sf_set_must_be_not_null(a, SINGLERESP_OF_NULL);
    sf_set_must_be_not_null(pp, PP_OF_NULL);
    Res = i2d_OCSP_SINGLERESP(a, pp);
    sf_set_errno_if(Res <= 0, ERRNO_OF_I2D_OCSP_SINGLERESP);
    return Res;
}

int ASYNC_WAIT_CTX_get_all_fds(ASYNC_WAIT_CTX *ctx, int *fds, size_t *numfds)
{
    int Res = 0;
    sf_set_must_be_not_null(ctx, CTX_OF_NULL);
    sf_set_must_be_not_null(fds, FDS_OF_NULL);
    sf_set_must_be_not_null(numfds, NUMFDS_OF_NULL);
    Res = ASYNC_WAIT_CTX_get_all_fds(ctx, fds, numfds);
    sf_set_errno_if(Res <= 0, ERRNO_OF_ASYNC_WAIT_CTX_GET_ALL_FDS);
    return Res;
}

int i2d_ASN1_OCTET_STRING(const ASN1_OCTET_STRING *a, unsigned char **pp)
{
    int ret = 0;
    sf_set_must_be_not_null(a, "ASN1_OCTET_STRING");
    sf_set_must_be_not_null(pp, "unsigned char**");
    sf_set_tainted(a->data, a->length);
    sf_buf_size_limit(a->data, a->length);
    sf_buf_stop_at_null(a->data);
    ret = ASN1_object_size(0, a->length, V_ASN1_OCTET_STRING);
    sf_set_errno_if(ret <= 0, "ASN1_object_size");
    sf_set_possible_null(ret);
    return ret;
}

int SHA512_Init(SHA512_CTX *c)
{
    int ret = 0;
    sf_set_must_be_not_null(c, "SHA512_CTX");
    ret = SHA512_Init(c);
    sf_set_errno_if(ret == 0, "SHA512_Init");
    return ret;
}

void SSL_SESSION_free(SSL_SESSION *ses)
{
    sf_set_must_be_not_null(ses, "SSL_SESSION");
    SSL_SESSION_free(ses);
    sf_delete(ses, SSL_SESSION_CATEGORY);
}

const void* UI_method_get_ex_data(const UI_METHOD *method, int idx)
{
    const void *ret = NULL;
    sf_set_must_be_not_null(method, "UI_METHOD");
    ret = UI_method_get_ex_data(method, idx);
    sf_set_possible_null(ret);
    return ret;
}

int SSL_up_ref(SSL *s)
{
    int ret = 0;
    sf_set_must_be_not_null(s, "SSL");
    ret = SSL_up_ref(s);
    sf_set_errno_if(ret == 0, "SSL_up_ref");
    return ret;
}
void DSA_set_flags(DSA* dsa, int flags);

X509_SIG* d2i_PKCS8_bio(BIO* bio, X509_SIG** sig);

int ENGINE_register_complete(ENGINE* e);

const EVP_CIPHER* EVP_aes_256_ecb();

int SSL_CTX_set_ex_data(SSL_CTX* ctx, int idx, void* data);


// SSL_CTX_dane_clear_flags
unsigned long SSL_CTX_dane_clear_flags(SSL_CTX* ctx, unsigned long flags) {
    unsigned long Res = 0;
    sf_set_trusted_sink_int(flags);
    sf_set_must_be_not_null(ctx, "SSL_CTX_dane_clear_flags");
    Res = SSL_CTX_dane_clear_flags(ctx, flags);
    sf_set_errno_if(Res == 0);
    return Res;
}

// BN_BLINDING_new
BN_BLINDING* BN_BLINDING_new(const BIGNUM* e, const BIGNUM* m, BIGNUM* x) {
    BN_BLINDING* Res = NULL;
    sf_set_must_be_not_null(e, "BN_BLINDING_new");
    sf_set_must_be_not_null(m, "BN_BLINDING_new");
    sf_set_must_be_not_null(x, "BN_BLINDING_new");
    Res = BN_BLINDING_new(e, m, x);
    sf_set_alloc_possible_null(Res);
    return Res;
}

// BIO_new_from_core_bio
BIO* BIO_new_from_core_bio(OSSL_LIB_CTX* libctx, OSSL_CORE_BIO* corebio) {
    BIO* Res = NULL;
    sf_set_must_be_not_null(corebio, "BIO_new_from_core_bio");
    Res = BIO_new_from_core_bio(libctx, corebio);
    sf_set_alloc_possible_null(Res);
    return Res;
}

// SSL_set0_wbio
void SSL_set0_wbio(SSL* s, BIO* wbio) {
    sf_set_must_be_not_null(s, "SSL_set0_wbio");
    sf_set_must_be_not_null(wbio, "SSL_set0_wbio");
    SSL_set0_wbio(s, wbio);
}

// EVP_PKEY_get_octet_string_param
int EVP_PKEY_get_octet_string_param(const EVP_PKEY* pkey, const char* key, unsigned char* out, size_t outlen, size_t* outlen_needed) {
    int Res = 0;
    sf_set_must_be_not_null(pkey, "EVP_PKEY_get_octet_string_param");
    sf_set_must_be_not_null(key, "EVP_PKEY_get_octet_string_param");
    sf_set_must_be_not_null(out, "EVP_PKEY_get_octet_string_param");
    sf_set_must_be_not_null(outlen_needed, "EVP_PKEY_get_octet_string_param");
    Res = EVP_PKEY_get_octet_string_param(pkey, key, out, outlen, outlen_needed);
    sf_set_errno_if(Res == 0);
    return Res;
}

void* SSL_CTX_get_ex_data(const SSL_CTX* ctx, int idx) {
    void* Res = NULL;
    sf_set_trusted_sink_int(idx);
    Res = (void*)ctx;
    sf_overwrite(Res);
    return Res;
}

const EVP_CIPHER* EVP_des_ede3() {
    const EVP_CIPHER* Res = NULL;
    Res = EVP_des_ede3();
    sf_overwrite(Res);
    return Res;
}

int SSL_CTX_ct_is_enabled(const SSL_CTX* ctx) {
    int Res = 0;
    Res = SSL_CTX_ct_is_enabled(ctx);
    sf_overwrite(&Res);
    return Res;
}

int OCSP_basic_add1_nonce(OCSP_BASICRESP* bs, unsigned char* nonce, int n) {
    int Res = 0;
    sf_set_trusted_sink_int(n);
    Res = OCSP_basic_add1_nonce(bs, nonce, n);
    sf_overwrite(&Res);
    return Res;
}

void BIO_free_all(BIO* a) {
    BIO_free_all(a);
    sf_delete(a, BIO_MEMORY_CATEGORY);
}

const SSL_METHOD* DTLSv1_server_method() {
    const SSL_METHOD* Res = NULL;
    Res = DTLSv1_server_method();
    sf_set_possible_null(Res);
    return Res;
}

int OSSL_PARAM_set_BN(OSSL_PARAM* param, const BIGNUM* bn) {
    int Res = 0;
    sf_password_use(bn);
    Res = OSSL_PARAM_set_BN(param, bn);
    sf_set_errno_if(Res == 0);
    return Res;
}

int RSA_set0_crt_params(RSA* r, BIGNUM* dmp1, BIGNUM* dmq1, BIGNUM* iqmp) {
    int Res = 0;
    sf_password_set(dmp1);
    sf_password_set(dmq1);
    sf_password_set(iqmp);
    Res = RSA_set0_crt_params(r, dmp1, dmq1, iqmp);
    sf_set_errno_if(Res == 0);
    return Res;
}

int X509_LOOKUP_meth_set_get_by_issuer_serial(X509_LOOKUP_METHOD* xl, X509_LOOKUP_get_by_issuer_serial_fn get_by_issuer_serial) {
    int Res = 0;
    Res = X509_LOOKUP_meth_set_get_by_issuer_serial(xl, get_by_issuer_serial);
    sf_set_errno_if(Res == 0);
    return Res;
}

stack_st_X509_EXTENSION* X509v3_add_ext(stack_st_X509_EXTENSION** extlist, X509_EXTENSION* ext, int loc) {
    stack_st_X509_EXTENSION* Res = NULL;
    Res = X509v3_add_ext(extlist, ext, loc);
    sf_set_possible_null(Res);
    return Res;
}

int BN_ucmp(const BIGNUM *a, const BIGNUM *b) {
    int res = 0;
    sf_set_must_be_not_null(a, BN_UCMP_OF_NULL);
    sf_set_must_be_not_null(b, BN_UCMP_OF_NULL);
    sf_set_errno_if(res == 0, BN_UCMP_ERROR);
    return res;
}

int X509_STORE_CTX_verify(X509_STORE_CTX *ctx) {
    int res = 0;
    sf_set_must_be_not_null(ctx, X509_STORE_CTX_VERIFY_OF_NULL);
    sf_set_errno_if(res <= 0, X509_STORE_CTX_VERIFY_ERROR);
    return res;
}

const char* EVP_SIGNATURE_get0_description(const EVP_SIGNATURE *sig) {
    const char *res = NULL;
    sf_set_must_be_not_null(sig, EVP_SIGNATURE_GET0_DESCRIPTION_OF_NULL);
    sf_set_possible_null(res);
    return res;
}

const BIGNUM* DH_get0_p(const DH *dh) {
    const BIGNUM *res = NULL;
    sf_set_must_be_not_null(dh, DH_GET0_P_OF_NULL);
    sf_set_possible_null(res);
    return res;
}

int UI_method_set_opener(UI_METHOD *method, int (UI*)(UI *ui)) {
    int res = 0;
    sf_set_must_be_not_null(method, UI_METHOD_SET_OPENER_OF_NULL);
    sf_set_must_be_not_null(ui, UI_METHOD_SET_OPENER_UI_OF_NULL);
    sf_set_errno_if(res != 0, UI_METHOD_SET_OPENER_ERROR);
    return res;
}

void* UI_add_user_data(UI* ui, void* data) {
    void* Res = NULL;
    sf_set_trusted_sink_ptr(data);
    Res = UI_add_user_data(ui, data);
    sf_overwrite(Res);
    return Res;
}

const EVP_MD* EVP_MD_CTX_get0_md(const EVP_MD_CTX* ctx) {
    const EVP_MD* Res = NULL;
    Res = EVP_MD_CTX_get0_md(ctx);
    sf_overwrite(Res);
    return Res;
}

unsigned int SSL_CONF_CTX_clear_flags(SSL_CONF_CTX* ctx, unsigned int flags) {
    unsigned int Res = 0;
    Res = SSL_CONF_CTX_clear_flags(ctx, flags);
    sf_overwrite(&Res);
    return Res;
}

stack_st_X509_ATTRIBUTE* X509at_add1_attr_by_OBJ(stack_st_X509_ATTRIBUTE** sk, const ASN1_OBJECT* obj, int type, const unsigned char* bytes, int len) {
    stack_st_X509_ATTRIBUTE* Res = NULL;
    Res = X509at_add1_attr_by_OBJ(sk, obj, type, bytes, len);
    sf_overwrite(Res);
    return Res;
}

int EVP_MAC_update(EVP_MAC_CTX* ctx, const unsigned char* data, size_t datalen) {
    int Res = 0;
    Res = EVP_MAC_update(ctx, data, datalen);
    sf_overwrite(&Res);
    return Res;
}
void X509_NAME_ENTRY_free(X509_NAME_ENTRY* entry);

void SSL_set_accept_state(SSL* ssl);

int EVP_PKEY_CTX_get_ecdh_kdf_outlen(EVP_PKEY_CTX* ctx, int* outlen);

int i2d_X509_SIG(const X509_SIG* sig, unsigned char** pp);

char* X509_VERIFY_PARAM_get0_email(X509_VERIFY_PARAM* param);

int EVP_PKEY_CTX_get_rsa_oaep_md_name(EVP_PKEY_CTX* ctx, char* mdname, size_t mdname_len);

void EVP_KEM_free(EVP_KEM* kem);

int CTLOG_STORE_load_file(CTLOG_STORE* ctx, const char* path);

int PEM_write_bio_PrivateKey_traditional(BIO* bio, const EVP_PKEY* pkey, const EVP_CIPHER* cipher, const unsigned char* passwd, int len, pem_password_cb* cb, void* u);

int OSSL_PARAM_set_utf8_ptr(OSSL_PARAM* param, const char* val);

int i2d_X509_ATTRIBUTE(const X509_ATTRIBUTE* a, unsigned char** pp);

int PKCS8_pkey_add1_attr_by_NID(PKCS8_PRIV_KEY_INFO* p8, int nid, int type, const unsigned char* bytes, int len);

int EC_KEY_set_public_key(EC_KEY* eckey, const EC_POINT* pub);

void* CRYPTO_malloc(size_t num, const char* file, int line);

EVP_MD_CTX* EVP_MD_CTX_new();


int SSL_CTX_load_verify_file(SSL_CTX* ctx, const char* file)
{
    int res = 0;
    sf_tocttou_check(file);
    sf_set_tainted(file);
    sf_set_errno_if(res <= 0, errno);
    return res;
}

const BIO_METHOD* BIO_f_readbuffer()
{
    const BIO_METHOD* res = NULL;
    return res;
}

int DSA_SIG_set0(DSA_SIG* sig, BIGNUM* r, BIGNUM* s)
{
    int res = 0;
    sf_set_tainted(r);
    sf_set_tainted(s);
    sf_set_errno_if(res <= 0, errno);
    return res;
}

const OSSL_PARAM* EVP_KEYMGMT_gettable_params(const EVP_KEYMGMT* keymgmt)
{
    const OSSL_PARAM* res = NULL;
    return res;
}

int SSL_CTX_add_custom_ext(SSL_CTX* ctx, unsigned int ext_type, unsigned int context, SSL_custom_ext_add_cb_ex add_cb, SSL_custom_ext_free_cb_ex free_cb, void* add_arg, SSL_custom_ext_parse_cb_ex parse_cb, void* parse_arg)
{
    int res = 0;
    sf_set_errno_if(res <= 0, errno);
    return res;
}

const unsigned char* EVP_CIPHER_CTX_iv(const EVP_CIPHER_CTX* ctx) {
    const unsigned char* Res = NULL;
    Res = ctx->iv;
    sf_set_trusted_sink_ptr(Res);
    return Res;
}

DH* DH_new_by_nid(int nid) {
    DH* Res = NULL;
    Res = DH_new();
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    return Res;
}

const EVP_MD* EVP_sm3() {
    const EVP_MD* Res = NULL;
    Res = EVP_get_digestbynid(NID_sm3);
    sf_set_possible_null(Res);
    return Res;
}

void EVP_PKEY_meth_get_sign(const EVP_PKEY_METHOD* pmeth, int (**sign_init) (EVP_PKEY_CTX *ctx), int (**sign) (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen)) {
    *sign_init = pmeth->sign_init;
    *sign = pmeth->sign;
    sf_set_trusted_sink_ptr(*sign_init);
    sf_set_trusted_sink_ptr(*sign);
}

X509_STORE_CTX_get_crl_fn X509_STORE_get_get_crl(const X509_STORE* store) {
    X509_STORE_CTX_get_crl_fn Res = NULL;
    Res = store->get_crl;
    sf_set_possible_null(Res);
    return Res;
}

void EVP_DigestFinal_ex(void *ctx, void *md, void *size) {
    int res = 0;
    sf_set_trusted_sink_int(size);
    sf_set_trusted_sink_ptr(md);
    sf_set_errno_if(res == 0);
    sf_no_errno_if(res == 1);
}

void DSA_SIG_new(void *sig) {
    sf_set_alloc_possible_null(sig);
    sf_new(sig, DSA_SIG_MEMORY_CATEGORY);
    sf_lib_arg_type(sig, "DSA_SIG_new");
}

void SSL_SESSION_get_protocol_version(void *session, void *version) {
    int res = 0;
    sf_set_must_be_not_null(session);
    sf_set_possible_null(version);
    sf_set_errno_if(res == 0);
}

void EC_GROUP_check_discriminant(void *group, void *ctx) {
    int res = 0;
    sf_set_must_be_not_null(group);
    sf_set_must_be_not_null(ctx);
    sf_set_errno_if(res == 0);
}

void X509v3_get_ext_count(void *exts, void *count) {
    int res = 0;
    sf_set_must_be_not_null(exts);
    sf_set_possible_null(count);
    sf_set_errno_if(res == 0);
}
int EVP_PKEY_set1_engine(EVP_PKEY *pkey, ENGINE *engine);

OCSP_RESPDATA *d2i_OCSP_RESPDATA(OCSP_RESPDATA **a, const unsigned char **in, long len);

X509_EXTENSION *X509_EXTENSION_dup(const X509_EXTENSION *ex);

int DHparams_print(BIO *bp, const DH *x);

int X509_LOOKUP_by_fingerprint(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type, const unsigned char *bytes, int len, X509_OBJECT *ret);


int BN_set_bit(BIGNUM *a, int n) {
    int Res = 0;
    sf_set_must_be_not_null(a, SET_BIT_OF_NULL);
    sf_set_trusted_sink_int(n, SET_BIT_SINK);
    sf_set_errno_if(Res == 0, SET_BIT_ERROR);
    sf_set_possible_null(Res, SET_BIT_POSSIBLE_NULL);
    return Res;
}

OSSL_PROVIDER* EVP_SIGNATURE_get0_provider(const EVP_SIGNATURE *sig) {
    OSSL_PROVIDER *Res = NULL;
    sf_set_must_be_not_null(sig, GET_PROVIDER_OF_NULL);
    sf_set_errno_if(Res == NULL, GET_PROVIDER_ERROR);
    sf_set_possible_null(Res, GET_PROVIDER_POSSIBLE_NULL);
    return Res;
}

X509* SSL_get_certificate(const SSL *s) {
    X509 *Res = NULL;
    sf_set_must_be_not_null(s, GET_CERTIFICATE_OF_NULL);
    sf_set_errno_if(Res == NULL, GET_CERTIFICATE_ERROR);
    sf_set_possible_null(Res, GET_CERTIFICATE_POSSIBLE_NULL);
    return Res;
}

EVP_KEYEXCH* EVP_KEYEXCH_fetch(OSSL_LIB_CTX *ctx, const char *algorithm, const char *properties) {
    EVP_KEYEXCH *Res = NULL;
    sf_set_must_be_not_null(ctx, FETCH_KEYEXCH_OF_NULL);
    sf_set_must_be_not_null(algorithm, FETCH_KEYEXCH_ALGORITHM_NULL);
    sf_set_must_be_not_null(properties, FETCH_KEYEXCH_PROPERTIES_NULL);
    sf_set_errno_if(Res == NULL, FETCH_KEYEXCH_ERROR);
    sf_set_possible_null(Res, FETCH_KEYEXCH_POSSIBLE_NULL);
    return Res;
}

int OCSP_resp_get0_id(const OCSP_BASICRESP *bs, const ASN1_OCTET_STRING **pid, const X509_NAME **pname) {
    int Res = 0;
    sf_set_must_be_not_null(bs, GET_ID_OF_NULL);
    sf_set_must_be_not_null(pid, GET_ID_PID_NULL);
    sf_set_must_be_not_null(pname, GET_ID_PNAME_NULL);
    sf_set_errno_if(Res == 0, GET_ID_ERROR);
    sf_set_possible_null(Res, GET_ID_POSSIBLE_NULL);
    return Res;
}

void EDIPARTYNAME_free(EDIPARTYNAME *edip) {
    if (edip != NULL) {
        OPENSSL_free(edip);
    }
}

void X509_free(X509 *x) {
    if (x != NULL) {
        X509_free(x);
    }
}

int ENGINE_register_ciphers(ENGINE *e) {
    int res = 0;
    sf_set_errno_if(ENGINE_register_ciphers(e), res, -1);
    return res;
}

EVP_PKEY *PEM_read_bio_PUBKEY_ex(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u, OSSL_LIB_CTX *libctx, const char *propq) {
    EVP_PKEY *res = NULL;
    sf_set_errno_if(PEM_read_bio_PUBKEY_ex(bp, x, cb, u, libctx, propq), res, NULL);
    return res;
}

DH *EVP_PKEY_get1_DH(EVP_PKEY *pkey) {
    DH *res = NULL;
    sf_set_errno_if(EVP_PKEY_get1_DH(pkey), res, NULL);
    return res;
}

int OSSL_PARAM_set_int32(OSSL_PARAM *param, int32_t val)
{
    int res = 0;
    sf_set_must_be_not_null(param, SET_INT32_OF_NULL);
    sf_set_must_be_not_null(param->data, SET_INT32_DATA_NULL);
    sf_set_trusted_sink_int(val);
    sf_set_tainted(val);
    sf_set_errno_if(param->data_size != sizeof(int32_t), SET_INT32_SIZE_ERROR);
    sf_set_errno_if(param->data_type != OSSL_PARAM_INTEGER, SET_INT32_TYPE_ERROR);
    *((int32_t *)param->data) = val;
    res = 1;
    sf_set_errno_if(res != 1, SET_INT32_FAILURE);
    return res;
}

size_t BUF_MEM_grow(BUF_MEM *str, size_t len)
{
    size_t res = 0;
    sf_set_must_be_not_null(str, BUF_MEM_GROW_NULL);
    sf_set_trusted_sink_int(len);
    sf_set_tainted(len);
    sf_set_buf_size_limit(str->data, len);
    sf_set_errno_if(len > str->max, BUF_MEM_GROW_SIZE_ERROR);
    if (len > str->max)
    {
        size_t new_len = len + str->max + 1;
        sf_set_trusted_sink_int(new_len);
        sf_set_tainted(new_len);
        str->data = OPENSSL_realloc(str->data, new_len);
        sf_set_alloc_possible_null(str->data, new_len);
        sf_set_errno_if(str->data == NULL, BUF_MEM_GROW_REALLOC_ERROR);
        str->max = new_len - 1;
    }
    res = len;
    sf_set_errno_if(res != len, BUF_MEM_GROW_FAILURE);
    return res;
}

int EVP_OpenInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, const unsigned char *ek, int ekl, const unsigned char *iv, EVP_PKEY *priv)
{
    int res = 0;
    sf_set_must_be_not_null(ctx, EVP_OPENINIT_CTX_NULL);
    sf_set_must_be_not_null(type, EVP_OPENINIT_TYPE_NULL);
    sf_set_must_be_not_null(ek, EVP_OPENINIT_EK_NULL);
    sf_set_must_be_not_null(iv, EVP_OPENINIT_IV_NULL);
    sf_set_must_be_not_null(priv, EVP_OPENINIT_PRIV_NULL);
    sf_set_trusted_sink_int(ekl);
    sf_set_tainted(ekl);
    sf_set_buf_size_limit(ek, ekl);
    sf_set_buf_size_limit(iv, type->iv_len);
    sf_set_password_use(priv);
    res = EVP_OpenInit_ex(ctx, type, NULL, ek, ekl, iv, priv);
    sf_set_errno_if(res <= 0, EVP_OPENINIT_FAILURE);
    return res;
}

int RSA_get0_multi_prime_factors(const RSA *r, const BIGNUM *primes[])
{
    int res = 0;
    sf_set_must_be_not_null(r, RSA_GET0_MULTI_PRIME_FACTORS_R_NULL);
    sf_set_must_be_not_null(primes, RSA_GET0_MULTI_PRIME_FACTORS_PRIMES_NULL);
    res = RSA_get0_factors(r, primes);
    sf_set_errno_if(res <= 0, RSA_GET0_MULTI_PRIME_FACTORS_FAILURE);
    return res;
}

const RSA_METHOD* RSA_PKCS1_OpenSSL()
{
    const RSA_METHOD *res = NULL;
    res = RSA_PKCS1_OpenSSL_method();
    sf_set_errno_if(res == NULL, RSA_PKCS1_OPENSSL_FAILURE);
    return res;
}

BIO* OSSL_HTTP_REQ_CTX_get0_mem_bio(const OSSL_HTTP_REQ_CTX* req_ctx) {
    BIO* Res = NULL;
    Res = (BIO*)OSSL_HTTP_REQ_CTX_get0_bio(req_ctx);
    sf_set_possible_null(Res);
    return Res;
}

size_t EC_get_builtin_curves(EC_builtin_curve* curves, size_t nitems) {
    size_t Res = 0;
    Res = EC_get_builtin_curves(curves, nitems);
    sf_set_possible_negative(Res);
    return Res;
}

int (int, const unsigned char*, unsigned char*, RSA*, int)* RSA_meth_get_pub_dec(const RSA_METHOD* meth) {
    int (int, const unsigned char*, unsigned char*, RSA*, int)* Res = NULL;
    Res = meth->rsa_pub_dec;
    sf_set_possible_null(Res);
    return Res;
}

int EVP_KEYMGMT_names_do_all(const EVP_KEYMGMT* keymgmt, void (const char*, void*)* fn, void* arg) {
    int Res = 0;
    Res = EVP_KEYMGMT_names_do_all(keymgmt, fn, arg);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int i2o_SCT_LIST(const stack_st_SCT* sct_list, unsigned char** pp) {
    int Res = 0;
    Res = i2o_SCT_LIST(sct_list, pp);
    sf_set_errno_if(Res <= 0);
    return Res;
}

ECPKPARAMETERS* EC_GROUP_get_ecpkparameters(const EC_GROUP* group, ECPKPARAMETERS* parameters) {
    ECPKPARAMETERS* Res = NULL;
    sf_set_must_be_not_null(group, "EC_GROUP");
    sf_set_must_be_not_null(parameters, "ECPKPARAMETERS");
    Res = EC_GROUP_get_ecpkparameters(group, parameters);
    sf_set_possible_null(Res, "ECPKPARAMETERS");
    return Res;
}

unsigned int SSL_client_hello_get0_legacy_version(SSL* s) {
    unsigned int Res = 0;
    sf_set_must_be_not_null(s, "SSL");
    Res = SSL_client_hello_get0_legacy_version(s);
    return Res;
}

int EVP_CIPHER_get_block_size(const EVP_CIPHER* cipher) {
    int Res = 0;
    sf_set_must_be_not_null(cipher, "EVP_CIPHER");
    Res = EVP_CIPHER_get_block_size(cipher);
    return Res;
}

ASN1_GENERALIZEDTIME* ASN1_GENERALIZEDTIME_set(ASN1_GENERALIZEDTIME* s, time_t t) {
    ASN1_GENERALIZEDTIME* Res = NULL;
    sf_set_must_be_not_null(s, "ASN1_GENERALIZEDTIME");
    Res = ASN1_GENERALIZEDTIME_set(s, t);
    sf_set_possible_null(Res, "ASN1_GENERALIZEDTIME");
    return Res;
}

int PKCS7_verify(PKCS7* p7, stack_st_X509* certs, X509_STORE* store, BIO* in, BIO* out, int flags) {
    int Res = 0;
    sf_set_must_be_not_null(p7, "PKCS7");
    sf_set_must_be_not_null(certs, "stack_st_X509");
    sf_set_must_be_not_null(store, "X509_STORE");
    sf_set_must_be_not_null(in, "BIO");
    sf_set_must_be_not_null(out, "BIO");
    Res = PKCS7_verify(p7, certs, store, in, out, flags);
    return Res;
}

int EVP_MD_get_type(const EVP_MD* md) {
    int Res = 0;
    // Check if md is not null
    sf_set_must_be_not_null(md, EVP_MD_NULL);
    // Check if md is a valid EVP_MD
    sf_set_must_be_valid(md, EVP_MD_VALID);
    // Set the return value as trusted sink
    sf_set_trusted_sink_int(Res);
    // Overwrite the return value
    sf_overwrite(Res);
    return Res;
}

int BN_sub_word(BIGNUM* a, unsigned long w) {
    int Res = 0;
    // Check if a is not null
    sf_set_must_be_not_null(a, BN_NULL);
    // Check if a is a valid BIGNUM
    sf_set_must_be_valid(a, BN_VALID);
    // Set the return value as trusted sink
    sf_set_trusted_sink_int(Res);
    // Overwrite the return value
    sf_overwrite(Res);
    return Res;
}

SSL_CTX* SSL_CTX_new_ex(OSSL_LIB_CTX* libctx, const char* name, const SSL_METHOD* method) {
    SSL_CTX* Res = NULL;
    // Check if libctx is not null
    sf_set_must_be_not_null(libctx, OSSL_LIB_CTX_NULL);
    // Check if name is not null
    sf_set_must_be_not_null(name, NAME_NULL);
    // Check if method is not null
    sf_set_must_be_not_null(method, SSL_METHOD_NULL);
    // Check if method is a valid SSL_METHOD
    sf_set_must_be_valid(method, SSL_METHOD_VALID);
    // Set the return value as trusted sink
    sf_set_trusted_sink_ptr(Res);
    // Overwrite the return value
    sf_overwrite(Res);
    return Res;
}

int SCT_validate(SCT* sct, const CT_POLICY_EVAL_CTX* ctx) {
    int Res = 0;
    // Check if sct is not null
    sf_set_must_be_not_null(sct, SCT_NULL);
    // Check if sct is a valid SCT
    sf_set_must_be_valid(sct, SCT_VALID);
    // Check if ctx is not null
    sf_set_must_be_not_null(ctx, CT_POLICY_EVAL_CTX_NULL);
    // Check if ctx is a valid CT_POLICY_EVAL_CTX
    sf_set_must_be_valid(ctx, CT_POLICY_EVAL_CTX_VALID);
    // Set the return value as trusted sink
    sf_set_trusted_sink_int(Res);
    // Overwrite the return value
    sf_overwrite(Res);
    return Res;
}

int EVP_PBE_CipherInit(ASN1_OBJECT* obj, const char* pass, int passlen, ASN1_TYPE* param, EVP_CIPHER_CTX* ctx, int enc) {
    int Res = 0;
    // Check if obj is not null
    sf_set_must_be_not_null(obj, ASN1_OBJECT_NULL);
    // Check if obj is a valid ASN1_OBJECT
    sf_set_must_be_valid(obj, ASN1_OBJECT_VALID);
    // Check if pass is not null
    sf_set_must_be_not_null(pass, PASS_NULL);
    // Check if passlen is not null
    sf_set_must_be_not_null(passlen, PASSLEN_NULL);
    // Check if param is not null
    sf_set_must_be_not_null(param, ASN1_TYPE_NULL);
    // Check if param is a valid ASN1_TYPE
    sf_set_must_be_valid(param, ASN1_TYPE_VALID);
    // Check if ctx is not null
    sf_set_must_be_not_null(ctx, EVP_CIPHER_CTX_NULL);
    // Check if ctx is a valid EVP_CIPHER_CTX
    sf_set_must_be_valid(ctx, EVP_CIPHER_CTX_VALID);
    // Set the return value as trusted sink
    sf_set_trusted_sink_int(Res);
    // Overwrite the return value
    sf_overwrite(Res);
    return Res;
}

int EVP_PKEY_CTX_set_dh_pad(EVP_PKEY_CTX* ctx, int pad) {
    int Res = 0;
    sf_set_tainted(ctx);
    sf_set_tainted(pad);
    sf_set_must_be_not_null(ctx, SET_DH_PAD_OF_NULL);
    Res = EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_DH_PAD, pad, NULL);
    sf_set_errno_if(Res <= 0, SET_DH_PAD_ERROR);
    return Res;
}

int EVP_PKEY_CTX_set_rsa_mgf1_md_name(EVP_PKEY_CTX* ctx, const char* md_name, const char* md_props) {
    int Res = 0;
    sf_set_tainted(ctx);
    sf_set_tainted(md_name);
    sf_set_tainted(md_props);
    sf_set_must_be_not_null(ctx, SET_RSA_MGF1_MD_NAME_OF_NULL);
    Res = EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_RSA_MGF1_MD, 0, (void *)md_name);
    sf_set_errno_if(Res <= 0, SET_RSA_MGF1_MD_NAME_ERROR);
    return Res;
}

void EVP_PKEY_asn1_free(EVP_PKEY_ASN1_METHOD* ameth) {
    sf_set_tainted(ameth);
    sf_set_must_be_not_null(ameth, ASN1_FREE_OF_NULL);
    EVP_PKEY_asn1_free(ameth);
}

int BN_cmp(const BIGNUM* a, const BIGNUM* b) {
    int Res = 0;
    sf_set_tainted(a);
    sf_set_tainted(b);
    sf_set_must_be_not_null(a, BN_CMP_A_OF_NULL);
    sf_set_must_be_not_null(b, BN_CMP_B_OF_NULL);
    Res = BN_cmp(a, b);
    return Res;
}

int EVP_PKEY_CTX_set_dsa_paramgen_md_props(EVP_PKEY_CTX* ctx, const char* md_name, const char* md_props) {
    int Res = 0;
    sf_set_tainted(ctx);
    sf_set_tainted(md_name);
    sf_set_tainted(md_props);
    sf_set_must_be_not_null(ctx, SET_DSA_PARAMGEN_MD_PROPS_OF_NULL);
    Res = EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_DSA_PARAMGEN_MD_PROPS, 0, (void *)md_name);
    sf_set_errno_if(Res <= 0, SET_DSA_PARAMGEN_MD_PROPS_ERROR);
    return Res;
}
int PEM_write_bio_SSL_SESSION(BIO* bio, const SSL_SESSION* session);

const char* SSL_rstate_string_long(const SSL* ssl);

ENGINE* ENGINE_by_id(const char* id);

void SSL_get0_alpn_selected(const SSL* ssl, const unsigned char** out, unsigned int* outlen);

void BUF_reverse(unsigned char* dst, const unsigned char* src, size_t size);


void* DSA_get_ex_data(const DSA* d, int idx) {
    void* Res = NULL;
    sf_set_trusted_sink_int(idx);
    Res = DSA_get_ex_data(d, idx);
    sf_overwrite(Res);
    return Res;
}

int BIO_meth_set_write_ex(BIO_METHOD* bi, int (*bwrite)(BIO*, const char*, size_t, size_t*)) {
    int Res = 0;
    sf_set_trusted_sink_ptr(bwrite);
    Res = BIO_meth_set_write_ex(bi, bwrite);
    sf_overwrite(&Res);
    return Res;
}

const BIO_METHOD* BIO_f_base64() {
    const BIO_METHOD* Res = NULL;
    Res = BIO_f_base64();
    sf_overwrite(Res);
    return Res;
}

EVP_PKEY* PEM_read_bio_Parameters(BIO* bp, EVP_PKEY** x) {
    EVP_PKEY* Res = NULL;
    Res = PEM_read_bio_Parameters(bp, x);
    sf_overwrite(Res);
    return Res;
}

size_t SSL_client_hello_get0_compression_methods(SSL* s, const unsigned char** comp_methods) {
    size_t Res = 0;
    Res = SSL_client_hello_get0_compression_methods(s, comp_methods);
    sf_overwrite(&Res);
    return Res;
}

int EVP_KEM_up_ref(EVP_KEM* kem) {
    int res = 0;
    sf_set_must_be_not_null(kem, UP_REF_OF_NULL);
    res = EVP_KEM_up_ref(kem);
    sf_set_possible_null(res, UP_REF_OF_NULL);
    return res;
}

int PEM_write_PKCS8(FILE* fp, const X509_SIG* p8) {
    int res = 0;
    sf_set_must_be_not_null(fp, WRITE_PEM_OF_NULL);
    sf_set_must_be_not_null(p8, WRITE_PEM_OF_NULL);
    res = PEM_write_PKCS8(fp, p8);
    sf_set_errno_if(res <= 0, WRITE_PEM_FAIL);
    return res;
}

const char* EVP_CIPHER_get0_name(const EVP_CIPHER* cipher) {
    const char* res = NULL;
    sf_set_must_be_not_null(cipher, CIPHER_GET_NAME_OF_NULL);
    res = EVP_CIPHER_get0_name(cipher);
    sf_set_possible_null(res, CIPHER_GET_NAME_OF_NULL);
    return res;
}

int SSL_SESSION_is_resumable(const SSL_SESSION* sess) {
    int res = 0;
    sf_set_must_be_not_null(sess, SESSION_IS_RESUMABLE_OF_NULL);
    res = SSL_SESSION_is_resumable(sess);
    return res;
}

X509_CRL* X509_CRL_new_ex(OSSL_LIB_CTX* ctx, const char* propq) {
    X509_CRL* res = NULL;
    sf_set_must_be_not_null(ctx, CRL_NEW_EX_OF_NULL);
    res = X509_CRL_new_ex(ctx, propq);
    sf_set_alloc_possible_null(res, CRL_NEW_EX_OF_NULL);
    return res;
}

const OSSL_PARAM* EVP_ASYM_CIPHER_gettable_ctx_params(const EVP_ASYM_CIPHER* ptr) {
    const OSSL_PARAM* Res = NULL;
    sf_set_trusted_sink_ptr(ptr);
    sf_set_must_be_not_null(ptr, GETTABLE_CTX_PARAMS_OF_NULL);
    Res = EVP_ASYM_CIPHER_gettable_ctx_params(ptr);
    sf_set_possible_null(Res);
    return Res;
}

void PKCS7_free(PKCS7* ptr) {
    sf_set_must_be_not_null(ptr, FREE_OF_NULL);
    sf_delete(ptr, PKCS7_CATEGORY);
    PKCS7_free(ptr);
}

int EVP_PKEY_CTX_set_dhx_rfc5114(EVP_PKEY_CTX* ctx, int nid) {
    int Res = 0;
    sf_set_must_be_not_null(ctx, SET_DHX_RFC5114_OF_NULL);
    Res = EVP_PKEY_CTX_set_dhx_rfc5114(ctx, nid);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int i2d_PKEY_USAGE_PERIOD(const PKEY_USAGE_PERIOD* in, unsigned char** out) {
    int Res = 0;
    sf_set_must_be_not_null(in, I2D_PKEY_USAGE_PERIOD_OF_NULL);
    sf_set_must_be_not_null(out, I2D_PKEY_USAGE_PERIOD_OF_NULL);
    Res = i2d_PKEY_USAGE_PERIOD(in, out);
    sf_set_errno_if(Res <= 0);
    return Res;
}

void* SSL_get_default_passwd_cb_userdata(SSL* ssl) {
    void* Res = NULL;
    sf_set_must_be_not_null(ssl, GET_DEFAULT_PASSWD_CB_USERDATA_OF_NULL);
    Res = SSL_get_default_passwd_cb_userdata(ssl);
    sf_set_possible_null(Res);
    return Res;
}
int EVP_CIPHER_CTX_get_nid(const EVP_CIPHER_CTX* ctx);

void ENGINE_unregister_DSA(ENGINE* e);

unsigned int SSL_CONF_CTX_set_flags(SSL_CONF_CTX* cctx, unsigned int flags);

void EC_POINT_free(EC_POINT* point);

int PEM_write_PrivateKey_ex(FILE* fp, const EVP_PKEY* x, const EVP_CIPHER* enc, const unsigned char* kstr, int klen, pem_password_cb* cb, void* u, OSSL_LIB_CTX* libctx, const char* propq);


const EVP_CIPHER* EVP_aria_256_ecb() {
    const EVP_CIPHER* Res = NULL;
    Res = EVP_aria_256_ecb();
    sf_set_possible_null(Res);
    return Res;
}

int i2d_DIRECTORYSTRING(const ASN1_STRING* a, unsigned char** pp) {
    int Res = 0;
    Res = i2d_DIRECTORYSTRING(a, pp);
    sf_set_errno_if(Res <= 0);
    return Res;
}

EC_GROUP* d2i_ECPKParameters(EC_GROUP** a, const unsigned char** pp, long length) {
    EC_GROUP* Res = NULL;
    Res = d2i_ECPKParameters(a, pp, length);
    sf_set_possible_null(Res);
    return Res;
}

ENGINE* ENGINE_get_default_DSA() {
    ENGINE* Res = NULL;
    Res = ENGINE_get_default_DSA();
    sf_set_possible_null(Res);
    return Res;
}

X509_SIG* PEM_read_PKCS8(FILE* fp, X509_SIG** x, pem_password_cb* cb, void* u) {
    X509_SIG* Res = NULL;
    Res = PEM_read_PKCS8(fp, x, cb, u);
    sf_set_possible_null(Res);
    return Res;
}
int SSL_CTX_set_session_ticket_cb(SSL_CTX* ctx, SSL_CTX_generate_session_ticket_fn gen_cb, SSL_CTX_decrypt_session_ticket_fn dec_cb, void* cb_arg);

int SSL_use_certificate_chain_file(SSL* ssl, const char* file);

int PEM_write_RSAPublicKey(FILE* fp, const RSA* rsa);

int i2d_X509_ALGORS(const X509_ALGORS* alg, unsigned char** pp);

void EVP_DecodeInit(EVP_ENCODE_CTX* ctx);


int i2d_ECDSA_SIG(const ECDSA_SIG *sig, unsigned char **pp)
{
    int ret = 0;
    sf_set_tainted(sig);
    sf_set_must_not_be_null(pp);
    sf_set_trusted_sink_ptr(pp);
    sf_set_errno_if(ret <= 0);
    sf_set_alloc_possible_null(*pp);
    sf_set_possible_null(ret);
    return ret;
}

EC_KEY *EC_KEY_new_by_curve_name(int nid)
{
    EC_KEY *key = NULL;
    sf_set_must_not_be_null(nid);
    sf_set_errno_if(key == NULL);
    sf_set_possible_null(key);
    return key;
}

int EC_GROUP_check(const EC_GROUP *group, BN_CTX *ctx)
{
    int ret = 0;
    sf_set_must_not_be_null(group);
    sf_set_must_not_be_null(ctx);
    sf_set_errno_if(ret <= 0);
    sf_set_possible_null(ret);
    return ret;
}

const EVP_MD *EVP_sha3_224()
{
    const EVP_MD *md = NULL;
    sf_set_errno_if(md == NULL);
    sf_set_possible_null(md);
    return md;
}

int X509_load_crl_file(X509_LOOKUP *lookup, const char *file, int type)
{
    int ret = 0;
    sf_set_must_not_be_null(lookup);
    sf_set_must_not_be_null(file);
    sf_set_tainted(file);
    sf_set_errno_if(ret <= 0);
    sf_set_possible_null(ret);
    return ret;
}
int SSL_COMP_get_id(const SSL_COMP* comp);

int HMAC_Init(HMAC_CTX* ctx, const void* key, int len, const EVP_MD* md);

int BN_BLINDING_invert_ex(BIGNUM* r, const BIGNUM* a, BN_BLINDING* b, BN_CTX* ctx);

int SSL_CTX_set_default_verify_paths(SSL_CTX* ctx);

void ASN1_STRING_TABLE_cleanup();


BIO_callback_fn_ex BIO_get_callback_ex(const BIO* bio) {
    BIO_callback_fn_ex res = NULL;
    sf_set_must_be_not_null(bio, BIO_GET_CALLBACK_EX_OF_NULL);
    res = BIO_get_callback_ex(bio);
    sf_set_possible_null(res);
    return res;
}

ASN1_STRING_TABLE* ASN1_STRING_TABLE_get(int nid) {
    ASN1_STRING_TABLE* res = NULL;
    res = ASN1_STRING_TABLE_get(nid);
    sf_set_possible_null(res);
    return res;
}

void IPAddressOrRange_free(IPAddressOrRange* ip) {
    sf_set_must_be_not_null(ip, IP_ADDRESS_OR_RANGE_FREE_OF_NULL);
    IPAddressOrRange_free(ip);
}

int i2d_PKCS8PrivateKey_nid_bio(BIO* bio, const EVP_PKEY* pkey, int nid, const char* pass, int passlen, pem_password_cb* cb, void* u) {
    int res = 0;
    sf_set_must_be_not_null(bio, I2D_PKCS8_PRIVATE_KEY_NID_BIO_OF_NULL);
    sf_password_use(pass);
    res = i2d_PKCS8PrivateKey_nid_bio(bio, pkey, nid, pass, passlen, cb, u);
    sf_set_errno_if(res <= 0);
    return res;
}

void SSL_CTX_set_client_cert_cb(SSL_CTX* ctx, int (*cb)(SSL*, X509**, EVP_PKEY**)) {
    sf_set_must_be_not_null(ctx, SSL_CTX_SET_CLIENT_CERT_CB_OF_NULL);
    SSL_CTX_set_client_cert_cb(ctx, cb);
}
long SSL_SESSION_set_time(SSL_SESSION* s, long time);

int SSL_CTX_set_tlsext_max_fragment_length(SSL_CTX* ctx, uint8_t max_fragment_length);

const OSSL_PARAM* EVP_CIPHER_gettable_params(const EVP_CIPHER* cipher);

int SSL_CTX_has_client_custom_ext(const SSL_CTX* ctx, unsigned int ext_type);

stack_st_X509_NAME* SSL_load_client_CA_file(const char* file);


BN_RECP_CTX* BN_RECP_CTX_new()
{
    BN_RECP_CTX* Res = NULL;
    Res = (BN_RECP_CTX*)sf_malloc_arg(sizeof(BN_RECP_CTX));
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    return Res;
}

void EVP_PKEY_asn1_set_ctrl(EVP_PKEY_ASN1_METHOD* p, int (*f)(EVP_PKEY*, int, long, void*))
{
    sf_lib_arg_type(p, "EVP_PKEY_ASN1_METHOD");
    p->ctrl = f;
}

PKCS7_ISSUER_AND_SERIAL* d2i_PKCS7_ISSUER_AND_SERIAL(PKCS7_ISSUER_AND_SERIAL** a, const unsigned char** in, long len)
{
    PKCS7_ISSUER_AND_SERIAL* Res = NULL;
    Res = (PKCS7_ISSUER_AND_SERIAL*)sf_malloc_arg(sizeof(PKCS7_ISSUER_AND_SERIAL));
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    return Res;
}

int i2d_ECPrivateKey_bio(BIO* bp, const EC_KEY* key)
{
    sf_lib_arg_type(bp, "BIO");
    sf_lib_arg_type(key, "EC_KEY");
    // Implementation of the function
}

long BIO_debug_callback_ex(BIO* bio, int cmd, const char* argp, size_t len, int argi, long argl, int ret, size_t* processlen)
{
    sf_lib_arg_type(bio, "BIO");
    sf_lib_arg_type(argp, "char");
    // Implementation of the function
}
int ECPKParameters_print(BIO*, const EC_GROUP*, int);

int i2d_OCSP_REVOKEDINFO(const OCSP_REVOKEDINFO*, unsigned char**);

int X509_REQ_get_attr_by_OBJ(const X509_REQ*, const ASN1_OBJECT*, int);

X509_VERIFY_PARAM* SSL_get0_param(SSL*);

void X509_get0_signature(const ASN1_BIT_STRING**, const X509_ALGOR**, const X509*);


int BIO_method_type(const BIO* bio) {
    int Res = 0;
    sf_set_must_be_not_null(bio, BIO_METHOD_TYPE_OF_NULL);
    sf_set_errno_if(Res == 0, BIO_METHOD_TYPE_FAILURE);
    return Res;
}

int EVP_PKEY_decapsulate_init(EVP_PKEY_CTX* ctx, const OSSL_PARAM params[]) {
    int Res = 0;
    sf_set_must_be_not_null(ctx, EVP_PKEY_DECAPSULATE_INIT_OF_NULL);
    sf_set_errno_if(Res <= 0, EVP_PKEY_DECAPSULATE_INIT_FAILURE);
    return Res;
}

int X509_STORE_up_ref(X509_STORE* store) {
    int Res = 0;
    sf_set_must_be_not_null(store, X509_STORE_UP_REF_OF_NULL);
    sf_set_errno_if(Res <= 0, X509_STORE_UP_REF_FAILURE);
    return Res;
}

const EVP_CIPHER* EVP_aes_128_cbc_hmac_sha256() {
    const EVP_CIPHER* Res = NULL;
    sf_set_errno_if(Res == NULL, EVP_AES_128_CBC_HMAC_SHA256_FAILURE);
    return Res;
}

unsigned char* SHA1(const unsigned char* d, size_t n, unsigned char* md) {
    unsigned char* Res = NULL;
    sf_set_must_be_not_null(d, SHA1_DATA_OF_NULL);
    sf_set_must_be_not_null(md, SHA1_RESULT_OF_NULL);
    sf_set_errno_if(Res == NULL, SHA1_FAILURE);
    return Res;
}

int EVP_PKEY_get_ec_point_conv_form(const EVP_PKEY* pkey) {
    int res = 0;
    sf_set_must_be_not_null(pkey, EC_POINT_CONV_FORM_OF_NULL);
    sf_set_errno_if(res < 0, EC_POINT_CONV_FORM_ERROR);
    return res;
}

void EXTENDED_KEY_USAGE_free(EXTENDED_KEY_USAGE* ex_key) {
    sf_set_must_be_not_null(ex_key, FREE_OF_NULL);
    sf_delete(ex_key, EXTENDED_KEY_USAGE_MEMORY_CATEGORY);
    sf_lib_arg_type(ex_key, "ExtendedKeyUsage");
}

int SSL_dane_tlsa_add(SSL* s, uint8_t usage, uint8_t selector, uint8_t mtype, const unsigned char* data, size_t dlen) {
    int res = 0;
    sf_set_must_be_not_null(s, SSL_DANE_TLS_ADD_ERROR);
    sf_set_buf_size_limit(data, dlen);
    sf_set_errno_if(res <= 0, SSL_DANE_TLS_ADD_ERROR);
    return res;
}

int i2b_PVK_bio(BIO* bp, const EVP_PKEY* pkey, int enclevel, pem_password_cb* cb, void* u) {
    int res = 0;
    sf_set_must_be_not_null(bp, BIO_WRITE_ERROR);
    sf_set_must_be_not_null(pkey, PVK_CONVERSION_ERROR);
    sf_password_use(cb, u);
    sf_set_errno_if(res <= 0, PVK_CONVERSION_ERROR);
    return res;
}

X509_VERIFY_PARAM* X509_STORE_CTX_get0_param(const X509_STORE_CTX* ctx) {
    X509_VERIFY_PARAM* res = NULL;
    sf_set_must_be_not_null(ctx, X509_STORE_CTX_GET_PARAM_ERROR);
    sf_set_possible_null(res);
    return res;
}
int X509_STORE_CTX_set_purpose(X509_STORE_CTX* ctx, int purpose);

int RSA_meth_set_sign(RSA_METHOD* rsa, int (*sign);

PKCS7_SIGNER_INFO* PKCS7_SIGNER_INFO_new();

ASN1_SEQUENCE_ANY* d2i_ASN1_SET_ANY(ASN1_SEQUENCE_ANY** a, const unsigned char** in, long len);

void CRYPTO_free(void* ptr, const char* file, int line);


RSA* d2i_RSAPrivateKey(RSA** rsa, const unsigned char** pp, long length)
{
    RSA* Res = NULL;
    sf_set_trusted_sink_int(length);
    sf_malloc_arg(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    sf_lib_arg_type(Res, "RSA");
    return Res;
}

int OBJ_cmp(const ASN1_OBJECT* a, const ASN1_OBJECT* b)
{
    int Res = 0;
    sf_set_possible_null(Res);
    return Res;
}

int DSA_set_method(DSA* dsa, const DSA_METHOD* meth)
{
    int Res = 0;
    sf_set_possible_null(Res);
    return Res;
}

const EVP_CIPHER* EVP_seed_ofb()
{
    const EVP_CIPHER* Res = NULL;
    sf_set_possible_null(Res);
    return Res;
}

int ENGINE_set_default_DSA(ENGINE* e)
{
    int Res = 0;
    sf_set_possible_null(Res);
    return Res;
}

OCSP_RESPONSE* OCSP_response_create(int type, OCSP_BASICRESP* bs) {
    OCSP_RESPONSE* Res = NULL;
    sf_set_trusted_sink_int(type);
    Res = OCSP_response_create(type, bs);
    sf_overwrite(Res);
    return Res;
}

ENGINE* ENGINE_get_default_RAND() {
    ENGINE* Res = NULL;
    Res = ENGINE_get_default_RAND();
    sf_overwrite(Res);
    return Res;
}

int PEM_write_bio_DSAparams(BIO* bio, const DSA* dsa) {
    int Res = 0;
    sf_set_trusted_sink_ptr(bio);
    Res = PEM_write_bio_DSAparams(bio, dsa);
    sf_overwrite(&Res);
    return Res;
}

void PKCS7_SIGNED_free(PKCS7_SIGNED* p7s) {
    sf_set_trusted_sink_ptr(p7s);
    PKCS7_SIGNED_free(p7s);
}

X509_EXTENSION* X509V3_EXT_i2d(int ext_nid, int crit, void* ext_struc) {
    X509_EXTENSION* Res = NULL;
    sf_set_trusted_sink_int(ext_nid);
    Res = X509V3_EXT_i2d(ext_nid, crit, ext_struc);
    sf_overwrite(Res);
    return Res;
}
int X509_get_ext_by_critical(const X509* x, int nid, int crit);

int SHA384_Update(SHA512_CTX* c, const void* data, size_t len);

int ENGINE_register_RAND(ENGINE* e);

int BIO_meth_set_gets(BIO_METHOD* biom, int (BIO*, char*, int);

const SSL_METHOD* TLSv1_2_method();


const EVP_CIPHER* EVP_seed_cfb128() {
    const EVP_CIPHER* Res = NULL;
    Res = EVP_seed_cfb128();
    sf_set_possible_null(Res);
    return Res;
}

int EVP_PKEY_CTX_set_rsa_oaep_md_name(EVP_PKEY_CTX* ctx, const char* mdname, const char* mdprops) {
    int Res = 0;
    Res = EVP_PKEY_CTX_set_rsa_oaep_md_name(ctx, mdname, mdprops);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int RSA_meth_set_multi_prime_keygen(RSA_METHOD* rsa, int (*multi_prime_keygen)(RSA*, int, int, BIGNUM*, BN_GENCB*)) {
    int Res = 0;
    Res = RSA_meth_set_multi_prime_keygen(rsa, multi_prime_keygen);
    sf_set_errno_if(Res <= 0);
    return Res;
}

NOTICEREF* NOTICEREF_new() {
    NOTICEREF* Res = NULL;
    Res = NOTICEREF_new();
    sf_set_possible_null(Res);
    return Res;
}

int SSL_use_RSAPrivateKey_ASN1(SSL* ssl, const unsigned char* d, long len) {
    int Res = 0;
    Res = SSL_use_RSAPrivateKey_ASN1(ssl, d, len);
    sf_set_errno_if(Res <= 0);
    return Res;
}
int SSL_renegotiate_abbreviated(SSL* ssl);

ASN1_TYPE* ASN1_generate_nconf(const char* str, CONF* conf);

int SSL_CONF_cmd(SSL_CONF_CTX* cctx, const char* cmd, const char* value);

int EVP_PKEY_CTX_set_dh_kdf_type(EVP_PKEY_CTX* ctx, int kdf_type);

void ADMISSIONS_set0_professionInfos(ADMISSIONS* adm, PROFESSION_INFOS* infos);

void HMAC_CTX_set_flags(HMAC_CTX* ctx, unsigned long flags);

int X509_check_host(X509* x, const char* name, size_t namelen, unsigned int flags, char** peername);

int X509_subject_name_cmp(const X509* a, const X509* b);

int X509_up_ref(X509* x);

int X509_VERIFY_PARAM_set1_ip(X509_VERIFY_PARAM* param, const unsigned char* ip, size_t iplen);


int EVP_MD_CTX_test_flags(const EVP_MD_CTX* ctx, int flags) {
    int res = 0;
    sf_set_must_be_not_null(ctx, "EVP_MD_CTX_test_flags");
    sf_set_tainted(flags);
    sf_set_errno_if(res == -1);
    return res;
}

int EVP_PKEY_CTX_set0_rsa_oaep_label(EVP_PKEY_CTX* ctx, void* label, int llen) {
    int res = 0;
    sf_set_must_be_not_null(ctx, "EVP_PKEY_CTX_set0_rsa_oaep_label");
    sf_set_tainted(label);
    sf_set_tainted(llen);
    sf_set_errno_if(res == 0);
    return res;
}

int EVP_RAND_verify_zeroization(EVP_RAND_CTX* ctx) {
    int res = 0;
    sf_set_must_be_not_null(ctx, "EVP_RAND_verify_zeroization");
    sf_set_errno_if(res == 0);
    return res;
}

OCSP_REQINFO* d2i_OCSP_REQINFO(OCSP_REQINFO** req, const unsigned char** in, long len) {
    OCSP_REQINFO* res = NULL;
    sf_set_tainted(req);
    sf_set_tainted(in);
    sf_set_tainted(len);
    sf_set_errno_if(res == NULL);
    return res;
}

int (EVP_MD_CTX*, unsigned char*)* EVP_MD_meth_get_final(const EVP_MD* md) {
    int (EVP_MD_CTX*, unsigned char*)* res = NULL;
    sf_set_must_be_not_null(md, "EVP_MD_meth_get_final");
    sf_set_errno_if(res == NULL);
    return res;
}

int EVP_PKEY_CTX_set_dsa_paramgen_bits(EVP_PKEY_CTX *ctx, int bits) {
    int res = 0;
    sf_set_must_be_not_null(ctx, SET_DSA_PARAMGEN_BITS_OF_NULL);
    sf_set_trusted_sink_int(bits, SET_DSA_PARAMGEN_BITS_SINK);
    res = EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DSA, EVP_PKEY_OP_PARAMGEN, EVP_PKEY_CTRL_DSA_PARAMGEN_BITS, bits, NULL);
    sf_set_errno_if(res <= 0, SET_DSA_PARAMGEN_BITS_FAIL);
    return res;
}

ADMISSIONS* d2i_ADMISSIONS(ADMISSIONS **a, const unsigned char **in, long len) {
    ADMISSIONS *res = NULL;
    sf_set_must_be_not_null(a, D2I_ADMISSIONS_NULL);
    sf_set_must_be_not_null(*in, D2I_ADMISSIONS_IN_NULL);
    sf_set_trusted_sink_int(len, D2I_ADMISSIONS_LEN_SINK);
    res = d2i_ADMISSIONS_internal(a, in, len);
    sf_set_errno_if(res == NULL, D2I_ADMISSIONS_FAIL);
    return res;
}

const EVP_MD* EVP_sha224() {
    const EVP_MD *res = NULL;
    res = EVP_sha224();
    sf_set_errno_if(res == NULL, EVP_SHA224_FAIL);
    return res;
}

void SSL_CTX_set_default_passwd_cb_userdata(SSL_CTX *ctx, void *userdata) {
    sf_set_must_be_not_null(ctx, SET_DEFAULT_PASSWD_CB_USERDATA_NULL);
    SSL_CTX_set_default_passwd_cb_userdata(ctx, userdata);
}

const EVP_MD* EVP_md4() {
    const EVP_MD *res = NULL;
    res = EVP_md4();
    sf_set_errno_if(res == NULL, EVP_MD4_FAIL);
    return res;
}

void UI_method_set_reader(UI_METHOD* m, int (*reader)(UI*, UI_STRING*)) {
    int res = 0;
    sf_set_trusted_sink_int(m);
    sf_set_trusted_sink_ptr(reader);
    res = UI_method_set_reader(m, reader);
    sf_set_errno_if(res == -1);
    sf_set_possible_null(res);
}

long SSL_ctrl(SSL* s, int cmd, long larg, void* parg) {
    long res = 0;
    sf_set_must_be_not_null(s, SSL_CTRL_OF_NULL);
    sf_set_trusted_sink_ptr(parg);
    res = SSL_ctrl(s, cmd, larg, parg);
    sf_set_errno_if(res == -1);
    sf_set_possible_negative(res);
    return res;
}

ASN1_INTEGER* d2i_ASN1_INTEGER(ASN1_INTEGER** a, const unsigned char** pp, long length) {
    ASN1_INTEGER* res = NULL;
    sf_set_trusted_sink_ptr(a);
    sf_set_trusted_sink_ptr(pp);
    sf_buf_size_limit(pp, length);
    res = d2i_ASN1_INTEGER(a, pp, length);
    sf_set_alloc_possible_null(res);
    return res;
}

stack_st_SSL_CIPHER* SSL_get1_supported_ciphers(SSL* s) {
    stack_st_SSL_CIPHER* res = NULL;
    sf_set_must_be_not_null(s, SSL_GET1_SUPPORTED_CIPHERS_OF_NULL);
    res = SSL_get1_supported_ciphers(s);
    sf_set_alloc_possible_null(res);
    return res;
}

void BASIC_CONSTRAINTS_free(BASIC_CONSTRAINTS* bc) {
    sf_set_must_be_not_null(bc, BASIC_CONSTRAINTS_FREE_OF_NULL);
    BASIC_CONSTRAINTS_free(bc);
    sf_delete(bc, BASIC_CONSTRAINTS_CATEGORY);
}

void ERR_remove_thread_state(void* ptr) {
    sf_set_trusted_sink_ptr(ptr);
    ERR_remove_thread_state(ptr);
}

size_t EC_KEY_key2buf(const EC_KEY *key, point_conversion_form_t form, unsigned char **buf, BN_CTX *ctx) {
    size_t res = 0;
    sf_set_trusted_sink_int(res);
    res = EC_KEY_key2buf(key, form, buf, ctx);
    sf_overwrite(res);
    return res;
}

int X509_REQ_add1_attr_by_OBJ(X509_REQ *req, const ASN1_OBJECT *obj, int type, const unsigned char *bytes, int len) {
    int res = 0;
    sf_set_must_not_be_null(req);
    sf_set_must_not_be_null(obj);
    sf_set_must_not_be_null(bytes);
    res = X509_REQ_add1_attr_by_OBJ(req, obj, type, bytes, len);
    sf_set_errno_if(res <= 0);
    return res;
}

int BN_clear_bit(BIGNUM *a, int n) {
    int res = 0;
    sf_set_must_not_be_null(a);
    res = BN_clear_bit(a, n);
    sf_overwrite(res);
    return res;
}

int EVP_PKEY_CTX_set_params(EVP_PKEY_CTX *ctx, const OSSL_PARAM *params) {
    int res = 0;
    sf_set_must_not_be_null(ctx);
    sf_set_must_not_be_null(params);
    res = EVP_PKEY_CTX_set_params(ctx, params);
    sf_set_errno_if(res <= 0);
    return res;
}

const stack_st_X509_NAME* SSL_get0_peer_CA_list(const SSL* s) {
    const stack_st_X509_NAME* Res = NULL;
    Res = s->peer_CA_list;
    sf_set_possible_null(Res);
    return Res;
}

int EC_POINT_oct2point(const EC_GROUP* group, EC_POINT* point, const unsigned char* buf, size_t len, BN_CTX* ctx) {
    int Res = 0;
    Res = EC_POINT_oct2point(group, point, buf, len, ctx);
    sf_set_errno_if(Res == 0);
    return Res;
}

void CRYPTO_secure_clear_free(void* ptr, size_t num, const char* file, int line) {
    CRYPTO_secure_clear_free(ptr, num);
    sf_delete(ptr, MALLOC_CATEGORY);
}

void X509_REQ_free(X509_REQ* req) {
    X509_REQ_free(req);
    sf_delete(req, MALLOC_CATEGORY);
}

X509_STORE_CTX_cleanup_fn X509_STORE_get_cleanup(const X509_STORE* store) {
    X509_STORE_CTX_cleanup_fn Res = NULL;
    Res = store->cleanup;
    sf_set_possible_null(Res);
    return Res;
}
int ENGINE_set_ciphers(ENGINE*, ENGINE_CIPHERS_PTR);

ASN1_VALUE* ASN1_item_d2i_ex(ASN1_VALUE**, const unsigned char**, long, const ASN1_ITEM*, OSSL_LIB_CTX*, const char*);

int (BIGNUM*, const BIGNUM*, RSA*, BN_CTX*);

int CTLOG_new_from_base64_ex(CTLOG**, const char*, const char*, OSSL_LIB_CTX*, const char*);

int ENGINE_set_RSA(ENGINE*, const RSA_METHOD*);

int i2d_ASIdentifierChoice(const ASIdentifierChoice* a, unsigned char** pp);

BASIC_CONSTRAINTS* d2i_BASIC_CONSTRAINTS(BASIC_CONSTRAINTS** a, const unsigned char** pp, long l);

OSSL_PARAM OSSL_PARAM_construct_ulong(const char* key, unsigned long int* buf);

int BN_print(BIO* bp, const BIGNUM* a);

void X509_VAL_free(X509_VAL* a);


int EC_POINT_set_compressed_coordinates(const EC_GROUP *group, EC_POINT *point, const BIGNUM *x, int y_bit, BN_CTX *ctx) {
    int res = 0;
    sf_set_trusted_sink_int(y_bit);
    sf_set_tainted(x);
    sf_set_tainted(group);
    sf_set_tainted(point);
    sf_set_tainted(ctx);
    sf_set_errno_if(res == 0, EDOM);
    sf_set_errno_if(res == -1, ERR_get_error());
    return res;
}

PKCS7_SIGNED* d2i_PKCS7_SIGNED(PKCS7_SIGNED **a, const unsigned char **in, long len) {
    PKCS7_SIGNED *res = NULL;
    sf_set_trusted_sink_int(len);
    sf_set_tainted(in);
    sf_set_alloc_possible_null(res, len);
    sf_set_errno_if(res == NULL, ERR_get_error());
    return res;
}

int EC_KEY_oct2priv(EC_KEY *eckey, const unsigned char *buf, size_t len) {
    int res = 0;
    sf_set_trusted_sink_int(len);
    sf_set_tainted(eckey);
    sf_set_tainted(buf);
    sf_set_errno_if(res == 0, EDOM);
    sf_set_errno_if(res == -1, ERR_get_error());
    return res;
}

X509_ATTRIBUTE* X509at_get_attr(const stack_st_X509_ATTRIBUTE *sk, int idx) {
    X509_ATTRIBUTE *res = NULL;
    sf_set_trusted_sink_int(idx);
    sf_set_tainted(sk);
    sf_set_possible_null(res);
    return res;
}

X509_REQ* d2i_X509_REQ_bio(BIO *bp, X509_REQ **x) {
    X509_REQ *res = NULL;
    sf_set_tainted(bp);
    sf_set_tainted(x);
    sf_set_alloc_possible_null(res);
    sf_set_errno_if(res == NULL, ERR_get_error());
    return res;
}

EVP_PKEY* PEM_read_bio_PrivateKey_ex(BIO* bio, EVP_PKEY** pkey, pem_password_cb* cb, void* u, OSSL_LIB_CTX* libctx, const char* propq) {
    EVP_PKEY* Res = NULL;
    sf_set_tainted(bio);
    sf_password_use(cb);
    sf_set_trusted_sink_ptr(u);
    sf_set_trusted_sink_int(libctx);
    sf_set_trusted_sink_str(propq);
    sf_set_must_be_not_null(bio, FREE_OF_NULL);
    sf_set_must_be_not_null(pkey, FREE_OF_NULL);
    sf_set_must_be_not_null(cb, FREE_OF_NULL);
    sf_set_must_be_not_null(libctx, FREE_OF_NULL);
    sf_set_must_be_not_null(propq, FREE_OF_NULL);
    sf_set_possible_null(Res);
    return Res;
}

void RSA_blinding_off(RSA* r) {
    sf_set_must_be_not_null(r, FREE_OF_NULL);
}

int EC_GROUP_get_curve_GFp(const EC_GROUP* group, BIGNUM* p, BIGNUM* a, BIGNUM* b, BN_CTX* ctx) {
    int Res = 0;
    sf_set_must_be_not_null(group, FREE_OF_NULL);
    sf_set_must_be_not_null(p, FREE_OF_NULL);
    sf_set_must_be_not_null(a, FREE_OF_NULL);
    sf_set_must_be_not_null(b, FREE_OF_NULL);
    sf_set_must_be_not_null(ctx, FREE_OF_NULL);
    sf_set_possible_null(Res);
    return Res;
}

const ASN1_ITEM* ISSUER_SIGN_TOOL_it() {
    const ASN1_ITEM* Res = NULL;
    sf_set_possible_null(Res);
    return Res;
}

ASN1_NULL* d2i_ASN1_NULL(ASN1_NULL** a, const unsigned char** in, long len) {
    ASN1_NULL* Res = NULL;
    sf_set_must_be_not_null(a, FREE_OF_NULL);
    sf_set_must_be_not_null(in, FREE_OF_NULL);
    sf_set_possible_null(Res);
    return Res;
}

void SSL_set_record_padding_callback_arg(SSL *ssl, void *arg)
{
    sf_set_tainted(arg);
    sf_set_trusted_sink_ptr(arg);
    SSL_set_record_padding_callback_arg(ssl, arg);
}

int BIO_wait(BIO *bio, time_t t, unsigned int u)
{
    sf_set_must_be_not_null(bio, BIO_WAIT_OF_NULL);
    sf_set_must_be_positive(t);
    sf_set_must_be_not_null(u, BIO_WAIT_OF_NULL);
    int res = BIO_wait(bio, t, u);
    sf_set_errno_if(res == -1);
    return res;
}

const OSSL_PARAM *EVP_MD_CTX_settable_params(EVP_MD_CTX *ctx)
{
    sf_set_must_be_not_null(ctx, EVP_MD_CTX_SETTABLE_PARAMS_OF_NULL);
    const OSSL_PARAM *res = EVP_MD_CTX_settable_params(ctx);
    return res;
}

int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *data, size_t len)
{
    sf_set_must_be_not_null(ctx, EVP_DIGEST_UPDATE_OF_NULL);
    sf_set_must_be_not_null(data, EVP_DIGEST_UPDATE_OF_NULL);
    sf_set_must_be_not_null(len, EVP_DIGEST_UPDATE_OF_NULL);
    sf_set_buf_size_limit(data, len);
    int res = EVP_DigestUpdate(ctx, data, len);
    sf_set_errno_if(res == 0);
    return res;
}

int ENGINE_add(ENGINE *engine)
{
    sf_set_must_be_not_null(engine, ENGINE_ADD_OF_NULL);
    int res = ENGINE_add(engine);
    sf_set_errno_if(res == 0);
    return res;
}
stack_st_X509_ATTRIBUTE* X509at_add1_attr(stack_st_X509_ATTRIBUTE** sk, X509_ATTRIBUTE* attr);

int UI_method_set_flusher(UI_METHOD* method, int (UI*);

const OSSL_PARAM* EVP_PKEY_fromdata_settable(EVP_PKEY_CTX* ctx, int selection);

const CTLOG* CTLOG_STORE_get0_log_by_id(const CTLOG_STORE* store, const uint8_t* id, size_t idlen);

int EC_KEY_get_flags(const EC_KEY* key);


void EVP_PKEY_get0_hmac(const EVP_PKEY* pkey, size_t* len) {
    const unsigned char* Res = NULL;
    Res = EVP_PKEY_get0_hmac(pkey, len);
    sf_set_possible_null(Res);
    sf_set_alloc_possible_null(Res, len);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_buf_size(Res, len);
    sf_lib_arg_type(Res, "MallocCategory");
}

void OSSL_LIB_CTX_free(OSSL_LIB_CTX* ctx) {
    OSSL_LIB_CTX* Res = NULL;
    Res = ctx;
    sf_delete(Res, MALLOC_CATEGORY);
    sf_lib_arg_type(Res, "MallocCategory");
}

void X509_STORE_CTX_init(X509_STORE_CTX* ctx, X509_STORE* store, X509* x509, stack_st_X509* chain) {
    int Res = 0;
    Res = X509_STORE_CTX_init(ctx, store, x509, chain);
    sf_set_errno_if(Res <= 0);
}

void RAND_write_file(const char* file) {
    int Res = 0;
    Res = RAND_write_file(file);
    sf_set_errno_if(Res <= 0);
    sf_tocttou_check(file);
}

void OCSP_RESPID_set_by_key_ex(OCSP_RESPID* id, X509* key, OSSL_LIB_CTX* libctx, const char* propq) {
    int Res = 0;
    Res = OCSP_RESPID_set_by_key_ex(id, key, libctx, propq);
    sf_set_errno_if(Res <= 0);
    sf_password_use(key);
    sf_lib_arg_type(libctx, "OSSL_LIB_CTX");
}

int SSL_set_wfd(SSL* ssl, int fd)
{
    int Res = 0;
    sf_set_trusted_sink_int(fd);
    Res = SSL_set_wfd(ssl, fd);
    sf_set_errno_if(Res, errno);
    sf_no_errno_if(Res);
    return Res;
}

int X509_LOOKUP_meth_set_get_by_alias(X509_LOOKUP_METHOD* method, X509_LOOKUP_get_by_alias_fn fn)
{
    int Res = 0;
    Res = X509_LOOKUP_meth_set_get_by_alias(method, fn);
    sf_set_errno_if(Res, errno);
    sf_no_errno_if(Res);
    return Res;
}

const X509_ALGOR* OCSP_resp_get0_tbs_sigalg(const OCSP_BASICRESP* bs)
{
    const X509_ALGOR* Res = NULL;
    Res = OCSP_resp_get0_tbs_sigalg(bs);
    sf_set_possible_null(Res);
    return Res;
}

int EVP_PKEY_get_id(const EVP_PKEY* pkey)
{
    int Res = 0;
    Res = EVP_PKEY_get_id(pkey);
    sf_set_possible_null(Res);
    return Res;
}

int EVP_KEYEXCH_up_ref(EVP_KEYEXCH* keyexch)
{
    int Res = 0;
    Res = EVP_KEYEXCH_up_ref(keyexch);
    sf_set_errno_if(Res, errno);
    sf_no_errno_if(Res);
    return Res;
}

BUF_MEM *Res = NULL;
sf_new(Res, PAGES_MEMORY_CATEGORY);
return Res;

sf_set_tainted(ctx);
sf_set_tainted(pkey);
int Res = 0;
sf_set_errno_if(Res == 0);
return Res;

const EVP_CIPHER *Res = NULL;
sf_set_possible_null(Res);
return Res;

sf_set_must_be_not_null(s, FREE_OF_NULL);
int Res = 0;
sf_set_errno_if(Res <= 0);
return Res;

sf_set_must_be_not_null(c, FREE_OF_NULL);
int Res = 0;
sf_set_possible_null(Res);
return Res;

void* SSL_get0_security_ex_data(const SSL* s) {
    void* Res = NULL;
    sf_set_trusted_sink_ptr(s);
    Res = SSL_get_ex_data(s, 0);
    sf_overwrite(Res);
    return Res;
}

const EVP_MD* EVP_sha384() {
    const EVP_MD* Res = NULL;
    Res = EVP_sha384();
    sf_overwrite(Res);
    return Res;
}

int i2d_ASN1_OBJECT(const ASN1_OBJECT* a, unsigned char** pp) {
    int Res = 0;
    sf_set_trusted_sink_ptr(pp);
    Res = i2d_ASN1_OBJECT(a, pp);
    sf_set_errno_if(Res <= 0);
    return Res;
}

void X509_STORE_CTX_set0_untrusted(X509_STORE_CTX* ctx, stack_st_X509* untrusted) {
    sf_set_trusted_sink_ptr(ctx);
    X509_STORE_CTX_set0_untrusted(ctx, untrusted);
}

int OSSL_PARAM_set_double(OSSL_PARAM* param, double value) {
    int Res = 0;
    sf_set_trusted_sink_ptr(param);
    Res = OSSL_PARAM_set_double(param, value);
    sf_set_errno_if(Res == 0);
    return Res;
}

ASIdentifiers* d2i_ASIdentifiers(ASIdentifiers** a, const unsigned char** pp, long length)
{
    ASIdentifiers* Res = NULL;
    sf_set_trusted_sink_int(length);
    sf_malloc_arg(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    sf_lib_arg_type(Res, "ASIdentifiers");
    return Res;
}

void NETSCAPE_SPKAC_free(NETSCAPE_SPKAC* a)
{
    sf_set_must_be_not_null(a, FREE_OF_NULL);
    sf_delete(a, PAGES_MEMORY_CATEGORY);
    sf_lib_arg_type(a, "NETSCAPE_SPKAC");
}

int X509_add_ext(X509* x, X509_EXTENSION* ex, int loc)
{
    int Res = 0;
    sf_set_errno_if(Res, EINVAL);
    sf_no_errno_if(Res);
    return Res;
}

SSL* SSL_new(SSL_CTX* ctx)
{
    SSL* Res = NULL;
    sf_set_trusted_sink_ptr(ctx);
    sf_malloc_arg(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    sf_lib_arg_type(Res, "SSL");
    return Res;
}

X509_EXTENSION* X509_EXTENSION_create_by_NID(X509_EXTENSION** ex, int nid, int crit, ASN1_OCTET_STRING* data)
{
    X509_EXTENSION* Res = NULL;
    sf_malloc_arg(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    sf_lib_arg_type(Res, "X509_EXTENSION");
    return Res;
}
int EVP_PKEY_CTX_get_rsa_oaep_md(EVP_PKEY_CTX*, const EVP_MD**);

size_t BIO_ctrl_get_read_request(BIO*);

int DSA_meth_get_sign_setup(const DSA_METHOD*, DSA*, BN_CTX*, BIGNUM**, BIGNUM**);

char* CRYPTO_strdup(const char*, const char*, int);

X509_STORE_CTX* X509_STORE_CTX_new();


const EVP_CIPHER* EVP_camellia_192_cbc() {
    const EVP_CIPHER* Res = NULL;
    Res = EVP_camellia_192_cbc();
    sf_set_possible_null(Res);
    return Res;
}

int BN_mod_sub(BIGNUM* r, const BIGNUM* a, const BIGNUM* b, const BIGNUM* m, BN_CTX* ctx) {
    int Res = 0;
    Res = BN_mod_sub(r, a, b, m, ctx);
    sf_set_errno_if(Res == 0);
    return Res;
}

const unsigned char* ASN1_STRING_get0_data(const ASN1_STRING* str) {
    const unsigned char* Res = NULL;
    Res = ASN1_STRING_get0_data(str);
    sf_set_possible_null(Res);
    return Res;
}

int i2d_X509_CERT_AUX(const X509_CERT_AUX* a, unsigned char** pp) {
    int Res = 0;
    Res = i2d_X509_CERT_AUX(a, pp);
    sf_set_errno_if(Res <= 0);
    return Res;
}

void BN_GENCB_set_old(BN_GENCB* cb, void (*callback)(int, int, void*), void* arg) {
    BN_GENCB_set_old(cb, callback, arg);
}
int PEM_write_bio_EC_PUBKEY(BIO* bio, const EC_KEY* ec_key);

int OBJ_create(const char* oid, const char* sn, const char* ln);

int i2d_POLICYQUALINFO(const POLICYQUALINFO* pqi, unsigned char** out);

sct_source_t SCT_get_source(const SCT* sct);

void SXNETID_free(SXNETID* sxnetid);


EVP_PKEY* PEM_read_PUBKEY(FILE* fp, EVP_PKEY** x, pem_password_cb* cb, void* u) {
    EVP_PKEY* Res = NULL;
    sf_set_trusted_sink_int(fp);
    sf_set_trusted_sink_ptr(cb);
    sf_set_trusted_sink_ptr(u);
    sf_set_tainted(x);
    sf_set_errno_if(Res == NULL);
    sf_set_possible_null(Res);
    return Res;
}

void* RSA_meth_get0_app_data(const RSA_METHOD* meth) {
    void* Res = NULL;
    sf_set_trusted_sink_ptr(meth);
    sf_set_possible_null(Res);
    return Res;
}

ASN1_ENUMERATED* BN_to_ASN1_ENUMERATED(const BIGNUM* bn, ASN1_ENUMERATED* ai) {
    ASN1_ENUMERATED* Res = NULL;
    sf_set_trusted_sink_ptr(bn);
    sf_set_trusted_sink_ptr(ai);
    sf_set_possible_null(Res);
    return Res;
}

ISSUING_DIST_POINT* d2i_ISSUING_DIST_POINT(ISSUING_DIST_POINT** a, const unsigned char** in, long len) {
    ISSUING_DIST_POINT* Res = NULL;
    sf_set_trusted_sink_ptr(a);
    sf_set_trusted_sink_ptr(in);
    sf_set_buf_size_limit(in, len);
    sf_set_errno_if(Res == NULL);
    sf_set_possible_null(Res);
    return Res;
}

const EVP_CIPHER* EVP_sm4_cfb128() {
    const EVP_CIPHER* Res = NULL;
    sf_set_possible_null(Res);
    return Res;
}

int EVP_PBE_alg_add(int nid, const EVP_CIPHER *cipher, const EVP_MD *md, EVP_PBE_KEYGEN *keygen) {
    int Res = 0;
    sf_set_trusted_sink_int(nid);
    sf_set_trusted_sink_ptr(cipher);
    sf_set_trusted_sink_ptr(md);
    sf_set_trusted_sink_ptr(keygen);
    Res = EVP_PBE_alg_add(nid, cipher, md, keygen);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen) {
    int Res = 0;
    sf_set_trusted_sink_ptr(ctx);
    sf_set_trusted_sink_ptr(key);
    sf_set_trusted_sink_ptr(keylen);
    Res = EVP_PKEY_derive(ctx, key, keylen);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int OSSL_PARAM_set_int64(OSSL_PARAM *param, int64_t val) {
    int Res = 0;
    sf_set_trusted_sink_ptr(param);
    Res = OSSL_PARAM_set_int64(param, val);
    sf_set_errno_if(Res <= 0);
    return Res;
}

size_t EC_GROUP_set_seed(EC_GROUP *group, const unsigned char *seed, size_t len) {
    size_t Res = 0;
    sf_set_trusted_sink_ptr(group);
    sf_set_trusted_sink_ptr(seed);
    sf_set_trusted_sink_int(len);
    Res = EC_GROUP_set_seed(group, seed, len);
    sf_set_errno_if(Res <= 0);
    return Res;
}

void* BIO_get_ex_data(const BIO *bio, int idx) {
    void *Res = NULL;
    sf_set_trusted_sink_ptr(bio);
    sf_set_trusted_sink_int(idx);
    Res = BIO_get_ex_data(bio, idx);
    sf_set_possible_null(Res);
    return Res;
}

const BIO_METHOD* BIO_f_buffer()
{
    const BIO_METHOD *Res = NULL;
    // Additional implementation here
    return Res;
}

int X509_SIG_INFO_get(const X509_SIG_INFO *siginf, int *mdnid, int *pknid, int *secbits, uint32_t *flags)
{
    int Res = 0;
    // Additional implementation here
    return Res;
}

void ENGINE_unregister_RSA(ENGINE *e)
{
    // Additional implementation here
}

EVP_MD* EVP_MD_fetch(OSSL_LIB_CTX *ctx, const char *name, const char *properties)
{
    EVP_MD *Res = NULL;
    // Additional implementation here
    return Res;
}

int EVP_MD_meth_get_result_size(const EVP_MD *md)
{
    int Res = 0;
    // Additional implementation here
    return Res;
}
const char* SSL_CIPHER_get_name(const SSL_CIPHER* cipher);

void DSA_get0_key(const DSA* dsa, const BIGNUM** pub_key, const BIGNUM** priv_key);

void DISPLAYTEXT_free(ASN1_STRING* displaytext);

unsigned char* OPENSSL_hexstr2buf(const char* str, long* len);

int SSL_SESSION_print(BIO* bio, const SSL_SESSION* sess);


int SSL_get_wfd(const SSL* s) {
    int Res = 0;
    Res = s->wfd;
    sf_set_must_be_not_null(s, SSL_GET_WFD_OF_NULL);
    sf_set_errno_if(Res < 0, SSL_GET_WFD_ERRNO);
    sf_set_possible_null(Res, SSL_GET_WFD_POSSIBLE_NULL);
    return Res;
}

int EVP_MD_meth_get_input_blocksize(const EVP_MD* e) {
    int Res = 0;
    Res = e->input_blocksize;
    sf_set_must_be_not_null(e, EVP_MD_METH_GET_INPUT_BLOCKSIZE_OF_NULL);
    sf_set_errno_if(Res < 0, EVP_MD_METH_GET_INPUT_BLOCKSIZE_ERRNO);
    sf_set_possible_null(Res, EVP_MD_METH_GET_INPUT_BLOCKSIZE_POSSIBLE_NULL);
    return Res;
}

int X509_VERIFY_PARAM_add0_policy(X509_VERIFY_PARAM* param, ASN1_OBJECT* policy) {
    int Res = 0;
    Res = X509_VERIFY_PARAM_add0_policy(param, policy);
    sf_set_must_be_not_null(param, X509_VERIFY_PARAM_ADD0_POLICY_OF_NULL);
    sf_set_must_be_not_null(policy, X509_VERIFY_PARAM_ADD0_POLICY_POLICY_OF_NULL);
    sf_set_errno_if(Res <= 0, X509_VERIFY_PARAM_ADD0_POLICY_ERRNO);
    sf_set_possible_null(Res, X509_VERIFY_PARAM_ADD0_POLICY_POSSIBLE_NULL);
    return Res;
}

int SSL_enable_ct(SSL* s, int onoff) {
    int Res = 0;
    Res = SSL_enable_ct(s, onoff);
    sf_set_must_be_not_null(s, SSL_ENABLE_CT_OF_NULL);
    sf_set_errno_if(Res <= 0, SSL_ENABLE_CT_ERRNO);
    sf_set_possible_null(Res, SSL_ENABLE_CT_POSSIBLE_NULL);
    return Res;
}

RSA* PEM_read_RSAPublicKey(FILE* fp, RSA** x, pem_password_cb* cb, void* u) {
    RSA* Res = NULL;
    Res = PEM_read_RSAPublicKey(fp, x, cb, u);
    sf_set_must_be_not_null(fp, PEM_READ_RSAPUBLICKEY_FP_OF_NULL);
    sf_set_possible_null(Res, PEM_READ_RSAPUBLICKEY_POSSIBLE_NULL);
    sf_password_use(cb);
    sf_set_must_be_not_null(x, PEM_READ_RSAPUBLICKEY_X_OF_NULL);
    sf_set_errno_if(Res == NULL, PEM_READ_RSAPUBLICKEY_ERRNO);
    return Res;
}

void* OPENSSL_sk_pop(OPENSSL_STACK* stack) {
    void *Res = NULL;
    Res = sk_pop(stack);
    sf_set_possible_null(Res);
    return Res;
}

int OCSP_id_issuer_cmp(const OCSP_CERTID* a, const OCSP_CERTID* b) {
    int Res = 0;
    Res = OCSP_id_issuer_cmp(a, b);
    sf_set_errno_if(Res, EFAULT);
    return Res;
}

int EC_POINT_get_Jprojective_coordinates_GFp(const EC_GROUP* group, const EC_POINT* p, BIGNUM* x, BIGNUM* y, BIGNUM* z, BN_CTX* ctx) {
    int Res = 0;
    Res = EC_POINT_get_Jprojective_coordinates_GFp(group, p, x, y, z, ctx);
    sf_set_errno_if(Res, EFAULT);
    return Res;
}

const EVP_MD* EVP_blake2s256() {
    const EVP_MD *Res = NULL;
    Res = EVP_blake2s256();
    sf_set_possible_null(Res);
    return Res;
}

tm* OPENSSL_gmtime(const time_t* timer, tm* result) {
    tm *Res = NULL;
    Res = OPENSSL_gmtime(timer, result);
    sf_set_possible_null(Res);
    return Res;
}

OSSL_PARAM* OSSL_PARAM_dup(const OSSL_PARAM* param) {
    OSSL_PARAM* Res = NULL;
    sf_malloc_arg(Res, sizeof(OSSL_PARAM));
    sf_bitcopy(Res, param, sizeof(OSSL_PARAM));
    return Res;
}

RSA* d2i_RSA_PUBKEY_bio(BIO* bp, RSA** rsa) {
    RSA* Res = NULL;
    sf_lib_arg_type(bp, "BIO");
    sf_lib_arg_type(rsa, "RSA");
    sf_set_trusted_sink_ptr(rsa);
    sf_set_errno_if(Res == NULL);
    return Res;
}

OCSP_BASICRESP* OCSP_BASICRESP_new() {
    OCSP_BASICRESP* Res = NULL;
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    return Res;
}

int X509_STORE_load_store_ex(X509_STORE* ctx, const char* uri, OSSL_LIB_CTX* libctx, const char* propq) {
    int Res = 0;
    sf_lib_arg_type(ctx, "X509_STORE");
    sf_lib_arg_type(libctx, "OSSL_LIB_CTX");
    sf_tocttou_check(uri);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int BN_mod_sqr(BIGNUM* r, const BIGNUM* a, const BIGNUM* m, BN_CTX* ctx) {
    int Res = 0;
    sf_lib_arg_type(r, "BIGNUM");
    sf_lib_arg_type(a, "BIGNUM");
    sf_lib_arg_type(m, "BIGNUM");
    sf_lib_arg_type(ctx, "BN_CTX");
    sf_set_errno_if(Res <= 0);
    return Res;
}
int CRYPTO_THREAD_read_lock(CRYPTO_RWLOCK*);

int EVP_PKEY_CTX_set_dsa_paramgen_seed(EVP_PKEY_CTX*, const unsigned char*, size_t);

int BN_mod_mul_montgomery(BIGNUM*, const BIGNUM*, const BIGNUM*, BN_MONT_CTX*, BN_CTX*);

int OPENSSL_sk_find(OPENSSL_STACK*, const void*);

int PKCS5_v2_PBE_keyivgen(EVP_CIPHER_CTX*, const char*, int, ASN1_TYPE*, const EVP_CIPHER*, const EVP_MD*, int);

int i2d_RSA_PSS_PARAMS(const RSA_PSS_PARAMS* rsa, unsigned char** p);

ASN1_IA5STRING* d2i_ASN1_IA5STRING(ASN1_IA5STRING** a, const unsigned char** in, long len);

stack_st_X509_INFO* PEM_X509_INFO_read_bio(BIO* bp, stack_st_X509_INFO* sk, pem_password_cb* cb, void* u);

int ECDSA_size(const EC_KEY* eckey);

EVP_MAC* EVP_MAC_CTX_get0_mac(EVP_MAC_CTX* ctx);


int X509_ATTRIBUTE_count(const X509_ATTRIBUTE* attr) {
    int res = 0;
    sf_set_must_be_not_null(attr, "X509_ATTRIBUTE");
    res = attr->count;
    sf_set_possible_negative(res);
    return res;
}

ASN1_TYPE* X509_ATTRIBUTE_get0_type(X509_ATTRIBUTE* attr, int idx) {
    ASN1_TYPE* res = NULL;
    sf_set_must_be_not_null(attr, "X509_ATTRIBUTE");
    sf_set_must_be_not_null(attr->value.set, "ASN1_TYPE");
    sf_set_possible_null(res);
    res = sk_ASN1_TYPE_value(attr->value.set, idx);
    return res;
}

void ERR_set_debug(const char* file, int line, const char* func) {
    sf_set_must_be_not_null(file, "ERR_set_debug");
    sf_set_must_be_not_null(func, "ERR_set_debug");
    // No return value, so no need to set a variable 'res'
}

int SCT_set1_extensions(SCT* sct, const unsigned char* exts, size_t exts_len) {
    int res = 0;
    sf_set_must_be_not_null(sct, "SCT");
    sf_set_must_be_not_null(exts, "SCT_set1_extensions");
    sf_buf_size_limit(exts, exts_len);
    res = sct_set1_extensions(sct, exts, exts_len);
    sf_set_errno_if(res == 0);
    return res;
}

int PEM_write_EC_PUBKEY(FILE* fp, const EC_KEY* ec) {
    int res = 0;
    sf_set_must_be_not_null(fp, "PEM_write_EC_PUBKEY");
    sf_set_must_be_not_null(ec, "PEM_write_EC_PUBKEY");
    res = PEM_write_EC_PUBKEY(fp, ec);
    sf_set_errno_if(res == 0);
    return res;
}

const EVP_CIPHER* EVP_des_ecb() {
    const EVP_CIPHER* Res = NULL;
    Res = EVP_des_ecb();
    sf_set_possible_null(Res);
    return Res;
}

int X509_CRL_set_issuer_name(X509_CRL* crl, const X509_NAME* name) {
    int Res = 0;
    Res = X509_CRL_set_issuer_name(crl, name);
    sf_set_errno_if(Res <= 0);
    return Res;
}

DH_METHOD* DH_meth_new(const char* name, int flags) {
    DH_METHOD* Res = NULL;
    Res = DH_meth_new(name, flags);
    sf_set_possible_null(Res);
    return Res;
}

DH* d2i_DHparams(DH** dh, const unsigned char** pp, long length) {
    DH* Res = NULL;
    Res = d2i_DHparams(dh, pp, length);
    sf_set_errno_if(Res == NULL);
    return Res;
}

const EVP_CIPHER* EVP_rc2_cfb64() {
    const EVP_CIPHER* Res = NULL;
    Res = EVP_rc2_cfb64();
    sf_set_possible_null(Res);
    return Res;
}

void EVP_PKEY_meth_get_public_check(const EVP_PKEY_METHOD *pmeth, int (*check_fn)(EVP_PKEY *pkey)) {
    sf_set_trusted_sink_ptr(pmeth);
    sf_set_trusted_sink_ptr(check_fn);
}

sct_validation_status_t SCT_get_validation_status(const SCT *sct) {
    sf_set_trusted_sink_ptr(sct);
    sct_validation_status_t res;
    sf_overwrite(res);
    return res;
}

EVP_PKEY* d2i_PrivateKey(int type, EVP_PKEY **a, const unsigned char **pp, long length) {
    sf_set_trusted_sink_int(type);
    sf_set_trusted_sink_ptr(a);
    sf_set_trusted_sink_ptr(*pp);
    sf_set_trusted_sink_int(length);
    EVP_PKEY *res = NULL;
    sf_overwrite(res);
    return res;
}

int i2d_DSA_PUBKEY_bio(BIO *bp, const DSA *a) {
    sf_set_trusted_sink_ptr(bp);
    sf_set_trusted_sink_ptr(a);
    int res = 0;
    sf_overwrite(res);
    return res;
}

int X509_ALGOR_cmp(const X509_ALGOR *a, const X509_ALGOR *b) {
    sf_set_trusted_sink_ptr(a);
    sf_set_trusted_sink_ptr(b);
    int res = 0;
    sf_overwrite(res);
    return res;
}
int EVP_PKEY_CTX_set1_rsa_keygen_pubexp(EVP_PKEY_CTX* ctx, BIGNUM* pubexp);

size_t BIO_ctrl_pending(BIO* bp);

int SSL_SESSION_set1_id(SSL_SESSION* s, const unsigned char* id, unsigned int idlen);

void BIO_set_callback_ex(BIO* bp, BIO_callback_fn_ex cb);

int EVP_CIPHER_CTX_is_encrypting(const EVP_CIPHER_CTX* ctx);


// ACCESS_DESCRIPTION* ACCESS_DESCRIPTION_new()
ACCESS_DESCRIPTION* ACCESS_DESCRIPTION_new() {
    ACCESS_DESCRIPTION* Res = NULL;
    Res = (ACCESS_DESCRIPTION*)sf_malloc_arg(sizeof(ACCESS_DESCRIPTION));
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    return Res;
}

// int i2d_ADMISSION_SYNTAX(const ADMISSION_SYNTAX*, unsigned char**)
int i2d_ADMISSION_SYNTAX(const ADMISSION_SYNTAX* a, unsigned char** p) {
    int Res = 0;
    sf_set_trusted_sink_int(a);
    sf_set_trusted_sink_ptr(p);
    Res = i2d_ASN1_ADMISSION_SYNTAX(a, p);
    sf_set_errno_if(Res <= 0);
    return Res;
}

// int i2d_ECParameters(const EC_KEY*, unsigned char**)
int i2d_ECParameters(const EC_KEY* a, unsigned char** p) {
    int Res = 0;
    sf_set_trusted_sink_int(a);
    sf_set_trusted_sink_ptr(p);
    Res = i2d_EC_PUBKEY(a, p);
    sf_set_errno_if(Res <= 0);
    return Res;
}

// void UI_free(UI*)
void UI_free(UI* u) {
    sf_delete(u, PAGES_MEMORY_CATEGORY);
    sf_not_acquire_if_eq(u);
    OPENSSL_free(u);
}

// int ASYNC_init_thread(size_t, size_t)
int ASYNC_init_thread(size_t num, size_t size) {
    int Res = 0;
    sf_set_buf_size(num, size);
    Res = async_init_thread(num, size);
    sf_set_errno_if(Res <= 0);
    return Res;
}

unsigned long X509_VERIFY_PARAM_get_flags(const X509_VERIFY_PARAM* param) {
    unsigned long Res = 0;
    sf_set_must_be_not_null(param, FLAGS_OF_NULL);
    sf_set_errno_if(Res == 0, errno);
    return Res;
}

EVP_PKEY* d2i_AutoPrivateKey_ex(EVP_PKEY** out, const unsigned char** in, long len, OSSL_LIB_CTX* libctx, const char* propq) {
    EVP_PKEY* Res = NULL;
    sf_set_must_be_not_null(out, OUTPUT_OF_NULL);
    sf_set_must_be_not_null(in, INPUT_OF_NULL);
    sf_set_must_be_not_null(libctx, LIBCTX_OF_NULL);
    sf_set_must_be_not_null(propq, PROPQ_OF_NULL);
    sf_set_errno_if(Res == NULL, errno);
    return Res;
}

const EVP_CIPHER* EVP_CIPHER_CTX_get0_cipher(const EVP_CIPHER_CTX* ctx) {
    const EVP_CIPHER* Res = NULL;
    sf_set_must_be_not_null(ctx, CIPHER_CTX_OF_NULL);
    sf_set_errno_if(Res == NULL, errno);
    return Res;
}

X509_REVOKED* d2i_X509_REVOKED(X509_REVOKED** a, const unsigned char** in, long len) {
    X509_REVOKED* Res = NULL;
    sf_set_must_be_not_null(a, OUTPUT_OF_NULL);
    sf_set_must_be_not_null(in, INPUT_OF_NULL);
    sf_set_errno_if(Res == NULL, errno);
    return Res;
}

int X509_NAME_ENTRY_set_data(X509_NAME_ENTRY* ne, int type, const unsigned char* bytes, int len) {
    int Res = 0;
    sf_set_must_be_not_null(ne, NAME_ENTRY_OF_NULL);
    sf_set_must_be_not_null(bytes, BYTES_OF_NULL);
    sf_set_errno_if(Res <= 0, errno);
    return Res;
}

int ASN1_UTCTIME_print(BIO* a, const ASN1_UTCTIME* b)
{
    int res = 0;
    sf_set_must_be_not_null(a, "BIO");
    sf_set_must_be_not_null(b, "ASN1_UTCTIME");
    sf_set_errno_if(res == 0, "ASN1_UTCTIME_print");
    return res;
}

void OPENSSL_config(const char* a)
{
    sf_set_must_be_not_null(a, "OPENSSL_config");
    sf_terminate_path("OPENSSL_config");
}

const char* SSL_CIPHER_get_version(const SSL_CIPHER* a)
{
    const char* res = NULL;
    sf_set_must_be_not_null(a, "SSL_CIPHER_get_version");
    sf_set_possible_null(res);
    return res;
}

int i2d_PKCS7_SIGN_ENVELOPE(const PKCS7_SIGN_ENVELOPE* a, unsigned char** b)
{
    int res = 0;
    sf_set_must_be_not_null(a, "i2d_PKCS7_SIGN_ENVELOPE");
    sf_set_must_be_not_null(b, "i2d_PKCS7_SIGN_ENVELOPE");
    sf_set_errno_if(res == 0, "i2d_PKCS7_SIGN_ENVELOPE");
    return res;
}

void OPENSSL_LH_node_stats(const OPENSSL_LHASH* a, FILE* b)
{
    sf_set_must_be_not_null(a, "OPENSSL_LH_node_stats");
    sf_set_must_be_not_null(b, "OPENSSL_LH_node_stats");
}

X509_EXTENSION* X509_EXTENSION_new() {
    X509_EXTENSION* Res = NULL;
    Res = (X509_EXTENSION*)sf_malloc_arg(sizeof(X509_EXTENSION));
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    sf_set_alloc_possible_null(Res);
    return Res;
}

int EC_POINT_set_compressed_coordinates_GFp(const EC_GROUP* group, EC_POINT* point, const BIGNUM* x, int y_bit, BN_CTX* ctx) {
    int Res = 0;
    Res = EC_POINT_set_compressed_coordinates_GFp(group, point, x, y_bit, ctx);
    sf_set_errno_if(Res == 0);
    return Res;
}

const SSL_METHOD* SSL_CTX_get_ssl_method(const SSL_CTX* ctx) {
    const SSL_METHOD* Res = NULL;
    Res = SSL_CTX_get_ssl_method(ctx);
    sf_set_possible_null(Res);
    return Res;
}

DIST_POINT_NAME* d2i_DIST_POINT_NAME(DIST_POINT_NAME** dpn, const unsigned char** in, long len) {
    DIST_POINT_NAME* Res = NULL;
    Res = d2i_DIST_POINT_NAME(dpn, in, len);
    sf_set_alloc_possible_null(Res);
    return Res;
}

PKCS7* PKCS7_new() {
    PKCS7* Res = NULL;
    Res = PKCS7_new();
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    sf_set_alloc_possible_null(Res);
    return Res;
}

OCSP_REVOKEDINFO* d2i_OCSP_REVOKEDINFO(OCSP_REVOKEDINFO** a, const unsigned char** pp, long length)
{
    OCSP_REVOKEDINFO* Res = NULL;
    sf_set_trusted_sink_int(length);
    sf_malloc_arg(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res, length);
    sf_lib_arg_type(Res, "OCSP_REVOKEDINFO");
    // Implementation of the function
    return Res;
}

const EVP_CIPHER* EVP_camellia_128_cfb1()
{
    const EVP_CIPHER* Res = NULL;
    // Implementation of the function
    return Res;
}

void OCSP_CERTSTATUS_free(OCSP_CERTSTATUS* a)
{
    sf_set_must_be_not_null(a, FREE_OF_NULL);
    sf_delete(a, PAGES_MEMORY_CATEGORY);
    sf_lib_arg_type(a, "OCSP_CERTSTATUS");
    // Implementation of the function
}

int i2d_ASN1_ENUMERATED(const ASN1_ENUMERATED* a, unsigned char** pp)
{
    int Res = 0;
    sf_set_trusted_sink_ptr(pp);
    // Implementation of the function
    return Res;
}

uint32_t X509_get_key_usage(X509* a)
{
    uint32_t Res = 0;
    // Implementation of the function
    return Res;
}

int UI_add_info_string(UI* ui, const char* string) {
    int res = 0;
    sf_set_tainted(string);
    sf_null_terminated(string);
    sf_set_errno_if(res == -1);
    return res;
}

int PEM_write_ECPrivateKey(FILE* file, const EC_KEY* key, const EVP_CIPHER* cipher, const unsigned char* passwd, int len, pem_password_cb* cb, void* u) {
    int res = 0;
    sf_set_must_be_not_null(file);
    sf_set_must_be_not_null(key);
    sf_password_use(passwd);
    sf_set_errno_if(res == 0);
    return res;
}

const BIO_METHOD* BIO_s_datagram() {
    const BIO_METHOD* res = NULL;
    sf_set_errno_if(res == NULL);
    return res;
}

int SSL_CTX_set_srp_username(SSL_CTX* ctx, char* name) {
    int res = 0;
    sf_set_must_be_not_null(ctx);
    sf_set_tainted(name);
    sf_null_terminated(name);
    sf_set_errno_if(res == 0);
    return res;
}

void BN_free(BIGNUM* bn) {
    sf_set_must_be_not_null(bn);
    sf_delete(bn, BIGNUM_MEMORY_CATEGORY);
    sf_lib_arg_type(bn, "BIGNUM");
}

const ASN1_TIME* X509_get0_notAfter(const X509* x) {
    const ASN1_TIME* Res = NULL;
    Res = X509_get0_notAfter(x);
    sf_set_possible_null(Res);
    return Res;
}

int (BIO*, const char*)* BIO_meth_get_puts(const BIO_METHOD* b) {
    int (BIO*, const char*)* Res = NULL;
    Res = BIO_meth_get_puts(b);
    sf_set_possible_null(Res);
    return Res;
}

X509_NAME* d2i_X509_NAME(X509_NAME** a, const unsigned char** pp, long length) {
    X509_NAME* Res = NULL;
    Res = d2i_X509_NAME(a, pp, length);
    sf_set_possible_null(Res);
    return Res;
}

const char* OSSL_EC_curve_nid2name(int nid) {
    const char* Res = NULL;
    Res = OSSL_EC_curve_nid2name(nid);
    sf_set_possible_null(Res);
    return Res;
}

int (EVP_CIPHER_CTX*, int, int, void*)* EVP_CIPHER_meth_get_ctrl(const EVP_CIPHER* c) {
    int (EVP_CIPHER_CTX*, int, int, void*)* Res = NULL;
    Res = EVP_CIPHER_meth_get_ctrl(c);
    sf_set_possible_null(Res);
    return Res;
}

OCSP_RESPONSE* OCSP_sendreq_bio(BIO* bio, const char* host, OCSP_REQUEST* req) {
    OCSP_RESPONSE* Res = NULL;
    sf_set_trusted_sink_int(bio);
    sf_set_trusted_sink_int(host);
    sf_set_trusted_sink_int(req);
    Res = OCSP_sendreq_bio(bio, host, req);
    sf_overwrite(Res);
    return Res;
}

int CT_POLICY_EVAL_CTX_set1_issuer(CT_POLICY_EVAL_CTX* ctx, X509* issuer) {
    int Res = 0;
    sf_set_trusted_sink_int(ctx);
    sf_set_trusted_sink_int(issuer);
    Res = CT_POLICY_EVAL_CTX_set1_issuer(ctx, issuer);
    return Res;
}

PKCS7_RECIP_INFO* PKCS7_RECIP_INFO_new() {
    PKCS7_RECIP_INFO* Res = NULL;
    Res = PKCS7_RECIP_INFO_new();
    sf_overwrite(Res);
    return Res;
}

int EC_GROUP_get_cofactor(const EC_GROUP* group, BIGNUM* cofactor, BN_CTX* ctx) {
    int Res = 0;
    sf_set_trusted_sink_int(group);
    sf_set_trusted_sink_int(cofactor);
    sf_set_trusted_sink_int(ctx);
    Res = EC_GROUP_get_cofactor(group, cofactor, ctx);
    return Res;
}

int SSL_CTX_set_tlsext_ticket_key_evp_cb(SSL_CTX* ctx, int (*cb)(SSL*, unsigned char*, unsigned char*, EVP_CIPHER_CTX*, EVP_MAC_CTX*, int)) {
    int Res = 0;
    sf_set_trusted_sink_int(ctx);
    sf_set_trusted_sink_int(cb);
    Res = SSL_CTX_set_tlsext_ticket_key_evp_cb(ctx, cb);
    return Res;
}

void X509_STORE_set_get_crl(X509_STORE *store, X509_STORE_CTX_get_crl_fn get_crl) {
    sf_set_trusted_sink_int(store);
    sf_set_trusted_sink_ptr(get_crl);
    sf_set_tainted(store);
    sf_set_tainted(get_crl);
}

int PEM_do_header(EVP_CIPHER_INFO *ci, unsigned char *data, long *plen, pem_password_cb *cb, void *u) {
    sf_set_must_be_not_null(ci);
    sf_set_must_be_not_null(data);
    sf_set_must_be_not_null(plen);
    sf_set_must_be_not_null(cb);
    sf_set_tainted(ci);
    sf_set_tainted(data);
    sf_set_tainted(plen);
    sf_set_tainted(cb);
    sf_set_tainted(u);
}

int i2d_OCSP_CRLID(const OCSP_CRLID *crlid, unsigned char **pp) {
    sf_set_must_be_not_null(crlid);
    sf_set_must_be_not_null(pp);
    sf_set_tainted(crlid);
    sf_set_tainted(pp);
}

void SCT_set0_extensions(SCT *sct, unsigned char *exts, size_t exts_len) {
    sf_set_must_be_not_null(sct);
    sf_set_tainted(sct);
    sf_set_tainted(exts);
    sf_set_tainted(exts_len);
}

void X509_get0_uids(const X509 *x, const ASN1_BIT_STRING **uid, const ASN1_BIT_STRING **issuer_uid) {
    sf_set_must_be_not_null(x);
    sf_set_must_be_not_null(uid);
    sf_set_must_be_not_null(issuer_uid);
    sf_set_tainted(x);
    sf_set_tainted(uid);
    sf_set_tainted(issuer_uid);
}

void ASIdentifiers_free(ASIdentifiers* ids) {
    sf_set_must_be_not_null(ids, FREE_OF_NULL);
    sf_delete(ids, PAGES_MEMORY_CATEGORY);
}

PKEY_USAGE_PERIOD* d2i_PKEY_USAGE_PERIOD(PKEY_USAGE_PERIOD** a, const unsigned char** pp, long length) {
    sf_set_trusted_sink_int(length);
    PKEY_USAGE_PERIOD* res = NULL;
    sf_new(res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(res);
    return res;
}

X509_STORE_CTX_cert_crl_fn X509_STORE_CTX_get_cert_crl(const X509_STORE_CTX* ctx) {
    sf_set_must_be_not_null(ctx, FREE_OF_NULL);
    X509_STORE_CTX_cert_crl_fn res = NULL;
    sf_set_possible_null(res);
    return res;
}

const SSL_METHOD* TLSv1_1_server_method() {
    const SSL_METHOD* res = NULL;
    sf_set_possible_null(res);
    return res;
}

int ENGINE_set_RAND(ENGINE* e, const RAND_METHOD* rand) {
    sf_set_must_be_not_null(e, FREE_OF_NULL);
    sf_set_must_be_not_null(rand, FREE_OF_NULL);
    int res = 0;
    sf_set_errno_if(res, ENGINE_set_RAND, -1);
    return res;
}

void BN_BLINDING_set_current_thread(BN_BLINDING *blinding) {
    sf_set_trusted_sink_ptr(blinding);
    // Implementation
}

void EVP_PKEY_free(EVP_PKEY *pkey) {
    sf_set_must_be_not_null(pkey, FREE_OF_NULL);
    sf_delete(pkey, PKEY_CATEGORY);
    // Implementation
}

int X509_set_version(X509 *x, long version) {
    sf_set_must_not_be_negative(version);
    // Implementation
}

void RSA_OAEP_PARAMS_free(RSA_OAEP_PARAMS *params) {
    sf_set_must_be_not_null(params, FREE_OF_NULL);
    sf_delete(params, OAEP_PARAMS_CATEGORY);
    // Implementation
}

EVP_PKEY_CTX *EVP_PKEY_CTX_new_from_pkey(OSSL_LIB_CTX *libctx, EVP_PKEY *pkey, const char *propquery) {
    sf_set_must_be_not_null(pkey, NEW_FROM_PKEY_NULL);
    EVP_PKEY_CTX *ctx;
    sf_new(ctx, PKEY_CTX_CATEGORY);
    // Implementation
    return ctx;
}
int EVP_PKEY_get_security_bits(const EVP_PKEY* pkey);

int i2d_GENERAL_NAME(const GENERAL_NAME* a, unsigned char** pp);

int EVP_PKEY_set_type_by_keymgmt(EVP_PKEY* pkey, EVP_KEYMGMT* keymgmt);

int X509_CRL_add1_ext_i2d(X509_CRL* crl, int nid, void* value, int crit, unsigned long flags);

int RAND_status();


stack_st_X509_EXTENSION* X509_REQ_get_extensions(X509_REQ* req) {
    stack_st_X509_EXTENSION* Res = NULL;
    sf_set_must_be_not_null(req, "X509_REQ");
    sf_set_errno_if(Res == NULL, ENOMEM);
    sf_set_alloc_possible_null(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    return Res;
}

void SSL_CTX_set_psk_client_callback(SSL_CTX* ctx, SSL_psk_client_cb_func cb) {
    sf_set_must_be_not_null(ctx, "SSL_CTX");
    sf_set_tainted(cb);
    ctx->psk_client_callback = cb;
}

int BIO_meth_set_create(BIO_METHOD* biom, int (BIO* *create)()) {
    int Res = 0;
    sf_set_must_be_not_null(biom, "BIO_METHOD");
    sf_set_must_be_not_null(create, "create");
    sf_set_errno_if(Res == 0, ENOMEM);
    biom->create = create;
    return Res;
}

void BN_BLINDING_free(BN_BLINDING* b) {
    sf_set_must_be_not_null(b, "BN_BLINDING");
    sf_delete(b, PAGES_MEMORY_CATEGORY);
    sf_lib_arg_type(b, "BN_BLINDING");
}

int i2d_ASN1_IA5STRING(const ASN1_IA5STRING* a, unsigned char** pp) {
    int Res = 0;
    sf_set_must_be_not_null(a, "ASN1_IA5STRING");
    sf_set_must_be_not_null(pp, "pp");
    sf_set_errno_if(Res == 0, ENOMEM);
    sf_buf_size_limit(pp, a->length);
    return Res;
}

PKCS7_ENCRYPT* PKCS7_ENCRYPT_new() {
    PKCS7_ENCRYPT* Res = NULL;
    Res = (PKCS7_ENCRYPT*)sf_malloc_arg(sizeof(PKCS7_ENCRYPT));
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_lib_arg_type(Res, "PKCS7_ENCRYPT");
    sf_overwrite(Res);
    return Res;
}

int BN_sqr(BIGNUM* a, const BIGNUM* b, BN_CTX* c) {
    int Res = 0;
    sf_set_trusted_sink_int(a);
    sf_set_trusted_sink_int(b);
    sf_set_trusted_sink_int(c);
    Res = BN_sqr(a, b, c);
    sf_overwrite(Res);
    return Res;
}

EC_KEY* EC_KEY_copy(EC_KEY* a, const EC_KEY* b) {
    EC_KEY* Res = NULL;
    sf_set_trusted_sink_ptr(a);
    sf_set_trusted_sink_ptr(b);
    Res = EC_KEY_copy(a, b);
    sf_lib_arg_type(Res, "EC_KEY");
    sf_overwrite(Res);
    return Res;
}

void X509_CRL_free(X509_CRL* a) {
    sf_set_trusted_sink_ptr(a);
    sf_delete(a, PAGES_MEMORY_CATEGORY);
    sf_lib_arg_type(a, "X509_CRL");
    X509_CRL_free(a);
}

X509_EXTENSION* d2i_X509_EXTENSION(X509_EXTENSION** a, const unsigned char** b, long c) {
    X509_EXTENSION* Res = NULL;
    sf_set_trusted_sink_ptr(a);
    sf_set_trusted_sink_ptr(b);
    Res = d2i_X509_EXTENSION(a, b, c);
    sf_lib_arg_type(Res, "X509_EXTENSION");
    sf_overwrite(Res);
    return Res;
}
int DSA_set0_pqg(DSA* dsa, BIGNUM* p, BIGNUM* q, BIGNUM* g);

const SSL_METHOD* DTLSv1_client_method();

void X509_SIG_getm(X509_SIG* sig, X509_ALGOR** algor, ASN1_OCTET_STRING** digest);

int i2d_ASN1_BMPSTRING(const ASN1_BMPSTRING* bmp, unsigned char** pp);

stack_st_X509* X509_STORE_CTX_get0_chain(const X509_STORE_CTX* ctx);

int i2d_DSAparams(const DSA* a, unsigned char** pp);

int OCSP_RESPID_set_by_name(OCSP_RESPID* res, X509* x);

const BIO_METHOD* BIO_f_md();

const EVP_CIPHER* EVP_cast5_ecb();

int ASN1_TIME_to_tm(const ASN1_TIME* s, tm* tm);


const OSSL_PARAM* EVP_MAC_CTX_gettable_params(EVP_MAC_CTX* ctx) {
    const OSSL_PARAM* Res = NULL;
    sf_set_must_be_not_null(ctx, GETTABLE_PARAMS_OF_NULL);
    Res = EVP_MAC_CTX_gettable_params(ctx);
    sf_set_possible_null(Res, GETTABLE_PARAMS_POSSIBLE_NULL);
    return Res;
}

BIO* BIO_get_retry_BIO(BIO* bio, int* reason) {
    BIO* Res = NULL;
    sf_set_must_be_not_null(bio, GET_RETRY_BIO_OF_NULL);
    sf_set_must_be_not_null(reason, GET_RETRY_BIO_REASON_OF_NULL);
    Res = BIO_get_retry_BIO(bio, reason);
    sf_set_possible_null(Res, GET_RETRY_BIO_POSSIBLE_NULL);
    return Res;
}

PKCS7* PKCS7_sign(X509* signcert, EVP_PKEY* pkey, stack_st_X509* certs, BIO* data, int flags) {
    PKCS7* Res = NULL;
    sf_set_must_be_not_null(signcert, PKCS7_SIGN_SIGNCERT_OF_NULL);
    sf_set_must_be_not_null(pkey, PKCS7_SIGN_PKEY_OF_NULL);
    sf_set_must_be_not_null(certs, PKCS7_SIGN_CERTS_OF_NULL);
    sf_set_must_be_not_null(data, PKCS7_SIGN_DATA_OF_NULL);
    Res = PKCS7_sign(signcert, pkey, certs, data, flags);
    sf_set_possible_null(Res, PKCS7_SIGN_POSSIBLE_NULL);
    return Res;
}

int PEM_write_PKCS8PrivateKey(FILE* fp, const EVP_PKEY* x, const EVP_CIPHER* enc, const char* kstr, int klen, pem_password_cb* cb, void* u) {
    int Res = 0;
    sf_set_must_be_not_null(fp, PEM_WRITE_PKCS8PRIVATEKEY_FP_OF_NULL);
    sf_set_must_be_not_null(x, PEM_WRITE_PKCS8PRIVATEKEY_X_OF_NULL);
    sf_set_must_be_not_null(enc, PEM_WRITE_PKCS8PRIVATEKEY_ENC_OF_NULL);
    sf_set_must_be_not_null(kstr, PEM_WRITE_PKCS8PRIVATEKEY_KSTR_OF_NULL);
    sf_set_must_be_not_null(cb, PEM_WRITE_PKCS8PRIVATEKEY_CB_OF_NULL);
    Res = PEM_write_PKCS8PrivateKey(fp, x, enc, kstr, klen, cb, u);
    sf_set_errno_if(Res <= 0, PEM_WRITE_PKCS8PRIVATEKEY_ERROR);
    return Res;
}

const EVP_CIPHER* EVP_aes_128_cfb128() {
    const EVP_CIPHER* Res = NULL;
    Res = EVP_aes_128_cfb128();
    sf_set_must_be_not_null(Res, EVP_AES_128_CFB128_NULL);
    return Res;
}

EVP_PKEY* X509_PUBKEY_get0(const X509_PUBKEY* pkey) {
    EVP_PKEY* Res = NULL;
    sf_set_trusted_sink_int(pkey);
    sf_set_possible_null(Res);
    Res = ... // Call the actual implementation of X509_PUBKEY_get0
    sf_set_alloc_possible_null(Res);
    return Res;
}

OSSL_PROVIDER* EVP_KEM_get0_provider(const EVP_KEM* kem) {
    OSSL_PROVIDER* Res = NULL;
    sf_set_trusted_sink_int(kem);
    sf_set_possible_null(Res);
    Res = ... // Call the actual implementation of EVP_KEM_get0_provider
    sf_set_alloc_possible_null(Res);
    return Res;
}

void ASRange_free(ASRange* range) {
    sf_set_must_be_not_null(range, FREE_OF_NULL);
    sf_delete(range, MALLOC_CATEGORY);
    sf_lib_arg_type(range, "MallocCategory");
}

int PEM_write_bio_PKCS8PrivateKey_nid(BIO* bio, const EVP_PKEY* pkey, int nid, const char* pass, int passlen, pem_password_cb* cb, void* u) {
    int Res = 0;
    sf_set_trusted_sink_int(bio);
    sf_set_trusted_sink_int(pkey);
    sf_set_trusted_sink_int(nid);
    sf_password_use(pass);
    sf_set_errno_if(Res <= 0);
    Res = ... // Call the actual implementation of PEM_write_bio_PKCS8PrivateKey_nid
    return Res;
}

int i2d_OTHERNAME(const OTHERNAME* other, unsigned char** out) {
    int Res = 0;
    sf_set_trusted_sink_int(other);
    sf_set_trusted_sink_int(out);
    sf_set_errno_if(Res <= 0);
    Res = ... // Call the actual implementation of i2d_OTHERNAME
    return Res;
}

int ENGINE_set_name(ENGINE* e, const char* name) {
    int res = 0;
    sf_set_tainted(name);
    sf_password_use(name);
    sf_set_must_be_not_null(e, ENGINE_NULL);
    sf_set_must_be_not_null(name, NAME_NULL);
    sf_set_errno_if(res == 0, ERRNO_ENGINE_SET_NAME);
    return res;
}

int EVP_DecodeUpdate(EVP_ENCODE_CTX* ctx, unsigned char* out, int* outl, const unsigned char* in, int inl) {
    int res = 0;
    sf_set_must_be_not_null(ctx, EVP_ENCODE_CTX_NULL);
    sf_set_must_be_not_null(out, OUT_NULL);
    sf_set_must_be_not_null(outl, OUTL_NULL);
    sf_set_must_be_not_null(in, IN_NULL);
    sf_buf_size_limit(out, *outl);
    sf_buf_size_limit_read(in, inl);
    sf_set_errno_if(res <= 0, ERRNO_EVP_DECODE_UPDATE);
    return res;
}

int EVP_PKEY_set_int_param(EVP_PKEY* pkey, const char* key, int value) {
    int res = 0;
    sf_set_must_be_not_null(pkey, EVP_PKEY_NULL);
    sf_set_must_be_not_null(key, KEY_NULL);
    sf_set_errno_if(res == 0, ERRNO_EVP_PKEY_SET_INT_PARAM);
    return res;
}

int X509_CRL_set_version(X509_CRL* x, long version) {
    int res = 0;
    sf_set_must_be_not_null(x, X509_CRL_NULL);
    sf_set_errno_if(res == 0, ERRNO_X509_CRL_SET_VERSION);
    return res;
}

const char* EVP_MD_get0_name(const EVP_MD* md) {
    const char* res = NULL;
    sf_set_must_be_not_null(md, EVP_MD_NULL);
    sf_set_possible_null(res);
    return res;
}

const OSSL_PARAM* EVP_SIGNATURE_settable_ctx_params(const EVP_SIGNATURE* sig) {
    const OSSL_PARAM* Res = NULL;
    // Specification code here
    return Res;
}

RSA* PEM_read_bio_RSA_PUBKEY(BIO* bio, RSA** rsa, pem_password_cb* cb, void* u) {
    RSA* Res = NULL;
    // Specification code here
    return Res;
}

void ADMISSION_SYNTAX_set0_contentsOfAdmissions(ADMISSION_SYNTAX* a, stack_st_ADMISSIONS* adms) {
    // Specification code here
}

int X509_REVOKED_set_serialNumber(X509_REVOKED* r, ASN1_INTEGER* serial) {
    int Res = 0;
    // Specification code here
    return Res;
}

int ASN1_ENUMERATED_set(ASN1_ENUMERATED* a, long value) {
    int Res = 0;
    // Specification code here
    return Res;
}

int EC_GROUP_get_field_type(const EC_GROUP* group)
{
    int Res = 0;
    sf_set_must_not_be_null(group);
    Res = group->field_type;
    sf_set_possible_negative(Res);
    return Res;
}

int CRYPTO_secure_malloc_initialized()
{
    int Res = 0;
    Res = secure_malloc_initialized;
    sf_set_possible_negative(Res);
    return Res;
}

void EVP_PKEY_meth_set_digestverify(EVP_PKEY_METHOD* pmeth, int (*digestverify) (EVP_MD_CTX* ctx, const unsigned char* sig, size_t siglen, const unsigned char* tbs, size_t tbslen))
{
    sf_set_must_not_be_null(pmeth);
    sf_set_must_not_be_null(digestverify);
    pmeth->digestverify = digestverify;
}

int OSSL_PARAM_set_time_t(OSSL_PARAM* param, time_t t)
{
    int Res = 0;
    sf_set_must_not_be_null(param);
    param->data = &t;
    param->data_size = sizeof(t);
    Res = 1;
    sf_set_possible_negative(Res);
    return Res;
}

const stack_st_X509_EXTENSION* X509_REVOKED_get0_extensions(const X509_REVOKED* rev)
{
    const stack_st_X509_EXTENSION* Res = NULL;
    sf_set_must_not_be_null(rev);
    Res = rev->extensions;
    return Res;
}
int OSSL_PARAM_get_octet_string_ptr(const OSSL_PARAM*, const void**, size_t*);

int SSL_CTX_use_certificate_file(SSL_CTX*, const char*, int);

const char* OSSL_default_cipher_list();

EVP_PKEY* EVP_PKCS82PKEY_ex(const PKCS8_PRIV_KEY_INFO*, OSSL_LIB_CTX*, const char*);

int SSL_peek(SSL*, void*, int);


const EVP_CIPHER* EVP_des_ede() {
    const EVP_CIPHER* Res = NULL;
    Res = EVP_des_ede();
    sf_set_possible_null(Res);
    return Res;
}

int ECDSA_SIG_set0(ECDSA_SIG* sig, BIGNUM* r, BIGNUM* s) {
    int Res = 0;
    Res = ECDSA_SIG_set0(sig, r, s);
    sf_set_errno_if(Res == 0);
    return Res;
}

const OSSL_PARAM* EVP_PKEY_CTX_gettable_params(const EVP_PKEY_CTX* ctx) {
    const OSSL_PARAM* Res = NULL;
    Res = EVP_PKEY_CTX_gettable_params(ctx);
    sf_set_possible_null(Res);
    return Res;
}

int SSL_SESSION_set_ex_data(SSL_SESSION* s, int idx, void* arg) {
    int Res = 0;
    Res = SSL_SESSION_set_ex_data(s, idx, arg);
    sf_set_errno_if(Res == 0);
    return Res;
}

CRYPTO_RWLOCK* CRYPTO_THREAD_lock_new() {
    CRYPTO_RWLOCK* Res = NULL;
    Res = CRYPTO_THREAD_lock_new();
    sf_set_possible_null(Res);
    return Res;
}

int X509_STORE_set_purpose(X509_STORE *store, int purpose) {
    int res = 0;
    sf_set_must_be_not_null(store, SET_PURPOSE_OF_NULL);
    sf_set_errno_if(res == 0, SET_PURPOSE_FAILURE);
    return res;
}

TLS_FEATURE* TLS_FEATURE_new() {
    TLS_FEATURE *res = NULL;
    res = sf_malloc_arg(sizeof(TLS_FEATURE), TLS_FEATURE_NEW);
    sf_new(res, TLS_FEATURE_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(res);
    return res;
}

void IPAddressChoice_free(IPAddressChoice *ip) {
    sf_set_must_be_not_null(ip, FREE_OF_NULL);
    sf_delete(ip, IP_ADDRESS_CHOICE_MEMORY_CATEGORY);
    sf_lib_arg_type(ip, "IPAddressChoice");
}

void EVP_MAC_CTX_free(EVP_MAC_CTX *ctx) {
    sf_set_must_be_not_null(ctx, FREE_OF_NULL);
    sf_delete(ctx, EVP_MAC_CTX_MEMORY_CATEGORY);
    sf_lib_arg_type(ctx, "EVP_MAC_CTX");
}

GENERAL_NAME* d2i_GENERAL_NAME(GENERAL_NAME **a, const unsigned char **in, long len) {
    GENERAL_NAME *res = NULL;
    sf_set_must_be_not_null(a, D2I_GENERAL_NAME_NULL);
    sf_set_must_be_not_null(*a, D2I_GENERAL_NAME_NULL);
    sf_set_must_be_not_null(in, D2I_GENERAL_NAME_NULL);
    sf_set_buf_size_limit(in, len);
    res = *a;
    sf_set_alloc_possible_null(res);
    return res;
}

int SSL_use_certificate(SSL *ssl, X509 *x) {
    int ret = 0;
    sf_set_tainted(x);
    sf_set_password_use(x);
    sf_set_must_not_be_null(ssl);
    sf_set_must_not_be_null(x);
    ret = ssl_use_certificate(ssl, x);
    sf_set_errno_if(ret <= 0);
    return ret;
}

void POLICY_CONSTRAINTS_free(POLICY_CONSTRAINTS *p) {
    sf_set_must_not_be_null(p);
    policy_constraints_free(p);
}

void *OPENSSL_sk_set(OPENSSL_STACK *st, int i, const void *data) {
    void *ret = NULL;
    sf_set_must_not_be_null(st);
    sf_set_must_not_be_null(data);
    ret = OPENSSL_sk_set(st, i, data);
    sf_set_errno_if(ret == NULL);
    return ret;
}

int UI_dup_input_boolean(UI *ui, const char *prompt, const char *action, const char *ok, const char *cancel, int def, char *result) {
    int ret = 0;
    sf_set_must_not_be_null(ui);
    sf_set_must_not_be_null(prompt);
    sf_set_must_not_be_null(action);
    sf_set_must_not_be_null(ok);
    sf_set_must_not_be_null(cancel);
    sf_set_must_not_be_null(result);
    ret = UI_dup_input_boolean(ui, prompt, action, ok, cancel, def, result);
    sf_set_errno_if(ret <= 0);
    return ret;
}

BIGNUM *BN_mod_inverse(BIGNUM *ret, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx) {
    BIGNUM *res = NULL;
    sf_set_must_not_be_null(a);
    sf_set_must_not_be_null(b);
    sf_set_must_not_be_null(ctx);
    res = BN_mod_inverse(ret, a, b, ctx);
    sf_set_errno_if(res == NULL);
    return res;
}

const EVP_MD* EVP_MD_CTX_md(const EVP_MD_CTX* ctx) {
    const EVP_MD* Res = NULL;
    Res = ctx->digest;
    sf_set_possible_null(Res);
    return Res;
}

long BIO_debug_callback(BIO* bio, int cmd, const char* argp, int argi, long argl, long ret) {
    long Res = 0;
    // Add necessary code here
    return Res;
}

int i2d_X509_fp(FILE* fp, const X509* x) {
    int Res = 0;
    // Add necessary code here
    return Res;
}

RSA_OAEP_PARAMS* d2i_RSA_OAEP_PARAMS(RSA_OAEP_PARAMS** oaep, const unsigned char** in, long len) {
    RSA_OAEP_PARAMS* Res = NULL;
    // Add necessary code here
    return Res;
}

OPENSSL_LHASH* OPENSSL_LH_new(OPENSSL_LH_HASHFUNC h, OPENSSL_LH_COMPFUNC c) {
    OPENSSL_LHASH* Res = NULL;
    // Add necessary code here
    return Res;
}

const char* EVP_SIGNATURE_get0_name(const EVP_SIGNATURE* sig) {
    const char* Res = NULL;
    Res = ossl_prov_get_name(sig->prov);
    sf_set_trusted_sink_ptr(Res);
    return Res;
}

int i2d_PKCS8_PRIV_KEY_INFO_fp(FILE* fp, const PKCS8_PRIV_KEY_INFO* p8inf) {
    int Res = 0;
    size_t size = i2d_PKCS8_PRIV_KEY_INFO(p8inf, NULL);
    unsigned char* data = OPENSSL_malloc(size);
    sf_malloc_arg(data, size);
    Res = i2d_PKCS8_PRIV_KEY_INFO(p8inf, &data);
    sf_set_buf_size(data, size);
    sf_buf_size_limit_read(data, size);
    fwrite(data, 1, size, fp);
    OPENSSL_free(data);
    return Res;
}

int EVP_PKEY_CTX_get_dh_kdf_type(EVP_PKEY_CTX* ctx) {
    int Res = 0;
    Res = EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, -1, EVP_PKEY_CTRL_GET_KDF_TYPE, 0, NULL);
    sf_set_errno_if(Res <= 0);
    return Res;
}

void ASYNC_cleanup_thread() {
    ASYNC_WAIT_CTX* waitctx = ASYNC_get_wait_ctx();
    ASYNC_unregister_wait_ctx(waitctx);
    ASYNC_free_wait_ctx(waitctx);
}

char* BIO_ADDR_service_string(const BIO_ADDR* addr, int numeric) {
    char* Res = NULL;
    size_t size = BIO_ADDR_service_string_len(addr, numeric);
    Res = OPENSSL_malloc(size);
    sf_malloc_arg(Res, size);
    BIO_ADDR_service_string(addr, numeric, Res, size);
    sf_set_buf_size(Res, size);
    sf_buf_stop_at_null(Res);
    return Res;
}
int EVP_PKEY_CTX_set_kem_op(EVP_PKEY_CTX* ctx, const char* str);

int SSL_set_block_padding(SSL* ssl, size_t padding);

void ENGINE_register_all_RSA();

const OSSL_PARAM* EVP_MD_gettable_params(const EVP_MD* md);

void OPENSSL_LH_stats_bio(const OPENSSL_LHASH* lh, BIO* bio);


const EVP_CIPHER* EVP_aria_128_cfb1() {
    const EVP_CIPHER* Res = NULL;
    Res = EVP_aria_128_cfb1();
    sf_set_possible_null(Res);
    return Res;
}

int CT_POLICY_EVAL_CTX_set1_cert(CT_POLICY_EVAL_CTX* ctx, X509* x) {
    int Res = 0;
    Res = CT_POLICY_EVAL_CTX_set1_cert(ctx, x);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int X509_CRL_get_signature_nid(const X509_CRL* crl) {
    int Res = 0;
    Res = X509_CRL_get_signature_nid(crl);
    sf_set_errno_if(Res == NID_undef);
    return Res;
}

EVP_PKEY* ENGINE_load_public_key(ENGINE* e, const char* key_id, UI_METHOD* ui_method, void* callback_data) {
    EVP_PKEY* Res = NULL;
    Res = ENGINE_load_public_key(e, key_id, ui_method, callback_data);
    sf_set_possible_null(Res);
    return Res;
}

PKCS7_ISSUER_AND_SERIAL* PKCS7_ISSUER_AND_SERIAL_new() {
    PKCS7_ISSUER_AND_SERIAL* Res = NULL;
    Res = PKCS7_ISSUER_AND_SERIAL_new();
    sf_set_possible_null(Res);
    return Res;
}

const DH_METHOD* ENGINE_get_DH(const ENGINE* engine) {
    const DH_METHOD* Res = NULL;
    sf_set_trusted_sink_ptr(engine);
    sf_set_possible_null(Res);
    Res = ENGINE_get_DH(engine);
    sf_set_alloc_possible_null(Res);
    return Res;
}

OSSL_PROVIDER* EVP_KEYEXCH_get0_provider(const EVP_KEYEXCH* keyexch) {
    OSSL_PROVIDER* Res = NULL;
    sf_set_trusted_sink_ptr(keyexch);
    sf_set_possible_null(Res);
    Res = EVP_KEYEXCH_get0_provider(keyexch);
    sf_set_alloc_possible_null(Res);
    return Res;
}

int EVP_EncodeBlock(unsigned char* out, const unsigned char* in, int inl) {
    int Res = 0;
    sf_set_trusted_sink_ptr(out);
    sf_set_trusted_sink_ptr(in);
    sf_buf_size_limit(in, inl);
    Res = EVP_EncodeBlock(out, in, inl);
    sf_set_errno_if(Res <= 0);
    return Res;
}

BIO* BIO_new_mem_buf(const void* buf, int len) {
    BIO* Res = NULL;
    sf_set_trusted_sink_ptr(buf);
    sf_buf_size_limit(buf, len);
    Res = BIO_new_mem_buf(buf, len);
    sf_set_alloc_possible_null(Res);
    return Res;
}

void DSA_get0_pqg(const DSA* d, const BIGNUM** p, const BIGNUM** q, const BIGNUM** g) {
    sf_set_trusted_sink_ptr(d);
    DSA_get0_pqg(d, p, q, g);
}

OCSP_SIGNATURE* d2i_OCSP_SIGNATURE(OCSP_SIGNATURE** a, const unsigned char** pp, long length) {
    OCSP_SIGNATURE* Res = NULL;
    sf_set_trusted_sink_int(length);
    Res = (OCSP_SIGNATURE*)sf_malloc_arg(length);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_lib_arg_type(Res, "MallocCategory");
    // Copy the contents of **pp to Res
    sf_bitcopy(Res, *pp, length);
    return Res;
}

int SSL_CTX_load_verify_locations(SSL_CTX* ctx, const char* CAfile, const char* CApath) {
    int Res = 0;
    sf_tocttou_check(CAfile);
    sf_tocttou_check(CApath);
    // Implementation of the function
    return Res;
}

DSA_METHOD* DSA_meth_dup(const DSA_METHOD* dsa) {
    DSA_METHOD* Res = NULL;
    // Implementation of the function
    return Res;
}

int ERR_load_strings(int lib, ERR_STRING_DATA* str) {
    int Res = 0;
    sf_set_tainted(str);
    // Implementation of the function
    return Res;
}

int i2d_OCSP_REQINFO(const OCSP_REQINFO* a, unsigned char** pp) {
    int Res = 0;
    // Implementation of the function
    return Res;
}

void GENERAL_SUBTREE_free(GENERAL_SUBTREE* gst) {
    if (gst != NULL) {
        sf_delete(gst, GENERAL_SUBTREE_MEMORY_CATEGORY);
    }
}

int SSL_get_read_ahead(const SSL* ssl) {
    int res = 0;
    sf_set_must_be_not_null(ssl, SSL_READ_AHEAD_OF_NULL);
    res = ssl->read_ahead;
    sf_overwrite(res);
    return res;
}

EVP_PKEY* X509_REQ_get0_pubkey(X509_REQ* req) {
    EVP_PKEY* res = NULL;
    sf_set_must_be_not_null(req, X509_REQ_PUBKEY_OF_NULL);
    res = req->pubkey;
    sf_set_possible_null(res);
    return res;
}

int SSL_CTX_use_psk_identity_hint(SSL_CTX* ctx, const char* hint) {
    int res = 0;
    sf_set_must_be_not_null(ctx, SSL_CTX_USE_PSK_IDENTITY_HINT_OF_NULL);
    sf_password_use(hint);
    res = ctx->use_psk_identity_hint(ctx, hint);
    sf_set_errno_if(res <= 0);
    return res;
}

const EVP_CIPHER* EVP_des_ede3_cbc() {
    const EVP_CIPHER* res = NULL;
    res = EVP_des_ede3_cbc();
    sf_set_possible_null(res);
    return res;
}

const EVP_CIPHER* EVP_desx_cbc() {
    const EVP_CIPHER* Res = NULL;
    Res = EVP_get_cipherbyname("desx_cbc");
    sf_set_possible_null(Res);
    return Res;
}

X509_STORE_CTX_check_issued_fn X509_STORE_CTX_get_check_issued(const X509_STORE_CTX* ctx) {
    X509_STORE_CTX_check_issued_fn Res = NULL;
    Res = X509_STORE_CTX_get_check_issued(ctx);
    sf_set_possible_null(Res);
    return Res;
}

int ENGINE_set_DSA(ENGINE* e, const DSA_METHOD* dsa) {
    int Res = 0;
    Res = ENGINE_set_DSA(e, dsa);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int BIO_puts(BIO* bp, const char* buf) {
    int Res = 0;
    sf_password_use(buf);
    Res = BIO_puts(bp, buf);
    sf_set_errno_if(Res <= 0);
    return Res;
}

void ASIdOrRange_free(ASIdOrRange* ar) {
    sf_delete(ar, PAGES_MEMORY_CATEGORY);
    ar = NULL;
}

const EVP_PKEY_ASN1_METHOD* EVP_PKEY_get0_asn1(const EVP_PKEY* pkey) {
    const EVP_PKEY_ASN1_METHOD* Res = NULL;
    sf_set_must_be_not_null(pkey, PKEY_NULL);
    Res = EVP_PKEY_get0_asn1(pkey);
    sf_set_possible_null(Res, PKEY_ASN1_METHOD_NULL);
    return Res;
}

int X509V3_set_issuer_pkey(X509V3_CTX* ctx, EVP_PKEY* pkey) {
    int Res = 0;
    sf_set_must_be_not_null(ctx, CTX_NULL);
    sf_set_must_be_not_null(pkey, PKEY_NULL);
    Res = X509V3_set_issuer_pkey(ctx, pkey);
    sf_set_errno_if(Res <= 0, SET_ISSUER_PKEY_FAIL);
    return Res;
}

int SHA512_Update(SHA512_CTX* ctx, const void* data, size_t len) {
    int Res = 0;
    sf_set_must_be_not_null(ctx, CTX_NULL);
    sf_set_must_be_not_null(data, DATA_NULL);
    sf_buf_size_limit(data, len, SHA512_UPDATE_OVERFLOW);
    Res = SHA512_Update(ctx, data, len);
    sf_set_errno_if(Res <= 0, SHA512_UPDATE_FAIL);
    return Res;
}

const char* EVP_KEM_get0_description(const EVP_KEM* kem) {
    const char* Res = NULL;
    sf_set_must_be_not_null(kem, KEM_NULL);
    Res = EVP_KEM_get0_description(kem);
    sf_set_possible_null(Res, DESCRIPTION_NULL);
    return Res;
}

void EVP_CIPHER_meth_free(EVP_CIPHER* cipher) {
    sf_set_must_be_not_null(cipher, CIPHER_NULL);
    EVP_CIPHER_meth_free(cipher);
}

sf_set_trusted_sink_ptr(kem);
const char* EVP_KEM_get0_name(const EVP_KEM* kem) {
    const char* Res = NULL;
    sf_set_possible_null(Res);
    sf_set_tainted(Res);
    sf_null_terminated(Res);
    return Res;
}

sf_set_trusted_sink_ptr(a);
OCSP_BASICRESP* d2i_OCSP_BASICRESP(OCSP_BASICRESP** a, const unsigned char** in, long len) {
    OCSP_BASICRESP* Res = NULL;
    sf_set_possible_null(Res);
    sf_set_alloc_possible_null(Res, len);
    sf_set_buf_size(in, len);
    return Res;
}

void ACCESS_DESCRIPTION_free(ACCESS_DESCRIPTION* ad) {
    sf_set_must_be_not_null(ad, FREE_OF_NULL);
    sf_delete(ad, MALLOC_CATEGORY);
    sf_lib_arg_type(ad, "MallocCategory");
}

BIGNUM* BN_get_rfc3526_prime_8192(BIGNUM* bn) {
    BIGNUM* Res = NULL;
    sf_set_possible_null(Res);
    sf_set_alloc_possible_null(Res, 8192);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    return Res;
}

sf_set_trusted_sink_ptr(lh);
void* OPENSSL_LH_retrieve(OPENSSL_LHASH* lh, const void* data) {
    void* Res = NULL;
    sf_set_possible_null(Res);
    return Res;
}

void PKEY_USAGE_PERIOD_free(PKEY_USAGE_PERIOD* period)
{
    if (period != NULL)
    {
        sf_delete(period, PAGES_MEMORY_CATEGORY);
    }
}

ASN1_OCTET_STRING* X509_digest_sig(const X509* x, EVP_MD** md, int* is_digest)
{
    ASN1_OCTET_STRING* res = NULL;
    sf_set_trusted_sink_ptr(res);
    sf_set_alloc_possible_null(res);
    sf_lib_arg_type(res, "ASN1_OCTET_STRING");
    return res;
}

X509* PEM_read_X509(FILE* fp, X509** x, pem_password_cb* cb, void* u)
{
    X509* res = NULL;
    sf_set_trusted_sink_ptr(res);
    sf_set_alloc_possible_null(res);
    sf_lib_arg_type(res, "X509");
    return res;
}

int EVP_PKEY_CTX_set_dh_paramgen_gindex(EVP_PKEY_CTX* ctx, int gindex)
{
    int res = 0;
    sf_set_errno_if(res <= 0);
    return res;
}

const char* SSL_get_servername(const SSL* s, const int type)
{
    const char* res = NULL;
    sf_set_possible_null(res);
    return res;
}
const BIGNUM* EC_GROUP_get0_cofactor(const EC_GROUP* group);

const RSA_PSS_PARAMS* RSA_get0_pss_params(const RSA* rsa);

void OPENSSL_thread_stop_ex(OSSL_LIB_CTX* ctx);

NETSCAPE_SPKI* d2i_NETSCAPE_SPKI(NETSCAPE_SPKI** spkip, const unsigned char** pp, long length);

int SHA256_Update(SHA256_CTX* ctx, const void* data, size_t len);


int EVP_CIPHER_meth_get_set_asn1_params(const EVP_CIPHER* cipher, ASN1_TYPE* type) {
    int res = 0;
    sf_set_tainted(type);
    sf_set_trusted_sink_ptr(cipher);
    sf_set_trusted_sink_ptr(type);
    return res;
}

int BN_BLINDING_is_current_thread(BN_BLINDING* b) {
    int res = 0;
    sf_set_trusted_sink_ptr(b);
    return res;
}

int EC_GROUP_order_bits(const EC_GROUP* group) {
    int res = 0;
    sf_set_trusted_sink_ptr(group);
    return res;
}

unsigned short BIO_ADDR_rawport(const BIO_ADDR* addr) {
    unsigned short res = 0;
    sf_set_trusted_sink_ptr(addr);
    return res;
}

void BIO_ADDR_clear(BIO_ADDR* addr) {
    sf_set_trusted_sink_ptr(addr);
    // No return statement needed
}

int EVP_PKEY_CTX_set_rsa_keygen_bits(EVP_PKEY_CTX* ctx, int bits) {
    int Res = 0;
    sf_set_trusted_sink_int(bits);
    sf_set_tainted(ctx);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int EVP_MD_CTX_update_fn(EVP_MD_CTX* ctx, const void* data, size_t size) {
    int Res = 0;
    sf_set_trusted_sink_int(size);
    sf_set_tainted(ctx);
    sf_set_errno_if(Res <= 0);
    return Res;
}

BIO* BIO_new_fp(FILE* stream, int close_flag) {
    BIO* Res = NULL;
    sf_set_tainted(stream);
    sf_set_errno_if(Res == NULL);
    return Res;
}

int EVP_PKEY_verify_init(EVP_PKEY_CTX* ctx) {
    int Res = 0;
    sf_set_tainted(ctx);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int SSL_CTX_set_ciphersuites(SSL_CTX* ctx, const char* str) {
    int Res = 0;
    sf_set_tainted(ctx);
    sf_set_errno_if(Res <= 0);
    return Res;
}

const stack_st_SCT* SSL_get0_peer_scts(SSL* s) {
    const stack_st_SCT* Res = NULL;
    Res = SSL_get0_peer_scts(s);
    sf_set_possible_null(Res);
    return Res;
}

int EVP_PKEY_CTX_get_params(EVP_PKEY_CTX* ctx, OSSL_PARAM* params) {
    int Res = 0;
    Res = EVP_PKEY_CTX_get_params(ctx, params);
    sf_set_errno_if(Res <= 0);
    return Res;
}

IPAddressOrRange* d2i_IPAddressOrRange(IPAddressOrRange** out, const unsigned char** in, long len) {
    IPAddressOrRange* Res = NULL;
    Res = d2i_IPAddressOrRange(out, in, len);
    sf_set_alloc_possible_null(Res);
    return Res;
}

int i2d_X509_EXTENSION(const X509_EXTENSION* ext, unsigned char** out) {
    int Res = 0;
    Res = i2d_X509_EXTENSION(ext, out);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int ENGINE_set_default_digests(ENGINE* e) {
    int Res = 0;
    Res = ENGINE_set_default_digests(e);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int BIO_ADDR_rawmake(BIO_ADDR* a, int b, const void* c, size_t d, unsigned short e) {
    int Res = 0;
    // Perform necessary actions
    return Res;
}

int BIO_ADDRINFO_socktype(const BIO_ADDRINFO* a) {
    int Res = 0;
    // Perform necessary actions
    return Res;
}

int EVP_PKEY_CTX_set_dh_kdf_md(EVP_PKEY_CTX* a, const EVP_MD* b) {
    int Res = 0;
    // Perform necessary actions
    return Res;
}

int EVP_MD_is_a(const EVP_MD* a, const char* b) {
    int Res = 0;
    // Perform necessary actions
    return Res;
}

void PROFESSION_INFO_set0_registrationNumber(PROFESSION_INFO* a, ASN1_PRINTABLESTRING* b) {
    // Perform necessary actions
}

int ENGINE_ctrl_cmd(ENGINE* e, const char* cmd, long i, void* p, void (*f)(), int cmd_opt) {
    int Res = 0;
    // Add memory allocation and deallocation specifications if applicable
    // Add password usage specifications if applicable
    // Add memory initialization specifications if applicable
    // Add memory overwrite specifications if applicable
    // Add string and buffer operations specifications if applicable
    // Add error handling specifications
    // Add TOCTTOU race conditions specifications if applicable
    // Add file descriptor validity specifications if applicable
    // Add tainted data specifications if applicable
    // Add sensitive data specifications if applicable
    // Add time specifications if applicable
    // Add file offsets or sizes specifications if applicable
    // Add program termination specifications if applicable
    // Add library argument type specifications if applicable
    // Add null checks specifications if applicable
    // Add uncontrolled pointers specifications if applicable
    // Add possible negative values specifications if applicable
    return Res;
}

int DH_generate_key(DH* dh) {
    int Res = 0;
    // Add memory allocation and deallocation specifications if applicable
    // Add password usage specifications if applicable
    // Add memory initialization specifications if applicable
    // Add memory overwrite specifications if applicable
    // Add string and buffer operations specifications if applicable
    // Add error handling specifications
    // Add TOCTTOU race conditions specifications if applicable
    // Add file descriptor validity specifications if applicable
    // Add tainted data specifications if applicable
    // Add sensitive data specifications if applicable
    // Add time specifications if applicable
    // Add file offsets or sizes specifications if applicable
    // Add program termination specifications if applicable
    // Add library argument type specifications if applicable
    // Add null checks specifications if applicable
    // Add uncontrolled pointers specifications if applicable
    // Add possible negative values specifications if applicable
    return Res;
}

int EVP_PKEY_get_field_type(const EVP_PKEY* pkey) {
    int Res = 0;
    // Add memory allocation and deallocation specifications if applicable
    // Add password usage specifications if applicable
    // Add memory initialization specifications if applicable
    // Add memory overwrite specifications if applicable
    // Add string and buffer operations specifications if applicable
    // Add error handling specifications
    // Add TOCTTOU race conditions specifications if applicable
    // Add file descriptor validity specifications if applicable
    // Add tainted data specifications if applicable
    // Add sensitive data specifications if applicable
    // Add time specifications if applicable
    // Add file offsets or sizes specifications if applicable
    // Add program termination specifications if applicable
    // Add library argument type specifications if applicable
    // Add null checks specifications if applicable
    // Add uncontrolled pointers specifications if applicable
    // Add possible negative values specifications if applicable
    return Res;
}

int EVP_PKEY_fromdata_init(EVP_PKEY_CTX* ctx) {
    int Res = 0;
    // Add memory allocation and deallocation specifications if applicable
    // Add password usage specifications if applicable
    // Add memory initialization specifications if applicable
    // Add memory overwrite specifications if applicable
    // Add string and buffer operations specifications if applicable
    // Add error handling specifications
    // Add TOCTTOU race conditions specifications if applicable
    // Add file descriptor validity specifications if applicable
    // Add tainted data specifications if applicable
    // Add sensitive data specifications if applicable
    // Add time specifications if applicable
    // Add file offsets or sizes specifications if applicable
    // Add program termination specifications if applicable
    // Add library argument type specifications if applicable
    // Add null checks specifications if applicable
    // Add uncontrolled pointers specifications if applicable
    // Add possible negative values specifications if applicable
    return Res;
}

int OSSL_LIB_CTX_load_config(OSSL_LIB_CTX* ctx, const char* config_name) {
    int Res = 0;
    // Add memory allocation and deallocation specifications if applicable
    // Add password usage specifications if applicable
    // Add memory initialization specifications if applicable
    // Add memory overwrite specifications if applicable
    // Add string and buffer operations specifications if applicable
    // Add error handling specifications
    // Add TOCTTOU race conditions specifications if applicable
    // Add file descriptor validity specifications if applicable
    // Add tainted data specifications if applicable
    // Add sensitive data specifications if applicable
    // Add time specifications if applicable
    // Add file offsets or sizes specifications if applicable
    // Add program termination specifications if applicable
    // Add library argument type specifications if applicable
    // Add null checks specifications if applicable
    // Add uncontrolled pointers specifications if applicable
    // Add possible negative values specifications if applicable
    return Res;
}
void BIO_set_data(BIO* bio, void* data);

int EVP_DecryptInit(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type, const unsigned char* key, const unsigned char* iv);

int CRYPTO_atomic_add(int* ptr, int value, int* new_val, CRYPTO_RWLOCK* lock);

DH* DH_generate_parameters(int bits, int qbits, void (int, int, void*);


    sf_set_tainted(params);
    for (int i = 0; i < sizeof(params); i++) {
        sf_set_tainted(params[i]);
    }
    return 1;

int SSL_session_reused(const SSL* ssl) {
    int res = 0;
    sf_set_must_be_not_null(ssl, SESSION_REUSED_OF_NULL);
    sf_set_errno_if(res == 0, EINVAL);
    sf_set_possible_null(res);
    return res;
}

int SSL_CTX_use_serverinfo(SSL_CTX* ctx, const unsigned char* serverinfo, size_t len) {
    int res = 0;
    sf_set_must_be_not_null(ctx, USE_SERVERINFO_OF_NULL);
    sf_set_must_be_not_null(serverinfo, USE_SERVERINFO_SERVERINFO_NULL);
    sf_set_errno_if(res == 0, EINVAL);
    sf_set_possible_null(res);
    return res;
}

SSL_CTX* SSL_CTX_new(const SSL_METHOD* method) {
    SSL_CTX* res = NULL;
    sf_set_must_be_not_null(method, CTX_NEW_METHOD_NULL);
    sf_set_alloc_possible_null(res);
    sf_new(res, SSL_CTX_MEMORY_CATEGORY);
    return res;
}

int SSL_CTX_dane_mtype_set(SSL_CTX* ctx, const EVP_MD* md, uint8_t mtype, uint8_t ord) {
    int res = 0;
    sf_set_must_be_not_null(ctx, DANE_MTYPE_SET_CTX_NULL);
    sf_set_must_be_not_null(md, DANE_MTYPE_SET_MD_NULL);
    sf_set_errno_if(res == 0, EINVAL);
    sf_set_possible_null(res);
    return res;
}

PBKDF2PARAM* d2i_PBKDF2PARAM(PBKDF2PARAM** param, const unsigned char** in, long len) {
    PBKDF2PARAM* res = NULL;
    sf_set_must_be_not_null(param, D2I_PBKDF2PARAM_PARAM_NULL);
    sf_set_must_be_not_null(in, D2I_PBKDF2PARAM_IN_NULL);
    sf_set_alloc_possible_null(res);
    sf_new(res, PBKDF2PARAM_MEMORY_CATEGORY);
    return res;
}
EVP_PKEY* CTLOG_get0_public_key(const CTLOG* log);

int EC_POINT_set_to_infinity(const EC_GROUP* group, EC_POINT* point);

const EVP_PKEY_ASN1_METHOD* EVP_PKEY_asn1_find_str(ENGINE** e, const char* str, int len);

void RSA_meth_free(RSA_METHOD* meth);

ASN1_OBJECT* OBJ_nid2obj(int nid);


int PEM_read_bio(BIO* bio, char** x, char** y, unsigned char** z, long* n) {
    int Res = 0;
    // Check for null pointers
    sf_set_must_be_not_null(bio, "PEM_read_bio");
    sf_set_must_be_not_null(x, "PEM_read_bio");
    sf_set_must_be_not_null(y, "PEM_read_bio");
    sf_set_must_be_not_null(z, "PEM_read_bio");
    sf_set_must_be_not_null(n, "PEM_read_bio");

    // Check for TOCTTOU race conditions
    sf_tocttou_check(bio);

    // Check for tainted data
    sf_set_tainted(x);
    sf_set_tainted(y);
    sf_set_tainted(z);
    sf_set_tainted(n);

    // Check for password usage
    sf_password_use(x);
    sf_password_use(y);

    // Check for error handling
    sf_set_errno_if(Res == 0, "PEM_read_bio");

    return Res;
}

int EVP_SealFinal(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl) {
    int Res = 0;
    // Check for null pointers
    sf_set_must_be_not_null(ctx, "EVP_SealFinal");
    sf_set_must_be_not_null(out, "EVP_SealFinal");
    sf_set_must_be_not_null(outl, "EVP_SealFinal");

    // Check for error handling
    sf_set_errno_if(Res <= 0, "EVP_SealFinal");

    return Res;
}

int EC_GROUP_get_curve_name(const EC_GROUP* group) {
    int Res = 0;
    // Check for null pointers
    sf_set_must_be_not_null(group, "EC_GROUP_get_curve_name");

    return Res;
}

void RAND_seed(const void* buf, int num) {
    // Check for null pointers
    sf_set_must_be_not_null(buf, "RAND_seed");

    // Check for tainted data
    sf_set_tainted(buf);

    // Check for password usage
    sf_password_use(buf);
}

int X509_REQ_get_attr_by_NID(const X509_REQ* req, int nid, int lastpos) {
    int Res = 0;
    // Check for null pointers
    sf_set_must_be_not_null(req, "X509_REQ_get_attr_by_NID");

    // Check for error handling
    sf_set_errno_if(Res == -1, "X509_REQ_get_attr_by_NID");

    return Res;
}
int SSL_set_tlsext_use_srtp(SSL*, const char*);

void EVP_KEYMGMT_do_all_provided(OSSL_LIB_CTX*, void (EVP_KEYMGMT*, void*);

int SSL_CTX_set1_param(SSL_CTX*, X509_VERIFY_PARAM*);

const ASN1_ITEM* ISSUING_DIST_POINT_it();

void SCT_print(const SCT*, BIO*, int, const CTLOG_STORE*);


ASN1_UTCTIME* d2i_ASN1_UTCTIME(ASN1_UTCTIME** a, const unsigned char** pp, long length)
{
    ASN1_UTCTIME* Res = NULL;
    sf_set_trusted_sink_int(length);
    sf_malloc_arg(Res, sizeof(ASN1_UTCTIME), "ASN1_UTCTIME");
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    sf_lib_arg_type(Res, "ASN1_UTCTIME");
    // Implementation of the function
    return Res;
}

void* ASN1_item_d2i_fp(const ASN1_ITEM* it, FILE* in, void* x)
{
    void* Res = NULL;
    sf_set_trusted_sink_ptr(in);
    sf_set_trusted_sink_ptr(it);
    sf_malloc_arg(Res, it->size, "ASN1_item_d2i_fp");
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    sf_lib_arg_type(Res, "ASN1_item_d2i_fp");
    // Implementation of the function
    return Res;
}

DIST_POINT* d2i_DIST_POINT(DIST_POINT** a, const unsigned char** pp, long length)
{
    DIST_POINT* Res = NULL;
    sf_set_trusted_sink_int(length);
    sf_malloc_arg(Res, sizeof(DIST_POINT), "DIST_POINT");
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    sf_lib_arg_type(Res, "DIST_POINT");
    // Implementation of the function
    return Res;
}

int EVP_PKEY_verify_recover_init(EVP_PKEY_CTX* ctx)
{
    int Res = 0;
    sf_set_trusted_sink_ptr(ctx);
    // Implementation of the function
    return Res;
}

int SSL_renegotiate_pending(const SSL* s)
{
    int Res = 0;
    sf_set_trusted_sink_ptr(s);
    // Implementation of the function
    return Res;
}

void SSL_set_msg_callback(SSL *ssl, void (*cb)(int, int, int, const void*, size_t, SSL*, void*))
{
    sf_set_trusted_sink_ptr(ssl);
    sf_set_trusted_sink_ptr(cb);
}

int SSL_stateless(SSL *ssl)
{
    int res = 0;
    sf_set_trusted_sink_ptr(ssl);
    sf_set_errno_if(res, ssl == NULL);
    return res;
}

ASN1_TIME *ASN1_TIME_dup(const ASN1_TIME *time)
{
    ASN1_TIME *res = NULL;
    sf_set_trusted_sink_ptr(time);
    sf_malloc_arg(res, sizeof(ASN1_TIME));
    sf_overwrite(res);
    sf_bitcopy(res, time);
    return res;
}

const char *UI_get0_output_string(UI_STRING *uis)
{
    const char *res = NULL;
    sf_set_trusted_sink_ptr(uis);
    sf_set_possible_null(res);
    return res;
}

int SSL_add_client_CA(SSL *ssl, X509 *x)
{
    int res = 0;
    sf_set_trusted_sink_ptr(ssl);
    sf_set_trusted_sink_ptr(x);
    sf_set_errno_if(res, ssl == NULL || x == NULL);
    return res;
}
int EVP_PKEY_get_attr_by_NID(const EVP_PKEY* pkey, int nid, int idx);

EVP_ASYM_CIPHER* EVP_ASYM_CIPHER_fetch(OSSL_LIB_CTX* ctx, const char* name, const char* propquery);

EVP_PKEY_ASN1_METHOD* EVP_PKEY_asn1_new(int id, int flags, const char* name, const char* description);

void* SSL_SESSION_get_ex_data(const SSL_SESSION* sess, int idx);

int (X509_LOOKUP*);


const EVP_CIPHER* EVP_aes_128_xts() {
    const EVP_CIPHER* Res = NULL;
    Res = EVP_aes_128_xts();
    sf_set_possible_null(Res);
    return Res;
}

ASN1_TIME* X509_getm_notBefore(const X509* x) {
    ASN1_TIME* Res = NULL;
    Res = X509_getm_notBefore(x);
    sf_set_possible_null(Res);
    return Res;
}

int BN_is_word(const BIGNUM* a, const unsigned long w) {
    int Res = 0;
    Res = BN_is_word(a, w);
    return Res;
}

uint32_t SSL_get_recv_max_early_data(const SSL* s) {
    uint32_t Res = 0;
    Res = SSL_get_recv_max_early_data(s);
    return Res;
}

SXNETID* d2i_SXNETID(SXNETID** a, const unsigned char** in, long len) {
    SXNETID* Res = NULL;
    Res = d2i_SXNETID(a, in, len);
    sf_set_possible_null(Res);
    return Res;
}
void SSL_free(SSL* ssl);

int EVP_PKEY_CTX_get0_dh_kdf_oid(EVP_PKEY_CTX* ctx, ASN1_OBJECT** oid);

PKCS7* PEM_read_bio_PKCS7(BIO* bio, PKCS7** p7, pem_password_cb* cb, void* u);

int i2d_RSA_PUBKEY(const RSA* rsa, unsigned char** p);

int SSL_SESSION_set_protocol_version(SSL_SESSION* s, int version);


int i2d_ASIdOrRange(const ASIdOrRange* a, unsigned char** pp) {
    int res = 0;
    sf_set_trusted_sink_int(a);
    sf_set_trusted_sink_ptr(pp);
    sf_set_tainted(a);
    sf_set_errno_if(res < 0);
    sf_set_possible_null(res);
    return res;
}

void ASN1_TYPE_set(ASN1_TYPE* a, int type, void* value) {
    sf_set_tainted(a);
    sf_set_tainted(value);
    sf_set_errno_if(a == NULL);
}

int X509_set_pubkey(X509* x, EVP_PKEY* pkey) {
    int res = 0;
    sf_set_tainted(x);
    sf_set_tainted(pkey);
    sf_set_errno_if(res <= 0);
    return res;
}

const EVP_CIPHER* EVP_camellia_192_cfb1() {
    const EVP_CIPHER* res = NULL;
    sf_set_tainted(res);
    return res;
}

int SSL_read(SSL* s, void* buf, int num) {
    int res = 0;
    sf_set_tainted(s);
    sf_set_tainted(buf);
    sf_set_errno_if(res <= 0);
    sf_buf_size_limit(buf, num);
    return res;
}

size_t EC_KEY_priv2buf(const EC_KEY *key, unsigned char **buf) {
    size_t Res = 0;
    sf_set_trusted_sink_int(Res);
    sf_malloc_arg(buf);
    Res = EC_KEY_priv2buf(key, buf);
    sf_overwrite(buf, Res);
    sf_new(buf, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res, buf);
    sf_lib_arg_type(buf, "MallocCategory");
    return Res;
}

EVP_PKEY* d2i_PrivateKey_bio(BIO *bp, EVP_PKEY **key) {
    EVP_PKEY* Res = NULL;
    sf_set_trusted_sink_ptr(Res);
    sf_set_must_be_not_null(bp, FREE_OF_NULL);
    Res = d2i_PrivateKey_bio(bp, key);
    sf_set_possible_null(Res);
    sf_set_possible_null(*key);
    return Res;
}

int X509_LOOKUP_by_alias(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type, const char *name, int namelen, X509_OBJECT *obj) {
    int Res = 0;
    sf_set_trusted_sink_int(Res);
    sf_set_must_be_not_null(ctx, FREE_OF_NULL);
    sf_set_must_be_not_null(name, FREE_OF_NULL);
    Res = X509_LOOKUP_by_alias(ctx, type, name, namelen, obj);
    sf_set_errno_if(Res <= 0);
    return Res;
}

void EVP_PKEY_meth_get0_info(int *pkey_id, int *flags, const EVP_PKEY_METHOD *meth) {
    sf_set_trusted_sink_ptr(pkey_id);
    sf_set_trusted_sink_ptr(flags);
    sf_set_must_be_not_null(meth, FREE_OF_NULL);
    EVP_PKEY_meth_get0_info(pkey_id, flags, meth);
}

int ENGINE_ctrl_cmd_string(ENGINE *e, const char *cmd_name, const char *arg, int cmd_optional) {
    int Res = 0;
    sf_set_trusted_sink_int(Res);
    sf_set_must_be_not_null(e, FREE_OF_NULL);
    sf_set_must_be_not_null(cmd_name, FREE_OF_NULL);
    sf_set_must_be_not_null(arg, FREE_OF_NULL);
    Res = ENGINE_ctrl_cmd_string(e, cmd_name, arg, cmd_optional);
    sf_set_errno_if(Res <= 0);
    return Res;
}

DSA* d2i_DSAPrivateKey_fp(FILE *fp, DSA **dsa)
{
    DSA *Res = NULL;
    sf_set_must_be_not_null(fp, FILE_PTR_NULL);
    sf_set_must_be_not_null(dsa, DSA_PTR_NULL);
    sf_set_tainted(dsa, DSA_PTR_TAINTED);
    sf_set_errno_if(Res == NULL, EVP_R_DECODE_ERROR);
    sf_set_alloc_possible_null(Res);
    return Res;
}

long BIO_ctrl(BIO *bp, int cmd, long larg, void *parg)
{
    long Res = 0;
    sf_set_must_be_not_null(bp, BIO_PTR_NULL);
    sf_set_errno_if(Res == 0, BIO_R_INVALID_ARGUMENT);
    return Res;
}

int PEM_write_DSA_PUBKEY(FILE *fp, const DSA *dsa)
{
    int Res = 0;
    sf_set_must_be_not_null(fp, FILE_PTR_NULL);
    sf_set_must_be_not_null(dsa, DSA_PTR_NULL);
    sf_set_errno_if(Res == 0, PEM_R_WRITE_ERROR);
    return Res;
}

uint32_t X509_VERIFY_PARAM_get_inh_flags(const X509_VERIFY_PARAM *param)
{
    uint32_t Res = 0;
    sf_set_must_be_not_null(param, X509_VERIFY_PARAM_PTR_NULL);
    return Res;
}

int ASN1_item_verify_ctx(const ASN1_ITEM *it, const X509_ALGOR *alg, const ASN1_BIT_STRING *signature, const void *data, EVP_MD_CTX *ctx)
{
    int Res = 0;
    sf_set_must_be_not_null(it, ASN1_ITEM_PTR_NULL);
    sf_set_must_be_not_null(alg, X509_ALGOR_PTR_NULL);
    sf_set_must_be_not_null(signature, ASN1_BIT_STRING_PTR_NULL);
    sf_set_must_be_not_null(data, DATA_PTR_NULL);
    sf_set_must_be_not_null(ctx, EVP_MD_CTX_PTR_NULL);
    sf_set_errno_if(Res == 0, ASN1_R_VERIFY_ERROR);
    return Res;
}

const OSSL_PARAM* OSSL_PARAM_locate_const(const OSSL_PARAM* params, const char* key)
{
    const OSSL_PARAM* Res = NULL;
    sf_set_must_be_not_null(params, PARAMS_NOT_NULL);
    sf_set_must_be_not_null(key, KEY_NOT_NULL);
    sf_null_terminated(key);
    sf_buf_stop_at_null(key);
    sf_set_errno_if(Res == NULL, ERRNO_IF_NOT_FOUND);
    return Res;
}

int PEM_write_bio_X509_PUBKEY(BIO* bio, const X509_PUBKEY* x)
{
    int Res = 0;
    sf_set_must_be_not_null(bio, BIO_NOT_NULL);
    sf_set_must_be_not_null(x, X509_PUBKEY_NOT_NULL);
    sf_set_errno_if(Res <= 0, ERRNO_IF_ERROR);
    return Res;
}

void UI_set_default_method(const UI_METHOD* method)
{
    sf_set_must_be_not_null(method, METHOD_NOT_NULL);
}

int EC_POINT_set_affine_coordinates(const EC_GROUP* group, EC_POINT* point, const BIGNUM* x, const BIGNUM* y, BN_CTX* ctx)
{
    int Res = 0;
    sf_set_must_be_not_null(group, GROUP_NOT_NULL);
    sf_set_must_be_not_null(point, POINT_NOT_NULL);
    sf_set_must_be_not_null(x, X_NOT_NULL);
    sf_set_must_be_not_null(y, Y_NOT_NULL);
    sf_set_errno_if(Res == 0, ERRNO_IF_ERROR);
    return Res;
}

ENGINE* ENGINE_get_cipher_engine(int nid)
{
    ENGINE* Res = NULL;
    sf_set_errno_if(Res == NULL, ERRNO_IF_NOT_FOUND);
    return Res;
}
void ADMISSION_SYNTAX_set0_admissionAuthority(ADMISSION_SYNTAX* a, GENERAL_NAME* b);

void ADMISSIONS_set0_namingAuthority(ADMISSIONS* a, NAMING_AUTHORITY* b);

EC_KEY* PEM_read_EC_PUBKEY(FILE* a, EC_KEY** b, pem_password_cb* c, void* d);

EVP_KEYMGMT* EVP_KEYMGMT_fetch(OSSL_LIB_CTX* a, const char* b, const char* c);

void EVP_RAND_CTX_free(EVP_RAND_CTX* a);


int SSL_CTX_get_quiet_shutdown(const SSL_CTX* ctx) {
    int Res = 0;
    Res = ctx->quiet_shutdown;
    sf_set_possible_null(Res);
    return Res;
}

int ASN1_ENUMERATED_get_int64(int64_t* out, const ASN1_ENUMERATED* ae) {
    int Res = 0;
    if (ae->length <= 8) {
        *out = 0;
        for (int i = 0; i < ae->length; i++) {
            *out |= ((int64_t)ae->data[i]) << (8 * i);
        }
        Res = 1;
    }
    sf_set_possible_null(Res);
    return Res;
}

int i2d_X509_REQ_INFO(const X509_REQ_INFO* ri, unsigned char** pp) {
    int Res = 0;
    Res = i2d_X509_REQ_INFO_internal(ri, pp);
    sf_set_possible_null(Res);
    return Res;
}

void X509_CRL_get0_signature(const X509_CRL* crl, const ASN1_BIT_STRING** out_sig, const X509_ALGOR** out_alg) {
    *out_sig = crl->signature;
    *out_alg = crl->sig_alg;
    sf_set_possible_null(*out_sig);
    sf_set_possible_null(*out_alg);
}

BIO* BIO_new_ex(OSSL_LIB_CTX* ctx, const BIO_METHOD* method) {
    BIO* Res = NULL;
    Res = BIO_new(method);
    sf_set_possible_null(Res);
    return Res;
}

int EVP_RAND_get_state(EVP_RAND_CTX* ctx) {
    int res = 0;
    sf_set_must_be_not_null(ctx, "EVP_RAND_CTX");
    res = EVP_RAND_get_state(ctx);
    sf_set_errno_if(res == -1);
    return res;
}

int SSL_set_recv_max_early_data(SSL* s, uint32_t max_early_data) {
    int res = 0;
    sf_set_must_be_not_null(s, "SSL");
    res = SSL_set_recv_max_early_data(s, max_early_data);
    sf_set_errno_if(res == 0);
    return res;
}

void PKCS8_PRIV_KEY_INFO_free(PKCS8_PRIV_KEY_INFO* p8inf) {
    sf_set_must_be_not_null(p8inf, "PKCS8_PRIV_KEY_INFO");
    PKCS8_PRIV_KEY_INFO_free(p8inf);
}

void POLICYQUALINFO_free(POLICYQUALINFO* pqi) {
    sf_set_must_be_not_null(pqi, "POLICYQUALINFO");
    POLICYQUALINFO_free(pqi);
}

ASN1_IA5STRING* s2i_ASN1_IA5STRING(X509V3_EXT_METHOD* method, X509V3_CTX* ctx, const char* str) {
    ASN1_IA5STRING* res = NULL;
    sf_set_must_be_not_null(method, "X509V3_EXT_METHOD");
    sf_set_must_be_not_null(ctx, "X509V3_CTX");
    sf_set_must_be_not_null(str, "str");
    res = s2i_ASN1_IA5STRING(method, ctx, str);
    sf_set_errno_if(res == NULL);
    return res;
}

void SSL_get_info_callback(const SSL *ssl, int where, int ret)
{
    void (*Res)(const SSL *, int, int) = NULL;
    Res = SSL_get_info_callback(ssl);
    sf_set_trusted_sink_ptr(Res);
}

const EC_METHOD* EC_POINT_method_of(const EC_POINT *point)
{
    const EC_METHOD *Res = NULL;
    Res = EC_POINT_method_of(point);
    sf_set_trusted_sink_ptr(Res);
}

PKCS7* PKCS7_encrypt_ex(stack_st_X509 *certs, BIO *in, const EVP_CIPHER *cipher, int flags, OSSL_LIB_CTX *libctx, const char *propq)
{
    PKCS7 *Res = NULL;
    Res = PKCS7_encrypt_ex(certs, in, cipher, flags, libctx, propq);
    sf_set_trusted_sink_ptr(Res);
}

long X509_REQ_get_version(const X509_REQ *req)
{
    long Res = 0;
    Res = X509_REQ_get_version(req);
    sf_set_trusted_sink_int(Res);
}

PKCS7_DIGEST* PKCS7_DIGEST_new()
{
    PKCS7_DIGEST *Res = NULL;
    Res = PKCS7_DIGEST_new();
    sf_set_trusted_sink_ptr(Res);
}

uint32_t SSL_CIPHER_get_id(const SSL_CIPHER* c) {
    uint32_t Res = 0;
    sf_set_must_be_not_null(c, CIPHER_NULL);
    Res = c->id;
    sf_overwrite(Res);
    return Res;
}

const ASN1_TIME* X509_REVOKED_get0_revocationDate(const X509_REVOKED* r) {
    const ASN1_TIME* Res = NULL;
    sf_set_must_be_not_null(r, REVOKED_NULL);
    Res = r->revocationDate;
    sf_set_possible_null(Res);
    return Res;
}

stack_st_X509_INFO* PEM_X509_INFO_read_ex(FILE* fp, stack_st_X509_INFO* sk, pem_password_cb* cb, void* u, OSSL_LIB_CTX* libctx, const char* propq) {
    stack_st_X509_INFO* Res = NULL;
    sf_set_must_be_not_null(fp, FILE_NULL);
    sf_set_must_be_not_null(sk, STACK_NULL);
    sf_set_must_be_not_null(cb, CB_NULL);
    sf_set_must_be_not_null(libctx, LIBCTX_NULL);
    sf_set_must_be_not_null(propq, PROPQ_NULL);
    Res = PEM_X509_INFO_read(fp, sk, cb, u);
    sf_set_possible_null(Res);
    return Res;
}

X509* d2i_X509_fp(FILE* fp, X509** x) {
    X509* Res = NULL;
    sf_set_must_be_not_null(fp, FILE_NULL);
    sf_set_must_be_not_null(x, X509_NULL);
    Res = d2i_X509_fp(fp, x);
    sf_set_possible_null(Res);
    return Res;
}

int EVP_PKEY_CTX_set_ecdh_kdf_outlen(EVP_PKEY_CTX* ctx, int outlen) {
    int Res = 0;
    sf_set_must_be_not_null(ctx, CTX_NULL);
    Res = EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_SET_OUTLEN, outlen, NULL);
    sf_set_errno_if(Res <= 0, SET_OUTLEN_ERROR);
    return Res;
}

int DSA_sign_setup(DSA* dsa, BN_CTX* ctx, BIGNUM** k, BIGNUM** x) {
    int Res = 0;
    sf_set_trusted_sink_int(dsa);
    sf_set_trusted_sink_int(ctx);
    sf_set_trusted_sink_ptr(k);
    sf_set_trusted_sink_ptr(x);
    Res = DSA_sign_setup(dsa, ctx, k, x);
    sf_set_errno_if(Res == 0);
    sf_set_possible_null(Res);
    return Res;
}

IPAddressFamily* d2i_IPAddressFamily(IPAddressFamily** a, const unsigned char** in, long len) {
    IPAddressFamily* Res = NULL;
    sf_set_trusted_sink_ptr(a);
    sf_set_trusted_sink_ptr(in);
    sf_set_trusted_sink_int(len);
    Res = d2i_IPAddressFamily(a, in, len);
    sf_set_errno_if(Res == NULL);
    sf_set_possible_null(Res);
    return Res;
}

int ENGINE_register_DSA(ENGINE* e) {
    int Res = 0;
    sf_set_trusted_sink_ptr(e);
    Res = ENGINE_register_DSA(e);
    sf_set_errno_if(Res == 0);
    return Res;
}

int EVP_RAND_up_ref(EVP_RAND* rand) {
    int Res = 0;
    sf_set_trusted_sink_ptr(rand);
    Res = EVP_RAND_up_ref(rand);
    sf_set_errno_if(Res == 0);
    return Res;
}

int (X509_LOOKUP*)* X509_LOOKUP_meth_get_shutdown(const X509_LOOKUP_METHOD* meth) {
    int (X509_LOOKUP*)* Res = NULL;
    sf_set_trusted_sink_ptr(meth);
    Res = X509_LOOKUP_meth_get_shutdown(meth);
    sf_set_possible_null(Res);
    return Res;
}

ENGINE* Res = NULL;
Res = ENGINE_get_prev(e);
sf_set_possible_null(Res);
return Res;

int Res = 0;
Res = EVP_RAND_CTX_get_params(ctx, params);
sf_set_errno_if(Res == 0);
return Res;

SSL_SESSION* Res = NULL;
Res = PEM_read_bio_SSL_SESSION(bio, session, cb, u);
sf_set_errno_if(Res == NULL);
return Res;

const char* Res = NULL;
Res = OPENSSL_version_pre_release();
sf_set_possible_null(Res);
return Res;

int Res = 0;
Res = EVP_PKEY_CTX_get_dh_kdf_md(ctx, md);
sf_set_errno_if(Res == 0);
return Res;

int SSL_new_session_ticket(SSL* ssl) {
    int Res = 0;
    // Function implementation
    return Res;
}

POLICYQUALINFO* POLICYQUALINFO_new() {
    POLICYQUALINFO* Res = NULL;
    // Function implementation
    return Res;
}

int OSSL_PARAM_set_ulong(OSSL_PARAM* param, unsigned long int val) {
    int Res = 0;
    // Function implementation
    return Res;
}

EC_KEY* d2i_ECPrivateKey_bio(BIO* bio, EC_KEY** eckey) {
    EC_KEY* Res = NULL;
    // Function implementation
    return Res;
}

OSSL_PARAM OSSL_PARAM_construct_int(const char* key, int* val) {
    OSSL_PARAM Res;
    // Function implementation
    return Res;
}

X509_STORE* SSL_CTX_get_cert_store(const SSL_CTX* ctx) {
    X509_STORE* Res = NULL;
    Res = ctx->cert_store;
    sf_set_possible_null(Res);
    return Res;
}

int BIO_ADDRINFO_protocol(const BIO_ADDRINFO* addr) {
    int Res = 0;
    Res = addr->protocol;
    sf_set_possible_negative(Res);
    return Res;
}

int X509_REQ_check_private_key(X509_REQ* req, EVP_PKEY* key) {
    int Res = 0;
    Res = X509_REQ_check_private_key(req, key);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int DSA_verify(int type, const unsigned char* dgst, int dlen, const unsigned char* sigbuf, int siglen, DSA* dsa) {
    int Res = 0;
    Res = DSA_verify(type, dgst, dlen, sigbuf, siglen, dsa);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int SSL_get_sigalgs(SSL* s, int idx, int* sigalg, int* hash, int* curve, unsigned char* rhash, unsigned char* rcurve) {
    int Res = 0;
    Res = SSL_get_sigalgs(s, idx, sigalg, hash, curve, rhash, rcurve);
    sf_set_errno_if(Res <= 0);
    return Res;
}
int PEM_write_bio_NETSCAPE_CERT_SEQUENCE(BIO* bio, const NETSCAPE_CERT_SEQUENCE* seq);

int SSL_CTX_set_ssl_version(SSL_CTX* ctx, const SSL_METHOD* meth);

ASN1_GENERALIZEDTIME* ASN1_GENERALIZEDTIME_dup(const ASN1_GENERALIZEDTIME* time);

X509_ATTRIBUTE* X509_ATTRIBUTE_create_by_NID(X509_ATTRIBUTE** attr, int nid, int type, const void* data, int len);

int X509_cmp_current_time(const ASN1_TIME* time);


BN_BLINDING* BN_BLINDING_create_param(BN_BLINDING *Res, const BIGNUM *a, BIGNUM *b, BN_CTX *c, int (BIGNUM*, const BIGNUM*, const BIGNUM*, const BIGNUM*, BN_CTX*, BN_MONT_CTX*) d, BN_MONT_CTX *e) {
    Res = NULL;
    sf_set_trusted_sink_int(a);
    sf_set_trusted_sink_int(b);
    sf_set_trusted_sink_int(c);
    sf_set_trusted_sink_int(d);
    sf_set_trusted_sink_int(e);
    sf_set_alloc_possible_null(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    return Res;
}

void IPAddressFamily_free(IPAddressFamily *a) {
    sf_set_must_be_not_null(a, FREE_OF_NULL);
    sf_delete(a, MALLOC_CATEGORY);
    sf_lib_arg_type(a, "MallocCategory");
}

char* i2s_ASN1_ENUMERATED(X509V3_EXT_METHOD *a, const ASN1_ENUMERATED *b) {
    char *Res = NULL;
    sf_set_trusted_sink_int(a);
    sf_set_trusted_sink_int(b);
    sf_set_alloc_possible_null(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    return Res;
}

EDIPARTYNAME* EDIPARTYNAME_new() {
    EDIPARTYNAME *Res = NULL;
    sf_set_alloc_possible_null(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    return Res;
}

unsigned long EVP_MD_meth_get_flags(const EVP_MD *a) {
    sf_set_trusted_sink_int(a);
    return 0;
}

const unsigned char* EVP_PKEY_get0_poly1305(const EVP_PKEY *pkey, size_t *len) {
    const unsigned char *Res = NULL;
    sf_set_trusted_sink_int(len);
    sf_set_tainted(pkey);
    sf_set_must_be_not_null(pkey, POLY1305_PKEY_NULL);
    sf_set_must_be_not_null(len, POLY1305_LEN_NULL);
    Res = EVP_PKEY_get0_poly1305(pkey, len);
    sf_set_possible_null(Res);
    return Res;
}

int EVP_PKEY_asn1_add_alias(int to, int from) {
    int Res = 0;
    sf_set_must_be_not_null(to, ASN1_ALIAS_TO_NULL);
    sf_set_must_be_not_null(from, ASN1_ALIAS_FROM_NULL);
    Res = EVP_PKEY_asn1_add_alias(to, from);
    sf_set_errno_if(Res <= 0, ASN1_ALIAS_ADD_FAIL);
    return Res;
}

int X509_CRL_get_ext_by_NID(const X509_CRL *crl, int nid, int lastpos) {
    int Res = 0;
    sf_set_must_be_not_null(crl, CRL_GET_EXT_NULL);
    sf_set_must_be_not_null(nid, CRL_GET_EXT_NID_NULL);
    sf_set_must_be_not_null(lastpos, CRL_GET_EXT_LASTPOS_NULL);
    Res = X509_CRL_get_ext_by_NID(crl, nid, lastpos);
    sf_set_errno_if(Res < 0, CRL_GET_EXT_FAIL);
    return Res;
}

const EVP_PKEY_ASN1_METHOD* EVP_PKEY_asn1_find(ENGINE **engine, int keytype) {
    const EVP_PKEY_ASN1_METHOD *Res = NULL;
    sf_set_must_be_not_null(engine, ASN1_FIND_ENGINE_NULL);
    sf_set_must_be_not_null(keytype, ASN1_FIND_KEYTYPE_NULL);
    Res = EVP_PKEY_asn1_find(engine, keytype);
    sf_set_possible_null(Res);
    return Res;
}

X509_ATTRIBUTE* X509_ATTRIBUTE_new() {
    X509_ATTRIBUTE *Res = NULL;
    Res = X509_ATTRIBUTE_new();
    sf_set_possible_null(Res);
    return Res;
}

int i2d_PKCS8_fp(FILE *fp, const X509_SIG *p8)
{
    int ret = 0;
    // Specify the file pointer as a trusted sink
    sf_set_trusted_sink_ptr(fp);
    // Check if the file pointer is null
    sf_set_must_be_not_null(fp, FREE_OF_NULL);
    // Check if the X509_SIG pointer is null
    sf_set_must_be_not_null(p8, FREE_OF_NULL);
    // Perform the operation and store the result in ret
    ret = i2d_PKCS8_fp(fp, p8);
    // Set errno if there was an error
    sf_set_errno_if(ret <= 0);
    // Return the result
    return ret;
}

ASN1_TIME* ASN1_TIME_adj(ASN1_TIME *s, time_t t, int offset_day, long offset_sec)
{
    ASN1_TIME *ret = NULL;
    // Check if the ASN1_TIME pointer is null
    sf_set_must_be_not_null(s, FREE_OF_NULL);
    // Perform the operation and store the result in ret
    ret = ASN1_TIME_adj(s, t, offset_day, offset_sec);
    // Set errno if there was an error
    sf_set_errno_if(ret == NULL);
    // Return the result
    return ret;
}

int DH_meth_set_finish(DH_METHOD *meth, int (*finish)(DH *))
{
    int ret = 0;
    // Check if the DH_METHOD pointer is null
    sf_set_must_be_not_null(meth, FREE_OF_NULL);
    // Perform the operation and store the result in ret
    ret = DH_meth_set_finish(meth, finish);
    // Set errno if there was an error
    sf_set_errno_if(ret == 0);
    // Return the result
    return ret;
}

int i2d_OCSP_SIGNATURE(const OCSP_SIGNATURE *a, unsigned char **pp)
{
    int ret = 0;
    // Check if the OCSP_SIGNATURE pointer is null
    sf_set_must_be_not_null(a, FREE_OF_NULL);
    // Perform the operation and store the result in ret
    ret = i2d_OCSP_SIGNATURE(a, pp);
    // Set errno if there was an error
    sf_set_errno_if(ret <= 0);
    // Return the result
    return ret;
}

int EVP_PKEY_CTX_set_rsa_padding(EVP_PKEY_CTX *ctx, int pad_mode)
{
    int ret = 0;
    // Check if the EVP_PKEY_CTX pointer is null
    sf_set_must_be_not_null(ctx, FREE_OF_NULL);
    // Perform the operation and store the result in ret
    ret = EVP_PKEY_CTX_set_rsa_padding(ctx, pad_mode);
    // Set errno if there was an error
    sf_set_errno_if(ret <= 0);
    // Return the result
    return ret;
}
int SSL_SESSION_set_cipher(SSL_SESSION* s, const SSL_CIPHER* c);

int OSSL_HTTP_close(OSSL_HTTP_REQ_CTX* r, int f);

EVP_PKEY_CTX* EVP_PKEY_CTX_dup(const EVP_PKEY_CTX* p);

const BIGNUM* EC_GROUP_get0_order(const EC_GROUP* g);

int EVP_PKEY_parameters_eq(const EVP_PKEY* a, const EVP_PKEY* b);


int PEM_write_ECPKParameters(FILE *fp, const EC_GROUP *group)
{
    int res = 0;
    sf_set_must_be_not_null(fp, FILE_PTR_NULL);
    sf_set_must_be_not_null(group, GROUP_PTR_NULL);
    // Implementation
    return res;
}

void EVP_PKEY_asn1_set_public_check(EVP_PKEY_ASN1_METHOD *ameth, int (*check) (const EVP_PKEY *))
{
    sf_set_must_be_not_null(ameth, ASN1_METHOD_PTR_NULL);
    sf_set_must_be_not_null(check, CHECK_FUNC_PTR_NULL);
    // Implementation
}

int X509_REQ_add_extensions(X509_REQ *req, const stack_st_X509_EXTENSION *exts)
{
    int res = 0;
    sf_set_must_be_not_null(req, REQ_PTR_NULL);
    sf_set_must_be_not_null(exts, EXTENSIONS_STACK_PTR_NULL);
    // Implementation
    return res;
}

int i2d_ASRange(const ASRange *range, unsigned char **out)
{
    int res = 0;
    sf_set_must_be_not_null(range, RANGE_PTR_NULL);
    sf_set_must_be_not_null(out, OUT_PTR_NULL);
    // Implementation
    return res;
}

X509* X509_new_ex(OSSL_LIB_CTX *libctx, const char *propq)
{
    X509 *res = NULL;
    sf_set_must_be_not_null(libctx, LIBCTX_PTR_NULL);
    sf_set_must_be_not_null(propq, PROPQ_PTR_NULL);
    // Implementation
    return res;
}

OCSP_CERTSTATUS* d2i_OCSP_CERTSTATUS(OCSP_CERTSTATUS** a, const unsigned char** pp, long length) {
    OCSP_CERTSTATUS* Res = NULL;
    sf_set_trusted_sink_int(length);
    sf_malloc_arg(Res, length);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    return Res;
}

int BIO_parse_hostserv(const char* str, char** host, char** service, BIO_hostserv_priorities hostserv_priorities) {
    int Res = 0;
    sf_set_must_be_not_null(str, FREE_OF_NULL);
    sf_set_must_be_not_null(host, FREE_OF_NULL);
    sf_set_must_be_not_null(service, FREE_OF_NULL);
    sf_set_must_be_not_null(hostserv_priorities, FREE_OF_NULL);
    sf_set_errno_if(Res == 0);
    sf_no_errno_if(Res != 0);
    return Res;
}

OSSL_LIB_CTX* OSSL_LIB_CTX_get0_global_default() {
    OSSL_LIB_CTX* Res = NULL;
    sf_set_possible_null(Res);
    return Res;
}

const OSSL_PARAM* EVP_RAND_gettable_ctx_params(const EVP_RAND* rand) {
    const OSSL_PARAM* Res = NULL;
    sf_set_must_be_not_null(rand, FREE_OF_NULL);
    sf_set_possible_null(Res);
    return Res;
}

int ASN1_INTEGER_get_uint64(uint64_t* ret, const ASN1_INTEGER* a) {
    int Res = 0;
    sf_set_must_be_not_null(ret, FREE_OF_NULL);
    sf_set_must_be_not_null(a, FREE_OF_NULL);
    sf_set_errno_if(Res == 0);
    sf_no_errno_if(Res != 0);
    return Res;
}

const ec_key_st* EVP_PKEY_get0_EC_KEY(const EVP_PKEY* pkey) {
    const ec_key_st* Res = NULL;
    sf_set_must_be_not_null(pkey, EC_KEY_NULL);
    Res = EVP_PKEY_get0_EC_KEY(pkey);
    sf_set_possible_null(Res, EC_KEY_NULL);
    return Res;
}

int EVP_PKEY_CTX_set_rsa_pss_keygen_md_name(EVP_PKEY_CTX* ctx, const char* md_name, const char* md_name2) {
    int Res = 0;
    sf_set_must_be_not_null(ctx, CTX_NULL);
    sf_set_must_be_not_null(md_name, MD_NAME_NULL);
    sf_set_must_be_not_null(md_name2, MD_NAME_NULL);
    Res = EVP_PKEY_CTX_set_rsa_pss_keygen_md_name(ctx, md_name, md_name2);
    sf_set_errno_if(Res <= 0, ERR_LIB_EVP);
    return Res;
}

int i2d_IPAddressFamily(const IPAddressFamily* ip, unsigned char** pp) {
    int Res = 0;
    sf_set_must_be_not_null(ip, IP_FAMILY_NULL);
    sf_set_must_be_not_null(pp, PP_NULL);
    Res = i2d_IPAddressFamily(ip, pp);
    sf_set_errno_if(Res <= 0, ERR_LIB_ASN1);
    return Res;
}

int (const unsigned char*, int, DSA_SIG*, DSA*)* DSA_meth_get_verify(const DSA_METHOD* dm) {
    int (const unsigned char*, int, DSA_SIG*, DSA*)* Res = NULL;
    sf_set_must_be_not_null(dm, DSA_METHOD_NULL);
    Res = DSA_meth_get_verify(dm);
    sf_set_possible_null(Res, DSA_METHOD_NULL);
    return Res;
}

const EVP_CIPHER* EVP_camellia_128_cfb8() {
    const EVP_CIPHER* Res = NULL;
    Res = EVP_camellia_128_cfb8();
    sf_set_possible_null(Res, EVP_CIPHER_NULL);
    return Res;
}

stack_st_X509_NAME* SSL_CTX_get_client_CA_list(const SSL_CTX* ctx) {
    stack_st_X509_NAME* Res = NULL;
    Res = (stack_st_X509_NAME*)sf_malloc_arg(ctx, sizeof(stack_st_X509_NAME));
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_lib_arg_type(Res, "MallocCategory");
    return Res;
}

const char* SSL_SESSION_get0_hostname(const SSL_SESSION* s) {
    const char* Res = NULL;
    Res = (const char*)sf_malloc_arg(s, sizeof(const char));
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_lib_arg_type(Res, "MallocCategory");
    return Res;
}

unsigned long SSL_dane_set_flags(SSL* s, unsigned long flags) {
    unsigned long Res = 0;
    Res = (unsigned long)sf_malloc_arg(s, sizeof(unsigned long));
    sf_overwrite(&Res);
    sf_new(&Res, PAGES_MEMORY_CATEGORY);
    sf_lib_arg_type(&Res, "MallocCategory");
    return Res;
}

int EVP_PKEY_set_params(EVP_PKEY* pkey, OSSL_PARAM params[]) {
    int Res = 0;
    Res = (int)sf_malloc_arg(pkey, sizeof(int));
    sf_overwrite(&Res);
    sf_new(&Res, PAGES_MEMORY_CATEGORY);
    sf_lib_arg_type(&Res, "MallocCategory");
    return Res;
}

int EVP_PKEY_meth_add0(const EVP_PKEY_METHOD* pmeth) {
    int Res = 0;
    Res = (int)sf_malloc_arg(pmeth, sizeof(int));
    sf_overwrite(&Res);
    sf_new(&Res, PAGES_MEMORY_CATEGORY);
    sf_lib_arg_type(&Res, "MallocCategory");
    return Res;
}

OCSP_ONEREQ* OCSP_request_onereq_get0(OCSP_REQUEST* req, int idx) {
    OCSP_ONEREQ* Res = NULL;
    sf_set_must_be_not_null(req, "OCSP_request_onereq_get0");
    sf_set_must_be_not_null(idx, "OCSP_request_onereq_get0");
    sf_set_possible_null(Res, "OCSP_request_onereq_get0");
    return Res;
}

EVP_PKEY* EVP_PKEY_new_CMAC_key(ENGINE* e, const unsigned char* key, size_t keylen, const EVP_CIPHER* cipher) {
    EVP_PKEY* Res = NULL;
    sf_set_must_be_not_null(e, "EVP_PKEY_new_CMAC_key");
    sf_set_must_be_not_null(key, "EVP_PKEY_new_CMAC_key");
    sf_set_must_be_not_null(keylen, "EVP_PKEY_new_CMAC_key");
    sf_set_must_be_not_null(cipher, "EVP_PKEY_new_CMAC_key");
    sf_set_possible_null(Res, "EVP_PKEY_new_CMAC_key");
    return Res;
}

int UI_dup_error_string(UI* u, const char* str) {
    int Res = 0;
    sf_set_must_be_not_null(u, "UI_dup_error_string");
    sf_set_must_be_not_null(str, "UI_dup_error_string");
    sf_set_errno_if(Res, "UI_dup_error_string");
    return Res;
}

RSA_METHOD* RSA_meth_new(const char* name, int flags) {
    RSA_METHOD* Res = NULL;
    sf_set_must_be_not_null(name, "RSA_meth_new");
    sf_set_must_be_not_null(flags, "RSA_meth_new");
    sf_set_possible_null(Res, "RSA_meth_new");
    return Res;
}

unsigned long EVP_CIPHER_get_flags(const EVP_CIPHER* cipher) {
    unsigned long Res = 0;
    sf_set_must_be_not_null(cipher, "EVP_CIPHER_get_flags");
    return Res;
}

void ECDSA_SIG_free(ECDSA_SIG* sig) {
    if (sig != NULL) {
        BN_clear_free(sig->r);
        BN_clear_free(sig->s);
        OPENSSL_free(sig);
    }
}

const BIGNUM* DH_get0_pub_key(const DH* dh) {
    sf_set_must_be_not_null(dh, DH_NULL);
    return dh->pub_key;
}

int EC_KEY_up_ref(EC_KEY* key) {
    sf_set_must_be_not_null(key, EC_KEY_NULL);
    key->references++;
    return key->references;
}

const stack_st_X509_NAME* SSL_get0_CA_list(const SSL* s) {
    sf_set_must_be_not_null(s, SSL_NULL);
    return s->ca_names;
}

int i2d_PKCS8_PRIV_KEY_INFO(const PKCS8_PRIV_KEY_INFO* p8inf, unsigned char** p) {
    sf_set_must_be_not_null(p8inf, PKCS8_PRIV_KEY_INFO_NULL);
    sf_set_must_be_not_null(p, PTR_NULL);
    int ret = i2d_PKCS8_PRIV_KEY_INFO_internal(p8inf, p);
    sf_set_errno_if(ret <= 0);
    return ret;
}

void d2i_ASN1_TYPE(ASN1_TYPE** a, const unsigned char** b, long c) {
    ASN1_TYPE* Res = NULL;
    sf_set_trusted_sink_int(c);
    sf_malloc_arg(a, PAGES_MEMORY_CATEGORY);
    sf_malloc_arg(b, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    sf_lib_arg_type(Res, "ASN1_TYPE");
    return Res;
}

void EVP_PKEY_get_attr_by_OBJ(const EVP_PKEY* a, const ASN1_OBJECT* b, int c) {
    int Res = 0;
    sf_set_tainted(a);
    sf_set_tainted(b);
    sf_set_must_be_not_null(a, FREE_OF_NULL);
    sf_set_must_be_not_null(b, FREE_OF_NULL);
    sf_set_errno_if(Res, EVP_PKEY_get_attr_by_OBJ_FAIL);
    return Res;
}

void SSL_version(const SSL* a) {
    int Res = 0;
    sf_set_must_be_not_null(a, FREE_OF_NULL);
    sf_set_errno_if(Res, SSL_version_FAIL);
    return Res;
}

void RSA_meth_get_init(const RSA_METHOD* a) {
    int (RSA*)* Res = NULL;
    sf_set_must_be_not_null(a, FREE_OF_NULL);
    sf_malloc_arg(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    sf_lib_arg_type(Res, "RSA_METHOD");
    return Res;
}

void BIO_get_data(BIO* a) {
    void* Res = NULL;
    sf_set_must_be_not_null(a, FREE_OF_NULL);
    sf_overwrite(Res);
    sf_lib_arg_type(Res, "BIO");
    return Res;
}

int SSL_CTX_get_security_callback(const SSL_CTX* ctx) {
    int Res = 0;
    Res = ctx->security_callback;
    sf_set_possible_null(Res);
    return Res;
}

int i2d_X509_ALGOR(const X509_ALGOR* algor, unsigned char** pp) {
    int Res = 0;
    sf_set_trusted_sink_int(pp);
    Res = algor->length;
    sf_set_possible_null(Res);
    return Res;
}

void DH_set_flags(DH* dh, int flags) {
    dh->flags = flags;
    sf_set_tainted(dh->flags);
}

int ENGINE_set_default_RSA(ENGINE* e) {
    int Res = 0;
    Res = ENGINE_set_default(e, ENGINE_METHOD_RSA);
    sf_set_errno_if(Res <= 0);
    return Res;
}

DSA_SIG* (*DSA_meth_get_sign(const DSA_METHOD* dm))(const unsigned char* dgst, int dlen, DSA* dsa) {
    DSA_SIG* (*Res)(const unsigned char*, int, DSA*) = NULL;
    Res = dm->dsa_do_sign;
    sf_set_possible_null(Res);
    return Res;
}

// Specification for SSL_get_num_tickets
size_t SSL_get_num_tickets(const SSL *ssl) {
    size_t res = 0;
    sf_set_must_not_be_null(ssl);
    sf_set_trusted_sink_int(res);
    sf_overwrite(res);
    return res;
}

// Specification for SSL_get_record_padding_callback_arg
void* SSL_get_record_padding_callback_arg(const SSL *ssl) {
    void *res = NULL;
    sf_set_must_not_be_null(ssl);
    sf_set_possible_null(res);
    sf_overwrite(res);
    return res;
}

// Specification for X509_STORE_get_check_revocation
X509_STORE_CTX_check_revocation_fn X509_STORE_get_check_revocation(const X509_STORE *store) {
    X509_STORE_CTX_check_revocation_fn res = NULL;
    sf_set_must_not_be_null(store);
    sf_set_possible_null(res);
    sf_overwrite(res);
    return res;
}

// Specification for d2i_AUTHORITY_INFO_ACCESS
AUTHORITY_INFO_ACCESS* d2i_AUTHORITY_INFO_ACCESS(AUTHORITY_INFO_ACCESS **aia, const unsigned char **in, long len) {
    AUTHORITY_INFO_ACCESS *res = NULL;
    sf_set_must_not_be_null(aia);
    sf_set_must_not_be_null(in);
    sf_set_trusted_sink_int(len);
    sf_set_possible_null(res);
    sf_overwrite(res);
    return res;
}

// Specification for X509_PUBKEY_free
void X509_PUBKEY_free(X509_PUBKEY *key) {
    sf_set_must_not_be_null(key);
    sf_delete(key, PUBKEY_MEMORY_CATEGORY);
    sf_lib_arg_type(key, "PubkeyCategory");
}

int BIO_meth_set_read_ex(BIO_METHOD *biom, int (BIO*,  char*, size_t, size_t*)* read_func) {
    int Res = 0;
    sf_set_trusted_sink_int(read_func);
    sf_set_tainted(biom);
    sf_set_tainted(read_func);
    sf_set_errno_if(Res == 0, EINVAL);
    return Res;
}

void OCSP_CRLID_free(OCSP_CRLID *crlid) {
    sf_set_must_be_not_null(crlid, FREE_OF_NULL);
    sf_delete(crlid, OCSP_CRLID_CATEGORY);
}

int BN_is_odd(const BIGNUM *a) {
    int Res = 0;
    sf_set_tainted(a);
    sf_set_errno_if(Res == 0, EINVAL);
    return Res;
}

void EVP_PKEY_meth_set_verify_recover(EVP_PKEY_METHOD *pmeth, int (EVP_PKEY_CTX*)* verify_recover_init, int (EVP_PKEY_CTX*, unsigned char*, size_t*, const unsigned char*, size_t)* verify_recover) {
    sf_set_trusted_sink_ptr(verify_recover_init);
    sf_set_trusted_sink_ptr(verify_recover);
    sf_set_tainted(pmeth);
    sf_set_tainted(verify_recover_init);
    sf_set_tainted(verify_recover);
}

int UI_get_result_minsize(UI_STRING *uis) {
    int Res = 0;
    sf_set_tainted(uis);
    sf_set_errno_if(Res == 0, EINVAL);
    return Res;
}

EC_GROUP* EC_GROUP_new_by_curve_name_ex(OSSL_LIB_CTX* ctx, const char* name, int len) {
    EC_GROUP* Res = NULL;
    sf_set_trusted_sink_int(len);
    sf_malloc_arg(Res, EC_GROUP_MEMORY_CATEGORY);
    sf_overwrite(Res);
    sf_new(Res, EC_GROUP_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    return Res;
}

int RSA_padding_check_none(unsigned char* to, int tlen, const unsigned char* fm, int flen, int num) {
    int Res = 0;
    sf_set_trusted_sink_int(num);
    sf_buf_size_limit(fm, flen);
    sf_buf_size_limit_read(to, tlen);
    sf_buf_overlap(to, fm);
    sf_set_errno_if(Res <= 0);
    sf_no_errno_if(Res > 0);
    return Res;
}

X509_EXTENSION* X509_CRL_get_ext(const X509_CRL* crl, int loc) {
    X509_EXTENSION* Res = NULL;
    sf_set_trusted_sink_int(loc);
    sf_lib_arg_type(crl, "X509_CRL");
    sf_malloc_arg(Res, X509_EXTENSION_MEMORY_CATEGORY);
    sf_overwrite(Res);
    sf_new(Res, X509_EXTENSION_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    return Res;
}

void DH_get0_pqg(const DH* dh, const BIGNUM** p, const BIGNUM** q, const BIGNUM** g) {
    sf_lib_arg_type(dh, "DH");
    sf_set_trusted_sink_ptr(p);
    sf_set_trusted_sink_ptr(q);
    sf_set_trusted_sink_ptr(g);
    sf_not_acquire_if_eq(*p);
    sf_not_acquire_if_eq(*q);
    sf_not_acquire_if_eq(*g);
}

long ASN1_INTEGER_get(const ASN1_INTEGER* ai) {
    long Res = 0;
    sf_lib_arg_type(ai, "ASN1_INTEGER");
    sf_overwrite(&Res);
    return Res;
}
int RSA_padding_check_PKCS1_type_2(unsigned char *to, int tlen, const unsigned char *from, int flen, int num);

DSA_SIG* d2i_DSA_SIG(DSA_SIG **a, const unsigned char **pp, long length);

const RAND_METHOD* ENGINE_get_RAND(const ENGINE *e);

int X509_REQ_get_signature_nid(const X509_REQ *req);

int (DSA*);


int EVP_PKEY_decrypt_init(EVP_PKEY_CTX* ctx) {
    int Res = 0;
    sf_set_must_be_not_null(ctx, DECRYPT_INIT_OF_NULL);
    Res = EVP_PKEY_decrypt(ctx);
    sf_set_errno_if(Res <= 0, DECRYPT_INIT_FAIL);
    return Res;
}

int SSL_add1_to_CA_list(SSL* ssl, const X509* x) {
    int Res = 0;
    sf_set_must_be_not_null(ssl, SSL_ADD1_TO_CA_LIST_NULL);
    sf_set_must_be_not_null(x, SSL_ADD1_TO_CA_LIST_X_NULL);
    Res = SSL_add_client_CA(ssl, x);
    sf_set_errno_if(Res != 1, SSL_ADD1_TO_CA_LIST_FAIL);
    return Res;
}

int BN_pseudo_rand_range(BIGNUM* r, const BIGNUM* range) {
    int Res = 0;
    sf_set_must_be_not_null(r, BN_PSEUDO_RAND_RANGE_R_NULL);
    sf_set_must_be_not_null(range, BN_PSEUDO_RAND_RANGE_RANGE_NULL);
    Res = BN_rand_range(r, range);
    sf_set_errno_if(Res != 1, BN_PSEUDO_RAND_RANGE_FAIL);
    return Res;
}

NOTICEREF* d2i_NOTICEREF(NOTICEREF** a, const unsigned char** in, long len) {
    NOTICEREF* Res = NULL;
    sf_set_must_be_not_null(a, D2I_NOTICEREF_A_NULL);
    sf_set_must_be_not_null(in, D2I_NOTICEREF_IN_NULL);
    Res = d2i_NOTICEREF(a, in, len);
    sf_set_errno_if(Res == NULL, D2I_NOTICEREF_FAIL);
    return Res;
}

void GENERAL_NAME_free(GENERAL_NAME* a) {
    sf_set_must_be_not_null(a, GENERAL_NAME_FREE_NULL);
    GENERAL_NAME_free(a);
}

int ASN1_item_sign_ex(const ASN1_ITEM *it, X509_ALGOR *alg1, X509_ALGOR *alg2, ASN1_BIT_STRING *signature, const void *data, const ASN1_OCTET_STRING *idata, EVP_PKEY *pkey, const EVP_MD *md, OSSL_LIB_CTX *ctx, const char *propq)
{
    int Res = 0;
    sf_set_must_be_not_null(it, "ASN1_ITEM");
    sf_set_must_be_not_null(alg1, "X509_ALGOR");
    sf_set_must_be_not_null(alg2, "X509_ALGOR");
    sf_set_must_be_not_null(signature, "ASN1_BIT_STRING");
    sf_set_must_be_not_null(data, "data");
    sf_set_must_be_not_null(idata, "ASN1_OCTET_STRING");
    sf_set_must_be_not_null(pkey, "EVP_PKEY");
    sf_set_must_be_not_null(md, "EVP_MD");
    sf_set_must_be_not_null(ctx, "OSSL_LIB_CTX");
    sf_set_must_be_not_null(propq, "propq");
    Res = ASN1_item_sign_ex(it, alg1, alg2, signature, data, idata, pkey, md, ctx, propq);
    sf_set_errno_if(Res <= 0, "ASN1_item_sign_ex");
    return Res;
}

int EVP_DecryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    int Res = 0;
    sf_set_must_be_not_null(ctx, "EVP_CIPHER_CTX");
    sf_set_must_be_not_null(out, "out");
    sf_set_must_be_not_null(outl, "outl");
    Res = EVP_DecryptFinal(ctx, out, outl);
    sf_set_errno_if(Res <= 0, "EVP_DecryptFinal");
    return Res;
}

int EC_GROUP_set_curve(EC_GROUP *group, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
{
    int Res = 0;
    sf_set_must_be_not_null(group, "EC_GROUP");
    sf_set_must_be_not_null(p, "p");
    sf_set_must_be_not_null(a, "a");
    sf_set_must_be_not_null(b, "b");
    sf_set_must_be_not_null(ctx, "BN_CTX");
    Res = EC_GROUP_set_curve(group, p, a, b, ctx);
    sf_set_errno_if(Res <= 0, "EC_GROUP_set_curve");
    return Res;
}

int ASN1_UTCTIME_set_string(ASN1_UTCTIME *s, const char *str)
{
    int Res = 0;
    sf_set_must_be_not_null(s, "ASN1_UTCTIME");
    sf_set_must_be_not_null(str, "str");
    Res = ASN1_UTCTIME_set_string(s, str);
    sf_set_errno_if(Res <= 0, "ASN1_UTCTIME_set_string");
    return Res;
}

const EVP_CIPHER* EVP_aes_256_ofb()
{
    const EVP_CIPHER *Res = NULL;
    Res = EVP_aes_256_ofb();
    sf_set_must_be_not_null(Res, "EVP_aes_256_ofb");
    return Res;
}
const char* UI_get0_result(UI* ui, int i);

unsigned long ERR_peek_last_error_all(const char** file, int* line, const char** data, const char** flags, int* num);

const char* ENGINE_get_id(const ENGINE* e);

int OCSP_request_sign(OCSP_REQUEST* req, X509* cert, EVP_PKEY* key, const EVP_MD* md, stack_st_X509* certs, unsigned long flags);

int RAND_bytes_ex(OSSL_LIB_CTX* ctx, unsigned char* buf, size_t num, unsigned int flags);


void EVP_PKEY_asn1_set_private(EVP_PKEY_ASN1_METHOD *ameth, int (*priv_decode) (EVP_PKEY *pk, const PKCS8_PRIV_KEY_INFO *p8inf), int (*priv_encode) (PKCS8_PRIV_KEY_INFO *p8inf, const EVP_PKEY *pk), int (*priv_print) (BIO *out, const EVP_PKEY *pk, int indent, ASN1_PCTX *pctx))
{
    sf_set_trusted_sink_ptr(ameth);
    sf_set_trusted_sink_ptr(priv_decode);
    sf_set_trusted_sink_ptr(priv_encode);
    sf_set_trusted_sink_ptr(priv_print);
}

X509_CRL* d2i_X509_CRL(X509_CRL **a, const unsigned char **in, long len)
{
    X509_CRL *Res = NULL;
    sf_set_trusted_sink_ptr(a);
    sf_set_trusted_sink_ptr(in);
    sf_set_trusted_sink_int(len);
    sf_set_alloc_possible_null(Res);
    return Res;
}

int i2d_PKCS7_SIGNER_INFO(const PKCS7_SIGNER_INFO *a, unsigned char **pp)
{
    int Res = 0;
    sf_set_trusted_sink_ptr(a);
    sf_set_trusted_sink_ptr(pp);
    return Res;
}

unsigned long ERR_peek_last_error_line_data(const char **file, int *line, const char **data, int *flags)
{
    unsigned long Res = 0;
    sf_set_trusted_sink_ptr(file);
    sf_set_trusted_sink_ptr(line);
    sf_set_trusted_sink_ptr(data);
    sf_set_trusted_sink_ptr(flags);
    return Res;
}

stack_st_CONF_VALUE* NCONF_get_section(const CONF *conf, const char *section)
{
    stack_st_CONF_VALUE *Res = NULL;
    sf_set_trusted_sink_ptr(conf);
    sf_set_trusted_sink_ptr(section);
    sf_set_alloc_possible_null(Res);
    return Res;
}
BIGNUM* EC_POINT_point2bn(const EC_GROUP*, const EC_POINT*, point_conversion_form_t, BIGNUM*, BN_CTX*);

const BIO_ADDRINFO* BIO_ADDRINFO_next(const BIO_ADDRINFO*);

int SSL_get_verify_depth(const SSL*);

X509* X509_STORE_CTX_get_current_cert(const X509_STORE_CTX*);

void OPENSSL_load_builtin_modules();

void OPENSSL_LH_doall_arg(OPENSSL_LHASH *lh, OPENSSL_LH_DOALL_FUNCARG func, void *arg);

int EVP_PKEY_get_default_digest_name(EVP_PKEY *pkey, char *buf, size_t len);

int EVP_PKEY_set1_encoded_public_key(EVP_PKEY *pkey, const unsigned char *pub, size_t len);

int EVP_PKEY_public_check(EVP_PKEY_CTX *ctx);

int SSL_CTX_use_certificate(SSL_CTX *ctx, X509 *x);

const char* EVP_RAND_get0_name(const EVP_RAND* rand);

int EVP_CipherInit_ex2(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type, const unsigned char* key, const unsigned char* iv, int enc);

EC_GROUP* EC_GROUP_new_by_curve_name(int nid);

const EVP_CIPHER* EVP_aria_128_ofb();

int OBJ_sn2nid(const char* sn);


int BIO_meth_get_write(const BIO_METHOD* meth) {
    int Res = 0;
    Res = meth->write;
    sf_set_possible_null(Res);
    return Res;
}

uint64_t SSL_clear_options(SSL* s, uint64_t op) {
    uint64_t Res = 0;
    Res = s->options & ~op;
    sf_set_possible_negative(Res);
    return Res;
}

const EVP_CIPHER* EVP_des_ede3_cfb1() {
    const EVP_CIPHER* Res = NULL;
    Res = EVP_des_ede3_cfb();
    sf_set_possible_null(Res);
    return Res;
}

const EVP_MD* EVP_sha1() {
    const EVP_MD* Res = NULL;
    Res = EVP_sha1();
    sf_set_possible_null(Res);
    return Res;
}

void OCSP_RESPBYTES_free(OCSP_RESPBYTES* Res) {
    if (Res != NULL) {
        OPENSSL_free(Res);
        sf_delete(Res, MALLOC_CATEGORY);
    }
}

void EVP_PKEY_meth_set_cleanup(EVP_PKEY_METHOD *pmeth, void (*cleanup)(EVP_PKEY_CTX *ctx))
{
    sf_set_trusted_sink_ptr(pmeth);
    sf_set_trusted_sink_ptr(cleanup);
    pmeth->cleanup = cleanup;
}

int BN_abs_is_word(const BIGNUM *a, const unsigned long w)
{
    sf_set_must_be_not_null(a, BN_ABS_IS_WORD_OF_NULL);
    sf_set_tainted(w);
    return BN_is_word(a, w);
}

const EVP_CIPHER* EVP_aria_256_ofb()
{
    const EVP_CIPHER *cipher = EVP_aria_256_ofb();
    sf_set_lib_arg_type(cipher, "EVP_CIPHER");
    return cipher;
}

int ASN1_STRING_cmp(const ASN1_STRING *a, const ASN1_STRING *b)
{
    sf_set_must_be_not_null(a, ASN1_STRING_CMP_OF_NULL);
    sf_set_must_be_not_null(b, ASN1_STRING_CMP_OF_NULL);
    return ASN1_STRING_cmp(a, b);
}

void PROFESSION_INFO_free(PROFESSION_INFO *p)
{
    sf_set_must_be_not_null(p, PROFESSION_INFO_FREE_OF_NULL);
    OPENSSL_free(p);
}

void i2d_DSAPrivateKey(const DSA *a, unsigned char **pp)
{
    int res = 0;
    sf_set_trusted_sink_int(pp);
    sf_set_possible_null(a);
    sf_set_possible_null(*pp);
    sf_set_alloc_possible_null(*pp, *pp);
    sf_new(*pp, PAGES_MEMORY_CATEGORY);
    sf_set_buf_size(*pp, *pp);
    sf_lib_arg_type(*pp, "MallocCategory");
    sf_bitcopy(*pp, a);
    res = M_i2d_DSAPrivateKey(a, pp);
    sf_overwrite(*pp);
    sf_set_errno_if(res <= 0);
    return res;
}

int X509_PUBKEY_set(X509_PUBKEY **x, EVP_PKEY *pkey)
{
    int res = 0;
    sf_set_possible_null(x);
    sf_set_possible_null(*x);
    sf_set_possible_null(pkey);
    sf_set_alloc_possible_null(*x, *x);
    sf_new(*x, PAGES_MEMORY_CATEGORY);
    sf_set_buf_size(*x, *x);
    sf_lib_arg_type(*x, "MallocCategory");
    sf_bitcopy(*x, pkey);
    res = M_X509_PUBKEY_set(x, pkey);
    sf_overwrite(*x);
    sf_set_errno_if(res <= 0);
    return res;
}

int OPENSSL_sk_find_all(OPENSSL_STACK *stack, const void *data, int *pnum)
{
    int res = 0;
    sf_set_possible_null(stack);
    sf_set_possible_null(data);
    sf_set_possible_null(pnum);
    res = M_OPENSSL_sk_find_all(stack, data, pnum);
    sf_set_errno_if(res <= 0);
    return res;
}

unsigned long X509_NAME_hash_ex(const X509_NAME *name, OSSL_LIB_CTX *ctx, const char *propq, int *ok)
{
    unsigned long res = 0;
    sf_set_possible_null(name);
    sf_set_possible_null(ctx);
    sf_set_possible_null(propq);
    sf_set_possible_null(ok);
    res = M_X509_NAME_hash_ex(name, ctx, propq, ok);
    sf_set_errno_if(res == 0);
    return res;
}

int EC_GROUP_get_pentanomial_basis(const EC_GROUP *group, unsigned int *k1, unsigned int *k2, unsigned int *k3)
{
    int res = 0;
    sf_set_possible_null(group);
    sf_set_possible_null(k1);
    sf_set_possible_null(k2);
    sf_set_possible_null(k3);
    res = M_EC_GROUP_get_pentanomial_basis(group, k1, k2, k3);
    sf_set_errno_if(res <= 0);
    return res;
}
int PEM_bytes_read_bio(unsigned char**, long*,  char**, const char*, BIO*, pem_password_cb*, void*);

int SSL_in_init(const SSL*);

int RAND_poll();

int SSL_get_all_async_fds(SSL*, int*, size_t*);


ENGINE* ENGINE_get_digest_engine(int nid) {
    ENGINE* Res = NULL;
    sf_set_must_be_not_null(Res, ENGINE_GET_DIGEST_ENGINE_OF_NULL);
    sf_set_errno_if(Res == NULL, ENGINE_GET_DIGEST_ENGINE_FAILURE);
    return Res;
}

void BN_CTX_end(BN_CTX* ctx) {
    sf_set_must_be_not_null(ctx, BN_CTX_END_OF_NULL);
    sf_no_errno_if(ctx != NULL);
}

NETSCAPE_CERT_SEQUENCE* PEM_read_NETSCAPE_CERT_SEQUENCE(FILE* fp, NETSCAPE_CERT_SEQUENCE** x, pem_password_cb* cb, void* u) {
    NETSCAPE_CERT_SEQUENCE* Res = NULL;
    sf_set_must_be_not_null(fp, PEM_READ_NETSCAPE_CERT_SEQUENCE_OF_NULL);
    sf_set_errno_if(Res == NULL, PEM_READ_NETSCAPE_CERT_SEQUENCE_FAILURE);
    return Res;
}

unsigned long ERR_peek_error_all(const char** file, int* line, const char** data, const char** flags, int* (error)) {
    unsigned long Res = 0;
    sf_set_must_be_not_null(file, ERR_PEEK_ERROR_ALL_OF_NULL);
    sf_set_must_be_not_null(line, ERR_PEEK_ERROR_ALL_OF_NULL);
    sf_set_must_be_not_null(data, ERR_PEEK_ERROR_ALL_OF_NULL);
    sf_set_must_be_not_null(flags, ERR_PEEK_ERROR_ALL_OF_NULL);
    sf_set_must_be_not_null(error, ERR_PEEK_ERROR_ALL_OF_NULL);
    sf_set_errno_if(Res == 0, ERR_PEEK_ERROR_ALL_FAILURE);
    return Res;
}

const SSL_METHOD* TLSv1_client_method() {
    const SSL_METHOD* Res = NULL;
    sf_set_must_be_not_null(Res, TLSv1_CLIENT_METHOD_OF_NULL);
    sf_set_errno_if(Res == NULL, TLSv1_CLIENT_METHOD_FAILURE);
    return Res;
}

void X509_STORE_CTX_set_cert(X509_STORE_CTX* ctx, X509* x) {
    sf_set_must_be_not_null(ctx, SET_CERT_OF_NULL);
    sf_set_must_be_not_null(x, SET_CERT_OF_NULL);
    ctx->cert = x;
}

stack_st_SSL_CIPHER* SSL_get_ciphers(const SSL* s) {
    sf_set_must_be_not_null(s, GET_CIPHERS_OF_NULL);
    return s->ciphers;
}

const char* OPENSSL_info(int t) {
    sf_set_must_be_not_null(t, OPENSSL_INFO_OF_NULL);
    return "info string"; // Replace with actual info string
}

const EVP_CIPHER* EVP_camellia_256_cfb128() {
    return EVP_camellia_256_cfb128();
}

int X509_CRL_get_ext_count(const X509_CRL* crl) {
    sf_set_must_be_not_null(crl, GET_EXT_COUNT_OF_NULL);
    return sk_X509_EXTENSION_num(crl->crl->extensions);
}

const char* SSL_alert_desc_string_long(int val) {
    const char* Res = NULL;
    Res = SSL_alert_desc_string_long(val);
    sf_set_must_be_not_null(Res, "SSL_alert_desc_string_long");
    sf_null_terminated(Res);
    return Res;
}

int SHA224_Final(unsigned char* md, SHA256_CTX* c) {
    int Res = 0;
    Res = SHA224_Final(md, c);
    sf_set_errno_if(Res == 0, "SHA224_Final");
    return Res;
}

void SSL_CTX_set_cert_verify_callback(SSL_CTX* ctx, int (*cb)(X509_STORE_CTX*, void*), void* arg) {
    SSL_CTX_set_cert_verify_callback(ctx, cb, arg);
    sf_set_tainted(ctx);
    sf_password_use(arg);
}

int EVP_PKEY_encapsulate_init(EVP_PKEY_CTX* ctx, const OSSL_PARAM params[]) {
    int Res = 0;
    Res = EVP_PKEY_encapsulate_init(ctx, params);
    sf_set_errno_if(Res == 0, "EVP_PKEY_encapsulate_init");
    return Res;
}

HMAC_CTX* HMAC_CTX_new() {
    HMAC_CTX* Res = NULL;
    Res = HMAC_CTX_new();
    sf_set_alloc_possible_null(Res);
    return Res;
}
int EVP_PKEY_CTX_get_ecdh_kdf_type(EVP_PKEY_CTX* ctx);

int SSL_set_ex_data(SSL* s, int idx, void* arg);

char* BN_bn2hex(const BIGNUM* bn);

EVP_CIPHER* EVP_CIPHER_fetch(OSSL_LIB_CTX* ctx, const char* name, const char* properties);

int BIO_snprintf(char* buf, size_t n, const char* format, ...);


BIGNUM* BN_get_rfc3526_prime_2048(BIGNUM* Res) {
    Res = NULL;
    // function body
    return Res;
}

void SSL_CONF_CTX_free(SSL_CONF_CTX* Res) {
    Res = NULL;
    // function body
}

int i2d_PKCS8PrivateKey_fp(FILE* Res, const EVP_PKEY* pkey, const EVP_CIPHER* cipher, const char* pass, int passlen, pem_password_cb* cb, void* u) {
    Res = NULL;
    // function body
    return Res;
}

int i2d_ECPrivateKey_fp(FILE* Res, const EC_KEY* eckey) {
    Res = NULL;
    // function body
    return Res;
}

int OPENSSL_INIT_set_config_appname(OPENSSL_INIT_SETTINGS* Res, const char* config_appname) {
    Res = NULL;
    // function body
    return Res;
}
int SSL_CTX_set_srp_strength(SSL_CTX*, int);

void* X509_STORE_get_ex_data(const X509_STORE*, int);

int PEM_write_DSAparams(FILE*, const DSA*);

stack_st_X509_ATTRIBUTE* X509at_add1_attr_by_NID(stack_st_X509_ATTRIBUTE**, int, int, const unsigned char*, int);

int OCSP_request_add1_nonce(OCSP_REQUEST*, unsigned char*, int);


// Specification for SSL_get_SSL_CTX
SSL_CTX* SSL_get_SSL_CTX(const SSL* s) {
    SSL_CTX* Res = NULL;
    sf_set_trusted_sink_ptr(Res);
    sf_set_alloc_possible_null(Res);
    return Res;
}

// Specification for SCT_set_log_entry_type
int SCT_set_log_entry_type(SCT* s, ct_log_entry_type_t type) {
    int Res = 0;
    sf_set_errno_if(Res == 0);
    return Res;
}

// Specification for X509_STORE_CTX_get_get_crl
X509_STORE_CTX_get_crl_fn X509_STORE_CTX_get_get_crl(const X509_STORE_CTX* ctx) {
    X509_STORE_CTX_get_crl_fn Res = NULL;
    sf_set_possible_null(Res);
    return Res;
}

// Specification for EC_POINT_get_affine_coordinates_GFp
int EC_POINT_get_affine_coordinates_GFp(const EC_GROUP* group, const EC_POINT* point, BIGNUM* x, BIGNUM* y, BN_CTX* ctx) {
    int Res = 0;
    sf_set_errno_if(Res == 0);
    return Res;
}

// Specification for i2d_ASN1_PRINTABLESTRING
int i2d_ASN1_PRINTABLESTRING(const ASN1_PRINTABLESTRING* a, unsigned char** pp) {
    int Res = 0;
    sf_set_errno_if(Res == 0);
    return Res;
}

int EC_POINT_invert(const EC_GROUP *group, EC_POINT *point, BN_CTX *ctx) {
    int res = 0;
    sf_set_must_be_not_null(group, INVERT_OF_NULL);
    sf_set_must_be_not_null(point, INVERT_OF_NULL);
    sf_set_must_be_not_null(ctx, INVERT_OF_NULL);
    sf_set_errno_if(res == 0, INVERT_FAILURE);
    return res;
}

const SSL_METHOD* DTLSv1_method() {
    const SSL_METHOD* res = NULL;
    sf_set_must_be_not_null(res, DTLSv1_METHOD_FAILURE);
    return res;
}

const stack_st_X509_NAME* SSL_CTX_get0_CA_list(const SSL_CTX *ctx) {
    const stack_st_X509_NAME* res = NULL;
    sf_set_must_be_not_null(ctx, CA_LIST_FAILURE);
    sf_set_possible_null(res);
    return res;
}

ASN1_BMPSTRING* d2i_ASN1_BMPSTRING(ASN1_BMPSTRING **a, const unsigned char **in, long len) {
    ASN1_BMPSTRING* res = NULL;
    sf_set_must_be_not_null(a, D2I_ASN1_BMPSTRING_FAILURE);
    sf_set_must_be_not_null(in, D2I_ASN1_BMPSTRING_FAILURE);
    sf_set_errno_if(len < 0, D2I_ASN1_BMPSTRING_FAILURE);
    sf_set_possible_null(res);
    return res;
}

X509* PEM_read_bio_X509_AUX(BIO *bp, X509 **x, pem_password_cb *cb, void *u) {
    X509* res = NULL;
    sf_set_must_be_not_null(bp, PEM_READ_BIO_X509_AUX_FAILURE);
    sf_set_must_be_not_null(x, PEM_READ_BIO_X509_AUX_FAILURE);
    sf_password_use(cb);
    sf_set_errno_if(res == NULL, PEM_READ_BIO_X509_AUX_FAILURE);
    return res;
}

const EVP_CIPHER* EVP_des_ede_ecb() {
    const EVP_CIPHER* Res = NULL;
    Res = EVP_des_ede_ecb();
    sf_set_possible_null(Res);
    return Res;
}

int SSL_CTX_set_srp_password(SSL_CTX* ctx, char* password) {
    int Res = 0;
    sf_password_use(password);
    Res = SSL_CTX_set_srp_password(ctx, password);
    sf_set_errno_if(Res <= 0);
    return Res;
}

RSA* d2i_RSAPublicKey(RSA** rsa, const unsigned char** in, long len) {
    RSA* Res = NULL;
    Res = d2i_RSAPublicKey(rsa, in, len);
    sf_set_alloc_possible_null(Res);
    return Res;
}

int SSL_SESSION_set1_hostname(SSL_SESSION* s, const char* hostname) {
    int Res = 0;
    Res = SSL_SESSION_set1_hostname(s, hostname);
    sf_set_errno_if(Res <= 0);
    return Res;
}

X509_LOOKUP_ctrl_fn X509_LOOKUP_meth_get_ctrl(const X509_LOOKUP_METHOD* method) {
    X509_LOOKUP_ctrl_fn Res = NULL;
    Res = X509_LOOKUP_meth_get_ctrl(method);
    sf_set_possible_null(Res);
    return Res;
}
int i2d_PKCS8PrivateKey_nid_fp(FILE*, const EVP_PKEY*, int, const char*, int, pem_password_cb*, void*);

ASN1_UTF8STRING* d2i_ASN1_UTF8STRING(ASN1_UTF8STRING**, const unsigned char**, long);

PKCS7* SMIME_read_PKCS7_ex(BIO*, BIO**, PKCS7**);

int i2d_RSAPrivateKey_fp(FILE*, const RSA*);

OSSL_PARAM OSSL_PARAM_construct_int64(const char*, int64_t*);


void ERR_set_mark() {
    int Res = 0;
    sf_set_errno_if(Res, ERR_set_mark);
}

int EC_GROUP_check_named_curve(const EC_GROUP *group, int nid, BN_CTX *ctx) {
    int Res = 0;
    sf_set_errno_if(Res, EC_GROUP_check_named_curve);
    return Res;
}

const EVP_CIPHER* EVP_aes_128_gcm() {
    const EVP_CIPHER *Res = NULL;
    sf_set_errno_if(Res, EVP_aes_128_gcm);
    return Res;
}

OSSL_PARAM OSSL_PARAM_construct_octet_ptr(const char *key, void **buf, size_t sz) {
    OSSL_PARAM Res = {NULL, 0, NULL, 0};
    sf_set_errno_if(Res.data_size, OSSL_PARAM_construct_octet_ptr);
    return Res;
}

void ENGINE_register_all_DSA() {
    sf_terminate_path(ENGINE_register_all_DSA);
}

void EVP_PKEY_meth_get_signctx(const EVP_PKEY_METHOD *pmeth, int (**signctx)(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx), int (**signctx_init)(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx))
{
    int *Res = NULL;
    sf_set_trusted_sink_ptr(pmeth);
    sf_set_trusted_sink_ptr(ctx);
    sf_set_trusted_sink_ptr(mctx);
    sf_set_trusted_sink_ptr(signctx);
    sf_set_trusted_sink_ptr(signctx_init);
    sf_set_errno_if(pmeth == NULL, EINVAL);
    sf_set_errno_if(ctx == NULL, EINVAL);
    sf_set_errno_if(mctx == NULL, EINVAL);
    sf_set_errno_if(signctx == NULL, EINVAL);
    sf_set_errno_if(signctx_init == NULL, EINVAL);
    Res = pmeth->signctx;
    sf_set_possible_null(Res);
    *signctx = Res;
    Res = pmeth->signctx_init;
    sf_set_possible_null(Res);
    *signctx_init = Res;
}

const OSSL_PARAM *EVP_CIPHER_CTX_gettable_params(EVP_CIPHER_CTX *ctx)
{
    const OSSL_PARAM *Res = NULL;
    sf_set_trusted_sink_ptr(ctx);
    sf_set_errno_if(ctx == NULL, EINVAL);
    Res = ctx->gettable_params;
    sf_set_possible_null(Res);
    return Res;
}

ASN1_STRING *ASN1_STRING_dup(const ASN1_STRING *a)
{
    ASN1_STRING *Res = NULL;
    sf_set_trusted_sink_ptr(a);
    sf_set_errno_if(a == NULL, EINVAL);
    Res = ASN1_STRING_type_new(a->type);
    sf_set_possible_null(Res);
    if (Res != NULL)
    {
        if (!ASN1_STRING_set(Res, a->data, a->length))
        {
            ASN1_STRING_free(Res);
            Res = NULL;
        }
    }
    return Res;
}

int X509_NAME_entry_count(const X509_NAME *name)
{
    int Res = 0;
    sf_set_trusted_sink_ptr(name);
    sf_set_errno_if(name == NULL, EINVAL);
    Res = sk_X509_NAME_ENTRY_num(name->entries);
    sf_set_possible_negative(Res);
    return Res;
}

int EVP_PKEY_sign_init(EVP_PKEY_CTX *ctx)
{
    int Res = 0;
    sf_set_trusted_sink_ptr(ctx);
    sf_set_errno_if(ctx == NULL, EINVAL);
    Res = ctx->sign_init;
    sf_set_possible_negative(Res);
    return Res;
}

int i2d_PBE2PARAM(const PBE2PARAM* a, unsigned char** pp)
{
    int res = 0;
    sf_set_must_be_not_null(a, PARAMETER_ERROR);
    sf_set_must_be_not_null(pp, PARAMETER_ERROR);
    sf_set_tainted(a);
    sf_set_errno_if(res <= 0, ERR_GET_REASON(ERR_peek_error()));
    return res;
}

int i2d_PKCS8PrivateKey_bio(BIO* bp, const EVP_PKEY* x, const EVP_CIPHER* enc, const char* kstr, int klen, pem_password_cb* cb, void* u)
{
    int res = 0;
    sf_set_must_be_not_null(bp, PARAMETER_ERROR);
    sf_set_must_be_not_null(x, PARAMETER_ERROR);
    sf_password_use(kstr);
    sf_set_errno_if(res <= 0, ERR_GET_REASON(ERR_peek_error()));
    return res;
}

X509_ALGOR* PKCS5_pbe2_set_scrypt(const EVP_CIPHER* cipher, const unsigned char* salt, int saltlen, unsigned char* iv, uint64_t N, uint64_t r, uint64_t p)
{
    X509_ALGOR* res = NULL;
    sf_set_must_be_not_null(cipher, PARAMETER_ERROR);
    sf_set_must_be_not_null(salt, PARAMETER_ERROR);
    sf_set_must_be_not_null(iv, PARAMETER_ERROR);
    sf_set_errno_if(res == NULL, ERR_GET_REASON(ERR_peek_error()));
    return res;
}

void* SSL_get_ex_data(const SSL* ssl, int idx)
{
    void* res = NULL;
    sf_set_must_be_not_null(ssl, PARAMETER_ERROR);
    sf_set_errno_if(res == NULL, ERR_GET_REASON(ERR_peek_error()));
    return res;
}

int X509_NAME_get_index_by_NID(const X509_NAME* name, int nid, int lastpos)
{
    int res = -1;
    sf_set_must_be_not_null(name, PARAMETER_ERROR);
    sf_set_errno_if(res < 0, ERR_GET_REASON(ERR_peek_error()));
    return res;
}

UI_METHOD* UI_UTIL_wrap_read_pem_callback(pem_password_cb* cb, int len) {
    UI_METHOD* Res = NULL;
    sf_set_trusted_sink_int(len);
    sf_malloc_arg(Res, UI_METHOD);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_lib_arg_type(Res, "UI_METHOD");
    return Res;
}

int EVP_PKEY_CTX_set_dh_kdf_outlen(EVP_PKEY_CTX* ctx, int len) {
    int Res = 0;
    sf_set_trusted_sink_int(len);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int DH_bits(const DH* dh) {
    int Res = 0;
    sf_set_errno_if(Res <= 0);
    return Res;
}

const EVP_CIPHER* EVP_aria_128_cfb8() {
    const EVP_CIPHER* Res = NULL;
    sf_overwrite(Res);
    sf_lib_arg_type(Res, "EVP_CIPHER");
    return Res;
}

void SSL_set0_CA_list(SSL* s, stack_st_X509_NAME* names) {
    sf_set_tainted(names);
    sf_lib_arg_type(names, "stack_st_X509_NAME");
}
void DSA_clear_flags(DSA* dsa, int flags);

void PKCS7_DIGEST_free(PKCS7_DIGEST* digest);

const ASN1_ITEM* ASN1_ITEM_lookup(const char* name);

void ADMISSIONS_set0_admissionAuthority(ADMISSIONS* adm, GENERAL_NAME* name);

int EVP_KEM_is_a(const EVP_KEM* kem, const char* name);


const DSA_METHOD* DSA_OpenSSL()
{
    const DSA_METHOD *Res = NULL;
    Res = DSA_OpenSSL();
    sf_lib_arg_type(Res, "DSA_METHOD");
    return Res;
}

int ENGINE_set_DH(ENGINE* e, const DH_METHOD* dh)
{
    int Res = 0;
    Res = ENGINE_set_DH(e, dh);
    sf_set_errno_if(Res <= 0, "ENGINE_set_DH");
    return Res;
}

int SSL_CTX_up_ref(SSL_CTX* ctx)
{
    int Res = 0;
    Res = SSL_CTX_up_ref(ctx);
    sf_set_errno_if(Res <= 0, "SSL_CTX_up_ref");
    return Res;
}

int BN_is_prime(const BIGNUM* bn, int checks, void (*cb)(int, int, void*), BN_CTX* ctx, void* cb_arg)
{
    int Res = 0;
    Res = BN_is_prime(bn, checks, cb, ctx, cb_arg);
    sf_set_errno_if(Res <= 0, "BN_is_prime");
    return Res;
}

const OSSL_PROVIDER* EVP_MD_get0_provider(const EVP_MD* md)
{
    const OSSL_PROVIDER *Res = NULL;
    Res = EVP_MD_get0_provider(md);
    sf_lib_arg_type(Res, "OSSL_PROVIDER");
    return Res;
}
int X509_STORE_CTX_set_trust(X509_STORE_CTX* ctx, int trust);

int SSL_CIPHER_get_digest_nid(const SSL_CIPHER* cipher);

DSA* PEM_read_DSAPrivateKey(FILE* fp, DSA** dsa, pem_password_cb* cb, void* u);

stack_st_X509* X509_build_chain(X509* x, stack_st_X509* sk, X509_STORE* st, int argc, OSSL_LIB_CTX* libctx, const char* propq);

int UI_dup_info_string(UI* ui, const char* text);


stack_st_X509_NAME* SSL_load_client_CA_file_ex(const char* file, OSSL_LIB_CTX* libctx, const char* propq) {
    stack_st_X509_NAME* res = NULL;
    sf_set_tainted(file);
    sf_tocttou_check(file);
    sf_set_trusted_sink_int(file);
    sf_set_must_be_not_null(file, FILE_NAME_NULL);
    sf_set_must_be_not_null(libctx, LIBCTX_NULL);
    sf_set_must_be_not_null(propq, PROPQ_NULL);
    sf_lib_arg_type(libctx, "OSSL_LIB_CTX");
    sf_lib_arg_type(propq, "PROPQ");
    sf_set_errno_if(res == NULL, ERRNO_LOAD_CA_FILE);
    return res;
}

int SSL_set_num_tickets(SSL* s, size_t num) {
    int res;
    sf_set_must_be_not_null(s, SSL_NULL);
    sf_set_errno_if(num == 0, ERRNO_NUM_TICKETS);
    res = SSL_ctrl(s, SSL_CTRL_SET_TLSEXT_TICKET_KEYS, num, NULL);
    sf_set_errno_if(res <= 0, ERRNO_SET_NUM_TICKETS);
    return res;
}

const EVP_CIPHER* EVP_camellia_256_cbc() {
    const EVP_CIPHER* res = EVP_camellia_256_cbc();
    sf_set_errno_if(res == NULL, ERRNO_CIPHER_NOT_FOUND);
    return res;
}

int RSA_meth_get_flags(const RSA_METHOD* meth) {
    int res;
    sf_set_must_be_not_null(meth, RSA_METHOD_NULL);
    res = meth->flags;
    sf_set_errno_if(res == 0, ERRNO_METHOD_FLAGS);
    return res;
}

int EVP_ENCODE_CTX_copy(EVP_ENCODE_CTX* dst, const EVP_ENCODE_CTX* src) {
    int res;
    sf_set_must_be_not_null(dst, EVP_ENCODE_CTX_NULL);
    sf_set_must_be_not_null(src, EVP_ENCODE_CTX_NULL);
    res = EVP_ENCODE_CTX_copy(dst, src);
    sf_set_errno_if(res <= 0, ERRNO_ENCODE_CTX_COPY);
    return res;
}

void USERNOTICE_free(USERNOTICE *notice) {
    sf_set_must_be_not_null(notice, FREE_OF_NULL);
    sf_delete(notice, USERNOTICE_CATEGORY);
}

int SSL_in_before(const SSL *ssl) {
    sf_set_must_be_not_null(ssl, SSL_NULL);
    int res = 0;
    sf_set_errno_if(res, ssl, SSL_ERROR_SYSCALL);
    sf_no_errno_if(res, ssl, SSL_ERROR_NONE);
    return res;
}

OSSL_LIB_CTX* OSSL_LIB_CTX_new() {
    OSSL_LIB_CTX *res = NULL;
    sf_new(res, OSSL_LIB_CTX_CATEGORY);
    return res;
}

int SSL_CTX_set_trust(SSL_CTX *ctx, int trust) {
    sf_set_must_be_not_null(ctx, SSL_CTX_NULL);
    int res = 0;
    sf_set_errno_if(res, ctx, SSL_ERROR_SYSCALL);
    sf_no_errno_if(res, ctx, SSL_ERROR_NONE);
    return res;
}

EVP_MD* EVP_MD_CTX_get1_md(EVP_MD_CTX *ctx) {
    sf_set_must_be_not_null(ctx, EVP_MD_CTX_NULL);
    EVP_MD *res = NULL;
    sf_set_possible_null(res);
    return res;
}

int BIO_read(BIO* bio, void* buf, int len) {
    int res = 0;
    sf_set_trusted_sink_int(len);
    sf_buf_size_limit(buf, len);
    sf_buf_overlap(bio->ptr, buf);
    res = bio->method->bread(bio, buf, len);
    sf_overwrite(buf, len);
    return res;
}

EVP_PKEY* X509_PUBKEY_get(const X509_PUBKEY* pubkey) {
    EVP_PKEY* res = NULL;
    sf_lib_arg_type(pubkey, "X509_PUBKEY");
    res = EVP_PKEY_new();
    sf_new(res, PKEY_MEMORY_CATEGORY);
    sf_lib_arg_type(res, "EVP_PKEY");
    if (pubkey->pkey != NULL) {
        EVP_PKEY_up_ref(pubkey->pkey);
        res = pubkey->pkey;
    }
    sf_set_possible_null(res);
    return res;
}

X509_STORE_CTX_check_crl_fn X509_STORE_CTX_get_check_crl(const X509_STORE_CTX* ctx) {
    X509_STORE_CTX_check_crl_fn res = NULL;
    sf_lib_arg_type(ctx, "X509_STORE_CTX");
    res = ctx->check_crl;
    sf_set_possible_null(res);
    return res;
}

int X509_EXTENSION_set_object(X509_EXTENSION* ext, const ASN1_OBJECT* obj) {
    int res = 0;
    sf_lib_arg_type(ext, "X509_EXTENSION");
    sf_lib_arg_type(obj, "ASN1_OBJECT");
    res = X509_EXTENSION_set_object(ext, obj);
    sf_overwrite(ext, sizeof(X509_EXTENSION));
    return res;
}

X509_ATTRIBUTE* EVP_PKEY_delete_attr(EVP_PKEY* pkey, int idx) {
    X509_ATTRIBUTE* res = NULL;
    sf_lib_arg_type(pkey, "EVP_PKEY");
    sf_set_must_be_not_null(pkey, FREE_OF_NULL);
    res = sk_X509_ATTRIBUTE_delete(pkey->attributes, idx);
    sf_set_possible_null(res);
    return res;
}
void SSL_CTX_set_security_level(SSL_CTX* ctx, int level);

int HMAC_Final(HMAC_CTX* ctx, unsigned char* md, unsigned int* len);

int EC_KEY_set_ex_data(EC_KEY* key, int idx, void* arg);


sf_set_must_be_not_null(key, OSSL_PARAM_CONSTRUCT_BN_KEY_OF_NULL);
sf_set_must_be_not_null(buf, OSSL_PARAM_CONSTRUCT_BN_BUF_OF_NULL);
OSSL_PARAM Res = {NULL, 0, NULL, 0};
ASN1_T61STRING* d2i_ASN1_T61STRING(ASN1_T61STRING** a, const unsigned char** in, long len);


const EVP_CIPHER* EVP_camellia_128_ecb()
{
    const EVP_CIPHER* Res = NULL;
    Res = EVP_camellia_128_ecb();
    sf_set_trusted_sink_ptr(Res);
    return Res;
}

const EVP_CIPHER* EVP_rc4_40()
{
    const EVP_CIPHER* Res = NULL;
    Res = EVP_rc4_40();
    sf_set_trusted_sink_ptr(Res);
    return Res;
}

int X509_CRL_get0_by_serial(X509_CRL* crl, X509_REVOKED** ret, const ASN1_INTEGER* serial)
{
    int Res = 0;
    Res = X509_CRL_get0_by_serial(crl, ret, serial);
    sf_set_errno_if(Res == 0);
    return Res;
}

int EVP_PKEY_cmp(const EVP_PKEY* a, const EVP_PKEY* b)
{
    int Res = 0;
    Res = EVP_PKEY_cmp(a, b);
    sf_set_errno_if(Res == 0);
    return Res;
}

SSL_SESSION* SSL_get1_session(SSL* s)
{
    SSL_SESSION* Res = NULL;
    Res = SSL_get1_session(s);
    sf_set_errno_if(Res == NULL);
    return Res;
}

int i2d_OCSP_BASICRESP(const OCSP_BASICRESP *a, unsigned char **pp)
{
    int ret = 0;
    size_t size = 0;

    sf_set_trusted_sink_int(size);
    size = i2d_OCSP_BASICRESP(a, NULL);
    if (size == 0)
        return 0;

    sf_malloc_arg(pp, size);
    ret = i2d_OCSP_BASICRESP(a, pp);
    sf_overwrite(*pp, size);
    sf_new(*pp, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(ret, *pp);
    sf_set_buf_size(*pp, size);
    sf_lib_arg_type(*pp, "MallocCategory");

    return ret;
}

int EVP_PKEY_set1_RSA(EVP_PKEY *pkey, RSA *key)
{
    int ret = 0;

    ret = EVP_PKEY_set1_RSA(pkey, key);
    sf_set_errno_if(ret <= 0);

    return ret;
}

int SSL_add1_host(SSL *s, const char *name)
{
    int ret = 0;

    ret = SSL_add1_host(s, name);
    sf_set_errno_if(ret <= 0);
    sf_tocttou_check(name);

    return ret;
}

void *CRYPTO_clear_realloc(void *ptr, size_t old_size, size_t new_size, const char *file, int line)
{
    void *ret = NULL;

    sf_set_trusted_sink_int(old_size);
    sf_set_trusted_sink_int(new_size);
    ret = CRYPTO_clear_realloc(ptr, old_size, new_size, file, line);
    sf_overwrite(ret, new_size);
    sf_new(ret, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(ret, new_size);
    sf_set_buf_size(ret, new_size);
    sf_lib_arg_type(ret, "MallocCategory");
    sf_not_acquire_if_eq(ret, NULL);
    sf_delete(ptr, PAGES_MEMORY_CATEGORY);

    return ret;
}

DH *DH_new_method(ENGINE *engine)
{
    DH *ret = NULL;

    ret = DH_new_method(engine);
    sf_set_possible_null(ret);

    return ret;
}

void* EC_KEY_get_ex_data(const EC_KEY* key, int idx) {
    void* Res = NULL;
    sf_set_trusted_sink_int(idx);
    Res = EC_KEY_get_ex_data(key, idx);
    sf_overwrite(Res);
    return Res;
}

void SSL_CONF_CTX_set_ssl(SSL_CONF_CTX* cctx, SSL* ssl) {
    sf_set_trusted_sink_ptr(cctx);
    sf_set_trusted_sink_ptr(ssl);
    SSL_CONF_CTX_set_ssl(cctx, ssl);
}

DSA* DSA_new() {
    DSA* Res = NULL;
    Res = DSA_new();
    sf_overwrite(Res);
    return Res;
}

const char* SSL_get_cipher_list(const SSL* s, int n) {
    const char* Res = NULL;
    sf_set_trusted_sink_int(n);
    Res = SSL_get_cipher_list(s, n);
    sf_overwrite(Res);
    return Res;
}

int ASN1_STRING_to_UTF8(unsigned char** out, const ASN1_STRING* str) {
    int Res = 0;
    sf_set_trusted_sink_ptr(out);
    Res = ASN1_STRING_to_UTF8(out, str);
    sf_overwrite(Res);
    return Res;
}

DH_meth_get_generate_params(const DH_METHOD *dh_meth, int *res)
{
    *res = NULL;
    sf_set_trusted_sink_int(res);
    sf_set_possible_null(res);
    sf_set_possible_null(dh_meth);
    sf_set_possible_null(dh_meth->generate_params);
    sf_set_alloc_possible_null(*res);
    sf_new(*res, PAGES_MEMORY_CATEGORY);
    sf_lib_arg_type(dh_meth, "DH_METHOD");
    sf_lib_arg_type(res, "DH_METHOD");
    return *res;
}

int X509_CRL_cmp(const X509_CRL *a, const X509_CRL *b)
{
    sf_set_must_be_not_null(a, CRL_NULL);
    sf_set_must_be_not_null(b, CRL_NULL);
    sf_lib_arg_type(a, "X509_CRL");
    sf_lib_arg_type(b, "X509_CRL");
    return 0;
}

void EC_KEY_free(EC_KEY *key)
{
    sf_set_must_be_not_null(key, KEY_NULL);
    sf_lib_arg_type(key, "EC_KEY");
    sf_delete(key, KEY_CATEGORY);
    sf_lib_arg_type(key, "EC_KEY");
}

int X509_load_cert_crl_file(X509_LOOKUP *lookup, const char *file, int type)
{
    sf_set_must_be_not_null(lookup, LOOKUP_NULL);
    sf_set_must_be_not_null(file, FILE_NULL);
    sf_lib_arg_type(lookup, "X509_LOOKUP");
    sf_lib_arg_type(file, "FILE");
    sf_tocttou_check(file);
    return 0;
}

void DH_get0_key(const DH *dh, const BIGNUM **pub_key, const BIGNUM **priv_key)
{
    sf_set_must_be_not_null(dh, DH_NULL);
    sf_lib_arg_type(dh, "DH");
    sf_set_possible_null(*pub_key);
    sf_set_possible_null(*priv_key);
    sf_lib_arg_type(*pub_key, "BIGNUM");
    sf_lib_arg_type(*priv_key, "BIGNUM");
}

const EVP_CIPHER* EVP_rc2_ofb() {
    const EVP_CIPHER* Res = NULL;
    Res = EVP_rc2_ofb();
    sf_set_possible_null(Res);
    return Res;
}

int X509_REQ_set_pubkey(X509_REQ* req, EVP_PKEY* pkey) {
    int Res = 0;
    Res = X509_REQ_set_pubkey(req, pkey);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int DSAparams_print_fp(FILE* fp, const DSA* dsa) {
    int Res = 0;
    Res = DSAparams_print_fp(fp, dsa);
    sf_set_errno_if(Res <= 0);
    return Res;
}

const unsigned char* OBJ_get0_data(const ASN1_OBJECT* obj) {
    const unsigned char* Res = NULL;
    Res = OBJ_get0_data(obj);
    sf_set_possible_null(Res);
    return Res;
}

DH* PEM_read_bio_DHparams(BIO* bio, DH** dh, pem_password_cb* cb, void* u) {
    DH* Res = NULL;
    Res = PEM_read_bio_DHparams(bio, dh, cb, u);
    sf_set_possible_null(Res);
    return Res;
}

int CRYPTO_atomic_load(uint64_t* object, uint64_t* value, CRYPTO_RWLOCK* lock) {
    int res = 0;
    sf_set_trusted_sink_int(object);
    sf_set_trusted_sink_int(value);
    sf_set_trusted_sink_ptr(lock);
    sf_set_must_be_not_null(object, LOAD_OF_NULL);
    sf_set_must_be_not_null(value, LOAD_OF_NULL);
    sf_set_must_be_not_null(lock, LOAD_OF_NULL);
    sf_overwrite(value);
    return res;
}

int DH_test_flags(const DH* dh, int flags) {
    int res = 0;
    sf_set_must_be_not_null(dh, TEST_FLAGS_OF_NULL);
    sf_set_trusted_sink_int(flags);
    sf_overwrite(res);
    return res;
}

int RSA_size(const RSA* rsa) {
    int res = 0;
    sf_set_must_be_not_null(rsa, SIZE_OF_NULL);
    sf_overwrite(res);
    return res;
}

void X509_STORE_set_lookup_crls(X509_STORE* store, X509_STORE_CTX_lookup_crls_fn lookup_crls) {
    sf_set_must_be_not_null(store, SET_LOOKUP_CRLS_OF_NULL);
    sf_set_trusted_sink_ptr(lookup_crls);
}

EVP_PKEY* PEM_read_bio_PrivateKey(BIO* bio, EVP_PKEY** pkey, pem_password_cb* cb, void* u) {
    EVP_PKEY* res = NULL;
    sf_set_must_be_not_null(bio, READ_BIO_PRIVATE_KEY_OF_NULL);
    sf_set_trusted_sink_ptr(pkey);
    sf_set_trusted_sink_ptr(cb);
    sf_set_trusted_sink_ptr(u);
    sf_set_possible_null(res);
    return res;
}

void d2i_ASN1_TIME(ASN1_TIME** out, const unsigned char** in, long len) {
    ASN1_TIME* Res = NULL;
    sf_set_trusted_sink_int(len);
    sf_malloc_arg(Res, len);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res, len);
    sf_lib_arg_type(Res, "ASN1TimeCategory");
    *out = Res;
}

void ASN1_STRING_type_new(ASN1_STRING* Res, int type) {
    sf_set_trusted_sink_int(type);
    sf_malloc_arg(Res, type);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res, type);
    sf_lib_arg_type(Res, "ASN1StringCategory");
}

void SSL_CTX_set_max_early_data(SSL_CTX* ctx, uint32_t max_early_data) {
    sf_set_trusted_sink_int(max_early_data);
    sf_must_not_be_release(ctx);
    sf_set_must_be_positive(max_early_data);
    sf_lib_arg_type(ctx, "SSL_CTX_Category");
}

void RSA_get0_dmq1(const BIGNUM* Res, const RSA* rsa) {
    sf_must_not_be_release(rsa);
    sf_lib_arg_type(rsa, "RSA_Category");
    sf_lib_arg_type(Res, "BIGNUM_Category");
}

void EC_KEY_set_flags(EC_KEY* key, int flags) {
    sf_set_trusted_sink_int(flags);
    sf_must_not_be_release(key);
    sf_lib_arg_type(key, "EC_KEY_Category");
}
int RSA_meth_set_keygen(RSA_METHOD *meth, int (*keygen_func);

int (*UI_method_get_reader(const UI_METHOD *method);

int DSA_bits(const DSA *dsa);

int SSL_has_pending(const SSL *ssl);

void* UI_get_ex_data(const UI *ui, int idx);


DH* d2i_DHxparams(DH** a, const unsigned char** pp, long length)
{
    DH* Res = NULL;
    sf_set_trusted_sink_int(length);
    sf_malloc_arg(a, PAGES_MEMORY_CATEGORY);
    Res = d2i_DHxparams(a, pp, length);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    return Res;
}

unsigned char* SHA512(const unsigned char* d, size_t n, unsigned char* md)
{
    unsigned char* Res = NULL;
    sf_set_trusted_sink_int(n);
    sf_malloc_arg(md, PAGES_MEMORY_CATEGORY);
    Res = SHA512(d, n, md);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    return Res;
}

X509_STORE_CTX_check_crl_fn X509_STORE_get_check_crl(const X509_STORE* ctx)
{
    X509_STORE_CTX_check_crl_fn Res = NULL;
    Res = X509_STORE_get_check_crl(ctx);
    sf_set_possible_null(Res);
    return Res;
}

int PEM_write_PKCS7(FILE* fp, const PKCS7* x)
{
    int Res = 0;
    sf_set_must_not_be_null(fp, FREE_OF_NULL);
    Res = PEM_write_PKCS7(fp, x);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int PEM_write_bio_PKCS8_PRIV_KEY_INFO(BIO* bp, const PKCS8_PRIV_KEY_INFO* x)
{
    int Res = 0;
    sf_set_must_not_be_null(bp, FREE_OF_NULL);
    Res = PEM_write_bio_PKCS8_PRIV_KEY_INFO(bp, x);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int X509_LOOKUP_meth_set_get_by_fingerprint(X509_LOOKUP_METHOD *method, X509_LOOKUP_get_by_fingerprint_fn get_by_fingerprint) {
    int res = 0;
    sf_set_must_be_not_null(method, SET_METHOD_OF_NULL);
    sf_set_must_be_not_null(get_by_fingerprint, GET_BY_FINGERPRINT_OF_NULL);
    sf_set_errno_if(res == 0, SET_METHOD_FAILURE);
    return res;
}

BIGNUM* BN_dup(const BIGNUM *a) {
    BIGNUM *res = NULL;
    sf_set_must_be_not_null(a, DUP_OF_NULL);
    sf_set_errno_if(res == NULL, DUP_FAILURE);
    return res;
}

int i2d_ISSUER_SIGN_TOOL(const ISSUER_SIGN_TOOL *issuer_sign_tool, unsigned char **out) {
    int res = 0;
    sf_set_must_be_not_null(issuer_sign_tool, I2D_OF_NULL);
    sf_set_must_be_not_null(out, I2D_OUT_OF_NULL);
    sf_set_errno_if(res <= 0, I2D_FAILURE);
    return res;
}

int SSL_set_generate_session_id(SSL *ssl, GEN_SESSION_CB cb) {
    int res = 0;
    sf_set_must_be_not_null(ssl, SET_GENERATE_SESSION_ID_OF_NULL);
    sf_set_must_be_not_null(cb, SET_GENERATE_SESSION_ID_CB_OF_NULL);
    sf_set_errno_if(res == 0, SET_GENERATE_SESSION_ID_FAILURE);
    return res;
}

int RSA_padding_add_PKCS1_type_2(unsigned char *to, int tlen, const unsigned char *f, int fl) {
    int res = 0;
    sf_set_must_be_not_null(to, PADDING_ADD_OF_NULL);
    sf_set_must_be_not_null(f, PADDING_ADD_F_OF_NULL);
    sf_set_errno_if(res <= 0, PADDING_ADD_FAILURE);
    return res;
}

void BN_priv_rand_range_ex(BIGNUM *r, const BIGNUM *range, unsigned int n, BN_CTX *ctx) {
    int Res = 0;
    sf_set_trusted_sink_int(n);
    sf_set_tainted(range);
    sf_set_must_not_be_null(ctx);
    sf_set_must_not_be_null(r);
    Res = BN_rand_range_ex(r, range, n, ctx);
    sf_set_errno_if(Res == 0);
    return Res;
}

int X509_check_ip(X509 *x, const unsigned char *ip, size_t len, unsigned int flags) {
    int Res = 0;
    sf_set_tainted(ip);
    sf_set_must_not_be_null(x);
    Res = X509_check_ip_asc(x, (const char *)ip, len, flags);
    sf_set_errno_if(Res == 0);
    return Res;
}

int SSL_extension_supported(unsigned int ext_type) {
    int Res = 0;
    Res = SSL_extension_supported_0(ext_type);
    return Res;
}

int OSSL_HTTP_proxy_connect(BIO *bio, const char *server, const char *port, const char *proxyuser, const char *proxypass, int timeout, BIO *bio_err, const char *opt_proxy_header) {
    int Res = 0;
    sf_set_tainted(server);
    sf_set_tainted(port);
    sf_set_tainted(proxyuser);
    sf_set_tainted(proxypass);
    sf_set_tainted(opt_proxy_header);
    sf_set_must_not_be_null(bio);
    sf_set_must_not_be_null(bio_err);
    Res = ossl_http_proxy_connect(bio, server, port, proxyuser, proxypass, timeout, bio_err, opt_proxy_header);
    sf_set_errno_if(Res == 0);
    return Res;
}

int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, ENGINE *impl, const unsigned char *key, const unsigned char *iv) {
    int Res = 0;
    sf_set_tainted(key);
    sf_set_tainted(iv);
    sf_set_must_not_be_null(ctx);
    sf_set_must_not_be_null(cipher);
    Res = EVP_DecryptInit_ex_0(ctx, cipher, impl, key, iv);
    sf_set_errno_if(Res == 0);
    return Res;
}

void SSL_CTX_set_stateless_cookie_generate_cb(SSL_CTX* ctx, int (*cb)(SSL*, unsigned char*, size_t*))
{
    sf_set_trusted_sink_int(ctx);
    sf_set_trusted_sink_ptr(cb);
    sf_set_tainted(ctx);
    sf_set_tainted(cb);
    sf_set_must_not_be_null(ctx);
    sf_set_must_not_be_null(cb);
    sf_set_possible_null(ctx);
    sf_set_possible_null(cb);
}

const OSSL_PROVIDER* EVP_PKEY_get0_provider(const EVP_PKEY* pkey)
{
    sf_set_must_not_be_null(pkey);
    sf_set_possible_null(pkey);
    const OSSL_PROVIDER* res = NULL;
    sf_set_possible_null(res);
    return res;
}

const dsa_st* EVP_PKEY_get0_DSA(const EVP_PKEY* pkey)
{
    sf_set_must_not_be_null(pkey);
    sf_set_possible_null(pkey);
    const dsa_st* res = NULL;
    sf_set_possible_null(res);
    return res;
}

int EVP_CIPHER_meth_set_flags(EVP_CIPHER* cipher, unsigned long flags)
{
    sf_set_must_not_be_null(cipher);
    sf_set_possible_null(cipher);
    sf_set_tainted(flags);
    int res = 0;
    sf_set_possible_null(res);
    return res;
}

int X509_CRL_add0_revoked(X509_CRL* crl, X509_REVOKED* rev)
{
    sf_set_must_not_be_null(crl);
    sf_set_must_not_be_null(rev);
    sf_set_possible_null(crl);
    sf_set_possible_null(rev);
    int res = 0;
    sf_set_possible_null(res);
    return res;
}
int OSSL_PARAM_get_int32(const OSSL_PARAM*, int32_t*);

int SSL_write_early_data(SSL*, const void*, size_t, size_t*);

int ASN1_item_verify_ex(const ASN1_ITEM*, const X509_ALGOR*, const ASN1_BIT_STRING*, const void*, const ASN1_OCTET_STRING*, EVP_PKEY*, OSSL_LIB_CTX*, const char*);

DSA_METHOD* DSA_meth_new(const char*, int);

size_t SSL_client_hello_get0_session_id(SSL*, const unsigned char**);

int EVP_PKEY_CTX_set_ecdh_kdf_type(EVP_PKEY_CTX* ctx, int kdf_type);

int i2d_ASN1_NULL(const ASN1_NULL* a, unsigned char** pp);

int ASN1_INTEGER_get_int64(int64_t* pr, const ASN1_INTEGER* a);

int ASYNC_start_job(ASYNC_JOB** job, ASYNC_WAIT_CTX* ctx, int* ret, int (void*);

int OBJ_txt2nid(const char* s);


const EVP_CIPHER* EVP_rc4()
{
    const EVP_CIPHER* Res = NULL;
    // Additional implementation here
    return Res;
}

void EVP_EncodeFinal(EVP_ENCODE_CTX* ctx, unsigned char* out, int* outl)
{
    // Additional implementation here
    // No return value, so no need to assign Res
}

OPENSSL_sk_compfunc OPENSSL_sk_set_cmp_func(OPENSSL_STACK* st, OPENSSL_sk_compfunc cmp)
{
    OPENSSL_sk_compfunc Res = NULL;
    // Additional implementation here
    return Res;
}

const rsa_st* EVP_PKEY_get0_RSA(const EVP_PKEY* pkey)
{
    const rsa_st* Res = NULL;
    // Additional implementation here
    return Res;
}

CTLOG_STORE* CTLOG_STORE_new_ex(OSSL_LIB_CTX* libctx, const char* propq)
{
    CTLOG_STORE* Res = NULL;
    // Additional implementation here
    return Res;
}
int X509_CRL_sign_ctx(X509_CRL *crl, EVP_MD_CTX *ctx);

int EC_POINT_cmp(const EC_GROUP *group, const EC_POINT *a, const EC_POINT *b, BN_CTX *ctx);

int SSL_do_handshake(SSL *s);

int i2d_PUBKEY(const EVP_PKEY *a, unsigned char **pp);

int X509_CRL_add_ext(X509_CRL *crl, X509_EXTENSION *ex, int loc);


const EVP_CIPHER* EVP_des_cfb64() {
    const EVP_CIPHER* Res = NULL;
    Res = EVP_des_cfb64();
    sf_set_possible_null(Res);
    return Res;
}

int (UI*)* UI_method_get_closer(const UI_METHOD* method) {
    int (UI*)* Res = NULL;
    Res = UI_method_get_closer(method);
    sf_set_possible_null(Res);
    return Res;
}

char* BIO_get_callback_arg(const BIO* bio) {
    char* Res = NULL;
    Res = BIO_get_callback_arg(bio);
    sf_set_possible_null(Res);
    return Res;
}

OCSP_RESPDATA* OCSP_RESPDATA_new() {
    OCSP_RESPDATA* Res = NULL;
    Res = OCSP_RESPDATA_new();
    sf_set_possible_null(Res);
    return Res;
}

EVP_KEM* EVP_KEM_fetch(OSSL_LIB_CTX* ctx, const char* name, const char* properties) {
    EVP_KEM* Res = NULL;
    Res = EVP_KEM_fetch(ctx, name, properties);
    sf_set_possible_null(Res);
    return Res;
}
int EVP_PKEY_private_check(EVP_PKEY_CTX* ctx);

const EC_METHOD* EC_GFp_nist_method();

int ASYNC_WAIT_CTX_get_changed_fds(ASYNC_WAIT_CTX* ctx, int* fd, size_t* numfds, int* add, size_t* numadd);

const BIGNUM* RSA_get0_iqmp(const RSA* rsa);

size_t EVP_MAC_CTX_get_block_size(EVP_MAC_CTX* ctx);

void BN_MONT_CTX_free(BN_MONT_CTX* mont);

int CRYPTO_alloc_ex_data(int index, void* to, CRYPTO_EX_DATA* ad, int num);

void EVP_PKEY_meth_get_ctrl(const EVP_PKEY_METHOD* pmeth, int (**ctrl);

BIO* OSSL_HTTP_exchange(OSSL_HTTP_REQ_CTX* rctx, char** redirect);

int EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(EVP_PKEY_CTX* ctx, int len);

int EVP_PKEY_print_private_fp(FILE*, const EVP_PKEY*, int, ASN1_PCTX*);

int SSL_check_private_key(const SSL*);

int PEM_write_NETSCAPE_CERT_SEQUENCE(FILE*, const NETSCAPE_CERT_SEQUENCE*);

int RAND_set_DRBG_type(OSSL_LIB_CTX*, const char*, const char*, const char*, const char*);

const EVP_CIPHER* EVP_camellia_256_ofb();


PKCS7_SIGN_ENVELOPE* d2i_PKCS7_SIGN_ENVELOPE(PKCS7_SIGN_ENVELOPE** a, const unsigned char** pp, long length) {
    PKCS7_SIGN_ENVELOPE* Res = NULL;
    sf_set_trusted_sink_int(length);
    Res = PKCS7_SIGN_ENVELOPE_new();
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    if (Res != NULL) {
        Res = d2i_PKCS7_SIGN_ENVELOPE(a, pp, length);
        sf_set_possible_null(Res);
    }
    return Res;
}

int X509_STORE_CTX_set_default(X509_STORE_CTX* ctx, const char* name) {
    int Res = 0;
    sf_password_use(name);
    Res = X509_STORE_CTX_set_default(ctx, name);
    sf_set_errno_if(Res == 0);
    return Res;
}

unsigned long BN_div_word(BIGNUM* a, unsigned long w) {
    unsigned long Res = 0;
    Res = BN_div_word(a, w);
    sf_set_possible_null(Res);
    return Res;
}

const unsigned char* SSL_SESSION_get_id(const SSL_SESSION* s, unsigned int* len) {
    const unsigned char* Res = NULL;
    Res = SSL_SESSION_get_id(s, len);
    sf_set_possible_null(Res);
    return Res;
}

size_t SCT_get0_extensions(const SCT* sct, unsigned char** exts) {
    size_t Res = 0;
    Res = SCT_get0_extensions(sct, exts);
    sf_set_buf_size_limit(exts, Res);
    return Res;
}

size_t SSL_get_client_random(const SSL* s, unsigned char* out, size_t outlen)
{
    size_t res = 0;
    sf_set_trusted_sink_int(outlen);
    sf_buf_size_limit(out, outlen);
    sf_overwrite(out);
    return res;
}

int BN_set_word(BIGNUM* a, unsigned long w)
{
    int res = 0;
    sf_overwrite(a);
    return res;
}

const char* EVP_KEYEXCH_get0_name(const EVP_KEYEXCH* ke)
{
    const char* res = NULL;
    sf_set_possible_null(res);
    return res;
}

void EVP_PKEY_meth_set_verifyctx(EVP_PKEY_METHOD* pmeth, int (*verifyctx) (EVP_PKEY_CTX*, EVP_MD_CTX*), int (*verifyctx_cleanup) (EVP_PKEY_CTX*, EVP_MD_CTX*))
{
    // No return value, no need for 'res' variable
}

int CRYPTO_set_mem_functions(CRYPTO_malloc_fn malloc_fn, CRYPTO_realloc_fn realloc_fn, CRYPTO_free_fn free_fn)
{
    int res = 0;
    sf_lib_arg_type(malloc_fn, "MallocCategory");
    sf_lib_arg_type(realloc_fn, "MallocCategory");
    sf_lib_arg_type(free_fn, "MallocCategory");
    return res;
}

int X509_get_ext_count(const X509* x) {
    int res = 0;
    sf_set_must_not_be_null(x, X509_NULL);
    sf_set_errno_if(res < 0, "X509_get_ext_count");
    return res;
}

const char* SCT_validation_status_string(const SCT* s) {
    const char* res = NULL;
    sf_set_must_not_be_null(s, SCT_NULL);
    return res;
}

const ASN1_INTEGER* X509_get0_serialNumber(const X509* x) {
    const ASN1_INTEGER* res = NULL;
    sf_set_must_not_be_null(x, X509_NULL);
    return res;
}

const stack_st_ASN1_OBJECT* PROFESSION_INFO_get0_professionOIDs(const PROFESSION_INFO* p) {
    const stack_st_ASN1_OBJECT* res = NULL;
    sf_set_must_not_be_null(p, PROFESSION_INFO_NULL);
    return res;
}

void OPENSSL_sk_zero(OPENSSL_STACK* sk) {
    sf_set_must_not_be_null(sk, OPENSSL_STACK_NULL);
    // No return value, so no need for a result variable
}

const char* SSL_alert_desc_string(int val)
{
    const char* Res = NULL;
    Res = SSL_alert_desc_string(val);
    sf_set_possible_null(Res);
    return Res;
}

const EVP_CIPHER* EVP_camellia_128_cfb128()
{
    const EVP_CIPHER* Res = NULL;
    Res = EVP_camellia_128_cfb128();
    sf_set_possible_null(Res);
    return Res;
}

int X509_VERIFY_PARAM_set_trust(X509_VERIFY_PARAM *param, int trust)
{
    int Res = 0;
    Res = X509_VERIFY_PARAM_set_trust(param, trust);
    sf_set_errno_if(Res <= 0);
    return Res;
}

const EVP_CIPHER* EVP_aria_128_ecb()
{
    const EVP_CIPHER* Res = NULL;
    Res = EVP_aria_128_ecb();
    sf_set_possible_null(Res);
    return Res;
}

const EVP_CIPHER* EVP_aria_192_gcm()
{
    const EVP_CIPHER* Res = NULL;
    Res = EVP_aria_192_gcm();
    sf_set_possible_null(Res);
    return Res;
}

void EVP_MAC_do_all_provided(OSSL_LIB_CTX* libctx, void (*fn)(EVP_MAC*, void*), void* arg) {
    sf_set_trusted_sink_int(libctx);
    sf_set_trusted_sink_ptr(fn);
    sf_set_trusted_sink_ptr(arg);
    // function body
}

X509_VAL* d2i_X509_VAL(X509_VAL** val, const unsigned char** in, long len) {
    X509_VAL* Res = NULL;
    sf_set_trusted_sink_ptr(val);
    sf_set_trusted_sink_ptr(in);
    sf_set_trusted_sink_int(len);
    // function body
    return Res;
}

ECPARAMETERS* EC_GROUP_get_ecparameters(const EC_GROUP* group, ECPARAMETERS* params) {
    ECPARAMETERS* Res = NULL;
    sf_set_trusted_sink_ptr(group);
    sf_set_trusted_sink_ptr(params);
    // function body
    return Res;
}

int EVP_PKEY_meth_remove(const EVP_PKEY_METHOD* pmeth) {
    int Res = 0;
    sf_set_trusted_sink_ptr(pmeth);
    // function body
    return Res;
}

int EVP_PKEY_can_sign(const EVP_PKEY* pkey) {
    int Res = 0;
    sf_set_trusted_sink_ptr(pkey);
    // function body
    return Res;
}

void* CRYPTO_realloc(void* ptr, size_t size, const char* file, int line) {
    void* Res = NULL;
    sf_set_trusted_sink_int(size);
    sf_malloc_arg(size);
    Res = realloc(ptr, size);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res, size);
    sf_buf_size_limit(Res, size);
    sf_lib_arg_type(Res, "MallocCategory");
    sf_delete(ptr, MALLOC_CATEGORY);
    return Res;
}

int EC_POINT_dbl(const EC_GROUP* group, EC_POINT* r, const EC_POINT* p, BN_CTX* ctx) {
    int Res = 0;
    Res = EC_POINT_dbl_internal(group, r, p, ctx);
    sf_set_errno_if(Res == 0);
    sf_set_possible_null(Res);
    return Res;
}

NETSCAPE_CERT_SEQUENCE* d2i_NETSCAPE_CERT_SEQUENCE(NETSCAPE_CERT_SEQUENCE** a, const unsigned char** pp, long length) {
    NETSCAPE_CERT_SEQUENCE* Res = NULL;
    Res = d2i_NETSCAPE_CERT_SEQUENCE_internal(a, pp, length);
    sf_set_errno_if(Res == NULL);
    sf_set_possible_null(Res);
    return Res;
}

int EVP_PKEY_pairwise_check(EVP_PKEY_CTX* ctx) {
    int Res = 0;
    Res = EVP_PKEY_pairwise_check_internal(ctx);
    sf_set_errno_if(Res == 0);
    sf_set_possible_null(Res);
    return Res;
}

int X509_LOOKUP_ctrl(X509_LOOKUP* ctx, int cmd, const char* argc, long argl,  char** ret) {
    int Res = 0;
    Res = X509_LOOKUP_ctrl_internal(ctx, cmd, argc, argl, ret);
    sf_set_errno_if(Res == 0);
    sf_set_possible_null(Res);
    return Res;
}

int BIO_do_connect_retry(BIO* bio, int ret, int flags) {
    int Res = 0;
    // Function body
    return Res;
}

EVP_PKEY* b2i_PVK_bio_ex(BIO* bio, pem_password_cb* cb, void* u, OSSL_LIB_CTX* libctx, const char* propq) {
    EVP_PKEY* Res = NULL;
    // Function body
    return Res;
}

int BN_MONT_CTX_set(BN_MONT_CTX* ctx, const BIGNUM* mod, BN_CTX* bn_ctx) {
    int Res = 0;
    // Function body
    return Res;
}

void EVP_PKEY_meth_get_param_check(const EVP_PKEY_METHOD* meth, int (EVP_PKEY*)** check) {
    // Function body
}

int X509_CRL_get_ext_by_critical(const X509_CRL* crl, int ext_nid, int crit) {
    int Res = 0;
    // Function body
    return Res;
}

int BIO_listen(int sock, const BIO_ADDR *addr, int backlog) {
    int Res = 0;
    sf_set_trusted_sink_int(backlog);
    sf_set_buf_size(addr, sizeof(BIO_ADDR));
    sf_set_must_be_not_null(addr, "BIO_ADDR");
    sf_set_must_be_not_null(sock, "Socket");
    sf_set_errno_if(Res <= 0);
    sf_tocttou_check(addr);
    return Res;
}

int PKCS5_v2_PBE_keyivgen_ex(EVP_CIPHER_CTX *ctx, const char *pass, int passlen, ASN1_TYPE *param, const EVP_CIPHER *cipher, const EVP_MD *md, int en_de, OSSL_LIB_CTX *libctx, const char *propq) {
    int Res = 0;
    sf_set_trusted_sink_int(passlen);
    sf_set_must_be_not_null(ctx, "EVP_CIPHER_CTX");
    sf_set_must_be_not_null(pass, "Password");
    sf_password_use(pass);
    sf_set_must_be_not_null(cipher, "EVP_CIPHER");
    sf_set_must_be_not_null(md, "EVP_MD");
    sf_set_must_be_not_null(libctx, "OSSL_LIB_CTX");
    sf_set_errno_if(Res <= 0);
    return Res;
}

int BN_num_bits_word(unsigned long w) {
    int Res = 0;
    sf_set_must_be_not_null(w, "Word");
    return Res;
}

void RSA_get0_key(const RSA *r, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d) {
    sf_set_must_be_not_null(r, "RSA");
    sf_set_must_be_not_null(n, "BIGNUM");
    sf_set_must_be_not_null(e, "BIGNUM");
    sf_set_must_be_not_null(d, "BIGNUM");
}

RSA_PSS_PARAMS* d2i_RSA_PSS_PARAMS(RSA_PSS_PARAMS **a, const unsigned char **in, long len) {
    RSA_PSS_PARAMS *Res = NULL;
    sf_set_trusted_sink_int(len);
    sf_set_must_be_not_null(a, "RSA_PSS_PARAMS");
    sf_set_must_be_not_null(in, "UnsignedChar");
    sf_set_alloc_possible_null(Res);
    return Res;
}

int X509_CRL_get_ext_by_OBJ(const X509_CRL *crl, const ASN1_OBJECT *obj, int lastpos)
{
    int Res = -1;
    sf_set_must_be_not_null(crl, CRL_NULL);
    sf_set_must_be_not_null(obj, OBJECT_NULL);
    sf_set_errno_if(Res == -1, ERR_GET_EXTENSION);
    return Res;
}

unsigned long ERR_peek_error_data(const char **file, int *line)
{
    unsigned long Res = 0;
    sf_set_possible_null(file);
    sf_set_possible_null(line);
    sf_set_errno_if(Res == 0, ERR_PEEK_LAST_ERROR);
    return Res;
}

void BN_swap(BIGNUM *a, BIGNUM *b)
{
    sf_set_must_be_not_null(a, BN_NULL);
    sf_set_must_be_not_null(b, BN_NULL);
    sf_bitcopy(a, b);
}

int CRYPTO_THREAD_unlock(CRYPTO_RWLOCK *lock)
{
    int Res = 0;
    sf_set_must_be_not_null(lock, LOCK_NULL);
    sf_set_errno_if(Res == 0, THREAD_UNLOCK_FAILURE);
    return Res;
}

const EVP_MD* EVP_sha3_512()
{
    const EVP_MD* Res = NULL;
    sf_set_possible_null(Res);
    return Res;
}

int EVP_PKEY_set_type(EVP_PKEY *pkey, int type) {
    int Res = 0;
    sf_set_must_be_not_null(pkey, SET_TYPE_OF_NULL);
    sf_set_must_be_not_null(type, SET_TYPE_OF_NULL);
    Res = EVP_PKEY_set_type(pkey, type);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int i2d_IPAddressRange(const IPAddressRange *a, unsigned char **pp) {
    int Res = 0;
    sf_set_must_be_not_null(a, I2D_IPADDRESSRANGE_NULL);
    sf_set_must_be_not_null(pp, I2D_IPADDRESSRANGE_NULL);
    Res = i2d_IPAddressRange(a, pp);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int SHA1_Update(SHA_CTX *c, const void *data, size_t len) {
    int Res = 0;
    sf_set_must_be_not_null(c, SHA1_UPDATE_NULL);
    sf_set_must_be_not_null(data, SHA1_UPDATE_NULL);
    sf_set_must_be_not_null(len, SHA1_UPDATE_NULL);
    Res = SHA1_Update(c, data, len);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int OSSL_PARAM_set_int(OSSL_PARAM *p, int val) {
    int Res = 0;
    sf_set_must_be_not_null(p, SET_PARAM_INT_NULL);
    Res = OSSL_PARAM_set_int(p, val);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int EC_KEY_set_group(EC_KEY *key, const EC_GROUP *group) {
    int Res = 0;
    sf_set_must_be_not_null(key, SET_GROUP_NULL);
    sf_set_must_be_not_null(group, SET_GROUP_NULL);
    Res = EC_KEY_set_group(key, group);
    sf_set_errno_if(Res <= 0);
    return Res;
}

OCSP_SERVICELOC* d2i_OCSP_SERVICELOC(OCSP_SERVICELOC** a, const unsigned char** pp, long length)
{
    OCSP_SERVICELOC* Res = NULL;
    sf_set_trusted_sink_int(length);
    sf_malloc_arg(Res, length);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    Res = d2i_OCSP_SERVICELOC(a, pp, length);
    sf_set_possible_null(Res);
    return Res;
}

void OPENSSL_LH_set_down_load(OPENSSL_LHASH* lh, unsigned long down_load)
{
    sf_set_trusted_sink_int(down_load);
    OPENSSL_LH_set_down_load(lh, down_load);
}

void RSA_set_flags(RSA* rsa, int flags)
{
    sf_set_trusted_sink_int(flags);
    RSA_set_flags(rsa, flags);
}

const BIO_METHOD* BIO_f_prefix()
{
    const BIO_METHOD* Res = NULL;
    Res = BIO_f_prefix();
    sf_set_possible_null(Res);
    return Res;
}

void PBE2PARAM_free(PBE2PARAM* pbe2)
{
    sf_delete(pbe2, MALLOC_CATEGORY);
    PBE2PARAM_free(pbe2);
}

int X509_STORE_load_path(X509_STORE *store, const char *path)
{
    int res = 0;
    sf_tocttou_check(path);
    sf_set_tainted(path);
    sf_set_must_be_not_null(store, "X509_STORE");
    sf_set_must_be_not_null(path, "Path");
    sf_set_errno_if(res == 0, "X509_STORE_load_path");
    return res;
}

int X509_LOOKUP_meth_set_init(X509_LOOKUP_METHOD *method, int (*init)(X509_LOOKUP *))
{
    int res = 0;
    sf_set_must_be_not_null(method, "X509_LOOKUP_METHOD");
    sf_set_must_be_not_null(init, "Init function");
    sf_set_errno_if(res == 0, "X509_LOOKUP_meth_set_init");
    return res;
}

int i2d_OCSP_RESPONSE(const OCSP_RESPONSE *ocsp, unsigned char **pp)
{
    int res = 0;
    sf_set_must_be_not_null(ocsp, "OCSP_RESPONSE");
    sf_set_must_be_not_null(pp, "PP");
    sf_set_errno_if(res == 0, "i2d_OCSP_RESPONSE");
    return res;
}

EVP_RAND_CTX* EVP_RAND_CTX_new(EVP_RAND *rand, EVP_RAND_CTX *parent)
{
    EVP_RAND_CTX *res = NULL;
    sf_set_must_be_not_null(rand, "EVP_RAND");
    sf_set_alloc_possible_null(res);
    sf_set_errno_if(res == NULL, "EVP_RAND_CTX_new");
    return res;
}

int DH_meth_set_generate_key(DH_METHOD *method, int (*generate_key)(DH *))
{
    int res = 0;
    sf_set_must_be_not_null(method, "DH_METHOD");
    sf_set_must_be_not_null(generate_key, "Generate key function");
    sf_set_errno_if(res == 0, "DH_meth_set_generate_key");
    return res;
}

const EVP_MD* EVP_shake128()
{
    const EVP_MD* Res = NULL;
    Res = EVP_shake128();
    sf_set_possible_null(Res);
    return Res;
}

const SSL_METHOD* DTLS_client_method()
{
    const SSL_METHOD* Res = NULL;
    Res = DTLS_client_method();
    sf_set_possible_null(Res);
    return Res;
}

int ASYNC_pause_job()
{
    int Res = 0;
    Res = ASYNC_pause_job();
    sf_set_errno_if(Res == 0);
    return Res;
}

int SSL_CTX_set_default_verify_dir(SSL_CTX* ctx)
{
    int Res = 0;
    Res = SSL_CTX_set_default_verify_dir(ctx);
    sf_set_errno_if(Res == 0);
    return Res;
}

int i2d_PKCS7_RECIP_INFO(const PKCS7_RECIP_INFO* ri, unsigned char** pp)
{
    int Res = 0;
    Res = i2d_PKCS7_RECIP_INFO(ri, pp);
    sf_set_errno_if(Res == 0);
    return Res;
}

int X509_LOOKUP_ctrl_ex(X509_LOOKUP *ctx, int cmd, const char *argc, long larg, char **parg, OSSL_LIB_CTX *libctx, const char *propq)
{
    int res = 0;
    sf_set_trusted_sink_int(larg);
    sf_set_trusted_sink_ptr(argc);
    sf_set_trusted_sink_ptr(parg);
    sf_set_trusted_sink_ptr(libctx);
    sf_set_trusted_sink_ptr(propq);
    sf_set_errno_if(res == -1);
    sf_no_errno_if(res != -1);
    return res;
}

int i2d_ASN1_UNIVERSALSTRING(const ASN1_UNIVERSALSTRING *a, unsigned char **pp)
{
    int res = 0;
    sf_set_trusted_sink_ptr(a);
    sf_set_trusted_sink_ptr(pp);
    sf_set_errno_if(res == -1);
    sf_no_errno_if(res != -1);
    return res;
}

int EVP_PKEY_set_ex_data(EVP_PKEY *key, int idx, void *arg)
{
    int res = 0;
    sf_set_trusted_sink_ptr(key);
    sf_set_trusted_sink_int(idx);
    sf_set_trusted_sink_ptr(arg);
    sf_set_errno_if(res == 0);
    sf_no_errno_if(res != 0);
    return res;
}

OPENSSL_STACK *OPENSSL_sk_dup(const OPENSSL_STACK *sk)
{
    OPENSSL_STACK *res = NULL;
    sf_set_trusted_sink_ptr(sk);
    sf_set_alloc_possible_null(res);
    sf_set_errno_if(res == NULL);
    sf_no_errno_if(res != NULL);
    return res;
}

int i2d_X509_NAME_ENTRY(const X509_NAME_ENTRY *ne, unsigned char **pp)
{
    int res = 0;
    sf_set_trusted_sink_ptr(ne);
    sf_set_trusted_sink_ptr(pp);
    sf_set_errno_if(res == -1);
    sf_no_errno_if(res != -1);
    return res;
}

GENERAL_NAMES* GENERAL_NAMES_new()
{
    GENERAL_NAMES* Res = NULL;
    sf_malloc_arg(Res, sizeof(GENERAL_NAMES));
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    return Res;
}

int OSSL_HTTP_set1_request(OSSL_HTTP_REQ_CTX* rctx, const char* server, const stack_st_CONF_VALUE* proxies, const char* no_proxy, BIO* bio, const char* path, int method, size_t buf_size, int timeout, int max_line_length)
{
    sf_set_trusted_sink_int(buf_size);
    sf_set_trusted_sink_int(max_line_length);
    sf_set_trusted_sink_int(timeout);
    sf_set_trusted_sink_ptr(server);
    sf_set_trusted_sink_ptr(no_proxy);
    sf_set_trusted_sink_ptr(path);
    return 0;
}

void SSL_set_bio(SSL* s, BIO* rbio, BIO* wbio)
{
    sf_set_trusted_sink_ptr(rbio);
    sf_set_trusted_sink_ptr(wbio);
}

int ECDSA_verify(int type, const unsigned char* dgst, int dlen, const unsigned char* sig, int slen, EC_KEY* eckey)
{
    sf_set_trusted_sink_int(type);
    sf_set_trusted_sink_ptr(dgst);
    sf_set_trusted_sink_int(dlen);
    sf_set_trusted_sink_ptr(sig);
    sf_set_trusted_sink_int(slen);
    sf_set_trusted_sink_ptr(eckey);
    return 0;
}

int EVP_PKEY_derive_init_ex(EVP_PKEY_CTX* ctx, const OSSL_PARAM params[])
{
    sf_set_trusted_sink_ptr(ctx);
    sf_set_trusted_sink_ptr(params);
    return 0;
}

int i2d_PKCS7_SIGNED(const PKCS7_SIGNED *a, unsigned char **pp)
{
    int res = 0;
    sf_set_must_be_not_null(a, "PKCS7_SIGNED");
    sf_set_must_be_not_null(pp, "unsigned char**");
    sf_set_trusted_sink_ptr(pp);
    sf_set_errno_if(res < 0, "i2d_PKCS7_SIGNED");
    sf_set_possible_null(res);
    return res;
}

EVP_PKEY* d2i_PUBKEY_fp(FILE *fp, EVP_PKEY **a)
{
    EVP_PKEY* res = NULL;
    sf_set_must_be_not_null(fp, "FILE*");
    sf_set_must_be_not_null(a, "EVP_PKEY**");
    sf_set_trusted_sink_ptr(a);
    sf_set_errno_if(res == NULL, "d2i_PUBKEY_fp");
    sf_set_possible_null(res);
    return res;
}

EVP_MD* EVP_MD_meth_new(int nid, int md_size)
{
    EVP_MD* res = NULL;
    sf_set_buf_size_limit(md_size);
    sf_set_errno_if(res == NULL, "EVP_MD_meth_new");
    sf_set_possible_null(res);
    return res;
}

int CRYPTO_THREAD_write_lock(CRYPTO_RWLOCK *lock)
{
    int res = 0;
    sf_set_must_be_not_null(lock, "CRYPTO_RWLOCK*");
    sf_set_errno_if(res != 1, "CRYPTO_THREAD_write_lock");
    return res;
}

PROXY_CERT_INFO_EXTENSION* PROXY_CERT_INFO_EXTENSION_new()
{
    PROXY_CERT_INFO_EXTENSION* res = NULL;
    sf_set_errno_if(res == NULL, "PROXY_CERT_INFO_EXTENSION_new");
    sf_set_possible_null(res);
    return res;
}

int EVP_PKEY_check(EVP_PKEY_CTX *ctx) {
    int res = 0;
    // Additional implementation here
    return res;
}

const EVP_CIPHER* EVP_aes_192_ccm() {
    const EVP_CIPHER *res = NULL;
    // Additional implementation here
    return res;
}

void ERR_error_string_n(unsigned long e, char *buf, size_t len) {
    // Additional implementation here
    // No return value, so no need for 'res' variable
}

uint32_t SSL_SESSION_get_max_early_data(const SSL_SESSION *s) {
    uint32_t res = 0;
    // Additional implementation here
    return res;
}

const unsigned char* EVP_PKEY_get0_siphash(const EVP_PKEY *pkey, size_t *size) {
    const unsigned char *res = NULL;
    // Additional implementation here
    return res;
}

int HMAC_Init_ex(HMAC_CTX* ctx, const void* key, int key_len, const EVP_MD* md, ENGINE* impl) {
    int Res = 0;
    sf_set_trusted_sink_int(key_len);
    sf_set_tainted(key);
    sf_set_tainted(md);
    sf_set_tainted(impl);
    sf_set_must_not_be_null(ctx);
    sf_set_must_not_be_null(key);
    sf_set_must_not_be_null(md);
    sf_set_possible_null(Res);
    return Res;
}

OTHERNAME* d2i_OTHERNAME(OTHERNAME** a, const unsigned char** in, long len) {
    OTHERNAME* Res = NULL;
    sf_set_trusted_sink_int(len);
    sf_set_tainted(in);
    sf_set_must_not_be_null(a);
    sf_set_possible_null(Res);
    return Res;
}

int SCT_set1_signature(SCT* s, const unsigned char* sig, size_t sig_len) {
    int Res = 0;
    sf_set_trusted_sink_int(sig_len);
    sf_set_tainted(sig);
    sf_set_must_not_be_null(s);
    sf_set_must_not_be_null(sig);
    sf_set_possible_null(Res);
    return Res;
}

int EVP_CIPHER_CTX_set_num(EVP_CIPHER_CTX* ctx, int val) {
    int Res = 0;
    sf_set_must_not_be_null(ctx);
    sf_set_possible_null(Res);
    return Res;
}

dsa_st* EVP_PKEY_get1_DSA(EVP_PKEY* pkey) {
    dsa_st* Res = NULL;
    sf_set_must_not_be_null(pkey);
    sf_set_possible_null(Res);
    return Res;
}

const NAMING_AUTHORITY* PROFESSION_INFO_get0_namingAuthority(const PROFESSION_INFO* a)
{
    const NAMING_AUTHORITY* Res = NULL;
    Res = a->namingAuthority;
    sf_set_possible_null(Res);
    return Res;
}

int X509_NAME_get_index_by_OBJ(const X509_NAME* a, const ASN1_OBJECT* b, int c)
{
    int Res = 0;
    Res = a->get_index_by_OBJ(b, c);
    sf_set_errno_if(Res < 0);
    sf_set_possible_negative(Res);
    return Res;
}

long BIO_callback_ctrl(BIO* a, int b, BIO_info_cb* c)
{
    long Res = 0;
    Res = a->callback_ctrl(b, c);
    sf_set_errno_if(Res <= 0);
    return Res;
}

const EVP_CIPHER* EVP_aes_192_ofb()
{
    const EVP_CIPHER* Res = NULL;
    Res = EVP_aes_192_ofb();
    sf_set_possible_null(Res);
    return Res;
}

stack_st_SCT* d2i_SCT_LIST(stack_st_SCT** a, const unsigned char** b, long c)
{
    stack_st_SCT* Res = NULL;
    Res = d2i_SCT_LIST(a, b, c);
    sf_set_possible_null(Res);
    return Res;
}

CT_POLICY_EVAL_CTX* CT_POLICY_EVAL_CTX_new() {
    CT_POLICY_EVAL_CTX* Res = NULL;
    Res = (CT_POLICY_EVAL_CTX*)OPENSSL_zalloc(sizeof(CT_POLICY_EVAL_CTX));
    sf_new(Res, CT_POLICY_EVAL_CTX_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    return Res;
}

int i2d_PKCS7_NDEF(const PKCS7* a, unsigned char** pp) {
    int Res = 0;
    Res = i2d_ASN1_TYPE((ASN1_TYPE*)a, pp);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int RSA_padding_add_none(unsigned char* to, int tlen, const unsigned char* from, int flen) {
    int Res = 0;
    Res = RSA_padding_add_none(to, tlen, from, flen);
    sf_set_errno_if(Res <= 0);
    return Res;
}

X509_NAME* X509_CRL_get_issuer(const X509_CRL* crl) {
    X509_NAME* Res = NULL;
    Res = X509_CRL_get_issuer(crl);
    sf_set_possible_null(Res);
    return Res;
}

size_t EVP_MAC_CTX_get_mac_size(EVP_MAC_CTX* ctx) {
    size_t Res = 0;
    Res = EVP_MAC_CTX_get_mac_size(ctx);
    sf_set_errno_if(Res <= 0);
    return Res;
}
BIO* OSSL_HTTP_transfer(OSSL_HTTP_REQ_CTX**, const char*, const char*, const char*, int, const char*, const char*, BIO*, BIO*, OSSL_HTTP_bio_cb_t, void*, int, const stack_st_CONF_VALUE*, const char*, BIO*, const char*, int, size_t, int, int);

PKCS7_SIGN_ENVELOPE* PKCS7_SIGN_ENVELOPE_new();

void CT_POLICY_EVAL_CTX_set_time(CT_POLICY_EVAL_CTX*, uint64_t);

X509_ALGOR* PKCS5_pbe2_set_iv(const EVP_CIPHER*, int, unsigned char*, int, unsigned char*, int);

ASN1_TIME* X509_time_adj(ASN1_TIME*, long, time_t*);


void DSA_meth_set_sign_setup(DSA_METHOD *meth, int (*sign_setup)(DSA*, BN_CTX*, BIGNUM**, BIGNUM**)) {
    sf_set_trusted_sink_int(sign_setup);
    sf_set_trusted_sink_ptr(meth);
    sf_set_trusted_sink_ptr(sign_setup);
}

void SSL_dup(SSL *s) {
    sf_set_must_not_be_null(s, DUP_OF_NULL);
    sf_lib_arg_type(s, "SSL");
}

void EVP_aes_192_ocb() {
    // No additional checks needed as it's a simple function that returns a const pointer.
}

void X509_STORE_set_check_revocation(X509_STORE *store, X509_STORE_CTX_check_revocation_fn check_revocation) {
    sf_set_must_not_be_null(store, CHECK_REVOCATION_OF_NULL);
    sf_set_trusted_sink_ptr(check_revocation);
    sf_lib_arg_type(store, "X509_STORE");
}

void AUTHORITY_KEYID_new() {
    // No additional checks needed as it's a simple function that returns a new object.
}
int BN_bn2bin(const BIGNUM *a, unsigned char *to);

int X509_STORE_add_cert(X509_STORE *ctx, X509 *x);

int RSA_meth_set_priv_dec(RSA_METHOD *meth, int (*priv_dec_fn);

unsigned long ERR_get_error_line_data(const char **file, int *line, const char **data, int *flags);

X509* SSL_get1_peer_certificate(const SSL *s);


void OCSP_SERVICELOC_free(OCSP_SERVICELOC* loc) {
    if (loc == NULL) {
        return;
    }
    sf_delete(loc, SERVICELOC_MEMORY_CATEGORY);
}

DSA* DSA_generate_parameters(int bits, unsigned char* seed_in, int seed_len, int* counter_ret, unsigned long* h_ret, void (int, int, void*)* cb, void* cb_arg) {
    DSA* res = NULL;
    sf_new(res, DSA_MEMORY_CATEGORY);
    // ... (rest of the function)
    return res;
}

CONF* NCONF_new_ex(OSSL_LIB_CTX* ctx, CONF_METHOD* meth) {
    CONF* res = NULL;
    sf_new(res, CONF_MEMORY_CATEGORY);
    // ... (rest of the function)
    return res;
}

char* BN_bn2dec(const BIGNUM* a) {
    char* res = NULL;
    sf_new(res, BN_MEMORY_CATEGORY);
    // ... (rest of the function)
    return res;
}

int i2d_PKCS8_PRIV_KEY_INFO_bio(BIO* bp, const PKCS8_PRIV_KEY_INFO* p8inf) {
    int res = 0;
    // ... (rest of the function)
    return res;
}
const BIGNUM* DH_get0_g(const DH* dh);

const BIGNUM* ECDSA_SIG_get0_r(const ECDSA_SIG* sig);

X509_STORE_CTX_check_policy_fn X509_STORE_CTX_get_check_policy(const X509_STORE_CTX* ctx);

char* X509_NAME_oneline(const X509_NAME* name,  char* buf, int len);

int ASN1_STRING_length(const ASN1_STRING* x);

int BN_is_prime_ex(const BIGNUM*, int, BN_CTX*, BN_GENCB*);

const EVP_CIPHER* EVP_camellia_256_cfb1();

int X509_REVOKED_set_revocationDate(X509_REVOKED*, ASN1_TIME*);

int PKCS8_pkey_add1_attr_by_OBJ(PKCS8_PRIV_KEY_INFO*, const ASN1_OBJECT*, int, const unsigned char*, int);

void SSL_set_psk_client_callback(SSL*, SSL_psk_client_cb_func);

int OPENSSL_sk_find_ex(OPENSSL_STACK*, const void*);

const OSSL_PROVIDER* EVP_KEYMGMT_get0_provider(const EVP_KEYMGMT*);

void EVP_PKEY_meth_get_digestverify(const EVP_PKEY_METHOD*, int (EVP_MD_CTX*, const unsigned char*, size_t, const unsigned char*, size_t);

int DH_check(const DH*, int*);

ASN1_BIT_STRING* d2i_ASN1_BIT_STRING(ASN1_BIT_STRING**, const unsigned char**, long);


sf_set_trusted_sink_int(ENGINE_set_default_ciphers);
int ENGINE_set_default_ciphers(ENGINE *e) {
    int Res = 0;
    sf_set_errno_if(Res <= 0, ENGINE_set_default_ciphers);
    return Res;
}

sf_set_trusted_sink_int(i2d_X509_bio);
int i2d_X509_bio(BIO *bp, const X509 *x) {
    int Res = 0;
    sf_set_errno_if(Res <= 0, i2d_X509_bio);
    return Res;
}

void SSL_CTX_set_psk_server_callback(SSL_CTX *ctx, SSL_psk_server_cb_func cb) {
    sf_password_use(cb);
    SSL_CTX_set_psk_server_callback(ctx, cb);
}

sf_set_trusted_sink_int(SSL_CTX_set_tlsext_use_srtp);
int SSL_CTX_set_tlsext_use_srtp(SSL_CTX *ctx, const char *str) {
    int Res = 0;
    sf_set_errno_if(Res <= 0, SSL_CTX_set_tlsext_use_srtp);
    return Res;
}

sf_set_trusted_sink_int(EVP_DigestInit);
int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type) {
    int Res = 0;
    sf_set_errno_if(Res <= 0, EVP_DigestInit);
    return Res;
}

stack_st_OPENSSL_CSTRING* NCONF_get_section_names(const CONF* conf) {
    stack_st_OPENSSL_CSTRING* Res = NULL;
    sf_set_trusted_sink_int(conf);
    Res = (stack_st_OPENSSL_CSTRING*)OPENSSL_malloc(sizeof(stack_st_OPENSSL_CSTRING));
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    return Res;
}

const stack_st_ADMISSIONS* ADMISSION_SYNTAX_get0_contentsOfAdmissions(const ADMISSION_SYNTAX* a) {
    const stack_st_ADMISSIONS* Res = NULL;
    sf_set_trusted_sink_int(a);
    Res = (const stack_st_ADMISSIONS*)OPENSSL_malloc(sizeof(stack_st_ADMISSIONS));
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    return Res;
}

EC_KEY* d2i_EC_PUBKEY(EC_KEY** a, const unsigned char** pp, long length) {
    EC_KEY* Res = NULL;
    sf_set_trusted_sink_int(a);
    Res = (EC_KEY*)OPENSSL_malloc(sizeof(EC_KEY));
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    return Res;
}

void OPENSSL_LH_flush(OPENSSL_LHASH* lh) {
    sf_set_trusted_sink_int(lh);
    OPENSSL_LH_flush(lh);
}

int CTLOG_new_from_base64(CTLOG** ctlog, const char* b64, const char* desc) {
    int Res = 0;
    sf_set_trusted_sink_int(ctlog);
    sf_set_trusted_sink_int(b64);
    sf_set_trusted_sink_int(desc);
    Res = CTLOG_new_from_base64(ctlog, b64, desc);
    sf_overwrite(&Res);
    return Res;
}

int UI_get_input_flags(UI_STRING* input) {
    int Res = 0;
    sf_set_must_be_not_null(input, FLAGS_OF_NULL);
    sf_set_tainted(input);
    Res = UI_get_input_flags(input);
    sf_set_errno_if(Res == -1);
    sf_set_possible_null(Res);
    return Res;
}

PBE2PARAM* PBE2PARAM_new() {
    PBE2PARAM* Res = NULL;
    Res = PBE2PARAM_new();
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    return Res;
}

int OSSL_HTTP_REQ_CTX_nbio(OSSL_HTTP_REQ_CTX* ctx) {
    int Res = 0;
    sf_set_must_be_not_null(ctx, NBIO_OF_NULL);
    Res = OSSL_HTTP_REQ_CTX_nbio(ctx);
    sf_set_errno_if(Res == -1);
    sf_set_possible_null(Res);
    return Res;
}

void (X509_LOOKUP*)* X509_LOOKUP_meth_get_free(const X509_LOOKUP_METHOD* method) {
    void (X509_LOOKUP*)* Res = NULL;
    sf_set_must_be_not_null(method, FREE_OF_NULL);
    Res = X509_LOOKUP_meth_get_free(method);
    sf_set_possible_null(Res);
    return Res;
}

BN_GENCB* BN_GENCB_new() {
    BN_GENCB* Res = NULL;
    Res = BN_GENCB_new();
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    return Res;
}
int EVP_PKEY_CTX_md(EVP_PKEY_CTX* ctx, int md, int override, const char* props);

unsigned long OpenSSL_version_num();

void X509_CRL_INFO_free(X509_CRL_INFO* a);

int EVP_PKEY_CTX_set_dh_paramgen_prime_len(EVP_PKEY_CTX* ctx, int len);

ASYNC_WAIT_CTX* ASYNC_get_wait_ctx(ASYNC_JOB* job);


int X509_PUBKEY_get0_param(ASN1_OBJECT** ppobj, const unsigned char** ppm, int* ppl, X509_ALGOR** ppalg, const X509_PUBKEY* pub)
{
    int ret = X509_PUBKEY_get0_param(ppobj, ppm, ppl, ppalg, pub);
    sf_set_errno_if(ret == 0, EINVAL);
    return ret;
}

ASN1_STRING* d2i_DIRECTORYSTRING(ASN1_STRING** a, const unsigned char** in, long len)
{
    ASN1_STRING* ret = d2i_ASN1_type_bytes(a, in, len);
    sf_set_errno_if(ret == NULL, EINVAL);
    return ret;
}

X509_LOOKUP_METHOD* X509_LOOKUP_hash_dir()
{
    X509_LOOKUP_METHOD* ret = X509_LOOKUP_hash_dir();
    sf_set_errno_if(ret == NULL, EINVAL);
    return ret;
}

char* CONF_get1_default_config_file()
{
    char* ret = CONF_get1_default_config_file();
    sf_set_errno_if(ret == NULL, EINVAL);
    return ret;
}

void EVP_SIGNATURE_do_all_provided(OSSL_LIB_CTX* ctx, void (EVP_SIGNATURE*, void*)* cb, void* arg)
{
    EVP_SIGNATURE_do_all_provided(ctx, cb, arg);
}
Here are the specifications for the mentioned functions:

1. int EVP_PKEY_set_size_t_param(EVP_PKEY* pkey, const char* key, size_t size)

    sf_set_trusted_sink_int(size);
    sf_set_tainted(key);
    sf_set_must_not_be_null(pkey);
    sf_set_must_not_be_null(key);
    sf_set_errno_if(pkey == NULL || key == NULL);
    sf_set_errno_if(EVP_PKEY_set_size_t_param(pkey, key, size) != 1);

2. int PEM_write_X509_AUX(FILE* out, const X509* x)

    sf_set_must_not_be_null(out);
    sf_set_must_not_be_null(x);
    sf_set_errno_if(out == NULL || x == NULL);
    sf_set_errno_if(PEM_write_X509_AUX(out, x) != 1);

3. int DH_meth_set_compute_key(DH_METHOD* dh_meth, int (*compute_key)(unsigned char* key, const BIGNUM* pub_key, DH* dh))

    sf_set_must_not_be_null(dh_meth);
    sf_set_must_not_be_null(compute_key);
    sf_set_errno_if(dh_meth == NULL || compute_key == NULL);
    sf_set_errno_if(DH_meth_set_compute_key(dh_meth, compute_key) != 1);

4. char* OPENSSL_buf2hexstr(const unsigned char* buf, long len)

    sf_set_must_not_be_null(buf);
    sf_set_must_not_be_null(len);
    sf_set_errno_if(buf == NULL || len == 0);
    sf_set_errno_if(OPENSSL_buf2hexstr(buf, len) == NULL);

5. int X509_LOOKUP_by_subject(X509_LOOKUP* lookup, X509_LOOKUP_TYPE type, const X509_NAME* name, X509_OBJECT* obj)

    sf_set_must_not_be_null(lookup);
    sf_set_must_not_be_null(name);
    sf_set_must_not_be_null(obj);
    sf_set_errno_if(lookup == NULL || name == NULL || obj == NULL);
    sf_set_errno_if(X509_LOOKUP_by_subject(lookup, type, name, obj) != 1);
const SSL_METHOD* DTLSv1_2_client_method() {
    const SSL_METHOD* Res = NULL;
    Res = DTLSv1_2_client_method();
    sf_set_possible_null(Res);
    return Res;
}

void OCSP_SINGLERESP_free(OCSP_SINGLERESP* a) {
    sf_set_must_be_not_null(a, FREE_OF_NULL);
    OCSP_SINGLERESP_free(a);
    sf_delete(a, OCSP_SINGLERESP_CATEGORY);
}

const OSSL_PARAM* EVP_CIPHER_CTX_settable_params(EVP_CIPHER_CTX* ctx) {
    const OSSL_PARAM* Res = NULL;
    Res = EVP_CIPHER_CTX_settable_params(ctx);
    sf_set_possible_null(Res);
    return Res;
}

void OCSP_RESPID_free(OCSP_RESPID* id) {
    sf_set_must_be_not_null(id, FREE_OF_NULL);
    OCSP_RESPID_free(id);
    sf_delete(id, OCSP_RESPID_CATEGORY);
}

void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX* ctx) {
    sf_set_must_be_not_null(ctx, FREE_OF_NULL);
    EVP_CIPHER_CTX_free(ctx);
    sf_delete(ctx, EVP_CIPHER_CTX_CATEGORY);
}

EVP_PKEY* d2i_PrivateKey_ex(int type, EVP_PKEY** out, const unsigned char** in, long len, OSSL_LIB_CTX* libctx, const char* propq) {
    EVP_PKEY* Res = NULL;
    sf_set_trusted_sink_int(len);
    sf_malloc_arg(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    sf_lib_arg_type(Res, "EVP_PKEY");
    sf_bitcopy(Res, *out);
    sf_set_possible_null(Res);
    sf_buf_size_limit(Res, len);
    return Res;
}

int PEM_write_bio_DHxparams(BIO* bio, const DH* dh) {
    int Res = 0;
    sf_set_must_be_not_null(bio, "PEM_write_bio_DHxparams");
    sf_set_must_be_not_null(dh, "PEM_write_bio_DHxparams");
    sf_set_errno_if(Res <= 0);
    sf_no_errno_if(Res > 0);
    return Res;
}

int SSL_set_srp_server_param_pw(SSL* s, const char* username, const char* passwd, const char* grp) {
    int Res = 0;
    sf_set_must_be_not_null(s, "SSL_set_srp_server_param_pw");
    sf_password_use(passwd);
    sf_set_errno_if(Res <= 0);
    sf_no_errno_if(Res > 0);
    return Res;
}

void AUTHORITY_INFO_ACCESS_free(AUTHORITY_INFO_ACCESS* aia) {
    sf_set_must_be_not_null(aia, "AUTHORITY_INFO_ACCESS_free");
    sf_delete(aia, PAGES_MEMORY_CATEGORY);
    sf_lib_arg_type(aia, "AUTHORITY_INFO_ACCESS");
}

ASN1_TIME* X509_getm_notAfter(const X509* x) {
    ASN1_TIME* Res = NULL;
    sf_set_must_be_not_null(x, "X509_getm_notAfter");
    sf_malloc_arg(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    sf_lib_arg_type(Res, "ASN1_TIME");
    sf_bitcopy(Res, x->notAfter);
    sf_set_possible_null(Res);
    return Res;
}

int PKCS5_v2_scrypt_keyivgen_ex(EVP_CIPHER_CTX* ctx, const char* pass, int passlen, ASN1_TYPE* params, const EVP_CIPHER* cipher, const EVP_MD* md, int en_de, OSSL_LIB_CTX* libctx, const char* propq) {
    int Res = 0;
    sf_set_tainted(pass);
    sf_password_use(pass);
    sf_set_must_be_not_null(ctx, "PKCS5_v2_scrypt_keyivgen_ex");
    sf_set_must_be_not_null(cipher, "PKCS5_v2_scrypt_keyivgen_ex");
    sf_set_must_be_not_null(md, "PKCS5_v2_scrypt_keyivgen_ex");
    sf_set_must_be_not_null(libctx, "PKCS5_v2_scrypt_keyivgen_ex");
    sf_set_must_be_not_null(propq, "PKCS5_v2_scrypt_keyivgen_ex");
    Res = PKCS5_v2_scrypt_keyivgen_ex(ctx, pass, passlen, params, cipher, md, en_de, libctx, propq);
    sf_set_errno_if(Res <= 0, "PKCS5_v2_scrypt_keyivgen_ex");
    return Res;
}

int i2d_NETSCAPE_SPKI(const NETSCAPE_SPKI* a, unsigned char** pp) {
    int Res = 0;
    sf_set_must_be_not_null(a, "i2d_NETSCAPE_SPKI");
    sf_set_must_be_not_null(pp, "i2d_NETSCAPE_SPKI");
    Res = i2d_NETSCAPE_SPKI(a, pp);
    sf_set_errno_if(Res <= 0, "i2d_NETSCAPE_SPKI");
    return Res;
}

ASN1_VALUE* ASN1_item_new(const ASN1_ITEM* it) {
    ASN1_VALUE* Res = NULL;
    sf_set_must_be_not_null(it, "ASN1_item_new");
    Res = ASN1_item_new(it);
    sf_set_alloc_possible_null(Res);
    return Res;
}

ECPKPARAMETERS* ECPKPARAMETERS_new() {
    ECPKPARAMETERS* Res = NULL;
    Res = ECPKPARAMETERS_new();
    sf_set_alloc_possible_null(Res);
    return Res;
}

EC_KEY* PEM_read_bio_EC_PUBKEY(BIO* bio, EC_KEY** ec_key, pem_password_cb* cb, void* u) {
    EC_KEY* Res = NULL;
    sf_set_must_be_not_null(bio, "PEM_read_bio_EC_PUBKEY");
    Res = PEM_read_bio_EC_PUBKEY(bio, ec_key, cb, u);
    sf_set_errno_if(Res == NULL, "PEM_read_bio_EC_PUBKEY");
    return Res;
}

int EVP_PKEY_CTX_set_rsa_mgf1_md(EVP_PKEY_CTX *ctx, const EVP_MD *md)
{
    int res = 0;
    sf_set_trusted_sink_int(ctx);
    sf_set_trusted_sink_ptr(md);
    res = EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md);
    sf_set_errno_if(res <= 0);
    return res;
}

ASN1_UTCTIME* ASN1_UTCTIME_adj(ASN1_UTCTIME *s, time_t t, int offset_day, long offset_sec)
{
    ASN1_UTCTIME *res = NULL;
    sf_set_trusted_sink_ptr(s);
    sf_set_trusted_sink_int(t);
    sf_set_trusted_sink_int(offset_day);
    sf_set_trusted_sink_int(offset_sec);
    res = ASN1_UTCTIME_adj(s, t, offset_day, offset_sec);
    sf_set_errno_if(res == NULL);
    return res;
}

void X509_LOOKUP_meth_free(X509_LOOKUP_METHOD *method)
{
    sf_set_trusted_sink_ptr(method);
    X509_LOOKUP_meth_free(method);
}

OCSP_CERTID* OCSP_cert_id_new(const EVP_MD *md, const X509_NAME *issuerName, const ASN1_BIT_STRING *issuerKey, const ASN1_INTEGER *serialNumber)
{
    OCSP_CERTID *res = NULL;
    sf_set_trusted_sink_ptr(md);
    sf_set_trusted_sink_ptr(issuerName);
    sf_set_trusted_sink_ptr(issuerKey);
    sf_set_trusted_sink_ptr(serialNumber);
    res = OCSP_cert_id_new(md, issuerName, issuerKey, serialNumber);
    sf_set_errno_if(res == NULL);
    return res;
}

int SSL_set0_tmp_dh_pkey(SSL *ssl, EVP_PKEY *pkey)
{
    int res = 0;
    sf_set_trusted_sink_ptr(ssl);
    sf_set_trusted_sink_ptr(pkey);
    res = SSL_set0_tmp_dh_pkey(ssl, pkey);
    sf_set_errno_if(res <= 0);
    return res;
}

stack_st_X509_INFO* PEM_X509_INFO_read(FILE *fp, stack_st_X509_INFO *sk, pem_password_cb *cb, void *u) {
    stack_st_X509_INFO *Res = NULL;
    sf_set_trusted_sink_int(fp);
    sf_set_trusted_sink_ptr(sk);
    sf_set_trusted_sink_ptr(cb);
    sf_set_trusted_sink_ptr(u);
    sf_set_errno_if(Res == NULL);
    sf_no_errno_if(Res != NULL);
    return Res;
}

int ENGINE_register_digests(ENGINE *e) {
    int Res = 0;
    sf_set_trusted_sink_ptr(e);
    sf_set_errno_if(Res == 0);
    sf_no_errno_if(Res != 0);
    return Res;
}

void EVP_ENCODE_CTX_free(EVP_ENCODE_CTX *ctx) {
    sf_set_trusted_sink_ptr(ctx);
    sf_delete(ctx, MALLOC_CATEGORY);
    sf_lib_arg_type(ctx, "MallocCategory");
}

OSSL_PARAM OSSL_PARAM_construct_double(const char *key, double *val) {
    OSSL_PARAM Res;
    sf_set_trusted_sink_ptr(key);
    sf_set_trusted_sink_ptr(val);
    sf_set_tainted(val);
    return Res;
}

int EVP_PKEY_CTX_set_rsa_keygen_pubexp(EVP_PKEY_CTX *ctx, BIGNUM *pubexp) {
    int Res = 0;
    sf_set_trusted_sink_ptr(ctx);
    sf_set_trusted_sink_ptr(pubexp);
    sf_set_errno_if(Res == 0);
    sf_no_errno_if(Res != 0);
    return Res;
}

const X509_ALGOR* X509_get0_tbs_sigalg(const X509* x) {
    const X509_ALGOR* Res = NULL;
    sf_set_must_be_not_null(x, X509_NULL);
    Res = X509_get0_tbs_sigalg(x);
    sf_set_possible_null(Res);
    return Res;
}

int HMAC_CTX_reset(HMAC_CTX* ctx) {
    int Res = 0;
    sf_set_must_be_not_null(ctx, HMAC_CTX_NULL);
    Res = HMAC_CTX_reset(ctx);
    return Res;
}

OCSP_SERVICELOC* OCSP_SERVICELOC_new() {
    OCSP_SERVICELOC* Res = NULL;
    Res = OCSP_SERVICELOC_new();
    sf_set_possible_null(Res);
    return Res;
}

int X509_STORE_set_depth(X509_STORE* store, int depth) {
    int Res = 0;
    sf_set_must_be_not_null(store, X509_STORE_NULL);
    sf_set_must_be_positive(depth, DEPTH_NEGATIVE);
    Res = X509_STORE_set_depth(store, depth);
    return Res;
}

int ENGINE_set_load_privkey_function(ENGINE* e, ENGINE_LOAD_KEY_PTR load_privkey_function) {
    int Res = 0;
    sf_set_must_be_not_null(e, ENGINE_NULL);
    Res = ENGINE_set_load_privkey_function(e, load_privkey_function);
    return Res;
}
PKCS7* SMIME_read_PKCS7(BIO*, BIO**);

int i2d_IPAddressChoice(const IPAddressChoice*, unsigned char**);

const EVP_CIPHER* EVP_chacha20();

void* X509V3_get_d2i(const stack_st_X509_EXTENSION*, int, int*, int*);

int EC_GROUP_get_basis_type(const EC_GROUP*);


int BIO_set_cipher(BIO* bio, const EVP_CIPHER* cipher, const unsigned char* key, const unsigned char* iv, int enc) {
    int Res = 0;
    // Check for null pointers and other necessary conditions
    // Perform memory allocation and initialization if necessary
    // Set trusted sink pointers if necessary
    // Mark password usage
    // Mark memory initialization
    // Mark memory overwrite
    // Mark string and buffer operations
    // Check for error handling
    // Check for TOCTTOU race conditions
    // Check for file descriptor validity
    // Mark tainted data
    // Mark sensitive data
    // Mark time usage
    // Limit buffer size
    // Terminate program path if necessary
    // Set library argument type
    // Check for null values
    // Check for possible negative return values
    // Mark uncontrolled pointers
    return Res;
}

int EVP_PKEY_asn1_add0(const EVP_PKEY_ASN1_METHOD* method) {
    int Res = 0;
    // Check for null pointers and other necessary conditions
    // Perform memory allocation and initialization if necessary
    // Set trusted sink pointers if necessary
    // Mark password usage
    // Mark memory initialization
    // Mark memory overwrite
    // Mark string and buffer operations
    // Check for error handling
    // Check for TOCTTOU race conditions
    // Check for file descriptor validity
    // Mark tainted data
    // Mark sensitive data
    // Mark time usage
    // Limit buffer size
    // Terminate program path if necessary
    // Set library argument type
    // Check for null values
    // Check for possible negative return values
    // Mark uncontrolled pointers
    return Res;
}

int EVP_PKEY_set_utf8_string_param(EVP_PKEY* pkey, const char* key, const char* value) {
    int Res = 0;
    // Check for null pointers and other necessary conditions
    // Perform memory allocation and initialization if necessary
    // Set trusted sink pointers if necessary
    // Mark password usage
    // Mark memory initialization
    // Mark memory overwrite
    // Mark string and buffer operations
    // Check for error handling
    // Check for TOCTTOU race conditions
    // Check for file descriptor validity
    // Mark tainted data
    // Mark sensitive data
    // Mark time usage
    // Limit buffer size
    // Terminate program path if necessary
    // Set library argument type
    // Check for null values
    // Check for possible negative return values
    // Mark uncontrolled pointers
    return Res;
}

int DH_meth_get_flags(const DH_METHOD* dh_meth) {
    int Res = 0;
    // Check for null pointers and other necessary conditions
    // Perform memory allocation and initialization if necessary
    // Set trusted sink pointers if necessary
    // Mark password usage
    // Mark memory initialization
    // Mark memory overwrite
    // Mark string and buffer operations
    // Check for error handling
    // Check for TOCTTOU race conditions
    // Check for file descriptor validity
    // Mark tainted data
    // Mark sensitive data
    // Mark time usage
    // Limit buffer size
    // Terminate program path if necessary
    // Set library argument type
    // Check for null values
    // Check for possible negative return values
    // Mark uncontrolled pointers
    return Res;
}

size_t SCT_get0_signature(const SCT* sct, unsigned char** signature) {
    size_t Res = 0;
    // Check for null pointers and other necessary conditions
    // Perform memory allocation and initialization if necessary
    // Set trusted sink pointers if necessary
    // Mark password usage
    // Mark memory initialization
    // Mark memory overwrite
    // Mark string and buffer operations
    // Check for error handling
    // Check for TOCTTOU race conditions
    // Check for file descriptor validity
    // Mark tainted data
    // Mark sensitive data
    // Mark time usage
    // Limit buffer size
    // Terminate program path if necessary
    // Set library argument type
    // Check for null values
    // Check for possible negative return values
    // Mark uncontrolled pointers
    return Res;
}

int OCSP_id_cmp(const OCSP_CERTID* a, const OCSP_CERTID* b)
{
    int res = 0;
    sf_set_must_be_not_null(a, OCSP_CERTID_NULL);
    sf_set_must_be_not_null(b, OCSP_CERTID_NULL);
    // Compare a and b
    return res;
}

void RAND_add(const void* buf, int num, double entropy)
{
    sf_set_must_be_not_null(buf, RAND_ADD_BUF_NULL);
    sf_set_trusted_sink_int(num);
    // Add buf to the PRNG state
}

int PEM_write_PKCS8PrivateKey_nid(FILE* fp, const EVP_PKEY* x, int nid, const char* kstr, int klen, pem_password_cb* cb, void* u)
{
    int res = 0;
    sf_set_must_be_not_null(fp, FILE_NULL);
    sf_set_must_be_not_null(x, EVP_PKEY_NULL);
    sf_password_use(kstr, klen);
    // Write x to fp in PKCS#8 format
    return res;
}

X509_SIG* PEM_read_bio_PKCS8(BIO* bp, X509_SIG** x, pem_password_cb* cb, void* u)
{
    X509_SIG* res = NULL;
    sf_set_must_be_not_null(bp, BIO_NULL);
    // Read and decode an X509_SIG from a BIO in PKCS#8 format
    return res;
}

void EVP_PKEY_meth_get_digestsign(const EVP_PKEY_METHOD* meth, int (EVP_MD_CTX*, unsigned char*, size_t*, const unsigned char*, size_t)** sign_init)
{
    sf_set_must_be_not_null(meth, EVP_PKEY_METHOD_NULL);
    // Get the digestsign method from meth
}

int EVP_PKEY_CTX_set_ecdh_cofactor_mode(EVP_PKEY_CTX *ctx, int mode)
{
    int Res = 0;
    sf_set_tainted(ctx);
    sf_set_tainted(mode);
    sf_set_must_be_not_null(ctx, SET_ECDH_COFACTOR_MODE_OF_NULL);
    sf_set_errno_if(Res == 0, SET_ECDH_COFACTOR_MODE_FAILURE);
    return Res;
}

void EVP_PKEY_meth_set_derive(EVP_PKEY_METHOD *pmeth,
                               int (*derive_init) (EVP_PKEY_CTX *ctx),
                               int (*derive) (EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen))
{
    sf_set_tainted(pmeth);
    sf_set_tainted(derive_init);
    sf_set_tainted(derive);
    sf_set_must_be_not_null(pmeth, SET_DERIVE_INIT_OF_NULL);
    sf_set_must_be_not_null(derive_init, SET_DERIVE_INIT_OF_NULL);
    sf_set_must_be_not_null(derive, SET_DERIVE_OF_NULL);
}

void EVP_PKEY_asn1_set_get_pub_key(EVP_PKEY_ASN1_METHOD *ameth,
                                    int (*get_pub_key) (const EVP_PKEY *pkey, unsigned char **pub, size_t *len))
{
    sf_set_tainted(ameth);
    sf_set_tainted(get_pub_key);
    sf_set_must_be_not_null(ameth, SET_GET_PUB_KEY_OF_NULL);
    sf_set_must_be_not_null(get_pub_key, SET_GET_PUB_KEY_OF_NULL);
}

int EVP_PKEY_CTX_set_mac_key(EVP_PKEY_CTX *ctx, const unsigned char *key, int keylen)
{
    int Res = 0;
    sf_set_tainted(ctx);
    sf_set_tainted(key);
    sf_set_tainted(keylen);
    sf_set_must_be_not_null(ctx, SET_MAC_KEY_OF_NULL);
    sf_set_must_be_not_null(key, SET_MAC_KEY_OF_NULL);
    sf_set_errno_if(Res == 0, SET_MAC_KEY_FAILURE);
    return Res;
}

int i2d_DHparams(const DH *dh, unsigned char **pp)
{
    int Res = 0;
    sf_set_tainted(dh);
    sf_set_tainted(pp);
    sf_set_must_be_not_null(dh, I2D_DHPARAMS_OF_NULL);
    sf_set_must_be_not_null(pp, I2D_DHPARAMS_OF_NULL);
    sf_set_errno_if(Res == 0, I2D_DHPARAMS_FAILURE);
    return Res;
}

RSA* d2i_RSA_PUBKEY_fp(FILE *fp, RSA **x)
{
    RSA *Res = NULL;
    sf_set_must_be_not_null(fp, FP_OF_NULL);
    sf_set_must_be_not_null(x, RSA_PTR_OF_NULL);
    sf_set_tainted(x, RSA_PTR_TAINTED);
    sf_set_errno_if(Res == NULL, ENOMEM);
    sf_set_alloc_possible_null(Res);
    sf_lib_arg_type(Res, "RSA");
    return Res;
}

const EVP_CIPHER* EVP_camellia_256_ctr()
{
    const EVP_CIPHER *Res = NULL;
    sf_set_errno_if(Res == NULL, ENOMEM);
    sf_set_possible_null(Res);
    sf_lib_arg_type(Res, "EVP_CIPHER");
    return Res;
}

void OTHERNAME_free(OTHERNAME *a)
{
    sf_set_must_be_not_null(a, OTHERNAME_FREE_OF_NULL);
    sf_delete(a, OTHERNAME_MEMORY_CATEGORY);
    sf_lib_arg_type(a, "OTHERNAME");
}

int ENGINE_set_default_string(ENGINE *e, const char *str)
{
    int Res = 0;
    sf_set_must_be_not_null(e, ENGINE_SET_DEFAULT_STRING_OF_NULL);
    sf_set_tainted((void *)str, STRING_TAINTED);
    sf_set_errno_if(Res <= 0, EINVAL);
    return Res;
}

int BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
{
    int Res = 0;
    sf_set_must_be_not_null(r, BN_MUL_R_OF_NULL);
    sf_set_must_be_not_null(a, BN_MUL_A_OF_NULL);
    sf_set_must_be_not_null(b, BN_MUL_B_OF_NULL);
    sf_set_must_be_not_null(ctx, BN_MUL_CTX_OF_NULL);
    sf_set_errno_if(Res <= 0, EINVAL);
    return Res;
}

int X509_CRL_match(const X509_CRL* a, const X509_CRL* b) {
    int Res = 0;
    // Specification code here
    return Res;
}

int SSL_get_ex_data_X509_STORE_CTX_idx() {
    int Res = 0;
    // Specification code here
    return Res;
}

DSA* d2i_DSAPrivateKey_bio(BIO* bp, DSA** a) {
    DSA* Res = NULL;
    // Specification code here
    return Res;
}

int EVP_PKEY_type_names_do_all(const EVP_PKEY* pkey, void (const char*, void*)* fn, void* arg) {
    int Res = 0;
    // Specification code here
    return Res;
}

int i2d_DSAPrivateKey_fp(FILE* fp, const DSA* a) {
    int Res = 0;
    // Specification code here
    return Res;
}

void EVP_PKEY_meth_set_encrypt(EVP_PKEY_METHOD *pkey_meth, int (*encrypt_init)(), int (*encrypt_fn)(EVP_PKEY_CTX*, unsigned char*, size_t*, const unsigned char*, size_t)) {
    sf_set_trusted_sink_int(encrypt_init);
    sf_set_trusted_sink_int(encrypt_fn);
    // Rest of the function
}

int PEM_write_RSAPrivateKey(FILE *fp, const RSA *x, const EVP_CIPHER *enc, const unsigned char *kstr, int klen, pem_password_cb *cb, void *u) {
    sf_password_use(cb);
    sf_password_use(u);
    // Rest of the function
}

pem_password_cb* SSL_CTX_get_default_passwd_cb(SSL_CTX *ctx) {
    pem_password_cb *res = NULL;
    sf_set_possible_null(res);
    // Rest of the function
    return res;
}

int BIO_gets(BIO *bp, char *buf, int size) {
    int res = 0;
    sf_buf_size_limit(buf, size);
    // Rest of the function
    return res;
}

int i2d_AUTHORITY_KEYID(const AUTHORITY_KEYID *a, unsigned char **pp) {
    int res = 0;
    sf_set_trusted_sink_ptr(pp);
    // Rest of the function
    return res;
}

size_t EC_GROUP_get_seed_len(const EC_GROUP* group) {
    size_t res = 0;
    sf_set_must_not_be_null(group);
    sf_set_trusted_sink_int(res);
    sf_set_errno_if(res == 0);
    return res;
}

AUTHORITY_KEYID* d2i_AUTHORITY_KEYID(AUTHORITY_KEYID** a, const unsigned char** in, long len) {
    AUTHORITY_KEYID* res = NULL;
    sf_set_must_not_be_null(a);
    sf_set_must_not_be_null(*a);
    sf_set_trusted_sink_ptr(in);
    sf_set_errno_if(res == NULL);
    return res;
}

const EVP_CIPHER* EVP_bf_cbc() {
    const EVP_CIPHER* res = NULL;
    sf_set_errno_if(res == NULL);
    return res;
}

unsigned char* EVP_CIPHER_CTX_iv_noconst(EVP_CIPHER_CTX* ctx) {
    unsigned char* res = NULL;
    sf_set_must_not_be_null(ctx);
    sf_set_errno_if(res == NULL);
    return res;
}

X509* SSL_get0_peer_certificate(const SSL* s) {
    X509* res = NULL;
    sf_set_must_not_be_null(s);
    sf_set_errno_if(res == NULL);
    return res;
}

X509_PUBKEY* d2i_X509_PUBKEY_fp(FILE *fp, X509_PUBKEY **x)
{
    X509_PUBKEY *Res = NULL;
    sf_set_trusted_sink_int(fp);
    sf_set_trusted_sink_ptr(x);
    Res = d2i_X509_PUBKEY_fp(fp, x);
    sf_overwrite(Res);
    return Res;
}

int SSL_waiting_for_async(SSL *s)
{
    int Res = 0;
    sf_set_tainted(s);
    Res = SSL_waiting_for_async(s);
    sf_set_errno_if(Res == -1);
    return Res;
}

void X509_STORE_CTX_cleanup(X509_STORE_CTX *ctx)
{
    sf_set_tainted(ctx);
    X509_STORE_CTX_cleanup(ctx);
}

const BIGNUM* DH_get0_priv_key(const DH *dh)
{
    const BIGNUM *Res = NULL;
    sf_set_tainted(dh);
    Res = DH_get0_priv_key(dh);
    sf_set_possible_null(Res);
    return Res;
}

const EVP_CIPHER* EVP_aria_256_ctr()
{
    const EVP_CIPHER *Res = NULL;
    Res = EVP_aria_256_ctr();
    sf_set_possible_null(Res);
    return Res;
}

BIO* OSSL_HTTP_get(const char* tls_hostname, const char* tls_certfile, const char* tls_keyfile, BIO* bio, BIO* connect_bio, OSSL_HTTP_bio_cb_t bio_update_fn, void* cb_arg, int buf_size, const stack_st_CONF_VALUE* proxy, const char* no_proxy, int timeout, size_t max_response_len, int expect_asn1)
{
    BIO* Res = NULL;
    // Perform all the necessary actions
    // ...
    return Res;
}

int EVP_DecodeBlock(unsigned char* out, const unsigned char* in, int inl)
{
    int Res = 0;
    // Perform all the necessary actions
    // ...
    return Res;
}

int PEM_write_DSAPrivateKey(FILE* fp, const DSA* x, const EVP_CIPHER* enc, const unsigned char* kstr, int klen, pem_password_cb* cb, void* u)
{
    int Res = 0;
    // Perform all the necessary actions
    // ...
    return Res;
}

int OSSL_PARAM_set_utf8_string(OSSL_PARAM* param, const char* str)
{
    int Res = 0;
    // Perform all the necessary actions
    // ...
    return Res;
}

int EVP_CipherUpdate(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl, const unsigned char* in, int inl)
{
    int Res = 0;
    // Perform all the necessary actions
    // ...
    return Res;
}
void OCSP_ONEREQ_free(OCSP_ONEREQ* req);

int EVP_PBE_alg_add_type(int nid, int pbe_nid, int cipher_nid, int md_nid, EVP_PBE_KEYGEN* keygen);

const EVP_CIPHER* EVP_aes_192_wrap();

int SSL_client_hello_get1_extensions_present(SSL* s, int** out_exts, size_t* out_len);

int BIO_meth_set_read(BIO_METHOD* biom, int (BIO*, char*, int);


int OSSL_PARAM_get_octet_string(const OSSL_PARAM *param, void **val, size_t max_len, size_t *used_len)
{
    int Res = 0;
    sf_set_trusted_sink_int(max_len);
    sf_set_trusted_sink_ptr(used_len);
    sf_set_must_be_not_null(param, PARAM_OF_NULL);
    sf_set_must_be_not_null(val, VAL_OF_NULL);
    sf_set_possible_null(Res);
    return Res;
}

int EVP_Digest(const void *data, size_t count, unsigned char *md, unsigned int *size, const EVP_MD *type, ENGINE *impl)
{
    int Res = 0;
    sf_set_must_be_not_null(data, DATA_OF_NULL);
    sf_set_must_be_not_null(md, MD_OF_NULL);
    sf_set_must_be_not_null(size, SIZE_OF_NULL);
    sf_set_must_be_not_null(type, TYPE_OF_NULL);
    sf_set_possible_null(Res);
    return Res;
}

void OCSP_RESPONSE_free(OCSP_RESPONSE *response)
{
    sf_set_must_be_not_null(response, RESPONSE_OF_NULL);
    sf_delete(response, OCSP_RESPONSE_CATEGORY);
    sf_lib_arg_type(response, "OCSPResponse");
}

int ENGINE_set_flags(ENGINE *e, int flags)
{
    int Res = 0;
    sf_set_must_be_not_null(e, ENGINE_OF_NULL);
    sf_set_possible_null(Res);
    return Res;
}

void *ENGINE_get_ex_data(const ENGINE *e, int idx)
{
    void *Res = NULL;
    sf_set_must_be_not_null(e, ENGINE_OF_NULL);
    sf_set_possible_null(Res);
    return Res;
}

BIGNUM* ASN1_ENUMERATED_to_BN(const ASN1_ENUMERATED* a, BIGNUM* b) {
    BIGNUM* Res = NULL;
    sf_set_trusted_sink_int(a);
    sf_set_trusted_sink_ptr(b);
    Res = BN_bin2bn((const unsigned char*)a->data, a->length, b);
    sf_overwrite(Res);
    return Res;
}

int OPENSSL_hexstr2buf_ex(unsigned char* buf, size_t buf_max_len, size_t* buf_len, const char* str) {
    int Res = 0;
    sf_set_trusted_sink_ptr(buf);
    sf_set_trusted_sink_ptr(buf_len);
    Res = OPENSSL_hexstr2buf(buf, buf_max_len, buf_len, str);
    sf_overwrite(Res);
    return Res;
}

const char* OSSL_default_ciphersuites() {
    const char* Res = NULL;
    Res = OSSL_default_cipher_list();
    sf_set_possible_null(Res);
    return Res;
}

int EC_POINT_set_affine_coordinates_GFp(const EC_GROUP* group, EC_POINT* point, const BIGNUM* x, const BIGNUM* y, BN_CTX* ctx) {
    int Res = 0;
    sf_set_trusted_sink_ptr(group);
    sf_set_trusted_sink_ptr(point);
    sf_set_trusted_sink_ptr(x);
    sf_set_trusted_sink_ptr(y);
    sf_set_trusted_sink_ptr(ctx);
    Res = EC_POINT_set_affine_coordinates(group, point, x, y, ctx);
    sf_overwrite(Res);
    return Res;
}

long SSL_get_verify_result(const SSL* s) {
    long Res = 0;
    sf_set_trusted_sink_ptr(s);
    Res = SSL_get_verify_result(s);
    sf_overwrite(Res);
    return Res;
}

int EVP_PKEY_param_check(EVP_PKEY_CTX *ctx) {
    int Res = 0;
    sf_set_must_be_not_null(ctx, PARAM_CHECK_OF_NULL);
    Res = EVP_PKEY_param_check(ctx);
    sf_set_errno_if(Res <= 0, PARAM_CHECK_FAILURE);
    return Res;
}

void IPAddressRange_free(IPAddressRange *range) {
    sf_set_must_be_not_null(range, FREE_OF_NULL);
    sf_delete(range, IP_ADDRESS_RANGE_CATEGORY);
    IPAddressRange_free(range);
}

int X509_STORE_CTX_get_num_untrusted(const X509_STORE_CTX *ctx) {
    int Res = 0;
    sf_set_must_be_not_null(ctx, GET_NUM_UNTRUSTED_OF_NULL);
    Res = X509_STORE_CTX_get_num_untrusted(ctx);
    sf_set_errno_if(Res < 0, GET_NUM_UNTRUSTED_FAILURE);
    return Res;
}

void RSA_set_default_method(const RSA_METHOD *meth) {
    sf_set_must_be_not_null(meth, SET_DEFAULT_METHOD_OF_NULL);
    RSA_set_default_method(meth);
}

const EVP_CIPHER* EVP_aria_192_ecb() {
    const EVP_CIPHER *Res = NULL;
    Res = EVP_aria_192_ecb();
    sf_set_possible_null(Res, EVP_ARIA_192_ECB_NULL);
    return Res;
}

const OSSL_PROVIDER* EVP_CIPHER_get0_provider(const EVP_CIPHER* cipher) {
    const OSSL_PROVIDER* Res = NULL;
    sf_set_trusted_sink_ptr(cipher);
    sf_set_possible_null(Res);
    return Res;
}

void DSA_SIG_get0(const DSA_SIG* sig, const BIGNUM** pr, const BIGNUM** ps) {
    sf_set_trusted_sink_ptr(sig);
    sf_set_trusted_sink_ptr(pr);
    sf_set_trusted_sink_ptr(ps);
}

stack_st_X509* SSL_get_peer_cert_chain(const SSL* s) {
    stack_st_X509* Res = NULL;
    sf_set_trusted_sink_ptr(s);
    sf_set_possible_null(Res);
    return Res;
}

X509* d2i_X509_bio(BIO* bp, X509** x) {
    X509* Res = NULL;
    sf_set_trusted_sink_ptr(bp);
    sf_set_trusted_sink_ptr(x);
    sf_set_possible_null(Res);
    return Res;
}

int DSA_meth_set_flags(DSA_METHOD* dsa, int flags) {
    int Res = 0;
    sf_set_trusted_sink_ptr(dsa);
    sf_set_trusted_sink_int(flags);
    return Res;
}

const EVP_CIPHER* EVP_aria_192_cfb1() {
    const EVP_CIPHER* Res = NULL;
    Res = EVP_aria_192_cfb1();
    sf_set_possible_null(Res);
    return Res;
}

const EVP_CIPHER* EVP_des_ede3_wrap() {
    const EVP_CIPHER* Res = NULL;
    Res = EVP_des_ede3_wrap();
    sf_set_possible_null(Res);
    return Res;
}

int OSSL_PARAM_set_octet_string(OSSL_PARAM* param, const void* data, size_t len) {
    int Res = 0;
    sf_set_trusted_sink_int(len);
    Res = OSSL_PARAM_set_octet_string(param, data, len);
    sf_set_errno_if(Res == 0);
    return Res;
}

int DSA_meth_set_bn_mod_exp(DSA_METHOD* dsa, int (*bn_mod_exp)(DSA*, BIGNUM*, const BIGNUM*, const BIGNUM*, const BIGNUM*, BN_CTX*, BN_MONT_CTX*)) {
    int Res = 0;
    Res = DSA_meth_set_bn_mod_exp(dsa, bn_mod_exp);
    sf_set_errno_if(Res == 0);
    return Res;
}

int EC_KEY_set_method(EC_KEY* key, const EC_KEY_METHOD* method) {
    int Res = 0;
    Res = EC_KEY_set_method(key, method);
    sf_set_errno_if(Res == 0);
    return Res;
}

void SSL_CTX_set_cookie_generate_cb(SSL_CTX* ctx, int (*cb)(SSL*, unsigned char*, unsigned int*))
{
    sf_set_trusted_sink_ptr(ctx);
    sf_set_trusted_sink_ptr(cb);
    // implementation
}

int SSL_write_ex(SSL* ssl, const void* buf, size_t num, size_t* written)
{
    sf_set_trusted_sink_ptr(ssl);
    sf_set_trusted_sink_ptr(buf);
    sf_set_trusted_sink_ptr(written);
    // implementation
}

NAME_CONSTRAINTS* NAME_CONSTRAINTS_new()
{
    NAME_CONSTRAINTS* res = NULL;
    sf_new(res, NAME_CONSTRAINTS_MEMORY_CATEGORY);
    // implementation
    return res;
}

int SSL_CTX_use_PrivateKey_ASN1(int type, SSL_CTX* ctx, const unsigned char* d, long len)
{
    sf_set_trusted_sink_int(type);
    sf_set_trusted_sink_ptr(ctx);
    sf_set_trusted_sink_ptr(d);
    sf_set_trusted_sink_int(len);
    // implementation
}

int EVP_CIPHER_meth_set_do_cipher(EVP_CIPHER* cipher, int (*do_cipher)(EVP_CIPHER_CTX*, unsigned char*, const unsigned char*, size_t))
{
    sf_set_trusted_sink_ptr(cipher);
    sf_set_trusted_sink_ptr(do_cipher);
    // implementation
}
int SSL_CTX_set_ctlog_list_file(SSL_CTX*, const char*);

int EVP_CIPHER_CTX_test_flags(const EVP_CIPHER_CTX*, int);

RAND_METHOD* RAND_OpenSSL();

int EVP_KEYEXCH_names_do_all(const EVP_KEYEXCH*, void (const char*, void*);

OCSP_BASICRESP* OCSP_response_get1_basic(OCSP_RESPONSE*);


unsigned long BN_BLINDING_get_flags(const BN_BLINDING* b) {
    unsigned long Res = 0;
    sf_set_trusted_sink_int(Res);
    sf_overwrite(Res);
    return Res;
}

const EVP_CIPHER* EVP_enc_null() {
    const EVP_CIPHER* Res = NULL;
    sf_set_possible_null(Res);
    return Res;
}

X509_CRL* X509_CRL_dup(const X509_CRL* crl) {
    X509_CRL* Res = NULL;
    sf_set_alloc_possible_null(Res);
    return Res;
}

int EC_POINTs_make_affine(const EC_GROUP* group, size_t num, EC_POINT* points[], BN_CTX* ctx) {
    int Res = 0;
    sf_set_errno_if(Res);
    return Res;
}

int i2d_X509_REQ(const X509_REQ* req, unsigned char** pp) {
    int Res = 0;
    sf_set_errno_if(Res);
    return Res;
}

// PBKDF2PARAM* PBKDF2PARAM_new()
PBKDF2PARAM* PBKDF2PARAM_new() {
    PBKDF2PARAM* Res = NULL;
    Res = (PBKDF2PARAM*)sf_malloc_arg(sizeof(PBKDF2PARAM));
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    return Res;
}

// int ASN1_GENERALIZEDTIME_check(const ASN1_GENERALIZEDTIME* time)
int ASN1_GENERALIZEDTIME_check(const ASN1_GENERALIZEDTIME* time) {
    int Res = 0;
    Res = time->type;
    sf_overwrite(&Res);
    return Res;
}

// const dh_st* EVP_PKEY_get0_DH(const EVP_PKEY* pkey)
const dh_st* EVP_PKEY_get0_DH(const EVP_PKEY* pkey) {
    const dh_st* Res = NULL;
    Res = pkey->pkey.dh;
    sf_overwrite(Res);
    return Res;
}

// const SSL_METHOD* TLSv1_2_server_method()
const SSL_METHOD* TLSv1_2_server_method() {
    const SSL_METHOD* Res = NULL;
    Res = TLSv1_2_server_method();
    sf_overwrite(Res);
    return Res;
}

// int X509_set_serialNumber(X509* x, ASN1_INTEGER* serial)
int X509_set_serialNumber(X509* x, ASN1_INTEGER* serial) {
    int Res = 0;
    Res = X509_set_serialNumber(x, serial);
    sf_overwrite(&Res);
    return Res;
}
int i2d_PKCS7_ENCRYPT(const PKCS7_ENCRYPT* a, unsigned char** pp);

void X509_STORE_free(X509_STORE* a);

X509_REQ_INFO* d2i_X509_REQ_INFO(X509_REQ_INFO** a, const unsigned char** pp, long length);

unsigned char* SHA224(const unsigned char* d, size_t n, unsigned char* md);

BIO* BIO_next(BIO* a);

int EVP_SIGNATURE_is_a(const EVP_SIGNATURE* sig, const char* name);

int PEM_write_bio_PrivateKey_ex(BIO* bio, const EVP_PKEY* key, const EVP_CIPHER* cipher, const unsigned char* passwd, int len, pem_password_cb* cb, void* u, OSSL_LIB_CTX* libctx, const char* propq);

const EVP_CIPHER* EVP_aes_256_cfb128();

int BN_lshift(BIGNUM* r, const BIGNUM* a, int n);

void EVP_KEYEXCH_free(EVP_KEYEXCH* keyexch);


int BIO_get_init(BIO* bio) {
    int res = 0;
    sf_set_must_be_not_null(bio, BIO_INIT_OF_NULL);
    sf_set_errno_if(res == 0, ERRNO_BIO_INIT);
    return res;
}

DH* DH_new() {
    DH* res = NULL;
    sf_set_alloc_possible_null(res);
    sf_new(res, DH_MEMORY_CATEGORY);
    sf_set_possible_null(res);
    return res;
}

ASN1_STRING* DIRECTORYSTRING_new() {
    ASN1_STRING* res = NULL;
    sf_set_alloc_possible_null(res);
    sf_new(res, ASN1_STRING_MEMORY_CATEGORY);
    sf_set_possible_null(res);
    return res;
}

void PROXY_POLICY_free(PROXY_POLICY* policy) {
    sf_set_must_be_not_null(policy, PROXY_POLICY_FREE_OF_NULL);
    sf_delete(policy, PROXY_POLICY_MEMORY_CATEGORY);
    sf_lib_arg_type(policy, "ProxyPolicy");
}

int EVP_PKEY_param_check_quick(EVP_PKEY_CTX* ctx) {
    int res = 0;
    sf_set_must_be_not_null(ctx, EVP_PKEY_PARAM_CHECK_QUICK_OF_NULL);
    sf_set_errno_if(res == 0, ERRNO_EVP_PKEY_PARAM_CHECK_QUICK);
    return res;
}
int i2d_PUBKEY_bio(BIO* bp, const EVP_PKEY* x);

int BN_is_one(const BIGNUM* a);

int SHA256_Final(unsigned char* md, SHA256_CTX* c);

int (DSA*);

void EVP_PKEY_meth_set_digestsign(EVP_PKEY_METHOD* pmeth, int (*digestsign);


void X509_STORE_set_verify(X509_STORE* ctx, X509_STORE_CTX_verify_fn verify) {
    sf_set_trusted_sink_ptr(ctx);
    sf_set_trusted_sink_ptr(verify);
    ctx->verify = verify;
}

void SSL_set_read_ahead(SSL* s, int yes) {
    sf_set_trusted_sink_ptr(s);
    sf_set_trusted_sink_int(yes);
    s->read_ahead = yes;
}

stack_st_SSL_CIPHER* SSL_get_client_ciphers(const SSL* s) {
    sf_set_trusted_sink_ptr(s);
    return s->cipher_list;
}

int SSL_use_PrivateKey(SSL* s, EVP_PKEY* pkey) {
    sf_set_trusted_sink_ptr(s);
    sf_set_trusted_sink_ptr(pkey);
    s->privatekey = pkey;
    return 1;
}

int EVP_PKEY_get_size(const EVP_PKEY* pkey) {
    sf_set_trusted_sink_ptr(pkey);
    return pkey->size;
}

int SSL_client_hello_isv2(SSL* s) {
    int res = 0;
    sf_set_must_be_not_null(s, SSL_PTR_NULL);
    // other necessary actions
    return res;
}

int X509_STORE_lock(X509_STORE* store) {
    int res = 0;
    sf_set_must_be_not_null(store, X509_STORE_PTR_NULL);
    // other necessary actions
    return res;
}

const OSSL_PARAM* EVP_RAND_CTX_gettable_params(EVP_RAND_CTX* ctx) {
    const OSSL_PARAM* res = NULL;
    sf_set_must_be_not_null(ctx, EVP_RAND_CTX_PTR_NULL);
    // other necessary actions
    return res;
}

const SSL_CIPHER* SSL_SESSION_get0_cipher(const SSL_SESSION* sess) {
    const SSL_CIPHER* res = NULL;
    sf_set_must_be_not_null(sess, SSL_SESSION_PTR_NULL);
    // other necessary actions
    return res;
}

const EVP_CIPHER* EVP_aes_256_ocb() {
    const EVP_CIPHER* res = NULL;
    // other necessary actions
    return res;
}

int EVP_PKEY_derive_set_peer_ex(EVP_PKEY_CTX *ctx, EVP_PKEY *peer, int ex) {
    int res = 0;
    sf_set_must_be_not_null(ctx, DERIVE_SET_PEER_EX_OF_NULL);
    sf_set_must_be_not_null(peer, DERIVE_SET_PEER_EX_PEER_NULL);
    res = EVP_PKEY_derive_set_peer_ex(ctx, peer, ex);
    sf_set_errno_if(res <= 0, DERIVE_SET_PEER_EX_ERROR);
    return res;
}

ASN1_OBJECT* X509_EXTENSION_get_object(X509_EXTENSION *ex) {
    ASN1_OBJECT *res = NULL;
    sf_set_must_be_not_null(ex, EXTENSION_GET_OBJECT_EX_NULL);
    res = X509_EXTENSION_get_object(ex);
    sf_set_errno_if(res == NULL, EXTENSION_GET_OBJECT_ERROR);
    return res;
}

const char* EVP_CIPHER_get0_description(const EVP_CIPHER *cipher) {
    const char *res = NULL;
    sf_set_must_be_not_null(cipher, CIPHER_GET0_DESCRIPTION_NULL);
    res = EVP_CIPHER_get0_description(cipher);
    sf_set_errno_if(res == NULL, CIPHER_GET0_DESCRIPTION_ERROR);
    return res;
}

RSA* d2i_RSAPrivateKey_bio(BIO *bp, RSA **x) {
    RSA *res = NULL;
    sf_set_must_be_not_null(bp, D2I_RSAPRIVATEKEY_BIO_BP_NULL);
    res = d2i_RSAPrivateKey_bio(bp, x);
    sf_set_errno_if(res == NULL, D2I_RSAPRIVATEKEY_BIO_ERROR);
    return res;
}

int X509_VERIFY_PARAM_get_auth_level(const X509_VERIFY_PARAM *param) {
    int res = 0;
    sf_set_must_be_not_null(param, VERIFY_PARAM_GET_AUTH_LEVEL_NULL);
    res = X509_VERIFY_PARAM_get_auth_level(param);
    return res;
}
void EC_KEY_clear_flags(EC_KEY* key, int flags);

void CRYPTO_free_ex_data(int index, void* parent, CRYPTO_EX_DATA* data);

OCSP_CERTID* OCSP_cert_to_id(const EVP_MD* dgst, const X509* subject, const X509* issuer);

long X509_get_pathlen(X509* x);

int RSA_security_bits(const RSA* rsa);


GENERERAL_NAMES* d2i_GENERAL_NAMES(GENERERAL_NAMES** a, const unsigned char** pp, long length) {
    GENERAL_NAMES* Res = NULL;
    sf_set_trusted_sink_int(length);
    sf_malloc_arg(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    sf_lib_arg_type(Res, "MallocCategory");
    Res = d2i_GENERAL_NAMES(a, pp, length);
    sf_set_possible_null(Res);
    return Res;
}

int EVP_DigestFinalXOF(EVP_MD_CTX* ctx, unsigned char* md, size_t size) {
    int Res = 0;
    sf_set_trusted_sink_int(size);
    sf_buf_size_limit(md, size);
    Res = EVP_DigestFinalXOF(ctx, md, size);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int X509_STORE_load_locations(X509_STORE* ctx, const char* file, const char* path) {
    int Res = 0;
    sf_tocttou_check(file);
    sf_tocttou_check(path);
    Res = X509_STORE_load_locations(ctx, file, path);
    sf_set_errno_if(Res <= 0);
    return Res;
}

ENGINE* EC_KEY_get0_engine(const EC_KEY* key) {
    ENGINE* Res = NULL;
    Res = EC_KEY_get0_engine(key);
    sf_set_possible_null(Res);
    return Res;
}

X509_NAME_ENTRY* X509_NAME_ENTRY_new() {
    X509_NAME_ENTRY* Res = NULL;
    sf_malloc_arg(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    sf_lib_arg_type(Res, "MallocCategory");
    Res = X509_NAME_ENTRY_new();
    sf_set_possible_null(Res);
    return Res;
}
int X509_STORE_CTX_set_ex_data(X509_STORE_CTX* ctx, int idx, void* data);

void SSL_CTX_set_quiet_shutdown(SSL_CTX* ctx, int mode);

void ERR_set_error(int lib, int reason, const char* file);

DH* PEM_read_DHparams(FILE* fp, DH** x, pem_password_cb* cb, void* u);

int i2d_X509_AUX(const X509* a, unsigned char** pp);


X509_ALGOR* X509_ALGOR_new() {
    X509_ALGOR* Res = NULL;
    Res = (X509_ALGOR*)sf_malloc_arg(sizeof(X509_ALGOR));
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_lib_arg_type(Res, "X509_ALGOR");
    sf_overwrite(Res);
    return Res;
}

int SSL_CTX_set_block_padding(SSL_CTX* ctx, size_t block_size) {
    sf_set_trusted_sink_int(block_size);
    sf_buf_size_limit(block_size);
    return ctx->block_padding = block_size;
}

int X509_CRL_sort(X509_CRL* crl) {
    sf_set_tainted(crl);
    sf_long_time();
    return crl->sort();
}

int SSL_SESSION_set_max_early_data(SSL_SESSION* sess, uint32_t max_early_data) {
    sf_set_trusted_sink_int(max_early_data);
    sf_buf_size_limit(max_early_data);
    return sess->max_early_data = max_early_data;
}

int CRYPTO_set_ex_data(CRYPTO_EX_DATA* ex_data, int idx, void* val) {
    sf_set_trusted_sink_int(idx);
    sf_set_tainted(val);
    sf_lib_arg_type(val, "CRYPTO_EX_DATA");
    return ex_data->set_ex_data(idx, val);
}

int BN_mod_exp_mont_consttime(BIGNUM *rr, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
{
    int Res = 0;
    sf_set_trusted_sink_int(rr);
    sf_set_trusted_sink_int(a);
    sf_set_trusted_sink_int(p);
    sf_set_trusted_sink_int(m);
    sf_set_trusted_sink_int(ctx);
    sf_set_trusted_sink_int(m_ctx);
    sf_set_errno_if(Res, ENOMEM);
    sf_no_errno_if(Res);
    return Res;
}

int ENGINE_set_default_RAND(ENGINE *e)
{
    int Res = 0;
    sf_set_trusted_sink_int(e);
    sf_set_errno_if(Res, ENOMEM);
    sf_no_errno_if(Res);
    return Res;
}

int ASN1_STRING_TABLE_add(int nid, long minsize, long maxsize, unsigned long mask, unsigned long flags)
{
    int Res = 0;
    sf_set_errno_if(Res, ENOMEM);
    sf_no_errno_if(Res);
    return Res;
}

void SSL_CTX_set_allow_early_data_cb(SSL_CTX *ctx, SSL_allow_early_data_cb_fn cb, void *arg)
{
    sf_set_trusted_sink_int(ctx);
    sf_set_trusted_sink_int(cb);
    sf_set_trusted_sink_int(arg);
}

int EVP_VerifyFinal_ex(EVP_MD_CTX *ctx, const unsigned char *sig, unsigned int siglen, EVP_PKEY *pkey, OSSL_LIB_CTX *libctx, const char *propq)
{
    int Res = 0;
    sf_set_trusted_sink_int(ctx);
    sf_set_trusted_sink_int(sig);
    sf_set_trusted_sink_int(siglen);
    sf_set_trusted_sink_int(pkey);
    sf_set_trusted_sink_int(libctx);
    sf_set_trusted_sink_int(propq);
    sf_set_errno_if(Res, ENOMEM);
    sf_no_errno_if(Res);
    return Res;
}

DIST_POINT* DIST_POINT_new() {
    DIST_POINT* Res = NULL;
    Res = (DIST_POINT*)OPENSSL_malloc(sizeof(DIST_POINT));
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    return Res;
}

BN_CTX* BN_CTX_new() {
    BN_CTX* Res = NULL;
    Res = (BN_CTX*)OPENSSL_malloc(sizeof(BN_CTX));
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    return Res;
}

int PEM_write_PKCS8_PRIV_KEY_INFO(FILE* file, const PKCS8_PRIV_KEY_INFO* p8inf) {
    int Res = 0;
    // Add necessary code here
    return Res;
}

int EVP_CIPHER_up_ref(EVP_CIPHER* cipher) {
    int Res = 0;
    // Add necessary code here
    return Res;
}

int X509_check_private_key(const X509* x, const EVP_PKEY* k) {
    int Res = 0;
    // Add necessary code here
    return Res;
}

int BIO_bind(int sock, const BIO_ADDR *addr, int flags) {
    int Res = 0;
    sf_set_trusted_sink_int(sock);
    sf_set_trusted_sink_ptr(addr);
    sf_set_trusted_sink_int(flags);
    Res = BIO_bind(sock, addr, flags);
    sf_set_errno_if(Res, -1);
    sf_set_possible_null(Res);
    return Res;
}

int X509_VERIFY_PARAM_add1_host(X509_VERIFY_PARAM *param, const char *name, size_t namelen) {
    int Res = 0;
    sf_set_trusted_sink_ptr(param);
    sf_set_trusted_sink_ptr(name);
    sf_set_trusted_sink_int(namelen);
    Res = X509_VERIFY_PARAM_add1_host(param, name, namelen);
    sf_set_errno_if(Res, 0);
    return Res;
}

int i2d_PKCS7_DIGEST(const PKCS7_DIGEST *a, unsigned char **pp) {
    int Res = 0;
    sf_set_trusted_sink_ptr(a);
    sf_set_trusted_sink_ptr(pp);
    Res = i2d_PKCS7_DIGEST(a, pp);
    sf_set_errno_if(Res, -1);
    return Res;
}

int EC_GROUP_get_degree(const EC_GROUP *group) {
    int Res = 0;
    sf_set_trusted_sink_ptr(group);
    Res = EC_GROUP_get_degree(group);
    sf_set_errno_if(Res, -1);
    return Res;
}

int PEM_write_X509_PUBKEY(FILE *fp, const X509_PUBKEY *x) {
    int Res = 0;
    sf_set_trusted_sink_ptr(fp);
    sf_set_trusted_sink_ptr(x);
    Res = PEM_write_X509_PUBKEY(fp, x);
    sf_set_errno_if(Res, -1);
    return Res;
}

void X509_REQ_get0_signature(const X509_REQ* req, const ASN1_BIT_STRING** psig, const X509_ALGOR** palg) {
    sf_set_must_be_not_null(req, "X509_REQ_get0_signature");
    sf_set_must_be_not_null(psig, "X509_REQ_get0_signature");
    sf_set_must_be_not_null(palg, "X509_REQ_get0_signature");
    sf_set_tainted(req, "X509_REQ_get0_signature");
    sf_set_tainted(*psig, "X509_REQ_get0_signature");
    sf_set_tainted(*palg, "X509_REQ_get0_signature");
}

int SSL_CTX_load_verify_dir(SSL_CTX* ctx, const char* dir) {
    sf_set_must_be_not_null(ctx, "SSL_CTX_load_verify_dir");
    sf_set_must_be_not_null(dir, "SSL_CTX_load_verify_dir");
    sf_set_tainted(ctx, "SSL_CTX_load_verify_dir");
    sf_set_tainted(dir, "SSL_CTX_load_verify_dir");
    sf_tocttou_check(dir, "SSL_CTX_load_verify_dir");
}

int X509_ALGOR_copy(X509_ALGOR* dest, const X509_ALGOR* src) {
    sf_set_must_be_not_null(dest, "X509_ALGOR_copy");
    sf_set_must_be_not_null(src, "X509_ALGOR_copy");
    sf_set_tainted(dest, "X509_ALGOR_copy");
    sf_set_tainted(src, "X509_ALGOR_copy");
}

int EVP_PKEY_CTX_set_ec_param_enc(EVP_PKEY_CTX* ctx, int param_enc) {
    sf_set_must_be_not_null(ctx, "EVP_PKEY_CTX_set_ec_param_enc");
    sf_set_tainted(ctx, "EVP_PKEY_CTX_set_ec_param_enc");
}

void EVP_MD_do_all_provided(OSSL_LIB_CTX* ctx, void (*fn)(EVP_MD*, void*), void* arg) {
    sf_set_must_be_not_null(ctx, "EVP_MD_do_all_provided");
    sf_set_must_be_not_null(fn, "EVP_MD_do_all_provided");
    sf_set_tainted(ctx, "EVP_MD_do_all_provided");
    sf_set_tainted(fn, "EVP_MD_do_all_provided");
    sf_set_tainted(arg, "EVP_MD_do_all_provided");
}

void SSL_CTX_set_msg_callback(SSL_CTX* ctx, void (*cb)(int, int, int, const void*, size_t, SSL*, void*))
{
    sf_set_trusted_sink_ptr(ctx);
    sf_set_trusted_sink_ptr(cb);
    // Implementation
}

int (*RSA_meth_get_bn_mod_exp(const RSA_METHOD* meth))(BIGNUM* r, const BIGNUM* a, const BIGNUM* p, const BIGNUM* m, BN_CTX* ctx, BN_MONT_CTX* m_ctx)
{
    sf_set_trusted_sink_ptr(meth);
    // Implementation
    return NULL;
}

EVP_PKEY* EVP_PKEY_CTX_get0_peerkey(EVP_PKEY_CTX* ctx)
{
    sf_set_trusted_sink_ptr(ctx);
    EVP_PKEY* Res = NULL;
    sf_set_possible_null(Res);
    // Implementation
    return Res;
}

void GENERAL_NAMES_free(GENERAL_NAMES* names)
{
    sf_set_trusted_sink_ptr(names);
    // Implementation
}

void DH_meth_free(DH_METHOD* meth)
{
    sf_set_trusted_sink_ptr(meth);
    // Implementation
}

OCSP_ONEREQ* OCSP_request_add0_id(OCSP_REQUEST* req, OCSP_CERTID* cid) {
    OCSP_ONEREQ* Res = NULL;
    sf_set_trusted_sink_int(req);
    sf_set_trusted_sink_int(cid);
    Res = OCSP_request_add0_id(req, cid);
    sf_overwrite(Res);
    return Res;
}

void DH_free(DH* dh) {
    sf_set_trusted_sink_int(dh);
    DH_free(dh);
}

int EVP_CIPHER_CTX_get_updated_iv(EVP_CIPHER_CTX* ctx, void* iv, size_t len) {
    int Res = 0;
    sf_set_trusted_sink_int(ctx);
    sf_set_trusted_sink_int(iv);
    Res = EVP_CIPHER_CTX_get_updated_iv(ctx, iv, len);
    sf_overwrite(Res);
    return Res;
}

const EVP_CIPHER* EVP_des_ede3_cfb8() {
    const EVP_CIPHER* Res = NULL;
    Res = EVP_des_ede3_cfb8();
    sf_overwrite(Res);
    return Res;
}

DSA* d2i_DSAPrivateKey(DSA** dsa, const unsigned char** pp, long length) {
    DSA* Res = NULL;
    sf_set_trusted_sink_int(dsa);
    sf_set_trusted_sink_int(pp);
    Res = d2i_DSAPrivateKey(dsa, pp, length);
    sf_overwrite(Res);
    return Res;
}

stack_st_X509_NAME* SSL_get_client_CA_list(const SSL* s) {
    stack_st_X509_NAME* Res = NULL;
    sf_set_trusted_sink_ptr(Res);
    sf_set_alloc_possible_null(Res);
    return Res;
}

int EVP_PKEY_print_private(BIO* out, const EVP_PKEY* pkey, int indent, ASN1_PCTX* pctx) {
    int Res = 0;
    sf_set_errno_if(Res <= 0);
    return Res;
}

rsa_st* EVP_PKEY_get1_RSA(EVP_PKEY* pkey) {
    rsa_st* Res = NULL;
    sf_set_possible_null(Res);
    return Res;
}

int BN_mod_mul_reciprocal(BIGNUM* r, const BIGNUM* a, const BIGNUM* b, BN_RECP_CTX* recp, BN_CTX* ctx) {
    int Res = 0;
    sf_set_errno_if(Res <= 0);
    return Res;
}

int EVP_CIPHER_meth_set_impl_ctx_size(EVP_CIPHER* cipher, int size) {
    int Res = 0;
    sf_set_errno_if(Res <= 0);
    return Res;
}
int i2o_SCT(const SCT*, unsigned char**);

int SSL_want(const SSL*);

void* X509_get_ext_d2i(const X509*, int, int*, int*);

PKCS8_PRIV_KEY_INFO* d2i_PKCS8_PRIV_KEY_INFO_fp(FILE*, PKCS8_PRIV_KEY_INFO**);

X509_ALGOR* PKCS5_pbkdf2_set_ex(int, unsigned char*, int, int, int, OSSL_LIB_CTX*);

int X509_CRL_verify(X509_CRL* crl, EVP_PKEY* pkey);

void X509_STORE_set_lookup_certs(X509_STORE* ctx, X509_STORE_CTX_lookup_certs_fn func);

OSSL_LIB_CTX* OSSL_LIB_CTX_set0_default(OSSL_LIB_CTX* libctx);

int ASYNC_WAIT_CTX_clear_fd(ASYNC_WAIT_CTX* ctx, const void* fd);

int SSL_CTX_use_PrivateKey(SSL_CTX* ctx, EVP_PKEY* pkey);


int ASN1_UTCTIME_check(const ASN1_UTCTIME* time) {
    int Res = 0;
    // Check for null and other necessary conditions
    sf_set_must_be_not_null(time, CHECK_OF_NULL);
    // Perform necessary actions
    // ...
    // Set the return value
    sf_set_errno_if(Res, ERROR_CONDITION);
    return Res;
}

ENGINE_CIPHERS_PTR ENGINE_get_ciphers(const ENGINE* engine) {
    ENGINE_CIPHERS_PTR Res = NULL;
    // Check for null and other necessary conditions
    sf_set_must_be_not_null(engine, CHECK_OF_NULL);
    // Perform necessary actions
    // ...
    // Set the return value
    sf_set_errno_if(Res, ERROR_CONDITION);
    return Res;
}

int EVP_PKEY_generate(EVP_PKEY_CTX* ctx, EVP_PKEY** ppkey) {
    int Res = 0;
    // Check for null and other necessary conditions
    sf_set_must_be_not_null(ctx, CHECK_OF_NULL);
    sf_set_must_be_not_null(ppkey, CHECK_OF_NULL);
    // Perform necessary actions
    // ...
    // Set the return value
    sf_set_errno_if(Res, ERROR_CONDITION);
    return Res;
}

PKCS7* d2i_PKCS7_bio(BIO* bp, PKCS7** p7) {
    PKCS7* Res = NULL;
    // Check for null and other necessary conditions
    sf_set_must_be_not_null(bp, CHECK_OF_NULL);
    sf_set_must_be_not_null(p7, CHECK_OF_NULL);
    // Perform necessary actions
    // ...
    // Set the return value
    sf_set_errno_if(Res, ERROR_CONDITION);
    return Res;
}

int ENGINE_set_digests(ENGINE* e, ENGINE_DIGESTS_PTR digests) {
    int Res = 0;
    // Check for null and other necessary conditions
    sf_set_must_be_not_null(e, CHECK_OF_NULL);
    sf_set_must_be_not_null(digests, CHECK_OF_NULL);
    // Perform necessary actions
    // ...
    // Set the return value
    sf_set_errno_if(Res, ERROR_CONDITION);
    return Res;
}

int CRYPTO_THREAD_run_once(CRYPTO_ONCE* once, void (*init)(void)) {
    int res = 0;
    // Add necessary static analysis function calls
    return res;
}

X509_STORE_CTX_lookup_certs_fn X509_STORE_CTX_get_lookup_certs(const X509_STORE_CTX* ctx) {
    X509_STORE_CTX_lookup_certs_fn res = NULL;
    // Add necessary static analysis function calls
    return res;
}

const EVP_CIPHER* EVP_camellia_192_cfb128() {
    const EVP_CIPHER* res = NULL;
    // Add necessary static analysis function calls
    return res;
}

int EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(EVP_PKEY_CTX* ctx, const EVP_MD* md) {
    int res = 0;
    // Add necessary static analysis function calls
    return res;
}

int ECDSA_do_verify(const unsigned char* digest, int digest_len, const ECDSA_SIG* sig, EC_KEY* key) {
    int res = 0;
    // Add necessary static analysis function calls
    return res;
}
void OPENSSL_LH_stats(const OPENSSL_LHASH* lh, FILE* f);

int EVP_CIPHER_asn1_to_param(EVP_CIPHER_CTX* c, ASN1_TYPE* t);

void EVP_PKEY_asn1_set_param(EVP_PKEY_ASN1_METHOD* ameth,
        int (*param_encode);

char* SSL_CIPHER_description(const SSL_CIPHER* c, char* buf, int len);

long DH_get_length(const DH* dh);


int UI_process(UI *ui) {
    int res = 0;
    // Function body
    return res;
}

int DSA_meth_get_flags(const DSA_METHOD *meth) {
    int res = 0;
    // Function body
    return res;
}

int SSL_CTX_use_serverinfo_ex(SSL_CTX *ctx, unsigned int type, const unsigned char *data, size_t len) {
    int res = 0;
    // Function body
    return res;
}

void SSL_set_psk_use_session_callback(SSL *ssl, SSL_psk_use_session_cb_func cb) {
    // Function body
}

int PEM_bytes_read_bio_secmem(unsigned char **data, long *len, char **pp,
                              const char *name, BIO *bp,
                              pem_password_cb *cb, void *u) {
    int res = 0;
    // Function body
    return res;
}

void OSSL_PARAM_get_uint32(const OSSL_PARAM *param, uint32_t *val) {
    int res = 0;
    sf_set_must_be_not_null(param, "OSSL_PARAM");
    sf_set_must_be_not_null(val, "uint32_t");
    sf_set_errno_if(res == 0, "OSSL_PARAM_get_uint32");
}

void ERR_lib_error_string(unsigned long lib) {
    const char *res = NULL;
    sf_set_possible_null(res);
    sf_set_errno_if(res == NULL, "ERR_lib_error_string");
}

void GENERAL_NAME_dup(const GENERAL_NAME *name) {
    GENERAL_NAME *res = NULL;
    sf_set_must_be_not_null(name, "GENERAL_NAME");
    sf_set_alloc_possible_null(res, "GENERAL_NAME");
    sf_set_errno_if(res == NULL, "GENERAL_NAME_dup");
}

void OSSL_PARAM_construct_end() {
    OSSL_PARAM res;
    sf_set_trusted_sink_int(res.data_size);
    sf_set_trusted_sink_ptr(res.data);
    sf_set_trusted_sink_ptr(res.key);
}

void ERR_new() {
    // No parameters or return value to check
}

int EVP_MD_CTX_copy(EVP_MD_CTX *dest, const EVP_MD_CTX *src)
{
    int res = 0;
    sf_set_trusted_sink_int(src);
    sf_set_trusted_sink_int(dest);
    sf_set_possible_null(src);
    sf_set_possible_null(dest);
    sf_set_errno_if(res == 0);
    return res;
}

const EVP_MD* EVP_sha512_256()
{
    const EVP_MD *res = NULL;
    sf_set_trusted_sink_ptr(res);
    sf_set_possible_null(res);
    return res;
}

const DH_METHOD* DH_get_default_method()
{
    const DH_METHOD *res = NULL;
    sf_set_trusted_sink_ptr(res);
    sf_set_possible_null(res);
    return res;
}

int X509_STORE_CTX_get1_issuer(X509 **issuer, X509_STORE_CTX *ctx, X509 *x)
{
    int res = 0;
    sf_set_trusted_sink_int(issuer);
    sf_set_trusted_sink_int(ctx);
    sf_set_trusted_sink_int(x);
    sf_set_possible_null(issuer);
    sf_set_possible_null(ctx);
    sf_set_possible_null(x);
    sf_set_errno_if(res == 0);
    return res;
}

void POLICYINFO_free(POLICYINFO *policy)
{
    sf_set_trusted_sink_ptr(policy);
    sf_set_possible_null(policy);
    sf_delete(policy, POLICYINFO_MEMORY_CATEGORY);
    sf_lib_arg_type(policy, "PolicyInfoCategory");
}

int i2d_AUTHORITY_INFO_ACCESS(const AUTHORITY_INFO_ACCESS* aia, unsigned char** pp)
{
    int res = 0;
    sf_set_must_be_not_null(aia, I2D_OF_NULL);
    sf_set_must_be_not_null(pp, I2D_OF_NULL);
    sf_set_trusted_sink_ptr(pp);
    sf_set_errno_if(res <= 0, I2D_OF_ERROR);
    return res;
}

BIGNUM* BN_get_rfc2409_prime_1024(BIGNUM* bn)
{
    BIGNUM* res = NULL;
    sf_set_possible_null(bn);
    sf_set_alloc_possible_null(res);
    sf_lib_arg_type(res, "BN_get_rfc2409_prime_1024");
    sf_set_errno_if(res == NULL, BN_GET_RFC2409_PRIME_1024_OF_NULL);
    return res;
}

void NAMING_AUTHORITY_set0_authorityURL(NAMING_AUTHORITY* a, ASN1_IA5STRING* url)
{
    sf_set_must_be_not_null(a, SET0_AUTHORITYURL_OF_NULL);
    sf_set_must_be_not_null(url, SET0_AUTHORITYURL_OF_NULL);
    sf_lib_arg_type(url, "NAMING_AUTHORITY_set0_authorityURL");
}

void OPENSSL_fork_parent()
{
    // No checks needed as this function does not take any arguments or return any value
}

DSA* PEM_read_bio_DSAparams(BIO* bio, DSA** dsa, pem_password_cb* cb, void* u)
{
    DSA* res = NULL;
    sf_set_must_be_not_null(bio, PEM_READ_BIO_DSA_OF_NULL);
    sf_set_must_be_not_null(dsa, PEM_READ_BIO_DSA_OF_NULL);
    sf_set_possible_null(cb);
    sf_set_possible_null(u);
    sf_set_alloc_possible_null(res);
    sf_lib_arg_type(res, "PEM_read_bio_DSAparams");
    sf_set_errno_if(res == NULL, PEM_READ_BIO_DSA_OF_ERROR);
    return res;
}

void X509_STORE_set_verify_cb(X509_STORE *store, X509_STORE_CTX_verify_cb verify_cb)
{
    sf_set_trusted_sink_ptr(store);
    sf_set_trusted_sink_ptr(verify_cb);
    // implementation
}

int i2d_PKCS7_bio_stream(BIO *out, PKCS7 *p7, BIO *in, int flags)
{
    sf_set_trusted_sink_ptr(out);
    sf_set_trusted_sink_ptr(p7);
    sf_set_trusted_sink_ptr(in);
    sf_set_trusted_sink_int(flags);
    // implementation
}

int X509_LOOKUP_meth_set_new_item(X509_LOOKUP_METHOD *method, int (*new_item)(X509_LOOKUP *))
{
    sf_set_trusted_sink_ptr(method);
    sf_set_trusted_sink_ptr(new_item);
    // implementation
}

int BIO_get_new_index()
{
    int index = 0;
    sf_set_trusted_sink_int(index);
    // implementation
    return index;
}

size_t EVP_PKEY_get1_encoded_public_key(EVP_PKEY *pkey, unsigned char **ppub)
{
    sf_set_trusted_sink_ptr(pkey);
    sf_set_trusted_sink_ptr(ppub);
    size_t res = 0;
    sf_set_trusted_sink_int(res);
    // implementation
    return res;
}
void X509_VERIFY_PARAM_set_depth(X509_VERIFY_PARAM* param, int depth);

const EVP_MD* EVP_whirlpool();

int (DH*);

unsigned EC_KEY_get_enc_flags(const EC_KEY* key);

OSSL_LIB_CTX* NCONF_get0_libctx(const CONF* conf);


const EVP_CIPHER* EVP_aes_192_ctr() {
    const EVP_CIPHER* Res = NULL;
    Res = EVP_aes_192_ctr();
    sf_set_possible_null(Res);
    return Res;
}

int EVP_EncryptUpdate(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl, const unsigned char* in, int inl) {
    int Res = 0;
    Res = EVP_EncryptUpdate(ctx, out, outl, in, inl);
    sf_set_errno_if(Res <= 0);
    return Res;
}

const EVP_MD* SSL_CIPHER_get_handshake_digest(const SSL_CIPHER* cipher) {
    const EVP_MD* Res = NULL;
    Res = SSL_CIPHER_get_handshake_digest(cipher);
    sf_set_possible_null(Res);
    return Res;
}

int RSA_set0_multi_prime_params(RSA* r, BIGNUM* primes[], BIGNUM* exps[], BIGNUM* coeffs[], int pnum) {
    int Res = 0;
    Res = RSA_set0_multi_prime_params(r, primes, exps, coeffs, pnum);
    sf_set_errno_if(Res <= 0);
    return Res;
}

X509_EXTENSION* X509v3_get_ext(const stack_st_X509_EXTENSION* exts, int idx) {
    X509_EXTENSION* Res = NULL;
    Res = X509v3_get_ext(exts, idx);
    sf_set_possible_null(Res);
    return Res;
}
void SSL_CTX_set_post_handshake_auth(SSL_CTX* ctx, int val);

X509_STORE_CTX_lookup_crls_fn X509_STORE_CTX_get_lookup_crls(const X509_STORE_CTX* ctx);

int SSL_get_servername_type(const SSL* ssl);

int EVP_CipherFinal(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl);

PKCS7_ENC_CONTENT* PKCS7_ENC_CONTENT_new();


int SSL_get_security_callback(const SSL* s) {
    int Res = 0;
    // Specification code here
    return Res;
}

PKCS8_PRIV_KEY_INFO* PKCS8_PRIV_KEY_INFO_new() {
    PKCS8_PRIV_KEY_INFO* Res = NULL;
    // Specification code here
    return Res;
}

const EVP_CIPHER* EVP_aes_256_ctr() {
    const EVP_CIPHER* Res = NULL;
    // Specification code here
    return Res;
}

IPAddressChoice* d2i_IPAddressChoice(IPAddressChoice** a, const unsigned char** in, long len) {
    IPAddressChoice* Res = NULL;
    // Specification code here
    return Res;
}

int SSL_use_RSAPrivateKey(SSL* s, RSA* rsa) {
    int Res = 0;
    // Specification code here
    return Res;
}
long SSL_callback_ctrl(SSL* ssl, int cmd, void (*fp);

int DSA_meth_set_mod_exp(DSA_METHOD* dsa, int (*mod_exp);

int X509_ATTRIBUTE_set1_data(X509_ATTRIBUTE* attr, int attrtype, const void* data, int len);

void SSL_CTX_set_security_callback(SSL_CTX* ctx, int (*cb);

const EVP_CIPHER* EVP_camellia_192_cfb8();

BIO_callback_fn BIO_get_callback(const BIO* bio) {
    BIO_callback_fn Res = NULL;
    sf_set_trusted_sink_ptr(bio);
    sf_set_must_be_not_null(bio, BIO_GET_CALLBACK_OF_NULL);
    Res = bio->callback;
    sf_set_possible_null(Res);
    return Res;
}

const BIGNUM* BN_value_one() {
    const BIGNUM* Res = NULL;
    Res = BN_value_one();
    sf_set_must_be_not_null(Res, BN_VALUE_ONE_IS_NULL);
    return Res;
}

int DH_meth_set_bn_mod_exp(DH_METHOD* dh_meth, int (*bn_mod_exp)(const DH*, BIGNUM*, const BIGNUM*, const BIGNUM*, const BIGNUM*, BN_CTX*, BN_MONT_CTX*)) {
    int Res = 0;
    sf_set_trusted_sink_ptr(dh_meth);
    sf_set_must_be_not_null(dh_meth, DH_METH_SET_BN_MOD_EXP_OF_NULL);
    Res = DH_meth_set_bn_mod_exp(dh_meth, bn_mod_exp);
    sf_set_errno_if(Res, DH_METH_SET_BN_MOD_EXP_FAILED);
    return Res;
}

int EVP_MD_get_pkey_type(const EVP_MD* md) {
    int Res = 0;
    sf_set_trusted_sink_ptr(md);
    sf_set_must_be_not_null(md, EVP_MD_GET_PKEY_TYPE_OF_NULL);
    Res = EVP_MD_get_pkey_type(md);
    sf_set_errno_if(Res, EVP_MD_GET_PKEY_TYPE_FAILED);
    return Res;
}

EVP_RAND* EVP_RAND_fetch(OSSL_LIB_CTX* ctx, const char* name, const char* propquery) {
    EVP_RAND* Res = NULL;
    sf_set_trusted_sink_ptr(ctx);
    sf_set_must_be_not_null(ctx, EVP_RAND_FETCH_OF_NULL);
    Res = EVP_RAND_fetch(ctx, name, propquery);
    sf_set_possible_null(Res);
    return Res;
}
PKCS7_DIGEST* d2i_PKCS7_DIGEST(PKCS7_DIGEST** a, const unsigned char** pp, long length) {
    PKCS7_DIGEST* Res = NULL;
    sf_set_trusted_sink_int(length);
    sf_malloc_arg(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    sf_lib_arg_type(Res, "MallocCategory");
    Res = (PKCS7_DIGEST*)*pp;
    sf_bitcopy(Res);
    sf_buf_size_limit(Res, length);
    return Res;
}

const BIO_METHOD* BIO_s_accept() {
    const BIO_METHOD* Res = NULL;
    Res = BIO_s_accept();
    sf_set_possible_null(Res);
    return Res;
}

const EVP_CIPHER* EVP_camellia_192_ofb() {
    const EVP_CIPHER* Res = NULL;
    Res = EVP_camellia_192_ofb();
    sf_set_possible_null(Res);
    return Res;
}

int PEM_write_PrivateKey(FILE* fp, const EVP_PKEY* x, const EVP_CIPHER* enc, const unsigned char* kstr, int klen, pem_password_cb* cb, void* u) {
    int Res = 0;
    sf_password_use(kstr);
    sf_password_set(kstr);
    Res = PEM_write_PrivateKey(fp, x, enc, kstr, klen, cb, u);
    sf_set_errno_if(Res <= 0);
    return Res;
}

void* DSA_meth_get0_app_data(const DSA_METHOD* dsa) {
    void* Res = NULL;
    Res = DSA_meth_get0_app_data(dsa);
    sf_set_possible_null(Res);
    return Res;
}
int SSL_SESSION_set1_alpn_selected(SSL_SESSION* s, const unsigned char* data, size_t len);

void EVP_PKEY_asn1_set_set_pub_key(EVP_PKEY_ASN1_METHOD* ameth, int (*pub_encode);

int i2d_NETSCAPE_CERT_SEQUENCE(const NETSCAPE_CERT_SEQUENCE* a, unsigned char** pp);

int EVP_PKEY_CTX_ctrl_uint64(EVP_PKEY_CTX* ctx, int keytype, int optype, int cmd, uint64_t value);

ENGINE* ENGINE_get_next(ENGINE* e);

OCSP_CERTID* OCSP_CERTID_dup(const OCSP_CERTID* cid);

const EVP_CIPHER* EVP_aes_128_cbc_hmac_sha1();

int OSSL_PARAM_get_int(const OSSL_PARAM* param, int* val);

BN_CTX* BN_CTX_secure_new();

void DH_clear_flags(DH* dh, int flags);


ISSUING_DIST_POINT* ISSUING_DIST_POINT_new()
{
    ISSUING_DIST_POINT* Res = NULL;
    Res = (ISSUING_DIST_POINT*)sf_malloc_arg(sizeof(ISSUING_DIST_POINT));
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    return Res;
}

ASN1_VALUE* SMIME_read_ASN1(BIO* a, BIO** b, const ASN1_ITEM* c)
{
    ASN1_VALUE* Res = NULL;
    Res = SMIME_read_ASN1(a, b, c);
    sf_set_possible_null(Res);
    return Res;
}

CERTIFICATEPOLICIES* CERTIFICATEPOLICIES_new()
{
    CERTIFICATEPOLICIES* Res = NULL;
    Res = (CERTIFICATEPOLICIES*)sf_malloc_arg(sizeof(CERTIFICATEPOLICIES));
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    return Res;
}

void BN_GENCB_set(BN_GENCB* a, int (int, int, BN_GENCB*)* b, void* c)
{
    BN_GENCB_set(a, b, c);
    sf_overwrite(a);
}

int SSL_set_max_early_data(SSL* a, uint32_t b)
{
    int Res = SSL_set_max_early_data(a, b);
    sf_set_errno_if(Res == 0);
    return Res;
}
int X509_LOOKUP_set_method_data(X509_LOOKUP*, void*);

void EC_KEY_set_enc_flags(EC_KEY*, unsigned int);

int EVP_PKEY_keygen_init(EVP_PKEY_CTX*);

EVP_PKEY* d2i_PUBKEY(EVP_PKEY**, const unsigned char**, long);

int BIO_get_shutdown(BIO*);


void NAME_CONSTRAINTS_free(NAME_CONSTRAINTS* ptr) {
    sf_delete(ptr, NAME_CONSTRAINTS_CATEGORY);
}

EC_KEY* d2i_EC_PUBKEY_fp(FILE* fp, EC_KEY** key) {
    EC_KEY* Res = NULL;
    sf_set_trusted_sink_ptr(fp);
    sf_set_trusted_sink_ptr(key);
    sf_set_tainted(Res);
    sf_set_possible_null(Res);
    sf_lib_arg_type(fp, "FILE");
    sf_lib_arg_type(key, "EC_KEY");
    return Res;
}

int DSA_meth_set1_name(DSA_METHOD* dsa, const char* name) {
    int Res = 0;
    sf_set_tainted(name);
    sf_lib_arg_type(dsa, "DSA_METHOD");
    return Res;
}

int BIO_meth_set_ctrl(BIO_METHOD* bio, long (*ctrl)(BIO*, int, long, void*)) {
    int Res = 0;
    sf_set_trusted_sink_ptr(ctrl);
    sf_lib_arg_type(bio, "BIO_METHOD");
    return Res;
}

int ENGINE_set_load_pubkey_function(ENGINE* e, ENGINE_LOAD_KEY_PTR load_pubkey_function) {
    int Res = 0;
    sf_set_trusted_sink_ptr(load_pubkey_function);
    sf_lib_arg_type(e, "ENGINE");
    return Res;
}

const EVP_CIPHER* EVP_aria_192_ctr() {
    const EVP_CIPHER* Res = NULL;
    Res = EVP_aria_192_ctr();
    sf_set_possible_null(Res);
    return Res;
}

void UI_destroy_method(UI_METHOD* method) {
    UI_destroy_method(method);
}

int EVP_CipherInit_ex(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type, ENGINE* impl, const unsigned char* key, const unsigned char* iv, int enc) {
    int Res = 0;
    Res = EVP_CipherInit_ex(ctx, type, impl, key, iv, enc);
    sf_set_errno_if(Res <= 0);
    return Res;
}

void PROXY_CERT_INFO_EXTENSION_free(PROXY_CERT_INFO_EXTENSION* pci) {
    PROXY_CERT_INFO_EXTENSION_free(pci);
}

int RSA_meth_set_verify(RSA_METHOD* rsa, int (*verify)(int, const unsigned char*, unsigned int, const unsigned char*, unsigned int, const RSA*)) {
    int Res = 0;
    Res = RSA_meth_set_verify(rsa, verify);
    sf_set_errno_if(Res <= 0);
    return Res;
}

BIO* BIO_new_socket(int fd, int close_flag) {
    BIO* Res = NULL;
    sf_set_trusted_sink_int(fd);
    sf_set_trusted_sink_int(close_flag);
    Res = BIO_new_socket(fd, close_flag);
    sf_set_possible_null(Res);
    return Res;
}

int i2d_X509_CRL_bio(BIO* bp, const X509_CRL* crl) {
    int Res = 0;
    sf_set_trusted_sink_ptr(bp);
    sf_set_trusted_sink_ptr(crl);
    Res = i2d_X509_CRL_bio(bp, crl);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int i2d_KeyParams(const EVP_PKEY* pkey, unsigned char** pp) {
    int Res = 0;
    sf_set_trusted_sink_ptr(pkey);
    sf_set_trusted_sink_ptr(pp);
    Res = i2d_KeyParams(pkey, pp);
    sf_set_errno_if(Res <= 0);
    return Res;
}

int X509_NAME_ENTRY_set_object(X509_NAME_ENTRY* ne, const ASN1_OBJECT* obj) {
    int Res = 0;
    sf_set_trusted_sink_ptr(ne);
    sf_set_trusted_sink_ptr(obj);
    Res = X509_NAME_ENTRY_set_object(ne, obj);
    sf_set_errno_if(Res <= 0);
    return Res;
}

uint32_t SSL_CTX_get_max_early_data(const SSL_CTX* ctx) {
    uint32_t Res = 0;
    sf_set_trusted_sink_ptr(ctx);
    Res = SSL_CTX_get_max_early_data(ctx);
    return Res;
}

const BIGNUM* DSA_get0_p(const DSA* dsa) {
    const BIGNUM* Res = NULL;
    Res = dsa->p;
    sf_set_possible_null(Res);
    return Res;
}

X509_CINF* X509_CINF_new() {
    X509_CINF* Res = NULL;
    Res = OPENSSL_zalloc(sizeof(*Res));
    sf_new(Res, X509_CINF_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    return Res;
}

ASYNC_JOB* ASYNC_get_current_job() {
    ASYNC_JOB* Res = NULL;
    Res = async_get_current_job();
    sf_set_possible_null(Res);
    return Res;
}

int EVP_MD_meth_set_init(EVP_MD* md, int (*init)(EVP_MD_CTX*)) {
    int Res = 0;
    Res = EVP_MD_meth_set_init(md, init);
    sf_set_errno_if(Res <= 0);
    return Res;
}

long (BIO*, int, long, void*)* BIO_meth_get_ctrl(const BIO_METHOD* type) {
    long (BIO*, int, long, void*)* Res = NULL;
    Res = BIO_meth_get_ctrl(type);
    sf_set_possible_null(Res);
    return Res;
}

ASN1_UTF8STRING* s2i_ASN1_UTF8STRING(X509V3_EXT_METHOD* method, X509V3_CTX* ctx, const char* str) {
    ASN1_UTF8STRING* Res = NULL;
    sf_set_tainted(str);
    sf_set_must_be_not_null(str, FREE_OF_NULL);
    sf_strlen(Res, str);
    sf_malloc_arg(Res, sizeof(ASN1_UTF8STRING));
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_lib_arg_type(Res, "ASN1_UTF8STRING");
    return Res;
}

const EVP_CIPHER* EVP_CIPHER_CTX_cipher(const EVP_CIPHER_CTX* ctx) {
    const EVP_CIPHER* Res = NULL;
    sf_set_must_be_not_null(ctx, FREE_OF_NULL);
    Res = ctx->cipher;
    sf_set_possible_null(Res);
    return Res;
}

size_t OPENSSL_strlcpy(char* dst, const char* src, size_t size) {
    size_t Res = 0;
    sf_set_tainted(src);
    sf_set_must_be_not_null(src, FREE_OF_NULL);
    sf_set_must_be_not_null(dst, FREE_OF_NULL);
    sf_buf_size_limit(dst, size);
    sf_buf_size_limit_read(src, size);
    sf_buf_overlap(dst, src);
    sf_buf_stop_at_null(src);
    sf_overwrite(Res);
    return Res;
}

void SSL_CTX_sess_set_get_cb(SSL_CTX* ctx, SSL_SESSION* (ssl_st*, const unsigned char*, int, int*)* get_cb) {
    sf_set_must_be_not_null(ctx, FREE_OF_NULL);
    ctx->sess_get_cb = get_cb;
}

IPAddressChoice* IPAddressChoice_new() {
    IPAddressChoice* Res = NULL;
    sf_malloc_arg(Res, sizeof(IPAddressChoice));
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_lib_arg_type(Res, "IPAddressChoice");
    return Res;
}

void* X509V3_EXT_d2i(X509_EXTENSION* ext) {
    void* Res = NULL;
    sf_set_trusted_sink_int(ext);
    Res = X509V3_EXT_d2i(ext);
    sf_overwrite(Res);
    return Res;
}

unsigned char* HMAC(const EVP_MD* md, const void* data, int len, const unsigned char* key, size_t keylen, unsigned char* md_out, unsigned int* mdlen_out) {
    unsigned char* Res = NULL;
    sf_set_trusted_sink_int(md);
    sf_set_trusted_sink_int(data);
    sf_set_trusted_sink_int(len);
    sf_set_trusted_sink_int(key);
    sf_set_trusted_sink_int(keylen);
    sf_set_trusted_sink_int(md_out);
    sf_set_trusted_sink_int(mdlen_out);
    Res = HMAC(md, data, len, key, keylen, md_out, mdlen_out);
    sf_overwrite(Res);
    return Res;
}

long SSL_CTX_callback_ctrl(SSL_CTX* ctx, int cmd, void (*fp)(void)) {
    long Res = 0;
    sf_set_trusted_sink_int(ctx);
    sf_set_trusted_sink_int(cmd);
    sf_set_trusted_sink_int(fp);
    Res = SSL_CTX_callback_ctrl(ctx, cmd, fp);
    sf_overwrite(&Res);
    return Res;
}

int RSA_sign_ASN1_OCTET_STRING(int type, const unsigned char* m, unsigned int m_len, unsigned char* sigret, unsigned int* siglen, RSA* rsa) {
    int Res = 0;
    sf_set_trusted_sink_int(type);
    sf_set_trusted_sink_int(m);
    sf_set_trusted_sink_int(m_len);
    sf_set_trusted_sink_int(sigret);
    sf_set_trusted_sink_int(siglen);
    sf_set_trusted_sink_int(rsa);
    Res = RSA_sign_ASN1_OCTET_STRING(type, m, m_len, sigret, siglen, rsa);
    sf_overwrite(&Res);
    return Res;
}

X509_PUBKEY* PEM_read_bio_X509_PUBKEY(BIO* bio, X509_PUBKEY** x, pem_password_cb* cb, void* u) {
    X509_PUBKEY* Res = NULL;
    sf_set_trusted_sink_int(bio);
    sf_set_trusted_sink_int(x);
    sf_password_use(cb);
    sf_set_trusted_sink_int(u);
    Res = PEM_read_bio_X509_PUBKEY(bio, x, cb, u);
    sf_overwrite(Res);
    return Res;
}

int OSSL_HTTP_REQ_CTX_nbio_d2i(OSSL_HTTP_REQ_CTX *ctx, ASN1_VALUE **val, const ASN1_ITEM *it)
{
    int res = 0;
    // Check for null values
    sf_set_must_be_not_null(ctx, "OSSL_HTTP_REQ_CTX");
    sf_set_must_be_not_null(val, "ASN1_VALUE");
    sf_set_must_be_not_null(it, "ASN1_ITEM");

    // Check for TOCTTOU race conditions
    sf_tocttou_check(ctx);

    // Check for possible negative values
    sf_set_possible_negative(res);

    // Check for errno values
    sf_set_errno_if(res == -1);

    return res;
}

const char* CTLOG_get0_name(const CTLOG *log)
{
    const char *res = NULL;
    // Check for null values
    sf_set_must_be_not_null(log, "CTLOG");

    // Check for TOCTTOU race conditions
    sf_tocttou_check(log);

    // Check for possible null return
    sf_set_possible_null(res);

    return res;
}

const EVP_PKEY_METHOD* EVP_PKEY_meth_get0(size_t idx)
{
    const EVP_PKEY_METHOD *res = NULL;
    // Check for possible out of bounds
    sf_set_possible_out_of_bounds(idx);

    // Check for TOCTTOU race conditions
    sf_tocttou_check(idx);

    // Check for possible null return
    sf_set_possible_null(res);

    return res;
}

void X509_VERIFY_PARAM_set_time(X509_VERIFY_PARAM *param, time_t t)
{
    // Check for null values
    sf_set_must_be_not_null(param, "X509_VERIFY_PARAM");

    // Check for TOCTTOU race conditions
    sf_tocttou_check(param);

    // Check for long time
    sf_long_time(t);
}

void EVP_PKEY_meth_get_keygen(const EVP_PKEY_METHOD *pmeth, int (**keygen) (EVP_PKEY_CTX *ctx), int (**keygen_init) (EVP_PKEY_CTX *ctx, EVP_PKEY *pkey))
{
    // Check for null values
    sf_set_must_be_not_null(pmeth, "EVP_PKEY_METHOD");
    sf_set_must_be_not_null(keygen, "keygen");
    sf_set_must_be_not_null(keygen_init, "keygen_init");

    // Check for TOCTTOU race conditions
    sf_tocttou_check(pmeth);
}

void NAMING_AUTHORITY_free(NAMING_AUTHORITY* ptr) {
    sf_delete(ptr, PAGES_MEMORY_CATEGORY);
}

X509* X509_load_http(const char* url, BIO* bio, BIO* bio2, int i) {
    X509* res = NULL;
    sf_set_trusted_sink_int(i);
    sf_lib_arg_type(bio, "BIO");
    sf_lib_arg_type(bio2, "BIO");
    sf_lib_arg_type(url, "URL");
    sf_set_tainted(url);
    sf_set_possible_null(res);
    return res;
}

void X509_STORE_set_check_crl(X509_STORE* store, X509_STORE_CTX_check_crl_fn func) {
    sf_lib_arg_type(store, "X509_STORE");
    sf_lib_arg_type(func, "X509_STORE_CTX_check_crl_fn");
}

unsigned int OPENSSL_version_minor() {
    unsigned int res = 0;
    sf_set_possible_negative(res);
    return res;
}

int X509_issuer_name_cmp(const X509* x, const X509* y) {
    int res = 0;
    sf_set_possible_negative(res);
    sf_lib_arg_type(x, "X509");
    sf_lib_arg_type(y, "X509");
    return res;
}
void BIO_ADDR_free(BIO_ADDR* a);

void CONF_modules_unload(int all);

void ENGINE_register_all_digests();

int DH_security_bits(const DH* dh);

int ASN1_STRING_type(const ASN1_STRING* x);

void EVP_PKEY_meth_get_verify(const EVP_PKEY_METHOD *method, int (**verify);

void SSL_CTX_set0_security_ex_data(SSL_CTX *ctx, void *ex_data);

void BIO_set_callback_arg(BIO *bio, char *arg);

int SSL_get_async_status(SSL *ssl, int *status);

int X509_LOOKUP_meth_set_free(X509_LOOKUP_METHOD *method, void (*free);


int PEM_write_bio_DSAPrivateKey(BIO* bio, const DSA* dsa, const EVP_CIPHER* cipher, const unsigned char* passwd, int len, pem_password_cb* cb, void* u) {
    int res = 0;
    sf_set_tainted(passwd);
    sf_password_use(passwd);
    sf_set_trusted_sink_ptr(bio);
    sf_set_trusted_sink_ptr(dsa);
    sf_set_trusted_sink_ptr(cipher);
    sf_set_trusted_sink_ptr(cb);
    sf_set_trusted_sink_ptr(u);
    sf_set_errno_if(res == 0);
    sf_no_errno_if(res != 0);
    return res;
}

int i2d_KeyParams_bio(BIO* bio, const EVP_PKEY* pkey) {
    int res = 0;
    sf_set_trusted_sink_ptr(bio);
    sf_set_trusted_sink_ptr(pkey);
    sf_set_errno_if(res == 0);
    sf_no_errno_if(res != 0);
    return res;
}

void X509_set_proxy_pathlen(X509* x, long l) {
    sf_set_trusted_sink_ptr(x);
    sf_set_trusted_sink_int(l);
}

int CONF_modules_load_file_ex(OSSL_LIB_CTX* ctx, const char* file, const char* dir, unsigned long flags) {
    int res = 0;
    sf_tocttou_check(file);
    sf_tocttou_check(dir);
    sf_set_trusted_sink_ptr(ctx);
    sf_set_errno_if(res == 0);
    sf_no_errno_if(res != 0);
    return res;
}

int X509v3_get_ext_by_OBJ(const stack_st_X509_EXTENSION* sk, const ASN1_OBJECT* obj, int lastpos) {
    int res = 0;
    sf_set_trusted_sink_ptr(sk);
    sf_set_trusted_sink_ptr(obj);
    sf_set_trusted_sink_int(lastpos);
    sf_set_errno_if(res == 0);
    sf_no_errno_if(res != 0);
    return res;
}

int PEM_write_bio_ECPKParameters(BIO* bio, const EC_GROUP* group) {
    int Res = 0;
    sf_set_trusted_sink_int(bio);
    sf_set_trusted_sink_ptr(group);
    Res = PEM_write_bio_ECPKParameters(bio, group);
    sf_overwrite(Res);
    return Res;
}

int BIO_ADDR_rawaddress(const BIO_ADDR* addr, void* buf, size_t* len) {
    int Res = 0;
    sf_set_trusted_sink_ptr(addr);
    sf_set_trusted_sink_ptr(buf);
    sf_set_trusted_sink_ptr(len);
    Res = BIO_ADDR_rawaddress(addr, buf, len);
    sf_overwrite(Res);
    return Res;
}

const BIGNUM* DH_get0_q(const DH* dh) {
    const BIGNUM* Res = NULL;
    sf_set_trusted_sink_ptr(dh);
    Res = DH_get0_q(dh);
    sf_overwrite(Res);
    return Res;
}

uint32_t SSL_get_max_early_data(const SSL* ssl) {
    uint32_t Res = 0;
    sf_set_trusted_sink_ptr(ssl);
    Res = SSL_get_max_early_data(ssl);
    sf_overwrite(Res);
    return Res;
}

unsigned long ERR_peek_last_error_func(const char** file, int* line) {
    unsigned long Res = 0;
    sf_set_trusted_sink_ptr(file);
    sf_set_trusted_sink_ptr(line);
    Res = ERR_peek_last_error_func(file, line);
    sf_overwrite(Res);
    return Res;
}

NETSCAPE_CERT_SEQUENCE* PEM_read_bio_NETSCAPE_CERT_SEQUENCE(BIO* bio, NETSCAPE_CERT_SEQUENCE** cert_seq, pem_password_cb* cb, void* u) {
    NETSCAPE_CERT_SEQUENCE* Res = NULL;
    sf_set_trusted_sink_int(bio);
    sf_set_trusted_sink_ptr(cert_seq);
    sf_set_trusted_sink_ptr(cb);
    sf_set_trusted_sink_ptr(u);
    sf_set_tainted(bio);
    sf_set_tainted(cert_seq);
    sf_set_tainted(cb);
    sf_set_tainted(u);
    sf_set_must_not_be_null(bio);
    sf_set_must_not_be_null(cert_seq);
    sf_set_possible_null(Res);
    return Res;
}

int SSL_get_fd(const SSL* ssl) {
    int Res = 0;
    sf_set_must_not_be_null(ssl);
    sf_set_must_be_positive(Res);
    sf_set_possible_null(Res);
    return Res;
}

int EVP_CIPHER_CTX_get_tag_length(const EVP_CIPHER_CTX* ctx) {
    int Res = 0;
    sf_set_must_not_be_null(ctx);
    sf_set_possible_negative(Res);
    return Res;
}

ASN1_UTCTIME* ASN1_UTCTIME_set(ASN1_UTCTIME* s, time_t t) {
    ASN1_UTCTIME* Res = NULL;
    sf_set_must_not_be_null(s);
    sf_set_possible_null(Res);
    return Res;
}

X509_LOOKUP_METHOD* X509_LOOKUP_meth_new(const char* name) {
    X509_LOOKUP_METHOD* Res = NULL;
    sf_set_must_not_be_null(name);
    sf_set_tainted(name);
    sf_set_possible_null(Res);
    return Res;
}
Here are the specifications for the functions:

1. int UI_set_result_ex(UI *ui, UI_STRING *uis, const char *string, int len)
```c
    sf_set_trusted_sink_int(len);
    int Res = 0;
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set_errno_if(Res, EINVAL);
    sf_set_errno_if(Res, ENOMEM);
    sf_set_errno_if(Res, EFAULT);
    sf_set_errno_if(Res, EOVERFLOW);
    sf_set
EVP_PKEY* EVP_PKEY_dup(EVP_PKEY* pkey) {
    EVP_PKEY* Res = NULL;
    sf_set_trusted_sink_ptr(Res);
    sf_set_alloc_possible_null(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_lib_arg_type(pkey, "EVP_PKEY");
    sf_bitcopy(Res, pkey);
    return Res;
}

void* DH_get_ex_data(const DH* dh, int idx) {
    void* Res = NULL;
    sf_set_possible_null(Res);
    sf_lib_arg_type(dh, "DH");
    sf_lib_arg_type(idx, "int");
    return Res;
}

int RAND_set_rand_method(const RAND_METHOD* meth) {
    int Res = 0;
    sf_set_errno_if(Res, meth == NULL);
    sf_lib_arg_type(meth, "RAND_METHOD");
    return Res;
}

ASN1_TIME* ASN1_TIME_set(ASN1_TIME* s, time_t t) {
    ASN1_TIME* Res = NULL;
    sf_set_trusted_sink_ptr(Res);
    sf_set_alloc_possible_null(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_lib_arg_type(s, "ASN1_TIME");
    sf_lib_arg_type(t, "time_t");
    sf_bitcopy(Res, s);
    return Res;
}

size_t EC_POINT_point2oct(const EC_GROUP* group, const EC_POINT* point, point_conversion_form_t form, unsigned char* buf, size_t len, BN_CTX* ctx) {
    size_t Res = 0;
    sf_set_buf_size_limit(buf, len);
    sf_lib_arg_type(group, "EC_GROUP");
    sf_lib_arg_type(point, "EC_POINT");
    sf_lib_arg_type(form, "point_conversion_form_t");
    sf_lib_arg_type(len, "size_t");
    sf_lib_arg_type(ctx, "BN_CTX");
    return Res;
}
void SSL_set0_rbio(SSL* s, BIO* rbio);

int RSA_set0_key(RSA* r, BIGNUM* n, BIGNUM* e, BIGNUM* d);

ASN1_GENERALIZEDTIME* ASN1_GENERALIZEDTIME_adj(ASN1_GENERALIZEDTIME* s, time_t t, int offset_day, long offset_sec);

int ASN1_TYPE_set1(ASN1_TYPE* a, int type, const void* value);

const BIGNUM* BN_get0_nist_prime_521();


stack_st_X509* X509_STORE_CTX_get0_untrusted(const X509_STORE_CTX* ctx) {
    stack_st_X509* Res = NULL;
    sf_set_trusted_sink_ptr(ctx);
    sf_set_possible_null(Res);
    return Res;
}

const EVP_CIPHER* EVP_aes_192_cfb8() {
    const EVP_CIPHER* Res = NULL;
    sf_set_trusted_sink_ptr(Res);
    sf_set_possible_null(Res);
    return Res;
}

int X509_NAME_add_entry_by_NID(X509_NAME* name, int nid, int type, const unsigned char* bytes, int len, int loc, int set) {
    int Res = 0;
    sf_set_trusted_sink_ptr(name);
    sf_set_trusted_sink_int(nid);
    sf_set_trusted_sink_int(type);
    sf_set_trusted_sink_int(len);
    sf_set_trusted_sink_int(loc);
    sf_set_trusted_sink_int(set);
    sf_set_errno_if(Res <= 0);
    return Res;
}

PKCS8_PRIV_KEY_INFO* PEM_read_bio_PKCS8_PRIV_KEY_INFO(BIO* bio, PKCS8_PRIV_KEY_INFO** p8inf, pem_password_cb* cb, void* u) {
    PKCS8_PRIV_KEY_INFO* Res = NULL;
    sf_set_trusted_sink_ptr(bio);
    sf_set_trusted_sink_ptr(p8inf);
    sf_set_trusted_sink_ptr(cb);
    sf_set_trusted_sink_ptr(u);
    sf_set_possible_null(Res);
    return Res;
}

const char* EVP_ASYM_CIPHER_get0_description(const EVP_ASYM_CIPHER* cipher) {
    const char* Res = NULL;
    sf_set_trusted_sink_ptr(cipher);
    sf_set_possible_null(Res);
    return Res;
}

void BIO_meth_set_destroy(BIO_METHOD *biom, int (*destroy)(BIO *)) {
    sf_set_trusted_sink_ptr(destroy);
    sf_set_trusted_sink_ptr(biom);
    biom->destroy = destroy;
}

EVP_MAC_CTX* EVP_MAC_CTX_new(EVP_MAC* mac) {
    EVP_MAC_CTX *ctx = NULL;
    sf_malloc_arg(ctx, sizeof(EVP_MAC_CTX));
    sf_overwrite(ctx);
    sf_new(ctx, MALLOC_CATEGORY);
    sf_set_alloc_possible_null(ctx);
    ctx->mac = mac;
    return ctx;
}

int PKCS5_PBE_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass, int passlen, ASN1_TYPE *param, const EVP_CIPHER *c, const EVP_MD *md, int en_de) {
    sf_password_use(pass, passlen);
    sf_set_must_be_not_null(ctx, "EVP_CIPHER_CTX");
    sf_set_must_be_not_null(c, "EVP_CIPHER");
    sf_set_must_be_not_null(md, "EVP_MD");
    // ... rest of the function
}

int EC_POINT_get_affine_coordinates(const EC_GROUP *group, const EC_POINT *point, BIGNUM *x, BIGNUM *y, BN_CTX *ctx) {
    sf_set_must_be_not_null(group, "EC_GROUP");
    sf_set_must_be_not_null(point, "EC_POINT");
    sf_set_must_be_not_null(x, "BIGNUM");
    sf_set_must_be_not_null(y, "BIGNUM");
    // ... rest of the function
}

void X509_STORE_set_cleanup(X509_STORE *store, X509_STORE_CTX_cleanup_fn cleanup) {
    sf_set_trusted_sink_ptr(cleanup);
    sf_set_trusted_sink_ptr(store);
    store->cleanup = cleanup;
}
ECDSA_SIG* ECDSA_do_sign(const unsigned char* dgst, int dlen, EC_KEY* key);

void OPENSSL_cleanup();

int RSA_flags(const RSA* rsa);

void EVP_PKEY_asn1_set_get_priv_key(EVP_PKEY_ASN1_METHOD* ameth, int (const EVP_PKEY*, unsigned char*, size_t*);

void BN_CTX_free(BN_CTX* ctx);


ENGINE_GEN_INT_FUNC_PTR ENGINE_get_init_function(const ENGINE* engine) {
    ENGINE_GEN_INT_FUNC_PTR Res = NULL;
    sf_set_must_be_not_null(engine, "Engine");
    sf_set_possible_null(Res);
    Res = ENGINE_get_init_function(engine);
    sf_set_alloc_possible_null(Res);
    return Res;
}

void X509_STORE_CTX_set0_crls(X509_STORE_CTX* ctx, stack_st_X509_CRL* crls) {
    sf_set_must_be_not_null(ctx, "X509_STORE_CTX");
    sf_set_must_be_not_null(crls, "stack_st_X509_CRL");
    X509_STORE_CTX_set0_crls(ctx, crls);
}

int BIO_meth_set_write(BIO_METHOD* biom, int (*write_fn)(BIO*, const char*, int)) {
    int Res = 0;
    sf_set_must_be_not_null(biom, "BIO_METHOD");
    sf_set_must_be_not_null(write_fn, "write_fn");
    Res = BIO_meth_set_write(biom, write_fn);
    sf_set_errno_if(Res <= 0, "BIO_meth_set_write");
    return Res;
}

void X509_STORE_CTX_set_error_depth(X509_STORE_CTX* ctx, int depth) {
    sf_set_must_be_not_null(ctx, "X509_STORE_CTX");
    sf_set_must_be_not_null(depth, "depth");
    X509_STORE_CTX_set_error_depth(ctx, depth);
}

const OSSL_PROVIDER* EVP_RAND_get0_provider(const EVP_RAND* rand) {
    const OSSL_PROVIDER* Res = NULL;
    sf_set_must_be_not_null(rand, "EVP_RAND");
    sf_set_possible_null(Res);
    Res = EVP_RAND_get0_provider(rand);
    return Res;
}

void DIST_POINT_free(DIST_POINT* point) {
    sf_set_must_be_not_null(point, FREE_OF_NULL);
    sf_delete(point, DIST_POINT_MEMORY_CATEGORY);
}

int UI_get_result_length(UI* ui, int len) {
    sf_set_must_be_not_null(ui, UI_NULL);
    sf_set_buf_size(ui->result, len);
    sf_buf_size_limit(ui->result, len);
    sf_buf_stop_at_null(ui->result);
    return len;
}

const char* EVP_PKEY_get0_type_name(const EVP_PKEY* pkey) {
    sf_set_must_be_not_null(pkey, EVP_PKEY_NULL);
    sf_set_tainted(pkey->type_name);
    return pkey->type_name;
}

int (UI*)* UI_method_get_flusher(const UI_METHOD* method) {
    sf_set_must_be_not_null(method, UI_METHOD_NULL);
    sf_set_tainted(method->flusher);
    return method->flusher;
}

int PEM_write_bio_RSA_PUBKEY(BIO* bio, const RSA* rsa) {
    sf_set_must_be_not_null(bio, BIO_NULL);
    sf_set_must_be_not_null(rsa, RSA_NULL);
    sf_set_tainted(bio->ptr);
    sf_set_tainted(rsa->n);
    sf_set_tainted(rsa->e);
    return 1;
}

char* EC_POINT_point2hex(const EC_GROUP* group, const EC_POINT* point, point_conversion_form_t form, BN_CTX* ctx) {
    char* Res = NULL;
    sf_set_trusted_sink_int(Res);
    sf_malloc_arg(Res);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    sf_lib_arg_type(Res, "MallocCategory");
    return Res;
}

int SSL_CTX_add_session(SSL_CTX* ctx, SSL_SESSION* session) {
    int Res = 0;
    sf_set_errno_if(Res == 0);
    sf_no_errno_if(Res == 1);
    return Res;
}

int EVP_DigestSignInit(EVP_MD_CTX* ctx, EVP_PKEY_CTX** pctx, const EVP_MD* type, ENGINE* e, EVP_PKEY* pkey) {
    int Res = 0;
    sf_set_errno_if(Res == 0);
    sf_no_errno_if(Res == 1);
    return Res;
}

stack_st_SCT* o2i_SCT_LIST(stack_st_SCT** a, const unsigned char** pp, size_t len) {
    stack_st_SCT* Res = NULL;
    sf_set_trusted_sink_ptr(Res);
    sf_set_alloc_possible_null(Res);
    sf_lib_arg_type(Res, "MallocCategory");
    return Res;
}

DSA_meth_get_mod_exp DSA_meth_get_mod_exp(const DSA_METHOD* dsa) {
    DSA_meth_get_mod_exp Res = NULL;
    sf_set_trusted_sink_ptr(Res);
    sf_set_possible_null(Res);
    return Res;
}

int X509_REQ_verify_ex(X509_REQ *req, EVP_PKEY *pubkey, OSSL_LIB_CTX *libctx, const char *propq) {
    int res = 0;
    sf_set_tainted(req);
    sf_set_tainted(pubkey);
    sf_set_tainted(libctx);
    sf_set_tainted(propq);
    sf_set_must_be_not_null(req, VERIFY_OF_NULL);
    sf_set_must_be_not_null(pubkey, VERIFY_OF_NULL);
    sf_set_must_be_not_null(libctx, VERIFY_OF_NULL);
    sf_set_must_be_not_null(propq, VERIFY_OF_NULL);
    sf_set_errno_if(res == 0);
    return res;
}

int UI_dup_user_data(UI *ui, void *user_data) {
    int res = 0;
    sf_set_tainted(ui);
    sf_set_tainted(user_data);
    sf_set_must_be_not_null(ui, DUP_USER_DATA_OF_NULL);
    sf_set_must_be_not_null(user_data, DUP_USER_DATA_OF_NULL);
    sf_set_errno_if(res == 0);
    return res;
}

X509_STORE_CTX_cert_crl_fn X509_STORE_get_cert_crl(const X509_STORE *store) {
    X509_STORE_CTX_cert_crl_fn res = NULL;
    sf_set_tainted(store);
    sf_set_must_be_not_null(store, GET_CERT_CRL_OF_NULL);
    return res;
}

int PEM_write_X509_REQ_NEW(FILE *fp, const X509_REQ *req) {
    int res = 0;
    sf_set_tainted(fp);
    sf_set_tainted(req);
    sf_set_must_be_not_null(fp, WRITE_X509_REQ_NEW_OF_NULL);
    sf_set_must_be_not_null(req, WRITE_X509_REQ_NEW_OF_NULL);
    sf_set_errno_if(res == 0);
    return res;
}

int EVP_KEYMGMT_is_a(const EVP_KEYMGMT *keymgmt, const char *name) {
    int res = 0;
    sf_set_tainted(keymgmt);
    sf_set_tainted(name);
    sf_set_must_be_not_null(keymgmt, KEYMGMT_IS_A_OF_NULL);
    sf_set_must_be_not_null(name, KEYMGMT_IS_A_OF_NULL);
    sf_set_errno_if(res == 0);
    return res;
}

void* ASN1_item_d2i_fp_ex(const ASN1_ITEM* it, FILE* in, void* x, OSSL_LIB_CTX* libctx, const char* propq) {
    void* Res = NULL;
    sf_set_trusted_sink_int(in);
    Res = ASN1_item_d2i_fp_ex(it, in, x, libctx, propq);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    return Res;
}

int DSA_set_ex_data(DSA* d, int idx, void* arg) {
    sf_set_must_be_not_null(d, SET_EX_DATA_OF_NULL);
    sf_set_must_be_not_null(arg, SET_EX_DATA_WITH_NULL);
    return DSA_set_ex_data(d, idx, arg);
}

int EVP_PKEY_CTX_get_group_name(EVP_PKEY_CTX* ctx, char* name, size_t len) {
    int Res = 0;
    sf_set_must_be_not_null(ctx, GET_GROUP_NAME_OF_NULL);
    sf_set_must_be_not_null(name, GET_GROUP_NAME_WITH_NULL);
    Res = EVP_PKEY_CTX_get_group_name(ctx, name, len);
    sf_buf_size_limit(name, len);
    sf_null_terminated(name);
    return Res;
}

int RSA_private_decrypt(int flen, const unsigned char* from, unsigned char* to, RSA* rsa, int padding) {
    int Res = 0;
    sf_set_must_be_not_null(from, PRIVATE_DECRYPT_FROM_NULL);
    sf_set_must_be_not_null(to, PRIVATE_DECRYPT_TO_NULL);
    sf_set_must_be_not_null(rsa, PRIVATE_DECRYPT_RSA_NULL);
    Res = RSA_private_decrypt(flen, from, to, rsa, padding);
    sf_buf_size_limit(to, RSA_size(rsa));
    return Res;
}

NAMING_AUTHORITY* d2i_NAMING_AUTHORITY(NAMING_AUTHORITY** a, const unsigned char** in, long len) {
    NAMING_AUTHORITY* Res = NULL;
    sf_set_trusted_sink_int(in);
    Res = d2i_NAMING_AUTHORITY(a, in, len);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    return Res;
}

void EVP_PKEY_asn1_set_check(EVP_PKEY_ASN1_METHOD* pkey_ameth, int (*check_fn)(const EVP_PKEY*)) {
    sf_set_tainted(pkey_ameth);
    sf_set_tainted(check_fn);
    sf_set_must_not_be_null(check_fn);
    sf_set_possible_null(pkey_ameth);
    sf_set_possible_null(check_fn);
}

DSA* d2i_DSAparams(DSA** dsa, const unsigned char** in, long len) {
    sf_set_tainted(dsa);
    sf_set_tainted(in);
    sf_set_tainted(len);
    sf_set_must_not_be_null(dsa);
    sf_set_must_not_be_null(in);
    sf_set_must_not_be_null(len);
    sf_set_possible_null(dsa);
    sf_set_possible_null(in);
    sf_set_possible_null(len);
}

X509_LOOKUP_METHOD* X509_LOOKUP_store() {
    X509_LOOKUP_METHOD* res = NULL;
    sf_set_possible_null(res);
    return res;
}

ENGINE* ENGINE_get_default_RSA() {
    ENGINE* res = NULL;
    sf_set_possible_null(res);
    return res;
}

PKCS7* PKCS7_encrypt(stack_st_X509* certs, BIO* data, const EVP_CIPHER* cipher, int flags) {
    sf_set_tainted(certs);
    sf_set_tainted(data);
    sf_set_tainted(cipher);
    sf_set_tainted(flags);
    sf_set_must_not_be_null(certs);
    sf_set_must_not_be_null(data);
    sf_set_must_not_be_null(cipher);
    sf_set_must_not_be_null(flags);
}
int SSL_SESSION_get0_ticket_appdata(SSL_SESSION* sess, void** data, size_t* len);

int i2d_DSAPrivateKey_bio(BIO* bp, const DSA* x);

int EVP_KEYMGMT_up_ref(EVP_KEYMGMT* km);

ASN1_TYPE* ASN1_TYPE_pack_sequence(const ASN1_ITEM* it, void* in, ASN1_TYPE** at);

void* EVP_PKEY_get0(const EVP_PKEY* pkey);


void DSA_set_default_method(const DSA_METHOD* meth) {
    DSA_METHOD* Res = NULL;
    sf_set_trusted_sink_ptr(meth);
    Res = DSA_get_default_method();
    sf_set_possible_null(Res);
    DSA_set_default_method(meth);
}

int EVP_PKEY_CTX_ctrl_str(EVP_PKEY_CTX *ctx, const char *name, const char *value) {
    int Res = 0;
    sf_set_must_not_be_null(ctx);
    sf_set_must_not_be_null(name);
    sf_set_must_not_be_null(value);
    Res = EVP_PKEY_CTX_ctrl_str(ctx, name, value);
    sf_set_errno_if(Res <= 0);
    return Res;
}

void EVP_CIPHER_CTX_clear_flags(EVP_CIPHER_CTX *ctx, int flags) {
    sf_set_must_not_be_null(ctx);
    EVP_CIPHER_CTX_clear_flags(ctx, flags);
}

void OPENSSL_LH_node_usage_stats(const OPENSSL_LHASH *lh, FILE *out) {
    sf_set_must_not_be_null(lh);
    sf_set_must_not_be_null(out);
    OPENSSL_LH_node_usage_stats(lh, out);
}

ASN1_ENUMERATED* d2i_ASN1_ENUMERATED(ASN1_ENUMERATED **a, const unsigned char **in, long len) {
    ASN1_ENUMERATED* Res = NULL;
    sf_set_must_not_be_null(a);
    sf_set_must_not_be_null(in);
    Res = d2i_ASN1_ENUMERATED(a, in, len);
    sf_set_possible_null(Res);
    return Res;
}

void ENGINE_register_all_RAND() {
    // No memory allocation or deallocation in this function
    // No password usage
    // No memory initialization
    // No password setting
    // No overwrite
    // No trusted sink pointer
    // No string and buffer operations
    // No error handling
    // No TOCTTOU race conditions
    // No file descriptor validity
    // No tainted data
    // No sensitive data
    // No time
    // No file offsets or sizes
    // No program termination
    // No library argument type
    // No null checks
    // No uncontrolled pointers
    // No possible negative values
}

BIO* BIO_new_buffer_ssl_connect(SSL_CTX* ctx) {
    BIO *Res = NULL;
    // Memory Allocation and Reallocation Functions
    sf_malloc_arg(Res, "BIO_new_buffer_ssl_connect");
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    // No password usage
    // No memory initialization
    // No password setting
    // No overwrite
    // No trusted sink pointer
    // No string and buffer operations
    // No error handling
    // No TOCTTOU race conditions
    // No file descriptor validity
    // No tainted data
    // No sensitive data
    // No time
    // No file offsets or sizes
    // No program termination
    // No library argument type
    // No null checks
    // No uncontrolled pointers
    // No possible negative values
    return Res;
}

int ENGINE_set_default(ENGINE* e, unsigned int flags) {
    int Res = 0;
    // Memory Allocation and Reallocation Functions
    // No password usage
    // No memory initialization
    // No password setting
    // No overwrite
    // No trusted sink pointer
    // No string and buffer operations
    // Error Handling
    sf_set_errno_if(Res == 0, "ENGINE_set_default");
    // No TOCTTOU race conditions
    // No file descriptor validity
    // No tainted data
    // No sensitive data
    // No time
    // No file offsets or sizes
    // No program termination
    // No library argument type
    // No null checks
    // No uncontrolled pointers
    // No possible negative values
    return Res;
}

int ECDSA_sign_setup(EC_KEY* eckey, BN_CTX* ctx, BIGNUM** kinv, BIGNUM** r) {
    int Res = 0;
    // Memory Allocation and Reallocation Functions
    // No password usage
    // No memory initialization
    // No password setting
    // No overwrite
    // No trusted sink pointer
    // No string and buffer operations
    // Error Handling
    sf_set_errno_if(Res == 0, "ECDSA_sign_setup");
    // No TOCTTOU race conditions
    // No file descriptor validity
    // No tainted data
    // No sensitive data
    // No time
    // No file offsets or sizes
    // No program termination
    // No library argument type
    // No null checks
    // No uncontrolled pointers
    // No possible negative values
    return Res;
}

unsigned long ERR_peek_error_func(const char** file, unsigned int* line) {
    unsigned long Res = 0;
    // Memory Allocation and Reallocation Functions
    // No password usage
    // No memory initialization
    // No password setting
    // No overwrite
    // No trusted sink pointer
    // No string and buffer operations
    // No error handling
    // No TOCTTOU race conditions
    // No file descriptor validity
    // No tainted data
    // No sensitive data
    // No time
    // No file offsets or sizes
    // No program termination
    // No library argument type
    // No null checks
    // No uncontrolled pointers
    // No possible negative values
    return Res;
}

const OSSL_PARAM* EVP_PKEY_CTX_settable_params(const EVP_PKEY_CTX* ctx) {
    const OSSL_PARAM* Res = NULL;
    sf_set_must_be_not_null(ctx, SETTABLE_PARAMS_OF_NULL);
    Res = ossl_pkey_ctx_settable_params(ctx);
    sf_set_possible_null(Res, SETTABLE_PARAMS_POSSIBLE_NULL);
    return Res;
}

BIO* SSL_get_wbio(const SSL* s) {
    BIO* Res = NULL;
    sf_set_must_be_not_null(s, GET_WBIO_OF_NULL);
    Res = ssl_get_wbio(s);
    sf_set_possible_null(Res, GET_WBIO_POSSIBLE_NULL);
    return Res;
}

int RSA_print_fp(FILE* fp, const RSA* rsa, int offset) {
    int Res = 0;
    sf_set_must_be_not_null(fp, PRINT_FP_OF_NULL);
    sf_set_must_be_not_null(rsa, PRINT_FP_RSA_NULL);
    Res = rsa_print_fp(fp, rsa, offset);
    sf_set_errno_if(Res <= 0, PRINT_FP_ERROR);
    return Res;
}

int EVP_PKEY_verify_recover_init_ex(EVP_PKEY_CTX* ctx, const OSSL_PARAM params[]) {
    int Res = 0;
    sf_set_must_be_not_null(ctx, VERIFY_RECOVER_INIT_EX_OF_NULL);
    Res = evp_pkey_verify_recover_init_ex(ctx, params);
    sf_set_errno_if(Res <= 0, VERIFY_RECOVER_INIT_EX_ERROR);
    return Res;
}

DSA* PEM_read_bio_DSAPrivateKey(BIO* bio, DSA** dsa, pem_password_cb* cb, void* u) {
    DSA* Res = NULL;
    sf_set_must_be_not_null(bio, READ_BIO_DSA_PRIVATE_KEY_OF_NULL);
    Res = pem_read_bio_dsa_private_key(bio, dsa, cb, u);
    sf_set_possible_null(Res, READ_BIO_DSA_PRIVATE_KEY_POSSIBLE_NULL);
    return Res;
}

int EVP_PKEY_CTX_set_dsa_paramgen_gindex(EVP_PKEY_CTX* ctx, int gindex) {
    int Res = 0;
    sf_set_tainted(gindex);
    sf_set_must_be_not_null(ctx, SET_DSA_PARAMGEN_GINDEX_OF_NULL);
    Res = EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_PARAMGEN, EVP_PKEY_CTRL_DSA_PARAMGEN_GINDEX, gindex, NULL);
    sf_set_errno_if(Res <= 0, SET_DSA_PARAMGEN_GINDEX_FAILURE);
    return Res;
}

int ASYNC_WAIT_CTX_set_wait_fd(ASYNC_WAIT_CTX* ctx, const void* fd, int num, void* cb, void (*cleanup)(ASYNC_WAIT_CTX*, const void*, int, void*)) {
    int Res = 0;
    sf_set_must_be_not_null(ctx, SET_WAIT_FD_OF_NULL);
    Res = ASYNC_WAIT_CTX_set_wait_fd(ctx, fd, num, cb, cleanup);
    sf_set_errno_if(Res <= 0, SET_WAIT_FD_FAILURE);
    return Res;
}

X509_ATTRIBUTE* X509_ATTRIBUTE_create(int nid, int atrtype, void* data) {
    X509_ATTRIBUTE* Res = NULL;
    sf_set_tainted(nid);
    sf_set_tainted(atrtype);
    sf_set_tainted(data);
    Res = X509_ATTRIBUTE_create(nid, atrtype, data);
    sf_set_errno_if(Res == NULL, X509_ATTRIBUTE_CREATE_FAILURE);
    return Res;
}

int EVP_MAC_final(EVP_MAC_CTX* ctx, unsigned char* out, size_t* outl, size_t outsize) {
    int Res = 0;
    sf_set_must_be_not_null(ctx, EVP_MAC_FINAL_OF_NULL);
    sf_set_buf_size_limit(out, outsize);
    Res = EVP_MAC_final(ctx, out, outl, outsize);
    sf_set_errno_if(Res <= 0, EVP_MAC_FINAL_FAILURE);
    return Res;
}

void DSA_meth_free(DSA_METHOD* meth) {
    sf_set_must_be_not_null(meth, DSA_METH_FREE_OF_NULL);
    DSA_meth_free(meth);
}

int i2d_X509_REQ_bio(BIO* bp, const X509_REQ* req) {
    int res = 0;
    sf_set_must_be_not_null(bp, BIO_FREE_OF_NULL);
    sf_set_must_be_not_null(req, X509_REQ_FREE_OF_NULL);
    res = i2d_X509_REQ_bio(bp, req);
    sf_set_errno_if(res <= 0);
    return res;
}

int RSA_meth_set_mod_exp(RSA_METHOD* rsa, int (*mod_exp)(BIGNUM*, const BIGNUM*, RSA*, BN_CTX*)) {
    int res = 0;
    sf_set_must_be_not_null(rsa, RSA_METHOD_FREE_OF_NULL);
    sf_set_must_be_not_null(mod_exp, MOD_EXP_FREE_OF_NULL);
    res = RSA_meth_set_mod_exp(rsa, mod_exp);
    sf_set_errno_if(res != 1);
    return res;
}

ASN1_VALUE* ASN1_item_d2i(ASN1_VALUE** val, const unsigned char** in, long len, const ASN1_ITEM* it) {
    ASN1_VALUE* res = NULL;
    sf_set_must_be_not_null(val, ASN1_VALUE_FREE_OF_NULL);
    sf_set_must_be_not_null(in, INPUT_DATA_FREE_OF_NULL);
    sf_set_must_be_not_null(it, ASN1_ITEM_FREE_OF_NULL);
    res = ASN1_item_d2i(val, in, len, it);
    sf_set_errno_if(res == NULL);
    return res;
}

void X509_ALGOR_set_md(X509_ALGOR* alg, const EVP_MD* md) {
    sf_set_must_be_not_null(alg, X509_ALGOR_FREE_OF_NULL);
    sf_set_must_be_not_null(md, EVP_MD_FREE_OF_NULL);
    X509_ALGOR_set_md(alg, md);
}

int X509_REVOKED_add1_ext_i2d(X509_REVOKED* rv, int nid, void* value, int crit, unsigned long flags) {
    int res = 0;
    sf_set_must_be_not_null(rv, X509_REVOKED_FREE_OF_NULL);
    res = X509_REVOKED_add1_ext_i2d(rv, nid, value, crit, flags);
    sf_set_errno_if(res != 1);
    return res;
}

int i2d_GENERAL_NAMES(const GENERAL_NAMES* a, unsigned char** pp)
{
    int res = 0;
    // Specify that pp is a trusted sink pointer
    sf_set_trusted_sink_ptr(pp);
    // Specify that a is a tainted data
    sf_set_tainted(a);
    // Check for null
    sf_set_must_be_not_null(a, GENERAL_NAMES_NULL);
    // Check for TOCTTOU race conditions
    sf_tocttou_check(a);
    // Check for buffer size limit
    sf_buf_size_limit(pp, GENERAL_NAMES_SIZE);
    // Check for error handling
    sf_set_errno_if(res <= 0, GENERAL_NAMES_ERROR);
    // Return result
    return res;
}

EVP_PKEY* EVP_PKEY_new_raw_private_key(int type, ENGINE* engine, const unsigned char* key, size_t keylen)
{
    EVP_PKEY* res = NULL;
    // Specify that key is a sensitive data
    sf_password_set(key);
    // Check for null
    sf_set_must_be_not_null(key, PRIVATE_KEY_NULL);
    // Check for TOCTTOU race conditions
    sf_tocttou_check(key);
    // Check for buffer size limit
    sf_buf_size_limit(&key, keylen, PRIVATE_KEY_SIZE);
    // Check for error handling
    sf_set_errno_if(res == NULL, PRIVATE_KEY_ERROR);
    // Return result
    return res;
}

void EVP_PKEY_asn1_copy(EVP_PKEY_ASN1_METHOD* dst, const EVP_PKEY_ASN1_METHOD* src)
{
    // Specify that src is a tainted data
    sf_set_tainted(src);
    // Check for null
    sf_set_must_be_not_null(src, ASN1_METHOD_NULL);
    // Check for TOCTTOU race conditions
    sf_tocttou_check(src);
    // Copy data from src to dst
    sf_bitcopy(dst, src);
}

PBEPARAM* d2i_PBEPARAM(PBEPARAM** a, const unsigned char** pp, long length)
{
    PBEPARAM* res = NULL;
    // Specify that pp is a trusted sink pointer
    sf_set_trusted_sink_ptr(pp);
    // Check for null
    sf_set_must_be_not_null(pp, PBEPARAM_NULL);
    // Check for TOCTTOU race conditions
    sf_tocttou_check(pp);
    // Check for buffer size limit
    sf_buf_size_limit(pp, length, PBEPARAM_SIZE);
    // Check for error handling
    sf_set_errno_if(res == NULL, PBEPARAM_ERROR);
    // Return result
    return res;
}

const EC_METHOD* EC_GFp_mont_method()
{
    const EC_METHOD* res = NULL;
    // Check for error handling
    sf_set_errno_if(res == NULL, EC_METHOD_ERROR);
    // Return result
    return res;
}
int i2d_SXNET(const SXNET *sx, unsigned char **pp);

void SSL_CTX_set_psk_use_session_callback(SSL_CTX *ctx, SSL_psk_use_session_cb_func cb);

int CONF_modules_load_file(const char *file, const char *module_section, unsigned long flags);

void SSL_set_hostflags(SSL *s, unsigned int flags);

int EVP_PKEY_get_bits(const EVP_PKEY *pkey);


const ASN1_ITEM* ASN1_ITEM_get(size_t size)
{
    sf_set_trusted_sink_int(size);
    const ASN1_ITEM* Res = NULL;
    // Function body
    return Res;
}

int BN_add(BIGNUM* a, const BIGNUM* b, const BIGNUM* c)
{
    int Res = 0;
    // Function body
    return Res;
}

const EVP_CIPHER* EVP_camellia_128_ofb()
{
    const EVP_CIPHER* Res = NULL;
    // Function body
    return Res;
}

int X509_REQ_set1_signature_algo(X509_REQ* a, X509_ALGOR* b)
{
    int Res = 0;
    // Function body
    return Res;
}

int EVP_EncryptInit_ex2(EVP_CIPHER_CTX* a, const EVP_CIPHER* b, const unsigned char* c, const unsigned char* d, const OSSL_PARAM e[])
{
    int Res = 0;
    // Function body
    return Res;
}

int CRYPTO_get_ex_new_index(int a1, long a2, void* a3, CRYPTO_EX_new* a4, CRYPTO_EX_dup* a5, CRYPTO_EX_free* a6) {
    int Res = 0;
    sf_set_trusted_sink_int(a1);
    sf_set_trusted_sink_int(a2);
    sf_set_trusted_sink_ptr(a3);
    sf_set_trusted_sink_ptr(a4);
    sf_set_trusted_sink_ptr(a5);
    sf_set_trusted_sink_ptr(a6);
    sf_set_errno_if(Res, ENOMEM);
    return Res;
}

int SSL_get_shared_sigalgs(SSL* a1, int a2, int* a3, int* a4, int* a5, unsigned char* a6, unsigned char* a7) {
    int Res = 0;
    sf_set_must_not_be_null(a1);
    sf_set_trusted_sink_int(a2);
    sf_set_trusted_sink_ptr(a3);
    sf_set_trusted_sink_ptr(a4);
    sf_set_trusted_sink_ptr(a5);
    sf_set_trusted_sink_ptr(a6);
    sf_set_trusted_sink_ptr(a7);
    sf_set_errno_if(Res, ENOMEM);
    return Res;
}

void EVP_CIPHER_CTX_set_flags(EVP_CIPHER_CTX* a1, int a2) {
    sf_set_must_not_be_null(a1);
    sf_set_trusted_sink_int(a2);
}

ASRange* d2i_ASRange(ASRange** a1, const unsigned char** a2, long a3) {
    ASRange* Res = NULL;
    sf_set_trusted_sink_ptr(a1);
    sf_set_trusted_sink_ptr(a2);
    sf_set_trusted_sink_long(a3);
    sf_set_alloc_possible_null(Res, a3);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    return Res;
}

int SSL_set_async_callback(SSL* a1, SSL_async_callback_fn a2) {
    int Res = 0;
    sf_set_must_not_be_null(a1);
    sf_set_trusted_sink_ptr(a2);
    sf_set_errno_if(Res, ENOMEM);
    return Res;
}

BIGNUM* BN_get_rfc3526_prime_1536(BIGNUM* Res) {
    Res = NULL;
    // function body
    return Res;
}

EC_KEY* d2i_ECPrivateKey(EC_KEY** Res, const unsigned char** in, long len) {
    Res = NULL;
    // function body
    return Res;
}

int SSL_set_fd(SSL* ssl, int fd) {
    int Res = 0;
    // function body
    return Res;
}

EVP_PKEY* EVP_PKEY_new_raw_public_key(int type, ENGINE* engine, const unsigned char* key, size_t keylen) {
    EVP_PKEY* Res = NULL;
    // function body
    return Res;
}

int EVP_RAND_uninstantiate(EVP_RAND_CTX* ctx) {
    int Res = 0;
    // function body
    return Res;
}

size_t DTLS_get_data_mtu(const SSL* ssl) {
    size_t Res = 0;
    sf_set_trusted_sink_int(Res);
    sf_malloc_arg(Res);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    sf_buf_size_limit(Res, ssl->d1->mtu);
    sf_lib_arg_type(Res, "DTLS_get_data_mtu");
    return Res;
}

const ASN1_TIME* X509_get0_notBefore(const X509* x) {
    const ASN1_TIME* Res = NULL;
    sf_set_must_be_not_null(x, X509_get0_notBefore);
    Res = x->cert_info->validity->notBefore;
    sf_null_terminated(Res);
    return Res;
}

void SSL_get0_next_proto_negotiated(const SSL* s, const unsigned char** data, unsigned* len) {
    sf_set_must_be_not_null(s, SSL_get0_next_proto_negotiated);
    sf_set_must_be_not_null(data, SSL_get0_next_proto_negotiated);
    sf_set_must_be_not_null(len, SSL_get0_next_proto_negotiated);
    *data = s->s3->next_proto_negotiated;
    *len = s->s3->next_proto_negotiated_len;
    sf_overwrite(*data);
    sf_overwrite(*len);
}

void EVP_KEM_do_all_provided(OSSL_LIB_CTX* ctx, void (EVP_KEM*, void*)* cb, void* arg) {
    sf_set_must_be_not_null(ctx, EVP_KEM_do_all_provided);
    sf_set_must_be_not_null(cb, EVP_KEM_do_all_provided);
    sf_set_must_be_not_null(arg, EVP_KEM_do_all_provided);
    // Call the callback function for each provided method
    for (EVP_KEM* kem : ctx->provided_KEMs) {
        (*cb)(kem, arg);
    }
}

int X509_load_cert_file(X509_LOOKUP* x, const char* file, int type) {
    int Res = 0;
    sf_set_must_be_not_null(x, X509_load_cert_file);
    sf_set_must_be_not_null(file, X509_load_cert_file);
    sf_tocttou_check(file);
    sf_set_buf_size(file, strlen(file));
    // Load the certificate file
    // ...
    sf_set_errno_if(Res <= 0);
    sf_set_possible_negative(Res);
    return Res;
}
uint64_t SSL_set_options(SSL* ssl, uint64_t options);

int BIO_meth_get_read(const BIO_METHOD* type);

OCSP_REVOKEDINFO* OCSP_REVOKEDINFO_new();

X509_REVOKED* X509_REVOKED_dup(const X509_REVOKED* rev);

RSA* RSAPublicKey_dup(const RSA* rsa);

int i2d_DIST_POINT_NAME(const DIST_POINT_NAME* a, unsigned char** pp);

RSA_OAEP_PARAMS* RSA_OAEP_PARAMS_new();

ASYNC_WAIT_CTX* ASYNC_WAIT_CTX_new();

int (EVP_MD_CTX*, int, int, void*);

int X509_add_certs(stack_st_X509* x, stack_st_X509* x509s, int flags);


int ENGINE_set_finish_function(ENGINE* e, ENGINE_GEN_INT_FUNC_PTR f) {
    int Res = 0;
    sf_set_trusted_sink_int(f);
    sf_set_errno_if(Res == 0, ENGINE_R_INIT_FAILED);
    return Res;
}

BIGNUM* BN_get_rfc2409_prime_768(BIGNUM* bn) {
    BIGNUM* Res = NULL;
    sf_set_possible_null(Res);
    sf_set_errno_if(Res == NULL, BN_R_NOT_A_PRIME);
    return Res;
}

int PEM_write_bio_PUBKEY_ex(BIO* bio, const EVP_PKEY* pkey, OSSL_LIB_CTX* libctx, const char* pass) {
    int Res = 0;
    sf_password_use(pass);
    sf_set_errno_if(Res == 0, PEM_R_PUBLIC_KEY_WRITE_ERROR);
    return Res;
}

int CTLOG_STORE_load_default_file(CTLOG_STORE* cts) {
    int Res = 0;
    sf_set_errno_if(Res == 0, CTLOG_R_LOADING_DEFAULTS_FAILED);
    return Res;
}

int i2d_NOTICEREF(const NOTICEREF* nr, unsigned char** pp) {
    int Res = 0;
    sf_set_errno_if(Res == 0, ASN1_R_ENCODING_ERROR);
    return Res;
}

ASN1_VISIBLESTRING* d2i_ASN1_VISIBLESTRING(ASN1_VISIBLESTRING** a, const unsigned char** pp, long length)
{
    ASN1_VISIBLESTRING* Res = NULL;
    sf_set_trusted_sink_int(length);
    sf_malloc_arg(Res, length);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res, length);
    sf_lib_arg_type(Res, "MallocCategory");
    return Res;
}

int SSL_CTX_set_recv_max_early_data(SSL_CTX* ctx, uint32_t size)
{
    sf_set_trusted_sink_int(size);
    sf_set_buf_size(ctx, size);
    return 0;
}

void SSL_CTX_set_verify(SSL_CTX* ctx, int mode, SSL_verify_cb verify_callback)
{
    sf_set_tainted(mode);
    sf_set_tainted(verify_callback);
    sf_set_tainted(ctx);
}

SSL_SESSION* SSL_SESSION_dup(const SSL_SESSION* sess)
{
    SSL_SESSION* Res = NULL;
    sf_malloc_arg(Res, sizeof(SSL_SESSION));
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res, sizeof(SSL_SESSION));
    sf_lib_arg_type(Res, "MallocCategory");
    return Res;
}

void SSL_CTX_flush_sessions(SSL_CTX* ctx, long tm)
{
    sf_set_trusted_sink_int(tm);
    sf_delete(ctx, SSL_CTX_CATEGORY);
    sf_lib_arg_type(ctx, "SSL_CTX_CATEGORY");
}

void EVP_PKEY_asn1_set_set_priv_key(EVP_PKEY_ASN1_METHOD* pkey_ameth, int (*set_priv_key) (EVP_PKEY* pkey, const unsigned char* priv, size_t len)) {
    sf_set_trusted_sink_ptr(pkey_ameth);
    sf_set_trusted_sink_ptr(set_priv_key);
    sf_set_tainted(priv);
    sf_buf_size_limit(priv, len);
    sf_lib_arg_type(pkey, "EVP_PKEY");
    sf_lib_arg_type(pkey_ameth, "EVP_PKEY_ASN1_METHOD");
}

int ASN1_GENERALIZEDTIME_print(BIO* bp, const ASN1_GENERALIZEDTIME* a) {
    sf_set_trusted_sink_ptr(bp);
    sf_set_trusted_sink_ptr(a);
    sf_lib_arg_type(bp, "BIO");
    sf_lib_arg_type(a, "ASN1_GENERALIZEDTIME");
}

int EVP_CIPHER_CTX_reset(EVP_CIPHER_CTX* ctx) {
    sf_set_trusted_sink_ptr(ctx);
    sf_lib_arg_type(ctx, "EVP_CIPHER_CTX");
}

BIO* BIO_new(const BIO_METHOD* method) {
    BIO* Res = NULL;
    sf_set_trusted_sink_ptr(method);
    sf_lib_arg_type(method, "BIO_METHOD");
    sf_malloc_arg(Res, sizeof(BIO));
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    return Res;
}

EVP_PKEY* EVP_PKEY_new_raw_private_key_ex(OSSL_LIB_CTX* libctx, const char* keytype, const char* propq, const unsigned char* priv, size_t len) {
    EVP_PKEY* Res = NULL;
    sf_set_trusted_sink_ptr(libctx);
    sf_set_tainted(keytype);
    sf_set_tainted(propq);
    sf_buf_size_limit(priv, len);
    sf_lib_arg_type(libctx, "OSSL_LIB_CTX");
    sf_malloc_arg(Res, sizeof(EVP_PKEY));
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    return Res;
}

X509_STORE_CTX_lookup_certs_fn X509_STORE_get_lookup_certs(const X509_STORE *store) {
    X509_STORE_CTX_lookup_certs_fn Res = NULL;
    sf_set_must_be_not_null(store, "X509_STORE");
    Res = store->get_lookup_certs;
    sf_set_possible_null(Res);
    return Res;
}

AUTHORITY_INFO_ACCESS* AUTHORITY_INFO_ACCESS_new() {
    AUTHORITY_INFO_ACCESS *Res = NULL;
    Res = (AUTHORITY_INFO_ACCESS *)OPENSSL_zalloc(sizeof(AUTHORITY_INFO_ACCESS));
    sf_new(Res, AUTHORITY_INFO_ACCESS_MEMORY_CATEGORY);
    sf_set_possible_null(Res);
    return Res;
}

int PEM_write_bio_PKCS8(BIO *bp, const X509_SIG *x) {
    int Res = 0;
    sf_set_must_be_not_null(bp, "BIO");
    sf_set_must_be_not_null(x, "X509_SIG");
    Res = i2d_PKCS8PrivateKeyInfo_bio(bp, x);
    sf_set_errno_if(Res <= 0, "PEM_write_bio_PKCS8");
    return Res;
}

int SSL_set_session(SSL *s, SSL_SESSION *session) {
    int Res = 0;
    sf_set_must_be_not_null(s, "SSL");
    sf_set_must_be_not_null(session, "SSL_SESSION");
    Res = SSL_set_session_internal(s, session);
    sf_set_errno_if(Res != 1, "SSL_set_session");
    return Res;
}

int EVP_PKEY_set_bn_param(EVP_PKEY *pkey, const char *key_name, const BIGNUM *bn) {
    int Res = 0;
    sf_set_must_be_not_null(pkey, "EVP_PKEY");
    sf_set_must_be_not_null(key_name, "Key name");
    sf_set_must_be_not_null(bn, "BIGNUM");
    Res = EVP_PKEY_set_bn_param_internal(pkey, key_name, bn);
    sf_set_errno_if(Res != 1, "EVP_PKEY_set_bn_param");
    return Res;
}
int ERR_clear_last_mark();

const EVP_CIPHER* EVP_des_ofb();

int ASN1_TIME_print_ex(BIO*, const ASN1_TIME*, unsigned long);

int i2d_X509_PUBKEY_bio(BIO*, const X509_PUBKEY*);

const EC_KEY_METHOD* EC_KEY_get_method(const EC_KEY*);


EVP_PKEY_CTX* EVP_PKEY_CTX_new_id(int id, ENGINE* engine) {
    EVP_PKEY_CTX* Res = NULL;
    sf_set_trusted_sink_int(id);
    Res = EVP_PKEY_CTX_new(id, engine);
    sf_overwrite(Res);
    return Res;
}

int EVP_PKEY_missing_parameters(const EVP_PKEY* pkey) {
    int Res = 0;
    Res = EVP_PKEY_missing_parameters(pkey);
    sf_overwrite(Res);
    return Res;
}

void SCT_set_timestamp(SCT* sct, uint64_t timestamp) {
    SCT_set_timestamp(sct, timestamp);
    sf_overwrite(sct);
}

int PEM_write_bio_RSAPublicKey(BIO* bio, const RSA* rsa) {
    int Res = 0;
    Res = PEM_write_bio_RSAPublicKey(bio, rsa);
    sf_overwrite(Res);
    return Res;
}

void OCSP_REQINFO_free(OCSP_REQINFO* reqinfo) {
    OCSP_REQINFO_free(reqinfo);
    sf_overwrite(reqinfo);
}

void SHA256_Init(SHA256_CTX* ctx) {
    int res = 0;
    sf_set_trusted_sink_int(ctx);
    sf_overwrite(ctx);
    res = SHA256_Init(ctx);
    sf_set_errno_if(res == 0);
    return res;
}

const char* SSL_get_psk_identity(const SSL* ssl) {
    const char* res = NULL;
    sf_set_tainted(res);
    res = SSL_get_psk_identity(ssl);
    sf_set_errno_if(res == NULL);
    return res;
}

int PEM_write_bio_X509_CRL(BIO* bio, const X509_CRL* crl) {
    int res = 0;
    sf_set_trusted_sink_int(bio);
    sf_set_trusted_sink_int(crl);
    res = PEM_write_bio_X509_CRL(bio, crl);
    sf_set_errno_if(res == 0);
    return res;
}

int i2d_OCSP_REQUEST(const OCSP_REQUEST* req, unsigned char** pp) {
    int res = 0;
    sf_set_trusted_sink_int(req);
    sf_set_trusted_sink_int(pp);
    res = i2d_OCSP_REQUEST(req, pp);
    sf_set_errno_if(res == 0);
    return res;
}

int SCT_set_signature_nid(SCT* sct, int nid) {
    int res = 0;
    sf_set_trusted_sink_int(sct);
    sf_set_trusted_sink_int(nid);
    res = SCT_set_signature_nid(sct, nid);
    sf_set_errno_if(res == 0);
    return res;
}

int EVP_Q_digest(OSSL_LIB_CTX* libctx, const char* name, const char* propquery, const void* data, size_t len, unsigned char* md, size_t* mdlen) {
    int res = 0;
    sf_set_trusted_sink_int(mdlen);
    sf_set_trusted_sink_ptr(data);
    sf_set_tainted(name);
    sf_set_tainted(propquery);
    sf_buf_size_limit(md, *mdlen);
    sf_buf_size_limit_read(data, len);
    sf_set_must_not_be_null(libctx);
    sf_set_must_not_be_null(data);
    sf_set_must_not_be_null(md);
    sf_set_must_not_be_null(mdlen);
    sf_set_errno_if(res == 0);
    return res;
}

int (EVP_CIPHER_CTX*)* EVP_CIPHER_meth_get_cleanup(const EVP_CIPHER* cipher) {
    int (EVP_CIPHER_CTX*)* res = NULL;
    sf_set_must_not_be_null(cipher);
    sf_set_possible_null(res);
    return res;
}

unsigned long ERR_peek_last_error_data(const char** file, int* line) {
    unsigned long res = 0;
    sf_set_trusted_sink_ptr(file);
    sf_set_trusted_sink_int(line);
    sf_set_possible_null(file);
    sf_set_possible_null(line);
    return res;
}

const EVP_CIPHER* EVP_aes_128_ocb() {
    const EVP_CIPHER* res = NULL;
    sf_set_must_not_be_null(res);
    return res;
}

ECDSA_SIG* ECDSA_SIG_new() {
    ECDSA_SIG* res = NULL;
    sf_set_alloc_possible_null(res);
    return res;
}

int BIO_free(BIO* a) {
    int Res = 0;
    sf_set_must_be_not_null(a, FREE_OF_NULL);
    sf_delete(a, BIO_CATEGORY);
    Res = BIO_free(a);
    sf_set_possible_null(Res);
    return Res;
}

ENGINE* RSA_get0_engine(const RSA* r) {
    ENGINE* Res = NULL;
    sf_set_must_be_not_null(r, ENGINE_NULL);
    Res = RSA_get0_engine(r);
    sf_set_possible_null(Res);
    return Res;
}

OSSL_HTTP_REQ_CTX* OSSL_HTTP_REQ_CTX_new(BIO* ibio, BIO* obbio, int proxy) {
    OSSL_HTTP_REQ_CTX* Res = NULL;
    sf_set_must_be_not_null(ibio, IBIOSTREAM_NULL);
    sf_set_must_be_not_null(obbio, OBIOSTREAM_NULL);
    Res = OSSL_HTTP_REQ_CTX_new(ibio, obbio, proxy);
    sf_new(Res, OSSL_HTTP_REQ_CTX_CATEGORY);
    return Res;
}

const SSL_METHOD* DTLSv1_2_method() {
    const SSL_METHOD* Res = NULL;
    Res = DTLSv1_2_method();
    sf_set_possible_null(Res);
    return Res;
}

X509_STORE_CTX_check_revocation_fn X509_STORE_CTX_get_check_revocation(const X509_STORE_CTX* ctx) {
    X509_STORE_CTX_check_revocation_fn Res = NULL;
    sf_set_must_be_not_null(ctx, X509_STORE_CTX_NULL);
    Res = X509_STORE_CTX_get_check_revocation(ctx);
    sf_set_possible_null(Res);
    return Res;
}
int X509_pubkey_digest(const X509* x, const EVP_MD* md, unsigned char* buf, unsigned int* len);

const SSL_METHOD* TLSv1_server_method();

int EVP_MD_meth_set_input_blocksize(EVP_MD* md, int blocksize);

int EVP_PKEY_CTX_get0_ecdh_kdf_ukm(EVP_PKEY_CTX* ctx, unsigned char** ukmp, size_t* ukmlen);

const EVP_CIPHER* EVP_aria_128_ctr();

int UI_add_input_string(UI*, const char*, int, char*, int, int);

EVP_PKEY* X509_REQ_get_pubkey(X509_REQ*);

void SSL_CTX_set_cert_store(SSL_CTX*, X509_STORE*);

const EVP_CIPHER* EVP_aes_128_ofb();

int SSL_CTX_config(SSL_CTX*, const char*);


// BN_MONT_CTX* BN_MONT_CTX_new()
BN_MONT_CTX* BN_MONT_CTX_new() {
    BN_MONT_CTX* Res = NULL;
    Res = (BN_MONT_CTX*)sf_malloc_arg(sizeof(BN_MONT_CTX));
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_lib_arg_type(Res, "BN_MONT_CTX");
    sf_overwrite(Res);
    return Res;
}

// int X509_set1_notBefore(X509*, const ASN1_TIME*)
int X509_set1_notBefore(X509* x, const ASN1_TIME* t) {
    int Res = 0;
    sf_set_must_be_not_null(x, X509_NOT_NULL);
    sf_set_must_be_not_null(t, ASN1_TIME_NOT_NULL);
    Res = X509_set1_notBefore(x, t);
    sf_set_errno_if(Res == 0);
    return Res;
}

// int EVP_DecryptInit_ex2(EVP_CIPHER_CTX*, const EVP_CIPHER*, const unsigned char*, const unsigned char*, const OSSL_PARAM[])
int EVP_DecryptInit_ex2(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type, const unsigned char* key, const unsigned char* iv, const OSSL_PARAM params[]) {
    int Res = 0;
    sf_set_must_be_not_null(ctx, EVP_CIPHER_CTX_NOT_NULL);
    sf_set_must_be_not_null(type, EVP_CIPHER_NOT_NULL);
    sf_set_must_be_not_null(key, KEY_NOT_NULL);
    sf_set_must_be_not_null(iv, IV_NOT_NULL);
    Res = EVP_DecryptInit_ex2(ctx, type, key, iv, params);
    sf_set_errno_if(Res == 0);
    return Res;
}

// time_t X509_VERIFY_PARAM_get_time(const X509_VERIFY_PARAM*)
time_t X509_VERIFY_PARAM_get_time(const X509_VERIFY_PARAM* param) {
    time_t Res = 0;
    sf_set_must_be_not_null(param, X509_VERIFY_PARAM_NOT_NULL);
    Res = X509_VERIFY_PARAM_get_time(param);
    sf_set_errno_if(Res == 0);
    return Res;
}

// int BN_mul_word(BIGNUM*, unsigned long)
int BN_mul_word(BIGNUM* a, unsigned long w) {
    int Res = 0;
    sf_set_must_be_not_null(a, BIGNUM_NOT_NULL);
    Res = BN_mul_word(a, w);
    sf_set_errno_if(Res == 0);
    return Res;
}
void EVP_PKEY_meth_set_public_check(EVP_PKEY_METHOD *pmeth, int (*public_check);

OSSL_HTTP_REQ_CTX* OCSP_sendreq_new(BIO *bio, const char *path, const OCSP_REQUEST *req, int maxline);

void OPENSSL_INIT_set_config_file_flags(OPENSSL_INIT_SETTINGS *settings, unsigned long flags);

int X509_STORE_set_flags(X509_STORE *ctx, unsigned long flags);

int ENGINE_up_ref(ENGINE *e);

int SSL_read_ex(SSL* s, void* buf, size_t len, size_t* readbytes);

const EVP_CIPHER* EVP_aes_128_wrap();

void ASN1_add_oid_module();

SSL_CONF_CTX* SSL_CONF_CTX_new();

int EVP_PKEY_paramgen(EVP_PKEY_CTX* ctx, EVP_PKEY** ppkey);


PROXY_POLICY *Res = NULL;
sf_malloc_arg(Res, sizeof(PROXY_POLICY), "PROXY_POLICY");
sf_overwrite(Res, sizeof(PROXY_POLICY));
sf_new(Res, PAGES_MEMORY_CATEGORY);
sf_lib_arg_type(Res, "PROXY_POLICY");
return Res;

sf_set_trusted_sink_int(a);
sf_set_trusted_sink_int(b);
sf_set_trusted_sink_ptr(c);
sf_set_trusted_sink_ptr(lock);
return 0;

sf_set_trusted_sink_ptr(meth);
sf_set_trusted_sink_ptr(init);
return 0;

ENGINE *Res = NULL;
sf_lib_arg_type(Res, "ENGINE");
sf_set_possible_null(Res);
return Res;

char *Res = NULL;
sf_lib_arg_type(Res, "X509_VERIFY_PARAM");
sf_set_possible_null(Res);
return Res;

void BN_RECP_CTX_free(BN_RECP_CTX* ctx) {
    sf_delete(ctx, BN_RECP_CTX_CATEGORY);
}

void ENGINE_add_conf_module() {
    // No specifications needed as this function does not allocate or deal with memory
}

X509_NAME_ENTRY* X509_NAME_delete_entry(X509_NAME* name, int loc) {
    X509_NAME_ENTRY* res = NULL;
    sf_set_must_be_not_null(name, X509_NAME_DELETE_ENTRY_OF_NULL);
    sf_set_must_be_not_null(res, X509_NAME_DELETE_ENTRY_RES_NULL);
    sf_set_buf_size(name, sizeof(X509_NAME));
    sf_set_buf_size(res, sizeof(X509_NAME_ENTRY));
    return res;
}

int PKCS7_add_crl(PKCS7* p7, X509_CRL* crl) {
    int res = 0;
    sf_set_must_be_not_null(p7, PKCS7_ADD_CRL_P7_NULL);
    sf_set_must_be_not_null(crl, PKCS7_ADD_CRL_CRL_NULL);
    sf_set_buf_size(p7, sizeof(PKCS7));
    sf_set_buf_size(crl, sizeof(X509_CRL));
    return res;
}

const SSL_CIPHER* SSL_CIPHER_find(SSL* s, const unsigned char* str) {
    const SSL_CIPHER* res = NULL;
    sf_set_must_be_not_null(s, SSL_CIPHER_FIND_S_NULL);
    sf_set_buf_size(s, sizeof(SSL));
    sf_set_buf_size(str, strlen((const char*)str) + 1);
    sf_set_possible_null(res);
    return res;
}

void EVP_PKEY_asn1_set_security_bits(EVP_PKEY_ASN1_METHOD* p, int (*cb)(const EVP_PKEY*)) {
    sf_set_trusted_sink_ptr(p);
    sf_set_trusted_sink_ptr(cb);
}

void EC_GROUP_set_asn1_flag(EC_GROUP* group, int flag) {
    sf_set_trusted_sink_ptr(group);
    sf_set_trusted_sink_int(flag);
}

int EC_POINTs_mul(const EC_GROUP* group, EC_POINT* r, const BIGNUM* n, size_t num_points, const EC_POINT* points[], const BIGNUM* coeffs[], BN_CTX* ctx) {
    sf_set_trusted_sink_ptr(group);
    sf_set_trusted_sink_ptr(r);
    sf_set_trusted_sink_ptr(n);
    sf_set_trusted_sink_int(num_points);
    sf_set_trusted_sink_ptr(points);
    sf_set_trusted_sink_ptr(coeffs);
    sf_set_trusted_sink_ptr(ctx);
}

void SCT_set0_signature(SCT* sct, unsigned char* sig, size_t siglen) {
    sf_set_trusted_sink_ptr(sct);
    sf_set_trusted_sink_ptr(sig);
    sf_set_trusted_sink_int(siglen);
}

void* EVP_CIPHER_CTX_get_cipher_data(const EVP_CIPHER_CTX* ctx) {
    sf_set_trusted_sink_ptr(ctx);
}
void NCONF_free(CONF* conf);

int BN_is_zero(const BIGNUM* bn);

const UI_METHOD* UI_set_method(UI* ui, const UI_METHOD* method);

void ASYNC_WAIT_CTX_free(ASYNC_WAIT_CTX* ctx);

int i2d_SCRYPT_PARAMS(const SCRYPT_PARAMS* params, unsigned char** pder);

int EVP_PKEY_derive_init(EVP_PKEY_CTX* ctx);

int SSL_CTX_get_client_cert_cb(SSL_CTX* ctx, void (*cb);

const BIO_ADDR* BIO_ADDRINFO_address(const BIO_ADDRINFO* ai);

int PEM_write_bio_PKCS7(BIO* bio, const PKCS7* p7);

int OPENSSL_sk_is_sorted(const OPENSSL_STACK* st);


int EVP_CIPHER_get_key_length(const EVP_CIPHER* cipher) {
    int Res = 0;
    sf_set_must_be_not_null(cipher, "EVP_CIPHER");
    Res = cipher->key_length;
    sf_set_possible_negative(Res);
    return Res;
}

GENERAL_SUBTREE* GENERAL_SUBTREE_new() {
    GENERAL_SUBTREE* Res = NULL;
    Res = (GENERAL_SUBTREE*)sf_malloc_arg(sizeof(GENERAL_SUBTREE), "GENERAL_SUBTREE");
    sf_set_alloc_possible_null(Res);
    return Res;
}

EVP_PKEY* EVP_PKEY_CTX_get0_pkey(EVP_PKEY_CTX* ctx) {
    EVP_PKEY* Res = NULL;
    sf_set_must_be_not_null(ctx, "EVP_PKEY_CTX");
    Res = ctx->pkey;
    sf_set_possible_null(Res);
    return Res;
}

POLICYINFO* d2i_POLICYINFO(POLICYINFO** a, const unsigned char** in, long len) {
    POLICYINFO* Res = NULL;
    sf_set_must_be_not_null(a, "POLICYINFO");
    sf_set_must_be_not_null(in, "unsigned char");
    Res = *a;
    sf_set_alloc_possible_null(Res);
    return Res;
}

int DH_check_ex(const DH* dh) {
    int Res = 0;
    sf_set_must_be_not_null(dh, "DH");
    Res = dh->check_ex;
    sf_set_possible_negative(Res);
    return Res;
}

int EVP_CIPHER_get_iv_length(const EVP_CIPHER* cipher) {
    int Res = 0;
    sf_set_must_be_not_null(cipher, "EVP_CIPHER");
    Res = cipher->iv_len;
    sf_set_possible_negative(Res);
    return Res;
}

void BUF_MEM_free(BUF_MEM* a) {
    sf_set_must_be_not_null(a, "BUF_MEM");
    sf_delete(a->data, PAGES_MEMORY_CATEGORY);
    sf_lib_arg_type(a, "BUF_MEM");
    a->data = NULL;
}

int (DH*)* DH_meth_get_finish(const DH_METHOD* dhm) {
    int (DH*)* Res = NULL;
    sf_set_must_be_not_null(dhm, "DH_METHOD");
    Res = dhm->finish;
    sf_set_possible_null(Res);
    return Res;
}

X509_REQ* d2i_X509_REQ_fp(FILE* fp, X509_REQ** req) {
    X509_REQ* Res = NULL;
    sf_set_must_be_not_null(fp, "FILE");
    sf_set_must_be_not_null(req, "X509_REQ");
    Res = *req;
    sf_set_possible_null(Res);
    return Res;
}

const EVP_CIPHER* EVP_sm4_cbc() {
    const EVP_CIPHER* Res = NULL;
    Res = EVP_enc_null();
    sf_set_possible_null(Res);
    return Res;
}

void SSL_set_async_callback_arg(SSL *ssl, void *arg) {
    int res = 0;
    sf_set_tainted(arg);
    sf_set_trusted_sink_ptr(arg);
    sf_set_possible_null(arg);
    sf_set_possible_null(res);
}

void DH_set_ex_data(DH *dh, int idx, void *arg) {
    int res = 0;
    sf_set_tainted(arg);
    sf_set_trusted_sink_ptr(arg);
    sf_set_possible_null(arg);
    sf_set_possible_null(res);
}

void EVP_MD_CTX_set_update_fn(EVP_MD_CTX *ctx, int (*update_fn)(EVP_MD_CTX*, const void*, size_t)) {
    sf_set_tainted(update_fn);
    sf_set_trusted_sink_ptr(update_fn);
}

void SCT_get_version(const SCT *sct) {
    sct_version_t res;
    sf_set_tainted(sct);
    sf_set_trusted_sink_ptr(sct);
}

void EC_GROUP_get_trinomial_basis(const EC_GROUP *group, unsigned int *res) {
    int ret;
    sf_set_tainted(group);
    sf_set_trusted_sink_ptr(group);
    sf_set_possible_null(res);
    sf_set_possible_null(ret);
}

const EVP_CIPHER* EVP_rc2_cbc() {
    const EVP_CIPHER* Res = NULL;
    Res = EVP_rc2_cbc();
    sf_set_possible_null(Res);
    return Res;
}

void SSL_set_security_level(SSL* ssl, int level) {
    sf_set_must_be_not_null(ssl, SECURITY_LEVEL_OF_NULL);
    SSL_set_security_level(ssl, level);
}

int EVP_MD_get_block_size(const EVP_MD* md) {
    int Res = 0;
    sf_set_possible_null(md);
    Res = EVP_MD_get_block_size(md);
    sf_set_possible_negative(Res);
    return Res;
}

const CTLOG_STORE* CT_POLICY_EVAL_CTX_get0_log_store(const CT_POLICY_EVAL_CTX* ctx) {
    const CTLOG_STORE* Res = NULL;
    sf_set_must_be_not_null(ctx, CT_POLICY_EVAL_CTX_OF_NULL);
    Res = CT_POLICY_EVAL_CTX_get0_log_store(ctx);
    sf_set_possible_null(Res);
    return Res;
}

int OSSL_PARAM_get_time_t(const OSSL_PARAM* param, time_t* t) {
    int Res = 0;
    sf_set_must_be_not_null(param, OSSL_PARAM_OF_NULL);
    sf_set_must_be_not_null(t, TIME_T_OF_NULL);
    Res = OSSL_PARAM_get_time_t(param, t);
    sf_set_errno_if(Res == 0);
    return Res;
}

DSA_SIG* DSA_do_sign(const unsigned char* dgst, int dlen, DSA* dsa) {
    DSA_SIG* Res = NULL;
    sf_set_trusted_sink_int(dlen);
    sf_malloc_arg(Res, sizeof(DSA_SIG));
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    return Res;
}

EVP_PKEY* PEM_read_PUBKEY_ex(FILE* fp, EVP_PKEY** x, pem_password_cb* cb, void* u, OSSL_LIB_CTX* libctx, const char* propq) {
    EVP_PKEY* Res = NULL;
    sf_set_trusted_sink_ptr(fp);
    sf_set_trusted_sink_ptr(cb);
    sf_set_trusted_sink_ptr(u);
    sf_set_trusted_sink_ptr(libctx);
    sf_set_trusted_sink_ptr(propq);
    sf_malloc_arg(Res, sizeof(EVP_PKEY));
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    return Res;
}

void TLS_FEATURE_free(TLS_FEATURE* feat) {
    sf_set_must_be_not_null(feat, FREE_OF_NULL);
    sf_delete(feat, MALLOC_CATEGORY);
    sf_lib_arg_type(feat, "MallocCategory");
}

const EVP_CIPHER* EVP_camellia_192_ecb() {
    const EVP_CIPHER* Res = NULL;
    sf_set_trusted_sink_ptr(Res);
    sf_overwrite(Res);
    return Res;
}

const EVP_CIPHER* EVP_des_ede_ofb() {
    const EVP_CIPHER* Res = NULL;
    sf_set_trusted_sink_ptr(Res);
    sf_overwrite(Res);
    return Res;
}

const BIO_METHOD* BIO_f_ssl() {
    const BIO_METHOD* Res = NULL;
    Res = BIO_f_ssl();
    sf_lib_arg_type(Res, "BIO_METHOD");
    return Res;
}

int EVP_DecryptFinal_ex(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl) {
    int Res = 0;
    Res = EVP_DecryptFinal_ex(ctx, out, outl);
    sf_set_errno_if(Res <= 0);
    sf_buf_size_limit(out, *outl);
    sf_overwrite(out);
    return Res;
}

size_t SCT_get0_log_id(const SCT* sct, unsigned char** id) {
    size_t Res = 0;
    Res = SCT_get0_log_id(sct, id);
    sf_buf_size_limit(id, Res);
    sf_overwrite(id);
    return Res;
}

int OSSL_PARAM_allocate_from_text(OSSL_PARAM* params, const OSSL_PARAM* defs, const char* key, const char* value, size_t value_n, int* found) {
    int Res = 0;
    Res = OSSL_PARAM_allocate_from_text(params, defs, key, value, value_n, found);
    sf_set_alloc_possible_null(params);
    sf_set_alloc_possible_null(defs);
    sf_set_possible_null(found);
    return Res;
}

int RSA_sign(int type, const unsigned char* m, unsigned int m_length, unsigned char* sigret, unsigned int* siglen, RSA* rsa) {
    int Res = 0;
    Res = RSA_sign(type, m, m_length, sigret, siglen, rsa);
    sf_set_errno_if(Res <= 0);
    sf_buf_size_limit(sigret, *siglen);
    sf_overwrite(sigret);
    return Res;
}

void OPENSSL_thread_stop() {
    sf_terminate_path();
}

const SSL_METHOD* DTLS_method() {
    const SSL_METHOD *Res = NULL;
    sf_set_possible_null(Res);
    return Res;
}

int BN_hex2bn(BIGNUM** a, const char* str) {
    int Res = 0;
    sf_set_errno_if(Res <= 0, "BN_hex2bn");
    return Res;
}

X509_NAME* X509_REQ_get_subject_name(const X509_REQ* req) {
    X509_NAME *Res = NULL;
    sf_set_possible_null(Res);
    return Res;
}

char* SSL_get_shared_ciphers(const SSL* s, char* buf, int len) {
    char *Res = NULL;
    sf_set_possible_null(Res);
    return Res;
}
int OSSL_PARAM_get_ulong(const OSSL_PARAM*, unsigned long int*);

void X509_set_proxy_flag(X509*);

void SSL_set0_security_ex_data(SSL*, void*);

void X509_STORE_CTX_set0_param(X509_STORE_CTX*, X509_VERIFY_PARAM*);

int X509_verify(X509*, EVP_PKEY*);

void SSL_set_verify(SSL* ssl, int mode, SSL_verify_cb callback);

int ECDSA_sign_ex(int type, const unsigned char* dgst, int dlen, unsigned char* sig, unsigned int* siglen, const BIGNUM* kinv, const BIGNUM* r, EC_KEY* eckey);

int SSL_CTX_enable_ct(SSL_CTX* ctx, int enabled);

int (BIO*, const char*, size_t, size_t*);

int EVP_set_default_properties(OSSL_LIB_CTX* ctx, const char* propq);


EC_GROUP* PEM_read_ECPKParameters(FILE* fp, EC_GROUP** x, pem_password_cb* cb, void* u) {
    EC_GROUP* Res = NULL;
    sf_set_trusted_sink_ptr(fp);
    sf_set_trusted_sink_ptr(cb);
    sf_set_trusted_sink_ptr(u);
    sf_set_tainted(fp);
    sf_password_use(cb);
    sf_set_must_not_be_null(x);
    sf_set_errno_if(Res == NULL);
    return Res;
}

int BN_generate_prime_ex2(BIGNUM* ret, int bits, int safe, const BIGNUM* add, const BIGNUM* rem, BN_GENCB* cb, BN_CTX* ctx) {
    int Res = 0;
    sf_set_trusted_sink_ptr(cb);
    sf_set_trusted_sink_ptr(ctx);
    sf_set_tainted(ret);
    sf_set_tainted(add);
    sf_set_tainted(rem);
    sf_password_use(cb);
    sf_set_errno_if(Res == 0);
    return Res;
}

ACCESS_DESCRIPTION* d2i_ACCESS_DESCRIPTION(ACCESS_DESCRIPTION** a, const unsigned char** in, long len) {
    ACCESS_DESCRIPTION* Res = NULL;
    sf_set_trusted_sink_ptr(a);
    sf_set_trusted_sink_ptr(in);
    sf_set_tainted(in);
    sf_set_errno_if(Res == NULL);
    return Res;
}

int CRYPTO_free_ex_index(int class, int idx) {
    int Res = 0;
    sf_set_errno_if(Res == 0);
    return Res;
}

const EC_METHOD* EC_GFp_nistp256_method() {
    const EC_METHOD* Res = NULL;
    return Res;
}

int EVP_PKEY_CTX_get_dh_kdf_outlen(EVP_PKEY_CTX *ctx, int *outlen) {
    int Res = 0;
    sf_set_must_be_not_null(ctx, "EVP_PKEY_CTX");
    sf_set_must_be_not_null(outlen, "outlen");
    sf_set_errno_if(Res <= 0, "EVP_PKEY_CTX_get_dh_kdf_outlen");
    sf_set_possible_null(Res);
    return Res;
}

void SSL_CTX_set_client_CA_list(SSL_CTX *ctx, stack_st_X509_NAME *list) {
    sf_set_must_be_not_null(ctx, "SSL_CTX");
    sf_set_must_be_not_null(list, "stack_st_X509_NAME");
    // No return value to check
}

int i2d_RSAPublicKey_fp(FILE *fp, const RSA *rsa) {
    int Res = 0;
    sf_set_must_be_not_null(fp, "FILE");
    sf_set_must_be_not_null(rsa, "RSA");
    sf_set_errno_if(Res <= 0, "i2d_RSAPublicKey_fp");
    sf_set_possible_null(Res);
    return Res;
}

const char* ERR_func_error_string(unsigned long e) {
    const char *Res = NULL;
    sf_set_possible_null(Res);
    return Res;
}

int BN_generate_prime_ex(BIGNUM *ret, int bits, int safe, const BIGNUM *add, const BIGNUM *rem, BN_GENCB *cb) {
    int Res = 0;
    sf_set_must_be_not_null(ret, "BIGNUM");
    sf_set_errno_if(Res <= 0, "BN_generate_prime_ex");
    sf_set_possible_null(Res);
    return Res;
}

EC_POINT* EC_POINT_new(const EC_GROUP* group)
{
    EC_POINT* Res = NULL;
    sf_set_trusted_sink_int(group);
    Res = EC_POINT_new(group);
    sf_overwrite(Res);
    return Res;
}

ASN1_OCTET_STRING* X509_REQ_get0_distinguishing_id(X509_REQ* req)
{
    ASN1_OCTET_STRING* Res = NULL;
    Res = X509_REQ_get0_distinguishing_id(req);
    sf_overwrite(Res);
    return Res;
}

int BN_gcd(BIGNUM* r, const BIGNUM* a, const BIGNUM* b, BN_CTX* ctx)
{
    int Res = 0;
    Res = BN_gcd(r, a, b, ctx);
    sf_overwrite(&Res);
    return Res;
}

ASN1_STRING* DISPLAYTEXT_new()
{
    ASN1_STRING* Res = NULL;
    Res = DISPLAYTEXT_new();
    sf_overwrite(Res);
    return Res;
}

int BIO_ADDR_family(const BIO_ADDR* addr)
{
    int Res = 0;
    Res = BIO_ADDR_family(addr);
    sf_overwrite(&Res);
    return Res;
}

void EVP_PKEY_meth_set_digest_custom(EVP_PKEY_METHOD *pkey_meth, int (*digest_custom)(EVP_PKEY_CTX*, EVP_MD_CTX*)) {
    sf_set_trusted_sink_ptr(pkey_meth);
    sf_set_trusted_sink_ptr(digest_custom);
    // function body
}

OCSP_RESPID* OCSP_RESPID_new() {
    OCSP_RESPID *Res = NULL;
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    // function body
    return Res;
}

const EVP_CIPHER* EVP_bf_cfb64() {
    const EVP_CIPHER *Res = NULL;
    // function body
    return Res;
}

int ECPKParameters_print_fp(FILE *fp, const EC_GROUP *group, int off) {
    int Res = 0;
    sf_set_must_not_be_null(fp);
    sf_set_must_not_be_null(group);
    // function body
    return Res;
}

void ERR_clear_error() {
    // function body
}
void ASN1_OBJECT_free(ASN1_OBJECT* obj);

int EVP_RAND_CTX_set_params(EVP_RAND_CTX* ctx, const OSSL_PARAM params[]);

int X509_ALGOR_set0(X509_ALGOR* alg, ASN1_OBJECT* obj, int nid, void* value);

EVP_PKEY* PEM_read_bio_Parameters_ex(BIO* bio, EVP_PKEY** pkey, OSSL_LIB_CTX* libctx, const char* propq);

int EC_KEY_decoded_from_explicit_params(const EC_KEY* key);


ADMISSIONS* ADMISSIONS_new() {
    ADMISSIONS* Res = NULL;
    Res = (ADMISSIONS*)sf_malloc_arg(sizeof(ADMISSIONS));
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    return Res;
}

EC_KEY* d2i_EC_PUBKEY_bio(BIO* bp, EC_KEY** a) {
    EC_KEY* Res = NULL;
    Res = (EC_KEY*)sf_malloc_arg(sizeof(EC_KEY));
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    return Res;
}

int RSA_meth_set_flags(RSA_METHOD* meth, int flags) {
    int Res = 0;
    sf_set_errno_if(meth == NULL, EINVAL);
    Res = flags;
    sf_overwrite(&Res);
    return Res;
}

ASIdOrRange* d2i_ASIdOrRange(ASIdOrRange** a, const unsigned char** in, long len) {
    ASIdOrRange* Res = NULL;
    Res = (ASIdOrRange*)sf_malloc_arg(sizeof(ASIdOrRange));
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_overwrite(Res);
    return Res;
}

int OSSL_PARAM_set_octet_ptr(OSSL_PARAM* p, const void* ptr, size_t len) {
    int Res = 0;
    sf_set_errno_if(p == NULL || ptr == NULL, EINVAL);
    Res = len;
    sf_overwrite(&Res);
    return Res;
}
int UI_UTIL_read_pw_string(char *buf, int length, const char *prompt, int verify);

int EVP_PKEY_get_group_name(const EVP_PKEY *pkey, char *buf, size_t len, size_t *outlen);

const BIGNUM* BN_get0_nist_prime_224();

ASRange* ASRange_new();

EVP_SIGNATURE* EVP_SIGNATURE_fetch(OSSL_LIB_CTX *ctx, const char *algorithm, const char *properties);


int EVP_DigestVerifyInit_ex(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const char *name, OSSL_LIB_CTX *libctx, const char *propq, EVP_PKEY *pkey, const OSSL_PARAM params[]) {
    int res = 0;
    sf_set_must_be_not_null(ctx, "EVP_DigestVerifyInit_ex");
    sf_set_must_be_not_null(pkey, "EVP_DigestVerifyInit_ex");
    sf_set_must_be_not_null(params, "EVP_DigestVerifyInit_ex");
    sf_set_tainted(name, "EVP_DigestVerifyInit_ex");
    sf_set_tainted(propq, "EVP_DigestVerifyInit_ex");
    sf_set_possible_null(pctx, "EVP_DigestVerifyInit_ex");
    sf_set_possible_null(ctx, "EVP_DigestVerifyInit_ex");
    res = EVP_DigestVerifyInit_ex(ctx, pctx, name, libctx, propq, pkey, params);
    sf_set_errno_if(res <= 0, "EVP_DigestVerifyInit_ex");
    return res;
}

const EVP_CIPHER* EVP_aes_128_cfb1() {
    const EVP_CIPHER *res = NULL;
    res = EVP_aes_128_cfb1();
    sf_set_possible_null(res, "EVP_aes_128_cfb1");
    return res;
}

int X509_STORE_CTX_print_verify_cb(int ok, X509_STORE_CTX *ctx) {
    int res = 0;
    sf_set_must_be_not_null(ctx, "X509_STORE_CTX_print_verify_cb");
    res = X509_STORE_CTX_print_verify_cb(ok, ctx);
    sf_set_errno_if(res <= 0, "X509_STORE_CTX_print_verify_cb");
    return res;
}

const GENERAL_NAMES* X509_get0_authority_issuer(X509 *x) {
    const GENERAL_NAMES *res = NULL;
    sf_set_must_be_not_null(x, "X509_get0_authority_issuer");
    res = X509_get0_authority_issuer(x);
    sf_set_possible_null(res, "X509_get0_authority_issuer");
    return res;
}

int i2d_OCSP_RESPID(const OCSP_RESPID *rid, unsigned char **pp) {
    int res = 0;
    sf_set_must_be_not_null(rid, "i2d_OCSP_RESPID");
    sf_set_must_be_not_null(pp, "i2d_OCSP_RESPID");
    res = i2d_OCSP_RESPID(rid, pp);
    sf_set_errno_if(res <= 0, "i2d_OCSP_RESPID");
    return res;
}
int SSL_SESSION_has_ticket(const SSL_SESSION* s);

ASIdentifierChoice* ASIdentifierChoice_new();

int DSA_meth_set0_app_data(DSA_METHOD* dsa, void* app_data);

int EVP_DigestSignUpdate(EVP_MD_CTX* ctx, const void* d, size_t cnt);

ASN1_OBJECT* X509_NAME_ENTRY_get_object(const X509_NAME_ENTRY* ne);


size_t BIO_ctrl_wpending(BIO *b) {
    size_t Res = 0;
    sf_set_trusted_sink_int(Res);
    sf_set_possible_null(Res);
    return Res;
}

DH* DH_get_2048_256() {
    DH* Res = NULL;
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_possible_null(Res);
    return Res;
}

void OPENSSL_fork_child() {
    // No return value, no variable to mark
}

const OSSL_PROVIDER* EVP_MAC_get0_provider(const EVP_MAC *mac) {
    const OSSL_PROVIDER* Res = NULL;
    sf_set_possible_null(Res);
    return Res;
}

void CTLOG_free(CTLOG *log) {
    sf_delete(log, PAGES_MEMORY_CATEGORY);
    sf_lib_arg_type(log, "CTLOG");
}
int ENGINE_ctrl(ENGINE*, int, long, void*, void ();

const BIGNUM* RSA_get0_d(const RSA*);

int X509_NAME_cmp(const X509_NAME*, const X509_NAME*);

int SSL_bytes_to_cipher_list(SSL*, const unsigned char*, size_t, int, stack_st_SSL_CIPHER**, stack_st_SSL_CIPHER**);

OSSL_PARAM* OSSL_PARAM_locate(OSSL_PARAM*, const char*);


const DSA_METHOD* ENGINE_get_DSA(const ENGINE* e) {
    const DSA_METHOD* Res = NULL;
    sf_set_trusted_sink_ptr(e);
    sf_set_alloc_possible_null(Res);
    return Res;
}

SCT* o2i_SCT(SCT** a, const unsigned char** pp, size_t len) {
    SCT* Res = NULL;
    sf_set_trusted_sink_int(len);
    sf_set_alloc_possible_null(Res);
    return Res;
}

int EC_GROUP_copy(EC_GROUP* dest, const EC_GROUP* src) {
    int Res = 0;
    sf_set_must_be_not_null(dest);
    sf_set_must_be_not_null(src);
    sf_set_errno_if(Res == 0);
    return Res;
}

OSSL_HANDSHAKE_STATE SSL_get_state(const SSL* ssl) {
    OSSL_HANDSHAKE_STATE Res = 0;
    sf_set_must_be_not_null(ssl);
    return Res;
}

int BN_lshift1(BIGNUM* r, const BIGNUM* a) {
    int Res = 0;
    sf_set_must_be_not_null(r);
    sf_set_must_be_not_null(a);
    sf_set_errno_if(Res == 0);
    return Res;
}

int EVP_CIPHER_meth_get_get_asn1_params(const EVP_CIPHER* cipher) {
    int Res = 0;
    sf_set_must_be_not_null(cipher, "EVP_CIPHER");
    sf_set_tainted(cipher);
    Res = cipher->get_asn1_parameters;
    sf_set_possible_null(Res);
    return Res;
}

int EVP_PKEY_CTX_ctrl(EVP_PKEY_CTX* ctx, int keytype, int optype, int cmd, int p1, void* p2) {
    int Res = 0;
    sf_set_must_be_not_null(ctx, "EVP_PKEY_CTX");
    sf_set_tainted(ctx);
    Res = ctx->ctrl(ctx, keytype, optype, cmd, p1, p2);
    sf_set_errno_if(Res <= 0);
    return Res;
}

SCT* SCT_new() {
    SCT* Res = NULL;
    Res = OPENSSL_zalloc(sizeof(SCT));
    sf_new(Res, SCT_MEMORY_CATEGORY);
    sf_set_possible_null(Res);
    return Res;
}

const OSSL_PARAM* EVP_MD_gettable_ctx_params(const EVP_MD* md) {
    const OSSL_PARAM* Res = NULL;
    sf_set_must_be_not_null(md, "EVP_MD");
    sf_set_tainted(md);
    Res = md->gettable_ctx_params;
    sf_set_possible_null(Res);
    return Res;
}

ENGINE* ENGINE_new() {
    ENGINE* Res = NULL;
    Res = OPENSSL_zalloc(sizeof(ENGINE));
    sf_new(Res, ENGINE_MEMORY_CATEGORY);
    sf_set_possible_null(Res);
    return Res;
}
int EVP_CIPHER_is_a(const EVP_CIPHER* cipher, const char* name);

int BN_rand_range(BIGNUM* r, const BIGNUM* range);

const BIO_METHOD* BIO_s_secmem();

int SSL_CTX_use_cert_and_key(SSL_CTX* ctx, X509* x, EVP_PKEY* pkey, stack_st_X509* chain, int override);

void PROFESSION_INFO_set0_professionOIDs(PROFESSION_INFO* info, stack_st_ASN1_OBJECT* oids);


int EVP_PKEY_up_ref(EVP_PKEY* pkey) {
    int res = 0;
    sf_set_must_be_not_null(pkey, EVP_PKEY_NULL);
    sf_set_tainted(pkey);
    res = pkey->references++;
    sf_set_possible_negative(res);
    sf_set_possible_null(res);
    return res;
}

void EVP_PKEY_meth_set_keygen(EVP_PKEY_METHOD* pmeth, int (*keygen)(EVP_PKEY_CTX*), int (*keygen_init)(EVP_PKEY_CTX*, EVP_PKEY*)) {
    sf_set_must_be_not_null(pmeth, EVP_PKEY_METHOD_NULL);
    sf_set_must_be_not_null(keygen, KEYGEN_NULL);
    sf_set_must_be_not_null(keygen_init, KEYGEN_INIT_NULL);
    pmeth->keygen = keygen;
    pmeth->keygen_init = keygen_init;
}

void ENGINE_unregister_ciphers(ENGINE* e) {
    sf_set_must_be_not_null(e, ENGINE_NULL);
    sf_set_tainted(e);
    e->ciphers = NULL;
}

int SSL_CTX_add_client_CA(SSL_CTX* ctx, X509* x) {
    int res = 0;
    sf_set_must_be_not_null(ctx, SSL_CTX_NULL);
    sf_set_must_be_not_null(x, X509_NULL);
    sf_set_tainted(x);
    res = sk_X509_NAME_push(ctx->client_CA, X509_get_subject_name(x));
    sf_set_possible_negative(res);
    return res;
}

int i2d_X509_CRL(const X509_CRL* crl, unsigned char** pp) {
    int res = 0;
    sf_set_must_be_not_null(crl, X509_CRL_NULL);
    sf_set_must_be_not_null(pp, PP_NULL);
    sf_set_tainted(crl);
    res = i2d_X509_CRL_bio(crl, *pp);
    sf_set_possible_negative(res);
    return res;
}

void SSL_set_post_handshake_auth(SSL* ssl, int val)
{
    sf_set_tainted(val);
    sf_set_must_be_not_null(ssl, SSL_SET_POST_HANDSHAKE_AUTH_OF_NULL);
    SSL_set_post_handshake_auth(ssl, val);
}

int i2d_ECPrivateKey(const EC_KEY* key, unsigned char** pp)
{
    int res = 0;
    sf_set_must_be_not_null(key, I2D_ECPRIVATEKEY_OF_NULL);
    sf_set_must_be_not_null(pp, I2D_ECPRIVATEKEY_TO_NULL);
    res = i2d_ECPrivateKey(key, pp);
    sf_set_errno_if(res <= 0, I2D_ECPRIVATEKEY_ERROR);
    return res;
}

int X509_PUBKEY_set0_param(X509_PUBKEY* key, ASN1_OBJECT* aobj, int nid, void* str, unsigned char* keybuf, int keylen)
{
    int res = 0;
    sf_set_must_be_not_null(key, X509_PUBKEY_SET0_PARAM_OF_NULL);
    sf_set_must_be_not_null(aobj, X509_PUBKEY_SET0_PARAM_AOBJ_OF_NULL);
    sf_set_must_be_not_null(str, X509_PUBKEY_SET0_PARAM_STR_OF_NULL);
    sf_set_must_be_not_null(keybuf, X509_PUBKEY_SET0_PARAM_KEYBUF_OF_NULL);
    res = X509_PUBKEY_set0_param(key, aobj, nid, str, keybuf, keylen);
    sf_set_errno_if(res <= 0, X509_PUBKEY_SET0_PARAM_ERROR);
    return res;
}

int X509v3_get_ext_by_critical(const stack_st_X509_EXTENSION* exts, int crit, int idx)
{
    int res = 0;
    sf_set_must_be_not_null(exts, X509V3_GET_EXT_BY_CRITICAL_OF_NULL);
    res = X509v3_get_ext_by_critical(exts, crit, idx);
    sf_set_errno_if(res < 0, X509V3_GET_EXT_BY_CRITICAL_ERROR);
    return res;
}

int SHA1_Init(SHA_CTX* ctx)
{
    int res = 0;
    sf_set_must_be_not_null(ctx, SHA1_INIT_OF_NULL);
    res = SHA1_Init(ctx);
    sf_set_errno_if(res != 1, SHA1_INIT_ERROR);
    return res;
}

size_t SSL_client_hello_get0_random(SSL* s, const unsigned char** out_random) {
    size_t Res = 0;
    sf_set_must_be_not_null(s, SSL_NULL);
    sf_set_must_be_not_null(out_random, OUT_RANDOM_NULL);
    sf_set_tainted(s, SSL_TRAFFIC);
    sf_set_trusted_sink_ptr(out_random, SSL_RANDOM_SINK);
    Res = s->method->ssl_get_client_random(s, out_random);
    sf_set_errno_if(Res == 0, ERRNO_FAILURE);
    sf_set_possible_null(Res, SSL_RANDOM_NULL);
    return Res;
}

int X509_issuer_and_serial_cmp(const X509* a, const X509* b) {
    int Res = 0;
    sf_set_must_be_not_null(a, X509_NULL);
    sf_set_must_be_not_null(b, X509_NULL);
    sf_set_tainted(a, X509_ISSUER);
    sf_set_tainted(b, X509_ISSUER);
    Res = a->cert_info->issuer->cmp(a->cert_info->issuer, b->cert_info->issuer);
    if (Res == 0) {
        Res = ASN1_INTEGER_cmp(a->cert_info->serialNumber, b->cert_info->serialNumber);
    }
    sf_set_errno_if(Res == 0, ERRNO_FAILURE);
    sf_set_possible_negative(Res, X509_CMP_NEGATIVE);
    return Res;
}
