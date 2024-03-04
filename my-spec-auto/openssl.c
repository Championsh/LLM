#include "specfunc.h"

#define STACK_OF(TYPE)TYPE

typedef struct CMS_RecipientInfo CMS_RecipientInfo;
typedef struct CMS_ContentInfo CMS_ContentInfo;
typedef struct ASN1_GENERALIZEDTIME ASN1_GENERALIZEDTIME;
typedef struct ASN1_OBJECT ASN1_OBJECT;
typedef struct ASN1_TYPE ASN1_TYPE;
typedef struct EVP_PKEY EVP_PKEY;
typedef struct EVP_PKEY_CTX EVP_PKEY_CTX;
typedef struct ENGINE ENGINE;
typedef struct CTLOG CTLOG;
typedef struct BIGNUM BIGNUM;
typedef struct DH DH;
typedef struct EVP_CIPHER EVP_CIPHER;
typedef struct EVP_CIPHER_CTX EVP_CIPHER_CTX;
typedef struct EVP_MD EVP_MD;
typedef struct PKCS12 PKCS12;
typedef struct BF_KEY BF_KEY;
typedef struct BIO BIO;
typedef struct X509 X509;
 

CMS_RecipientInfo *CMS_add0_recipient_key(CMS_ContentInfo *cms, int nid, unsigned char *key, size_t keylen, unsigned char *id, size_t idlen, ASN1_GENERALIZEDTIME *date, ASN1_OBJECT *otherTypeId, ASN1_TYPE *otherType);

EVP_PKEY *EVP_PKEY_new_mac_key(int type, ENGINE *e, const unsigned char *key, int keylen);

EVP_PKEY *EVP_PKEY_new_raw_private_key(int type, ENGINE *e, const unsigned char *key, size_t keylen);

EVP_PKEY *EVP_PKEY_new_raw_public_key(int type, ENGINE *e, const unsigned char *key, size_t keylen);

int CMS_RecipientInfo_set0_key(CMS_RecipientInfo *ri, unsigned char *key, size_t keylen);

int CTLOG_new_from_base64(CTLOG ** ct_log, const char *pkey_base64, const char *name);

int DH_compute_key(unsigned char *key, BIGNUM *pub_key, DH *dh);

int compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh);

int EVP_BytesToKey(const EVP_CIPHER *type, const EVP_MD *md, const unsigned char *salt, const unsigned char *data, int datal, int count, unsigned char *key, unsigned char *iv);

int EVP_CIPHER_CTX_rand_key(EVP_CIPHER_CTX *ctx, unsigned char *key);

int EVP_CipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, const unsigned char *key, const unsigned char *iv, int enc);

int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv, int enc);

int EVP_DecryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, const unsigned char *key, const unsigned char *iv);

int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv);

int EVP_EncryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, const unsigned char *key, const unsigned char *iv);

int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv);

int EVP_PKEY_CTX_set1_hkdf_key(EVP_PKEY_CTX *pctx, unsigned char *key, int keylen);

int EVP_PKEY_CTX_set_mac_key(EVP_PKEY_CTX *ctx, unsigned char *key, int len);

int EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);

void BIO_set_cipher(BIO *b, const EVP_CIPHER *cipher, unsigned char *key, unsigned char *iv, int enc);

EVP_PKEY *EVP_PKEY_new_CMAC_key(ENGINE *e, const unsigned char *priv, size_t len, const EVP_CIPHER *cipher);

int EVP_OpenInit(EVP_CIPHER_CTX *ctx, EVP_CIPHER *type, unsigned char *ek, int ekl, unsigned char *iv, EVP_PKEY *priv);

int EVP_PKEY_get_raw_private_key(const EVP_PKEY *pkey, unsigned char *priv, size_t *len);

int EVP_SealInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, unsigned char **ek, int *ekl, unsigned char *iv, EVP_PKEY **pubk, int npubk);

void BF_cbc_encrypt(const unsigned char *in, unsigned char *out, long length, BF_KEY *schedule, unsigned char *ivec, int enc);

void BF_cfb64_encrypt(const unsigned char *in, unsigned char *out, long length, BF_KEY *schedule, unsigned char *ivec, int *num, int enc);

void BF_ofb64_encrypt(const unsigned char *in, unsigned char *out, long length, BF_KEY *schedule, unsigned char *ivec, int *num);

int get_priv_key(const EVP_PKEY *pk, unsigned char *priv, size_t *len);

int set_priv_key(EVP_PKEY *pk, const unsigned char *priv, size_t len);

char *DES_crypt(const char *buf, const char *salt);

char *DES_fcrypt(const char *buf, const char *salt, char *ret);

int EVP_PKEY_CTX_set1_hkdf_salt(EVP_PKEY_CTX *pctx, unsigned char *salt, int saltlen);

int PKCS5_PBKDF2_HMAC(const char *pass, int passlen, const unsigned char *salt, int saltlen, int iter, const EVP_MD *digest, int keylen, unsigned char *out);

int PKCS5_PBKDF2_HMAC_SHA1(const char *pass, int passlen, const unsigned char *salt, int saltlen, int iter, int keylen, unsigned char *out);

int PKCS12_newpass(PKCS12 *p12, const char *oldpass, const char *newpass);

int PKCS12_parse(PKCS12 *p12, const char *pass, EVP_PKEY **pkey, X509 **cert, STACK_OF(X509)**ca);

PKCS12 *PKCS12_create(const char *pass, const char *name, EVP_PKEY *pkey, X509 *cert, STACK_OF(X509)*ca, int nid_key, int nid_cert, int iter, int mac_iter, int keytype);

int EVP_PKEY_get_raw_public_key(const EVP_PKEY *pkey, unsigned char *pub, size_t *len);

int get_pub_key(const EVP_PKEY *pk, unsigned char *pub, size_t *len);

int set_pub_key(EVP_PKEY *pk, const unsigned char *pub, size_t len);

 
