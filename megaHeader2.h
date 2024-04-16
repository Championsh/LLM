#include "specfunc.h"
#include <stdint.h>

#define TSAN_QUALIFIER volatile
#define DWORD int
#define LONG long

// Structure Typedefs
typedef struct {
  int   is_initialized;  
  int   init_executed;   
} pthread_once_t;

typedef struct aes_key_st aes_key_st;

typedef struct asn1_string_st asn1_string_st;

typedef struct asn1_string_table_st asn1_string_table_st;

typedef struct asn1_type_st asn1_type_st;

typedef struct ASN1_TEMPLATE_st ASN1_TEMPLATE_st;

typedef struct ASN1_ADB_st ASN1_ADB_st;

typedef struct ASN1_ADB_TABLE_st ASN1_ADB_TABLE_st;

typedef struct ASN1_ITEM_st ASN1_ITEM_st;

typedef struct ASN1_TLC_st ASN1_TLC_st;

typedef struct bio_dgram_sctp_sndinfo bio_dgram_sctp_sndinfo;

typedef struct bio_dgram_sctp_rcvinfo bio_dgram_sctp_rcvinfo;

typedef struct bio_dgram_sctp_prinfo bio_dgram_sctp_prinfo;

typedef struct buf_mem_st buf_mem_st;

typedef struct camellia_key_st camellia_key_st;

typedef struct conf_st conf_st;

typedef struct conf_method_st conf_method_st;

typedef struct conf_method_st conf_method_st;

typedef struct conf_st conf_st;

typedef struct ossl_dispatch_st ossl_dispatch_st;

typedef struct ossl_item_st ossl_item_st;

typedef struct ossl_algorithm_st ossl_algorithm_st;

struct ossl_param_st {
    const char *key;
    unsigned int data_type;
    void *data;
    size_t data_size;
    size_t return_size;
};

typedef struct crypto_ex_data_st crypto_ex_data_st;

typedef struct err_state_st err_state_st;

typedef struct rsa_st rsa_st;

typedef struct dsa_st dsa_st;

typedef struct dh_st dh_st;

typedef struct ec_key_st ec_key_st;

typedef struct rand_meth_st rand_meth_st;

typedef struct rsa_pss_params_st rsa_pss_params_st;

typedef struct tls_session_ticket_ext_st tls_session_ticket_ext_st;

typedef struct TS_resp_ctx TS_resp_ctx;

typedef struct X509_algor_st X509_algor_st;

typedef struct v3_ext_method v3_ext_method;

typedef struct v3_ext_ctx v3_ext_ctx;

typedef struct v3_ext_method v3_ext_method;

typedef struct v3_ext_ctx v3_ext_ctx;

typedef struct DIST_POINT_st DIST_POINT_st;

typedef struct AUTHORITY_KEYID_st AUTHORITY_KEYID_st;

typedef struct NAME_CONSTRAINTS_st NAME_CONSTRAINTS_st;

typedef struct ISSUING_DIST_POINT_st ISSUING_DIST_POINT_st;

// Defines
#define OPENSSL_AES_H 

#define HEADER_AES_H 

#define AES_BLOCK_SIZE 16

#define AES_ENCRYPT 1

#define AES_DECRYPT 0

#define AES_MAXNR 14

#define OPENSSL_ASN1_H 

#define HEADER_ASN1_H 

#define OPENSSL_EXTERN OPENSSL_EXPORT

#define V_ASN1_UNIVERSAL 0x00

#define V_ASN1_APPLICATION 0x40

#define V_ASN1_CONTEXT_SPECIFIC 0x80

#define V_ASN1_PRIVATE 0xc0

#define V_ASN1_CONSTRUCTED 0x20

#define V_ASN1_PRIMITIVE_TAG 0x1f

#define V_ASN1_PRIMATIVE_TAG V_ASN1_PRIMITIVE_TAG

#define V_ASN1_APP_CHOOSE -2

#define V_ASN1_OTHER -3

#define V_ASN1_ANY -4

#define V_ASN1_UNDEF -1

#define V_ASN1_EOC 0

#define V_ASN1_BOOLEAN 1

#define V_ASN1_INTEGER 2

#define V_ASN1_BIT_STRING 3

#define V_ASN1_OCTET_STRING 4

#define V_ASN1_NULL 5

#define V_ASN1_OBJECT 6

#define V_ASN1_OBJECT_DESCRIPTOR 7

#define V_ASN1_EXTERNAL 8

#define V_ASN1_REAL 9

#define V_ASN1_ENUMERATED 10

#define V_ASN1_UTF8STRING 12

#define V_ASN1_SEQUENCE 16

#define V_ASN1_SET 17

#define V_ASN1_NUMERICSTRING 18

#define V_ASN1_PRINTABLESTRING 19

#define V_ASN1_T61STRING 20

#define V_ASN1_TELETEXSTRING 20

#define V_ASN1_VIDEOTEXSTRING 21

#define V_ASN1_IA5STRING 22

#define V_ASN1_UTCTIME 23

#define V_ASN1_GENERALIZEDTIME 24

#define V_ASN1_GRAPHICSTRING 25

#define V_ASN1_ISO64STRING 26

#define V_ASN1_VISIBLESTRING 26

#define V_ASN1_GENERALSTRING 27

#define V_ASN1_UNIVERSALSTRING 28

#define V_ASN1_BMPSTRING 30

#define V_ASN1_NEG 0x100

#define V_ASN1_NEG_INTEGER (2 | V_ASN1_NEG)

#define V_ASN1_NEG_ENUMERATED (10 | V_ASN1_NEG)

#define B_ASN1_NUMERICSTRING 0x0001

#define B_ASN1_PRINTABLESTRING 0x0002

#define B_ASN1_T61STRING 0x0004

#define B_ASN1_TELETEXSTRING 0x0004

#define B_ASN1_VIDEOTEXSTRING 0x0008

#define B_ASN1_IA5STRING 0x0010

#define B_ASN1_GRAPHICSTRING 0x0020

#define B_ASN1_ISO64STRING 0x0040

#define B_ASN1_VISIBLESTRING 0x0040

#define B_ASN1_GENERALSTRING 0x0080

#define B_ASN1_UNIVERSALSTRING 0x0100

#define B_ASN1_OCTET_STRING 0x0200

#define B_ASN1_BIT_STRING 0x0400

#define B_ASN1_BMPSTRING 0x0800

#define B_ASN1_UNKNOWN 0x1000

#define B_ASN1_UTF8STRING 0x2000

#define B_ASN1_UTCTIME 0x4000

#define B_ASN1_GENERALIZEDTIME 0x8000

#define B_ASN1_SEQUENCE 0x10000

#define MBSTRING_FLAG 0x1000

#define MBSTRING_UTF8 (MBSTRING_FLAG)

#define MBSTRING_ASC (MBSTRING_FLAG|1)

#define MBSTRING_BMP (MBSTRING_FLAG|2)

#define MBSTRING_UNIV (MBSTRING_FLAG|4)

#define SMIME_OLDMIME 0x400

#define SMIME_CRLFEOL 0x800

#define SMIME_STREAM 0x1000

#define ASN1_STRING_FLAG_BITS_LEFT 0x08

#define ASN1_STRING_FLAG_NDEF 0x010

#define ASN1_STRING_FLAG_CONT 0x020

#define ASN1_STRING_FLAG_MSTRING 0x040

#define ASN1_STRING_FLAG_EMBED 0x080

#define ASN1_STRING_FLAG_X509_TIME 0x100

#define ASN1_LONG_UNDEF 0x7fffffffL

#define STABLE_FLAGS_MALLOC 0x01

#define STABLE_FLAGS_CLEAR STABLE_FLAGS_MALLOC

#define STABLE_NO_MASK 0x02

#define DIRSTRING_TYPE \
	(B_ASN1_PRINTABLESTRING|B_ASN1_T61STRING|B_ASN1_BMPSTRING|B_ASN1_UTF8STRING)

#define PKCS9STRING_TYPE (DIRSTRING_TYPE|B_ASN1_IA5STRING)

#define ub_name 32768

#define ub_common_name 64

#define ub_locality_name 128

#define ub_state_name 128

#define ub_organization_name 64

#define ub_organization_unit_name 64

#define ub_title 64

#define ub_email_address 128

#define DECLARE_ASN1_FUNCTIONS_attr (attr, type)\
	DECLARE_ASN1_FUNCTIONS_name_attr(attr, type, type)

#define DECLARE_ASN1_FUNCTIONS (type)\
	DECLARE_ASN1_FUNCTIONS_attr(extern, type)

#define DECLARE_ASN1_ALLOC_FUNCTIONS_attr (attr, type)\
	DECLARE_ASN1_ALLOC_FUNCTIONS_name_attr(attr, type, type)

#define DECLARE_ASN1_ALLOC_FUNCTIONS (type)\
	DECLARE_ASN1_ALLOC_FUNCTIONS_attr(extern, type)

#define DECLARE_ASN1_FUNCTIONS_name_attr (attr, type, name)\
	DECLARE_ASN1_ALLOC_FUNCTIONS_name_attr(attr, type, name)                \\
	DECLARE_ASN1_ENCODE_FUNCTIONS_name_attr(attr, type, name)

#define DECLARE_ASN1_FUNCTIONS_name (type, name)\
	DECLARE_ASN1_FUNCTIONS_name_attr(extern, type, name)

#define DECLARE_ASN1_ENCODE_FUNCTIONS_attr (attr, type, itname, name)\
	DECLARE_ASN1_ENCODE_FUNCTIONS_only_attr(attr, type, name)               \\
	DECLARE_ASN1_ITEM_attr(attr, itname)

#define DECLARE_ASN1_ENCODE_FUNCTIONS (type, itname, name)\
	DECLARE_ASN1_ENCODE_FUNCTIONS_attr(extern, type, itname, name)

#define DECLARE_ASN1_ENCODE_FUNCTIONS_name_attr (attr, type, name)\
	DECLARE_ASN1_ENCODE_FUNCTIONS_attr(attr, type, name, name)

#define DECLARE_ASN1_ENCODE_FUNCTIONS_name (type, name)\
	DECLARE_ASN1_ENCODE_FUNCTIONS_name_attr(extern, type, name)

#define DECLARE_ASN1_ENCODE_FUNCTIONS_only_attr (attr, type, name)\
	attr type *d2i_##name(type **a, const unsigned char **in, long len);    \\
	attr int i2d_##name(const type *a, unsigned char **out);

#define DECLARE_ASN1_ENCODE_FUNCTIONS_only (type, name)\
	DECLARE_ASN1_ENCODE_FUNCTIONS_only_attr(extern, type, name)

#define DECLARE_ASN1_NDEF_FUNCTION_attr (attr, name)\
	attr int i2d_##name##_NDEF(const name *a, unsigned char **out);

#define DECLARE_ASN1_NDEF_FUNCTION (name)\
	DECLARE_ASN1_NDEF_FUNCTION_attr(extern, name)

#define DECLARE_ASN1_ALLOC_FUNCTIONS_name_attr (attr, type, name)\
	attr type *name##_new(void);                                            \\
	attr void name##_free(type *a);

#define DECLARE_ASN1_ALLOC_FUNCTIONS_name (type, name)\
	DECLARE_ASN1_ALLOC_FUNCTIONS_name_attr(extern, type, name)

#define DECLARE_ASN1_DUP_FUNCTION_attr (attr, type)\
	DECLARE_ASN1_DUP_FUNCTION_name_attr(attr, type, type)

#define DECLARE_ASN1_DUP_FUNCTION (type)\
	DECLARE_ASN1_DUP_FUNCTION_attr(extern, type)

#define DECLARE_ASN1_DUP_FUNCTION_name_attr (attr, type, name)\
	attr type *name##_dup(const type *a);

#define DECLARE_ASN1_DUP_FUNCTION_name (type, name)\
	DECLARE_ASN1_DUP_FUNCTION_name_attr(extern, type, name)

#define DECLARE_ASN1_PRINT_FUNCTION_attr (attr, stname)\
	DECLARE_ASN1_PRINT_FUNCTION_fname_attr(attr, stname, stname)

#define DECLARE_ASN1_PRINT_FUNCTION (stname)\
	DECLARE_ASN1_PRINT_FUNCTION_attr(extern, stname)

typedef struct bio_st BIO;
#define DECLARE_ASN1_PRINT_FUNCTION_fname_attr (attr, stname, fname)\
	attr int fname##_print_ctx(BIO *out, const stname *x, int indent,       \\
	const ASN1_PCTX *pctx);

#define DECLARE_ASN1_PRINT_FUNCTION_fname (stname, fname)\
	DECLARE_ASN1_PRINT_FUNCTION_fname_attr(extern, stname, fname)

#define D2I_OF (type) type *(*)(type **,const unsigned char **,long)

#define I2D_OF (type) int (*)(const type *,unsigned char **)

#define CHECKED_D2I_OF (type, d2i)\
	((d2i_of_void*) (1 ? d2i : ((D2I_OF(type))0)))

#define CHECKED_I2D_OF (type, i2d)\
	((i2d_of_void*) (1 ? i2d : ((I2D_OF(type))0)))

#define CHECKED_NEW_OF (type, xnew)\
	((void *(*)(void)) (1 ? xnew : ((type *(*)(void))0)))

#define CHECKED_PTR_OF (type, p)\
	((void*) (1 ? p : (type*)0))

#define CHECKED_PPTR_OF (type, p)\
	((void**) (1 ? p : (type**)0))

#define TYPEDEF_D2I_OF (type) typedef type *d2i_of_##type(type **,const unsigned char **,long)

#define TYPEDEF_I2D_OF (type) typedef int i2d_of_##type(const type *,unsigned char **)

#define TYPEDEF_D2I2D_OF (type) TYPEDEF_D2I_OF(type); TYPEDEF_I2D_OF(type)

#define ASN1_ITEM_ptr (iptr) (iptr())

#define ASN1_ITEM_ref (iptr) (iptr##_it)

#define ASN1_ITEM_rptr (ref) (ref##_it())

#define DECLARE_ASN1_ITEM_attr (attr, name)\
	attr const ASN1_ITEM * name##_it(void);

#define DECLARE_ASN1_ITEM (name)\
	DECLARE_ASN1_ITEM_attr(extern, name)

#define ASN1_STRFLGS_ESC_2253 1

#define ASN1_STRFLGS_ESC_CTRL 2

#define ASN1_STRFLGS_ESC_MSB 4

#define ASN1_DTFLGS_TYPE_MASK 0x0FUL

#define ASN1_DTFLGS_RFC822 0x00UL

#define ASN1_DTFLGS_ISO8601 0x01UL

#define ASN1_STRFLGS_ESC_QUOTE 8

#define CHARTYPE_PRINTABLESTRING 0x10

#define CHARTYPE_FIRST_ESC_2253 0x20

#define CHARTYPE_LAST_ESC_2253 0x40

#define ASN1_STRFLGS_UTF8_CONVERT 0x10

#define ASN1_STRFLGS_IGNORE_TYPE 0x20

#define ASN1_STRFLGS_SHOW_TYPE 0x40

#define ASN1_STRFLGS_DUMP_ALL 0x80

#define ASN1_STRFLGS_DUMP_UNKNOWN 0x100

#define ASN1_STRFLGS_DUMP_DER 0x200

#define ASN1_STRFLGS_ESC_2254 0x400

#define ASN1_STRFLGS_RFC2253 (ASN1_STRFLGS_ESC_2253 |\
	ASN1_STRFLGS_ESC_CTRL | \\
	ASN1_STRFLGS_ESC_MSB | \\
	ASN1_STRFLGS_UTF8_CONVERT | \\
	ASN1_STRFLGS_DUMP_UNKNOWN | \\
	ASN1_STRFLGS_DUMP_DER)

#define B_ASN1_TIME \
	B_ASN1_UTCTIME | \\
	B_ASN1_GENERALIZEDTIME

#define B_ASN1_PRINTABLE \
	B_ASN1_NUMERICSTRING| \\
	B_ASN1_PRINTABLESTRING| \\
	B_ASN1_T61STRING| \\
	B_ASN1_IA5STRING| \\
	B_ASN1_BIT_STRING| \\
	B_ASN1_UNIVERSALSTRING|\\
	B_ASN1_BMPSTRING|\\
	B_ASN1_UTF8STRING|\\
	B_ASN1_SEQUENCE|\\
	B_ASN1_UNKNOWN

#define B_ASN1_DIRECTORYSTRING \
	B_ASN1_PRINTABLESTRING| \\
	B_ASN1_TELETEXSTRING|\\
	B_ASN1_BMPSTRING|\\
	B_ASN1_UNIVERSALSTRING|\\
	B_ASN1_UTF8STRING

#define B_ASN1_DISPLAYTEXT \
	B_ASN1_IA5STRING| \\
	B_ASN1_VISIBLESTRING| \\
	B_ASN1_BMPSTRING|\\
	B_ASN1_UTF8STRING

#define ASN1_dup_of (type,i2d,d2i,x)\
	((type*)ASN1_dup(CHECKED_I2D_OF(type, i2d), \\
	CHECKED_D2I_OF(type, d2i), \\
	CHECKED_PTR_OF(const type, x)))

#define M_ASN1_new_of (type) (type *)ASN1_item_new(ASN1_ITEM_rptr(type))

#define M_ASN1_free_of (x, type)\
	ASN1_item_free(CHECKED_PTR_OF(type, x), ASN1_ITEM_rptr(type))

#define ASN1_d2i_fp_of (type,xnew,d2i,in,x)\
	((type*)ASN1_d2i_fp(CHECKED_NEW_OF(type, xnew), \\
	CHECKED_D2I_OF(type, d2i), \\
	in, \\
	CHECKED_PPTR_OF(type, x)))

#define ASN1_i2d_fp_of (type,i2d,out,x)\
	(ASN1_i2d_fp(CHECKED_I2D_OF(type, i2d), \\
	out, \\
	CHECKED_PTR_OF(const type, x)))

#define ASN1_d2i_bio_of (type,xnew,d2i,in,x)\
	((type*)ASN1_d2i_bio( CHECKED_NEW_OF(type, xnew), \\
	CHECKED_D2I_OF(type, d2i), \\
	in, \\
	CHECKED_PPTR_OF(type, x)))

#define ASN1_i2d_bio_of (type,i2d,out,x)\
	(ASN1_i2d_bio(CHECKED_I2D_OF(type, i2d), \\
	out, \\
	CHECKED_PTR_OF(const type, x)))

#define ASN1_PCTX_FLAGS_SHOW_ABSENT 0x001

#define ASN1_PCTX_FLAGS_SHOW_SEQUENCE 0x002

#define ASN1_PCTX_FLAGS_SHOW_SSOF 0x004

#define ASN1_PCTX_FLAGS_SHOW_TYPE 0x008

#define ASN1_PCTX_FLAGS_NO_ANY_TYPE 0x010

#define ASN1_PCTX_FLAGS_NO_MSTRING_TYPE 0x020

#define ASN1_PCTX_FLAGS_NO_FIELD_NAME 0x040

#define ASN1_PCTX_FLAGS_SHOW_FIELD_STRUCT_NAME 0x080

#define ASN1_PCTX_FLAGS_NO_STRUCT_NAME 0x100

#define DECLARE_ASN1_FUNCTIONS_fname (type, itname, name)\
	DECLARE_ASN1_ALLOC_FUNCTIONS_name(type, name) \\
	DECLARE_ASN1_ENCODE_FUNCTIONS(type, itname, name)

#define DECLARE_ASN1_FUNCTIONS_const (type) DECLARE_ASN1_FUNCTIONS(type)

#define DECLARE_ASN1_ENCODE_FUNCTIONS_const (type, name)\
	DECLARE_ASN1_ENCODE_FUNCTIONS(type, name)

#define I2D_OF_const (type) I2D_OF(type)

#define ASN1_dup_of_const (type,i2d,d2i,x) ASN1_dup_of(type,i2d,d2i,x)

#define ASN1_i2d_fp_of_const (type,i2d,out,x) ASN1_i2d_fp_of(type,i2d,out,x)

#define ASN1_i2d_bio_of_const (type,i2d,out,x) ASN1_i2d_bio_of(type,i2d,out,x)

#define OPENSSL_ASN1ERR_H 

#define ASN1_R_ADDING_OBJECT 171

#define ASN1_R_ASN1_PARSE_ERROR 203

#define ASN1_R_ASN1_SIG_PARSE_ERROR 204

#define ASN1_R_AUX_ERROR 100

#define ASN1_R_BAD_OBJECT_HEADER 102

#define ASN1_R_BAD_TEMPLATE 230

#define ASN1_R_BMPSTRING_IS_WRONG_LENGTH 214

#define ASN1_R_BN_LIB 105

#define ASN1_R_BOOLEAN_IS_WRONG_LENGTH 106

#define ASN1_R_BUFFER_TOO_SMALL 107

#define ASN1_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER 108

#define ASN1_R_CONTEXT_NOT_INITIALISED 217

#define ASN1_R_DATA_IS_WRONG 109

#define ASN1_R_DECODE_ERROR 110

#define ASN1_R_DEPTH_EXCEEDED 174

#define ASN1_R_DIGEST_AND_KEY_TYPE_NOT_SUPPORTED 198

#define ASN1_R_ENCODE_ERROR 112

#define ASN1_R_ERROR_GETTING_TIME 173

#define ASN1_R_ERROR_LOADING_SECTION 172

#define ASN1_R_ERROR_SETTING_CIPHER_PARAMS 114

#define ASN1_R_EXPECTING_AN_INTEGER 115

#define ASN1_R_EXPECTING_AN_OBJECT 116

#define ASN1_R_EXPLICIT_LENGTH_MISMATCH 119

#define ASN1_R_EXPLICIT_TAG_NOT_CONSTRUCTED 120

#define ASN1_R_FIELD_MISSING 121

#define ASN1_R_FIRST_NUM_TOO_LARGE 122

#define ASN1_R_GENERALIZEDTIME_IS_TOO_SHORT 232

#define ASN1_R_HEADER_TOO_LONG 123

#define ASN1_R_ILLEGAL_BITSTRING_FORMAT 175

#define ASN1_R_ILLEGAL_BOOLEAN 176

#define ASN1_R_ILLEGAL_CHARACTERS 124

#define ASN1_R_ILLEGAL_FORMAT 177

#define ASN1_R_ILLEGAL_HEX 178

#define ASN1_R_ILLEGAL_IMPLICIT_TAG 179

#define ASN1_R_ILLEGAL_INTEGER 180

#define ASN1_R_ILLEGAL_NEGATIVE_VALUE 226

#define ASN1_R_ILLEGAL_NESTED_TAGGING 181

#define ASN1_R_ILLEGAL_NULL 125

#define ASN1_R_ILLEGAL_NULL_VALUE 182

#define ASN1_R_ILLEGAL_OBJECT 183

#define ASN1_R_ILLEGAL_OPTIONAL_ANY 126

#define ASN1_R_ILLEGAL_OPTIONS_ON_ITEM_TEMPLATE 170

#define ASN1_R_ILLEGAL_PADDING 221

#define ASN1_R_ILLEGAL_TAGGED_ANY 127

#define ASN1_R_ILLEGAL_TIME_VALUE 184

#define ASN1_R_ILLEGAL_ZERO_CONTENT 222

#define ASN1_R_INTEGER_NOT_ASCII_FORMAT 185

#define ASN1_R_INTEGER_TOO_LARGE_FOR_LONG 128

#define ASN1_R_INVALID_BIT_STRING_BITS_LEFT 220

#define ASN1_R_INVALID_BMPSTRING_LENGTH 129

#define ASN1_R_INVALID_DIGIT 130

#define ASN1_R_INVALID_MIME_TYPE 205

#define ASN1_R_INVALID_MODIFIER 186

#define ASN1_R_INVALID_NUMBER 187

#define ASN1_R_INVALID_OBJECT_ENCODING 216

#define ASN1_R_INVALID_SCRYPT_PARAMETERS 227

#define ASN1_R_INVALID_SEPARATOR 131

#define ASN1_R_INVALID_STRING_TABLE_VALUE 218

#define ASN1_R_INVALID_UNIVERSALSTRING_LENGTH 133

#define ASN1_R_INVALID_UTF8STRING 134

#define ASN1_R_INVALID_VALUE 219

#define ASN1_R_LENGTH_TOO_LONG 231

#define ASN1_R_LIST_ERROR 188

#define ASN1_R_MIME_NO_CONTENT_TYPE 206

#define ASN1_R_MIME_PARSE_ERROR 207

#define ASN1_R_MIME_SIG_PARSE_ERROR 208

#define ASN1_R_MISSING_EOC 137

#define ASN1_R_MISSING_SECOND_NUMBER 138

#define ASN1_R_MISSING_VALUE 189

#define ASN1_R_MSTRING_NOT_UNIVERSAL 139

#define ASN1_R_MSTRING_WRONG_TAG 140

#define ASN1_R_NESTED_ASN1_STRING 197

#define ASN1_R_NESTED_TOO_DEEP 201

#define ASN1_R_NON_HEX_CHARACTERS 141

#define ASN1_R_NOT_ASCII_FORMAT 190

#define ASN1_R_NOT_ENOUGH_DATA 142

#define ASN1_R_NO_CONTENT_TYPE 209

#define ASN1_R_NO_MATCHING_CHOICE_TYPE 143

#define ASN1_R_NO_MULTIPART_BODY_FAILURE 210

#define ASN1_R_NO_MULTIPART_BOUNDARY 211

#define ASN1_R_NO_SIG_CONTENT_TYPE 212

#define ASN1_R_NULL_IS_WRONG_LENGTH 144

#define ASN1_R_OBJECT_NOT_ASCII_FORMAT 191

#define ASN1_R_ODD_NUMBER_OF_CHARS 145

#define ASN1_R_SECOND_NUMBER_TOO_LARGE 147

#define ASN1_R_SEQUENCE_LENGTH_MISMATCH 148

#define ASN1_R_SEQUENCE_NOT_CONSTRUCTED 149

#define ASN1_R_SEQUENCE_OR_SET_NEEDS_CONFIG 192

#define ASN1_R_SHORT_LINE 150

#define ASN1_R_SIG_INVALID_MIME_TYPE 213

#define ASN1_R_STREAMING_NOT_SUPPORTED 202

#define ASN1_R_STRING_TOO_LONG 151

#define ASN1_R_STRING_TOO_SHORT 152

#define ASN1_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD 154

#define ASN1_R_TIME_NOT_ASCII_FORMAT 193

#define ASN1_R_TOO_LARGE 223

#define ASN1_R_TOO_LONG 155

#define ASN1_R_TOO_SMALL 224

#define ASN1_R_TYPE_NOT_CONSTRUCTED 156

#define ASN1_R_TYPE_NOT_PRIMITIVE 195

#define ASN1_R_UNEXPECTED_EOC 159

#define ASN1_R_UNIVERSALSTRING_IS_WRONG_LENGTH 215

#define ASN1_R_UNKNOWN_DIGEST 229

#define ASN1_R_UNKNOWN_FORMAT 160

#define ASN1_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM 161

#define ASN1_R_UNKNOWN_OBJECT_TYPE 162

#define ASN1_R_UNKNOWN_PUBLIC_KEY_TYPE 163

#define ASN1_R_UNKNOWN_SIGNATURE_ALGORITHM 199

#define ASN1_R_UNKNOWN_TAG 194

#define ASN1_R_UNSUPPORTED_ANY_DEFINED_BY_TYPE 164

#define ASN1_R_UNSUPPORTED_CIPHER 228

#define ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE 167

#define ASN1_R_UNSUPPORTED_TYPE 196

#define ASN1_R_UTCTIME_IS_TOO_SHORT 233

#define ASN1_R_WRONG_INTEGER_TYPE 225

#define ASN1_R_WRONG_PUBLIC_KEY_TYPE 200

#define ASN1_R_WRONG_TAG 168

#define OPENSSL_ASN1T_H 

#define HEADER_ASN1T_H 

#define ASN1_ITYPE_PRIMITIVE 0x0

#define ASN1_ITYPE_SEQUENCE 0x1

#define ASN1_ITYPE_CHOICE 0x2

#define ASN1_ITYPE_EXTERN 0x4

#define ASN1_ITYPE_MSTRING 0x5

#define ASN1_ITYPE_NDEF_SEQUENCE 0x6

#define ASN1_ADB_ptr (iptr) ((const ASN1_ADB *)((iptr)()))

#define ASN1_ITEM_start (itname)\
	const ASN1_ITEM * itname##_it(void) \\
	{ \\
	static const ASN1_ITEM local_it = {

#define static_ASN1_ITEM_start (itname)\
	static ASN1_ITEM_start(itname)

#define ASN1_ITEM_end (itname)\
	}; \\
	return &local_it; \\
	}

#define ASN1_ITEM_TEMPLATE (tname)\
	static const ASN1_TEMPLATE tname##_item_tt

#define ASN1_ITEM_TEMPLATE_END (tname)\
	;\\
	ASN1_ITEM_start(tname) \\
	ASN1_ITYPE_PRIMITIVE,\\
	-1,\\
	&tname##_item_tt,\\
	0,\\
	NULL,\\
	0,\\
	#tname \\
	ASN1_ITEM_end(tname)

#define static_ASN1_ITEM_TEMPLATE_END (tname)\
	;\\
	static_ASN1_ITEM_start(tname) \\
	ASN1_ITYPE_PRIMITIVE,\\
	-1,\\
	&tname##_item_tt,\\
	0,\\
	NULL,\\
	0,\\
	#tname \\
	ASN1_ITEM_end(tname)

#define ASN1_SEQUENCE (tname)\
	static const ASN1_TEMPLATE tname##_seq_tt[]

#define ASN1_SEQUENCE_END (stname) ASN1_SEQUENCE_END_name(stname, stname)

#define static_ASN1_SEQUENCE_END (stname) static_ASN1_SEQUENCE_END_name(stname, stname)

#define ASN1_SEQUENCE_END_name (stname, tname)\
	;\\
	ASN1_ITEM_start(tname) \\
	ASN1_ITYPE_SEQUENCE,\\
	V_ASN1_SEQUENCE,\\
	tname##_seq_tt,\\
	sizeof(tname##_seq_tt) / sizeof(ASN1_TEMPLATE),\\
	NULL,\\
	sizeof(stname),\\
	#tname \\
	ASN1_ITEM_end(tname)

#define static_ASN1_SEQUENCE_END_name (stname, tname)\
	;\\
	static_ASN1_ITEM_start(tname) \\
	ASN1_ITYPE_SEQUENCE,\\
	V_ASN1_SEQUENCE,\\
	tname##_seq_tt,\\
	sizeof(tname##_seq_tt) / sizeof(ASN1_TEMPLATE),\\
	NULL,\\
	sizeof(stname),\\
	#stname \\
	ASN1_ITEM_end(tname)

#define ASN1_NDEF_SEQUENCE (tname)\
	ASN1_SEQUENCE(tname)

#define ASN1_NDEF_SEQUENCE_cb (tname, cb)\
	ASN1_SEQUENCE_cb(tname, cb)

#define ASN1_SEQUENCE_cb (tname, cb)\
	static const ASN1_AUX tname##_aux = {NULL, 0, 0, 0, cb, 0, NULL}; \\
	ASN1_SEQUENCE(tname)

#define ASN1_SEQUENCE_const_cb (tname, const_cb)\
	static const ASN1_AUX tname##_aux = \\
	{NULL, ASN1_AFLG_CONST_CB, 0, 0, NULL, 0, const_cb}; \\
	ASN1_SEQUENCE(tname)

#define ASN1_SEQUENCE_cb_const_cb (tname, cb, const_cb)\
	static const ASN1_AUX tname##_aux = \\
	{NULL, ASN1_AFLG_CONST_CB, 0, 0, cb, 0, const_cb}; \\
	ASN1_SEQUENCE(tname)

#define ASN1_SEQUENCE_ref (tname, cb)\
	static const ASN1_AUX tname##_aux = {NULL, ASN1_AFLG_REFCOUNT, offsetof(tname, references), offsetof(tname, lock), cb, 0, NULL}; \\
	ASN1_SEQUENCE(tname)

#define ASN1_SEQUENCE_enc (tname, enc, cb)\
	static const ASN1_AUX tname##_aux = {NULL, ASN1_AFLG_ENCODING, 0, 0, cb, offsetof(tname, enc), NULL}; \\
	ASN1_SEQUENCE(tname)

#define ASN1_NDEF_SEQUENCE_END (tname)\
	;\\
	ASN1_ITEM_start(tname) \\
	ASN1_ITYPE_NDEF_SEQUENCE,\\
	V_ASN1_SEQUENCE,\\
	tname##_seq_tt,\\
	sizeof(tname##_seq_tt) / sizeof(ASN1_TEMPLATE),\\
	NULL,\\
	sizeof(tname),\\
	#tname \\
	ASN1_ITEM_end(tname)

#define static_ASN1_NDEF_SEQUENCE_END (tname)\
	;\\
	static_ASN1_ITEM_start(tname) \\
	ASN1_ITYPE_NDEF_SEQUENCE,\\
	V_ASN1_SEQUENCE,\\
	tname##_seq_tt,\\
	sizeof(tname##_seq_tt) / sizeof(ASN1_TEMPLATE),\\
	NULL,\\
	sizeof(tname),\\
	#tname \\
	ASN1_ITEM_end(tname)

#define ASN1_SEQUENCE_END_enc (stname, tname) ASN1_SEQUENCE_END_ref(stname, tname)

#define ASN1_SEQUENCE_END_cb (stname, tname) ASN1_SEQUENCE_END_ref(stname, tname)

#define static_ASN1_SEQUENCE_END_cb (stname, tname) static_ASN1_SEQUENCE_END_ref(stname, tname)

#define ASN1_SEQUENCE_END_ref (stname, tname)\
	;\\
	ASN1_ITEM_start(tname) \\
	ASN1_ITYPE_SEQUENCE,\\
	V_ASN1_SEQUENCE,\\
	tname##_seq_tt,\\
	sizeof(tname##_seq_tt) / sizeof(ASN1_TEMPLATE),\\
	&tname##_aux,\\
	sizeof(stname),\\
	#tname \\
	ASN1_ITEM_end(tname)

#define static_ASN1_SEQUENCE_END_ref (stname, tname)\
	;\\
	static_ASN1_ITEM_start(tname) \\
	ASN1_ITYPE_SEQUENCE,\\
	V_ASN1_SEQUENCE,\\
	tname##_seq_tt,\\
	sizeof(tname##_seq_tt) / sizeof(ASN1_TEMPLATE),\\
	&tname##_aux,\\
	sizeof(stname),\\
	#stname \\
	ASN1_ITEM_end(tname)

#define ASN1_NDEF_SEQUENCE_END_cb (stname, tname)\
	;\\
	ASN1_ITEM_start(tname) \\
	ASN1_ITYPE_NDEF_SEQUENCE,\\
	V_ASN1_SEQUENCE,\\
	tname##_seq_tt,\\
	sizeof(tname##_seq_tt) / sizeof(ASN1_TEMPLATE),\\
	&tname##_aux,\\
	sizeof(stname),\\
	#stname \\
	ASN1_ITEM_end(tname)

#define ASN1_CHOICE (tname)\
	static const ASN1_TEMPLATE tname##_ch_tt[]

#define ASN1_CHOICE_cb (tname, cb)\
	static const ASN1_AUX tname##_aux = {NULL, 0, 0, 0, cb, 0, NULL}; \\
	ASN1_CHOICE(tname)

#define ASN1_CHOICE_END (stname) ASN1_CHOICE_END_name(stname, stname)

#define static_ASN1_CHOICE_END (stname) static_ASN1_CHOICE_END_name(stname, stname)

#define ASN1_CHOICE_END_name (stname, tname) ASN1_CHOICE_END_selector(stname, tname, type)

#define static_ASN1_CHOICE_END_name (stname, tname) static_ASN1_CHOICE_END_selector(stname, tname, type)

#define ASN1_CHOICE_END_selector (stname, tname, selname)\
	;\\
	ASN1_ITEM_start(tname) \\
	ASN1_ITYPE_CHOICE,\\
	offsetof(stname,selname) ,\\
	tname##_ch_tt,\\
	sizeof(tname##_ch_tt) / sizeof(ASN1_TEMPLATE),\\
	NULL,\\
	sizeof(stname),\\
	#stname \\
	ASN1_ITEM_end(tname)

#define static_ASN1_CHOICE_END_selector (stname, tname, selname)\
	;\\
	static_ASN1_ITEM_start(tname) \\
	ASN1_ITYPE_CHOICE,\\
	offsetof(stname,selname) ,\\
	tname##_ch_tt,\\
	sizeof(tname##_ch_tt) / sizeof(ASN1_TEMPLATE),\\
	NULL,\\
	sizeof(stname),\\
	#stname \\
	ASN1_ITEM_end(tname)

#define ASN1_CHOICE_END_cb (stname, tname, selname)\
	;\\
	ASN1_ITEM_start(tname) \\
	ASN1_ITYPE_CHOICE,\\
	offsetof(stname,selname) ,\\
	tname##_ch_tt,\\
	sizeof(tname##_ch_tt) / sizeof(ASN1_TEMPLATE),\\
	&tname##_aux,\\
	sizeof(stname),\\
	#stname \\
	ASN1_ITEM_end(tname)

#define ASN1_EX_TEMPLATE_TYPE (flags, tag, name, type) {\
	(flags), (tag), 0,\\
	#name, ASN1_ITEM_ref(type) }

#define ASN1_EX_TYPE (flags, tag, stname, field, type) {\
	(flags), (tag), offsetof(stname, field),\\
	#field, ASN1_ITEM_ref(type) }

#define ASN1_IMP_EX (stname, field, type, tag, ex)\
	ASN1_EX_TYPE(ASN1_TFLG_IMPLICIT | (ex), tag, stname, field, type)

#define ASN1_EXP_EX (stname, field, type, tag, ex)\
	ASN1_EX_TYPE(ASN1_TFLG_EXPLICIT | (ex), tag, stname, field, type)

#define ASN1_ADB_OBJECT (tblname) { ASN1_TFLG_ADB_OID, -1, 0, #tblname, tblname##_adb }

#define ASN1_ADB_INTEGER (tblname) { ASN1_TFLG_ADB_INT, -1, 0, #tblname, tblname##_adb }

#define ASN1_SIMPLE (stname, field, type) ASN1_EX_TYPE(0,0, stname, field, type)

#define ASN1_EMBED (stname, field, type) ASN1_EX_TYPE(ASN1_TFLG_EMBED,0, stname, field, type)

#define ASN1_OPT (stname, field, type) ASN1_EX_TYPE(ASN1_TFLG_OPTIONAL, 0, stname, field, type)

#define ASN1_OPT_EMBED (stname, field, type) ASN1_EX_TYPE(ASN1_TFLG_OPTIONAL|ASN1_TFLG_EMBED, 0, stname, field, type)

#define ASN1_IMP (stname, field, type, tag) ASN1_IMP_EX(stname, field, type, tag, 0)

#define ASN1_IMP_EMBED (stname, field, type, tag) ASN1_IMP_EX(stname, field, type, tag, ASN1_TFLG_EMBED)

#define ASN1_IMP_OPT (stname, field, type, tag) ASN1_IMP_EX(stname, field, type, tag, ASN1_TFLG_OPTIONAL)

#define ASN1_IMP_OPT_EMBED (stname, field, type, tag) ASN1_IMP_EX(stname, field, type, tag, ASN1_TFLG_OPTIONAL|ASN1_TFLG_EMBED)

#define ASN1_EXP (stname, field, type, tag) ASN1_EXP_EX(stname, field, type, tag, 0)

#define ASN1_EXP_EMBED (stname, field, type, tag) ASN1_EXP_EX(stname, field, type, tag, ASN1_TFLG_EMBED)

#define ASN1_EXP_OPT (stname, field, type, tag) ASN1_EXP_EX(stname, field, type, tag, ASN1_TFLG_OPTIONAL)

#define ASN1_EXP_OPT_EMBED (stname, field, type, tag) ASN1_EXP_EX(stname, field, type, tag, ASN1_TFLG_OPTIONAL|ASN1_TFLG_EMBED)

#define ASN1_SEQUENCE_OF (stname, field, type)\
	ASN1_EX_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, stname, field, type)

#define ASN1_SEQUENCE_OF_OPT (stname, field, type)\
	ASN1_EX_TYPE(ASN1_TFLG_SEQUENCE_OF|ASN1_TFLG_OPTIONAL, 0, stname, field, type)

#define ASN1_SET_OF (stname, field, type)\
	ASN1_EX_TYPE(ASN1_TFLG_SET_OF, 0, stname, field, type)

#define ASN1_SET_OF_OPT (stname, field, type)\
	ASN1_EX_TYPE(ASN1_TFLG_SET_OF|ASN1_TFLG_OPTIONAL, 0, stname, field, type)

#define ASN1_IMP_SET_OF (stname, field, type, tag)\
	ASN1_IMP_EX(stname, field, type, tag, ASN1_TFLG_SET_OF)

#define ASN1_EXP_SET_OF (stname, field, type, tag)\
	ASN1_EXP_EX(stname, field, type, tag, ASN1_TFLG_SET_OF)

#define ASN1_IMP_SET_OF_OPT (stname, field, type, tag)\
	ASN1_IMP_EX(stname, field, type, tag, ASN1_TFLG_SET_OF|ASN1_TFLG_OPTIONAL)

#define ASN1_EXP_SET_OF_OPT (stname, field, type, tag)\
	ASN1_EXP_EX(stname, field, type, tag, ASN1_TFLG_SET_OF|ASN1_TFLG_OPTIONAL)

#define ASN1_IMP_SEQUENCE_OF (stname, field, type, tag)\
	ASN1_IMP_EX(stname, field, type, tag, ASN1_TFLG_SEQUENCE_OF)

#define ASN1_IMP_SEQUENCE_OF_OPT (stname, field, type, tag)\
	ASN1_IMP_EX(stname, field, type, tag, ASN1_TFLG_SEQUENCE_OF|ASN1_TFLG_OPTIONAL)

#define ASN1_EXP_SEQUENCE_OF (stname, field, type, tag)\
	ASN1_EXP_EX(stname, field, type, tag, ASN1_TFLG_SEQUENCE_OF)

#define ASN1_EXP_SEQUENCE_OF_OPT (stname, field, type, tag)\
	ASN1_EXP_EX(stname, field, type, tag, ASN1_TFLG_SEQUENCE_OF|ASN1_TFLG_OPTIONAL)

#define ASN1_NDEF_EXP (stname, field, type, tag)\
	ASN1_EXP_EX(stname, field, type, tag, ASN1_TFLG_NDEF)

#define ASN1_NDEF_EXP_OPT (stname, field, type, tag)\
	ASN1_EXP_EX(stname, field, type, tag, ASN1_TFLG_OPTIONAL|ASN1_TFLG_NDEF)

#define ASN1_ADB_TMP (name)\
	static const ASN1_ADB_TABLE name##_adbtbl[]

#define ASN1_ADB_END (name, flags, field, adb_cb, def, none)\
	;\\
	static const ASN1_ITEM *name##_adb(void) \\
	{ \\
	static const ASN1_ADB_TMP internal_adb = \\
	{\\
	flags,\\
	offsetof(name, field),\\
	adb_cb,\\
	name##_adbtbl,\\
	sizeof(name##_adbtbl) / sizeof(ASN1_ADB_TABLE),\\
	def,\\
	none\\
	}; \\
	return (const ASN1_ITEM *) &internal_adb; \\
	} \\
	void dummy_function(void)

#define ADB_ENTRY (val, template) {val, template}

#define ASN1_ADB_TEMPLATE (name)\
	static const ASN1_TEMPLATE name##_tt

#define ASN1_TEMPLATE_item (t) (t->item_ptr)

#define ASN1_TEMPLATE_adb (t) (t->item_ptr)

#define ASN1_TFLG_OPTIONAL (0x1)

#define ASN1_TFLG_SET_OF (0x1 << 1)

#define ASN1_TFLG_SEQUENCE_OF (0x2 << 1)

#define ASN1_TFLG_SET_ORDER (0x3 << 1)

#define ASN1_TFLG_SK_MASK (0x3 << 1)

#define ASN1_TFLG_IMPTAG (0x1 << 3)

#define ASN1_TFLG_EXPTAG (0x2 << 3)

#define ASN1_TFLG_TAG_MASK (0x3 << 3)

#define ASN1_TFLG_IMPLICIT (ASN1_TFLG_IMPTAG|ASN1_TFLG_CONTEXT)

#define ASN1_TFLG_EXPLICIT (ASN1_TFLG_EXPTAG|ASN1_TFLG_CONTEXT)

#define ASN1_TFLG_UNIVERSAL (0x0<<6)

#define ASN1_TFLG_APPLICATION (0x1<<6)

#define ASN1_TFLG_CONTEXT (0x2<<6)

#define ASN1_TFLG_PRIVATE (0x3<<6)

#define ASN1_TFLG_TAG_CLASS (0x3<<6)

#define ASN1_TFLG_ADB_MASK (0x3<<8)

#define ASN1_TFLG_ADB_OID (0x1<<8)

#define ASN1_TFLG_ADB_INT (0x1<<9)

#define ASN1_TFLG_NDEF (0x1<<11)

#define ASN1_TFLG_EMBED (0x1 << 12)

#define ASN1_AFLG_REFCOUNT 1

#define ASN1_AFLG_ENCODING 2

#define ASN1_AFLG_BROKEN 4

#define ASN1_AFLG_CONST_CB 8

#define ASN1_OP_NEW_PRE 0

#define ASN1_OP_NEW_POST 1

#define ASN1_OP_FREE_PRE 2

#define ASN1_OP_FREE_POST 3

#define ASN1_OP_D2I_PRE 4

#define ASN1_OP_D2I_POST 5

#define ASN1_OP_I2D_PRE 6

#define ASN1_OP_I2D_POST 7

#define ASN1_OP_PRINT_PRE 8

#define ASN1_OP_PRINT_POST 9

#define ASN1_OP_STREAM_PRE 10

#define ASN1_OP_STREAM_POST 11

#define ASN1_OP_DETACHED_PRE 12

#define ASN1_OP_DETACHED_POST 13

#define ASN1_OP_DUP_PRE 14

#define ASN1_OP_DUP_POST 15

#define ASN1_OP_GET0_LIBCTX 16

#define ASN1_OP_GET0_PROPQ 17

#define IMPLEMENT_ASN1_TYPE (stname) IMPLEMENT_ASN1_TYPE_ex(stname, stname, 0)

#define IMPLEMENT_ASN1_TYPE_ex (itname, vname, ex)\
	ASN1_ITEM_start(itname) \\
	ASN1_ITYPE_PRIMITIVE, V_##vname, NULL, 0, NULL, ex, #itname \\
	ASN1_ITEM_end(itname)

#define IMPLEMENT_ASN1_MSTRING (itname, mask)\
	ASN1_ITEM_start(itname) \\
	ASN1_ITYPE_MSTRING, mask, NULL, 0, NULL, sizeof(ASN1_STRING), #itname \\
	ASN1_ITEM_end(itname)

#define IMPLEMENT_EXTERN_ASN1 (sname, tag, fptrs)\
	ASN1_ITEM_start(sname) \\
	ASN1_ITYPE_EXTERN, \\
	tag, \\
	NULL, \\
	0, \\
	&fptrs, \\
	0, \\
	#sname \\
	ASN1_ITEM_end(sname)

#define IMPLEMENT_ASN1_FUNCTIONS (stname) IMPLEMENT_ASN1_FUNCTIONS_fname(stname, stname, stname)

#define IMPLEMENT_ASN1_FUNCTIONS_name (stname, itname) IMPLEMENT_ASN1_FUNCTIONS_fname(stname, itname, itname)

#define IMPLEMENT_ASN1_FUNCTIONS_ENCODE_name (stname, itname)\
	IMPLEMENT_ASN1_FUNCTIONS_ENCODE_fname(stname, itname, itname)

#define IMPLEMENT_STATIC_ASN1_ALLOC_FUNCTIONS (stname)\
	IMPLEMENT_ASN1_ALLOC_FUNCTIONS_pfname(static, stname, stname, stname)

#define IMPLEMENT_ASN1_ALLOC_FUNCTIONS (stname)\
	IMPLEMENT_ASN1_ALLOC_FUNCTIONS_fname(stname, stname, stname)

#define IMPLEMENT_ASN1_ALLOC_FUNCTIONS_pfname (pre, stname, itname, fname)\
	pre stname *fname##_new(void) \\
	{ \\
	return (stname *)ASN1_item_new(ASN1_ITEM_rptr(itname)); \\
	} \\
	pre void fname##_free(stname *a) \\
	{ \\
	ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(itname)); \\
	}

#define IMPLEMENT_ASN1_ALLOC_FUNCTIONS_fname (stname, itname, fname)\
	stname *fname##_new(void) \\
	{ \\
	return (stname *)ASN1_item_new(ASN1_ITEM_rptr(itname)); \\
	} \\
	void fname##_free(stname *a) \\
	{ \\
	ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(itname)); \\
	}

#define IMPLEMENT_ASN1_FUNCTIONS_fname (stname, itname, fname)\
	IMPLEMENT_ASN1_ENCODE_FUNCTIONS_fname(stname, itname, fname) \\
	IMPLEMENT_ASN1_ALLOC_FUNCTIONS_fname(stname, itname, fname)

#define IMPLEMENT_ASN1_ENCODE_FUNCTIONS_fname (stname, itname, fname)\
	stname *d2i_##fname(stname **a, const unsigned char **in, long len) \\
	{ \\
	return (stname *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(itname));\\
	} \\
	int i2d_##fname(const stname *a, unsigned char **out) \\
	{ \\
	return ASN1_item_i2d((const ASN1_VALUE *)a, out, ASN1_ITEM_rptr(itname));\\
	}

#define IMPLEMENT_ASN1_NDEF_FUNCTION (stname)\
	int i2d_##stname##_NDEF(const stname *a, unsigned char **out) \\
	{ \\
	return ASN1_item_ndef_i2d((const ASN1_VALUE *)a, out, ASN1_ITEM_rptr(stname));\\
	}

#define IMPLEMENT_STATIC_ASN1_ENCODE_FUNCTIONS (stname)\
	static stname *d2i_##stname(stname **a, \\
	const unsigned char **in, long len) \\
	{ \\
	return (stname *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, \\
	ASN1_ITEM_rptr(stname)); \\
	} \\
	static int i2d_##stname(const stname *a, unsigned char **out) \\
	{ \\
	return ASN1_item_i2d((const ASN1_VALUE *)a, out, \\
	ASN1_ITEM_rptr(stname)); \\
	}

#define IMPLEMENT_ASN1_DUP_FUNCTION (stname)\
	stname * stname##_dup(const stname *x) \\
	{ \\
	return ASN1_item_dup(ASN1_ITEM_rptr(stname), x); \\
	}

#define IMPLEMENT_ASN1_PRINT_FUNCTION (stname)\
	IMPLEMENT_ASN1_PRINT_FUNCTION_fname(stname, stname, stname)

#define IMPLEMENT_ASN1_PRINT_FUNCTION_fname (stname, itname, fname)\
	int fname##_print_ctx(BIO *out, const stname *x, int indent, \\
	const ASN1_PCTX *pctx) \\
	{ \\
	return ASN1_item_print(out, (const ASN1_VALUE *)x, indent, \\
	ASN1_ITEM_rptr(itname), pctx); \\
	}

#define IMPLEMENT_ASN1_FUNCTIONS_const (name) IMPLEMENT_ASN1_FUNCTIONS(name)

#define IMPLEMENT_ASN1_ENCODE_FUNCTIONS_const_fname (stname, itname, fname)\
	IMPLEMENT_ASN1_ENCODE_FUNCTIONS_fname(stname, itname, fname)

#define OPENSSL_ASYNC_H 

#define HEADER_ASYNC_H 

#define OSSL_ASYNC_FD HANDLE

#define OSSL_BAD_ASYNC_FD INVALID_HANDLE_VALUE

#define ASYNC_ERR 0

#define ASYNC_NO_JOBS 1

#define ASYNC_PAUSE 2

#define ASYNC_FINISH 3

#define ASYNC_STATUS_UNSUPPORTED 0

#define ASYNC_STATUS_ERR 1

#define ASYNC_STATUS_OK 2

#define ASYNC_STATUS_EAGAIN 3

#define OPENSSL_ASYNCERR_H 

#define ASYNC_R_FAILED_TO_SET_POOL 101

#define ASYNC_R_FAILED_TO_SWAP_CONTEXT 102

#define ASYNC_R_INIT_FAILED 105

#define ASYNC_R_INVALID_POOL_SIZE 103

#define OPENSSL_BIO_H 

#define HEADER_BIO_H 

#define BIO_TYPE_DESCRIPTOR 0x0100

#define BIO_TYPE_FILTER 0x0200

#define BIO_TYPE_SOURCE_SINK 0x0400

#define BIO_TYPE_NONE 0

#define BIO_TYPE_MEM ( 1|BIO_TYPE_SOURCE_SINK)

#define BIO_TYPE_FILE ( 2|BIO_TYPE_SOURCE_SINK)

#define BIO_TYPE_FD ( 4|BIO_TYPE_SOURCE_SINK|BIO_TYPE_DESCRIPTOR)

#define BIO_TYPE_SOCKET ( 5|BIO_TYPE_SOURCE_SINK|BIO_TYPE_DESCRIPTOR)

#define BIO_TYPE_NULL ( 6|BIO_TYPE_SOURCE_SINK)

#define BIO_TYPE_SSL ( 7|BIO_TYPE_FILTER)

#define BIO_TYPE_MD ( 8|BIO_TYPE_FILTER)

#define BIO_TYPE_BUFFER ( 9|BIO_TYPE_FILTER)

#define BIO_TYPE_CIPHER (10|BIO_TYPE_FILTER)

#define BIO_TYPE_BASE64 (11|BIO_TYPE_FILTER)

#define BIO_TYPE_CONNECT (12|BIO_TYPE_SOURCE_SINK|BIO_TYPE_DESCRIPTOR)

#define BIO_TYPE_ACCEPT (13|BIO_TYPE_SOURCE_SINK|BIO_TYPE_DESCRIPTOR)

#define BIO_TYPE_NBIO_TEST (16|BIO_TYPE_FILTER)

#define BIO_TYPE_NULL_FILTER (17|BIO_TYPE_FILTER)

#define BIO_TYPE_BIO (19|BIO_TYPE_SOURCE_SINK)

#define BIO_TYPE_LINEBUFFER (20|BIO_TYPE_FILTER)

#define BIO_TYPE_DGRAM (21|BIO_TYPE_SOURCE_SINK|BIO_TYPE_DESCRIPTOR)

#define BIO_TYPE_ASN1 (22|BIO_TYPE_FILTER)

#define BIO_TYPE_COMP (23|BIO_TYPE_FILTER)

#define BIO_TYPE_DGRAM_SCTP (24|BIO_TYPE_SOURCE_SINK|BIO_TYPE_DESCRIPTOR)

#define BIO_TYPE_CORE_TO_PROV (25|BIO_TYPE_SOURCE_SINK)

#define BIO_TYPE_DGRAM_PAIR (26|BIO_TYPE_SOURCE_SINK)

#define BIO_TYPE_DGRAM_MEM (27|BIO_TYPE_SOURCE_SINK)

#define BIO_TYPE_START 128

#define BIO_TYPE_MASK 0xFF

#define BIO_NOCLOSE 0x00

#define BIO_CLOSE 0x01

#define BIO_CTRL_RESET 1

#define BIO_CTRL_EOF 2

#define BIO_CTRL_INFO 3

#define BIO_CTRL_SET 4

#define BIO_CTRL_GET 5

#define BIO_CTRL_PUSH 6

#define BIO_CTRL_POP 7

#define BIO_CTRL_GET_CLOSE 8

#define BIO_CTRL_SET_CLOSE 9

#define BIO_CTRL_PENDING 10

#define BIO_CTRL_FLUSH 11

#define BIO_CTRL_DUP 12

#define BIO_CTRL_WPENDING 13

#define BIO_CTRL_SET_CALLBACK 14

#define BIO_CTRL_GET_CALLBACK 15

#define BIO_CTRL_PEEK 29

#define BIO_CTRL_SET_FILENAME 30

#define BIO_CTRL_DGRAM_CONNECT 31

#define BIO_CTRL_DGRAM_SET_CONNECTED 32

#define BIO_CTRL_DGRAM_SET_RECV_TIMEOUT 33

#define BIO_CTRL_DGRAM_GET_RECV_TIMEOUT 34

#define BIO_CTRL_DGRAM_SET_SEND_TIMEOUT 35

#define BIO_CTRL_DGRAM_GET_SEND_TIMEOUT 36

#define BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP 37

#define BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP 38

#define BIO_CTRL_DGRAM_MTU_DISCOVER 39

#define BIO_CTRL_DGRAM_QUERY_MTU 40

#define BIO_CTRL_DGRAM_GET_FALLBACK_MTU 47

#define BIO_CTRL_DGRAM_GET_MTU 41

#define BIO_CTRL_DGRAM_SET_MTU 42

#define BIO_CTRL_DGRAM_MTU_EXCEEDED 43

#define BIO_CTRL_DGRAM_GET_PEER 46

#define BIO_CTRL_DGRAM_SET_PEER 44

#define BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT 45

#define BIO_CTRL_DGRAM_SET_DONT_FRAG 48

#define BIO_CTRL_DGRAM_GET_MTU_OVERHEAD 49

#define BIO_CTRL_DGRAM_SCTP_SET_IN_HANDSHAKE 50

#define BIO_CTRL_DGRAM_SCTP_ADD_AUTH_KEY 51

#define BIO_CTRL_DGRAM_SCTP_NEXT_AUTH_KEY 52

#define BIO_CTRL_DGRAM_SCTP_AUTH_CCS_RCVD 53

#define BIO_CTRL_DGRAM_SCTP_GET_SNDINFO 60

#define BIO_CTRL_DGRAM_SCTP_SET_SNDINFO 61

#define BIO_CTRL_DGRAM_SCTP_GET_RCVINFO 62

#define BIO_CTRL_DGRAM_SCTP_SET_RCVINFO 63

#define BIO_CTRL_DGRAM_SCTP_GET_PRINFO 64

#define BIO_CTRL_DGRAM_SCTP_SET_PRINFO 65

#define BIO_CTRL_DGRAM_SCTP_SAVE_SHUTDOWN 70

#define BIO_CTRL_DGRAM_SET_PEEK_MODE 71

#define BIO_CTRL_GET_KTLS_SEND 73

#define BIO_CTRL_GET_KTLS_RECV 76

#define BIO_CTRL_DGRAM_SCTP_WAIT_FOR_DRY 77

#define BIO_CTRL_DGRAM_SCTP_MSG_WAITING 78

#define BIO_CTRL_SET_PREFIX 79

#define BIO_CTRL_SET_INDENT 80

#define BIO_CTRL_GET_INDENT 81

#define BIO_CTRL_DGRAM_GET_LOCAL_ADDR_CAP 82

#define BIO_CTRL_DGRAM_GET_LOCAL_ADDR_ENABLE 83

#define BIO_CTRL_DGRAM_SET_LOCAL_ADDR_ENABLE 84

#define BIO_CTRL_DGRAM_GET_EFFECTIVE_CAPS 85

#define BIO_CTRL_DGRAM_GET_CAPS 86

#define BIO_CTRL_DGRAM_SET_CAPS 87

#define BIO_CTRL_DGRAM_GET_NO_TRUNC 88

#define BIO_CTRL_DGRAM_SET_NO_TRUNC 89

#define BIO_CTRL_GET_RPOLL_DESCRIPTOR 91

#define BIO_CTRL_GET_WPOLL_DESCRIPTOR 92

#define BIO_CTRL_DGRAM_DETECT_PEER_ADDR 93

#define BIO_DGRAM_CAP_NONE 0U

#define BIO_DGRAM_CAP_HANDLES_SRC_ADDR (1U << 0)

#define BIO_DGRAM_CAP_HANDLES_DST_ADDR (1U << 1)

#define BIO_DGRAM_CAP_PROVIDES_SRC_ADDR (1U << 2)

#define BIO_DGRAM_CAP_PROVIDES_DST_ADDR (1U << 3)

#define BIO_get_ktls_send (b)\
	(BIO_ctrl(b, BIO_CTRL_GET_KTLS_SEND, 0, NULL) > 0)

#define BIO_get_ktls_recv (b)\
	(BIO_ctrl(b, BIO_CTRL_GET_KTLS_RECV, 0, NULL) > 0)

#define BIO_FP_READ 0x02

#define BIO_FP_WRITE 0x04

#define BIO_FP_APPEND 0x08

#define BIO_FP_TEXT 0x10

#define BIO_FLAGS_READ 0x01

#define BIO_FLAGS_WRITE 0x02

#define BIO_FLAGS_IO_SPECIAL 0x04

#define BIO_FLAGS_RWS (BIO_FLAGS_READ|BIO_FLAGS_WRITE|BIO_FLAGS_IO_SPECIAL)

#define BIO_FLAGS_SHOULD_RETRY 0x08

#define BIO_FLAGS_UPLINK 0

#define BIO_FLAGS_BASE64_NO_NL 0x100

#define BIO_FLAGS_MEM_RDONLY 0x200

#define BIO_FLAGS_NONCLEAR_RST 0x400

#define BIO_FLAGS_IN_EOF 0x800

#define BIO_get_flags (b) BIO_test_flags(b, ~(0x0))

#define BIO_set_retry_special (b)\
	BIO_set_flags(b, (BIO_FLAGS_IO_SPECIAL|BIO_FLAGS_SHOULD_RETRY))

#define BIO_set_retry_read (b)\
	BIO_set_flags(b, (BIO_FLAGS_READ|BIO_FLAGS_SHOULD_RETRY))

#define BIO_set_retry_write (b)\
	BIO_set_flags(b, (BIO_FLAGS_WRITE|BIO_FLAGS_SHOULD_RETRY))

#define BIO_clear_retry_flags (b)\
	BIO_clear_flags(b, (BIO_FLAGS_RWS|BIO_FLAGS_SHOULD_RETRY))

#define BIO_get_retry_flags (b)\
	BIO_test_flags(b, (BIO_FLAGS_RWS|BIO_FLAGS_SHOULD_RETRY))

#define BIO_should_read (a)              BIO_test_flags(a, BIO_FLAGS_READ)

#define BIO_should_write (a)             BIO_test_flags(a, BIO_FLAGS_WRITE)

#define BIO_should_io_special (a)        BIO_test_flags(a, BIO_FLAGS_IO_SPECIAL)

#define BIO_retry_type (a)               BIO_test_flags(a, BIO_FLAGS_RWS)

#define BIO_should_retry (a)             BIO_test_flags(a, BIO_FLAGS_SHOULD_RETRY)

#define BIO_RR_SSL_X509_LOOKUP 0x01

#define BIO_RR_CONNECT 0x02

#define BIO_RR_ACCEPT 0x03

#define BIO_CB_FREE 0x01

#define BIO_CB_READ 0x02

#define BIO_CB_WRITE 0x03

#define BIO_CB_PUTS 0x04

#define BIO_CB_GETS 0x05

#define BIO_CB_CTRL 0x06

#define BIO_CB_RECVMMSG 0x07

#define BIO_CB_SENDMMSG 0x08

#define BIO_CB_RETURN 0x80

#define BIO_CB_return (a) ((a)|BIO_CB_RETURN)

#define BIO_cb_pre (a)   (!((a)&BIO_CB_RETURN))

#define BIO_cb_post (a)  ((a)&BIO_CB_RETURN)

#define BIO_POLL_DESCRIPTOR_TYPE_NONE 0

#define BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD 1

#define BIO_POLL_DESCRIPTOR_TYPE_SSL 2

#define BIO_POLL_DESCRIPTOR_CUSTOM_START 8192

#define BIO_C_SET_CONNECT 100

#define BIO_C_DO_STATE_MACHINE 101

#define BIO_C_SET_NBIO 102

#define BIO_C_SET_FD 104

#define BIO_C_GET_FD 105

#define BIO_C_SET_FILE_PTR 106

#define BIO_C_GET_FILE_PTR 107

#define BIO_C_SET_FILENAME 108

#define BIO_C_SET_SSL 109

#define BIO_C_GET_SSL 110

#define BIO_C_SET_MD 111

#define BIO_C_GET_MD 112

#define BIO_C_GET_CIPHER_STATUS 113

#define BIO_C_SET_BUF_MEM 114

#define BIO_C_GET_BUF_MEM_PTR 115

#define BIO_C_GET_BUFF_NUM_LINES 116

#define BIO_C_SET_BUFF_SIZE 117

#define BIO_C_SET_ACCEPT 118

#define BIO_C_SSL_MODE 119

#define BIO_C_GET_MD_CTX 120

#define BIO_C_SET_BUFF_READ_DATA 122

#define BIO_C_GET_CONNECT 123

#define BIO_C_GET_ACCEPT 124

#define BIO_C_SET_SSL_RENEGOTIATE_BYTES 125

#define BIO_C_GET_SSL_NUM_RENEGOTIATES 126

#define BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT 127

#define BIO_C_FILE_SEEK 128

#define BIO_C_GET_CIPHER_CTX 129

#define BIO_C_SET_BUF_MEM_EOF_RETURN 130

#define BIO_C_SET_BIND_MODE 131

#define BIO_C_GET_BIND_MODE 132

#define BIO_C_FILE_TELL 133

#define BIO_C_GET_SOCKS 134

#define BIO_C_SET_SOCKS 135

#define BIO_C_SET_WRITE_BUF_SIZE 136

#define BIO_C_GET_WRITE_BUF_SIZE 137

#define BIO_C_MAKE_BIO_PAIR 138

#define BIO_C_DESTROY_BIO_PAIR 139

#define BIO_C_GET_WRITE_GUARANTEE 140

#define BIO_C_GET_READ_REQUEST 141

#define BIO_C_SHUTDOWN_WR 142

#define BIO_C_NREAD0 143

#define BIO_C_NREAD 144

#define BIO_C_NWRITE0 145

#define BIO_C_NWRITE 146

#define BIO_C_RESET_READ_REQUEST 147

#define BIO_C_SET_MD_CTX 148

#define BIO_C_SET_PREFIX 149

#define BIO_C_GET_PREFIX 150

#define BIO_C_SET_SUFFIX 151

#define BIO_C_GET_SUFFIX 152

#define BIO_C_SET_EX_ARG 153

#define BIO_C_GET_EX_ARG 154

#define BIO_C_SET_CONNECT_MODE 155

#define BIO_C_SET_TFO 156

#define BIO_C_SET_SOCK_TYPE 157

#define BIO_C_GET_SOCK_TYPE 158

#define BIO_C_GET_DGRAM_BIO 159

#define BIO_set_app_data (s,arg)         BIO_set_ex_data(s,0,arg)

#define BIO_get_app_data (s)             BIO_get_ex_data(s,0)

#define BIO_set_nbio (b,n)               BIO_ctrl(b,BIO_C_SET_NBIO,(n),NULL)

#define BIO_set_tfo (b,n)                BIO_ctrl(b,BIO_C_SET_TFO,(n),NULL)

#define BIO_FAMILY_IPV4 4

#define BIO_FAMILY_IPV6 6

#define BIO_FAMILY_IPANY 256

#define BIO_set_conn_hostname (b,name) BIO_ctrl(b,BIO_C_SET_CONNECT,0,\
	(char *)(name))

#define BIO_set_conn_port (b,port)     BIO_ctrl(b,BIO_C_SET_CONNECT,1,\
	(char *)(port))

#define BIO_set_conn_address (b,addr)  BIO_ctrl(b,BIO_C_SET_CONNECT,2,\
	(char *)(addr))

#define BIO_set_conn_ip_family (b,f)   BIO_int_ctrl(b,BIO_C_SET_CONNECT,3,f)

#define BIO_get_conn_hostname (b)      ((const char *)BIO_ptr_ctrl(b,BIO_C_GET_CONNECT,0))

#define BIO_get_conn_port (b)          ((const char *)BIO_ptr_ctrl(b,BIO_C_GET_CONNECT,1))

#define BIO_get_conn_address (b)       ((const BIO_ADDR *)BIO_ptr_ctrl(b,BIO_C_GET_CONNECT,2))

#define BIO_get_conn_ip_family (b)     BIO_ctrl(b,BIO_C_GET_CONNECT,3,NULL)

#define BIO_get_conn_mode (b)          BIO_ctrl(b,BIO_C_GET_CONNECT,4,NULL)

#define BIO_set_conn_mode (b,n)        BIO_ctrl(b,BIO_C_SET_CONNECT_MODE,(n),NULL)

#define BIO_set_sock_type (b,t)        BIO_ctrl(b,BIO_C_SET_SOCK_TYPE,(t),NULL)

#define BIO_get_sock_type (b)          BIO_ctrl(b,BIO_C_GET_SOCK_TYPE,0,NULL)

#define BIO_get0_dgram_bio (b, p)      BIO_ctrl(b,BIO_C_GET_DGRAM_BIO,0,(void *)(BIO **)(p))

#define BIO_set_accept_name (b,name)   BIO_ctrl(b,BIO_C_SET_ACCEPT,0,\
	(char *)(name))

#define BIO_set_accept_port (b,port)   BIO_ctrl(b,BIO_C_SET_ACCEPT,1,\
	(char *)(port))

#define BIO_get_accept_name (b)        ((const char *)BIO_ptr_ctrl(b,BIO_C_GET_ACCEPT,0))

#define BIO_get_accept_port (b)        ((const char *)BIO_ptr_ctrl(b,BIO_C_GET_ACCEPT,1))

#define BIO_get_peer_name (b)          ((const char *)BIO_ptr_ctrl(b,BIO_C_GET_ACCEPT,2))

#define BIO_get_peer_port (b)          ((const char *)BIO_ptr_ctrl(b,BIO_C_GET_ACCEPT,3))

#define BIO_set_nbio_accept (b,n)      BIO_ctrl(b,BIO_C_SET_ACCEPT,2,(n)?(void *)"a":NULL)

#define BIO_set_accept_bios (b,bio)    BIO_ctrl(b,BIO_C_SET_ACCEPT,3,\
	(char *)(bio))

#define BIO_set_accept_ip_family (b,f) BIO_int_ctrl(b,BIO_C_SET_ACCEPT,4,f)

#define BIO_get_accept_ip_family (b)   BIO_ctrl(b,BIO_C_GET_ACCEPT,4,NULL)

#define BIO_set_tfo_accept (b,n)       BIO_ctrl(b,BIO_C_SET_ACCEPT,5,(n)?(void *)"a":NULL)

#define BIO_BIND_NORMAL 0

#define BIO_BIND_REUSEADDR BIO_SOCK_REUSEADDR

#define BIO_BIND_REUSEADDR_IF_UNUSED BIO_SOCK_REUSEADDR

#define BIO_set_bind_mode (b,mode) BIO_ctrl(b,BIO_C_SET_BIND_MODE,mode,NULL)

#define BIO_get_bind_mode (b)    BIO_ctrl(b,BIO_C_GET_BIND_MODE,0,NULL)

#define BIO_do_connect (b)       BIO_do_handshake(b)

#define BIO_do_accept (b)        BIO_do_handshake(b)

#define BIO_do_handshake (b)     BIO_ctrl(b,BIO_C_DO_STATE_MACHINE,0,NULL)

#define BIO_set_fd (b,fd,c)      BIO_int_ctrl(b,BIO_C_SET_FD,c,fd)

#define BIO_get_fd (b,c)         BIO_ctrl(b,BIO_C_GET_FD,0,(char *)(c))

#define BIO_set_fp (b,fp,c)      BIO_ctrl(b,BIO_C_SET_FILE_PTR,c,(char *)(fp))

#define BIO_get_fp (b,fpp)       BIO_ctrl(b,BIO_C_GET_FILE_PTR,0,(char *)(fpp))

#define BIO_seek (b,ofs) (int)BIO_ctrl(b,BIO_C_FILE_SEEK,ofs,NULL)

#define BIO_tell (b)     (int)BIO_ctrl(b,BIO_C_FILE_TELL,0,NULL)

// #define BIO_read_filename (b,name) (int)BIO_ctrl(b,BIO_C_SET_FILENAME,\
// 	BIO_CLOSE|BIO_FP_READ,(char *)(name))

#define BIO_write_filename (b,name) (int)BIO_ctrl(b,BIO_C_SET_FILENAME,\
	BIO_CLOSE|BIO_FP_WRITE,name)

#define BIO_append_filename (b,name) (int)BIO_ctrl(b,BIO_C_SET_FILENAME,\
	BIO_CLOSE|BIO_FP_APPEND,name)

#define BIO_rw_filename (b,name) (int)BIO_ctrl(b,BIO_C_SET_FILENAME,\
	BIO_CLOSE|BIO_FP_READ|BIO_FP_WRITE,name)

#define BIO_set_ssl (b,ssl,c)    BIO_ctrl(b,BIO_C_SET_SSL,c,(char *)(ssl))

#define BIO_get_ssl (b,sslp)     BIO_ctrl(b,BIO_C_GET_SSL,0,(char *)(sslp))

#define BIO_set_ssl_mode (b,client)      BIO_ctrl(b,BIO_C_SSL_MODE,client,NULL)

#define BIO_set_ssl_renegotiate_bytes (b,num)\
	BIO_ctrl(b,BIO_C_SET_SSL_RENEGOTIATE_BYTES,num,NULL)

#define BIO_get_num_renegotiates (b)\
	BIO_ctrl(b,BIO_C_GET_SSL_NUM_RENEGOTIATES,0,NULL)

#define BIO_set_ssl_renegotiate_timeout (b,seconds)\
	BIO_ctrl(b,BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT,seconds,NULL)

#define BIO_get_mem_data (b,pp)  BIO_ctrl(b,BIO_CTRL_INFO,0,(char *)(pp))

#define BIO_set_mem_buf (b,bm,c) BIO_ctrl(b,BIO_C_SET_BUF_MEM,c,(char *)(bm))

#define BIO_get_mem_ptr (b,pp)   BIO_ctrl(b,BIO_C_GET_BUF_MEM_PTR,0,\
	(char *)(pp))

#define BIO_set_mem_eof_return (b,v)\
	BIO_ctrl(b,BIO_C_SET_BUF_MEM_EOF_RETURN,v,NULL)

#define BIO_get_buffer_num_lines (b)     BIO_ctrl(b,BIO_C_GET_BUFF_NUM_LINES,0,NULL)

#define BIO_set_buffer_size (b,size)     BIO_ctrl(b,BIO_C_SET_BUFF_SIZE,size,NULL)

#define BIO_set_read_buffer_size (b,size) BIO_int_ctrl(b,BIO_C_SET_BUFF_SIZE,size,0)

#define BIO_set_write_buffer_size (b,size) BIO_int_ctrl(b,BIO_C_SET_BUFF_SIZE,size,1)

#define BIO_set_buffer_read_data (b,buf,num) BIO_ctrl(b,BIO_C_SET_BUFF_READ_DATA,num,buf)

#define BIO_dup_state (b,ret)    BIO_ctrl(b,BIO_CTRL_DUP,0,(char *)(ret))

#define BIO_reset (b)            (int)BIO_ctrl(b,BIO_CTRL_RESET,0,NULL)

#define BIO_eof (b)              (int)BIO_ctrl(b,BIO_CTRL_EOF,0,NULL)

#define BIO_set_close (b,c)      (int)BIO_ctrl(b,BIO_CTRL_SET_CLOSE,(c),NULL)

#define BIO_get_close (b)        (int)BIO_ctrl(b,BIO_CTRL_GET_CLOSE,0,NULL)

#define BIO_pending (b)          (int)BIO_ctrl(b,BIO_CTRL_PENDING,0,NULL)

#define BIO_wpending (b)         (int)BIO_ctrl(b,BIO_CTRL_WPENDING,0,NULL)

#define BIO_flush (b)            (int)BIO_ctrl(b,BIO_CTRL_FLUSH,0,NULL)

#define BIO_get_info_callback (b,cbp) (int)BIO_ctrl(b,BIO_CTRL_GET_CALLBACK,0,\
	cbp)

#define BIO_set_info_callback (b,cb) (int)BIO_callback_ctrl(b,BIO_CTRL_SET_CALLBACK,cb)

#define BIO_buffer_get_num_lines (b) BIO_ctrl(b,BIO_CTRL_GET,0,NULL)

#define BIO_buffer_peek (b,s,l) BIO_ctrl(b,BIO_CTRL_PEEK,(l),(s))

#define BIO_set_write_buf_size (b,size) (int)BIO_ctrl(b,BIO_C_SET_WRITE_BUF_SIZE,size,NULL)

#define BIO_get_write_buf_size (b,size) (size_t)BIO_ctrl(b,BIO_C_GET_WRITE_BUF_SIZE,size,NULL)

#define BIO_make_bio_pair (b1,b2)   (int)BIO_ctrl(b1,BIO_C_MAKE_BIO_PAIR,0,b2)

#define BIO_destroy_bio_pair (b)    (int)BIO_ctrl(b,BIO_C_DESTROY_BIO_PAIR,0,NULL)

#define BIO_shutdown_wr (b) (int)BIO_ctrl(b, BIO_C_SHUTDOWN_WR, 0, NULL)

#define BIO_get_write_guarantee (b) (int)BIO_ctrl(b,BIO_C_GET_WRITE_GUARANTEE,0,NULL)

#define BIO_get_read_request (b)    (int)BIO_ctrl(b,BIO_C_GET_READ_REQUEST,0,NULL)

#define BIO_ctrl_dgram_connect (b,peer)\
	(int)BIO_ctrl(b,BIO_CTRL_DGRAM_CONNECT,0, (char *)(peer))

#define BIO_ctrl_set_connected (b,peer)\
	(int)BIO_ctrl(b, BIO_CTRL_DGRAM_SET_CONNECTED, 0, (char *)(peer))

#define BIO_dgram_recv_timedout (b)\
	(int)BIO_ctrl(b, BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP, 0, NULL)

#define BIO_dgram_send_timedout (b)\
	(int)BIO_ctrl(b, BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP, 0, NULL)

#define BIO_dgram_get_peer (b,peer)\
	(int)BIO_ctrl(b, BIO_CTRL_DGRAM_GET_PEER, 0, (char *)(peer))

#define BIO_dgram_set_peer (b,peer)\
	(int)BIO_ctrl(b, BIO_CTRL_DGRAM_SET_PEER, 0, (char *)(peer))

#define BIO_dgram_detect_peer_addr (b,peer)\
	(int)BIO_ctrl(b, BIO_CTRL_DGRAM_DETECT_PEER_ADDR, 0, (char *)(peer))

#define BIO_dgram_get_mtu_overhead (b)\
	(unsigned int)BIO_ctrl((b), BIO_CTRL_DGRAM_GET_MTU_OVERHEAD, 0, NULL)

#define BIO_dgram_get_local_addr_cap (b)\
	(int)BIO_ctrl((b), BIO_CTRL_DGRAM_GET_LOCAL_ADDR_CAP, 0, NULL)

#define BIO_dgram_get_local_addr_enable (b, penable)\
	(int)BIO_ctrl((b), BIO_CTRL_DGRAM_GET_LOCAL_ADDR_ENABLE, 0, (char *)(penable))

#define BIO_dgram_set_local_addr_enable (b, enable)\
	(int)BIO_ctrl((b), BIO_CTRL_DGRAM_SET_LOCAL_ADDR_ENABLE, (enable), NULL)

#define BIO_dgram_get_effective_caps (b)\
	(uint32_t)BIO_ctrl((b), BIO_CTRL_DGRAM_GET_EFFECTIVE_CAPS, 0, NULL)

#define BIO_dgram_get_caps (b)\
	(uint32_t)BIO_ctrl((b), BIO_CTRL_DGRAM_GET_CAPS, 0, NULL)

#define BIO_dgram_set_caps (b, caps)\
	(int)BIO_ctrl((b), BIO_CTRL_DGRAM_SET_CAPS, (long)(caps), NULL)

#define BIO_dgram_get_no_trunc (b)\
	(unsigned int)BIO_ctrl((b), BIO_CTRL_DGRAM_GET_NO_TRUNC, 0, NULL)

#define BIO_dgram_set_no_trunc (b, enable)\
	(int)BIO_ctrl((b), BIO_CTRL_DGRAM_SET_NO_TRUNC, (enable), NULL)

#define BIO_dgram_get_mtu (b)\
	(unsigned int)BIO_ctrl((b), BIO_CTRL_DGRAM_GET_MTU, 0, NULL)

#define BIO_dgram_set_mtu (b, mtu)\
	(int)BIO_ctrl((b), BIO_CTRL_DGRAM_SET_MTU, (mtu), NULL)

#define BIO_set_prefix (b,p) BIO_ctrl((b), BIO_CTRL_SET_PREFIX, 0, (void *)(p))

#define BIO_set_indent (b,i) BIO_ctrl((b), BIO_CTRL_SET_INDENT, (i), NULL)

#define BIO_get_indent (b) BIO_ctrl((b), BIO_CTRL_GET_INDENT, 0, NULL)

#define BIO_get_ex_new_index (l, p, newf, dupf, freef)\
	CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_BIO, l, p, newf, dupf, freef)

#define BIO_sock_cleanup () while(0) continue

#define BIO_SOCK_REUSEADDR 0x01

#define BIO_SOCK_V6_ONLY 0x02

#define BIO_SOCK_KEEPALIVE 0x04

#define BIO_SOCK_NONBLOCK 0x08

#define BIO_SOCK_NODELAY 0x10

#define BIO_SOCK_TFO 0x20

#define ossl_bio__attr__ (x)

#define ossl_bio__printf__ __gnu_printf__

#define OPENSSL_BIOERR_H 

#define BIO_R_ACCEPT_ERROR 100

#define BIO_R_ADDRINFO_ADDR_IS_NOT_AF_INET 141

#define BIO_R_AMBIGUOUS_HOST_OR_SERVICE 129

#define BIO_R_BAD_FOPEN_MODE 101

#define BIO_R_BROKEN_PIPE 124

#define BIO_R_CONNECT_ERROR 103

#define BIO_R_CONNECT_TIMEOUT 147

#define BIO_R_GETHOSTBYNAME_ADDR_IS_NOT_AF_INET 107

#define BIO_R_GETSOCKNAME_ERROR 132

#define BIO_R_GETSOCKNAME_TRUNCATED_ADDRESS 133

#define BIO_R_GETTING_SOCKTYPE 134

#define BIO_R_INVALID_ARGUMENT 125

#define BIO_R_INVALID_SOCKET 135

#define BIO_R_IN_USE 123

#define BIO_R_LENGTH_TOO_LONG 102

#define BIO_R_LISTEN_V6_ONLY 136

#define BIO_R_LOCAL_ADDR_NOT_AVAILABLE 111

#define BIO_R_LOOKUP_RETURNED_NOTHING 142

#define BIO_R_MALFORMED_HOST_OR_SERVICE 130

#define BIO_R_NBIO_CONNECT_ERROR 110

#define BIO_R_NON_FATAL 112

#define BIO_R_NO_ACCEPT_ADDR_OR_SERVICE_SPECIFIED 143

#define BIO_R_NO_HOSTNAME_OR_SERVICE_SPECIFIED 144

#define BIO_R_NO_PORT_DEFINED 113

#define BIO_R_NO_SUCH_FILE 128

#define BIO_R_NULL_PARAMETER 115

#define BIO_R_TFO_DISABLED 106

#define BIO_R_TFO_NO_KERNEL_SUPPORT 108

#define BIO_R_TRANSFER_ERROR 104

#define BIO_R_TRANSFER_TIMEOUT 105

#define BIO_R_UNABLE_TO_BIND_SOCKET 117

#define BIO_R_UNABLE_TO_CREATE_SOCKET 118

#define BIO_R_UNABLE_TO_KEEPALIVE 137

#define BIO_R_UNABLE_TO_LISTEN_SOCKET 119

#define BIO_R_UNABLE_TO_NODELAY 138

#define BIO_R_UNABLE_TO_REUSEADDR 139

#define BIO_R_UNABLE_TO_TFO 109

#define BIO_R_UNAVAILABLE_IP_FAMILY 145

#define BIO_R_UNINITIALIZED 120

#define BIO_R_UNKNOWN_INFO_TYPE 140

#define BIO_R_UNSUPPORTED_IP_FAMILY 146

#define BIO_R_UNSUPPORTED_METHOD 121

#define BIO_R_UNSUPPORTED_PROTOCOL_FAMILY 131

#define BIO_R_WRITE_TO_READ_ONLY_BIO 126

#define BIO_R_WSASTARTUP 122

#define BIO_R_PORT_MISMATCH 150

#define BIO_R_PEER_ADDR_NOT_AVAILABLE 151

#define OPENSSL_BLOWFISH_H 

#define HEADER_BLOWFISH_H 

#define BF_BLOCK 8

#define BF_ENCRYPT 1

#define BF_DECRYPT 0

#define BF_LONG unsigned int

#define BF_ROUNDS 16

#define OPENSSL_BN_H 

#define HEADER_BN_H 

#define BN_ULONG unsigned long

#define BN_BYTES 8

#define BN_BITS2 (BN_BYTES * 8)

#define BN_BITS (BN_BITS2 * 2)

#define BN_TBIT ((BN_ULONG)1 << (BN_BITS2 - 1))

#define BN_FLG_MALLOCED 0x01

#define BN_FLG_STATIC_DATA 0x02

#define BN_FLG_CONSTTIME 0x04

#define BN_FLG_SECURE 0x08

#define BN_FLG_EXP_CONSTTIME BN_FLG_CONSTTIME

#define BN_FLG_FREE 0x8000

#define BN_RAND_TOP_ANY -1

#define BN_RAND_TOP_ONE 0

#define BN_RAND_TOP_TWO 1

#define BN_RAND_BOTTOM_ANY 0

#define BN_RAND_BOTTOM_ODD 1

#define BN_prime_checks 0

#define BN_prime_checks_for_size (b) ((b) >= 3747 ?  3 :\
	(b) >=  1345 ?  4 : \\
	(b) >=  476 ?  5 : \\
	(b) >=  400 ?  6 : \\
	(b) >=  347 ?  7 : \\
	(b) >=  308 ?  8 : \\
	(b) >=  55  ? 27 : \\
	34)

#define BN_num_bytes (a) ((BN_num_bits(a)+7)/8)

#define BN_one (a)       (BN_set_word((a),1))

#define BN_zero (a)      BN_zero_ex(a)

#define BN_mod (rem,m,d,ctx) BN_div(NULL,(rem),(m),(d),(ctx))

#define BN_BLINDING_NO_UPDATE 0x00000001

#define BN_BLINDING_NO_RECREATE 0x00000002

#define BN_GF2m_sub (r, a, b) BN_GF2m_add(r, a, b)

#define BN_GF2m_cmp (a, b) BN_ucmp((a), (b))

#define get_rfc2409_prime_768 BN_get_rfc2409_prime_768

#define get_rfc2409_prime_1024 BN_get_rfc2409_prime_1024

#define get_rfc3526_prime_1536 BN_get_rfc3526_prime_1536

#define get_rfc3526_prime_2048 BN_get_rfc3526_prime_2048

#define get_rfc3526_prime_3072 BN_get_rfc3526_prime_3072

#define get_rfc3526_prime_4096 BN_get_rfc3526_prime_4096

#define get_rfc3526_prime_6144 BN_get_rfc3526_prime_6144

#define get_rfc3526_prime_8192 BN_get_rfc3526_prime_8192

#define OPENSSL_BNERR_H 

#define BN_R_ARG2_LT_ARG3 100

#define BN_R_BAD_RECIPROCAL 101

#define BN_R_BIGNUM_TOO_LONG 114

#define BN_R_BITS_TOO_SMALL 118

#define BN_R_CALLED_WITH_EVEN_MODULUS 102

#define BN_R_DIV_BY_ZERO 103

#define BN_R_ENCODING_ERROR 104

#define BN_R_EXPAND_ON_STATIC_BIGNUM_DATA 105

#define BN_R_INPUT_NOT_REDUCED 110

#define BN_R_INVALID_LENGTH 106

#define BN_R_INVALID_RANGE 115

#define BN_R_INVALID_SHIFT 119

#define BN_R_NOT_A_SQUARE 111

#define BN_R_NOT_INITIALIZED 107

#define BN_R_NO_INVERSE 108

#define BN_R_NO_PRIME_CANDIDATE 121

#define BN_R_NO_SOLUTION 116

#define BN_R_NO_SUITABLE_DIGEST 120

#define BN_R_PRIVATE_KEY_TOO_LARGE 117

#define BN_R_P_IS_NOT_PRIME 112

#define BN_R_TOO_MANY_ITERATIONS 113

#define BN_R_TOO_MANY_TEMPORARY_VARIABLES 109

#define OPENSSL_BUFFER_H 

#define HEADER_BUFFER_H 

#define BUF_strdup (s) OPENSSL_strdup(s)

#define BUF_strndup (s, size) OPENSSL_strndup(s, size)

#define BUF_memdup (data, size) OPENSSL_memdup(data, size)

#define BUF_strlcpy (dst, src, size)  OPENSSL_strlcpy(dst, src, size)

#define BUF_strlcat (dst, src, size) OPENSSL_strlcat(dst, src, size)

#define BUF_strnlen (str, maxlen) OPENSSL_strnlen(str, maxlen)

#define BUF_MEM_FLAG_SECURE 0x01

#define OPENSSL_BUFFERERR_H 

#define OPENSSL_CAMELLIA_H 

#define HEADER_CAMELLIA_H 

#define CAMELLIA_BLOCK_SIZE 16

#define CAMELLIA_ENCRYPT 1

#define CAMELLIA_DECRYPT 0

#define CAMELLIA_TABLE_BYTE_LEN 272

#define CAMELLIA_TABLE_WORD_LEN (CAMELLIA_TABLE_BYTE_LEN / 4)

#define OPENSSL_CAST_H 

#define HEADER_CAST_H 

#define CAST_BLOCK 8

#define CAST_KEY_LENGTH 16

#define CAST_ENCRYPT 1

#define CAST_DECRYPT 0

#define CAST_LONG unsigned int

#define OPENSSL_CMAC_H 

#define HEADER_CMAC_H 

#define OPENSSL_CMP_H 

#define OSSL_CMP_PVNO_2 2

#define OSSL_CMP_PVNO_3 3

#define OSSL_CMP_PVNO OSSL_CMP_PVNO_2

#define OSSL_CMP_PKIFAILUREINFO_badAlg 0

#define OSSL_CMP_PKIFAILUREINFO_badMessageCheck 1

#define OSSL_CMP_PKIFAILUREINFO_badRequest 2

#define OSSL_CMP_PKIFAILUREINFO_badTime 3

#define OSSL_CMP_PKIFAILUREINFO_badCertId 4

#define OSSL_CMP_PKIFAILUREINFO_badDataFormat 5

#define OSSL_CMP_PKIFAILUREINFO_wrongAuthority 6

#define OSSL_CMP_PKIFAILUREINFO_incorrectData 7

#define OSSL_CMP_PKIFAILUREINFO_missingTimeStamp 8

#define OSSL_CMP_PKIFAILUREINFO_badPOP 9

#define OSSL_CMP_PKIFAILUREINFO_certRevoked 10

#define OSSL_CMP_PKIFAILUREINFO_certConfirmed 11

#define OSSL_CMP_PKIFAILUREINFO_wrongIntegrity 12

#define OSSL_CMP_PKIFAILUREINFO_badRecipientNonce 13

#define OSSL_CMP_PKIFAILUREINFO_timeNotAvailable 14

#define OSSL_CMP_PKIFAILUREINFO_unacceptedPolicy 15

#define OSSL_CMP_PKIFAILUREINFO_unacceptedExtension 16

#define OSSL_CMP_PKIFAILUREINFO_addInfoNotAvailable 17

#define OSSL_CMP_PKIFAILUREINFO_badSenderNonce 18

#define OSSL_CMP_PKIFAILUREINFO_badCertTemplate 19

#define OSSL_CMP_PKIFAILUREINFO_signerNotTrusted 20

#define OSSL_CMP_PKIFAILUREINFO_transactionIdInUse 21

#define OSSL_CMP_PKIFAILUREINFO_unsupportedVersion 22

#define OSSL_CMP_PKIFAILUREINFO_notAuthorized 23

#define OSSL_CMP_PKIFAILUREINFO_systemUnavail 24

#define OSSL_CMP_PKIFAILUREINFO_systemFailure 25

#define OSSL_CMP_PKIFAILUREINFO_duplicateCertReq 26

#define OSSL_CMP_PKIFAILUREINFO_MAX 26

#define OSSL_CMP_PKIFAILUREINFO_MAX_BIT_PATTERN \
	((1 << (OSSL_CMP_PKIFAILUREINFO_MAX + 1)) - 1)

#define OSSL_CMP_CTX_FAILINFO_badAlg (1 << 0)

#define OSSL_CMP_CTX_FAILINFO_badMessageCheck (1 << 1)

#define OSSL_CMP_CTX_FAILINFO_badRequest (1 << 2)

#define OSSL_CMP_CTX_FAILINFO_badTime (1 << 3)

#define OSSL_CMP_CTX_FAILINFO_badCertId (1 << 4)

#define OSSL_CMP_CTX_FAILINFO_badDataFormat (1 << 5)

#define OSSL_CMP_CTX_FAILINFO_wrongAuthority (1 << 6)

#define OSSL_CMP_CTX_FAILINFO_incorrectData (1 << 7)

#define OSSL_CMP_CTX_FAILINFO_missingTimeStamp (1 << 8)

#define OSSL_CMP_CTX_FAILINFO_badPOP (1 << 9)

#define OSSL_CMP_CTX_FAILINFO_certRevoked (1 << 10)

#define OSSL_CMP_CTX_FAILINFO_certConfirmed (1 << 11)

#define OSSL_CMP_CTX_FAILINFO_wrongIntegrity (1 << 12)

#define OSSL_CMP_CTX_FAILINFO_badRecipientNonce (1 << 13)

#define OSSL_CMP_CTX_FAILINFO_timeNotAvailable (1 << 14)

#define OSSL_CMP_CTX_FAILINFO_unacceptedPolicy (1 << 15)

#define OSSL_CMP_CTX_FAILINFO_unacceptedExtension (1 << 16)

#define OSSL_CMP_CTX_FAILINFO_addInfoNotAvailable (1 << 17)

#define OSSL_CMP_CTX_FAILINFO_badSenderNonce (1 << 18)

#define OSSL_CMP_CTX_FAILINFO_badCertTemplate (1 << 19)

#define OSSL_CMP_CTX_FAILINFO_signerNotTrusted (1 << 20)

#define OSSL_CMP_CTX_FAILINFO_transactionIdInUse (1 << 21)

#define OSSL_CMP_CTX_FAILINFO_unsupportedVersion (1 << 22)

#define OSSL_CMP_CTX_FAILINFO_notAuthorized (1 << 23)

#define OSSL_CMP_CTX_FAILINFO_systemUnavail (1 << 24)

#define OSSL_CMP_CTX_FAILINFO_systemFailure (1 << 25)

#define OSSL_CMP_CTX_FAILINFO_duplicateCertReq (1 << 26)

#define OSSL_CMP_PKISTATUS_request -3

#define OSSL_CMP_PKISTATUS_trans -2

#define OSSL_CMP_PKISTATUS_unspecified -1

#define OSSL_CMP_PKISTATUS_accepted 0

#define OSSL_CMP_PKISTATUS_grantedWithMods 1

#define OSSL_CMP_PKISTATUS_rejection 2

#define OSSL_CMP_PKISTATUS_waiting 3

#define OSSL_CMP_PKISTATUS_revocationWarning 4

#define OSSL_CMP_PKISTATUS_revocationNotification 5

#define OSSL_CMP_PKISTATUS_keyUpdateWarning 6

#define OSSL_CMP_CERTORENCCERT_CERTIFICATE 0

#define OSSL_CMP_CERTORENCCERT_ENCRYPTEDCERT 1

#define OSSL_CMP_OPT_LOG_VERBOSITY 0

#define OSSL_CMP_OPT_KEEP_ALIVE 10

#define OSSL_CMP_OPT_MSG_TIMEOUT 11

#define OSSL_CMP_OPT_TOTAL_TIMEOUT 12

#define OSSL_CMP_OPT_USE_TLS 13

#define OSSL_CMP_OPT_VALIDITY_DAYS 20

#define OSSL_CMP_OPT_SUBJECTALTNAME_NODEFAULT 21

#define OSSL_CMP_OPT_SUBJECTALTNAME_CRITICAL 22

#define OSSL_CMP_OPT_POLICIES_CRITICAL 23

#define OSSL_CMP_OPT_POPO_METHOD 24

#define OSSL_CMP_OPT_IMPLICIT_CONFIRM 25

#define OSSL_CMP_OPT_DISABLE_CONFIRM 26

#define OSSL_CMP_OPT_REVOCATION_REASON 27

#define OSSL_CMP_OPT_UNPROTECTED_SEND 30

#define OSSL_CMP_OPT_UNPROTECTED_ERRORS 31

#define OSSL_CMP_OPT_OWF_ALGNID 32

#define OSSL_CMP_OPT_MAC_ALGNID 33

#define OSSL_CMP_OPT_DIGEST_ALGNID 34

#define OSSL_CMP_OPT_IGNORE_KEYUSAGE 35

#define OSSL_CMP_OPT_PERMIT_TA_IN_EXTRACERTS_FOR_IR 36

#define OSSL_CMP_OPT_NO_CACHE_EXTRACERTS 37

#define OSSL_CMP_CTX_set_log_verbosity (ctx, level)\
	OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_LOG_VERBOSITY, level)

#define OSSL_CMP_CTX_set0_trusted OSSL_CMP_CTX_set0_trustedStore

#define OSSL_CMP_CTX_get0_trusted OSSL_CMP_CTX_get0_trustedStore

#define OSSL_CMP_PKISI_BUFLEN 1024

#define OSSL_CMP_IR 0

#define OSSL_CMP_CR 2

#define OSSL_CMP_P10CR 4

#define OSSL_CMP_KUR 7

#define OSSL_CMP_GENM 21

#define OSSL_CMP_ERROR 23

#define OSSL_CMP_exec_IR_ses (ctx)\
	OSSL_CMP_exec_certreq(ctx, OSSL_CMP_IR, NULL)

#define OSSL_CMP_exec_CR_ses (ctx)\
	OSSL_CMP_exec_certreq(ctx, OSSL_CMP_CR, NULL)

#define OSSL_CMP_exec_P10CR_ses (ctx)\
	OSSL_CMP_exec_certreq(ctx, OSSL_CMP_P10CR, NULL)

#define OSSL_CMP_exec_KUR_ses (ctx)\
	OSSL_CMP_exec_certreq(ctx, OSSL_CMP_KUR, NULL)

#define OPENSSL_CMPERR_H 

#define CMP_R_ALGORITHM_NOT_SUPPORTED 139

#define CMP_R_BAD_CHECKAFTER_IN_POLLREP 167

#define CMP_R_BAD_REQUEST_ID 108

#define CMP_R_CERTHASH_UNMATCHED 156

#define CMP_R_CERTID_NOT_FOUND 109

#define CMP_R_CERTIFICATE_NOT_ACCEPTED 169

#define CMP_R_CERTIFICATE_NOT_FOUND 112

#define CMP_R_CERTREQMSG_NOT_FOUND 157

#define CMP_R_CERTRESPONSE_NOT_FOUND 113

#define CMP_R_CERT_AND_KEY_DO_NOT_MATCH 114

#define CMP_R_CHECKAFTER_OUT_OF_RANGE 181

#define CMP_R_ENCOUNTERED_KEYUPDATEWARNING 176

#define CMP_R_ENCOUNTERED_WAITING 162

#define CMP_R_ERROR_CALCULATING_PROTECTION 115

#define CMP_R_ERROR_CREATING_CERTCONF 116

#define CMP_R_ERROR_CREATING_CERTREP 117

#define CMP_R_ERROR_CREATING_CERTREQ 163

#define CMP_R_ERROR_CREATING_ERROR 118

#define CMP_R_ERROR_CREATING_GENM 119

#define CMP_R_ERROR_CREATING_GENP 120

#define CMP_R_ERROR_CREATING_PKICONF 122

#define CMP_R_ERROR_CREATING_POLLREP 123

#define CMP_R_ERROR_CREATING_POLLREQ 124

#define CMP_R_ERROR_CREATING_RP 125

#define CMP_R_ERROR_CREATING_RR 126

#define CMP_R_ERROR_PARSING_PKISTATUS 107

#define CMP_R_ERROR_PROCESSING_MESSAGE 158

#define CMP_R_ERROR_PROTECTING_MESSAGE 127

#define CMP_R_ERROR_SETTING_CERTHASH 128

#define CMP_R_ERROR_UNEXPECTED_CERTCONF 160

#define CMP_R_ERROR_VALIDATING_PROTECTION 140

#define CMP_R_ERROR_VALIDATING_SIGNATURE 171

#define CMP_R_EXPECTED_POLLREQ 104

#define CMP_R_FAILED_BUILDING_OWN_CHAIN 164

#define CMP_R_FAILED_EXTRACTING_PUBKEY 141

#define CMP_R_FAILURE_OBTAINING_RANDOM 110

#define CMP_R_FAIL_INFO_OUT_OF_RANGE 129

#define CMP_R_GETTING_GENP 192

#define CMP_R_INVALID_ARGS 100

#define CMP_R_INVALID_GENP 193

#define CMP_R_INVALID_OPTION 174

#define CMP_R_INVALID_ROOTCAKEYUPDATE 195

#define CMP_R_MISSING_CERTID 165

#define CMP_R_MISSING_KEY_INPUT_FOR_CREATING_PROTECTION 130

#define CMP_R_MISSING_KEY_USAGE_DIGITALSIGNATURE 142

#define CMP_R_MISSING_P10CSR 121

#define CMP_R_MISSING_PBM_SECRET 166

#define CMP_R_MISSING_PRIVATE_KEY 131

#define CMP_R_MISSING_PRIVATE_KEY_FOR_POPO 190

#define CMP_R_MISSING_PROTECTION 143

#define CMP_R_MISSING_PUBLIC_KEY 183

#define CMP_R_MISSING_REFERENCE_CERT 168

#define CMP_R_MISSING_SECRET 178

#define CMP_R_MISSING_SENDER_IDENTIFICATION 111

#define CMP_R_MISSING_TRUST_ANCHOR 179

#define CMP_R_MISSING_TRUST_STORE 144

#define CMP_R_MULTIPLE_REQUESTS_NOT_SUPPORTED 161

#define CMP_R_MULTIPLE_RESPONSES_NOT_SUPPORTED 170

#define CMP_R_MULTIPLE_SAN_SOURCES 102

#define CMP_R_NO_STDIO 194

#define CMP_R_NO_SUITABLE_SENDER_CERT 145

#define CMP_R_NULL_ARGUMENT 103

#define CMP_R_PKIBODY_ERROR 146

#define CMP_R_PKISTATUSINFO_NOT_FOUND 132

#define CMP_R_POLLING_FAILED 172

#define CMP_R_POTENTIALLY_INVALID_CERTIFICATE 147

#define CMP_R_RECEIVED_ERROR 180

#define CMP_R_RECIPNONCE_UNMATCHED 148

#define CMP_R_REQUEST_NOT_ACCEPTED 149

#define CMP_R_REQUEST_REJECTED_BY_SERVER 182

#define CMP_R_SENDER_GENERALNAME_TYPE_NOT_SUPPORTED 150

#define CMP_R_SRVCERT_DOES_NOT_VALIDATE_MSG 151

#define CMP_R_TOTAL_TIMEOUT 184

#define CMP_R_TRANSACTIONID_UNMATCHED 152

#define CMP_R_TRANSFER_ERROR 159

#define CMP_R_UNCLEAN_CTX 191

#define CMP_R_UNEXPECTED_CERTPROFILE 196

#define CMP_R_UNEXPECTED_PKIBODY 133

#define CMP_R_UNEXPECTED_PKISTATUS 185

#define CMP_R_UNEXPECTED_POLLREQ 105

#define CMP_R_UNEXPECTED_PVNO 153

#define CMP_R_UNEXPECTED_SENDER 106

#define CMP_R_UNKNOWN_ALGORITHM_ID 134

#define CMP_R_UNKNOWN_CERT_TYPE 135

#define CMP_R_UNKNOWN_PKISTATUS 186

#define CMP_R_UNSUPPORTED_ALGORITHM 136

#define CMP_R_UNSUPPORTED_KEY_TYPE 137

#define CMP_R_UNSUPPORTED_PKIBODY 101

#define CMP_R_UNSUPPORTED_PROTECTION_ALG_DHBASEDMAC 154

#define CMP_R_VALUE_TOO_LARGE 175

#define CMP_R_VALUE_TOO_SMALL 177

#define CMP_R_WRONG_ALGORITHM_OID 138

#define CMP_R_WRONG_CERTID 189

#define CMP_R_WRONG_CERTID_IN_RP 187

#define CMP_R_WRONG_PBM_VALUE 155

#define CMP_R_WRONG_RP_COMPONENT_COUNT 188

#define CMP_R_WRONG_SERIAL_IN_RP 173

#define OPENSSL_CMP_UTIL_H 

#define OSSL_CMP_LOG_PREFIX "CMP "

#define OSSL_CMP_LOG_EMERG 0

#define OSSL_CMP_LOG_ALERT 1

#define OSSL_CMP_LOG_CRIT 2

#define OSSL_CMP_LOG_ERR 3

#define OSSL_CMP_LOG_WARNING 4

#define OSSL_CMP_LOG_NOTICE 5

#define OSSL_CMP_LOG_INFO 6

#define OSSL_CMP_LOG_DEBUG 7

#define OSSL_CMP_LOG_TRACE 8

#define OSSL_CMP_LOG_MAX OSSL_CMP_LOG_TRACE

#define OPENSSL_CMS_H 

#define HEADER_CMS_H 

#define CMS_SIGNERINFO_ISSUER_SERIAL 0

#define CMS_SIGNERINFO_KEYIDENTIFIER 1

#define CMS_RECIPINFO_NONE -1

#define CMS_RECIPINFO_TRANS 0

#define CMS_RECIPINFO_AGREE 1

#define CMS_RECIPINFO_KEK 2

#define CMS_RECIPINFO_PASS 3

#define CMS_RECIPINFO_OTHER 4

#define CMS_TEXT 0x1

#define CMS_NOCERTS 0x2

#define CMS_NO_CONTENT_VERIFY 0x4

#define CMS_NO_ATTR_VERIFY 0x8

#define CMS_NOSIGS \
	(CMS_NO_CONTENT_VERIFY|CMS_NO_ATTR_VERIFY)

#define CMS_NOINTERN 0x10

#define CMS_NO_SIGNER_CERT_VERIFY 0x20

#define CMS_NOVERIFY 0x20

#define CMS_DETACHED 0x40

#define CMS_BINARY 0x80

#define CMS_NOATTR 0x100

#define CMS_NOSMIMECAP 0x200

#define CMS_NOOLDMIMETYPE 0x400

#define CMS_CRLFEOL 0x800

#define CMS_STREAM 0x1000

#define CMS_NOCRL 0x2000

#define CMS_PARTIAL 0x4000

#define CMS_REUSE_DIGEST 0x8000

#define CMS_USE_KEYID 0x10000

#define CMS_DEBUG_DECRYPT 0x20000

#define CMS_KEY_PARAM 0x40000

#define CMS_ASCIICRLF 0x80000

#define CMS_CADES 0x100000

#define CMS_USE_ORIGINATOR_KEYID 0x200000

#define CMS_R_UNKNOWN_DIGEST_ALGORITM CMS_R_UNKNOWN_DIGEST_ALGORITHM

#define CMS_R_UNSUPPORTED_RECPIENTINFO_TYPE \
	CMS_R_UNSUPPORTED_RECIPIENTINFO_TYPE

#define OPENSSL_CMSERR_H 

#define CMS_R_ADD_SIGNER_ERROR 99

#define CMS_R_ATTRIBUTE_ERROR 161

#define CMS_R_CERTIFICATE_ALREADY_PRESENT 175

#define CMS_R_CERTIFICATE_HAS_NO_KEYID 160

#define CMS_R_CERTIFICATE_VERIFY_ERROR 100

#define CMS_R_CIPHER_AEAD_SET_TAG_ERROR 184

#define CMS_R_CIPHER_GET_TAG 185

#define CMS_R_CIPHER_INITIALISATION_ERROR 101

#define CMS_R_CIPHER_PARAMETER_INITIALISATION_ERROR 102

#define CMS_R_CMS_DATAFINAL_ERROR 103

#define CMS_R_CMS_LIB 104

#define CMS_R_CONTENTIDENTIFIER_MISMATCH 170

#define CMS_R_CONTENT_NOT_FOUND 105

#define CMS_R_CONTENT_TYPE_MISMATCH 171

#define CMS_R_CONTENT_TYPE_NOT_COMPRESSED_DATA 106

#define CMS_R_CONTENT_TYPE_NOT_ENVELOPED_DATA 107

#define CMS_R_CONTENT_TYPE_NOT_SIGNED_DATA 108

#define CMS_R_CONTENT_VERIFY_ERROR 109

#define CMS_R_CTRL_ERROR 110

#define CMS_R_CTRL_FAILURE 111

#define CMS_R_DECODE_ERROR 187

#define CMS_R_DECRYPT_ERROR 112

#define CMS_R_ERROR_GETTING_PUBLIC_KEY 113

#define CMS_R_ERROR_READING_MESSAGEDIGEST_ATTRIBUTE 114

#define CMS_R_ERROR_SETTING_KEY 115

#define CMS_R_ERROR_SETTING_RECIPIENTINFO 116

#define CMS_R_ESS_SIGNING_CERTID_MISMATCH_ERROR 183

#define CMS_R_INVALID_ENCRYPTED_KEY_LENGTH 117

#define CMS_R_INVALID_KEY_ENCRYPTION_PARAMETER 176

#define CMS_R_INVALID_KEY_LENGTH 118

#define CMS_R_INVALID_LABEL 190

#define CMS_R_INVALID_OAEP_PARAMETERS 191

#define CMS_R_KDF_PARAMETER_ERROR 186

#define CMS_R_MD_BIO_INIT_ERROR 119

#define CMS_R_MESSAGEDIGEST_ATTRIBUTE_WRONG_LENGTH 120

#define CMS_R_MESSAGEDIGEST_WRONG_LENGTH 121

#define CMS_R_MSGSIGDIGEST_ERROR 172

#define CMS_R_MSGSIGDIGEST_VERIFICATION_FAILURE 162

#define CMS_R_MSGSIGDIGEST_WRONG_LENGTH 163

#define CMS_R_NEED_ONE_SIGNER 164

#define CMS_R_NOT_A_SIGNED_RECEIPT 165

#define CMS_R_NOT_ENCRYPTED_DATA 122

#define CMS_R_NOT_KEK 123

#define CMS_R_NOT_KEY_AGREEMENT 181

#define CMS_R_NOT_KEY_TRANSPORT 124

#define CMS_R_NOT_PWRI 177

#define CMS_R_NOT_SUPPORTED_FOR_THIS_KEY_TYPE 125

#define CMS_R_NO_CIPHER 126

#define CMS_R_NO_CONTENT 127

#define CMS_R_NO_CONTENT_TYPE 173

#define CMS_R_NO_DEFAULT_DIGEST 128

#define CMS_R_NO_DIGEST_SET 129

#define CMS_R_NO_KEY 130

#define CMS_R_NO_KEY_OR_CERT 174

#define CMS_R_NO_MATCHING_DIGEST 131

#define CMS_R_NO_MATCHING_RECIPIENT 132

#define CMS_R_NO_MATCHING_SIGNATURE 166

#define CMS_R_NO_MSGSIGDIGEST 167

#define CMS_R_NO_PASSWORD 178

#define CMS_R_NO_PRIVATE_KEY 133

#define CMS_R_NO_PUBLIC_KEY 134

#define CMS_R_NO_RECEIPT_REQUEST 168

#define CMS_R_NO_SIGNERS 135

#define CMS_R_OPERATION_UNSUPPORTED 182

#define CMS_R_PEER_KEY_ERROR 188

#define CMS_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE 136

#define CMS_R_RECEIPT_DECODE_ERROR 169

#define CMS_R_RECIPIENT_ERROR 137

#define CMS_R_SHARED_INFO_ERROR 189

#define CMS_R_SIGNER_CERTIFICATE_NOT_FOUND 138

#define CMS_R_SIGNFINAL_ERROR 139

#define CMS_R_SMIME_TEXT_ERROR 140

#define CMS_R_STORE_INIT_ERROR 141

#define CMS_R_TYPE_NOT_COMPRESSED_DATA 142

#define CMS_R_TYPE_NOT_DATA 143

#define CMS_R_TYPE_NOT_DIGESTED_DATA 144

#define CMS_R_TYPE_NOT_ENCRYPTED_DATA 145

#define CMS_R_TYPE_NOT_ENVELOPED_DATA 146

#define CMS_R_UNABLE_TO_FINALIZE_CONTEXT 147

#define CMS_R_UNKNOWN_CIPHER 148

#define CMS_R_UNKNOWN_DIGEST_ALGORITHM 149

#define CMS_R_UNKNOWN_ID 150

#define CMS_R_UNSUPPORTED_COMPRESSION_ALGORITHM 151

#define CMS_R_UNSUPPORTED_CONTENT_ENCRYPTION_ALGORITHM 194

#define CMS_R_UNSUPPORTED_CONTENT_TYPE 152

#define CMS_R_UNSUPPORTED_ENCRYPTION_TYPE 192

#define CMS_R_UNSUPPORTED_KEK_ALGORITHM 153

#define CMS_R_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM 179

#define CMS_R_UNSUPPORTED_LABEL_SOURCE 193

#define CMS_R_UNSUPPORTED_RECIPIENTINFO_TYPE 155

#define CMS_R_UNSUPPORTED_RECIPIENT_TYPE 154

#define CMS_R_UNSUPPORTED_SIGNATURE_ALGORITHM 195

#define CMS_R_UNSUPPORTED_TYPE 156

#define CMS_R_UNWRAP_ERROR 157

#define CMS_R_UNWRAP_FAILURE 180

#define CMS_R_VERIFICATION_FAILURE 158

#define CMS_R_WRAP_ERROR 159

#define OPENSSL_COMP_H 

#define HEADER_COMP_H 

#define COMP_zlib_cleanup () while(0) continue

#define OPENSSL_COMPERR_H 

#define COMP_R_BROTLI_DECODE_ERROR 102

#define COMP_R_BROTLI_ENCODE_ERROR 103

#define COMP_R_BROTLI_NOT_SUPPORTED 104

#define COMP_R_ZLIB_DEFLATE_ERROR 99

#define COMP_R_ZLIB_INFLATE_ERROR 100

#define COMP_R_ZLIB_NOT_SUPPORTED 101

#define COMP_R_ZSTD_COMPRESS_ERROR 105

#define COMP_R_ZSTD_DECODE_ERROR 106

#define COMP_R_ZSTD_DECOMPRESS_ERROR 107

#define COMP_R_ZSTD_NOT_SUPPORTED 108

#define OPENSSL_CONF_H 

#define HEADER_CONF_H 

#define CONF_MFLAGS_IGNORE_ERRORS 0x1

#define CONF_MFLAGS_IGNORE_RETURN_CODES 0x2

#define CONF_MFLAGS_SILENT 0x4

#define CONF_MFLAGS_NO_DSO 0x8

#define CONF_MFLAGS_IGNORE_MISSING_FILE 0x10

#define CONF_MFLAGS_DEFAULT_SECTION 0x20

#define OPENSSL_no_config ()\
	OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL)

#define NCONF_get_number (c,g,n,r) NCONF_get_number_e(c,g,n,r)

#define CONF_modules_free () while(0) continue

#define OPENSSL_CONFERR_H 

#define CONF_R_ERROR_LOADING_DSO 110

#define CONF_R_INVALID_PRAGMA 122

#define CONF_R_LIST_CANNOT_BE_NULL 115

#define CONF_R_MANDATORY_BRACES_IN_VARIABLE_EXPANSION 123

#define CONF_R_MISSING_CLOSE_SQUARE_BRACKET 100

#define CONF_R_MISSING_EQUAL_SIGN 101

#define CONF_R_MISSING_INIT_FUNCTION 112

#define CONF_R_MODULE_INITIALIZATION_ERROR 109

#define CONF_R_NO_CLOSE_BRACE 102

#define CONF_R_NO_CONF 105

#define CONF_R_NO_CONF_OR_ENVIRONMENT_VARIABLE 106

#define CONF_R_NO_SECTION 107

#define CONF_R_NO_SUCH_FILE 114

#define CONF_R_NO_VALUE 108

#define CONF_R_NUMBER_TOO_LARGE 121

#define CONF_R_OPENSSL_CONF_REFERENCES_MISSING_SECTION 124

#define CONF_R_RECURSIVE_DIRECTORY_INCLUDE 111

#define CONF_R_RECURSIVE_SECTION_REFERENCE 126

#define CONF_R_RELATIVE_PATH 125

#define CONF_R_SSL_COMMAND_SECTION_EMPTY 117

#define CONF_R_SSL_COMMAND_SECTION_NOT_FOUND 118

#define CONF_R_SSL_SECTION_EMPTY 119

#define CONF_R_SSL_SECTION_NOT_FOUND 120

#define CONF_R_UNABLE_TO_CREATE_NEW_SECTION 103

#define CONF_R_UNKNOWN_MODULE_NAME 113

#define CONF_R_VARIABLE_EXPANSION_TOO_LONG 116

#define CONF_R_VARIABLE_HAS_NO_VALUE 104

#define OPENSSL_CONFIGURATION_H 

#define RC4_INT int

#define OPENSSL_NO_COMP_ALG 

#define OPENSSL_CONFTYPES_H 

#define OPENSSL_CONF_API_H 

#define HEADER_CONF_API_H 

#define OPENSSL_CORE_H 

#define OSSL_DISPATCH_END \
	{ 0, NULL }

#define OSSL_PARAM_INTEGER 1

#define OSSL_PARAM_UNSIGNED_INTEGER 2

#define OSSL_PARAM_REAL 3

#define OSSL_PARAM_UTF8_STRING 4

#define OSSL_PARAM_OCTET_STRING 5

#define OSSL_PARAM_UTF8_PTR 6

#define OSSL_PARAM_OCTET_PTR 7

#define OPENSSL_CORE_NUMBERS_H 

#define OSSL_CORE_MAKE_FUNC (type,name,args)\
	typedef type (OSSL_FUNC_##name##_fn)args;                           \\
	static ossl_unused ossl_inline \\
	OSSL_FUNC_##name##_fn *OSSL_FUNC_##name(const OSSL_DISPATCH *opf)   \\
	{                                                                   \\
	return (OSSL_FUNC_##name##_fn *)opf->function;                  \\
	}

#define OSSL_FUNC_CORE_GETTABLE_PARAMS 1

#define OSSL_FUNC_CORE_GET_PARAMS 2

#define OSSL_FUNC_CORE_THREAD_START 3

#define OSSL_FUNC_CORE_GET_LIBCTX 4

#define OSSL_FUNC_CORE_NEW_ERROR 5

#define OSSL_FUNC_CORE_SET_ERROR_DEBUG 6

#define OSSL_FUNC_CORE_VSET_ERROR 7

#define OSSL_FUNC_CORE_SET_ERROR_MARK 8

#define OSSL_FUNC_CORE_CLEAR_LAST_ERROR_MARK 9

#define OSSL_FUNC_CORE_POP_ERROR_TO_MARK 10

#define OSSL_FUNC_CORE_OBJ_ADD_SIGID 11

#define OSSL_FUNC_CORE_OBJ_CREATE 12

#define OSSL_FUNC_CRYPTO_MALLOC 20

#define OSSL_FUNC_CRYPTO_ZALLOC 21

#define OSSL_FUNC_CRYPTO_FREE 22

#define OSSL_FUNC_CRYPTO_CLEAR_FREE 23

#define OSSL_FUNC_CRYPTO_REALLOC 24

#define OSSL_FUNC_CRYPTO_CLEAR_REALLOC 25

#define OSSL_FUNC_CRYPTO_SECURE_MALLOC 26

#define OSSL_FUNC_CRYPTO_SECURE_ZALLOC 27

#define OSSL_FUNC_CRYPTO_SECURE_FREE 28

#define OSSL_FUNC_CRYPTO_SECURE_CLEAR_FREE 29

#define OSSL_FUNC_CRYPTO_SECURE_ALLOCATED 30

#define OSSL_FUNC_OPENSSL_CLEANSE 31

#define OSSL_FUNC_BIO_NEW_FILE 40

#define OSSL_FUNC_BIO_NEW_MEMBUF 41

#define OSSL_FUNC_BIO_READ_EX 42

#define OSSL_FUNC_BIO_WRITE_EX 43

#define OSSL_FUNC_BIO_UP_REF 44

#define OSSL_FUNC_BIO_FREE 45

#define OSSL_FUNC_BIO_VPRINTF 46

#define OSSL_FUNC_BIO_VSNPRINTF 47

#define OSSL_FUNC_BIO_PUTS 48

#define OSSL_FUNC_BIO_GETS 49

#define OSSL_FUNC_BIO_CTRL 50

#define OSSL_FUNC_CLEANUP_USER_ENTROPY 96

#define OSSL_FUNC_CLEANUP_USER_NONCE 97

#define OSSL_FUNC_GET_USER_ENTROPY 98

#define OSSL_FUNC_GET_USER_NONCE 99

#define OSSL_FUNC_SELF_TEST_CB 100

#define OSSL_FUNC_GET_ENTROPY 101

#define OSSL_FUNC_CLEANUP_ENTROPY 102

#define OSSL_FUNC_GET_NONCE 103

#define OSSL_FUNC_CLEANUP_NONCE 104

#define OSSL_FUNC_PROVIDER_REGISTER_CHILD_CB 105

#define OSSL_FUNC_PROVIDER_DEREGISTER_CHILD_CB 106

#define OSSL_FUNC_PROVIDER_NAME 107

#define OSSL_FUNC_PROVIDER_GET0_PROVIDER_CTX 108

#define OSSL_FUNC_PROVIDER_GET0_DISPATCH 109

#define OSSL_FUNC_PROVIDER_UP_REF 110

#define OSSL_FUNC_PROVIDER_FREE 111

#define OSSL_FUNC_PROVIDER_TEARDOWN 1024

#define OSSL_FUNC_PROVIDER_GETTABLE_PARAMS 1025

#define OSSL_FUNC_PROVIDER_GET_PARAMS 1026

#define OSSL_FUNC_PROVIDER_QUERY_OPERATION 1027

#define OSSL_FUNC_PROVIDER_UNQUERY_OPERATION 1028

#define OSSL_FUNC_PROVIDER_GET_REASON_STRINGS 1029

#define OSSL_FUNC_PROVIDER_GET_CAPABILITIES 1030

#define OSSL_FUNC_PROVIDER_SELF_TEST 1031

#define OSSL_OP_DIGEST 1

#define OSSL_OP_CIPHER 2

#define OSSL_OP_MAC 3

#define OSSL_OP_KDF 4

#define OSSL_OP_RAND 5

#define OSSL_OP_KEYMGMT 10

#define OSSL_OP_KEYEXCH 11

#define OSSL_OP_SIGNATURE 12

#define OSSL_OP_ASYM_CIPHER 13

#define OSSL_OP_KEM 14

#define OSSL_OP_ENCODER 20

#define OSSL_OP_DECODER 21

#define OSSL_OP_STORE 22

#define OSSL_OP__HIGHEST 22

#define OSSL_FUNC_DIGEST_NEWCTX 1

#define OSSL_FUNC_DIGEST_INIT 2

#define OSSL_FUNC_DIGEST_UPDATE 3

#define OSSL_FUNC_DIGEST_FINAL 4

#define OSSL_FUNC_DIGEST_DIGEST 5

#define OSSL_FUNC_DIGEST_FREECTX 6

#define OSSL_FUNC_DIGEST_DUPCTX 7

#define OSSL_FUNC_DIGEST_GET_PARAMS 8

#define OSSL_FUNC_DIGEST_SET_CTX_PARAMS 9

#define OSSL_FUNC_DIGEST_GET_CTX_PARAMS 10

#define OSSL_FUNC_DIGEST_GETTABLE_PARAMS 11

#define OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS 12

#define OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS 13

#define OSSL_FUNC_DIGEST_SQUEEZE 14

#define OSSL_FUNC_CIPHER_NEWCTX 1

#define OSSL_FUNC_CIPHER_ENCRYPT_INIT 2

#define OSSL_FUNC_CIPHER_DECRYPT_INIT 3

#define OSSL_FUNC_CIPHER_UPDATE 4

#define OSSL_FUNC_CIPHER_FINAL 5

#define OSSL_FUNC_CIPHER_CIPHER 6

#define OSSL_FUNC_CIPHER_FREECTX 7

#define OSSL_FUNC_CIPHER_DUPCTX 8

#define OSSL_FUNC_CIPHER_GET_PARAMS 9

#define OSSL_FUNC_CIPHER_GET_CTX_PARAMS 10

#define OSSL_FUNC_CIPHER_SET_CTX_PARAMS 11

#define OSSL_FUNC_CIPHER_GETTABLE_PARAMS 12

#define OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS 13

#define OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS 14

#define OSSL_FUNC_MAC_NEWCTX 1

#define OSSL_FUNC_MAC_DUPCTX 2

#define OSSL_FUNC_MAC_FREECTX 3

#define OSSL_FUNC_MAC_INIT 4

#define OSSL_FUNC_MAC_UPDATE 5

#define OSSL_FUNC_MAC_FINAL 6

#define OSSL_FUNC_MAC_GET_PARAMS 7

#define OSSL_FUNC_MAC_GET_CTX_PARAMS 8

#define OSSL_FUNC_MAC_SET_CTX_PARAMS 9

#define OSSL_FUNC_MAC_GETTABLE_PARAMS 10

#define OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS 11

#define OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS 12

#define OSSL_FUNC_KDF_NEWCTX 1

#define OSSL_FUNC_KDF_DUPCTX 2

#define OSSL_FUNC_KDF_FREECTX 3

#define OSSL_FUNC_KDF_RESET 4

#define OSSL_FUNC_KDF_DERIVE 5

#define OSSL_FUNC_KDF_GETTABLE_PARAMS 6

#define OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS 7

#define OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS 8

#define OSSL_FUNC_KDF_GET_PARAMS 9

#define OSSL_FUNC_KDF_GET_CTX_PARAMS 10

#define OSSL_FUNC_KDF_SET_CTX_PARAMS 11

#define OSSL_FUNC_RAND_NEWCTX 1

#define OSSL_FUNC_RAND_FREECTX 2

#define OSSL_FUNC_RAND_INSTANTIATE 3

#define OSSL_FUNC_RAND_UNINSTANTIATE 4

#define OSSL_FUNC_RAND_GENERATE 5

#define OSSL_FUNC_RAND_RESEED 6

#define OSSL_FUNC_RAND_NONCE 7

#define OSSL_FUNC_RAND_ENABLE_LOCKING 8

#define OSSL_FUNC_RAND_LOCK 9

#define OSSL_FUNC_RAND_UNLOCK 10

#define OSSL_FUNC_RAND_GETTABLE_PARAMS 11

#define OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS 12

#define OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS 13

#define OSSL_FUNC_RAND_GET_PARAMS 14

#define OSSL_FUNC_RAND_GET_CTX_PARAMS 15

#define OSSL_FUNC_RAND_SET_CTX_PARAMS 16

#define OSSL_FUNC_RAND_VERIFY_ZEROIZATION 17

#define OSSL_FUNC_RAND_GET_SEED 18

#define OSSL_FUNC_RAND_CLEAR_SEED 19

#define OSSL_KEYMGMT_SELECT_PRIVATE_KEY 0x01

#define OSSL_KEYMGMT_SELECT_PUBLIC_KEY 0x02

#define OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS 0x04

#define OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS 0x80

#define OSSL_KEYMGMT_SELECT_ALL_PARAMETERS \
	( OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS     \\
	| OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS)

#define OSSL_KEYMGMT_SELECT_KEYPAIR \
	( OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_PUBLIC_KEY )

#define OSSL_KEYMGMT_SELECT_ALL \
	( OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS )

#define OSSL_KEYMGMT_VALIDATE_FULL_CHECK 0

#define OSSL_KEYMGMT_VALIDATE_QUICK_CHECK 1

#define OSSL_FUNC_KEYMGMT_NEW 1

#define OSSL_FUNC_KEYMGMT_GEN_INIT 2

#define OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE 3

#define OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS 4

#define OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS 5

#define OSSL_FUNC_KEYMGMT_GEN 6

#define OSSL_FUNC_KEYMGMT_GEN_CLEANUP 7

#define OSSL_FUNC_KEYMGMT_LOAD 8

#define OSSL_FUNC_KEYMGMT_FREE 10

#define OSSL_FUNC_KEYMGMT_GET_PARAMS 11

#define OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS 12

#define OSSL_FUNC_KEYMGMT_SET_PARAMS 13

#define OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS 14

#define OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME 20

#define OSSL_FUNC_KEYMGMT_HAS 21

#define OSSL_FUNC_KEYMGMT_VALIDATE 22

#define OSSL_FUNC_KEYMGMT_MATCH 23

#define OSSL_FUNC_KEYMGMT_IMPORT 40

#define OSSL_FUNC_KEYMGMT_IMPORT_TYPES 41

#define OSSL_FUNC_KEYMGMT_EXPORT 42

#define OSSL_FUNC_KEYMGMT_EXPORT_TYPES 43

#define OSSL_FUNC_KEYMGMT_DUP 44

#define OSSL_FUNC_KEYMGMT_IMPORT_TYPES_EX 45

#define OSSL_FUNC_KEYMGMT_EXPORT_TYPES_EX 46

#define OSSL_FUNC_KEYEXCH_NEWCTX 1

#define OSSL_FUNC_KEYEXCH_INIT 2

#define OSSL_FUNC_KEYEXCH_DERIVE 3

#define OSSL_FUNC_KEYEXCH_SET_PEER 4

#define OSSL_FUNC_KEYEXCH_FREECTX 5

#define OSSL_FUNC_KEYEXCH_DUPCTX 6

#define OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS 7

#define OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS 8

#define OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS 9

#define OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS 10

#define OSSL_FUNC_SIGNATURE_NEWCTX 1

#define OSSL_FUNC_SIGNATURE_SIGN_INIT 2

#define OSSL_FUNC_SIGNATURE_SIGN 3

#define OSSL_FUNC_SIGNATURE_VERIFY_INIT 4

#define OSSL_FUNC_SIGNATURE_VERIFY 5

#define OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT 6

#define OSSL_FUNC_SIGNATURE_VERIFY_RECOVER 7

#define OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT 8

#define OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE 9

#define OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL 10

#define OSSL_FUNC_SIGNATURE_DIGEST_SIGN 11

#define OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT 12

#define OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE 13

#define OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL 14

#define OSSL_FUNC_SIGNATURE_DIGEST_VERIFY 15

#define OSSL_FUNC_SIGNATURE_FREECTX 16

#define OSSL_FUNC_SIGNATURE_DUPCTX 17

#define OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS 18

#define OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS 19

#define OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS 20

#define OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS 21

#define OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS 22

#define OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS 23

#define OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS 24

#define OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS 25

#define OSSL_FUNC_ASYM_CIPHER_NEWCTX 1

#define OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT 2

#define OSSL_FUNC_ASYM_CIPHER_ENCRYPT 3

#define OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT 4

#define OSSL_FUNC_ASYM_CIPHER_DECRYPT 5

#define OSSL_FUNC_ASYM_CIPHER_FREECTX 6

#define OSSL_FUNC_ASYM_CIPHER_DUPCTX 7

#define OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS 8

#define OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS 9

#define OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS 10

#define OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS 11

#define OSSL_FUNC_KEM_NEWCTX 1

#define OSSL_FUNC_KEM_ENCAPSULATE_INIT 2

#define OSSL_FUNC_KEM_ENCAPSULATE 3

#define OSSL_FUNC_KEM_DECAPSULATE_INIT 4

#define OSSL_FUNC_KEM_DECAPSULATE 5

#define OSSL_FUNC_KEM_FREECTX 6

#define OSSL_FUNC_KEM_DUPCTX 7

#define OSSL_FUNC_KEM_GET_CTX_PARAMS 8

#define OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS 9

#define OSSL_FUNC_KEM_SET_CTX_PARAMS 10

#define OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS 11

#define OSSL_FUNC_KEM_AUTH_ENCAPSULATE_INIT 12

#define OSSL_FUNC_KEM_AUTH_DECAPSULATE_INIT 13

#define OSSL_FUNC_ENCODER_NEWCTX 1

#define OSSL_FUNC_ENCODER_FREECTX 2

#define OSSL_FUNC_ENCODER_GET_PARAMS 3

#define OSSL_FUNC_ENCODER_GETTABLE_PARAMS 4

#define OSSL_FUNC_ENCODER_SET_CTX_PARAMS 5

#define OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS 6

#define OSSL_FUNC_ENCODER_DOES_SELECTION 10

#define OSSL_FUNC_ENCODER_ENCODE 11

#define OSSL_FUNC_ENCODER_IMPORT_OBJECT 20

#define OSSL_FUNC_ENCODER_FREE_OBJECT 21

#define OSSL_FUNC_DECODER_NEWCTX 1

#define OSSL_FUNC_DECODER_FREECTX 2

#define OSSL_FUNC_DECODER_GET_PARAMS 3

#define OSSL_FUNC_DECODER_GETTABLE_PARAMS 4

#define OSSL_FUNC_DECODER_SET_CTX_PARAMS 5

#define OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS 6

#define OSSL_FUNC_DECODER_DOES_SELECTION 10

#define OSSL_FUNC_DECODER_DECODE 11

#define OSSL_FUNC_DECODER_EXPORT_OBJECT 20

#define OSSL_FUNC_STORE_OPEN 1

#define OSSL_FUNC_STORE_ATTACH 2

#define OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS 3

#define OSSL_FUNC_STORE_SET_CTX_PARAMS 4

#define OSSL_FUNC_STORE_LOAD 5

#define OSSL_FUNC_STORE_EOF 6

#define OSSL_FUNC_STORE_CLOSE 7

#define OSSL_FUNC_STORE_EXPORT_OBJECT 8

#define OSSL_FUNC_STORE_DELETE 9

#define OSSL_FUNC_STORE_OPEN_EX 10

#define OPENSSL_CORE_NAMES_H 

#define OSSL_CIPHER_CTS_MODE_CS1 "CS1"

#define OSSL_CIPHER_CTS_MODE_CS2 "CS2"

#define OSSL_CIPHER_CTS_MODE_CS3 "CS3"

#define OSSL_CIPHER_NAME_AES_128_GCM_SIV "AES-128-GCM-SIV"

#define OSSL_CIPHER_NAME_AES_192_GCM_SIV "AES-192-GCM-SIV"

#define OSSL_CIPHER_NAME_AES_256_GCM_SIV "AES-256-GCM-SIV"

#define OSSL_DIGEST_NAME_MD5 "MD5"

#define OSSL_DIGEST_NAME_MD5_SHA1 "MD5-SHA1"

#define OSSL_DIGEST_NAME_SHA1 "SHA1"

#define OSSL_DIGEST_NAME_SHA2_224 "SHA2-224"

#define OSSL_DIGEST_NAME_SHA2_256 "SHA2-256"

#define OSSL_DIGEST_NAME_SHA2_256_192 "SHA2-256/192"

#define OSSL_DIGEST_NAME_SHA2_384 "SHA2-384"

#define OSSL_DIGEST_NAME_SHA2_512 "SHA2-512"

#define OSSL_DIGEST_NAME_SHA2_512_224 "SHA2-512/224"

#define OSSL_DIGEST_NAME_SHA2_512_256 "SHA2-512/256"

#define OSSL_DIGEST_NAME_MD2 "MD2"

#define OSSL_DIGEST_NAME_MD4 "MD4"

#define OSSL_DIGEST_NAME_MDC2 "MDC2"

#define OSSL_DIGEST_NAME_RIPEMD160 "RIPEMD160"

#define OSSL_DIGEST_NAME_SHA3_224 "SHA3-224"

#define OSSL_DIGEST_NAME_SHA3_256 "SHA3-256"

#define OSSL_DIGEST_NAME_SHA3_384 "SHA3-384"

#define OSSL_DIGEST_NAME_SHA3_512 "SHA3-512"

#define OSSL_DIGEST_NAME_KECCAK_KMAC128 "KECCAK-KMAC-128"

#define OSSL_DIGEST_NAME_KECCAK_KMAC256 "KECCAK-KMAC-256"

#define OSSL_DIGEST_NAME_SM3 "SM3"

#define OSSL_MAC_NAME_BLAKE2BMAC "BLAKE2BMAC"

#define OSSL_MAC_NAME_BLAKE2SMAC "BLAKE2SMAC"

#define OSSL_MAC_NAME_CMAC "CMAC"

#define OSSL_MAC_NAME_GMAC "GMAC"

#define OSSL_MAC_NAME_HMAC "HMAC"

#define OSSL_MAC_NAME_KMAC128 "KMAC128"

#define OSSL_MAC_NAME_KMAC256 "KMAC256"

#define OSSL_MAC_NAME_POLY1305 "POLY1305"

#define OSSL_MAC_NAME_SIPHASH "SIPHASH"

#define OSSL_KDF_NAME_HKDF "HKDF"

#define OSSL_KDF_NAME_TLS1_3_KDF "TLS13-KDF"

#define OSSL_KDF_NAME_PBKDF1 "PBKDF1"

#define OSSL_KDF_NAME_PBKDF2 "PBKDF2"

#define OSSL_KDF_NAME_SCRYPT "SCRYPT"

#define OSSL_KDF_NAME_SSHKDF "SSHKDF"

#define OSSL_KDF_NAME_SSKDF "SSKDF"

#define OSSL_KDF_NAME_TLS1_PRF "TLS1-PRF"

#define OSSL_KDF_NAME_X942KDF_ASN1 "X942KDF-ASN1"

#define OSSL_KDF_NAME_X942KDF_CONCAT "X942KDF-CONCAT"

#define OSSL_KDF_NAME_X963KDF "X963KDF"

#define OSSL_KDF_NAME_KBKDF "KBKDF"

#define OSSL_KDF_NAME_KRB5KDF "KRB5KDF"

#define OSSL_KDF_NAME_HMACDRBGKDF "HMAC-DRBG-KDF"

#define OSSL_PKEY_RSA_PAD_MODE_NONE "none"

#define OSSL_PKEY_RSA_PAD_MODE_PKCSV15 "pkcs1"

#define OSSL_PKEY_RSA_PAD_MODE_OAEP "oaep"

#define OSSL_PKEY_RSA_PAD_MODE_X931 "x931"

#define OSSL_PKEY_RSA_PAD_MODE_PSS "pss"

#define OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST "digest"

#define OSSL_PKEY_RSA_PSS_SALT_LEN_MAX "max"

#define OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO "auto"

#define OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO_DIGEST_MAX "auto-digestmax"

#define OSSL_PKEY_EC_ENCODING_EXPLICIT "explicit"

#define OSSL_PKEY_EC_ENCODING_GROUP "named_curve"

#define OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_UNCOMPRESSED "uncompressed"

#define OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_COMPRESSED "compressed"

#define OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_HYBRID "hybrid"

#define OSSL_PKEY_EC_GROUP_CHECK_DEFAULT "default"

#define OSSL_PKEY_EC_GROUP_CHECK_NAMED "named"

#define OSSL_PKEY_EC_GROUP_CHECK_NAMED_NIST "named-nist"

#define OSSL_KEM_PARAM_OPERATION_RSASVE "RSASVE"

#define OSSL_KEM_PARAM_OPERATION_DHKEM "DHKEM"

#define OPENSSL_CORE_OBJECT_H 

#define OSSL_OBJECT_UNKNOWN 0

#define OSSL_OBJECT_NAME 1

#define OSSL_OBJECT_PKEY 2

#define OSSL_OBJECT_CERT 3

#define OSSL_OBJECT_CRL 4

#define OPENSSL_CRMF_H 

#define OSSL_CRMF_POPOPRIVKEY_THISMESSAGE 0

#define OSSL_CRMF_POPOPRIVKEY_SUBSEQUENTMESSAGE 1

#define OSSL_CRMF_POPOPRIVKEY_DHMAC 2

#define OSSL_CRMF_POPOPRIVKEY_AGREEMAC 3

#define OSSL_CRMF_POPOPRIVKEY_ENCRYPTEDKEY 4

#define OSSL_CRMF_SUBSEQUENTMESSAGE_ENCRCERT 0

#define OSSL_CRMF_SUBSEQUENTMESSAGE_CHALLENGERESP 1

#define OSSL_CRMF_PUB_METHOD_DONTCARE 0

#define OSSL_CRMF_PUB_METHOD_X500 1

#define OSSL_CRMF_PUB_METHOD_WEB 2

#define OSSL_CRMF_PUB_METHOD_LDAP 3

#define OSSL_CRMF_PUB_ACTION_DONTPUBLISH 0

#define OSSL_CRMF_PUB_ACTION_PLEASEPUBLISH 1

#define OSSL_CRMF_POPO_NONE -1

#define OSSL_CRMF_POPO_RAVERIFIED 0

#define OSSL_CRMF_POPO_SIGNATURE 1

#define OSSL_CRMF_POPO_KEYENC 2

#define OSSL_CRMF_POPO_KEYAGREE 3

#define OPENSSL_CRMFERR_H 

#define CRMF_R_BAD_PBM_ITERATIONCOUNT 100

#define CRMF_R_CRMFERROR 102

#define CRMF_R_ERROR 103

#define CRMF_R_ERROR_DECODING_CERTIFICATE 104

#define CRMF_R_ERROR_DECRYPTING_CERTIFICATE 105

#define CRMF_R_ERROR_DECRYPTING_SYMMETRIC_KEY 106

#define CRMF_R_FAILURE_OBTAINING_RANDOM 107

#define CRMF_R_ITERATIONCOUNT_BELOW_100 108

#define CRMF_R_MALFORMED_IV 101

#define CRMF_R_NULL_ARGUMENT 109

#define CRMF_R_POPOSKINPUT_NOT_SUPPORTED 113

#define CRMF_R_POPO_INCONSISTENT_PUBLIC_KEY 117

#define CRMF_R_POPO_MISSING 121

#define CRMF_R_POPO_MISSING_PUBLIC_KEY 118

#define CRMF_R_POPO_MISSING_SUBJECT 119

#define CRMF_R_POPO_RAVERIFIED_NOT_ACCEPTED 120

#define CRMF_R_SETTING_MAC_ALGOR_FAILURE 110

#define CRMF_R_SETTING_OWF_ALGOR_FAILURE 111

#define CRMF_R_UNSUPPORTED_ALGORITHM 112

#define CRMF_R_UNSUPPORTED_CIPHER 114

#define CRMF_R_UNSUPPORTED_METHOD_FOR_CREATING_POPO 115

#define CRMF_R_UNSUPPORTED_POPO_METHOD 116

#define OPENSSL_CRYPTO_H 

#define HEADER_CRYPTO_H 

#define SSLeay OpenSSL_version_num

#define SSLeay_version OpenSSL_version

#define SSLEAY_VERSION_NUMBER OPENSSL_VERSION_NUMBER

#define SSLEAY_VERSION OPENSSL_VERSION

#define SSLEAY_CFLAGS OPENSSL_CFLAGS

#define SSLEAY_BUILT_ON OPENSSL_BUILT_ON

#define SSLEAY_PLATFORM OPENSSL_PLATFORM

#define SSLEAY_DIR OPENSSL_DIR

#define OPENSSL_malloc_init () while(0) continue

// #define OPENSSL_malloc (num)\
// 	CRYPTO_malloc(num, OPENSSL_FILE, OPENSSL_LINE)

#define OPENSSL_zalloc (num)\
	CRYPTO_zalloc(num, OPENSSL_FILE, OPENSSL_LINE)

#define OPENSSL_realloc (addr, num)\
	CRYPTO_realloc(addr, num, OPENSSL_FILE, OPENSSL_LINE)

#define OPENSSL_clear_realloc (addr, old_num, num)\
	CRYPTO_clear_realloc(addr, old_num, num, OPENSSL_FILE, OPENSSL_LINE)

#define OPENSSL_clear_free (addr, num)\
	CRYPTO_clear_free(addr, num, OPENSSL_FILE, OPENSSL_LINE)

// #define OPENSSL_free (addr)\
// 	CRYPTO_free(addr, OPENSSL_FILE, OPENSSL_LINE)

#define OPENSSL_memdup (str, s)\
	CRYPTO_memdup((str), s, OPENSSL_FILE, OPENSSL_LINE)

#define OPENSSL_strdup (str)\
	CRYPTO_strdup(str, OPENSSL_FILE, OPENSSL_LINE)

#define OPENSSL_strndup (str, n)\
	CRYPTO_strndup(str, n, OPENSSL_FILE, OPENSSL_LINE)

#define OPENSSL_secure_malloc (num)\
	CRYPTO_secure_malloc(num, OPENSSL_FILE, OPENSSL_LINE)

#define OPENSSL_secure_zalloc (num)\
	CRYPTO_secure_zalloc(num, OPENSSL_FILE, OPENSSL_LINE)

#define OPENSSL_secure_free (addr)\
	CRYPTO_secure_free(addr, OPENSSL_FILE, OPENSSL_LINE)

#define OPENSSL_secure_clear_free (addr, num)\
	CRYPTO_secure_clear_free(addr, num, OPENSSL_FILE, OPENSSL_LINE)

#define OPENSSL_secure_actual_size (ptr)\
	CRYPTO_secure_actual_size(ptr)

#define OPENSSL_MALLOC_MAX_NELEMS (type)  (((1U<<(sizeof(int)*8-1))-1)/sizeof(type))

#define OPENSSL_VERSION 0

#define OPENSSL_CFLAGS 1

#define OPENSSL_BUILT_ON 2

#define OPENSSL_PLATFORM 3

#define OPENSSL_DIR 4

#define OPENSSL_ENGINES_DIR 5

#define OPENSSL_VERSION_STRING 6

#define OPENSSL_FULL_VERSION_STRING 7

#define OPENSSL_MODULES_DIR 8

#define OPENSSL_CPU_INFO 9

#define OPENSSL_INFO_CONFIG_DIR 1001

#define OPENSSL_INFO_ENGINES_DIR 1002

#define OPENSSL_INFO_MODULES_DIR 1003

#define OPENSSL_INFO_DSO_EXTENSION 1004

#define OPENSSL_INFO_DIR_FILENAME_SEPARATOR 1005

#define OPENSSL_INFO_LIST_SEPARATOR 1006

#define OPENSSL_INFO_SEED_SOURCE 1007

#define OPENSSL_INFO_CPU_SETTINGS 1008

#define CRYPTO_EX_INDEX_SSL 0

#define CRYPTO_EX_INDEX_SSL_CTX 1

#define CRYPTO_EX_INDEX_SSL_SESSION 2

#define CRYPTO_EX_INDEX_X509 3

#define CRYPTO_EX_INDEX_X509_STORE 4

#define CRYPTO_EX_INDEX_X509_STORE_CTX 5

#define CRYPTO_EX_INDEX_DH 6

#define CRYPTO_EX_INDEX_DSA 7

#define CRYPTO_EX_INDEX_EC_KEY 8

#define CRYPTO_EX_INDEX_RSA 9

#define CRYPTO_EX_INDEX_ENGINE 10

#define CRYPTO_EX_INDEX_UI 11

#define CRYPTO_EX_INDEX_BIO 12

#define CRYPTO_EX_INDEX_APP 13

#define CRYPTO_EX_INDEX_UI_METHOD 14

#define CRYPTO_EX_INDEX_RAND_DRBG 15

#define CRYPTO_EX_INDEX_DRBG CRYPTO_EX_INDEX_RAND_DRBG

#define CRYPTO_EX_INDEX_OSSL_LIB_CTX 16

#define CRYPTO_EX_INDEX_EVP_PKEY 17

#define CRYPTO_EX_INDEX__COUNT 18

#define CRYPTO_cleanup_all_ex_data () while(0) continue

#define CRYPTO_num_locks ()            (1)

#define CRYPTO_set_locking_callback (func)

#define CRYPTO_get_locking_callback ()         (NULL)

#define CRYPTO_set_add_lock_callback (func)

#define CRYPTO_get_add_lock_callback ()        (NULL)

#define CRYPTO_LOCK 1

#define CRYPTO_UNLOCK 2

#define CRYPTO_READ 4

#define CRYPTO_WRITE 8

#define CRYPTO_THREADID_set_numeric (id, val)

#define CRYPTO_THREADID_set_pointer (id, ptr)

#define CRYPTO_THREADID_set_callback (threadid_func)   (0)

#define CRYPTO_THREADID_get_callback ()                (NULL)

#define CRYPTO_THREADID_current (id)

#define CRYPTO_THREADID_cmp (a, b)                     (-1)

#define CRYPTO_THREADID_cpy (dest, src)

#define CRYPTO_THREADID_hash (id)                      (0UL)

#define CRYPTO_set_id_callback (func)

#define CRYPTO_get_id_callback ()                     (NULL)

#define CRYPTO_thread_id ()                           (0UL)

#define CRYPTO_set_dynlock_create_callback (dyn_create_function)

#define CRYPTO_set_dynlock_lock_callback (dyn_lock_function)

#define CRYPTO_set_dynlock_destroy_callback (dyn_destroy_function)

#define CRYPTO_get_dynlock_create_callback ()          (NULL)

#define CRYPTO_get_dynlock_lock_callback ()            (NULL)

#define CRYPTO_get_dynlock_destroy_callback ()         (NULL)

#define CRYPTO_MEM_CHECK_OFF 0x0

#define CRYPTO_MEM_CHECK_ON 0x1

#define CRYPTO_MEM_CHECK_ENABLE 0x2

#define CRYPTO_MEM_CHECK_DISABLE 0x3

#define OPENSSL_mem_debug_push (info)\
	CRYPTO_mem_debug_push(info, OPENSSL_FILE, OPENSSL_LINE)

#define OPENSSL_mem_debug_pop ()\
	CRYPTO_mem_debug_pop()

#define OpenSSLDie (f,l,a) OPENSSL_die((a),(f),(l))

#define OPENSSL_assert (e)\
	(void)((e) ? 0 : (OPENSSL_die("assertion failed: " #e, OPENSSL_FILE, OPENSSL_LINE), 1))

#define OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS 0x00000001L

#define OPENSSL_INIT_LOAD_CRYPTO_STRINGS 0x00000002L

#define OPENSSL_INIT_ADD_ALL_CIPHERS 0x00000004L

#define OPENSSL_INIT_ADD_ALL_DIGESTS 0x00000008L

#define OPENSSL_INIT_NO_ADD_ALL_CIPHERS 0x00000010L

#define OPENSSL_INIT_NO_ADD_ALL_DIGESTS 0x00000020L

#define OPENSSL_INIT_LOAD_CONFIG 0x00000040L

#define OPENSSL_INIT_NO_LOAD_CONFIG 0x00000080L

#define OPENSSL_INIT_ASYNC 0x00000100L

#define OPENSSL_INIT_ENGINE_RDRAND 0x00000200L

#define OPENSSL_INIT_ENGINE_DYNAMIC 0x00000400L

#define OPENSSL_INIT_ENGINE_OPENSSL 0x00000800L

#define OPENSSL_INIT_ENGINE_CRYPTODEV 0x00001000L

#define OPENSSL_INIT_ENGINE_CAPI 0x00002000L

#define OPENSSL_INIT_ENGINE_PADLOCK 0x00004000L

#define OPENSSL_INIT_ENGINE_AFALG 0x00008000L

#define OPENSSL_INIT_ATFORK 0x00020000L

#define OPENSSL_INIT_NO_ATEXIT 0x00080000L

#define OPENSSL_INIT_ENGINE_ALL_BUILTIN \
	(OPENSSL_INIT_ENGINE_RDRAND | OPENSSL_INIT_ENGINE_DYNAMIC \\
	| OPENSSL_INIT_ENGINE_CRYPTODEV | OPENSSL_INIT_ENGINE_CAPI | \\
	OPENSSL_INIT_ENGINE_PADLOCK)

#define CRYPTO_ONCE_STATIC_INIT 0

#define SPT_THREAD_SIGNAL 1

#define SPT_THREAD_AWARE 1

#define OPENSSL_CRYPTOERR_H 

#define CRYPTO_R_BAD_ALGORITHM_NAME 117

#define CRYPTO_R_CONFLICTING_NAMES 118

#define CRYPTO_R_HEX_STRING_TOO_SHORT 121

#define CRYPTO_R_ILLEGAL_HEX_DIGIT 102

#define CRYPTO_R_INSUFFICIENT_DATA_SPACE 106

#define CRYPTO_R_INSUFFICIENT_PARAM_SIZE 107

#define CRYPTO_R_INSUFFICIENT_SECURE_DATA_SPACE 108

#define CRYPTO_R_INTEGER_OVERFLOW 127

#define CRYPTO_R_INVALID_NEGATIVE_VALUE 122

#define CRYPTO_R_INVALID_NULL_ARGUMENT 109

#define CRYPTO_R_INVALID_OSSL_PARAM_TYPE 110

#define CRYPTO_R_NO_PARAMS_TO_MERGE 131

#define CRYPTO_R_NO_SPACE_FOR_TERMINATING_NULL 128

#define CRYPTO_R_ODD_NUMBER_OF_DIGITS 103

#define CRYPTO_R_PARAM_CANNOT_BE_REPRESENTED_EXACTLY 123

#define CRYPTO_R_PARAM_NOT_INTEGER_TYPE 124

#define CRYPTO_R_PARAM_OF_INCOMPATIBLE_TYPE 129

#define CRYPTO_R_PARAM_UNSIGNED_INTEGER_NEGATIVE_VALUE_UNSUPPORTED 125

#define CRYPTO_R_PARAM_UNSUPPORTED_FLOATING_POINT_FORMAT 130

#define CRYPTO_R_PARAM_VALUE_TOO_LARGE_FOR_DESTINATION 126

#define CRYPTO_R_PROVIDER_ALREADY_EXISTS 104

#define CRYPTO_R_PROVIDER_SECTION_ERROR 105

#define CRYPTO_R_RANDOM_SECTION_ERROR 119

#define CRYPTO_R_SECURE_MALLOC_FAILURE 111

#define CRYPTO_R_STRING_TOO_LONG 112

#define CRYPTO_R_TOO_MANY_BYTES 113

#define CRYPTO_R_TOO_MANY_RECORDS 114

#define CRYPTO_R_TOO_SMALL_BUFFER 116

#define CRYPTO_R_UNKNOWN_NAME_IN_RANDOM_SECTION 120

#define CRYPTO_R_ZERO_LENGTH_NUMBER 115

#define OPENSSL_CRYPTOERR_LEGACY_H 

#define ASN1_F_A2D_ASN1_OBJECT 0

#define ASN1_F_A2I_ASN1_INTEGER 0

#define ASN1_F_A2I_ASN1_STRING 0

#define ASN1_F_APPEND_EXP 0

#define ASN1_F_ASN1_BIO_INIT 0

#define ASN1_F_ASN1_BIT_STRING_SET_BIT 0

#define ASN1_F_ASN1_CB 0

#define ASN1_F_ASN1_CHECK_TLEN 0

#define ASN1_F_ASN1_COLLECT 0

#define ASN1_F_ASN1_D2I_EX_PRIMITIVE 0

#define ASN1_F_ASN1_D2I_FP 0

#define ASN1_F_ASN1_D2I_READ_BIO 0

#define ASN1_F_ASN1_DIGEST 0

#define ASN1_F_ASN1_DO_ADB 0

#define ASN1_F_ASN1_DO_LOCK 0

#define ASN1_F_ASN1_DUP 0

#define ASN1_F_ASN1_ENC_SAVE 0

#define ASN1_F_ASN1_EX_C2I 0

#define ASN1_F_ASN1_FIND_END 0

#define ASN1_F_ASN1_GENERALIZEDTIME_ADJ 0

#define ASN1_F_ASN1_GENERATE_V3 0

#define ASN1_F_ASN1_GET_INT64 0

#define ASN1_F_ASN1_GET_OBJECT 0

#define ASN1_F_ASN1_GET_UINT64 0

#define ASN1_F_ASN1_I2D_BIO 0

#define ASN1_F_ASN1_I2D_FP 0

#define ASN1_F_ASN1_ITEM_D2I_FP 0

#define ASN1_F_ASN1_ITEM_DUP 0

#define ASN1_F_ASN1_ITEM_EMBED_D2I 0

#define ASN1_F_ASN1_ITEM_EMBED_NEW 0

#define ASN1_F_ASN1_ITEM_FLAGS_I2D 0

#define ASN1_F_ASN1_ITEM_I2D_BIO 0

#define ASN1_F_ASN1_ITEM_I2D_FP 0

#define ASN1_F_ASN1_ITEM_PACK 0

#define ASN1_F_ASN1_ITEM_SIGN 0

#define ASN1_F_ASN1_ITEM_SIGN_CTX 0

#define ASN1_F_ASN1_ITEM_UNPACK 0

#define ASN1_F_ASN1_ITEM_VERIFY 0

#define ASN1_F_ASN1_MBSTRING_NCOPY 0

#define ASN1_F_ASN1_OBJECT_NEW 0

#define ASN1_F_ASN1_OUTPUT_DATA 0

#define ASN1_F_ASN1_PCTX_NEW 0

#define ASN1_F_ASN1_PRIMITIVE_NEW 0

#define ASN1_F_ASN1_SCTX_NEW 0

#define ASN1_F_ASN1_SIGN 0

#define ASN1_F_ASN1_STR2TYPE 0

#define ASN1_F_ASN1_STRING_GET_INT64 0

#define ASN1_F_ASN1_STRING_GET_UINT64 0

#define ASN1_F_ASN1_STRING_SET 0

#define ASN1_F_ASN1_STRING_TABLE_ADD 0

#define ASN1_F_ASN1_STRING_TO_BN 0

#define ASN1_F_ASN1_STRING_TYPE_NEW 0

#define ASN1_F_ASN1_TEMPLATE_EX_D2I 0

#define ASN1_F_ASN1_TEMPLATE_NEW 0

#define ASN1_F_ASN1_TEMPLATE_NOEXP_D2I 0

#define ASN1_F_ASN1_TIME_ADJ 0

#define ASN1_F_ASN1_TYPE_GET_INT_OCTETSTRING 0

#define ASN1_F_ASN1_TYPE_GET_OCTETSTRING 0

#define ASN1_F_ASN1_UTCTIME_ADJ 0

#define ASN1_F_ASN1_VERIFY 0

#define ASN1_F_B64_READ_ASN1 0

#define ASN1_F_B64_WRITE_ASN1 0

#define ASN1_F_BIO_NEW_NDEF 0

#define ASN1_F_BITSTR_CB 0

#define ASN1_F_BN_TO_ASN1_STRING 0

#define ASN1_F_C2I_ASN1_BIT_STRING 0

#define ASN1_F_C2I_ASN1_INTEGER 0

#define ASN1_F_C2I_ASN1_OBJECT 0

#define ASN1_F_C2I_IBUF 0

#define ASN1_F_C2I_UINT64_INT 0

#define ASN1_F_COLLECT_DATA 0

#define ASN1_F_D2I_ASN1_OBJECT 0

#define ASN1_F_D2I_ASN1_UINTEGER 0

#define ASN1_F_D2I_AUTOPRIVATEKEY 0

#define ASN1_F_D2I_PRIVATEKEY 0

#define ASN1_F_D2I_PUBLICKEY 0

#define ASN1_F_DO_BUF 0

#define ASN1_F_DO_CREATE 0

#define ASN1_F_DO_DUMP 0

#define ASN1_F_DO_TCREATE 0

#define ASN1_F_I2A_ASN1_OBJECT 0

#define ASN1_F_I2D_ASN1_BIO_STREAM 0

#define ASN1_F_I2D_ASN1_OBJECT 0

#define ASN1_F_I2D_DSA_PUBKEY 0

#define ASN1_F_I2D_EC_PUBKEY 0

#define ASN1_F_I2D_PRIVATEKEY 0

#define ASN1_F_I2D_PUBLICKEY 0

#define ASN1_F_I2D_RSA_PUBKEY 0

#define ASN1_F_LONG_C2I 0

#define ASN1_F_NDEF_PREFIX 0

#define ASN1_F_NDEF_SUFFIX 0

#define ASN1_F_OID_MODULE_INIT 0

#define ASN1_F_PARSE_TAGGING 0

#define ASN1_F_PKCS5_PBE2_SET_IV 0

#define ASN1_F_PKCS5_PBE2_SET_SCRYPT 0

#define ASN1_F_PKCS5_PBE_SET 0

#define ASN1_F_PKCS5_PBE_SET0_ALGOR 0

#define ASN1_F_PKCS5_PBKDF2_SET 0

#define ASN1_F_PKCS5_SCRYPT_SET 0

#define ASN1_F_SMIME_READ_ASN1 0

#define ASN1_F_SMIME_TEXT 0

#define ASN1_F_STABLE_GET 0

#define ASN1_F_STBL_MODULE_INIT 0

#define ASN1_F_UINT32_C2I 0

#define ASN1_F_UINT32_NEW 0

#define ASN1_F_UINT64_C2I 0

#define ASN1_F_UINT64_NEW 0

#define ASN1_F_X509_CRL_ADD0_REVOKED 0

#define ASN1_F_X509_INFO_NEW 0

#define ASN1_F_X509_NAME_ENCODE 0

#define ASN1_F_X509_NAME_EX_D2I 0

#define ASN1_F_X509_NAME_EX_NEW 0

#define ASN1_F_X509_PKEY_NEW 0

#define ASYNC_F_ASYNC_CTX_NEW 0

#define ASYNC_F_ASYNC_INIT_THREAD 0

#define ASYNC_F_ASYNC_JOB_NEW 0

#define ASYNC_F_ASYNC_PAUSE_JOB 0

#define ASYNC_F_ASYNC_START_FUNC 0

#define ASYNC_F_ASYNC_START_JOB 0

#define ASYNC_F_ASYNC_WAIT_CTX_SET_WAIT_FD 0

#define BIO_F_ACPT_STATE 0

#define BIO_F_ADDRINFO_WRAP 0

#define BIO_F_ADDR_STRINGS 0

#define BIO_F_BIO_ACCEPT 0

#define BIO_F_BIO_ACCEPT_EX 0

#define BIO_F_BIO_ACCEPT_NEW 0

#define BIO_F_BIO_ADDR_NEW 0

#define BIO_F_BIO_BIND 0

#define BIO_F_BIO_CALLBACK_CTRL 0

#define BIO_F_BIO_CONNECT 0

#define BIO_F_BIO_CONNECT_NEW 0

#define BIO_F_BIO_CTRL 0

#define BIO_F_BIO_GETS 0

#define BIO_F_BIO_GET_HOST_IP 0

#define BIO_F_BIO_GET_NEW_INDEX 0

#define BIO_F_BIO_GET_PORT 0

#define BIO_F_BIO_LISTEN 0

#define BIO_F_BIO_LOOKUP 0

#define BIO_F_BIO_LOOKUP_EX 0

#define BIO_F_BIO_MAKE_PAIR 0

#define BIO_F_BIO_METH_NEW 0

#define BIO_F_BIO_NEW 0

#define BIO_F_BIO_NEW_DGRAM_SCTP 0

#define BIO_F_BIO_NEW_FILE 0

#define BIO_F_BIO_NEW_MEM_BUF 0

#define BIO_F_BIO_NREAD 0

#define BIO_F_BIO_NREAD0 0

#define BIO_F_BIO_NWRITE 0

#define BIO_F_BIO_NWRITE0 0

#define BIO_F_BIO_PARSE_HOSTSERV 0

#define BIO_F_BIO_PUTS 0

#define BIO_F_BIO_READ 0

#define BIO_F_BIO_READ_EX 0

#define BIO_F_BIO_READ_INTERN 0

#define BIO_F_BIO_SOCKET 0

#define BIO_F_BIO_SOCKET_NBIO 0

#define BIO_F_BIO_SOCK_INFO 0

#define BIO_F_BIO_SOCK_INIT 0

#define BIO_F_BIO_WRITE 0

#define BIO_F_BIO_WRITE_EX 0

#define BIO_F_BIO_WRITE_INTERN 0

#define BIO_F_BUFFER_CTRL 0

#define BIO_F_CONN_CTRL 0

#define BIO_F_CONN_STATE 0

#define BIO_F_DGRAM_SCTP_NEW 0

#define BIO_F_DGRAM_SCTP_READ 0

#define BIO_F_DGRAM_SCTP_WRITE 0

#define BIO_F_DOAPR_OUTCH 0

#define BIO_F_FILE_CTRL 0

#define BIO_F_FILE_READ 0

#define BIO_F_LINEBUFFER_CTRL 0

#define BIO_F_LINEBUFFER_NEW 0

#define BIO_F_MEM_WRITE 0

#define BIO_F_NBIOF_NEW 0

#define BIO_F_SLG_WRITE 0

#define BIO_F_SSL_NEW 0

#define BN_F_BNRAND 0

#define BN_F_BNRAND_RANGE 0

#define BN_F_BN_BLINDING_CONVERT_EX 0

#define BN_F_BN_BLINDING_CREATE_PARAM 0

#define BN_F_BN_BLINDING_INVERT_EX 0

#define BN_F_BN_BLINDING_NEW 0

#define BN_F_BN_BLINDING_UPDATE 0

#define BN_F_BN_BN2DEC 0

#define BN_F_BN_BN2HEX 0

#define BN_F_BN_COMPUTE_WNAF 0

#define BN_F_BN_CTX_GET 0

#define BN_F_BN_CTX_NEW 0

#define BN_F_BN_CTX_START 0

#define BN_F_BN_DIV 0

#define BN_F_BN_DIV_RECP 0

#define BN_F_BN_EXP 0

#define BN_F_BN_EXPAND_INTERNAL 0

#define BN_F_BN_GENCB_NEW 0

#define BN_F_BN_GENERATE_DSA_NONCE 0

#define BN_F_BN_GENERATE_PRIME_EX 0

#define BN_F_BN_GF2M_MOD 0

#define BN_F_BN_GF2M_MOD_EXP 0

#define BN_F_BN_GF2M_MOD_MUL 0

#define BN_F_BN_GF2M_MOD_SOLVE_QUAD 0

#define BN_F_BN_GF2M_MOD_SOLVE_QUAD_ARR 0

#define BN_F_BN_GF2M_MOD_SQR 0

#define BN_F_BN_GF2M_MOD_SQRT 0

#define BN_F_BN_LSHIFT 0

#define BN_F_BN_MOD_EXP2_MONT 0

#define BN_F_BN_MOD_EXP_MONT 0

#define BN_F_BN_MOD_EXP_MONT_CONSTTIME 0

#define BN_F_BN_MOD_EXP_MONT_WORD 0

#define BN_F_BN_MOD_EXP_RECP 0

#define BN_F_BN_MOD_EXP_SIMPLE 0

#define BN_F_BN_MOD_INVERSE 0

#define BN_F_BN_MOD_INVERSE_NO_BRANCH 0

#define BN_F_BN_MOD_LSHIFT_QUICK 0

#define BN_F_BN_MOD_SQRT 0

#define BN_F_BN_MONT_CTX_NEW 0

#define BN_F_BN_MPI2BN 0

#define BN_F_BN_NEW 0

#define BN_F_BN_POOL_GET 0

#define BN_F_BN_RAND 0

#define BN_F_BN_RAND_RANGE 0

#define BN_F_BN_RECP_CTX_NEW 0

#define BN_F_BN_RSHIFT 0

#define BN_F_BN_SET_WORDS 0

#define BN_F_BN_STACK_PUSH 0

#define BN_F_BN_USUB 0

#define BUF_F_BUF_MEM_GROW 0

#define BUF_F_BUF_MEM_GROW_CLEAN 0

#define BUF_F_BUF_MEM_NEW 0

#define CMS_F_CHECK_CONTENT 0

#define CMS_F_CMS_ADD0_CERT 0

#define CMS_F_CMS_ADD0_RECIPIENT_KEY 0

#define CMS_F_CMS_ADD0_RECIPIENT_PASSWORD 0

#define CMS_F_CMS_ADD1_RECEIPTREQUEST 0

#define CMS_F_CMS_ADD1_RECIPIENT_CERT 0

#define CMS_F_CMS_ADD1_SIGNER 0

#define CMS_F_CMS_ADD1_SIGNINGTIME 0

#define CMS_F_CMS_COMPRESS 0

#define CMS_F_CMS_COMPRESSEDDATA_CREATE 0

#define CMS_F_CMS_COMPRESSEDDATA_INIT_BIO 0

#define CMS_F_CMS_COPY_CONTENT 0

#define CMS_F_CMS_COPY_MESSAGEDIGEST 0

#define CMS_F_CMS_DATA 0

#define CMS_F_CMS_DATAFINAL 0

#define CMS_F_CMS_DATAINIT 0

#define CMS_F_CMS_DECRYPT 0

#define CMS_F_CMS_DECRYPT_SET1_KEY 0

#define CMS_F_CMS_DECRYPT_SET1_PASSWORD 0

#define CMS_F_CMS_DECRYPT_SET1_PKEY 0

#define CMS_F_CMS_DIGESTALGORITHM_FIND_CTX 0

#define CMS_F_CMS_DIGESTALGORITHM_INIT_BIO 0

#define CMS_F_CMS_DIGESTEDDATA_DO_FINAL 0

#define CMS_F_CMS_DIGEST_VERIFY 0

#define CMS_F_CMS_ENCODE_RECEIPT 0

#define CMS_F_CMS_ENCRYPT 0

#define CMS_F_CMS_ENCRYPTEDCONTENT_INIT 0

#define CMS_F_CMS_ENCRYPTEDCONTENT_INIT_BIO 0

#define CMS_F_CMS_ENCRYPTEDDATA_DECRYPT 0

#define CMS_F_CMS_ENCRYPTEDDATA_ENCRYPT 0

#define CMS_F_CMS_ENCRYPTEDDATA_SET1_KEY 0

#define CMS_F_CMS_ENVELOPEDDATA_CREATE 0

#define CMS_F_CMS_ENVELOPEDDATA_INIT_BIO 0

#define CMS_F_CMS_ENVELOPED_DATA_INIT 0

#define CMS_F_CMS_ENV_ASN1_CTRL 0

#define CMS_F_CMS_FINAL 0

#define CMS_F_CMS_GET0_CERTIFICATE_CHOICES 0

#define CMS_F_CMS_GET0_CONTENT 0

#define CMS_F_CMS_GET0_ECONTENT_TYPE 0

#define CMS_F_CMS_GET0_ENVELOPED 0

#define CMS_F_CMS_GET0_REVOCATION_CHOICES 0

#define CMS_F_CMS_GET0_SIGNED 0

#define CMS_F_CMS_MSGSIGDIGEST_ADD1 0

#define CMS_F_CMS_RECEIPTREQUEST_CREATE0 0

#define CMS_F_CMS_RECEIPT_VERIFY 0

#define CMS_F_CMS_RECIPIENTINFO_DECRYPT 0

#define CMS_F_CMS_RECIPIENTINFO_ENCRYPT 0

#define CMS_F_CMS_RECIPIENTINFO_KARI_ENCRYPT 0

#define CMS_F_CMS_RECIPIENTINFO_KARI_GET0_ALG 0

#define CMS_F_CMS_RECIPIENTINFO_KARI_GET0_ORIG_ID 0

#define CMS_F_CMS_RECIPIENTINFO_KARI_GET0_REKS 0

#define CMS_F_CMS_RECIPIENTINFO_KARI_ORIG_ID_CMP 0

#define CMS_F_CMS_RECIPIENTINFO_KEKRI_DECRYPT 0

#define CMS_F_CMS_RECIPIENTINFO_KEKRI_ENCRYPT 0

#define CMS_F_CMS_RECIPIENTINFO_KEKRI_GET0_ID 0

#define CMS_F_CMS_RECIPIENTINFO_KEKRI_ID_CMP 0

#define CMS_F_CMS_RECIPIENTINFO_KTRI_CERT_CMP 0

#define CMS_F_CMS_RECIPIENTINFO_KTRI_DECRYPT 0

#define CMS_F_CMS_RECIPIENTINFO_KTRI_ENCRYPT 0

#define CMS_F_CMS_RECIPIENTINFO_KTRI_GET0_ALGS 0

#define CMS_F_CMS_RECIPIENTINFO_KTRI_GET0_SIGNER_ID 0

#define CMS_F_CMS_RECIPIENTINFO_PWRI_CRYPT 0

#define CMS_F_CMS_RECIPIENTINFO_SET0_KEY 0

#define CMS_F_CMS_RECIPIENTINFO_SET0_PASSWORD 0

#define CMS_F_CMS_RECIPIENTINFO_SET0_PKEY 0

#define CMS_F_CMS_SD_ASN1_CTRL 0

#define CMS_F_CMS_SET1_IAS 0

#define CMS_F_CMS_SET1_KEYID 0

#define CMS_F_CMS_SET1_SIGNERIDENTIFIER 0

#define CMS_F_CMS_SET_DETACHED 0

#define CMS_F_CMS_SIGN 0

#define CMS_F_CMS_SIGNED_DATA_INIT 0

#define CMS_F_CMS_SIGNERINFO_CONTENT_SIGN 0

#define CMS_F_CMS_SIGNERINFO_SIGN 0

#define CMS_F_CMS_SIGNERINFO_VERIFY 0

#define CMS_F_CMS_SIGNERINFO_VERIFY_CERT 0

#define CMS_F_CMS_SIGNERINFO_VERIFY_CONTENT 0

#define CMS_F_CMS_SIGN_RECEIPT 0

#define CMS_F_CMS_SI_CHECK_ATTRIBUTES 0

#define CMS_F_CMS_STREAM 0

#define CMS_F_CMS_UNCOMPRESS 0

#define CMS_F_CMS_VERIFY 0

#define CMS_F_KEK_UNWRAP_KEY 0

#define COMP_F_BIO_ZLIB_FLUSH 0

#define COMP_F_BIO_ZLIB_NEW 0

#define COMP_F_BIO_ZLIB_READ 0

#define COMP_F_BIO_ZLIB_WRITE 0

#define COMP_F_COMP_CTX_NEW 0

#define CONF_F_CONF_DUMP_FP 0

#define CONF_F_CONF_LOAD 0

#define CONF_F_CONF_LOAD_FP 0

#define CONF_F_CONF_PARSE_LIST 0

#define CONF_F_DEF_LOAD 0

#define CONF_F_DEF_LOAD_BIO 0

#define CONF_F_GET_NEXT_FILE 0

#define CONF_F_MODULE_ADD 0

#define CONF_F_MODULE_INIT 0

#define CONF_F_MODULE_LOAD_DSO 0

#define CONF_F_MODULE_RUN 0

#define CONF_F_NCONF_DUMP_BIO 0

#define CONF_F_NCONF_DUMP_FP 0

#define CONF_F_NCONF_GET_NUMBER_E 0

#define CONF_F_NCONF_GET_SECTION 0

#define CONF_F_NCONF_GET_STRING 0

#define CONF_F_NCONF_LOAD 0

#define CONF_F_NCONF_LOAD_BIO 0

#define CONF_F_NCONF_LOAD_FP 0

#define CONF_F_NCONF_NEW 0

#define CONF_F_PROCESS_INCLUDE 0

#define CONF_F_SSL_MODULE_INIT 0

#define CONF_F_STR_COPY 0

#define CRYPTO_F_CMAC_CTX_NEW 0

#define CRYPTO_F_CRYPTO_DUP_EX_DATA 0

#define CRYPTO_F_CRYPTO_FREE_EX_DATA 0

#define CRYPTO_F_CRYPTO_GET_EX_NEW_INDEX 0

#define CRYPTO_F_CRYPTO_MEMDUP 0

#define CRYPTO_F_CRYPTO_NEW_EX_DATA 0

#define CRYPTO_F_CRYPTO_OCB128_COPY_CTX 0

#define CRYPTO_F_CRYPTO_OCB128_INIT 0

#define CRYPTO_F_CRYPTO_SET_EX_DATA 0

#define CRYPTO_F_GET_AND_LOCK 0

#define CRYPTO_F_OPENSSL_ATEXIT 0

#define CRYPTO_F_OPENSSL_BUF2HEXSTR 0

#define CRYPTO_F_OPENSSL_FOPEN 0

#define CRYPTO_F_OPENSSL_HEXSTR2BUF 0

#define CRYPTO_F_OPENSSL_INIT_CRYPTO 0

#define CRYPTO_F_OPENSSL_LH_NEW 0

#define CRYPTO_F_OPENSSL_SK_DEEP_COPY 0

#define CRYPTO_F_OPENSSL_SK_DUP 0

#define CRYPTO_F_PKEY_HMAC_INIT 0

#define CRYPTO_F_PKEY_POLY1305_INIT 0

#define CRYPTO_F_PKEY_SIPHASH_INIT 0

#define CRYPTO_F_SK_RESERVE 0

#define CT_F_CTLOG_NEW 0

#define CT_F_CTLOG_NEW_FROM_BASE64 0

#define CT_F_CTLOG_NEW_FROM_CONF 0

#define CT_F_CTLOG_STORE_LOAD_CTX_NEW 0

#define CT_F_CTLOG_STORE_LOAD_FILE 0

#define CT_F_CTLOG_STORE_LOAD_LOG 0

#define CT_F_CTLOG_STORE_NEW 0

#define CT_F_CT_BASE64_DECODE 0

#define CT_F_CT_POLICY_EVAL_CTX_NEW 0

#define CT_F_CT_V1_LOG_ID_FROM_PKEY 0

#define CT_F_I2O_SCT 0

#define CT_F_I2O_SCT_LIST 0

#define CT_F_I2O_SCT_SIGNATURE 0

#define CT_F_O2I_SCT 0

#define CT_F_O2I_SCT_LIST 0

#define CT_F_O2I_SCT_SIGNATURE 0

#define CT_F_SCT_CTX_NEW 0

#define CT_F_SCT_CTX_VERIFY 0

#define CT_F_SCT_NEW 0

#define CT_F_SCT_NEW_FROM_BASE64 0

#define CT_F_SCT_SET0_LOG_ID 0

#define CT_F_SCT_SET1_EXTENSIONS 0

#define CT_F_SCT_SET1_LOG_ID 0

#define CT_F_SCT_SET1_SIGNATURE 0

#define CT_F_SCT_SET_LOG_ENTRY_TYPE 0

#define CT_F_SCT_SET_SIGNATURE_NID 0

#define CT_F_SCT_SET_VERSION 0

#define DH_F_COMPUTE_KEY 0

#define DH_F_DHPARAMS_PRINT_FP 0

#define DH_F_DH_BUILTIN_GENPARAMS 0

#define DH_F_DH_CHECK_EX 0

#define DH_F_DH_CHECK_PARAMS_EX 0

#define DH_F_DH_CHECK_PUB_KEY_EX 0

#define DH_F_DH_CMS_DECRYPT 0

#define DH_F_DH_CMS_SET_PEERKEY 0

#define DH_F_DH_CMS_SET_SHARED_INFO 0

#define DH_F_DH_METH_DUP 0

#define DH_F_DH_METH_NEW 0

#define DH_F_DH_METH_SET1_NAME 0

#define DH_F_DH_NEW_BY_NID 0

#define DH_F_DH_NEW_METHOD 0

#define DH_F_DH_PARAM_DECODE 0

#define DH_F_DH_PKEY_PUBLIC_CHECK 0

#define DH_F_DH_PRIV_DECODE 0

#define DH_F_DH_PRIV_ENCODE 0

#define DH_F_DH_PUB_DECODE 0

#define DH_F_DH_PUB_ENCODE 0

#define DH_F_DO_DH_PRINT 0

#define DH_F_GENERATE_KEY 0

#define DH_F_PKEY_DH_CTRL_STR 0

#define DH_F_PKEY_DH_DERIVE 0

#define DH_F_PKEY_DH_INIT 0

#define DH_F_PKEY_DH_KEYGEN 0

#define DSA_F_DSAPARAMS_PRINT 0

#define DSA_F_DSAPARAMS_PRINT_FP 0

#define DSA_F_DSA_BUILTIN_PARAMGEN 0

#define DSA_F_DSA_BUILTIN_PARAMGEN2 0

#define DSA_F_DSA_DO_SIGN 0

#define DSA_F_DSA_DO_VERIFY 0

#define DSA_F_DSA_METH_DUP 0

#define DSA_F_DSA_METH_NEW 0

#define DSA_F_DSA_METH_SET1_NAME 0

#define DSA_F_DSA_NEW_METHOD 0

#define DSA_F_DSA_PARAM_DECODE 0

#define DSA_F_DSA_PRINT_FP 0

#define DSA_F_DSA_PRIV_DECODE 0

#define DSA_F_DSA_PRIV_ENCODE 0

#define DSA_F_DSA_PUB_DECODE 0

#define DSA_F_DSA_PUB_ENCODE 0

#define DSA_F_DSA_SIGN 0

#define DSA_F_DSA_SIGN_SETUP 0

#define DSA_F_DSA_SIG_NEW 0

#define DSA_F_OLD_DSA_PRIV_DECODE 0

#define DSA_F_PKEY_DSA_CTRL 0

#define DSA_F_PKEY_DSA_CTRL_STR 0

#define DSA_F_PKEY_DSA_KEYGEN 0

#define EC_F_BN_TO_FELEM 0

#define EC_F_D2I_ECPARAMETERS 0

#define EC_F_D2I_ECPKPARAMETERS 0

#define EC_F_D2I_ECPRIVATEKEY 0

#define EC_F_DO_EC_KEY_PRINT 0

#define EC_F_ECDH_CMS_DECRYPT 0

#define EC_F_ECDH_CMS_SET_SHARED_INFO 0

#define EC_F_ECDH_COMPUTE_KEY 0

#define EC_F_ECDH_SIMPLE_COMPUTE_KEY 0

#define EC_F_ECDSA_DO_SIGN_EX 0

#define EC_F_ECDSA_DO_VERIFY 0

#define EC_F_ECDSA_SIGN_EX 0

#define EC_F_ECDSA_SIGN_SETUP 0

#define EC_F_ECDSA_SIG_NEW 0

#define EC_F_ECDSA_VERIFY 0

#define EC_F_ECD_ITEM_VERIFY 0

#define EC_F_ECKEY_PARAM2TYPE 0

#define EC_F_ECKEY_PARAM_DECODE 0

#define EC_F_ECKEY_PRIV_DECODE 0

#define EC_F_ECKEY_PRIV_ENCODE 0

#define EC_F_ECKEY_PUB_DECODE 0

#define EC_F_ECKEY_PUB_ENCODE 0

#define EC_F_ECKEY_TYPE2PARAM 0

#define EC_F_ECPARAMETERS_PRINT 0

#define EC_F_ECPARAMETERS_PRINT_FP 0

#define EC_F_ECPKPARAMETERS_PRINT 0

#define EC_F_ECPKPARAMETERS_PRINT_FP 0

#define EC_F_ECP_NISTZ256_GET_AFFINE 0

#define EC_F_ECP_NISTZ256_INV_MOD_ORD 0

#define EC_F_ECP_NISTZ256_MULT_PRECOMPUTE 0

#define EC_F_ECP_NISTZ256_POINTS_MUL 0

#define EC_F_ECP_NISTZ256_PRE_COMP_NEW 0

#define EC_F_ECP_NISTZ256_WINDOWED_MUL 0

#define EC_F_ECX_KEY_OP 0

#define EC_F_ECX_PRIV_ENCODE 0

#define EC_F_ECX_PUB_ENCODE 0

#define EC_F_EC_ASN1_GROUP2CURVE 0

#define EC_F_EC_ASN1_GROUP2FIELDID 0

#define EC_F_EC_GF2M_MONTGOMERY_POINT_MULTIPLY 0

#define EC_F_EC_GF2M_SIMPLE_FIELD_INV 0

#define EC_F_EC_GF2M_SIMPLE_GROUP_CHECK_DISCRIMINANT 0

#define EC_F_EC_GF2M_SIMPLE_GROUP_SET_CURVE 0

#define EC_F_EC_GF2M_SIMPLE_LADDER_POST 0

#define EC_F_EC_GF2M_SIMPLE_LADDER_PRE 0

#define EC_F_EC_GF2M_SIMPLE_OCT2POINT 0

#define EC_F_EC_GF2M_SIMPLE_POINT2OCT 0

#define EC_F_EC_GF2M_SIMPLE_POINTS_MUL 0

#define EC_F_EC_GF2M_SIMPLE_POINT_GET_AFFINE_COORDINATES 0

#define EC_F_EC_GF2M_SIMPLE_POINT_SET_AFFINE_COORDINATES 0

#define EC_F_EC_GF2M_SIMPLE_SET_COMPRESSED_COORDINATES 0

#define EC_F_EC_GFP_MONT_FIELD_DECODE 0

#define EC_F_EC_GFP_MONT_FIELD_ENCODE 0

#define EC_F_EC_GFP_MONT_FIELD_INV 0

#define EC_F_EC_GFP_MONT_FIELD_MUL 0

#define EC_F_EC_GFP_MONT_FIELD_SET_TO_ONE 0

#define EC_F_EC_GFP_MONT_FIELD_SQR 0

#define EC_F_EC_GFP_MONT_GROUP_SET_CURVE 0

#define EC_F_EC_GFP_NISTP224_GROUP_SET_CURVE 0

#define EC_F_EC_GFP_NISTP224_POINTS_MUL 0

#define EC_F_EC_GFP_NISTP224_POINT_GET_AFFINE_COORDINATES 0

#define EC_F_EC_GFP_NISTP256_GROUP_SET_CURVE 0

#define EC_F_EC_GFP_NISTP256_POINTS_MUL 0

#define EC_F_EC_GFP_NISTP256_POINT_GET_AFFINE_COORDINATES 0

#define EC_F_EC_GFP_NISTP521_GROUP_SET_CURVE 0

#define EC_F_EC_GFP_NISTP521_POINTS_MUL 0

#define EC_F_EC_GFP_NISTP521_POINT_GET_AFFINE_COORDINATES 0

#define EC_F_EC_GFP_NIST_FIELD_MUL 0

#define EC_F_EC_GFP_NIST_FIELD_SQR 0

#define EC_F_EC_GFP_NIST_GROUP_SET_CURVE 0

#define EC_F_EC_GFP_SIMPLE_BLIND_COORDINATES 0

#define EC_F_EC_GFP_SIMPLE_FIELD_INV 0

#define EC_F_EC_GFP_SIMPLE_GROUP_CHECK_DISCRIMINANT 0

#define EC_F_EC_GFP_SIMPLE_GROUP_SET_CURVE 0

#define EC_F_EC_GFP_SIMPLE_MAKE_AFFINE 0

#define EC_F_EC_GFP_SIMPLE_OCT2POINT 0

#define EC_F_EC_GFP_SIMPLE_POINT2OCT 0

#define EC_F_EC_GFP_SIMPLE_POINTS_MAKE_AFFINE 0

#define EC_F_EC_GFP_SIMPLE_POINT_GET_AFFINE_COORDINATES 0

#define EC_F_EC_GFP_SIMPLE_POINT_SET_AFFINE_COORDINATES 0

#define EC_F_EC_GFP_SIMPLE_SET_COMPRESSED_COORDINATES 0

#define EC_F_EC_GROUP_CHECK 0

#define EC_F_EC_GROUP_CHECK_DISCRIMINANT 0

#define EC_F_EC_GROUP_COPY 0

#define EC_F_EC_GROUP_GET_CURVE 0

#define EC_F_EC_GROUP_GET_CURVE_GF2M 0

#define EC_F_EC_GROUP_GET_CURVE_GFP 0

#define EC_F_EC_GROUP_GET_DEGREE 0

#define EC_F_EC_GROUP_GET_ECPARAMETERS 0

#define EC_F_EC_GROUP_GET_ECPKPARAMETERS 0

#define EC_F_EC_GROUP_GET_PENTANOMIAL_BASIS 0

#define EC_F_EC_GROUP_GET_TRINOMIAL_BASIS 0

#define EC_F_EC_GROUP_NEW 0

#define EC_F_EC_GROUP_NEW_BY_CURVE_NAME 0

#define EC_F_EC_GROUP_NEW_FROM_DATA 0

#define EC_F_EC_GROUP_NEW_FROM_ECPARAMETERS 0

#define EC_F_EC_GROUP_NEW_FROM_ECPKPARAMETERS 0

#define EC_F_EC_GROUP_SET_CURVE 0

#define EC_F_EC_GROUP_SET_CURVE_GF2M 0

#define EC_F_EC_GROUP_SET_CURVE_GFP 0

#define EC_F_EC_GROUP_SET_GENERATOR 0

#define EC_F_EC_GROUP_SET_SEED 0

#define EC_F_EC_KEY_CHECK_KEY 0

#define EC_F_EC_KEY_COPY 0

#define EC_F_EC_KEY_GENERATE_KEY 0

#define EC_F_EC_KEY_NEW 0

#define EC_F_EC_KEY_NEW_METHOD 0

#define EC_F_EC_KEY_OCT2PRIV 0

#define EC_F_EC_KEY_PRINT 0

#define EC_F_EC_KEY_PRINT_FP 0

#define EC_F_EC_KEY_PRIV2BUF 0

#define EC_F_EC_KEY_PRIV2OCT 0

#define EC_F_EC_KEY_SET_PUBLIC_KEY_AFFINE_COORDINATES 0

#define EC_F_EC_KEY_SIMPLE_CHECK_KEY 0

#define EC_F_EC_KEY_SIMPLE_OCT2PRIV 0

#define EC_F_EC_KEY_SIMPLE_PRIV2OCT 0

#define EC_F_EC_PKEY_CHECK 0

#define EC_F_EC_PKEY_PARAM_CHECK 0

#define EC_F_EC_POINTS_MAKE_AFFINE 0

#define EC_F_EC_POINTS_MUL 0

#define EC_F_EC_POINT_ADD 0

#define EC_F_EC_POINT_BN2POINT 0

#define EC_F_EC_POINT_CMP 0

#define EC_F_EC_POINT_COPY 0

#define EC_F_EC_POINT_DBL 0

#define EC_F_EC_POINT_GET_AFFINE_COORDINATES 0

#define EC_F_EC_POINT_GET_AFFINE_COORDINATES_GF2M 0

#define EC_F_EC_POINT_GET_AFFINE_COORDINATES_GFP 0

#define EC_F_EC_POINT_GET_JPROJECTIVE_COORDINATES_GFP 0

#define EC_F_EC_POINT_INVERT 0

#define EC_F_EC_POINT_IS_AT_INFINITY 0

#define EC_F_EC_POINT_IS_ON_CURVE 0

#define EC_F_EC_POINT_MAKE_AFFINE 0

#define EC_F_EC_POINT_NEW 0

#define EC_F_EC_POINT_OCT2POINT 0

#define EC_F_EC_POINT_POINT2BUF 0

#define EC_F_EC_POINT_POINT2OCT 0

#define EC_F_EC_POINT_SET_AFFINE_COORDINATES 0

#define EC_F_EC_POINT_SET_AFFINE_COORDINATES_GF2M 0

#define EC_F_EC_POINT_SET_AFFINE_COORDINATES_GFP 0

#define EC_F_EC_POINT_SET_COMPRESSED_COORDINATES 0

#define EC_F_EC_POINT_SET_COMPRESSED_COORDINATES_GF2M 0

#define EC_F_EC_POINT_SET_COMPRESSED_COORDINATES_GFP 0

#define EC_F_EC_POINT_SET_JPROJECTIVE_COORDINATES_GFP 0

#define EC_F_EC_POINT_SET_TO_INFINITY 0

#define EC_F_EC_PRE_COMP_NEW 0

#define EC_F_EC_SCALAR_MUL_LADDER 0

#define EC_F_EC_WNAF_MUL 0

#define EC_F_EC_WNAF_PRECOMPUTE_MULT 0

#define EC_F_I2D_ECPARAMETERS 0

#define EC_F_I2D_ECPKPARAMETERS 0

#define EC_F_I2D_ECPRIVATEKEY 0

#define EC_F_I2O_ECPUBLICKEY 0

#define EC_F_NISTP224_PRE_COMP_NEW 0

#define EC_F_NISTP256_PRE_COMP_NEW 0

#define EC_F_NISTP521_PRE_COMP_NEW 0

#define EC_F_O2I_ECPUBLICKEY 0

#define EC_F_OLD_EC_PRIV_DECODE 0

#define EC_F_OSSL_ECDH_COMPUTE_KEY 0

#define EC_F_OSSL_ECDSA_SIGN_SIG 0

#define EC_F_OSSL_ECDSA_VERIFY_SIG 0

#define EC_F_PKEY_ECD_CTRL 0

#define EC_F_PKEY_ECD_DIGESTSIGN 0

#define EC_F_PKEY_ECD_DIGESTSIGN25519 0

#define EC_F_PKEY_ECD_DIGESTSIGN448 0

#define EC_F_PKEY_ECX_DERIVE 0

#define EC_F_PKEY_EC_CTRL 0

#define EC_F_PKEY_EC_CTRL_STR 0

#define EC_F_PKEY_EC_DERIVE 0

#define EC_F_PKEY_EC_INIT 0

#define EC_F_PKEY_EC_KDF_DERIVE 0

#define EC_F_PKEY_EC_KEYGEN 0

#define EC_F_PKEY_EC_PARAMGEN 0

#define EC_F_PKEY_EC_SIGN 0

#define EC_F_VALIDATE_ECX_DERIVE 0

#define ENGINE_F_DIGEST_UPDATE 0

#define ENGINE_F_DYNAMIC_CTRL 0

#define ENGINE_F_DYNAMIC_GET_DATA_CTX 0

#define ENGINE_F_DYNAMIC_LOAD 0

#define ENGINE_F_DYNAMIC_SET_DATA_CTX 0

#define ENGINE_F_ENGINE_ADD 0

#define ENGINE_F_ENGINE_BY_ID 0

#define ENGINE_F_ENGINE_CMD_IS_EXECUTABLE 0

#define ENGINE_F_ENGINE_CTRL 0

#define ENGINE_F_ENGINE_CTRL_CMD 0

#define ENGINE_F_ENGINE_CTRL_CMD_STRING 0

#define ENGINE_F_ENGINE_FINISH 0

#define ENGINE_F_ENGINE_GET_CIPHER 0

#define ENGINE_F_ENGINE_GET_DIGEST 0

#define ENGINE_F_ENGINE_GET_FIRST 0

#define ENGINE_F_ENGINE_GET_LAST 0

#define ENGINE_F_ENGINE_GET_NEXT 0

#define ENGINE_F_ENGINE_GET_PKEY_ASN1_METH 0

#define ENGINE_F_ENGINE_GET_PKEY_METH 0

#define ENGINE_F_ENGINE_GET_PREV 0

#define ENGINE_F_ENGINE_INIT 0

#define ENGINE_F_ENGINE_LIST_ADD 0

#define ENGINE_F_ENGINE_LIST_REMOVE 0

#define ENGINE_F_ENGINE_LOAD_PRIVATE_KEY 0

#define ENGINE_F_ENGINE_LOAD_PUBLIC_KEY 0

#define ENGINE_F_ENGINE_LOAD_SSL_CLIENT_CERT 0

#define ENGINE_F_ENGINE_NEW 0

#define ENGINE_F_ENGINE_PKEY_ASN1_FIND_STR 0

#define ENGINE_F_ENGINE_REMOVE 0

#define ENGINE_F_ENGINE_SET_DEFAULT_STRING 0

#define ENGINE_F_ENGINE_SET_ID 0

#define ENGINE_F_ENGINE_SET_NAME 0

#define ENGINE_F_ENGINE_TABLE_REGISTER 0

#define ENGINE_F_ENGINE_UNLOCKED_FINISH 0

#define ENGINE_F_ENGINE_UP_REF 0

#define ENGINE_F_INT_CLEANUP_ITEM 0

#define ENGINE_F_INT_CTRL_HELPER 0

#define ENGINE_F_INT_ENGINE_CONFIGURE 0

#define ENGINE_F_INT_ENGINE_MODULE_INIT 0

#define ENGINE_F_OSSL_HMAC_INIT 0

#define EVP_F_AESNI_INIT_KEY 0

#define EVP_F_AESNI_XTS_INIT_KEY 0

#define EVP_F_AES_GCM_CTRL 0

#define EVP_F_AES_INIT_KEY 0

#define EVP_F_AES_OCB_CIPHER 0

#define EVP_F_AES_T4_INIT_KEY 0

#define EVP_F_AES_T4_XTS_INIT_KEY 0

#define EVP_F_AES_WRAP_CIPHER 0

#define EVP_F_AES_XTS_INIT_KEY 0

#define EVP_F_ALG_MODULE_INIT 0

#define EVP_F_ARIA_CCM_INIT_KEY 0

#define EVP_F_ARIA_GCM_CTRL 0

#define EVP_F_ARIA_GCM_INIT_KEY 0

#define EVP_F_ARIA_INIT_KEY 0

#define EVP_F_B64_NEW 0

#define EVP_F_CAMELLIA_INIT_KEY 0

#define EVP_F_CHACHA20_POLY1305_CTRL 0

#define EVP_F_CMLL_T4_INIT_KEY 0

#define EVP_F_DES_EDE3_WRAP_CIPHER 0

#define EVP_F_DO_SIGVER_INIT 0

#define EVP_F_ENC_NEW 0

#define EVP_F_EVP_CIPHERINIT_EX 0

#define EVP_F_EVP_CIPHER_ASN1_TO_PARAM 0

#define EVP_F_EVP_CIPHER_CTX_COPY 0

#define EVP_F_EVP_CIPHER_CTX_CTRL 0

#define EVP_F_EVP_CIPHER_CTX_SET_KEY_LENGTH 0

#define EVP_F_EVP_CIPHER_PARAM_TO_ASN1 0

#define EVP_F_EVP_DECRYPTFINAL_EX 0

#define EVP_F_EVP_DECRYPTUPDATE 0

#define EVP_F_EVP_DIGESTFINALXOF 0

#define EVP_F_EVP_DIGESTINIT_EX 0

#define EVP_F_EVP_ENCRYPTDECRYPTUPDATE 0

#define EVP_F_EVP_ENCRYPTFINAL_EX 0

#define EVP_F_EVP_ENCRYPTUPDATE 0

#define EVP_F_EVP_MD_CTX_COPY_EX 0

#define EVP_F_EVP_MD_SIZE 0

#define EVP_F_EVP_OPENINIT 0

#define EVP_F_EVP_PBE_ALG_ADD 0

#define EVP_F_EVP_PBE_ALG_ADD_TYPE 0

#define EVP_F_EVP_PBE_CIPHERINIT 0

#define EVP_F_EVP_PBE_SCRYPT 0

#define EVP_F_EVP_PKCS82PKEY 0

#define EVP_F_EVP_PKEY2PKCS8 0

#define EVP_F_EVP_PKEY_ASN1_ADD0 0

#define EVP_F_EVP_PKEY_CHECK 0

#define EVP_F_EVP_PKEY_COPY_PARAMETERS 0

#define EVP_F_EVP_PKEY_CTX_CTRL 0

#define EVP_F_EVP_PKEY_CTX_CTRL_STR 0

#define EVP_F_EVP_PKEY_CTX_DUP 0

#define EVP_F_EVP_PKEY_CTX_MD 0

#define EVP_F_EVP_PKEY_DECRYPT 0

#define EVP_F_EVP_PKEY_DECRYPT_INIT 0

#define EVP_F_EVP_PKEY_DECRYPT_OLD 0

#define EVP_F_EVP_PKEY_DERIVE 0

#define EVP_F_EVP_PKEY_DERIVE_INIT 0

#define EVP_F_EVP_PKEY_DERIVE_SET_PEER 0

#define EVP_F_EVP_PKEY_ENCRYPT 0

#define EVP_F_EVP_PKEY_ENCRYPT_INIT 0

#define EVP_F_EVP_PKEY_ENCRYPT_OLD 0

#define EVP_F_EVP_PKEY_GET0_DH 0

#define EVP_F_EVP_PKEY_GET0_DSA 0

#define EVP_F_EVP_PKEY_GET0_EC_KEY 0

#define EVP_F_EVP_PKEY_GET0_HMAC 0

#define EVP_F_EVP_PKEY_GET0_POLY1305 0

#define EVP_F_EVP_PKEY_GET0_RSA 0

#define EVP_F_EVP_PKEY_GET0_SIPHASH 0

#define EVP_F_EVP_PKEY_GET_RAW_PRIVATE_KEY 0

#define EVP_F_EVP_PKEY_GET_RAW_PUBLIC_KEY 0

#define EVP_F_EVP_PKEY_KEYGEN 0

#define EVP_F_EVP_PKEY_KEYGEN_INIT 0

#define EVP_F_EVP_PKEY_METH_ADD0 0

#define EVP_F_EVP_PKEY_METH_NEW 0

#define EVP_F_EVP_PKEY_NEW 0

#define EVP_F_EVP_PKEY_NEW_CMAC_KEY 0

#define EVP_F_EVP_PKEY_NEW_RAW_PRIVATE_KEY 0

#define EVP_F_EVP_PKEY_NEW_RAW_PUBLIC_KEY 0

#define EVP_F_EVP_PKEY_PARAMGEN 0

#define EVP_F_EVP_PKEY_PARAMGEN_INIT 0

#define EVP_F_EVP_PKEY_PARAM_CHECK 0

#define EVP_F_EVP_PKEY_PUBLIC_CHECK 0

#define EVP_F_EVP_PKEY_SET1_ENGINE 0

#define EVP_F_EVP_PKEY_SET_ALIAS_TYPE 0

#define EVP_F_EVP_PKEY_SIGN 0

#define EVP_F_EVP_PKEY_SIGN_INIT 0

#define EVP_F_EVP_PKEY_VERIFY 0

#define EVP_F_EVP_PKEY_VERIFY_INIT 0

#define EVP_F_EVP_PKEY_VERIFY_RECOVER 0

#define EVP_F_EVP_PKEY_VERIFY_RECOVER_INIT 0

#define EVP_F_EVP_SIGNFINAL 0

#define EVP_F_EVP_VERIFYFINAL 0

#define EVP_F_INT_CTX_NEW 0

#define EVP_F_OK_NEW 0

#define EVP_F_PKCS5_PBE_KEYIVGEN 0

#define EVP_F_PKCS5_V2_PBE_KEYIVGEN 0

#define EVP_F_PKCS5_V2_PBKDF2_KEYIVGEN 0

#define EVP_F_PKCS5_V2_SCRYPT_KEYIVGEN 0

#define EVP_F_PKEY_SET_TYPE 0

#define EVP_F_RC2_MAGIC_TO_METH 0

#define EVP_F_RC5_CTRL 0

#define EVP_F_R_32_12_16_INIT_KEY 0

#define EVP_F_S390X_AES_GCM_CTRL 0

#define EVP_F_UPDATE 0

#define KDF_F_PKEY_HKDF_CTRL_STR 0

#define KDF_F_PKEY_HKDF_DERIVE 0

#define KDF_F_PKEY_HKDF_INIT 0

#define KDF_F_PKEY_SCRYPT_CTRL_STR 0

#define KDF_F_PKEY_SCRYPT_CTRL_UINT64 0

#define KDF_F_PKEY_SCRYPT_DERIVE 0

#define KDF_F_PKEY_SCRYPT_INIT 0

#define KDF_F_PKEY_SCRYPT_SET_MEMBUF 0

#define KDF_F_PKEY_TLS1_PRF_CTRL_STR 0

#define KDF_F_PKEY_TLS1_PRF_DERIVE 0

#define KDF_F_PKEY_TLS1_PRF_INIT 0

#define KDF_F_TLS1_PRF_ALG 0

#define KDF_R_INVALID_DIGEST 0

#define KDF_R_MISSING_ITERATION_COUNT 0

#define KDF_R_MISSING_KEY 0

#define KDF_R_MISSING_MESSAGE_DIGEST 0

#define KDF_R_MISSING_PARAMETER 0

#define KDF_R_MISSING_PASS 0

#define KDF_R_MISSING_SALT 0

#define KDF_R_MISSING_SECRET 0

#define KDF_R_MISSING_SEED 0

#define KDF_R_UNKNOWN_PARAMETER_TYPE 0

#define KDF_R_VALUE_ERROR 0

#define KDF_R_VALUE_MISSING 0

#define OBJ_F_OBJ_ADD_OBJECT 0

#define OBJ_F_OBJ_ADD_SIGID 0

#define OBJ_F_OBJ_CREATE 0

#define OBJ_F_OBJ_DUP 0

#define OBJ_F_OBJ_NAME_NEW_INDEX 0

#define OBJ_F_OBJ_NID2LN 0

#define OBJ_F_OBJ_NID2OBJ 0

#define OBJ_F_OBJ_NID2SN 0

#define OBJ_F_OBJ_TXT2OBJ 0

#define OCSP_F_D2I_OCSP_NONCE 0

#define OCSP_F_OCSP_BASIC_ADD1_STATUS 0

#define OCSP_F_OCSP_BASIC_SIGN 0

#define OCSP_F_OCSP_BASIC_SIGN_CTX 0

#define OCSP_F_OCSP_BASIC_VERIFY 0

#define OCSP_F_OCSP_CERT_ID_NEW 0

#define OCSP_F_OCSP_CHECK_DELEGATED 0

#define OCSP_F_OCSP_CHECK_IDS 0

#define OCSP_F_OCSP_CHECK_ISSUER 0

#define OCSP_F_OCSP_CHECK_VALIDITY 0

#define OCSP_F_OCSP_MATCH_ISSUERID 0

#define OCSP_F_OCSP_PARSE_URL 0

#define OCSP_F_OCSP_REQUEST_SIGN 0

#define OCSP_F_OCSP_REQUEST_VERIFY 0

#define OCSP_F_OCSP_RESPONSE_GET1_BASIC 0

#define OCSP_F_PARSE_HTTP_LINE1 0

#define PEM_F_B2I_DSS 0

#define PEM_F_B2I_PVK_BIO 0

#define PEM_F_B2I_RSA 0

#define PEM_F_CHECK_BITLEN_DSA 0

#define PEM_F_CHECK_BITLEN_RSA 0

#define PEM_F_D2I_PKCS8PRIVATEKEY_BIO 0

#define PEM_F_D2I_PKCS8PRIVATEKEY_FP 0

#define PEM_F_DO_B2I 0

#define PEM_F_DO_B2I_BIO 0

#define PEM_F_DO_BLOB_HEADER 0

#define PEM_F_DO_I2B 0

#define PEM_F_DO_PK8PKEY 0

#define PEM_F_DO_PK8PKEY_FP 0

#define PEM_F_DO_PVK_BODY 0

#define PEM_F_DO_PVK_HEADER 0

#define PEM_F_GET_HEADER_AND_DATA 0

#define PEM_F_GET_NAME 0

#define PEM_F_I2B_PVK 0

#define PEM_F_I2B_PVK_BIO 0

#define PEM_F_LOAD_IV 0

#define PEM_F_PEM_ASN1_READ 0

#define PEM_F_PEM_ASN1_READ_BIO 0

#define PEM_F_PEM_ASN1_WRITE 0

#define PEM_F_PEM_ASN1_WRITE_BIO 0

#define PEM_F_PEM_DEF_CALLBACK 0

#define PEM_F_PEM_DO_HEADER 0

#define PEM_F_PEM_GET_EVP_CIPHER_INFO 0

#define PEM_F_PEM_READ 0

#define PEM_F_PEM_READ_BIO 0

#define PEM_F_PEM_READ_BIO_DHPARAMS 0

#define PEM_F_PEM_READ_BIO_EX 0

#define PEM_F_PEM_READ_BIO_PARAMETERS 0

#define PEM_F_PEM_READ_BIO_PRIVATEKEY 0

#define PEM_F_PEM_READ_DHPARAMS 0

#define PEM_F_PEM_READ_PRIVATEKEY 0

#define PEM_F_PEM_SIGNFINAL 0

#define PEM_F_PEM_WRITE 0

#define PEM_F_PEM_WRITE_BIO 0

#define PEM_F_PEM_WRITE_BIO_PRIVATEKEY_TRADITIONAL 0

#define PEM_F_PEM_WRITE_PRIVATEKEY 0

#define PEM_F_PEM_X509_INFO_READ 0

#define PEM_F_PEM_X509_INFO_READ_BIO 0

#define PEM_F_PEM_X509_INFO_WRITE_BIO 0

#define PKCS12_F_OPENSSL_ASC2UNI 0

#define PKCS12_F_OPENSSL_UNI2ASC 0

#define PKCS12_F_OPENSSL_UNI2UTF8 0

#define PKCS12_F_OPENSSL_UTF82UNI 0

#define PKCS12_F_PKCS12_CREATE 0

#define PKCS12_F_PKCS12_GEN_MAC 0

#define PKCS12_F_PKCS12_INIT 0

#define PKCS12_F_PKCS12_ITEM_DECRYPT_D2I 0

#define PKCS12_F_PKCS12_ITEM_I2D_ENCRYPT 0

#define PKCS12_F_PKCS12_ITEM_PACK_SAFEBAG 0

#define PKCS12_F_PKCS12_KEY_GEN_ASC 0

#define PKCS12_F_PKCS12_KEY_GEN_UNI 0

#define PKCS12_F_PKCS12_KEY_GEN_UTF8 0

#define PKCS12_F_PKCS12_NEWPASS 0

#define PKCS12_F_PKCS12_PACK_P7DATA 0

#define PKCS12_F_PKCS12_PACK_P7ENCDATA 0

#define PKCS12_F_PKCS12_PARSE 0

#define PKCS12_F_PKCS12_PBE_CRYPT 0

#define PKCS12_F_PKCS12_PBE_KEYIVGEN 0

#define PKCS12_F_PKCS12_SAFEBAG_CREATE0_P8INF 0

#define PKCS12_F_PKCS12_SAFEBAG_CREATE0_PKCS8 0

#define PKCS12_F_PKCS12_SAFEBAG_CREATE_PKCS8_ENCRYPT 0

#define PKCS12_F_PKCS12_SETUP_MAC 0

#define PKCS12_F_PKCS12_SET_MAC 0

#define PKCS12_F_PKCS12_UNPACK_AUTHSAFES 0

#define PKCS12_F_PKCS12_UNPACK_P7DATA 0

#define PKCS12_F_PKCS12_VERIFY_MAC 0

#define PKCS12_F_PKCS8_ENCRYPT 0

#define PKCS12_F_PKCS8_SET0_PBE 0

#define PKCS7_F_DO_PKCS7_SIGNED_ATTRIB 0

#define PKCS7_F_PKCS7_ADD0_ATTRIB_SIGNING_TIME 0

#define PKCS7_F_PKCS7_ADD_ATTRIB_SMIMECAP 0

#define PKCS7_F_PKCS7_ADD_CERTIFICATE 0

#define PKCS7_F_PKCS7_ADD_CRL 0

#define PKCS7_F_PKCS7_ADD_RECIPIENT_INFO 0

#define PKCS7_F_PKCS7_ADD_SIGNATURE 0

#define PKCS7_F_PKCS7_ADD_SIGNER 0

#define PKCS7_F_PKCS7_BIO_ADD_DIGEST 0

#define PKCS7_F_PKCS7_COPY_EXISTING_DIGEST 0

#define PKCS7_F_PKCS7_CTRL 0

#define PKCS7_F_PKCS7_DATADECODE 0

#define PKCS7_F_PKCS7_DATAFINAL 0

#define PKCS7_F_PKCS7_DATAINIT 0

#define PKCS7_F_PKCS7_DATAVERIFY 0

#define PKCS7_F_PKCS7_DECRYPT 0

#define PKCS7_F_PKCS7_DECRYPT_RINFO 0

#define PKCS7_F_PKCS7_ENCODE_RINFO 0

#define PKCS7_F_PKCS7_ENCRYPT 0

#define PKCS7_F_PKCS7_FINAL 0

#define PKCS7_F_PKCS7_FIND_DIGEST 0

#define PKCS7_F_PKCS7_GET0_SIGNERS 0

#define PKCS7_F_PKCS7_RECIP_INFO_SET 0

#define PKCS7_F_PKCS7_SET_CIPHER 0

#define PKCS7_F_PKCS7_SET_CONTENT 0

#define PKCS7_F_PKCS7_SET_DIGEST 0

#define PKCS7_F_PKCS7_SET_TYPE 0

#define PKCS7_F_PKCS7_SIGN 0

#define PKCS7_F_PKCS7_SIGNATUREVERIFY 0

#define PKCS7_F_PKCS7_SIGNER_INFO_SET 0

#define PKCS7_F_PKCS7_SIGNER_INFO_SIGN 0

#define PKCS7_F_PKCS7_SIGN_ADD_SIGNER 0

#define PKCS7_F_PKCS7_SIMPLE_SMIMECAP 0

#define PKCS7_F_PKCS7_VERIFY 0

#define RAND_F_DATA_COLLECT_METHOD 0

#define RAND_F_DRBG_BYTES 0

#define RAND_F_DRBG_GET_ENTROPY 0

#define RAND_F_DRBG_SETUP 0

#define RAND_F_GET_ENTROPY 0

#define RAND_F_RAND_BYTES 0

#define RAND_F_RAND_DRBG_ENABLE_LOCKING 0

#define RAND_F_RAND_DRBG_GENERATE 0

#define RAND_F_RAND_DRBG_GET_ENTROPY 0

#define RAND_F_RAND_DRBG_GET_NONCE 0

#define RAND_F_RAND_DRBG_INSTANTIATE 0

#define RAND_F_RAND_DRBG_NEW 0

#define RAND_F_RAND_DRBG_RESEED 0

#define RAND_F_RAND_DRBG_RESTART 0

#define RAND_F_RAND_DRBG_SET 0

#define RAND_F_RAND_DRBG_SET_DEFAULTS 0

#define RAND_F_RAND_DRBG_UNINSTANTIATE 0

#define RAND_F_RAND_LOAD_FILE 0

#define RAND_F_RAND_POOL_ACQUIRE_ENTROPY 0

#define RAND_F_RAND_POOL_ADD 0

#define RAND_F_RAND_POOL_ADD_BEGIN 0

#define RAND_F_RAND_POOL_ADD_END 0

#define RAND_F_RAND_POOL_ATTACH 0

#define RAND_F_RAND_POOL_BYTES_NEEDED 0

#define RAND_F_RAND_POOL_GROW 0

#define RAND_F_RAND_POOL_NEW 0

#define RAND_F_RAND_PSEUDO_BYTES 0

#define RAND_F_RAND_WRITE_FILE 0

#define RSA_F_CHECK_PADDING_MD 0

#define RSA_F_ENCODE_PKCS1 0

#define RSA_F_INT_RSA_VERIFY 0

#define RSA_F_OLD_RSA_PRIV_DECODE 0

#define RSA_F_PKEY_PSS_INIT 0

#define RSA_F_PKEY_RSA_CTRL 0

#define RSA_F_PKEY_RSA_CTRL_STR 0

#define RSA_F_PKEY_RSA_SIGN 0

#define RSA_F_PKEY_RSA_VERIFY 0

#define RSA_F_PKEY_RSA_VERIFYRECOVER 0

#define RSA_F_RSA_ALGOR_TO_MD 0

#define RSA_F_RSA_BUILTIN_KEYGEN 0

#define RSA_F_RSA_CHECK_KEY 0

#define RSA_F_RSA_CHECK_KEY_EX 0

#define RSA_F_RSA_CMS_DECRYPT 0

#define RSA_F_RSA_CMS_VERIFY 0

#define RSA_F_RSA_ITEM_VERIFY 0

#define RSA_F_RSA_METH_DUP 0

#define RSA_F_RSA_METH_NEW 0

#define RSA_F_RSA_METH_SET1_NAME 0

#define RSA_F_RSA_MGF1_TO_MD 0

#define RSA_F_RSA_MULTIP_INFO_NEW 0

#define RSA_F_RSA_NEW_METHOD 0

#define RSA_F_RSA_NULL 0

#define RSA_F_RSA_NULL_PRIVATE_DECRYPT 0

#define RSA_F_RSA_NULL_PRIVATE_ENCRYPT 0

#define RSA_F_RSA_NULL_PUBLIC_DECRYPT 0

#define RSA_F_RSA_NULL_PUBLIC_ENCRYPT 0

#define RSA_F_RSA_OSSL_PRIVATE_DECRYPT 0

#define RSA_F_RSA_OSSL_PRIVATE_ENCRYPT 0

#define RSA_F_RSA_OSSL_PUBLIC_DECRYPT 0

#define RSA_F_RSA_OSSL_PUBLIC_ENCRYPT 0

#define RSA_F_RSA_PADDING_ADD_NONE 0

#define RSA_F_RSA_PADDING_ADD_PKCS1_OAEP 0

#define RSA_F_RSA_PADDING_ADD_PKCS1_OAEP_MGF1 0

#define RSA_F_RSA_PADDING_ADD_PKCS1_PSS 0

#define RSA_F_RSA_PADDING_ADD_PKCS1_PSS_MGF1 0

#define RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_1 0

#define RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_2 0

#define RSA_F_RSA_PADDING_ADD_SSLV23 0

#define RSA_F_RSA_PADDING_ADD_X931 0

#define RSA_F_RSA_PADDING_CHECK_NONE 0

#define RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP 0

#define RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP_MGF1 0

#define RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_1 0

#define RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_2 0

#define RSA_F_RSA_PADDING_CHECK_SSLV23 0

#define RSA_F_RSA_PADDING_CHECK_X931 0

#define RSA_F_RSA_PARAM_DECODE 0

#define RSA_F_RSA_PRINT 0

#define RSA_F_RSA_PRINT_FP 0

#define RSA_F_RSA_PRIV_DECODE 0

#define RSA_F_RSA_PRIV_ENCODE 0

#define RSA_F_RSA_PSS_GET_PARAM 0

#define RSA_F_RSA_PSS_TO_CTX 0

#define RSA_F_RSA_PUB_DECODE 0

#define RSA_F_RSA_SETUP_BLINDING 0

#define RSA_F_RSA_SIGN 0

#define RSA_F_RSA_SIGN_ASN1_OCTET_STRING 0

#define RSA_F_RSA_VERIFY 0

#define RSA_F_RSA_VERIFY_ASN1_OCTET_STRING 0

#define RSA_F_RSA_VERIFY_PKCS1_PSS_MGF1 0

#define RSA_F_SETUP_TBUF 0

#define OSSL_STORE_F_FILE_CTRL 0

#define OSSL_STORE_F_FILE_FIND 0

#define OSSL_STORE_F_FILE_GET_PASS 0

#define OSSL_STORE_F_FILE_LOAD 0

#define OSSL_STORE_F_FILE_LOAD_TRY_DECODE 0

#define OSSL_STORE_F_FILE_NAME_TO_URI 0

#define OSSL_STORE_F_FILE_OPEN 0

#define OSSL_STORE_F_OSSL_STORE_ATTACH_PEM_BIO 0

#define OSSL_STORE_F_OSSL_STORE_EXPECT 0

#define OSSL_STORE_F_OSSL_STORE_FILE_ATTACH_PEM_BIO_INT 0

#define OSSL_STORE_F_OSSL_STORE_FIND 0

#define OSSL_STORE_F_OSSL_STORE_GET0_LOADER_INT 0

#define OSSL_STORE_F_OSSL_STORE_INFO_GET1_CERT 0

#define OSSL_STORE_F_OSSL_STORE_INFO_GET1_CRL 0

#define OSSL_STORE_F_OSSL_STORE_INFO_GET1_NAME 0

#define OSSL_STORE_F_OSSL_STORE_INFO_GET1_NAME_DESCRIPTION 0

#define OSSL_STORE_F_OSSL_STORE_INFO_GET1_PARAMS 0

#define OSSL_STORE_F_OSSL_STORE_INFO_GET1_PKEY 0

#define OSSL_STORE_F_OSSL_STORE_INFO_NEW_CERT 0

#define OSSL_STORE_F_OSSL_STORE_INFO_NEW_CRL 0

#define OSSL_STORE_F_OSSL_STORE_INFO_NEW_EMBEDDED 0

#define OSSL_STORE_F_OSSL_STORE_INFO_NEW_NAME 0

#define OSSL_STORE_F_OSSL_STORE_INFO_NEW_PARAMS 0

#define OSSL_STORE_F_OSSL_STORE_INFO_NEW_PKEY 0

#define OSSL_STORE_F_OSSL_STORE_INFO_SET0_NAME_DESCRIPTION 0

#define OSSL_STORE_F_OSSL_STORE_INIT_ONCE 0

#define OSSL_STORE_F_OSSL_STORE_LOADER_NEW 0

#define OSSL_STORE_F_OSSL_STORE_OPEN 0

#define OSSL_STORE_F_OSSL_STORE_OPEN_INT 0

#define OSSL_STORE_F_OSSL_STORE_REGISTER_LOADER_INT 0

#define OSSL_STORE_F_OSSL_STORE_SEARCH_BY_ALIAS 0

#define OSSL_STORE_F_OSSL_STORE_SEARCH_BY_ISSUER_SERIAL 0

#define OSSL_STORE_F_OSSL_STORE_SEARCH_BY_KEY_FINGERPRINT 0

#define OSSL_STORE_F_OSSL_STORE_SEARCH_BY_NAME 0

#define OSSL_STORE_F_OSSL_STORE_UNREGISTER_LOADER_INT 0

#define OSSL_STORE_F_TRY_DECODE_PARAMS 0

#define OSSL_STORE_F_TRY_DECODE_PKCS12 0

#define OSSL_STORE_F_TRY_DECODE_PKCS8ENCRYPTED 0

#define TS_F_DEF_SERIAL_CB 0

#define TS_F_DEF_TIME_CB 0

#define TS_F_ESS_ADD_SIGNING_CERT 0

#define TS_F_ESS_ADD_SIGNING_CERT_V2 0

#define TS_F_ESS_CERT_ID_NEW_INIT 0

#define TS_F_ESS_CERT_ID_V2_NEW_INIT 0

#define TS_F_ESS_SIGNING_CERT_NEW_INIT 0

#define TS_F_ESS_SIGNING_CERT_V2_NEW_INIT 0

#define TS_F_INT_TS_RESP_VERIFY_TOKEN 0

#define TS_F_PKCS7_TO_TS_TST_INFO 0

#define TS_F_TS_ACCURACY_SET_MICROS 0

#define TS_F_TS_ACCURACY_SET_MILLIS 0

#define TS_F_TS_ACCURACY_SET_SECONDS 0

#define TS_F_TS_CHECK_IMPRINTS 0

#define TS_F_TS_CHECK_NONCES 0

#define TS_F_TS_CHECK_POLICY 0

#define TS_F_TS_CHECK_SIGNING_CERTS 0

#define TS_F_TS_CHECK_STATUS_INFO 0

#define TS_F_TS_COMPUTE_IMPRINT 0

#define TS_F_TS_CONF_INVALID 0

#define TS_F_TS_CONF_LOAD_CERT 0

#define TS_F_TS_CONF_LOAD_CERTS 0

#define TS_F_TS_CONF_LOAD_KEY 0

#define TS_F_TS_CONF_LOOKUP_FAIL 0

#define TS_F_TS_CONF_SET_DEFAULT_ENGINE 0

#define TS_F_TS_GET_STATUS_TEXT 0

#define TS_F_TS_MSG_IMPRINT_SET_ALGO 0

#define TS_F_TS_REQ_SET_MSG_IMPRINT 0

#define TS_F_TS_REQ_SET_NONCE 0

#define TS_F_TS_REQ_SET_POLICY_ID 0

#define TS_F_TS_RESP_CREATE_RESPONSE 0

#define TS_F_TS_RESP_CREATE_TST_INFO 0

#define TS_F_TS_RESP_CTX_ADD_FAILURE_INFO 0

#define TS_F_TS_RESP_CTX_ADD_MD 0

#define TS_F_TS_RESP_CTX_ADD_POLICY 0

#define TS_F_TS_RESP_CTX_NEW 0

#define TS_F_TS_RESP_CTX_SET_ACCURACY 0

#define TS_F_TS_RESP_CTX_SET_CERTS 0

#define TS_F_TS_RESP_CTX_SET_DEF_POLICY 0

#define TS_F_TS_RESP_CTX_SET_SIGNER_CERT 0

#define TS_F_TS_RESP_CTX_SET_STATUS_INFO 0

#define TS_F_TS_RESP_GET_POLICY 0

#define TS_F_TS_RESP_SET_GENTIME_WITH_PRECISION 0

#define TS_F_TS_RESP_SET_STATUS_INFO 0

#define TS_F_TS_RESP_SET_TST_INFO 0

#define TS_F_TS_RESP_SIGN 0

#define TS_F_TS_RESP_VERIFY_SIGNATURE 0

#define TS_F_TS_TST_INFO_SET_ACCURACY 0

#define TS_F_TS_TST_INFO_SET_MSG_IMPRINT 0

#define TS_F_TS_TST_INFO_SET_NONCE 0

#define TS_F_TS_TST_INFO_SET_POLICY_ID 0

#define TS_F_TS_TST_INFO_SET_SERIAL 0

#define TS_F_TS_TST_INFO_SET_TIME 0

#define TS_F_TS_TST_INFO_SET_TSA 0

#define TS_F_TS_VERIFY 0

#define TS_F_TS_VERIFY_CERT 0

#define TS_F_TS_VERIFY_CTX_NEW 0

#define UI_F_CLOSE_CONSOLE 0

#define UI_F_ECHO_CONSOLE 0

#define UI_F_GENERAL_ALLOCATE_BOOLEAN 0

#define UI_F_GENERAL_ALLOCATE_PROMPT 0

#define UI_F_NOECHO_CONSOLE 0

#define UI_F_OPEN_CONSOLE 0

#define UI_F_UI_CONSTRUCT_PROMPT 0

#define UI_F_UI_CREATE_METHOD 0

#define UI_F_UI_CTRL 0

#define UI_F_UI_DUP_ERROR_STRING 0

#define UI_F_UI_DUP_INFO_STRING 0

#define UI_F_UI_DUP_INPUT_BOOLEAN 0

#define UI_F_UI_DUP_INPUT_STRING 0

#define UI_F_UI_DUP_USER_DATA 0

#define UI_F_UI_DUP_VERIFY_STRING 0

#define UI_F_UI_GET0_RESULT 0

#define UI_F_UI_GET_RESULT_LENGTH 0

#define UI_F_UI_NEW_METHOD 0

#define UI_F_UI_PROCESS 0

#define UI_F_UI_SET_RESULT 0

#define UI_F_UI_SET_RESULT_EX 0

#define X509_F_ADD_CERT_DIR 0

#define X509_F_BUILD_CHAIN 0

#define X509_F_BY_FILE_CTRL 0

#define X509_F_CHECK_NAME_CONSTRAINTS 0

#define X509_F_CHECK_POLICY 0

#define X509_F_DANE_I2D 0

#define X509_F_DIR_CTRL 0

#define X509_F_GET_CERT_BY_SUBJECT 0

#define X509_F_I2D_X509_AUX 0

#define X509_F_LOOKUP_CERTS_SK 0

#define X509_F_NETSCAPE_SPKI_B64_DECODE 0

#define X509_F_NETSCAPE_SPKI_B64_ENCODE 0

#define X509_F_NEW_DIR 0

#define X509_F_X509AT_ADD1_ATTR 0

#define X509_F_X509V3_ADD_EXT 0

#define X509_F_X509_ATTRIBUTE_CREATE_BY_NID 0

#define X509_F_X509_ATTRIBUTE_CREATE_BY_OBJ 0

#define X509_F_X509_ATTRIBUTE_CREATE_BY_TXT 0

#define X509_F_X509_ATTRIBUTE_GET0_DATA 0

#define X509_F_X509_ATTRIBUTE_SET1_DATA 0

#define X509_F_X509_CHECK_PRIVATE_KEY 0

#define X509_F_X509_CRL_DIFF 0

#define X509_F_X509_CRL_METHOD_NEW 0

#define X509_F_X509_CRL_PRINT_FP 0

#define X509_F_X509_EXTENSION_CREATE_BY_NID 0

#define X509_F_X509_EXTENSION_CREATE_BY_OBJ 0

#define X509_F_X509_GET_PUBKEY_PARAMETERS 0

#define X509_F_X509_LOAD_CERT_CRL_FILE 0

#define X509_F_X509_LOAD_CERT_FILE 0

#define X509_F_X509_LOAD_CRL_FILE 0

#define X509_F_X509_LOOKUP_METH_NEW 0

#define X509_F_X509_LOOKUP_NEW 0

#define X509_F_X509_NAME_ADD_ENTRY 0

#define X509_F_X509_NAME_CANON 0

#define X509_F_X509_NAME_ENTRY_CREATE_BY_NID 0

#define X509_F_X509_NAME_ENTRY_CREATE_BY_TXT 0

#define X509_F_X509_NAME_ENTRY_SET_OBJECT 0

#define X509_F_X509_NAME_ONELINE 0

#define X509_F_X509_NAME_PRINT 0

#define X509_F_X509_OBJECT_NEW 0

#define X509_F_X509_PRINT_EX_FP 0

#define X509_F_X509_PUBKEY_DECODE 0

#define X509_F_X509_PUBKEY_GET 0

#define X509_F_X509_PUBKEY_GET0 0

#define X509_F_X509_PUBKEY_SET 0

#define X509_F_X509_REQ_CHECK_PRIVATE_KEY 0

#define X509_F_X509_REQ_PRINT_EX 0

#define X509_F_X509_REQ_PRINT_FP 0

#define X509_F_X509_REQ_TO_X509 0

#define X509_F_X509_STORE_ADD_CERT 0

#define X509_F_X509_STORE_ADD_CRL 0

#define X509_F_X509_STORE_ADD_LOOKUP 0

#define X509_F_X509_STORE_CTX_GET1_ISSUER 0

#define X509_F_X509_STORE_CTX_INIT 0

#define X509_F_X509_STORE_CTX_NEW 0

#define X509_F_X509_STORE_CTX_PURPOSE_INHERIT 0

#define X509_F_X509_STORE_NEW 0

#define X509_F_X509_TO_X509_REQ 0

#define X509_F_X509_TRUST_ADD 0

#define X509_F_X509_TRUST_SET 0

#define X509_F_X509_VERIFY_CERT 0

#define X509_F_X509_VERIFY_PARAM_NEW 0

#define X509V3_F_A2I_GENERAL_NAME 0

#define X509V3_F_ADDR_VALIDATE_PATH_INTERNAL 0

#define X509V3_F_ASIDENTIFIERCHOICE_CANONIZE 0

#define X509V3_F_ASIDENTIFIERCHOICE_IS_CANONICAL 0

#define X509V3_F_BIGNUM_TO_STRING 0

#define X509V3_F_COPY_EMAIL 0

#define X509V3_F_COPY_ISSUER 0

#define X509V3_F_DO_DIRNAME 0

#define X509V3_F_DO_EXT_I2D 0

#define X509V3_F_DO_EXT_NCONF 0

#define X509V3_F_GNAMES_FROM_SECTNAME 0

#define X509V3_F_I2S_ASN1_ENUMERATED 0

#define X509V3_F_I2S_ASN1_IA5STRING 0

#define X509V3_F_I2S_ASN1_INTEGER 0

#define X509V3_F_I2V_AUTHORITY_INFO_ACCESS 0

#define X509V3_F_LEVEL_ADD_NODE 0

#define X509V3_F_NOTICE_SECTION 0

#define X509V3_F_NREF_NOS 0

#define X509V3_F_POLICY_CACHE_CREATE 0

#define X509V3_F_POLICY_CACHE_NEW 0

#define X509V3_F_POLICY_DATA_NEW 0

#define X509V3_F_POLICY_SECTION 0

#define X509V3_F_PROCESS_PCI_VALUE 0

#define X509V3_F_R2I_CERTPOL 0

#define X509V3_F_R2I_PCI 0

#define X509V3_F_S2I_ASN1_IA5STRING 0

#define X509V3_F_S2I_ASN1_INTEGER 0

#define X509V3_F_S2I_ASN1_OCTET_STRING 0

#define X509V3_F_S2I_SKEY_ID 0

#define X509V3_F_SET_DIST_POINT_NAME 0

#define X509V3_F_SXNET_ADD_ID_ASC 0

#define X509V3_F_SXNET_ADD_ID_INTEGER 0

#define X509V3_F_SXNET_ADD_ID_ULONG 0

#define X509V3_F_SXNET_GET_ID_ASC 0

#define X509V3_F_SXNET_GET_ID_ULONG 0

#define X509V3_F_TREE_INIT 0

#define X509V3_F_V2I_ASIDENTIFIERS 0

#define X509V3_F_V2I_ASN1_BIT_STRING 0

#define X509V3_F_V2I_AUTHORITY_INFO_ACCESS 0

#define X509V3_F_V2I_AUTHORITY_KEYID 0

#define X509V3_F_V2I_BASIC_CONSTRAINTS 0

#define X509V3_F_V2I_CRLD 0

#define X509V3_F_V2I_EXTENDED_KEY_USAGE 0

#define X509V3_F_V2I_GENERAL_NAMES 0

#define X509V3_F_V2I_GENERAL_NAME_EX 0

#define X509V3_F_V2I_IDP 0

#define X509V3_F_V2I_IPADDRBLOCKS 0

#define X509V3_F_V2I_ISSUER_ALT 0

#define X509V3_F_V2I_NAME_CONSTRAINTS 0

#define X509V3_F_V2I_POLICY_CONSTRAINTS 0

#define X509V3_F_V2I_POLICY_MAPPINGS 0

#define X509V3_F_V2I_SUBJECT_ALT 0

#define X509V3_F_V2I_TLS_FEATURE 0

#define X509V3_F_V3_GENERIC_EXTENSION 0

#define X509V3_F_X509V3_ADD1_I2D 0

#define X509V3_F_X509V3_ADD_VALUE 0

#define X509V3_F_X509V3_EXT_ADD 0

#define X509V3_F_X509V3_EXT_ADD_ALIAS 0

#define X509V3_F_X509V3_EXT_I2D 0

#define X509V3_F_X509V3_EXT_NCONF 0

#define X509V3_F_X509V3_GET_SECTION 0

#define X509V3_F_X509V3_GET_STRING 0

#define X509V3_F_X509V3_GET_VALUE_BOOL 0

#define X509V3_F_X509V3_PARSE_LIST 0

#define X509V3_F_X509_PURPOSE_ADD 0

#define X509V3_F_X509_PURPOSE_SET 0

#define EVP_R_OPERATON_NOT_INITIALIZED EVP_R_OPERATION_NOT_INITIALIZED

#define OPENSSL_CT_H 

#define HEADER_CT_H 

#define SCT_MIN_RSA_BITS 2048

#define CT_V1_HASHLEN SHA256_DIGEST_LENGTH

#define OPENSSL_CTERR_H 

#define CT_R_BASE64_DECODE_ERROR 108

#define CT_R_INVALID_LOG_ID_LENGTH 100

#define CT_R_LOG_CONF_INVALID 109

#define CT_R_LOG_CONF_INVALID_KEY 110

#define CT_R_LOG_CONF_MISSING_DESCRIPTION 111

#define CT_R_LOG_CONF_MISSING_KEY 112

#define CT_R_LOG_KEY_INVALID 113

#define CT_R_SCT_FUTURE_TIMESTAMP 116

#define CT_R_SCT_INVALID 104

#define CT_R_SCT_INVALID_SIGNATURE 107

#define CT_R_SCT_LIST_INVALID 105

#define CT_R_SCT_LOG_ID_MISMATCH 114

#define CT_R_SCT_NOT_SET 106

#define CT_R_SCT_UNSUPPORTED_VERSION 115

#define CT_R_UNRECOGNIZED_SIGNATURE_NID 101

#define CT_R_UNSUPPORTED_ENTRY_TYPE 102

#define CT_R_UNSUPPORTED_VERSION 103

#define OPENSSL_DECODER_H 

#define OPENSSL_DECODERERR_H 

#define OSSL_DECODER_R_COULD_NOT_DECODE_OBJECT 101

#define OSSL_DECODER_R_DECODER_NOT_FOUND 102

#define OSSL_DECODER_R_MISSING_GET_PARAMS 100

#define OPENSSL_DES_H 

#define HEADER_DES_H 

#define DES_KEY_SZ (sizeof(DES_cblock))

#define DES_SCHEDULE_SZ (sizeof(DES_key_schedule))

#define DES_ENCRYPT 1

#define DES_DECRYPT 0

#define DES_CBC_MODE 0

#define DES_PCBC_MODE 1

#define DES_ecb2_encrypt (i,o,k1,k2,e)\
	DES_ecb3_encrypt((i),(o),(k1),(k2),(k1),(e))

#define DES_ede2_cbc_encrypt (i,o,l,k1,k2,iv,e)\
	DES_ede3_cbc_encrypt((i),(o),(l),(k1),(k2),(k1),(iv),(e))

#define DES_ede2_cfb64_encrypt (i,o,l,k1,k2,iv,n,e)\
	DES_ede3_cfb64_encrypt((i),(o),(l),(k1),(k2),(k1),(iv),(n),(e))

#define DES_ede2_ofb64_encrypt (i,o,l,k1,k2,iv,n)\
	DES_ede3_ofb64_encrypt((i),(o),(l),(k1),(k2),(k1),(iv),(n))

#define DES_fixup_key_parity DES_set_odd_parity

#define OPENSSL_DH_H 

#define HEADER_DH_H 

#define DH_PARAMGEN_TYPE_GENERATOR 0

#define DH_PARAMGEN_TYPE_FIPS_186_2 1

#define DH_PARAMGEN_TYPE_FIPS_186_4 2

#define DH_PARAMGEN_TYPE_GROUP 3

#define EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN (EVP_PKEY_ALG_CTRL + 1)

#define EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR (EVP_PKEY_ALG_CTRL + 2)

#define EVP_PKEY_CTRL_DH_RFC5114 (EVP_PKEY_ALG_CTRL + 3)

#define EVP_PKEY_CTRL_DH_PARAMGEN_SUBPRIME_LEN (EVP_PKEY_ALG_CTRL + 4)

#define EVP_PKEY_CTRL_DH_PARAMGEN_TYPE (EVP_PKEY_ALG_CTRL + 5)

#define EVP_PKEY_CTRL_DH_KDF_TYPE (EVP_PKEY_ALG_CTRL + 6)

#define EVP_PKEY_CTRL_DH_KDF_MD (EVP_PKEY_ALG_CTRL + 7)

#define EVP_PKEY_CTRL_GET_DH_KDF_MD (EVP_PKEY_ALG_CTRL + 8)

#define EVP_PKEY_CTRL_DH_KDF_OUTLEN (EVP_PKEY_ALG_CTRL + 9)

#define EVP_PKEY_CTRL_GET_DH_KDF_OUTLEN (EVP_PKEY_ALG_CTRL + 10)

#define EVP_PKEY_CTRL_DH_KDF_UKM (EVP_PKEY_ALG_CTRL + 11)

#define EVP_PKEY_CTRL_GET_DH_KDF_UKM (EVP_PKEY_ALG_CTRL + 12)

#define EVP_PKEY_CTRL_DH_KDF_OID (EVP_PKEY_ALG_CTRL + 13)

#define EVP_PKEY_CTRL_GET_DH_KDF_OID (EVP_PKEY_ALG_CTRL + 14)

#define EVP_PKEY_CTRL_DH_NID (EVP_PKEY_ALG_CTRL + 15)

#define EVP_PKEY_CTRL_DH_PAD (EVP_PKEY_ALG_CTRL + 16)

#define EVP_PKEY_DH_KDF_NONE 1

#define EVP_PKEY_DH_KDF_X9_42 2

#define OPENSSL_DH_MAX_MODULUS_BITS 10000

#define OPENSSL_DH_CHECK_MAX_MODULUS_BITS 32768

#define OPENSSL_DH_FIPS_MIN_MODULUS_BITS 1024

#define DH_FLAG_CACHE_MONT_P 0x01

#define DH_FLAG_TYPE_MASK 0xF000

#define DH_FLAG_TYPE_DH 0x0000

#define DH_FLAG_TYPE_DHX 0x1000

#define DH_FLAG_NO_EXP_CONSTTIME 0x00

#define DH_FLAG_FIPS_METHOD 0x0400

#define DH_FLAG_NON_FIPS_ALLOW 0x0400

#define DH_GENERATOR_2 2

#define DH_GENERATOR_3 3

#define DH_GENERATOR_5 5

#define DH_CHECK_P_NOT_PRIME 0x01

#define DH_CHECK_P_NOT_SAFE_PRIME 0x02

#define DH_UNABLE_TO_CHECK_GENERATOR 0x04

#define DH_NOT_SUITABLE_GENERATOR 0x08

#define DH_CHECK_Q_NOT_PRIME 0x10

#define DH_CHECK_INVALID_Q_VALUE 0x20

#define DH_CHECK_INVALID_J_VALUE 0x40

#define DH_MODULUS_TOO_SMALL 0x80

#define DH_MODULUS_TOO_LARGE 0x100

#define DH_CHECK_PUBKEY_TOO_SMALL 0x01

#define DH_CHECK_PUBKEY_TOO_LARGE 0x02

#define DH_CHECK_PUBKEY_INVALID 0x04

#define DH_CHECK_P_NOT_STRONG_PRIME DH_CHECK_P_NOT_SAFE_PRIME

#define d2i_DHparams_fp (fp, x)\
	(DH *)ASN1_d2i_fp((char *(*)())DH_new, \\
	(char *(*)())d2i_DHparams, \\
	(fp), \\
	(unsigned char **)(x))

#define i2d_DHparams_fp (fp, x)\
	ASN1_i2d_fp(i2d_DHparams,(fp), (unsigned char *)(x))

#define d2i_DHparams_bio (bp, x)\
	ASN1_d2i_bio_of(DH, DH_new, d2i_DHparams, bp, x)

#define i2d_DHparams_bio (bp, x)\
	ASN1_i2d_bio_of(DH, i2d_DHparams, bp, x)

#define d2i_DHxparams_fp (fp,x)\
	(DH *)ASN1_d2i_fp((char *(*)())DH_new, \\
	(char *(*)())d2i_DHxparams, \\
	(fp), \\
	(unsigned char **)(x))

#define i2d_DHxparams_fp (fp, x)\
	ASN1_i2d_fp(i2d_DHxparams,(fp), (unsigned char *)(x))

#define d2i_DHxparams_bio (bp, x)\
	ASN1_d2i_bio_of(DH, DH_new, d2i_DHxparams, bp, x)

#define i2d_DHxparams_bio (bp, x)\
	ASN1_i2d_bio_of(DH, i2d_DHxparams, bp, x)

#define DH_get_ex_new_index (l, p, newf, dupf, freef)\
	CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_DH, l, p, newf, dupf, freef)

#define OPENSSL_DHERR_H 

#define DH_R_BAD_FFC_PARAMETERS 127

#define DH_R_BAD_GENERATOR 101

#define DH_R_BN_DECODE_ERROR 109

#define DH_R_BN_ERROR 106

#define DH_R_CHECK_INVALID_J_VALUE 115

#define DH_R_CHECK_INVALID_Q_VALUE 116

#define DH_R_CHECK_PUBKEY_INVALID 122

#define DH_R_CHECK_PUBKEY_TOO_LARGE 123

#define DH_R_CHECK_PUBKEY_TOO_SMALL 124

#define DH_R_CHECK_P_NOT_PRIME 117

#define DH_R_CHECK_P_NOT_SAFE_PRIME 118

#define DH_R_CHECK_Q_NOT_PRIME 119

#define DH_R_DECODE_ERROR 104

#define DH_R_INVALID_PARAMETER_NAME 110

#define DH_R_INVALID_PARAMETER_NID 114

#define DH_R_INVALID_PUBKEY 102

#define DH_R_INVALID_SECRET 128

#define DH_R_INVALID_SIZE 129

#define DH_R_KDF_PARAMETER_ERROR 112

#define DH_R_KEYS_NOT_SET 108

#define DH_R_MISSING_PUBKEY 125

#define DH_R_MODULUS_TOO_LARGE 103

#define DH_R_MODULUS_TOO_SMALL 126

#define DH_R_NOT_SUITABLE_GENERATOR 120

#define DH_R_NO_PARAMETERS_SET 107

#define DH_R_NO_PRIVATE_VALUE 100

#define DH_R_PARAMETER_ENCODING_ERROR 105

#define DH_R_PEER_KEY_ERROR 111

#define DH_R_Q_TOO_LARGE 130

#define DH_R_SHARED_INFO_ERROR 113

#define DH_R_UNABLE_TO_CHECK_GENERATOR 121

#define OPENSSL_DSA_H 

#define HEADER_DSA_H 

#define EVP_PKEY_CTRL_DSA_PARAMGEN_BITS (EVP_PKEY_ALG_CTRL + 1)

#define EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS (EVP_PKEY_ALG_CTRL + 2)

#define EVP_PKEY_CTRL_DSA_PARAMGEN_MD (EVP_PKEY_ALG_CTRL + 3)

#define OPENSSL_DSA_MAX_MODULUS_BITS 10000

#define OPENSSL_DSA_FIPS_MIN_MODULUS_BITS 1024

#define DSA_FLAG_NO_EXP_CONSTTIME 0x00

#define DSA_FLAG_CACHE_MONT_P 0x01

#define DSA_FLAG_FIPS_METHOD 0x0400

#define DSA_FLAG_NON_FIPS_ALLOW 0x0400

#define DSA_FLAG_FIPS_CHECKED 0x0800

#define d2i_DSAparams_fp (fp, x)\
	(DSA *)ASN1_d2i_fp((char *(*)())DSA_new, \\
	(char *(*)())d2i_DSAparams, (fp), \\
	(unsigned char **)(x))

#define i2d_DSAparams_fp (fp, x)\
	ASN1_i2d_fp(i2d_DSAparams, (fp), (unsigned char *)(x))

#define d2i_DSAparams_bio (bp, x)\
	ASN1_d2i_bio_of(DSA, DSA_new, d2i_DSAparams, bp, x)

#define i2d_DSAparams_bio (bp, x)\
	ASN1_i2d_bio_of(DSA, i2d_DSAparams, bp, x)

#define DSA_get_ex_new_index (l, p, newf, dupf, freef)\
	CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_DSA, l, p, newf, dupf, freef)

#define DSS_prime_checks 64

#define DSA_is_prime (n, callback, cb_arg)\
	BN_is_prime(n, DSS_prime_checks, callback, NULL, cb_arg)

#define OPENSSL_DSAERR_H 

#define DSA_R_BAD_FFC_PARAMETERS 114

#define DSA_R_BAD_Q_VALUE 102

#define DSA_R_BN_DECODE_ERROR 108

#define DSA_R_BN_ERROR 109

#define DSA_R_DECODE_ERROR 104

#define DSA_R_INVALID_DIGEST_TYPE 106

#define DSA_R_INVALID_PARAMETERS 112

#define DSA_R_MISSING_PARAMETERS 101

#define DSA_R_MISSING_PRIVATE_KEY 111

#define DSA_R_MODULUS_TOO_LARGE 103

#define DSA_R_NO_PARAMETERS_SET 107

#define DSA_R_PARAMETER_ENCODING_ERROR 105

#define DSA_R_P_NOT_PRIME 115

#define DSA_R_Q_NOT_PRIME 113

#define DSA_R_SEED_LEN_SMALL 110

#define DSA_R_TOO_MANY_RETRIES 116

#define OPENSSL_DTLS1_H 

#define HEADER_DTLS1_H 

#define DTLS_MIN_VERSION DTLS1_VERSION

#define DTLS_MAX_VERSION DTLS1_2_VERSION

#define DTLS1_VERSION_MAJOR 0xFE

#define DTLS_ANY_VERSION 0x1FFFF

#define DTLS1_COOKIE_LENGTH 255

#define DTLS1_RT_HEADER_LENGTH 13

#define DTLS1_HM_HEADER_LENGTH 12

#define DTLS1_HM_BAD_FRAGMENT -2

#define DTLS1_HM_FRAGMENT_RETRY -3

#define DTLS1_CCS_HEADER_LENGTH 1

#define DTLS1_AL_HEADER_LENGTH 2

#define DTLS1_TMO_ALERT_COUNT 12

#define OPENSSL_EBCDIC_H 

#define HEADER_EBCDIC_H 

#define os_toascii _openssl_os_toascii

#define os_toebcdic _openssl_os_toebcdic

#define ebcdic2ascii _openssl_ebcdic2ascii

#define ascii2ebcdic _openssl_ascii2ebcdic

#define OPENSSL_EC_H 

#define HEADER_EC_H 

#define OPENSSL_EC_EXPLICIT_CURVE 0x000

#define OPENSSL_EC_NAMED_CURVE 0x001

#define EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID (EVP_PKEY_ALG_CTRL + 1)

#define EVP_PKEY_CTRL_EC_PARAM_ENC (EVP_PKEY_ALG_CTRL + 2)

#define EVP_PKEY_CTRL_EC_ECDH_COFACTOR (EVP_PKEY_ALG_CTRL + 3)

#define EVP_PKEY_CTRL_EC_KDF_TYPE (EVP_PKEY_ALG_CTRL + 4)

#define EVP_PKEY_CTRL_EC_KDF_MD (EVP_PKEY_ALG_CTRL + 5)

#define EVP_PKEY_CTRL_GET_EC_KDF_MD (EVP_PKEY_ALG_CTRL + 6)

#define EVP_PKEY_CTRL_EC_KDF_OUTLEN (EVP_PKEY_ALG_CTRL + 7)

#define EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN (EVP_PKEY_ALG_CTRL + 8)

#define EVP_PKEY_CTRL_EC_KDF_UKM (EVP_PKEY_ALG_CTRL + 9)

#define EVP_PKEY_CTRL_GET_EC_KDF_UKM (EVP_PKEY_ALG_CTRL + 10)

#define EVP_PKEY_ECDH_KDF_NONE 1

#define EVP_PKEY_ECDH_KDF_X9_63 2

#define EVP_PKEY_ECDH_KDF_X9_62 EVP_PKEY_ECDH_KDF_X9_63

#define OPENSSL_ECC_MAX_FIELD_BITS 661

#define d2i_ECPKParameters_bio (bp,x)\
	ASN1_d2i_bio_of(EC_GROUP, NULL, d2i_ECPKParameters, bp, x)

#define i2d_ECPKParameters_bio (bp,x)\
	ASN1_i2d_bio_of(EC_GROUP, i2d_ECPKParameters, bp, x)

#define d2i_ECPKParameters_fp (fp,x)\
	(EC_GROUP *)ASN1_d2i_fp(NULL, (d2i_of_void *)d2i_ECPKParameters, (fp), \\
	(void **)(x))

#define i2d_ECPKParameters_fp (fp,x)\
	ASN1_i2d_fp((i2d_of_void *)i2d_ECPKParameters, (fp), (void *)(x))

#define EC_PKEY_NO_PARAMETERS 0x001

#define EC_PKEY_NO_PUBKEY 0x002

#define EC_FLAG_SM2_RANGE 0x0004

#define EC_FLAG_COFACTOR_ECDH 0x1000

#define EC_FLAG_CHECK_NAMED_GROUP 0x2000

#define EC_FLAG_CHECK_NAMED_GROUP_NIST 0x4000

#define EC_FLAG_CHECK_NAMED_GROUP_MASK \
	(EC_FLAG_CHECK_NAMED_GROUP | EC_FLAG_CHECK_NAMED_GROUP_NIST)

#define EC_FLAG_NON_FIPS_ALLOW 0x0000

#define EC_FLAG_FIPS_CHECKED 0x0000

#define EC_KEY_get_ex_new_index (l, p, newf, dupf, freef)\
	CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_EC_KEY, l, p, newf, dupf, freef)

#define EVP_EC_gen (curve)\
	EVP_PKEY_Q_keygen(NULL, NULL, "EC", (char *)(strstr(curve, "")))

#define ECParameters_dup (x) ASN1_dup_of(EC_KEY, i2d_ECParameters,\
	d2i_ECParameters, x)

#define OPENSSL_ECERR_H 

#define EC_R_ASN1_ERROR 115

#define EC_R_BAD_SIGNATURE 156

#define EC_R_BIGNUM_OUT_OF_RANGE 144

#define EC_R_BUFFER_TOO_SMALL 100

#define EC_R_CANNOT_INVERT 165

#define EC_R_COORDINATES_OUT_OF_RANGE 146

#define EC_R_CURVE_DOES_NOT_SUPPORT_ECDH 160

#define EC_R_CURVE_DOES_NOT_SUPPORT_ECDSA 170

#define EC_R_CURVE_DOES_NOT_SUPPORT_SIGNING 159

#define EC_R_DECODE_ERROR 142

#define EC_R_DISCRIMINANT_IS_ZERO 118

#define EC_R_EC_GROUP_NEW_BY_NAME_FAILURE 119

#define EC_R_EXPLICIT_PARAMS_NOT_SUPPORTED 127

#define EC_R_FAILED_MAKING_PUBLIC_KEY 166

#define EC_R_FIELD_TOO_LARGE 143

#define EC_R_GF2M_NOT_SUPPORTED 147

#define EC_R_GROUP2PKPARAMETERS_FAILURE 120

#define EC_R_I2D_ECPKPARAMETERS_FAILURE 121

#define EC_R_INCOMPATIBLE_OBJECTS 101

#define EC_R_INVALID_A 168

#define EC_R_INVALID_ARGUMENT 112

#define EC_R_INVALID_B 169

#define EC_R_INVALID_COFACTOR 171

#define EC_R_INVALID_COMPRESSED_POINT 110

#define EC_R_INVALID_COMPRESSION_BIT 109

#define EC_R_INVALID_CURVE 141

#define EC_R_INVALID_DIGEST 151

#define EC_R_INVALID_DIGEST_TYPE 138

#define EC_R_INVALID_ENCODING 102

#define EC_R_INVALID_FIELD 103

#define EC_R_INVALID_FORM 104

#define EC_R_INVALID_GENERATOR 173

#define EC_R_INVALID_GROUP_ORDER 122

#define EC_R_INVALID_KEY 116

#define EC_R_INVALID_LENGTH 117

#define EC_R_INVALID_NAMED_GROUP_CONVERSION 174

#define EC_R_INVALID_OUTPUT_LENGTH 161

#define EC_R_INVALID_P 172

#define EC_R_INVALID_PEER_KEY 133

#define EC_R_INVALID_PENTANOMIAL_BASIS 132

#define EC_R_INVALID_PRIVATE_KEY 123

#define EC_R_INVALID_SEED 175

#define EC_R_INVALID_TRINOMIAL_BASIS 137

#define EC_R_KDF_PARAMETER_ERROR 148

#define EC_R_KEYS_NOT_SET 140

#define EC_R_LADDER_POST_FAILURE 136

#define EC_R_LADDER_PRE_FAILURE 153

#define EC_R_LADDER_STEP_FAILURE 162

#define EC_R_MISSING_OID 167

#define EC_R_MISSING_PARAMETERS 124

#define EC_R_MISSING_PRIVATE_KEY 125

#define EC_R_NEED_NEW_SETUP_VALUES 157

#define EC_R_NOT_A_NIST_PRIME 135

#define EC_R_NOT_IMPLEMENTED 126

#define EC_R_NOT_INITIALIZED 111

#define EC_R_NO_PARAMETERS_SET 139

#define EC_R_NO_PRIVATE_VALUE 154

#define EC_R_OPERATION_NOT_SUPPORTED 152

#define EC_R_PASSED_NULL_PARAMETER 134

#define EC_R_PEER_KEY_ERROR 149

#define EC_R_POINT_ARITHMETIC_FAILURE 155

#define EC_R_POINT_AT_INFINITY 106

#define EC_R_POINT_COORDINATES_BLIND_FAILURE 163

#define EC_R_POINT_IS_NOT_ON_CURVE 107

#define EC_R_RANDOM_NUMBER_GENERATION_FAILED 158

#define EC_R_SHARED_INFO_ERROR 150

#define EC_R_SLOT_FULL 108

#define EC_R_TOO_MANY_RETRIES 176

#define EC_R_UNDEFINED_GENERATOR 113

#define EC_R_UNDEFINED_ORDER 128

#define EC_R_UNKNOWN_COFACTOR 164

#define EC_R_UNKNOWN_GROUP 129

#define EC_R_UNKNOWN_ORDER 114

#define EC_R_UNSUPPORTED_FIELD 131

#define EC_R_WRONG_CURVE_PARAMETERS 145

#define EC_R_WRONG_ORDER 130

#define OPENSSL_ENCODER_H 

#define OPENSSL_ENCODERERR_H 

#define OSSL_ENCODER_R_ENCODER_NOT_FOUND 101

#define OSSL_ENCODER_R_INCORRECT_PROPERTY_QUERY 100

#define OSSL_ENCODER_R_MISSING_GET_PARAMS 102

#define OPENSSL_ENGINE_H 

#define HEADER_ENGINE_H 

#define ENGINE_METHOD_RSA (unsigned int)0x0001

#define ENGINE_METHOD_DSA (unsigned int)0x0002

#define ENGINE_METHOD_DH (unsigned int)0x0004

#define ENGINE_METHOD_RAND (unsigned int)0x0008

#define ENGINE_METHOD_CIPHERS (unsigned int)0x0040

#define ENGINE_METHOD_DIGESTS (unsigned int)0x0080

#define ENGINE_METHOD_PKEY_METHS (unsigned int)0x0200

#define ENGINE_METHOD_PKEY_ASN1_METHS (unsigned int)0x0400

#define ENGINE_METHOD_EC (unsigned int)0x0800

#define ENGINE_METHOD_ALL (unsigned int)0xFFFF

#define ENGINE_METHOD_NONE (unsigned int)0x0000

#define ENGINE_TABLE_FLAG_NOINIT (unsigned int)0x0001

#define ENGINE_FLAGS_MANUAL_CMD_CTRL (int)0x0002

#define ENGINE_FLAGS_BY_ID_COPY (int)0x0004

#define ENGINE_FLAGS_NO_REGISTER_ALL (int)0x0008

#define ENGINE_CMD_FLAG_NUMERIC (unsigned int)0x0001

#define ENGINE_CMD_FLAG_STRING (unsigned int)0x0002

#define ENGINE_CMD_FLAG_NO_INPUT (unsigned int)0x0004

#define ENGINE_CMD_FLAG_INTERNAL (unsigned int)0x0008

#define ENGINE_CTRL_SET_LOGSTREAM 1

#define ENGINE_CTRL_SET_PASSWORD_CALLBACK 2

#define ENGINE_CTRL_HUP 3

#define ENGINE_CTRL_SET_USER_INTERFACE 4

#define ENGINE_CTRL_SET_CALLBACK_DATA 5

#define ENGINE_CTRL_LOAD_CONFIGURATION 6

#define ENGINE_CTRL_LOAD_SECTION 7

#define ENGINE_CTRL_HAS_CTRL_FUNCTION 10

#define ENGINE_CTRL_GET_FIRST_CMD_TYPE 11

#define ENGINE_CTRL_GET_NEXT_CMD_TYPE 12

#define ENGINE_CTRL_GET_CMD_FROM_NAME 13

#define ENGINE_CTRL_GET_NAME_LEN_FROM_CMD 14

#define ENGINE_CTRL_GET_NAME_FROM_CMD 15

#define ENGINE_CTRL_GET_DESC_LEN_FROM_CMD 16

#define ENGINE_CTRL_GET_DESC_FROM_CMD 17

#define ENGINE_CTRL_GET_CMD_FLAGS 18

#define ENGINE_CMD_BASE 200

#define ENGINE_CTRL_CHIL_SET_FORKCHECK 100

#define ENGINE_CTRL_CHIL_NO_LOCKING 101

#define ENGINE_load_openssl ()\
	OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_OPENSSL, NULL)

#define ENGINE_load_dynamic ()\
	OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_DYNAMIC, NULL)

#define ENGINE_load_padlock ()\
	OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_PADLOCK, NULL)

#define ENGINE_load_capi ()\
	OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_CAPI, NULL)

#define ENGINE_load_afalg ()\
	OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_AFALG, NULL)

#define ENGINE_load_cryptodev ()\
	OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_CRYPTODEV, NULL)

#define ENGINE_load_rdrand ()\
	OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_RDRAND, NULL)

#define ENGINE_get_ex_new_index (l, p, newf, dupf, freef)\
	CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_ENGINE, l, p, newf, dupf, freef)

#define ENGINE_cleanup () while(0) continue

#define OSSL_DYNAMIC_VERSION (unsigned long)0x00030000

#define OSSL_DYNAMIC_OLDEST (unsigned long)0x00030000

#define IMPLEMENT_DYNAMIC_CHECK_FN ()\
	OPENSSL_EXPORT unsigned long v_check(unsigned long v); \\
	OPENSSL_EXPORT unsigned long v_check(unsigned long v) { \\
	if (v >= OSSL_DYNAMIC_OLDEST) return OSSL_DYNAMIC_VERSION; \\
	return 0; }

#define IMPLEMENT_DYNAMIC_BIND_FN (fn)\
	OPENSSL_EXPORT \\
	int bind_engine(ENGINE *e, const char *id, const dynamic_fns *fns); \\
	OPENSSL_EXPORT \\
	int bind_engine(ENGINE *e, const char *id, const dynamic_fns *fns) { \\
	if (ENGINE_get_static_state() == fns->static_state) goto skip_cbs; \\
	CRYPTO_set_mem_functions(fns->mem_fns.malloc_fn, \\
	fns->mem_fns.realloc_fn, \\
	fns->mem_fns.free_fn); \\
	OPENSSL_init_crypto(OPENSSL_INIT_NO_ATEXIT, NULL); \\
	skip_cbs: \\
	if (!fn(e, id)) return 0; \\
	return 1; }

#define OPENSSL_ENGINEERR_H 

#define ENGINE_R_ALREADY_LOADED 100

#define ENGINE_R_ARGUMENT_IS_NOT_A_NUMBER 133

#define ENGINE_R_CMD_NOT_EXECUTABLE 134

#define ENGINE_R_COMMAND_TAKES_INPUT 135

#define ENGINE_R_COMMAND_TAKES_NO_INPUT 136

#define ENGINE_R_CONFLICTING_ENGINE_ID 103

#define ENGINE_R_CTRL_COMMAND_NOT_IMPLEMENTED 119

#define ENGINE_R_DSO_FAILURE 104

#define ENGINE_R_DSO_NOT_FOUND 132

#define ENGINE_R_ENGINES_SECTION_ERROR 148

#define ENGINE_R_ENGINE_CONFIGURATION_ERROR 102

#define ENGINE_R_ENGINE_IS_NOT_IN_LIST 105

#define ENGINE_R_ENGINE_SECTION_ERROR 149

#define ENGINE_R_FAILED_LOADING_PRIVATE_KEY 128

#define ENGINE_R_FAILED_LOADING_PUBLIC_KEY 129

#define ENGINE_R_FINISH_FAILED 106

#define ENGINE_R_ID_OR_NAME_MISSING 108

#define ENGINE_R_INIT_FAILED 109

#define ENGINE_R_INTERNAL_LIST_ERROR 110

#define ENGINE_R_INVALID_ARGUMENT 143

#define ENGINE_R_INVALID_CMD_NAME 137

#define ENGINE_R_INVALID_CMD_NUMBER 138

#define ENGINE_R_INVALID_INIT_VALUE 151

#define ENGINE_R_INVALID_STRING 150

#define ENGINE_R_NOT_INITIALISED 117

#define ENGINE_R_NOT_LOADED 112

#define ENGINE_R_NO_CONTROL_FUNCTION 120

#define ENGINE_R_NO_INDEX 144

#define ENGINE_R_NO_LOAD_FUNCTION 125

#define ENGINE_R_NO_REFERENCE 130

#define ENGINE_R_NO_SUCH_ENGINE 116

#define ENGINE_R_UNIMPLEMENTED_CIPHER 146

#define ENGINE_R_UNIMPLEMENTED_DIGEST 147

#define ENGINE_R_UNIMPLEMENTED_PUBLIC_KEY_METHOD 101

#define ENGINE_R_VERSION_INCOMPATIBILITY 145

#define OPENSSL_ERR_H 

#define HEADER_ERR_H 

#define ERR_PUT_error (l,f,r,fn,ln)      ERR_put_error(l,f,r,fn,ln)

#define ERR_TXT_MALLOCED 0x01

#define ERR_TXT_STRING 0x02

#define ERR_FLAG_MARK 0x01

#define ERR_FLAG_CLEAR 0x02

#define ERR_NUM_ERRORS 16

#define ERR_LIB_NONE 1

#define ERR_LIB_SYS 2

#define ERR_LIB_BN 3

#define ERR_LIB_RSA 4

#define ERR_LIB_DH 5

#define ERR_LIB_EVP 6

#define ERR_LIB_BUF 7

#define ERR_LIB_OBJ 8

#define ERR_LIB_PEM 9

#define ERR_LIB_DSA 10

#define ERR_LIB_X509 11

#define ERR_LIB_ASN1 13

#define ERR_LIB_CONF 14

#define ERR_LIB_CRYPTO 15

#define ERR_LIB_EC 16

#define ERR_LIB_SSL 20

#define ERR_LIB_BIO 32

#define ERR_LIB_PKCS7 33

#define ERR_LIB_X509V3 34

#define ERR_LIB_PKCS12 35

#define ERR_LIB_RAND 36

#define ERR_LIB_DSO 37

#define ERR_LIB_ENGINE 38

#define ERR_LIB_OCSP 39

#define ERR_LIB_UI 40

#define ERR_LIB_COMP 41

#define ERR_LIB_ECDSA 42

#define ERR_LIB_ECDH 43

#define ERR_LIB_OSSL_STORE 44

#define ERR_LIB_FIPS 45

#define ERR_LIB_CMS 46

#define ERR_LIB_TS 47

#define ERR_LIB_HMAC 48

#define ERR_LIB_CT 50

#define ERR_LIB_ASYNC 51

#define ERR_LIB_KDF 52

#define ERR_LIB_SM2 53

#define ERR_LIB_ESS 54

#define ERR_LIB_PROP 55

#define ERR_LIB_CRMF 56

#define ERR_LIB_PROV 57

#define ERR_LIB_CMP 58

#define ERR_LIB_OSSL_ENCODER 59

#define ERR_LIB_OSSL_DECODER 60

#define ERR_LIB_HTTP 61

#define ERR_LIB_USER 128

#define ASN1err (f, r) ERR_raise_data(ERR_LIB_ASN1, (r), NULL)

#define ASYNCerr (f, r) ERR_raise_data(ERR_LIB_ASYNC, (r), NULL)

#define BIOerr (f, r) ERR_raise_data(ERR_LIB_BIO, (r), NULL)

#define BNerr (f, r)  ERR_raise_data(ERR_LIB_BN, (r), NULL)

#define BUFerr (f, r) ERR_raise_data(ERR_LIB_BUF, (r), NULL)

#define CMPerr (f, r) ERR_raise_data(ERR_LIB_CMP, (r), NULL)

#define CMSerr (f, r) ERR_raise_data(ERR_LIB_CMS, (r), NULL)

#define COMPerr (f, r) ERR_raise_data(ERR_LIB_COMP, (r), NULL)

#define CONFerr (f, r) ERR_raise_data(ERR_LIB_CONF, (r), NULL)

#define CRMFerr (f, r) ERR_raise_data(ERR_LIB_CRMF, (r), NULL)

#define CRYPTOerr (f, r) ERR_raise_data(ERR_LIB_CRYPTO, (r), NULL)

#define CTerr (f, r) ERR_raise_data(ERR_LIB_CT, (r), NULL)

#define DHerr (f, r)  ERR_raise_data(ERR_LIB_DH, (r), NULL)

#define DSAerr (f, r) ERR_raise_data(ERR_LIB_DSA, (r), NULL)

#define DSOerr (f, r) ERR_raise_data(ERR_LIB_DSO, (r), NULL)

#define ECDHerr (f, r) ERR_raise_data(ERR_LIB_ECDH, (r), NULL)

#define ECDSAerr (f, r) ERR_raise_data(ERR_LIB_ECDSA, (r), NULL)

#define ECerr (f, r)  ERR_raise_data(ERR_LIB_EC, (r), NULL)

#define ENGINEerr (f, r) ERR_raise_data(ERR_LIB_ENGINE, (r), NULL)

#define ESSerr (f, r) ERR_raise_data(ERR_LIB_ESS, (r), NULL)

#define EVPerr (f, r) ERR_raise_data(ERR_LIB_EVP, (r), NULL)

#define FIPSerr (f, r) ERR_raise_data(ERR_LIB_FIPS, (r), NULL)

#define HMACerr (f, r) ERR_raise_data(ERR_LIB_HMAC, (r), NULL)

#define HTTPerr (f, r) ERR_raise_data(ERR_LIB_HTTP, (r), NULL)

#define KDFerr (f, r) ERR_raise_data(ERR_LIB_KDF, (r), NULL)

#define OBJerr (f, r) ERR_raise_data(ERR_LIB_OBJ, (r), NULL)

#define OCSPerr (f, r) ERR_raise_data(ERR_LIB_OCSP, (r), NULL)

#define OSSL_STOREerr (f, r) ERR_raise_data(ERR_LIB_OSSL_STORE, (r), NULL)

#define PEMerr (f, r) ERR_raise_data(ERR_LIB_PEM, (r), NULL)

#define PKCS12err (f, r) ERR_raise_data(ERR_LIB_PKCS12, (r), NULL)

#define PKCS7err (f, r) ERR_raise_data(ERR_LIB_PKCS7, (r), NULL)

#define PROPerr (f, r) ERR_raise_data(ERR_LIB_PROP, (r), NULL)

#define PROVerr (f, r) ERR_raise_data(ERR_LIB_PROV, (r), NULL)

#define RANDerr (f, r) ERR_raise_data(ERR_LIB_RAND, (r), NULL)

#define RSAerr (f, r) ERR_raise_data(ERR_LIB_RSA, (r), NULL)

#define SM2err (f, r) ERR_raise_data(ERR_LIB_SM2, (r), NULL)

#define SSLerr (f, r) ERR_raise_data(ERR_LIB_SSL, (r), NULL)

#define SYSerr (f, r) ERR_raise_data(ERR_LIB_SYS, (r), NULL)

#define TSerr (f, r) ERR_raise_data(ERR_LIB_TS, (r), NULL)

#define UIerr (f, r) ERR_raise_data(ERR_LIB_UI, (r), NULL)

#define X509V3err (f, r) ERR_raise_data(ERR_LIB_X509V3, (r), NULL)

#define X509err (f, r) ERR_raise_data(ERR_LIB_X509, (r), NULL)

#define ERR_SYSTEM_FLAG ((unsigned int)INT_MAX + 1)

#define ERR_SYSTEM_MASK ((unsigned int)INT_MAX)

#define ERR_LIB_OFFSET 23L

#define ERR_LIB_MASK 0xFF

#define ERR_RFLAGS_OFFSET 18L

#define ERR_RFLAGS_MASK 0x1F

#define ERR_REASON_MASK 0X7FFFFF

#define ERR_RFLAG_FATAL (0x1 << ERR_RFLAGS_OFFSET)

#define ERR_RFLAG_COMMON (0x2 << ERR_RFLAGS_OFFSET)

#define ERR_SYSTEM_ERROR (errcode)      (((errcode) & ERR_SYSTEM_FLAG) != 0)

#define ERR_PACK (lib,func,reason)\
	( (((unsigned long)(lib)    & ERR_LIB_MASK   ) << ERR_LIB_OFFSET) | \\
	(((unsigned long)(reason) & ERR_REASON_MASK)) )

#define SYS_F_FOPEN 0

#define SYS_F_CONNECT 0

#define SYS_F_GETSERVBYNAME 0

#define SYS_F_SOCKET 0

#define SYS_F_IOCTLSOCKET 0

#define SYS_F_BIND 0

#define SYS_F_LISTEN 0

#define SYS_F_ACCEPT 0

#define SYS_F_WSASTARTUP 0

#define SYS_F_OPENDIR 0

#define SYS_F_FREAD 0

#define SYS_F_GETADDRINFO 0

#define SYS_F_GETNAMEINFO 0

#define SYS_F_SETSOCKOPT 0

#define SYS_F_GETSOCKOPT 0

#define SYS_F_GETSOCKNAME 0

#define SYS_F_GETHOSTBYNAME 0

#define SYS_F_FFLUSH 0

#define SYS_F_OPEN 0

#define SYS_F_CLOSE 0

#define SYS_F_IOCTL 0

#define SYS_F_STAT 0

#define SYS_F_FCNTL 0

#define SYS_F_FSTAT 0

#define SYS_F_SENDFILE 0

#define ERR_R_SYS_LIB (ERR_LIB_SYS  | ERR_RFLAG_COMMON)

#define ERR_R_BN_LIB (ERR_LIB_BN  | ERR_RFLAG_COMMON)

#define ERR_R_RSA_LIB (ERR_LIB_RSA  | ERR_RFLAG_COMMON)

#define ERR_R_DH_LIB (ERR_LIB_DH  | ERR_RFLAG_COMMON)

#define ERR_R_EVP_LIB (ERR_LIB_EVP  | ERR_RFLAG_COMMON)

#define ERR_R_BUF_LIB (ERR_LIB_BUF  | ERR_RFLAG_COMMON)

#define ERR_R_OBJ_LIB (ERR_LIB_OBJ  | ERR_RFLAG_COMMON)

#define ERR_R_PEM_LIB (ERR_LIB_PEM  | ERR_RFLAG_COMMON)

#define ERR_R_DSA_LIB (ERR_LIB_DSA  | ERR_RFLAG_COMMON)

#define ERR_R_X509_LIB (ERR_LIB_X509  | ERR_RFLAG_COMMON)

#define ERR_R_ASN1_LIB (ERR_LIB_ASN1  | ERR_RFLAG_COMMON)

#define ERR_R_CONF_LIB (ERR_LIB_CONF  | ERR_RFLAG_COMMON)

#define ERR_R_CRYPTO_LIB (ERR_LIB_CRYPTO  | ERR_RFLAG_COMMON)

#define ERR_R_EC_LIB (ERR_LIB_EC  | ERR_RFLAG_COMMON)

#define ERR_R_SSL_LIB (ERR_LIB_SSL  | ERR_RFLAG_COMMON)

#define ERR_R_BIO_LIB (ERR_LIB_BIO  | ERR_RFLAG_COMMON)

#define ERR_R_PKCS7_LIB (ERR_LIB_PKCS7  | ERR_RFLAG_COMMON)

#define ERR_R_X509V3_LIB (ERR_LIB_X509V3  | ERR_RFLAG_COMMON)

#define ERR_R_PKCS12_LIB (ERR_LIB_PKCS12  | ERR_RFLAG_COMMON)

#define ERR_R_RAND_LIB (ERR_LIB_RAND  | ERR_RFLAG_COMMON)

#define ERR_R_DSO_LIB (ERR_LIB_DSO  | ERR_RFLAG_COMMON)

#define ERR_R_ENGINE_LIB (ERR_LIB_ENGINE  | ERR_RFLAG_COMMON)

#define ERR_R_UI_LIB (ERR_LIB_UI  | ERR_RFLAG_COMMON)

#define ERR_R_ECDSA_LIB (ERR_LIB_ECDSA  | ERR_RFLAG_COMMON)

#define ERR_R_OSSL_STORE_LIB (ERR_LIB_OSSL_STORE  | ERR_RFLAG_COMMON)

#define ERR_R_CMS_LIB (ERR_LIB_CMS  | ERR_RFLAG_COMMON)

#define ERR_R_TS_LIB (ERR_LIB_TS  | ERR_RFLAG_COMMON)

#define ERR_R_CT_LIB (ERR_LIB_CT  | ERR_RFLAG_COMMON)

#define ERR_R_PROV_LIB (ERR_LIB_PROV  | ERR_RFLAG_COMMON)

#define ERR_R_ESS_LIB (ERR_LIB_ESS  | ERR_RFLAG_COMMON)

#define ERR_R_CMP_LIB (ERR_LIB_CMP  | ERR_RFLAG_COMMON)

#define ERR_R_OSSL_ENCODER_LIB (ERR_LIB_OSSL_ENCODER  | ERR_RFLAG_COMMON)

#define ERR_R_OSSL_DECODER_LIB (ERR_LIB_OSSL_DECODER  | ERR_RFLAG_COMMON)

#define ERR_R_FATAL (ERR_RFLAG_FATAL|ERR_RFLAG_COMMON)

#define ERR_R_MALLOC_FAILURE (256|ERR_R_FATAL)

#define ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED (257|ERR_R_FATAL)

#define ERR_R_PASSED_NULL_PARAMETER (258|ERR_R_FATAL)

#define ERR_R_INTERNAL_ERROR (259|ERR_R_FATAL)

#define ERR_R_DISABLED (260|ERR_R_FATAL)

#define ERR_R_INIT_FAIL (261|ERR_R_FATAL)

#define ERR_R_PASSED_INVALID_ARGUMENT (262|ERR_RFLAG_COMMON)

#define ERR_R_OPERATION_FAIL (263|ERR_R_FATAL)

#define ERR_R_INVALID_PROVIDER_FUNCTIONS (264|ERR_R_FATAL)

#define ERR_R_INTERRUPTED_OR_CANCELLED (265|ERR_RFLAG_COMMON)

#define ERR_R_NESTED_ASN1_ERROR (266|ERR_RFLAG_COMMON)

#define ERR_R_MISSING_ASN1_EOS (267|ERR_RFLAG_COMMON)

#define ERR_R_UNSUPPORTED (268|ERR_RFLAG_COMMON)

#define ERR_R_FETCH_FAILED (269|ERR_RFLAG_COMMON)

#define ERR_R_INVALID_PROPERTY_DEFINITION (270|ERR_RFLAG_COMMON)

#define ERR_R_UNABLE_TO_GET_READ_LOCK (271|ERR_R_FATAL)

#define ERR_R_UNABLE_TO_GET_WRITE_LOCK (272|ERR_R_FATAL)

#define ERR_MAX_DATA_SIZE 1024

#define ERR_raise (lib, reason) ERR_raise_data((lib),(reason),NULL)

#define ERR_raise_data \
	(ERR_new(),                                                 \\
	ERR_set_debug(OPENSSL_FILE,OPENSSL_LINE,OPENSSL_FUNC),     \\
	ERR_set_error)

#define ERR_put_error (lib, func, reason, file, line)\
	(ERR_new(),                                                 \\
	ERR_set_debug((file), (line), OPENSSL_FUNC),               \\
	ERR_set_error((lib), (reason), NULL))

#define ERR_load_crypto_strings ()\
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL)

#define ERR_free_strings () while(0) continue

#define OPENSSL_ESS_H 

#define OPENSSL_ESSERR_H 

#define ESS_R_EMPTY_ESS_CERT_ID_LIST 107

#define ESS_R_ESS_CERT_DIGEST_ERROR 103

#define ESS_R_ESS_CERT_ID_NOT_FOUND 104

#define ESS_R_ESS_CERT_ID_WRONG_ORDER 105

#define ESS_R_ESS_DIGEST_ALG_UNKNOWN 106

#define ESS_R_ESS_SIGNING_CERTIFICATE_ERROR 102

#define ESS_R_ESS_SIGNING_CERT_ADD_ERROR 100

#define ESS_R_ESS_SIGNING_CERT_V2_ADD_ERROR 101

#define ESS_R_MISSING_SIGNING_CERTIFICATE_ATTRIBUTE 108

#define OPENSSL_EVP_H 

#define HEADER_ENVELOPE_H 

#define EVP_MAX_MD_SIZE 64

#define EVP_MAX_KEY_LENGTH 64

#define EVP_MAX_IV_LENGTH 16

#define EVP_MAX_BLOCK_LENGTH 32

#define EVP_MAX_AEAD_TAG_LENGTH 16

#define PKCS5_SALT_LEN 8

#define PKCS5_DEFAULT_ITER 2048

#define EVP_PK_RSA 0x0001

#define EVP_PK_DSA 0x0002

#define EVP_PK_DH 0x0004

#define EVP_PK_EC 0x0008

#define EVP_PKT_SIGN 0x0010

#define EVP_PKT_ENC 0x0020

#define EVP_PKT_EXCH 0x0040

#define EVP_PKS_RSA 0x0100

#define EVP_PKS_DSA 0x0200

#define EVP_PKS_EC 0x0400

#define EVP_PKEY_NONE NID_undef

#define EVP_PKEY_RSA NID_rsaEncryption

#define EVP_PKEY_RSA2 NID_rsa

#define EVP_PKEY_RSA_PSS NID_rsassaPss

#define EVP_PKEY_DSA NID_dsa

#define EVP_PKEY_DSA1 NID_dsa_2

#define EVP_PKEY_DSA2 NID_dsaWithSHA

#define EVP_PKEY_DSA3 NID_dsaWithSHA1

#define EVP_PKEY_DSA4 NID_dsaWithSHA1_2

#define EVP_PKEY_DH NID_dhKeyAgreement

#define EVP_PKEY_DHX NID_dhpublicnumber

#define EVP_PKEY_EC NID_X9_62_id_ecPublicKey

#define EVP_PKEY_SM2 NID_sm2

#define EVP_PKEY_HMAC NID_hmac

#define EVP_PKEY_CMAC NID_cmac

#define EVP_PKEY_SCRYPT NID_id_scrypt

#define EVP_PKEY_TLS1_PRF NID_tls1_prf

#define EVP_PKEY_HKDF NID_hkdf

#define EVP_PKEY_POLY1305 NID_poly1305

#define EVP_PKEY_SIPHASH NID_siphash

#define EVP_PKEY_X25519 NID_X25519

#define EVP_PKEY_ED25519 NID_ED25519

#define EVP_PKEY_X448 NID_X448

#define EVP_PKEY_ED448 NID_ED448

#define EVP_PKEY_KEYMGMT -1

#define EVP_PKEY_KEY_PARAMETERS \
	( OSSL_KEYMGMT_SELECT_ALL_PARAMETERS )

#define EVP_PKEY_PRIVATE_KEY \
	( EVP_PKEY_KEY_PARAMETERS | OSSL_KEYMGMT_SELECT_PRIVATE_KEY )

#define EVP_PKEY_PUBLIC_KEY \
	( EVP_PKEY_KEY_PARAMETERS | OSSL_KEYMGMT_SELECT_PUBLIC_KEY )

#define EVP_PKEY_KEYPAIR \
	( EVP_PKEY_PUBLIC_KEY | OSSL_KEYMGMT_SELECT_PRIVATE_KEY )

#define EVP_PKEY_MO_SIGN 0x0001

#define EVP_PKEY_MO_VERIFY 0x0002

#define EVP_PKEY_MO_ENCRYPT 0x0004

#define EVP_PKEY_MO_DECRYPT 0x0008

#define EVP_MD_FLAG_ONESHOT 0x0001

#define EVP_MD_FLAG_XOF 0x0002

#define EVP_MD_FLAG_DIGALGID_MASK 0x0018

#define EVP_MD_FLAG_DIGALGID_NULL 0x0000

#define EVP_MD_FLAG_DIGALGID_ABSENT 0x0008

#define EVP_MD_FLAG_DIGALGID_CUSTOM 0x0018

#define EVP_MD_FLAG_FIPS 0x0400

#define EVP_MD_CTRL_DIGALGID 0x1

#define EVP_MD_CTRL_MICALG 0x2

#define EVP_MD_CTRL_XOF_LEN 0x3

#define EVP_MD_CTRL_TLSTREE 0x4

#define EVP_MD_CTRL_ALG_CTRL 0x1000

#define EVP_MD_CTX_FLAG_ONESHOT 0x0001

#define EVP_MD_CTX_FLAG_CLEANED 0x0002

#define EVP_MD_CTX_FLAG_REUSE 0x0004

#define EVP_MD_CTX_FLAG_NON_FIPS_ALLOW 0x0008

#define EVP_MD_CTX_FLAG_PAD_MASK 0xF0

#define EVP_MD_CTX_FLAG_PAD_PKCS1 0x00

#define EVP_MD_CTX_FLAG_PAD_X931 0x10

#define EVP_MD_CTX_FLAG_PAD_PSS 0x20

#define EVP_MD_CTX_FLAG_NO_INIT 0x0100

#define EVP_MD_CTX_FLAG_FINALISE 0x0200

#define EVP_CIPH_STREAM_CIPHER 0x0

#define EVP_CIPH_ECB_MODE 0x1

#define EVP_CIPH_CBC_MODE 0x2

#define EVP_CIPH_CFB_MODE 0x3

#define EVP_CIPH_OFB_MODE 0x4

#define EVP_CIPH_CTR_MODE 0x5

#define EVP_CIPH_GCM_MODE 0x6

#define EVP_CIPH_CCM_MODE 0x7

#define EVP_CIPH_XTS_MODE 0x10001

#define EVP_CIPH_WRAP_MODE 0x10002

#define EVP_CIPH_OCB_MODE 0x10003

#define EVP_CIPH_SIV_MODE 0x10004

#define EVP_CIPH_GCM_SIV_MODE 0x10005

#define EVP_CIPH_MODE 0xF0007

#define EVP_CIPH_VARIABLE_LENGTH 0x8

#define EVP_CIPH_CUSTOM_IV 0x10

#define EVP_CIPH_ALWAYS_CALL_INIT 0x20

#define EVP_CIPH_CTRL_INIT 0x40

#define EVP_CIPH_CUSTOM_KEY_LENGTH 0x80

#define EVP_CIPH_NO_PADDING 0x100

#define EVP_CIPH_RAND_KEY 0x200

#define EVP_CIPH_CUSTOM_COPY 0x400

#define EVP_CIPH_CUSTOM_IV_LENGTH 0x800

#define EVP_CIPH_FLAG_DEFAULT_ASN1 0

#define EVP_CIPH_FLAG_LENGTH_BITS 0x2000

#define EVP_CIPH_FLAG_FIPS 0

#define EVP_CIPH_FLAG_NON_FIPS_ALLOW 0

#define EVP_CIPH_FLAG_CTS 0x4000

#define EVP_CIPH_FLAG_CUSTOM_CIPHER 0x100000

#define EVP_CIPH_FLAG_AEAD_CIPHER 0x200000

#define EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK 0x400000

#define EVP_CIPH_FLAG_PIPELINE 0X800000

#define EVP_CIPH_FLAG_CUSTOM_ASN1 0x1000000

#define EVP_CIPH_FLAG_CIPHER_WITH_MAC 0x2000000

#define EVP_CIPH_FLAG_GET_WRAP_CIPHER 0x4000000

#define EVP_CIPH_FLAG_INVERSE_CIPHER 0x8000000

#define EVP_CIPHER_CTX_FLAG_WRAP_ALLOW 0x1

#define EVP_CTRL_INIT 0x0

#define EVP_CTRL_SET_KEY_LENGTH 0x1

#define EVP_CTRL_GET_RC2_KEY_BITS 0x2

#define EVP_CTRL_SET_RC2_KEY_BITS 0x3

#define EVP_CTRL_GET_RC5_ROUNDS 0x4

#define EVP_CTRL_SET_RC5_ROUNDS 0x5

#define EVP_CTRL_RAND_KEY 0x6

#define EVP_CTRL_PBE_PRF_NID 0x7

#define EVP_CTRL_COPY 0x8

#define EVP_CTRL_AEAD_SET_IVLEN 0x9

#define EVP_CTRL_AEAD_GET_TAG 0x10

#define EVP_CTRL_AEAD_SET_TAG 0x11

#define EVP_CTRL_AEAD_SET_IV_FIXED 0x12

#define EVP_CTRL_GCM_SET_IVLEN EVP_CTRL_AEAD_SET_IVLEN

#define EVP_CTRL_GCM_GET_TAG EVP_CTRL_AEAD_GET_TAG

#define EVP_CTRL_GCM_SET_TAG EVP_CTRL_AEAD_SET_TAG

#define EVP_CTRL_GCM_SET_IV_FIXED EVP_CTRL_AEAD_SET_IV_FIXED

#define EVP_CTRL_GCM_IV_GEN 0x13

#define EVP_CTRL_CCM_SET_IVLEN EVP_CTRL_AEAD_SET_IVLEN

#define EVP_CTRL_CCM_GET_TAG EVP_CTRL_AEAD_GET_TAG

#define EVP_CTRL_CCM_SET_TAG EVP_CTRL_AEAD_SET_TAG

#define EVP_CTRL_CCM_SET_IV_FIXED EVP_CTRL_AEAD_SET_IV_FIXED

#define EVP_CTRL_CCM_SET_L 0x14

#define EVP_CTRL_CCM_SET_MSGLEN 0x15

#define EVP_CTRL_AEAD_TLS1_AAD 0x16

#define EVP_CTRL_AEAD_SET_MAC_KEY 0x17

#define EVP_CTRL_GCM_SET_IV_INV 0x18

#define EVP_CTRL_TLS1_1_MULTIBLOCK_AAD 0x19

#define EVP_CTRL_TLS1_1_MULTIBLOCK_ENCRYPT 0x1a

#define EVP_CTRL_TLS1_1_MULTIBLOCK_DECRYPT 0x1b

#define EVP_CTRL_TLS1_1_MULTIBLOCK_MAX_BUFSIZE 0x1c

#define EVP_CTRL_SSL3_MASTER_SECRET 0x1d

#define EVP_CTRL_SET_SBOX 0x1e

#define EVP_CTRL_SBOX_USED 0x1f

#define EVP_CTRL_KEY_MESH 0x20

#define EVP_CTRL_BLOCK_PADDING_MODE 0x21

#define EVP_CTRL_SET_PIPELINE_OUTPUT_BUFS 0x22

#define EVP_CTRL_SET_PIPELINE_INPUT_BUFS 0x23

#define EVP_CTRL_SET_PIPELINE_INPUT_LENS 0x24

#define EVP_CTRL_GET_IVLEN 0x25

#define EVP_CTRL_SET_SPEED 0x27

#define EVP_CTRL_PROCESS_UNPROTECTED 0x28

#define EVP_CTRL_GET_WRAP_CIPHER 0x29

#define EVP_CTRL_TLSTREE 0x2A

#define EVP_PADDING_PKCS7 1

#define EVP_PADDING_ISO7816_4 2

#define EVP_PADDING_ANSI923 3

#define EVP_PADDING_ISO10126 4

#define EVP_PADDING_ZERO 5

#define EVP_AEAD_TLS1_AAD_LEN 13

#define EVP_GCM_TLS_FIXED_IV_LEN 4

#define EVP_GCM_TLS_EXPLICIT_IV_LEN 8

#define EVP_GCM_TLS_TAG_LEN 16

#define EVP_CCM_TLS_FIXED_IV_LEN 4

#define EVP_CCM_TLS_EXPLICIT_IV_LEN 8

#define EVP_CCM_TLS_IV_LEN 12

#define EVP_CCM_TLS_TAG_LEN 16

#define EVP_CCM8_TLS_TAG_LEN 8

#define EVP_CHACHAPOLY_TLS_TAG_LEN 16

#define EVP_PKEY_assign_RSA (pkey,rsa) EVP_PKEY_assign((pkey),EVP_PKEY_RSA,\
	(rsa))

#define EVP_PKEY_assign_DSA (pkey,dsa) EVP_PKEY_assign((pkey),EVP_PKEY_DSA,\
	(dsa))

#define EVP_PKEY_assign_DH (pkey,dh) EVP_PKEY_assign((pkey),EVP_PKEY_DH,(dh))

#define EVP_PKEY_assign_EC_KEY (pkey,eckey)\
	EVP_PKEY_assign((pkey), EVP_PKEY_EC, (eckey))

#define EVP_PKEY_assign_SIPHASH (pkey,shkey) EVP_PKEY_assign((pkey),\
	EVP_PKEY_SIPHASH,(shkey))

#define EVP_PKEY_assign_POLY1305 (pkey,polykey) EVP_PKEY_assign((pkey),\
	EVP_PKEY_POLY1305,(polykey))

#define EVP_get_digestbynid (a) EVP_get_digestbyname(OBJ_nid2sn(a))

#define EVP_get_digestbyobj (a) EVP_get_digestbynid(OBJ_obj2nid(a))

#define EVP_get_cipherbynid (a) EVP_get_cipherbyname(OBJ_nid2sn(a))

#define EVP_get_cipherbyobj (a) EVP_get_cipherbynid(OBJ_obj2nid(a))

#define EVP_MD_type EVP_MD_get_type

#define EVP_MD_nid EVP_MD_get_type

#define EVP_MD_name EVP_MD_get0_name

#define EVP_MD_pkey_type EVP_MD_get_pkey_type

#define EVP_MD_size EVP_MD_get_size

#define EVP_MD_block_size EVP_MD_get_block_size

#define EVP_MD_flags EVP_MD_get_flags

#define EVP_MD_CTX_get0_name (e)       EVP_MD_get0_name(EVP_MD_CTX_get0_md(e))

#define EVP_MD_CTX_get_size (e)        EVP_MD_get_size(EVP_MD_CTX_get0_md(e))

#define EVP_MD_CTX_size EVP_MD_CTX_get_size

#define EVP_MD_CTX_get_block_size (e)  EVP_MD_get_block_size(EVP_MD_CTX_get0_md(e))

#define EVP_MD_CTX_block_size EVP_MD_CTX_get_block_size

#define EVP_MD_CTX_get_type (e)            EVP_MD_get_type(EVP_MD_CTX_get0_md(e))

#define EVP_MD_CTX_type EVP_MD_CTX_get_type

#define EVP_MD_CTX_pkey_ctx EVP_MD_CTX_get_pkey_ctx

#define EVP_MD_CTX_md_data EVP_MD_CTX_get0_md_data

#define EVP_CIPHER_nid EVP_CIPHER_get_nid

#define EVP_CIPHER_name EVP_CIPHER_get0_name

#define EVP_CIPHER_block_size EVP_CIPHER_get_block_size

#define EVP_CIPHER_key_length EVP_CIPHER_get_key_length

#define EVP_CIPHER_iv_length EVP_CIPHER_get_iv_length

#define EVP_CIPHER_flags EVP_CIPHER_get_flags

#define EVP_CIPHER_mode EVP_CIPHER_get_mode

#define EVP_CIPHER_type EVP_CIPHER_get_type

#define EVP_CIPHER_CTX_encrypting EVP_CIPHER_CTX_is_encrypting

#define EVP_CIPHER_CTX_nid EVP_CIPHER_CTX_get_nid

#define EVP_CIPHER_CTX_block_size EVP_CIPHER_CTX_get_block_size

#define EVP_CIPHER_CTX_key_length EVP_CIPHER_CTX_get_key_length

#define EVP_CIPHER_CTX_iv_length EVP_CIPHER_CTX_get_iv_length

#define EVP_CIPHER_CTX_tag_length EVP_CIPHER_CTX_get_tag_length

#define EVP_CIPHER_CTX_num EVP_CIPHER_CTX_get_num

#define EVP_CIPHER_CTX_get0_name (c) EVP_CIPHER_get0_name(EVP_CIPHER_CTX_get0_cipher(c))

#define EVP_CIPHER_CTX_get_type (c)  EVP_CIPHER_get_type(EVP_CIPHER_CTX_get0_cipher(c))

#define EVP_CIPHER_CTX_type EVP_CIPHER_CTX_get_type

#define EVP_CIPHER_CTX_flags (c)    EVP_CIPHER_get_flags(EVP_CIPHER_CTX_get0_cipher(c))

#define EVP_CIPHER_CTX_get_mode (c)  EVP_CIPHER_get_mode(EVP_CIPHER_CTX_get0_cipher(c))

#define EVP_CIPHER_CTX_mode EVP_CIPHER_CTX_get_mode

#define EVP_ENCODE_LENGTH (l)    ((((l)+2)/3*4)+((l)/48+1)*2+80)

#define EVP_DECODE_LENGTH (l)    (((l)+3)/4*3+80)

#define EVP_SignInit_ex (a,b,c)          EVP_DigestInit_ex(a,b,c)

#define EVP_SignInit (a,b)               EVP_DigestInit(a,b)

#define EVP_SignUpdate (a,b,c)           EVP_DigestUpdate(a,b,c)

#define EVP_VerifyInit_ex (a,b,c)        EVP_DigestInit_ex(a,b,c)

#define EVP_VerifyInit (a,b)             EVP_DigestInit(a,b)

#define EVP_VerifyUpdate (a,b,c)         EVP_DigestUpdate(a,b,c)

#define EVP_OpenUpdate (a,b,c,d,e)       EVP_DecryptUpdate(a,b,c,d,e)

#define EVP_SealUpdate (a,b,c,d,e)       EVP_EncryptUpdate(a,b,c,d,e)

// #define BIO_set_md (b,md)          BIO_ctrl(b,BIO_C_SET_MD,0,(void *)(md))

#define BIO_get_md (b,mdp)          BIO_ctrl(b,BIO_C_GET_MD,0,(mdp))

#define BIO_get_md_ctx (b,mdcp)     BIO_ctrl(b,BIO_C_GET_MD_CTX,0,(mdcp))

#define BIO_set_md_ctx (b,mdcp)     BIO_ctrl(b,BIO_C_SET_MD_CTX,0,(mdcp))

#define BIO_get_cipher_status (b)   BIO_ctrl(b,BIO_C_GET_CIPHER_STATUS,0,NULL)

#define BIO_get_cipher_ctx (b,c_pp) BIO_ctrl(b,BIO_C_GET_CIPHER_CTX,0,(c_pp))

#define EVP_add_cipher_alias (n,alias)\
	OBJ_NAME_add((alias),OBJ_NAME_TYPE_CIPHER_METH|OBJ_NAME_ALIAS,(n))

#define EVP_add_digest_alias (n,alias)\
	OBJ_NAME_add((alias),OBJ_NAME_TYPE_MD_METH|OBJ_NAME_ALIAS,(n))

#define EVP_delete_cipher_alias (alias)\
	OBJ_NAME_remove(alias,OBJ_NAME_TYPE_CIPHER_METH|OBJ_NAME_ALIAS);

#define EVP_delete_digest_alias (alias)\
	OBJ_NAME_remove(alias,OBJ_NAME_TYPE_MD_METH|OBJ_NAME_ALIAS);

#define EVP_MD_CTX_create ()     EVP_MD_CTX_new()

#define EVP_MD_CTX_init (ctx)    EVP_MD_CTX_reset((ctx))

#define EVP_MD_CTX_destroy (ctx) EVP_MD_CTX_free((ctx))

#define EVP_CIPHER_CTX_init (c)      EVP_CIPHER_CTX_reset(c)

#define EVP_CIPHER_CTX_cleanup (c)   EVP_CIPHER_CTX_reset(c)

#define EVP_des_cfb EVP_des_cfb64

#define EVP_des_ede_cfb EVP_des_ede_cfb64

#define EVP_des_ede3_cfb EVP_des_ede3_cfb64

#define EVP_idea_cfb EVP_idea_cfb64

#define EVP_rc2_cfb EVP_rc2_cfb64

#define EVP_bf_cfb EVP_bf_cfb64

#define EVP_cast5_cfb EVP_cast5_cfb64

#define EVP_rc5_32_12_16_cfb EVP_rc5_32_12_16_cfb64

#define EVP_aes_128_cfb EVP_aes_128_cfb128

#define EVP_aes_192_cfb EVP_aes_192_cfb128

#define EVP_aes_256_cfb EVP_aes_256_cfb128

#define EVP_aria_128_cfb EVP_aria_128_cfb128

#define EVP_aria_192_cfb EVP_aria_192_cfb128

#define EVP_aria_256_cfb EVP_aria_256_cfb128

#define EVP_camellia_128_cfb EVP_camellia_128_cfb128

#define EVP_camellia_192_cfb EVP_camellia_192_cfb128

#define EVP_camellia_256_cfb EVP_camellia_256_cfb128

#define EVP_seed_cfb EVP_seed_cfb128

#define EVP_sm4_cfb EVP_sm4_cfb128

#define OPENSSL_add_all_algorithms_conf ()\
	OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS \\
	| OPENSSL_INIT_ADD_ALL_DIGESTS \\
	| OPENSSL_INIT_LOAD_CONFIG, NULL)

#define OPENSSL_add_all_algorithms_noconf ()\
	OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS \\
	| OPENSSL_INIT_ADD_ALL_DIGESTS, NULL)

#define OpenSSL_add_all_algorithms () OPENSSL_add_all_algorithms_conf()

#define OpenSSL_add_all_ciphers ()\
	OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS, NULL)

#define OpenSSL_add_all_digests ()\
	OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_DIGESTS, NULL)

#define EVP_cleanup () while(0) continue

#define EVP_RAND_STATE_UNINITIALISED 0

#define EVP_RAND_STATE_READY 1

#define EVP_RAND_STATE_ERROR 2

#define EVP_PKEY_id EVP_PKEY_get_id

#define EVP_PKEY_base_id EVP_PKEY_get_base_id

#define EVP_PKEY_bits EVP_PKEY_get_bits

#define EVP_PKEY_security_bits EVP_PKEY_get_security_bits

#define EVP_PKEY_size EVP_PKEY_get_size

#define EVP_PKEY_set1_tls_encodedpoint (pkey, pt, ptlen)\
	EVP_PKEY_set1_encoded_public_key((pkey), (pt), (ptlen))

#define EVP_PKEY_get1_tls_encodedpoint (pkey, ppt)\
	EVP_PKEY_get1_encoded_public_key((pkey), (ppt))

#define EVP_PBE_TYPE_OUTER 0x0

#define EVP_PBE_TYPE_PRF 0x1

#define EVP_PBE_TYPE_KDF 0x2

#define ASN1_PKEY_ALIAS 0x1

#define ASN1_PKEY_DYNAMIC 0x2

#define ASN1_PKEY_SIGPARAM_NULL 0x4

#define ASN1_PKEY_CTRL_PKCS7_SIGN 0x1

#define ASN1_PKEY_CTRL_PKCS7_ENCRYPT 0x2

#define ASN1_PKEY_CTRL_DEFAULT_MD_NID 0x3

#define ASN1_PKEY_CTRL_CMS_SIGN 0x5

#define ASN1_PKEY_CTRL_CMS_ENVELOPE 0x7

#define ASN1_PKEY_CTRL_CMS_RI_TYPE 0x8

#define ASN1_PKEY_CTRL_SET1_TLS_ENCPT 0x9

#define ASN1_PKEY_CTRL_GET1_TLS_ENCPT 0xa

#define ASN1_PKEY_CTRL_CMS_IS_RI_TYPE_SUPPORTED 0xb

#define EVP_PKEY_OP_UNDEFINED 0

#define EVP_PKEY_OP_PARAMGEN (1<<1)

#define EVP_PKEY_OP_KEYGEN (1<<2)

#define EVP_PKEY_OP_FROMDATA (1<<3)

#define EVP_PKEY_OP_SIGN (1<<4)

#define EVP_PKEY_OP_VERIFY (1<<5)

#define EVP_PKEY_OP_VERIFYRECOVER (1<<6)

#define EVP_PKEY_OP_SIGNCTX (1<<7)

#define EVP_PKEY_OP_VERIFYCTX (1<<8)

#define EVP_PKEY_OP_ENCRYPT (1<<9)

#define EVP_PKEY_OP_DECRYPT (1<<10)

#define EVP_PKEY_OP_DERIVE (1<<11)

#define EVP_PKEY_OP_ENCAPSULATE (1<<12)

#define EVP_PKEY_OP_DECAPSULATE (1<<13)

#define EVP_PKEY_OP_TYPE_SIG \
	(EVP_PKEY_OP_SIGN | EVP_PKEY_OP_VERIFY | EVP_PKEY_OP_VERIFYRECOVER \\
	| EVP_PKEY_OP_SIGNCTX | EVP_PKEY_OP_VERIFYCTX)

#define EVP_PKEY_OP_TYPE_CRYPT \
	(EVP_PKEY_OP_ENCRYPT | EVP_PKEY_OP_DECRYPT)

#define EVP_PKEY_OP_TYPE_NOGEN \
	(EVP_PKEY_OP_TYPE_SIG | EVP_PKEY_OP_TYPE_CRYPT | EVP_PKEY_OP_DERIVE)

#define EVP_PKEY_OP_TYPE_GEN \
	(EVP_PKEY_OP_PARAMGEN | EVP_PKEY_OP_KEYGEN)

#define EVP_PKEY_CTRL_MD 1

#define EVP_PKEY_CTRL_PEER_KEY 2

#define EVP_PKEY_CTRL_SET_MAC_KEY 6

#define EVP_PKEY_CTRL_DIGESTINIT 7

#define EVP_PKEY_CTRL_SET_IV 8

#define EVP_PKEY_CTRL_PKCS7_ENCRYPT 3

#define EVP_PKEY_CTRL_PKCS7_DECRYPT 4

#define EVP_PKEY_CTRL_PKCS7_SIGN 5

#define EVP_PKEY_CTRL_CMS_ENCRYPT 9

#define EVP_PKEY_CTRL_CMS_DECRYPT 10

#define EVP_PKEY_CTRL_CMS_SIGN 11

#define EVP_PKEY_CTRL_CIPHER 12

#define EVP_PKEY_CTRL_GET_MD 13

#define EVP_PKEY_CTRL_SET_DIGEST_SIZE 14

#define EVP_PKEY_CTRL_SET1_ID 15

#define EVP_PKEY_CTRL_GET1_ID 16

#define EVP_PKEY_CTRL_GET1_ID_LEN 17

#define EVP_PKEY_ALG_CTRL 0x1000

#define EVP_PKEY_FLAG_AUTOARGLEN 2

#define EVP_PKEY_FLAG_SIGCTX_CUSTOM 4

#define EVP_PKEY_get_ex_new_index (l, p, newf, dupf, freef)\
	CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_EVP_PKEY, l, p, newf, dupf, freef)

#define OPENSSL_EVPERR_H 

#define EVP_R_AES_KEY_SETUP_FAILED 143

#define EVP_R_ARIA_KEY_SETUP_FAILED 176

#define EVP_R_BAD_ALGORITHM_NAME 200

#define EVP_R_BAD_DECRYPT 100

#define EVP_R_BAD_KEY_LENGTH 195

#define EVP_R_BUFFER_TOO_SMALL 155

#define EVP_R_CACHE_CONSTANTS_FAILED 225

#define EVP_R_CAMELLIA_KEY_SETUP_FAILED 157

#define EVP_R_CANNOT_GET_PARAMETERS 197

#define EVP_R_CANNOT_SET_PARAMETERS 198

#define EVP_R_CIPHER_NOT_GCM_MODE 184

#define EVP_R_CIPHER_PARAMETER_ERROR 122

#define EVP_R_COMMAND_NOT_SUPPORTED 147

#define EVP_R_CONFLICTING_ALGORITHM_NAME 201

#define EVP_R_COPY_ERROR 173

#define EVP_R_CTRL_NOT_IMPLEMENTED 132

#define EVP_R_CTRL_OPERATION_NOT_IMPLEMENTED 133

#define EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH 138

#define EVP_R_DECODE_ERROR 114

#define EVP_R_DEFAULT_QUERY_PARSE_ERROR 210

#define EVP_R_DIFFERENT_KEY_TYPES 101

#define EVP_R_DIFFERENT_PARAMETERS 153

#define EVP_R_ERROR_LOADING_SECTION 165

#define EVP_R_EXPECTING_AN_HMAC_KEY 174

#define EVP_R_EXPECTING_AN_RSA_KEY 127

#define EVP_R_EXPECTING_A_DH_KEY 128

#define EVP_R_EXPECTING_A_DSA_KEY 129

#define EVP_R_EXPECTING_A_ECX_KEY 219

#define EVP_R_EXPECTING_A_EC_KEY 142

#define EVP_R_EXPECTING_A_POLY1305_KEY 164

#define EVP_R_EXPECTING_A_SIPHASH_KEY 175

#define EVP_R_FINAL_ERROR 188

#define EVP_R_GENERATE_ERROR 214

#define EVP_R_GET_RAW_KEY_FAILED 182

#define EVP_R_ILLEGAL_SCRYPT_PARAMETERS 171

#define EVP_R_INACCESSIBLE_DOMAIN_PARAMETERS 204

#define EVP_R_INACCESSIBLE_KEY 203

#define EVP_R_INITIALIZATION_ERROR 134

#define EVP_R_INPUT_NOT_INITIALIZED 111

#define EVP_R_INVALID_CUSTOM_LENGTH 185

#define EVP_R_INVALID_DIGEST 152

#define EVP_R_INVALID_IV_LENGTH 194

#define EVP_R_INVALID_KEY 163

#define EVP_R_INVALID_KEY_LENGTH 130

#define EVP_R_INVALID_LENGTH 221

#define EVP_R_INVALID_NULL_ALGORITHM 218

#define EVP_R_INVALID_OPERATION 148

#define EVP_R_INVALID_PROVIDER_FUNCTIONS 193

#define EVP_R_INVALID_SALT_LENGTH 186

#define EVP_R_INVALID_SECRET_LENGTH 223

#define EVP_R_INVALID_SEED_LENGTH 220

#define EVP_R_INVALID_VALUE 222

#define EVP_R_KEYMGMT_EXPORT_FAILURE 205

#define EVP_R_KEY_SETUP_FAILED 180

#define EVP_R_LOCKING_NOT_SUPPORTED 213

#define EVP_R_MEMORY_LIMIT_EXCEEDED 172

#define EVP_R_MESSAGE_DIGEST_IS_NULL 159

#define EVP_R_METHOD_NOT_SUPPORTED 144

#define EVP_R_MISSING_PARAMETERS 103

#define EVP_R_NOT_ABLE_TO_COPY_CTX 190

#define EVP_R_NOT_XOF_OR_INVALID_LENGTH 178

#define EVP_R_NO_CIPHER_SET 131

#define EVP_R_NO_DEFAULT_DIGEST 158

#define EVP_R_NO_DIGEST_SET 139

#define EVP_R_NO_IMPORT_FUNCTION 206

#define EVP_R_NO_KEYMGMT_AVAILABLE 199

#define EVP_R_NO_KEYMGMT_PRESENT 196

#define EVP_R_NO_KEY_SET 154

#define EVP_R_NO_OPERATION_SET 149

#define EVP_R_NULL_MAC_PKEY_CTX 208

#define EVP_R_ONLY_ONESHOT_SUPPORTED 177

#define EVP_R_OPERATION_NOT_INITIALIZED 151

#define EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE 150

#define EVP_R_OUTPUT_WOULD_OVERFLOW 202

#define EVP_R_PARAMETER_TOO_LARGE 187

#define EVP_R_PARTIALLY_OVERLAPPING 162

#define EVP_R_PBKDF2_ERROR 181

#define EVP_R_PKEY_APPLICATION_ASN1_METHOD_ALREADY_REGISTERED 179

#define EVP_R_PRIVATE_KEY_DECODE_ERROR 145

#define EVP_R_PRIVATE_KEY_ENCODE_ERROR 146

#define EVP_R_PUBLIC_KEY_NOT_RSA 106

#define EVP_R_SETTING_XOF_FAILED 227

#define EVP_R_SET_DEFAULT_PROPERTY_FAILURE 209

#define EVP_R_TOO_MANY_RECORDS 183

#define EVP_R_UNABLE_TO_ENABLE_LOCKING 212

#define EVP_R_UNABLE_TO_GET_MAXIMUM_REQUEST_SIZE 215

#define EVP_R_UNABLE_TO_GET_RANDOM_STRENGTH 216

#define EVP_R_UNABLE_TO_LOCK_CONTEXT 211

#define EVP_R_UNABLE_TO_SET_CALLBACKS 217

#define EVP_R_UNKNOWN_BITS 166

#define EVP_R_UNKNOWN_CIPHER 160

#define EVP_R_UNKNOWN_DIGEST 161

#define EVP_R_UNKNOWN_KEY_TYPE 207

#define EVP_R_UNKNOWN_MAX_SIZE 167

#define EVP_R_UNKNOWN_OPTION 169

#define EVP_R_UNKNOWN_PBE_ALGORITHM 121

#define EVP_R_UNKNOWN_SECURITY_BITS 168

#define EVP_R_UNSUPPORTED_ALGORITHM 156

#define EVP_R_UNSUPPORTED_CIPHER 107

#define EVP_R_UNSUPPORTED_KEYLENGTH 123

#define EVP_R_UNSUPPORTED_KEY_DERIVATION_FUNCTION 124

#define EVP_R_UNSUPPORTED_KEY_SIZE 108

#define EVP_R_UNSUPPORTED_KEY_TYPE 224

#define EVP_R_UNSUPPORTED_NUMBER_OF_ROUNDS 135

#define EVP_R_UNSUPPORTED_PRF 125

#define EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM 118

#define EVP_R_UNSUPPORTED_SALT_TYPE 126

#define EVP_R_UPDATE_ERROR 189

#define EVP_R_WRAP_MODE_NOT_ALLOWED 170

#define EVP_R_WRONG_FINAL_BLOCK_LENGTH 109

#define EVP_R_XTS_DATA_UNIT_IS_TOO_LARGE 191

#define EVP_R_XTS_DUPLICATED_KEYS 192

#define OPENSSL_E_OS2_H 

#define HEADER_E_OS2_H 

#define OPENSSL_SYS_UNIX 

#define OPENSSL_SYS_WIN32_UWIN 

#define OPENSSL_SYS_WIN32_CYGWIN 

#define OPENSSL_SYS_WIN32 

#define OPENSSL_SYS_WIN64 

#define OPENSSL_SYS_WINDOWS 

#define OPENSSL_SYS_MSDOS 

#define OPENSSL_OPT_WINDLL 

#define OPENSSL_SYS_VMS 

#define OPENSSL_SYS_VMS_DECC 

#define OPENSSL_SYS_VMS_DECCXX 

#define OPENSSL_SYS_VMS_NODECC 

#define OPENSSL_SYS_LINUX 

#define OPENSSL_SYS_AIX 

#define OPENSSL_SYS_VOS 

#define OPENSSL_SYS_VOS_HPPA 

#define OPENSSL_SYS_VOS_IA32 

#define OPENSSL_USE_BUILD_DATE 

#define OPENSSL_EXPORT extern __declspec(dllexport)

#define ossl_ssize_t __int64

#define OSSL_SSIZE_MAX _I64_MAX

#define __owur __attribute__((__warn_unused_result__))

#define OPENSSL_NO_INTTYPES_H 

#define OPENSSL_NO_STDINT_H 

#define ossl_inline inline

#define ossl_noreturn _Noreturn

#define ossl_unused __attribute__((unused))

#define OPENSSL_E_OSTIME_H 

#define OPENSSL_FIPSKEY_H 

#define FIPS_KEY_ELEMENTS \
	{- join(', ', map { "0x$_" } unpack("(A2)*", $config{FIPSKEY})) -}

#define FIPS_KEY_STRING "{- $config{FIPSKEY} -}"

#define OPENSSL_FIPS_NAMES_H 

#define OSSL_PROV_FIPS_PARAM_MODULE_MAC "module-mac"

#define OSSL_PROV_FIPS_PARAM_INSTALL_VERSION "install-version"

#define OSSL_PROV_FIPS_PARAM_INSTALL_MAC "install-mac"

#define OSSL_PROV_FIPS_PARAM_INSTALL_STATUS "install-status"

#define OSSL_PROV_FIPS_PARAM_CONDITIONAL_ERRORS "conditional-errors"

#define OSSL_PROV_FIPS_PARAM_SECURITY_CHECKS "security-checks"

#define OSSL_PROV_FIPS_PARAM_TLS1_PRF_EMS_CHECK "tls1-prf-ems-check"

#define OSSL_PROV_FIPS_PARAM_DRBG_TRUNC_DIGEST "drbg-no-trunc-md"

#define OPENSSL_HMAC_H 

#define HEADER_HMAC_H 

#define HMAC_MAX_MD_CBLOCK 200

#define OSSL_HPKE_H 

#define OSSL_HPKE_MODE_BASE 0

#define OSSL_HPKE_MODE_PSK 1

#define OSSL_HPKE_MODE_AUTH 2

#define OSSL_HPKE_MODE_PSKAUTH 3

#define OSSL_HPKE_MAX_PARMLEN 66

#define OSSL_HPKE_MIN_PSKLEN 32

#define OSSL_HPKE_MAX_INFOLEN 1024

#define OSSL_HPKE_KEM_ID_RESERVED 0x0000

#define OSSL_HPKE_KEM_ID_P256 0x0010

#define OSSL_HPKE_KEM_ID_P384 0x0011

#define OSSL_HPKE_KEM_ID_P521 0x0012

#define OSSL_HPKE_KEM_ID_X25519 0x0020

#define OSSL_HPKE_KEM_ID_X448 0x0021

#define OSSL_HPKE_KDF_ID_RESERVED 0x0000

#define OSSL_HPKE_KDF_ID_HKDF_SHA256 0x0001

#define OSSL_HPKE_KDF_ID_HKDF_SHA384 0x0002

#define OSSL_HPKE_KDF_ID_HKDF_SHA512 0x0003

#define OSSL_HPKE_AEAD_ID_RESERVED 0x0000

#define OSSL_HPKE_AEAD_ID_AES_GCM_128 0x0001

#define OSSL_HPKE_AEAD_ID_AES_GCM_256 0x0002

#define OSSL_HPKE_AEAD_ID_CHACHA_POLY1305 0x0003

#define OSSL_HPKE_AEAD_ID_EXPORTONLY 0xFFFF

#define OSSL_HPKE_KEMSTR_P256 "P-256"

#define OSSL_HPKE_KEMSTR_P384 "P-384"

#define OSSL_HPKE_KEMSTR_P521 "P-521"

#define OSSL_HPKE_KEMSTR_X25519 "X25519"

#define OSSL_HPKE_KEMSTR_X448 "X448"

#define OSSL_HPKE_KDFSTR_256 "hkdf-sha256"

#define OSSL_HPKE_KDFSTR_384 "hkdf-sha384"

#define OSSL_HPKE_KDFSTR_512 "hkdf-sha512"

#define OSSL_HPKE_AEADSTR_AES128GCM "aes-128-gcm"

#define OSSL_HPKE_AEADSTR_AES256GCM "aes-256-gcm"

#define OSSL_HPKE_AEADSTR_CP "chacha20-poly1305"

#define OSSL_HPKE_AEADSTR_EXP "exporter"

#define OSSL_HPKE_ROLE_SENDER 0

#define OSSL_HPKE_ROLE_RECEIVER 1

#define OSSL_HPKE_SUITE_DEFAULT \
	{\\
	OSSL_HPKE_KEM_ID_X25519, \\
	OSSL_HPKE_KDF_ID_HKDF_SHA256, \\
	OSSL_HPKE_AEAD_ID_AES_GCM_128 \\
	}

#define OPENSSL_HTTP_H 

#define OSSL_HTTP_NAME "http"

#define OSSL_HTTPS_NAME "https"

#define OSSL_HTTP_PREFIX OSSL_HTTP_NAME"://"

#define OSSL_HTTPS_PREFIX OSSL_HTTPS_NAME"://"

#define OSSL_HTTP_PORT "80"

#define OSSL_HTTPS_PORT "443"

#define OPENSSL_NO_PROXY "NO_PROXY"

#define OPENSSL_HTTP_PROXY "HTTP_PROXY"

#define OPENSSL_HTTPS_PROXY "HTTPS_PROXY"

#define OSSL_HTTP_DEFAULT_MAX_LINE_LEN (4 * 1024)

#define OSSL_HTTP_DEFAULT_MAX_RESP_LEN (100 * 1024)

#define OSSL_HTTP_DEFAULT_MAX_RESP_HDR_LINES 256

#define OPENSSL_HTTPERR_H 

#define HTTP_R_ASN1_LEN_EXCEEDS_MAX_RESP_LEN 108

#define HTTP_R_CONNECT_FAILURE 100

#define HTTP_R_ERROR_PARSING_ASN1_LENGTH 109

#define HTTP_R_ERROR_PARSING_CONTENT_LENGTH 119

#define HTTP_R_ERROR_PARSING_URL 101

#define HTTP_R_ERROR_RECEIVING 103

#define HTTP_R_ERROR_SENDING 102

#define HTTP_R_FAILED_READING_DATA 128

#define HTTP_R_HEADER_PARSE_ERROR 126

#define HTTP_R_INCONSISTENT_CONTENT_LENGTH 120

#define HTTP_R_INVALID_PORT_NUMBER 123

#define HTTP_R_INVALID_URL_PATH 125

#define HTTP_R_INVALID_URL_SCHEME 124

#define HTTP_R_MAX_RESP_LEN_EXCEEDED 117

#define HTTP_R_MISSING_ASN1_ENCODING 110

#define HTTP_R_MISSING_CONTENT_TYPE 121

#define HTTP_R_MISSING_REDIRECT_LOCATION 111

#define HTTP_R_RECEIVED_ERROR 105

#define HTTP_R_RECEIVED_WRONG_HTTP_VERSION 106

#define HTTP_R_REDIRECTION_FROM_HTTPS_TO_HTTP 112

#define HTTP_R_REDIRECTION_NOT_ENABLED 116

#define HTTP_R_RESPONSE_LINE_TOO_LONG 113

#define HTTP_R_RESPONSE_PARSE_ERROR 104

#define HTTP_R_RESPONSE_TOO_MANY_HDRLINES 130

#define HTTP_R_RETRY_TIMEOUT 129

#define HTTP_R_SERVER_CANCELED_CONNECTION 127

#define HTTP_R_SOCK_NOT_SUPPORTED 122

#define HTTP_R_STATUS_CODE_UNSUPPORTED 114

#define HTTP_R_TLS_NOT_ENABLED 107

#define HTTP_R_TOO_MANY_REDIRECTIONS 115

#define HTTP_R_UNEXPECTED_CONTENT_TYPE 118

#define OPENSSL_IDEA_H 

#define HEADER_IDEA_H 

#define IDEA_BLOCK 8

#define IDEA_KEY_LENGTH 16

#define IDEA_ENCRYPT 1

#define IDEA_DECRYPT 0

#define idea_options IDEA_options

#define idea_ecb_encrypt IDEA_ecb_encrypt

#define idea_set_encrypt_key IDEA_set_encrypt_key

#define idea_set_decrypt_key IDEA_set_decrypt_key

#define idea_cbc_encrypt IDEA_cbc_encrypt

#define idea_cfb64_encrypt IDEA_cfb64_encrypt

#define idea_ofb64_encrypt IDEA_ofb64_encrypt

#define idea_encrypt IDEA_encrypt

#define OPENSSL_KDF_H 

#define HEADER_KDF_H 

#define EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND 0

#define EVP_KDF_HKDF_MODE_EXTRACT_ONLY 1

#define EVP_KDF_HKDF_MODE_EXPAND_ONLY 2

#define EVP_KDF_SSHKDF_TYPE_INITIAL_IV_CLI_TO_SRV 65

#define EVP_KDF_SSHKDF_TYPE_INITIAL_IV_SRV_TO_CLI 66

#define EVP_KDF_SSHKDF_TYPE_ENCRYPTION_KEY_CLI_TO_SRV 67

#define EVP_KDF_SSHKDF_TYPE_ENCRYPTION_KEY_SRV_TO_CLI 68

#define EVP_KDF_SSHKDF_TYPE_INTEGRITY_KEY_CLI_TO_SRV 69

#define EVP_KDF_SSHKDF_TYPE_INTEGRITY_KEY_SRV_TO_CLI 70

#define EVP_PKEY_CTRL_TLS_MD (EVP_PKEY_ALG_CTRL)

#define EVP_PKEY_CTRL_TLS_SECRET (EVP_PKEY_ALG_CTRL + 1)

#define EVP_PKEY_CTRL_TLS_SEED (EVP_PKEY_ALG_CTRL + 2)

#define EVP_PKEY_CTRL_HKDF_MD (EVP_PKEY_ALG_CTRL + 3)

#define EVP_PKEY_CTRL_HKDF_SALT (EVP_PKEY_ALG_CTRL + 4)

#define EVP_PKEY_CTRL_HKDF_KEY (EVP_PKEY_ALG_CTRL + 5)

#define EVP_PKEY_CTRL_HKDF_INFO (EVP_PKEY_ALG_CTRL + 6)

#define EVP_PKEY_CTRL_HKDF_MODE (EVP_PKEY_ALG_CTRL + 7)

#define EVP_PKEY_CTRL_PASS (EVP_PKEY_ALG_CTRL + 8)

#define EVP_PKEY_CTRL_SCRYPT_SALT (EVP_PKEY_ALG_CTRL + 9)

#define EVP_PKEY_CTRL_SCRYPT_N (EVP_PKEY_ALG_CTRL + 10)

#define EVP_PKEY_CTRL_SCRYPT_R (EVP_PKEY_ALG_CTRL + 11)

#define EVP_PKEY_CTRL_SCRYPT_P (EVP_PKEY_ALG_CTRL + 12)

#define EVP_PKEY_CTRL_SCRYPT_MAXMEM_BYTES (EVP_PKEY_ALG_CTRL + 13)

#define EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND \
	EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND

#define EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY \
	EVP_KDF_HKDF_MODE_EXTRACT_ONLY

#define EVP_PKEY_HKDEF_MODE_EXPAND_ONLY \
	EVP_KDF_HKDF_MODE_EXPAND_ONLY

#define EVP_PKEY_CTX_hkdf_mode EVP_PKEY_CTX_set_hkdf_mode

#define OPENSSL_KDFERR_H 

#define OPENSSL_LHASH_H 

#define HEADER_LHASH_H 

#define DECLARE_LHASH_HASH_FN (name, o_type)\
	unsigned long name##_LHASH_HASH(const void *);

#define IMPLEMENT_LHASH_HASH_FN (name, o_type)\
	unsigned long name##_LHASH_HASH(const void *arg) { \\
	const o_type *a = arg; \\
	return name##_hash(a); }

#define LHASH_HASH_FN (name) name##_LHASH_HASH

#define DECLARE_LHASH_COMP_FN (name, o_type)\
	int name##_LHASH_COMP(const void *, const void *);

#define IMPLEMENT_LHASH_COMP_FN (name, o_type)\
	int name##_LHASH_COMP(const void *arg1, const void *arg2) { \\
	const o_type *a = arg1;             \\
	const o_type *b = arg2; \\
	return name##_cmp(a,b); }

#define LHASH_COMP_FN (name) name##_LHASH_COMP

#define DECLARE_LHASH_DOALL_ARG_FN (name, o_type, a_type)\
	void name##_LHASH_DOALL_ARG(void *, void *);

#define IMPLEMENT_LHASH_DOALL_ARG_FN (name, o_type, a_type)\
	void name##_LHASH_DOALL_ARG(void *arg1, void *arg2) { \\
	o_type *a = arg1; \\
	a_type *b = arg2; \\
	name##_doall_arg(a, b); }

#define LHASH_DOALL_ARG_FN (name) name##_LHASH_DOALL_ARG

#define LH_LOAD_MULT 256

#define _LHASH OPENSSL_LHASH

#define LHASH_NODE OPENSSL_LH_NODE

#define lh_error OPENSSL_LH_error

#define lh_new OPENSSL_LH_new

#define lh_free OPENSSL_LH_free

#define lh_insert OPENSSL_LH_insert

#define lh_delete OPENSSL_LH_delete

#define lh_retrieve OPENSSL_LH_retrieve

#define lh_doall OPENSSL_LH_doall

#define lh_doall_arg OPENSSL_LH_doall_arg

#define lh_strhash OPENSSL_LH_strhash

#define lh_num_items OPENSSL_LH_num_items

#define lh_stats OPENSSL_LH_stats

#define lh_node_stats OPENSSL_LH_node_stats

#define lh_node_usage_stats OPENSSL_LH_node_usage_stats

#define lh_stats_bio OPENSSL_LH_stats_bio

#define lh_node_stats_bio OPENSSL_LH_node_stats_bio

#define lh_node_usage_stats_bio OPENSSL_LH_node_usage_stats_bio

#define LHASH_OF(TYPE) TYPE

#define DEFINE_LHASH_OF_INTERNAL (type)\
	LHASH_OF(type) { \\
	union lh_##type##_dummy { void* d1; unsigned long d2; int d3; } dummy; \\
	}; \\
	typedef int (*lh_##type##_compfunc)(const type *a, const type *b); \\
	typedef unsigned long (*lh_##type##_hashfunc)(const type *a); \\
	typedef void (*lh_##type##_doallfunc)(type *a); \\
	static ossl_inline unsigned long lh_##type##_hash_thunk(const void *data, OPENSSL_LH_HASHFUNC hfn) \\
	{ \\
	unsigned long (*hfn_conv)(const type *) = (unsigned long (*)(const type *))hfn; \\
	return hfn_conv((const type *)data); \\
	} \\
	static ossl_inline int lh_##type##_comp_thunk(const void *da, const void *db, OPENSSL_LH_COMPFUNC cfn) \\
	{ \\
	int (*cfn_conv)(const type *, const type *) = (int (*)(const type *, const type *))cfn; \\
	return cfn_conv((const type *)da, (const type *)db); \\
	} \\
	static ossl_inline void lh_##type##_doall_thunk(void *node, OPENSSL_LH_DOALL_FUNC doall) \\
	{ \\
	void (*doall_conv)(type *) = (void (*)(type *))doall; \\
	doall_conv((type *)node); \\
	} \\
	static ossl_inline void lh_##type##_doall_arg_thunk(void *node, void *arg, OPENSSL_LH_DOALL_FUNCARG doall) \\
	{ \\
	void (*doall_conv)(type *, void *) = (void (*)(type *, void *))doall; \\
	doall_conv((type *)node, arg); \\
	} \\
	static ossl_unused ossl_inline type *\\
	ossl_check_##type##_lh_plain_type(type *ptr) \\
	{ \\
	return ptr; \\
	} \\
	static ossl_unused ossl_inline const type * \\
	ossl_check_const_##type##_lh_plain_type(const type *ptr) \\
	{ \\
	return ptr; \\
	} \\
	static ossl_unused ossl_inline const OPENSSL_LHASH * \\
	ossl_check_const_##type##_lh_type(const LHASH_OF(type) *lh) \\
	{ \\
	return (const OPENSSL_LHASH *)lh; \\
	} \\
	static ossl_unused ossl_inline OPENSSL_LHASH * \\
	ossl_check_##type##_lh_type(LHASH_OF(type) *lh) \\
	{ \\
	return (OPENSSL_LHASH *)lh; \\
	} \\
	static ossl_unused ossl_inline OPENSSL_LH_COMPFUNC \\
	ossl_check_##type##_lh_compfunc_type(lh_##type##_compfunc cmp) \\
	{ \\
	return (OPENSSL_LH_COMPFUNC)cmp; \\
	} \\
	static ossl_unused ossl_inline OPENSSL_LH_HASHFUNC \\
	ossl_check_##type##_lh_hashfunc_type(lh_##type##_hashfunc hfn) \\
	{ \\
	return (OPENSSL_LH_HASHFUNC)hfn; \\
	} \\
	static ossl_unused ossl_inline OPENSSL_LH_DOALL_FUNC \\
	ossl_check_##type##_lh_doallfunc_type(lh_##type##_doallfunc dfn) \\
	{ \\
	return (OPENSSL_LH_DOALL_FUNC)dfn; \\
	} \\
	LHASH_OF(type)

#define DEFINE_LHASH_OF_DEPRECATED (type)\
	static ossl_unused ossl_inline void \\
	lh_##type##_node_stats_bio(const LHASH_OF(type) *lh, BIO *out) \\
	{ \\
	OPENSSL_LH_node_stats_bio((const OPENSSL_LHASH *)lh, out); \\
	} \\
	static ossl_unused ossl_inline void \\
	lh_##type##_node_usage_stats_bio(const LHASH_OF(type) *lh, BIO *out) \\
	{ \\
	OPENSSL_LH_node_usage_stats_bio((const OPENSSL_LHASH *)lh, out); \\
	} \\
	static ossl_unused ossl_inline void \\
	lh_##type##_stats_bio(const LHASH_OF(type) *lh, BIO *out) \\
	{ \\
	OPENSSL_LH_stats_bio((const OPENSSL_LHASH *)lh, out); \\
	}

#define DEFINE_LHASH_OF_EX (type)\
	LHASH_OF(type) { \\
	union lh_##type##_dummy { void* d1; unsigned long d2; int d3; } dummy; \\
	}; \\
	static unsigned long \\
	lh_##type##_hfn_thunk(const void *data, OPENSSL_LH_HASHFUNC hfn) \\
	{ \\
	unsigned long (*hfn_conv)(const type *) = (unsigned long (*)(const type *))hfn; \\
	return hfn_conv((const type *)data); \\
	} \\
	static int lh_##type##_cfn_thunk(const void *da, const void *db, OPENSSL_LH_COMPFUNC cfn) \\
	{ \\
	int (*cfn_conv)(const type *, const type *) = (int (*)(const type *, const type *))cfn; \\
	return cfn_conv((const type *)da, (const type *)db); \\
	} \\
	static ossl_unused ossl_inline void \\
	lh_##type##_free(LHASH_OF(type) *lh) \\
	{ \\
	OPENSSL_LH_free((OPENSSL_LHASH *)lh); \\
	} \\
	static ossl_unused ossl_inline void \\
	lh_##type##_flush(LHASH_OF(type) *lh) \\
	{ \\
	OPENSSL_LH_flush((OPENSSL_LHASH *)lh); \\
	} \\
	static ossl_unused ossl_inline type * \\
	lh_##type##_insert(LHASH_OF(type) *lh, type *d) \\
	{ \\
	return (type *)OPENSSL_LH_insert((OPENSSL_LHASH *)lh, d); \\
	} \\
	static ossl_unused ossl_inline type * \\
	lh_##type##_delete(LHASH_OF(type) *lh, const type *d) \\
	{ \\
	return (type *)OPENSSL_LH_delete((OPENSSL_LHASH *)lh, d); \\
	} \\
	static ossl_unused ossl_inline type * \\
	lh_##type##_retrieve(LHASH_OF(type) *lh, const type *d) \\
	{ \\
	return (type *)OPENSSL_LH_retrieve((OPENSSL_LHASH *)lh, d); \\
	} \\
	static ossl_unused ossl_inline int \\
	lh_##type##_error(LHASH_OF(type) *lh) \\
	{ \\
	return OPENSSL_LH_error((OPENSSL_LHASH *)lh); \\
	} \\
	static ossl_unused ossl_inline unsigned long \\
	lh_##type##_num_items(LHASH_OF(type) *lh) \\
	{ \\
	return OPENSSL_LH_num_items((OPENSSL_LHASH *)lh); \\
	} \\
	static ossl_unused ossl_inline unsigned long \\
	lh_##type##_get_down_load(LHASH_OF(type) *lh) \\
	{ \\
	return OPENSSL_LH_get_down_load((OPENSSL_LHASH *)lh); \\
	} \\
	static ossl_unused ossl_inline void \\
	lh_##type##_set_down_load(LHASH_OF(type) *lh, unsigned long dl) \\
	{ \\
	OPENSSL_LH_set_down_load((OPENSSL_LHASH *)lh, dl); \\
	} \\
	static ossl_unused ossl_inline void \\
	lh_##type##_doall_thunk(void *node, OPENSSL_LH_DOALL_FUNC doall) \\
	{ \\
	void (*doall_conv)(type *) = (void (*)(type *))doall; \\
	doall_conv((type *)node); \\
	} \\
	static ossl_unused ossl_inline void \\
	lh_##type##_doall_arg_thunk(void *node, void *arg, OPENSSL_LH_DOALL_FUNCARG doall) \\
	{ \\
	void (*doall_conv)(type *, void *) = (void (*)(type *, void *))doall; \\
	doall_conv((type *)node, arg); \\
	} \\
	static ossl_unused ossl_inline void \\
	lh_##type##_doall(LHASH_OF(type) *lh, void (*doall)(type *)) \\
	{ \\
	OPENSSL_LH_doall((OPENSSL_LHASH *)lh, (OPENSSL_LH_DOALL_FUNC)doall); \\
	} \\
	static ossl_unused ossl_inline LHASH_OF(type) * \\
	lh_##type##_new(unsigned long (*hfn)(const type *), \\
	int (*cfn)(const type *, const type *)) \\
	{ \\
	return (LHASH_OF(type) *)OPENSSL_LH_set_thunks(OPENSSL_LH_new((OPENSSL_LH_HASHFUNC)hfn, (OPENSSL_LH_COMPFUNC)cfn), \\
	lh_##type##_hfn_thunk, lh_##type##_cfn_thunk, \\
	lh_##type##_doall_thunk, \\
	lh_##type##_doall_arg_thunk); \\
	} \\
	static ossl_unused ossl_inline void \\
	lh_##type##_doall_arg(LHASH_OF(type) *lh, \\
	void (*doallarg)(type *, void *), void *arg) \\
	{ \\
	OPENSSL_LH_doall_arg((OPENSSL_LHASH *)lh, \\
	(OPENSSL_LH_DOALL_FUNCARG)doallarg, arg); \\
	} \\
	LHASH_OF(type)

#define DEFINE_LHASH_OF (type)\
	DEFINE_LHASH_OF_EX(type); \\
	DEFINE_LHASH_OF_DEPRECATED(type) \\
	LHASH_OF(type)

#define IMPLEMENT_LHASH_DOALL_ARG_CONST (type, argtype)\
	int_implement_lhash_doall(type, argtype, const type)

#define IMPLEMENT_LHASH_DOALL_ARG (type, argtype)\
	int_implement_lhash_doall(type, argtype, type)

#define int_implement_lhash_doall (type, argtype, cbargtype)\
	static ossl_unused ossl_inline void \\
	lh_##type##_doall_##argtype##_thunk(void *node, void *arg, OPENSSL_LH_DOALL_FUNCARG fn) \\
	{ \\
	void (*fn_conv)(cbargtype *, argtype *) = (void (*)(cbargtype *, argtype *))fn; \\
	fn_conv((cbargtype *)node, (argtype *)arg); \\
	} \\
	static ossl_unused ossl_inline void \\
	lh_##type##_doall_##argtype(LHASH_OF(type) *lh, \\
	void (*fn)(cbargtype *, argtype *), \\
	argtype *arg) \\
	{ \\
	OPENSSL_LH_doall_arg_thunk((OPENSSL_LHASH *)lh, \\
	lh_##type##_doall_##argtype##_thunk, \\
	(OPENSSL_LH_DOALL_FUNCARG)fn, \\
	(void *)arg); \\
	} \\
	LHASH_OF(type)

#define OPENSSL_MACROS_H 

#define OPENSSL_MSTR_HELPER (x) #x

#define OPENSSL_MSTR (x) OPENSSL_MSTR_HELPER(x)

#define NON_EMPTY_TRANSLATION_UNIT static void *dummy = &dummy;

#define OSSL_DEPRECATED (since)\
	__declspec(deprecated("Since OpenSSL " # since))

#define OSSL_DEPRECATED_FOR (since, message)\
	__declspec(deprecated("Since OpenSSL " # since ";" message))

#define OPENSSL_API_LEVEL (OPENSSL_API_COMPAT)

#define OSSL_DEPRECATEDIN_3_1 OSSL_DEPRECATED(3.1)

#define OSSL_DEPRECATEDIN_3_1_FOR (msg)       OSSL_DEPRECATED_FOR(3.1, msg)

#define OPENSSL_NO_DEPRECATED_3_1 

#define OSSL_DEPRECATEDIN_3_0 OSSL_DEPRECATED(3.0)

#define OSSL_DEPRECATEDIN_3_0_FOR (msg)       OSSL_DEPRECATED_FOR(3.0, msg)

#define OPENSSL_NO_DEPRECATED_3_0 

#define OSSL_DEPRECATEDIN_1_1_1 OSSL_DEPRECATED(1.1.1)

#define OSSL_DEPRECATEDIN_1_1_1_FOR (msg)     OSSL_DEPRECATED_FOR(1.1.1, msg)

#define OPENSSL_NO_DEPRECATED_1_1_1 

#define OSSL_DEPRECATEDIN_1_1_0 OSSL_DEPRECATED(1.1.0)

#define OSSL_DEPRECATEDIN_1_1_0_FOR (msg)     OSSL_DEPRECATED_FOR(1.1.0, msg)

#define OPENSSL_NO_DEPRECATED_1_1_0 

#define OSSL_DEPRECATEDIN_1_0_2 OSSL_DEPRECATED(1.0.2)

#define OSSL_DEPRECATEDIN_1_0_2_FOR (msg)     OSSL_DEPRECATED_FOR(1.0.2, msg)

#define OPENSSL_NO_DEPRECATED_1_0_2 

#define OSSL_DEPRECATEDIN_1_0_1 OSSL_DEPRECATED(1.0.1)

#define OSSL_DEPRECATEDIN_1_0_1_FOR (msg)     OSSL_DEPRECATED_FOR(1.0.1, msg)

#define OPENSSL_NO_DEPRECATED_1_0_1 

#define OSSL_DEPRECATEDIN_1_0_0 OSSL_DEPRECATED(1.0.0)

#define OSSL_DEPRECATEDIN_1_0_0_FOR (msg)     OSSL_DEPRECATED_FOR(1.0.0, msg)

#define OPENSSL_NO_DEPRECATED_1_0_0 

#define OSSL_DEPRECATEDIN_0_9_8 OSSL_DEPRECATED(0.9.8)

#define OSSL_DEPRECATEDIN_0_9_8_FOR (msg)     OSSL_DEPRECATED_FOR(0.9.8, msg)

#define OPENSSL_NO_DEPRECATED_0_9_8 

#define OPENSSL_FILE ""

#define OPENSSL_LINE 0

#define OPENSSL_FUNC __func__

#define OSSL_CRYPTO_ALLOC __attribute__((__malloc__))

#define OPENSSL_MD2_H 

#define HEADER_MD2_H 

#define MD2_DIGEST_LENGTH 16

#define MD2_BLOCK 16

#define OPENSSL_MD4_H 

#define HEADER_MD4_H 

#define MD4_DIGEST_LENGTH 16

#define MD4_LONG unsigned int

#define MD4_CBLOCK 64

#define MD4_LBLOCK (MD4_CBLOCK/4)

#define OPENSSL_MD5_H 

#define HEADER_MD5_H 

#define MD5_DIGEST_LENGTH 16

#define MD5_LONG unsigned int

#define MD5_CBLOCK 64

#define MD5_LBLOCK (MD5_CBLOCK/4)

#define OPENSSL_MDC2_H 

#define HEADER_MDC2_H 

#define MDC2_DIGEST_LENGTH 16

#define MDC2_BLOCK 8

#define OPENSSL_MODES_H 

#define HEADER_MODES_H 

#define OPENSSL_OBJECTS_H 

#define HEADER_OBJECTS_H 

#define OBJ_NAME_TYPE_UNDEF 0x00

#define OBJ_NAME_TYPE_MD_METH 0x01

#define OBJ_NAME_TYPE_CIPHER_METH 0x02

#define OBJ_NAME_TYPE_PKEY_METH 0x03

#define OBJ_NAME_TYPE_COMP_METH 0x04

#define OBJ_NAME_TYPE_MAC_METH 0x05

#define OBJ_NAME_TYPE_KDF_METH 0x06

#define OBJ_NAME_TYPE_NUM 0x07

#define OBJ_NAME_ALIAS 0x8000

#define OBJ_BSEARCH_VALUE_ON_NOMATCH 0x01

#define OBJ_BSEARCH_FIRST_VALUE_ON_MATCH 0x02

#define OBJ_create_and_add_object (a,b,c) OBJ_create(a,b,c)

#define _DECLARE_OBJ_BSEARCH_CMP_FN (scope, type1, type2, nm)\
	static int nm##_cmp_BSEARCH_CMP_FN(const void *, const void *); \\
	static int nm##_cmp(type1 const *, type2 const *); \\
	scope type2 * OBJ_bsearch_##nm(type1 *key, type2 const *base, int num)

#define DECLARE_OBJ_BSEARCH_CMP_FN (type1, type2, cmp)\
	_DECLARE_OBJ_BSEARCH_CMP_FN(static, type1, type2, cmp)

#define DECLARE_OBJ_BSEARCH_GLOBAL_CMP_FN (type1, type2, nm)\
	type2 * OBJ_bsearch_##nm(type1 *key, type2 const *base, int num)

#define IMPLEMENT_OBJ_BSEARCH_CMP_FN (type1, type2, nm)\
	static int nm##_cmp_BSEARCH_CMP_FN(const void *a_, const void *b_)    \\
	{ \\
	type1 const *a = a_; \\
	type2 const *b = b_; \\
	return nm##_cmp(a,b); \\
	} \\
	static type2 *OBJ_bsearch_##nm(type1 *key, type2 const *base, int num) \\
	{ \\
	return (type2 *)OBJ_bsearch_(key, base, num, sizeof(type2), \\
	nm##_cmp_BSEARCH_CMP_FN); \\
	} \\
	extern void dummy_prototype(void)

#define IMPLEMENT_OBJ_BSEARCH_GLOBAL_CMP_FN (type1, type2, nm)\
	static int nm##_cmp_BSEARCH_CMP_FN(const void *a_, const void *b_)    \\
	{ \\
	type1 const *a = a_; \\
	type2 const *b = b_; \\
	return nm##_cmp(a,b); \\
	} \\
	type2 *OBJ_bsearch_##nm(type1 *key, type2 const *base, int num) \\
	{ \\
	return (type2 *)OBJ_bsearch_(key, base, num, sizeof(type2), \\
	nm##_cmp_BSEARCH_CMP_FN); \\
	} \\
	extern void dummy_prototype(void)

#define OBJ_bsearch (type1,key,type2,base,num,cmp)\
	((type2 *)OBJ_bsearch_(CHECKED_PTR_OF(type1,key),CHECKED_PTR_OF(type2,base), \\
	num,sizeof(type2),                             \\
	((void)CHECKED_PTR_OF(type1,cmp##_type_1),     \\
	(void)CHECKED_PTR_OF(type2,cmp##_type_2),     \\
	cmp##_BSEARCH_CMP_FN)))

#define OBJ_bsearch_ex (type1,key,type2,base,num,cmp,flags)\
	((type2 *)OBJ_bsearch_ex_(CHECKED_PTR_OF(type1,key),CHECKED_PTR_OF(type2,base), \\
	num,sizeof(type2),                             \\
	((void)CHECKED_PTR_OF(type1,cmp##_type_1),     \\
	(void)type_2=CHECKED_PTR_OF(type2,cmp##_type_2), \\
	cmp##_BSEARCH_CMP_FN)),flags)

#define OBJ_cleanup () while(0) continue

#define OPENSSL_OBJECTSERR_H 

#define OBJ_R_OID_EXISTS 102

#define OBJ_R_UNKNOWN_NID 101

#define OBJ_R_UNKNOWN_OBJECT_NAME 103

#define OPENSSL_OBJ_MAC_H 

#define SN_undef "UNDEF"

#define LN_undef "undefined"

#define NID_undef 0

#define OBJ_undef 0L

#define SN_itu_t "ITU-T"

#define LN_itu_t "itu-t"

#define NID_itu_t 645

#define OBJ_itu_t 0L

#define NID_ccitt 404

#define OBJ_ccitt OBJ_itu_t

#define SN_iso "ISO"

#define LN_iso "iso"

#define NID_iso 181

#define OBJ_iso 1L

#define SN_joint_iso_itu_t "JOINT-ISO-ITU-T"

#define LN_joint_iso_itu_t "joint-iso-itu-t"

#define NID_joint_iso_itu_t 646

#define OBJ_joint_iso_itu_t 2L

#define NID_joint_iso_ccitt 393

#define OBJ_joint_iso_ccitt OBJ_joint_iso_itu_t

#define SN_member_body "member-body"

#define LN_member_body "ISO Member Body"

#define NID_member_body 182

#define OBJ_member_body OBJ_iso,2L

#define SN_identified_organization "identified-organization"

#define NID_identified_organization 676

#define OBJ_identified_organization OBJ_iso,3L

#define SN_gmac "GMAC"

#define LN_gmac "gmac"

#define NID_gmac 1195

#define OBJ_gmac OBJ_iso,0L,9797L,3L,4L

#define SN_hmac_md5 "HMAC-MD5"

#define LN_hmac_md5 "hmac-md5"

#define NID_hmac_md5 780

#define OBJ_hmac_md5 OBJ_identified_organization,6L,1L,5L,5L,8L,1L,1L

#define SN_hmac_sha1 "HMAC-SHA1"

#define LN_hmac_sha1 "hmac-sha1"

#define NID_hmac_sha1 781

#define OBJ_hmac_sha1 OBJ_identified_organization,6L,1L,5L,5L,8L,1L,2L

#define SN_x509ExtAdmission "x509ExtAdmission"

#define LN_x509ExtAdmission "Professional Information or basis for Admission"

#define NID_x509ExtAdmission 1093

#define OBJ_x509ExtAdmission OBJ_identified_organization,36L,8L,3L,3L

#define SN_certicom_arc "certicom-arc"

#define NID_certicom_arc 677

#define OBJ_certicom_arc OBJ_identified_organization,132L

#define SN_ieee "ieee"

#define NID_ieee 1170

#define OBJ_ieee OBJ_identified_organization,111L

#define SN_ieee_siswg "ieee-siswg"

#define LN_ieee_siswg "IEEE Security in Storage Working Group"

#define NID_ieee_siswg 1171

#define OBJ_ieee_siswg OBJ_ieee,2L,1619L

#define SN_international_organizations "international-organizations"

#define LN_international_organizations "International Organizations"

#define NID_international_organizations 647

#define OBJ_international_organizations OBJ_joint_iso_itu_t,23L

#define SN_wap "wap"

#define NID_wap 678

#define OBJ_wap OBJ_international_organizations,43L

#define SN_wap_wsg "wap-wsg"

#define NID_wap_wsg 679

#define OBJ_wap_wsg OBJ_wap,1L

#define SN_selected_attribute_types "selected-attribute-types"

#define LN_selected_attribute_types "Selected Attribute Types"

#define NID_selected_attribute_types 394

#define OBJ_selected_attribute_types OBJ_joint_iso_itu_t,5L,1L,5L

#define SN_clearance "clearance"

#define NID_clearance 395

#define OBJ_clearance OBJ_selected_attribute_types,55L

#define SN_ISO_US "ISO-US"

#define LN_ISO_US "ISO US Member Body"

#define NID_ISO_US 183

#define OBJ_ISO_US OBJ_member_body,840L

#define SN_X9_57 "X9-57"

#define LN_X9_57 "X9.57"

#define NID_X9_57 184

#define OBJ_X9_57 OBJ_ISO_US,10040L

#define SN_X9cm "X9cm"

#define LN_X9cm "X9.57 CM ?"

#define NID_X9cm 185

#define OBJ_X9cm OBJ_X9_57,4L

#define SN_ISO_CN "ISO-CN"

#define LN_ISO_CN "ISO CN Member Body"

#define NID_ISO_CN 1140

#define OBJ_ISO_CN OBJ_member_body,156L

#define SN_oscca "oscca"

#define NID_oscca 1141

#define OBJ_oscca OBJ_ISO_CN,10197L

#define SN_sm_scheme "sm-scheme"

#define NID_sm_scheme 1142

#define OBJ_sm_scheme OBJ_oscca,1L

#define SN_dsa "DSA"

#define LN_dsa "dsaEncryption"

#define NID_dsa 116

#define OBJ_dsa OBJ_X9cm,1L

#define SN_dsaWithSHA1 "DSA-SHA1"

#define LN_dsaWithSHA1 "dsaWithSHA1"

#define NID_dsaWithSHA1 113

#define OBJ_dsaWithSHA1 OBJ_X9cm,3L

#define SN_ansi_X9_62 "ansi-X9-62"

#define LN_ansi_X9_62 "ANSI X9.62"

#define NID_ansi_X9_62 405

#define OBJ_ansi_X9_62 OBJ_ISO_US,10045L

#define OBJ_X9_62_id_fieldType OBJ_ansi_X9_62,1L

#define SN_X9_62_prime_field "prime-field"

#define NID_X9_62_prime_field 406

#define OBJ_X9_62_prime_field OBJ_X9_62_id_fieldType,1L

#define SN_X9_62_characteristic_two_field "characteristic-two-field"

#define NID_X9_62_characteristic_two_field 407

#define OBJ_X9_62_characteristic_two_field OBJ_X9_62_id_fieldType,2L

#define SN_X9_62_id_characteristic_two_basis "id-characteristic-two-basis"

#define NID_X9_62_id_characteristic_two_basis 680

#define OBJ_X9_62_id_characteristic_two_basis OBJ_X9_62_characteristic_two_field,3L

#define SN_X9_62_onBasis "onBasis"

#define NID_X9_62_onBasis 681

#define OBJ_X9_62_onBasis OBJ_X9_62_id_characteristic_two_basis,1L

#define SN_X9_62_tpBasis "tpBasis"

#define NID_X9_62_tpBasis 682

#define OBJ_X9_62_tpBasis OBJ_X9_62_id_characteristic_two_basis,2L

#define SN_X9_62_ppBasis "ppBasis"

#define NID_X9_62_ppBasis 683

#define OBJ_X9_62_ppBasis OBJ_X9_62_id_characteristic_two_basis,3L

#define OBJ_X9_62_id_publicKeyType OBJ_ansi_X9_62,2L

#define SN_X9_62_id_ecPublicKey "id-ecPublicKey"

#define NID_X9_62_id_ecPublicKey 408

#define OBJ_X9_62_id_ecPublicKey OBJ_X9_62_id_publicKeyType,1L

#define OBJ_X9_62_ellipticCurve OBJ_ansi_X9_62,3L

#define OBJ_X9_62_c_TwoCurve OBJ_X9_62_ellipticCurve,0L

#define SN_X9_62_c2pnb163v1 "c2pnb163v1"

#define NID_X9_62_c2pnb163v1 684

#define OBJ_X9_62_c2pnb163v1 OBJ_X9_62_c_TwoCurve,1L

#define SN_X9_62_c2pnb163v2 "c2pnb163v2"

#define NID_X9_62_c2pnb163v2 685

#define OBJ_X9_62_c2pnb163v2 OBJ_X9_62_c_TwoCurve,2L

#define SN_X9_62_c2pnb163v3 "c2pnb163v3"

#define NID_X9_62_c2pnb163v3 686

#define OBJ_X9_62_c2pnb163v3 OBJ_X9_62_c_TwoCurve,3L

#define SN_X9_62_c2pnb176v1 "c2pnb176v1"

#define NID_X9_62_c2pnb176v1 687

#define OBJ_X9_62_c2pnb176v1 OBJ_X9_62_c_TwoCurve,4L

#define SN_X9_62_c2tnb191v1 "c2tnb191v1"

#define NID_X9_62_c2tnb191v1 688

#define OBJ_X9_62_c2tnb191v1 OBJ_X9_62_c_TwoCurve,5L

#define SN_X9_62_c2tnb191v2 "c2tnb191v2"

#define NID_X9_62_c2tnb191v2 689

#define OBJ_X9_62_c2tnb191v2 OBJ_X9_62_c_TwoCurve,6L

#define SN_X9_62_c2tnb191v3 "c2tnb191v3"

#define NID_X9_62_c2tnb191v3 690

#define OBJ_X9_62_c2tnb191v3 OBJ_X9_62_c_TwoCurve,7L

#define SN_X9_62_c2onb191v4 "c2onb191v4"

#define NID_X9_62_c2onb191v4 691

#define OBJ_X9_62_c2onb191v4 OBJ_X9_62_c_TwoCurve,8L

#define SN_X9_62_c2onb191v5 "c2onb191v5"

#define NID_X9_62_c2onb191v5 692

#define OBJ_X9_62_c2onb191v5 OBJ_X9_62_c_TwoCurve,9L

#define SN_X9_62_c2pnb208w1 "c2pnb208w1"

#define NID_X9_62_c2pnb208w1 693

#define OBJ_X9_62_c2pnb208w1 OBJ_X9_62_c_TwoCurve,10L

#define SN_X9_62_c2tnb239v1 "c2tnb239v1"

#define NID_X9_62_c2tnb239v1 694

#define OBJ_X9_62_c2tnb239v1 OBJ_X9_62_c_TwoCurve,11L

#define SN_X9_62_c2tnb239v2 "c2tnb239v2"

#define NID_X9_62_c2tnb239v2 695

#define OBJ_X9_62_c2tnb239v2 OBJ_X9_62_c_TwoCurve,12L

#define SN_X9_62_c2tnb239v3 "c2tnb239v3"

#define NID_X9_62_c2tnb239v3 696

#define OBJ_X9_62_c2tnb239v3 OBJ_X9_62_c_TwoCurve,13L

#define SN_X9_62_c2onb239v4 "c2onb239v4"

#define NID_X9_62_c2onb239v4 697

#define OBJ_X9_62_c2onb239v4 OBJ_X9_62_c_TwoCurve,14L

#define SN_X9_62_c2onb239v5 "c2onb239v5"

#define NID_X9_62_c2onb239v5 698

#define OBJ_X9_62_c2onb239v5 OBJ_X9_62_c_TwoCurve,15L

#define SN_X9_62_c2pnb272w1 "c2pnb272w1"

#define NID_X9_62_c2pnb272w1 699

#define OBJ_X9_62_c2pnb272w1 OBJ_X9_62_c_TwoCurve,16L

#define SN_X9_62_c2pnb304w1 "c2pnb304w1"

#define NID_X9_62_c2pnb304w1 700

#define OBJ_X9_62_c2pnb304w1 OBJ_X9_62_c_TwoCurve,17L

#define SN_X9_62_c2tnb359v1 "c2tnb359v1"

#define NID_X9_62_c2tnb359v1 701

#define OBJ_X9_62_c2tnb359v1 OBJ_X9_62_c_TwoCurve,18L

#define SN_X9_62_c2pnb368w1 "c2pnb368w1"

#define NID_X9_62_c2pnb368w1 702

#define OBJ_X9_62_c2pnb368w1 OBJ_X9_62_c_TwoCurve,19L

#define SN_X9_62_c2tnb431r1 "c2tnb431r1"

#define NID_X9_62_c2tnb431r1 703

#define OBJ_X9_62_c2tnb431r1 OBJ_X9_62_c_TwoCurve,20L

#define OBJ_X9_62_primeCurve OBJ_X9_62_ellipticCurve,1L

#define SN_X9_62_prime192v1 "prime192v1"

#define NID_X9_62_prime192v1 409

#define OBJ_X9_62_prime192v1 OBJ_X9_62_primeCurve,1L

#define SN_X9_62_prime192v2 "prime192v2"

#define NID_X9_62_prime192v2 410

#define OBJ_X9_62_prime192v2 OBJ_X9_62_primeCurve,2L

#define SN_X9_62_prime192v3 "prime192v3"

#define NID_X9_62_prime192v3 411

#define OBJ_X9_62_prime192v3 OBJ_X9_62_primeCurve,3L

#define SN_X9_62_prime239v1 "prime239v1"

#define NID_X9_62_prime239v1 412

#define OBJ_X9_62_prime239v1 OBJ_X9_62_primeCurve,4L

#define SN_X9_62_prime239v2 "prime239v2"

#define NID_X9_62_prime239v2 413

#define OBJ_X9_62_prime239v2 OBJ_X9_62_primeCurve,5L

#define SN_X9_62_prime239v3 "prime239v3"

#define NID_X9_62_prime239v3 414

#define OBJ_X9_62_prime239v3 OBJ_X9_62_primeCurve,6L

#define SN_X9_62_prime256v1 "prime256v1"

#define NID_X9_62_prime256v1 415

#define OBJ_X9_62_prime256v1 OBJ_X9_62_primeCurve,7L

#define OBJ_X9_62_id_ecSigType OBJ_ansi_X9_62,4L

#define SN_ecdsa_with_SHA1 "ecdsa-with-SHA1"

#define NID_ecdsa_with_SHA1 416

#define OBJ_ecdsa_with_SHA1 OBJ_X9_62_id_ecSigType,1L

#define SN_ecdsa_with_Recommended "ecdsa-with-Recommended"

#define NID_ecdsa_with_Recommended 791

#define OBJ_ecdsa_with_Recommended OBJ_X9_62_id_ecSigType,2L

#define SN_ecdsa_with_Specified "ecdsa-with-Specified"

#define NID_ecdsa_with_Specified 792

#define OBJ_ecdsa_with_Specified OBJ_X9_62_id_ecSigType,3L

#define SN_ecdsa_with_SHA224 "ecdsa-with-SHA224"

#define NID_ecdsa_with_SHA224 793

#define OBJ_ecdsa_with_SHA224 OBJ_ecdsa_with_Specified,1L

#define SN_ecdsa_with_SHA256 "ecdsa-with-SHA256"

#define NID_ecdsa_with_SHA256 794

#define OBJ_ecdsa_with_SHA256 OBJ_ecdsa_with_Specified,2L

#define SN_ecdsa_with_SHA384 "ecdsa-with-SHA384"

#define NID_ecdsa_with_SHA384 795

#define OBJ_ecdsa_with_SHA384 OBJ_ecdsa_with_Specified,3L

#define SN_ecdsa_with_SHA512 "ecdsa-with-SHA512"

#define NID_ecdsa_with_SHA512 796

#define OBJ_ecdsa_with_SHA512 OBJ_ecdsa_with_Specified,4L

#define OBJ_secg_ellipticCurve OBJ_certicom_arc,0L

#define SN_secp112r1 "secp112r1"

#define NID_secp112r1 704

#define OBJ_secp112r1 OBJ_secg_ellipticCurve,6L

#define SN_secp112r2 "secp112r2"

#define NID_secp112r2 705

#define OBJ_secp112r2 OBJ_secg_ellipticCurve,7L

#define SN_secp128r1 "secp128r1"

#define NID_secp128r1 706

#define OBJ_secp128r1 OBJ_secg_ellipticCurve,28L

#define SN_secp128r2 "secp128r2"

#define NID_secp128r2 707

#define OBJ_secp128r2 OBJ_secg_ellipticCurve,29L

#define SN_secp160k1 "secp160k1"

#define NID_secp160k1 708

#define OBJ_secp160k1 OBJ_secg_ellipticCurve,9L

#define SN_secp160r1 "secp160r1"

#define NID_secp160r1 709

#define OBJ_secp160r1 OBJ_secg_ellipticCurve,8L

#define SN_secp160r2 "secp160r2"

#define NID_secp160r2 710

#define OBJ_secp160r2 OBJ_secg_ellipticCurve,30L

#define SN_secp192k1 "secp192k1"

#define NID_secp192k1 711

#define OBJ_secp192k1 OBJ_secg_ellipticCurve,31L

#define SN_secp224k1 "secp224k1"

#define NID_secp224k1 712

#define OBJ_secp224k1 OBJ_secg_ellipticCurve,32L

#define SN_secp224r1 "secp224r1"

#define NID_secp224r1 713

#define OBJ_secp224r1 OBJ_secg_ellipticCurve,33L

#define SN_secp256k1 "secp256k1"

#define NID_secp256k1 714

#define OBJ_secp256k1 OBJ_secg_ellipticCurve,10L

#define SN_secp384r1 "secp384r1"

#define NID_secp384r1 715

#define OBJ_secp384r1 OBJ_secg_ellipticCurve,34L

#define SN_secp521r1 "secp521r1"

#define NID_secp521r1 716

#define OBJ_secp521r1 OBJ_secg_ellipticCurve,35L

#define SN_sect113r1 "sect113r1"

#define NID_sect113r1 717

#define OBJ_sect113r1 OBJ_secg_ellipticCurve,4L

#define SN_sect113r2 "sect113r2"

#define NID_sect113r2 718

#define OBJ_sect113r2 OBJ_secg_ellipticCurve,5L

#define SN_sect131r1 "sect131r1"

#define NID_sect131r1 719

#define OBJ_sect131r1 OBJ_secg_ellipticCurve,22L

#define SN_sect131r2 "sect131r2"

#define NID_sect131r2 720

#define OBJ_sect131r2 OBJ_secg_ellipticCurve,23L

#define SN_sect163k1 "sect163k1"

#define NID_sect163k1 721

#define OBJ_sect163k1 OBJ_secg_ellipticCurve,1L

#define SN_sect163r1 "sect163r1"

#define NID_sect163r1 722

#define OBJ_sect163r1 OBJ_secg_ellipticCurve,2L

#define SN_sect163r2 "sect163r2"

#define NID_sect163r2 723

#define OBJ_sect163r2 OBJ_secg_ellipticCurve,15L

#define SN_sect193r1 "sect193r1"

#define NID_sect193r1 724

#define OBJ_sect193r1 OBJ_secg_ellipticCurve,24L

#define SN_sect193r2 "sect193r2"

#define NID_sect193r2 725

#define OBJ_sect193r2 OBJ_secg_ellipticCurve,25L

#define SN_sect233k1 "sect233k1"

#define NID_sect233k1 726

#define OBJ_sect233k1 OBJ_secg_ellipticCurve,26L

#define SN_sect233r1 "sect233r1"

#define NID_sect233r1 727

#define OBJ_sect233r1 OBJ_secg_ellipticCurve,27L

#define SN_sect239k1 "sect239k1"

#define NID_sect239k1 728

#define OBJ_sect239k1 OBJ_secg_ellipticCurve,3L

#define SN_sect283k1 "sect283k1"

#define NID_sect283k1 729

#define OBJ_sect283k1 OBJ_secg_ellipticCurve,16L

#define SN_sect283r1 "sect283r1"

#define NID_sect283r1 730

#define OBJ_sect283r1 OBJ_secg_ellipticCurve,17L

#define SN_sect409k1 "sect409k1"

#define NID_sect409k1 731

#define OBJ_sect409k1 OBJ_secg_ellipticCurve,36L

#define SN_sect409r1 "sect409r1"

#define NID_sect409r1 732

#define OBJ_sect409r1 OBJ_secg_ellipticCurve,37L

#define SN_sect571k1 "sect571k1"

#define NID_sect571k1 733

#define OBJ_sect571k1 OBJ_secg_ellipticCurve,38L

#define SN_sect571r1 "sect571r1"

#define NID_sect571r1 734

#define OBJ_sect571r1 OBJ_secg_ellipticCurve,39L

#define OBJ_wap_wsg_idm_ecid OBJ_wap_wsg,4L

#define SN_wap_wsg_idm_ecid_wtls1 "wap-wsg-idm-ecid-wtls1"

#define NID_wap_wsg_idm_ecid_wtls1 735

#define OBJ_wap_wsg_idm_ecid_wtls1 OBJ_wap_wsg_idm_ecid,1L

#define SN_wap_wsg_idm_ecid_wtls3 "wap-wsg-idm-ecid-wtls3"

#define NID_wap_wsg_idm_ecid_wtls3 736

#define OBJ_wap_wsg_idm_ecid_wtls3 OBJ_wap_wsg_idm_ecid,3L

#define SN_wap_wsg_idm_ecid_wtls4 "wap-wsg-idm-ecid-wtls4"

#define NID_wap_wsg_idm_ecid_wtls4 737

#define OBJ_wap_wsg_idm_ecid_wtls4 OBJ_wap_wsg_idm_ecid,4L

#define SN_wap_wsg_idm_ecid_wtls5 "wap-wsg-idm-ecid-wtls5"

#define NID_wap_wsg_idm_ecid_wtls5 738

#define OBJ_wap_wsg_idm_ecid_wtls5 OBJ_wap_wsg_idm_ecid,5L

#define SN_wap_wsg_idm_ecid_wtls6 "wap-wsg-idm-ecid-wtls6"

#define NID_wap_wsg_idm_ecid_wtls6 739

#define OBJ_wap_wsg_idm_ecid_wtls6 OBJ_wap_wsg_idm_ecid,6L

#define SN_wap_wsg_idm_ecid_wtls7 "wap-wsg-idm-ecid-wtls7"

#define NID_wap_wsg_idm_ecid_wtls7 740

#define OBJ_wap_wsg_idm_ecid_wtls7 OBJ_wap_wsg_idm_ecid,7L

#define SN_wap_wsg_idm_ecid_wtls8 "wap-wsg-idm-ecid-wtls8"

#define NID_wap_wsg_idm_ecid_wtls8 741

#define OBJ_wap_wsg_idm_ecid_wtls8 OBJ_wap_wsg_idm_ecid,8L

#define SN_wap_wsg_idm_ecid_wtls9 "wap-wsg-idm-ecid-wtls9"

#define NID_wap_wsg_idm_ecid_wtls9 742

#define OBJ_wap_wsg_idm_ecid_wtls9 OBJ_wap_wsg_idm_ecid,9L

#define SN_wap_wsg_idm_ecid_wtls10 "wap-wsg-idm-ecid-wtls10"

#define NID_wap_wsg_idm_ecid_wtls10 743

#define OBJ_wap_wsg_idm_ecid_wtls10 OBJ_wap_wsg_idm_ecid,10L

#define SN_wap_wsg_idm_ecid_wtls11 "wap-wsg-idm-ecid-wtls11"

#define NID_wap_wsg_idm_ecid_wtls11 744

#define OBJ_wap_wsg_idm_ecid_wtls11 OBJ_wap_wsg_idm_ecid,11L

#define SN_wap_wsg_idm_ecid_wtls12 "wap-wsg-idm-ecid-wtls12"

#define NID_wap_wsg_idm_ecid_wtls12 745

#define OBJ_wap_wsg_idm_ecid_wtls12 OBJ_wap_wsg_idm_ecid,12L

#define SN_cast5_cbc "CAST5-CBC"

#define LN_cast5_cbc "cast5-cbc"

#define NID_cast5_cbc 108

#define OBJ_cast5_cbc OBJ_ISO_US,113533L,7L,66L,10L

#define SN_cast5_ecb "CAST5-ECB"

#define LN_cast5_ecb "cast5-ecb"

#define NID_cast5_ecb 109

#define SN_cast5_cfb64 "CAST5-CFB"

#define LN_cast5_cfb64 "cast5-cfb"

#define NID_cast5_cfb64 110

#define SN_cast5_ofb64 "CAST5-OFB"

#define LN_cast5_ofb64 "cast5-ofb"

#define NID_cast5_ofb64 111

#define LN_pbeWithMD5AndCast5_CBC "pbeWithMD5AndCast5CBC"

#define NID_pbeWithMD5AndCast5_CBC 112

#define OBJ_pbeWithMD5AndCast5_CBC OBJ_ISO_US,113533L,7L,66L,12L

#define SN_id_PasswordBasedMAC "id-PasswordBasedMAC"

#define LN_id_PasswordBasedMAC "password based MAC"

#define NID_id_PasswordBasedMAC 782

#define OBJ_id_PasswordBasedMAC OBJ_ISO_US,113533L,7L,66L,13L

#define SN_id_DHBasedMac "id-DHBasedMac"

#define LN_id_DHBasedMac "Diffie-Hellman based MAC"

#define NID_id_DHBasedMac 783

#define OBJ_id_DHBasedMac OBJ_ISO_US,113533L,7L,66L,30L

#define SN_rsadsi "rsadsi"

#define LN_rsadsi "RSA Data Security, Inc."

#define NID_rsadsi 1

#define OBJ_rsadsi OBJ_ISO_US,113549L

#define SN_pkcs "pkcs"

#define LN_pkcs "RSA Data Security, Inc. PKCS"

#define NID_pkcs 2

#define OBJ_pkcs OBJ_rsadsi,1L

#define SN_pkcs1 "pkcs1"

#define NID_pkcs1 186

#define OBJ_pkcs1 OBJ_pkcs,1L

#define LN_rsaEncryption "rsaEncryption"

#define NID_rsaEncryption 6

#define OBJ_rsaEncryption OBJ_pkcs1,1L

#define SN_md2WithRSAEncryption "RSA-MD2"

#define LN_md2WithRSAEncryption "md2WithRSAEncryption"

#define NID_md2WithRSAEncryption 7

#define OBJ_md2WithRSAEncryption OBJ_pkcs1,2L

#define SN_md4WithRSAEncryption "RSA-MD4"

#define LN_md4WithRSAEncryption "md4WithRSAEncryption"

#define NID_md4WithRSAEncryption 396

#define OBJ_md4WithRSAEncryption OBJ_pkcs1,3L

#define SN_md5WithRSAEncryption "RSA-MD5"

#define LN_md5WithRSAEncryption "md5WithRSAEncryption"

#define NID_md5WithRSAEncryption 8

#define OBJ_md5WithRSAEncryption OBJ_pkcs1,4L

#define SN_sha1WithRSAEncryption "RSA-SHA1"

#define LN_sha1WithRSAEncryption "sha1WithRSAEncryption"

#define NID_sha1WithRSAEncryption 65

#define OBJ_sha1WithRSAEncryption OBJ_pkcs1,5L

#define SN_rsaesOaep "RSAES-OAEP"

#define LN_rsaesOaep "rsaesOaep"

#define NID_rsaesOaep 919

#define OBJ_rsaesOaep OBJ_pkcs1,7L

#define SN_mgf1 "MGF1"

#define LN_mgf1 "mgf1"

#define NID_mgf1 911

#define OBJ_mgf1 OBJ_pkcs1,8L

#define SN_pSpecified "PSPECIFIED"

#define LN_pSpecified "pSpecified"

#define NID_pSpecified 935

#define OBJ_pSpecified OBJ_pkcs1,9L

#define SN_rsassaPss "RSASSA-PSS"

#define LN_rsassaPss "rsassaPss"

#define NID_rsassaPss 912

#define OBJ_rsassaPss OBJ_pkcs1,10L

#define SN_sha256WithRSAEncryption "RSA-SHA256"

#define LN_sha256WithRSAEncryption "sha256WithRSAEncryption"

#define NID_sha256WithRSAEncryption 668

#define OBJ_sha256WithRSAEncryption OBJ_pkcs1,11L

#define SN_sha384WithRSAEncryption "RSA-SHA384"

#define LN_sha384WithRSAEncryption "sha384WithRSAEncryption"

#define NID_sha384WithRSAEncryption 669

#define OBJ_sha384WithRSAEncryption OBJ_pkcs1,12L

#define SN_sha512WithRSAEncryption "RSA-SHA512"

#define LN_sha512WithRSAEncryption "sha512WithRSAEncryption"

#define NID_sha512WithRSAEncryption 670

#define OBJ_sha512WithRSAEncryption OBJ_pkcs1,13L

#define SN_sha224WithRSAEncryption "RSA-SHA224"

#define LN_sha224WithRSAEncryption "sha224WithRSAEncryption"

#define NID_sha224WithRSAEncryption 671

#define OBJ_sha224WithRSAEncryption OBJ_pkcs1,14L

#define SN_sha512_224WithRSAEncryption "RSA-SHA512/224"

#define LN_sha512_224WithRSAEncryption "sha512-224WithRSAEncryption"

#define NID_sha512_224WithRSAEncryption 1145

#define OBJ_sha512_224WithRSAEncryption OBJ_pkcs1,15L

#define SN_sha512_256WithRSAEncryption "RSA-SHA512/256"

#define LN_sha512_256WithRSAEncryption "sha512-256WithRSAEncryption"

#define NID_sha512_256WithRSAEncryption 1146

#define OBJ_sha512_256WithRSAEncryption OBJ_pkcs1,16L

#define SN_pkcs3 "pkcs3"

#define NID_pkcs3 27

#define OBJ_pkcs3 OBJ_pkcs,3L

#define LN_dhKeyAgreement "dhKeyAgreement"

#define NID_dhKeyAgreement 28

#define OBJ_dhKeyAgreement OBJ_pkcs3,1L

#define SN_pkcs5 "pkcs5"

#define NID_pkcs5 187

#define OBJ_pkcs5 OBJ_pkcs,5L

#define SN_pbeWithMD2AndDES_CBC "PBE-MD2-DES"

#define LN_pbeWithMD2AndDES_CBC "pbeWithMD2AndDES-CBC"

#define NID_pbeWithMD2AndDES_CBC 9

#define OBJ_pbeWithMD2AndDES_CBC OBJ_pkcs5,1L

#define SN_pbeWithMD5AndDES_CBC "PBE-MD5-DES"

#define LN_pbeWithMD5AndDES_CBC "pbeWithMD5AndDES-CBC"

#define NID_pbeWithMD5AndDES_CBC 10

#define OBJ_pbeWithMD5AndDES_CBC OBJ_pkcs5,3L

#define SN_pbeWithMD2AndRC2_CBC "PBE-MD2-RC2-64"

#define LN_pbeWithMD2AndRC2_CBC "pbeWithMD2AndRC2-CBC"

#define NID_pbeWithMD2AndRC2_CBC 168

#define OBJ_pbeWithMD2AndRC2_CBC OBJ_pkcs5,4L

#define SN_pbeWithMD5AndRC2_CBC "PBE-MD5-RC2-64"

#define LN_pbeWithMD5AndRC2_CBC "pbeWithMD5AndRC2-CBC"

#define NID_pbeWithMD5AndRC2_CBC 169

#define OBJ_pbeWithMD5AndRC2_CBC OBJ_pkcs5,6L

#define SN_pbeWithSHA1AndDES_CBC "PBE-SHA1-DES"

#define LN_pbeWithSHA1AndDES_CBC "pbeWithSHA1AndDES-CBC"

#define NID_pbeWithSHA1AndDES_CBC 170

#define OBJ_pbeWithSHA1AndDES_CBC OBJ_pkcs5,10L

#define SN_pbeWithSHA1AndRC2_CBC "PBE-SHA1-RC2-64"

#define LN_pbeWithSHA1AndRC2_CBC "pbeWithSHA1AndRC2-CBC"

#define NID_pbeWithSHA1AndRC2_CBC 68

#define OBJ_pbeWithSHA1AndRC2_CBC OBJ_pkcs5,11L

#define LN_id_pbkdf2 "PBKDF2"

#define NID_id_pbkdf2 69

#define OBJ_id_pbkdf2 OBJ_pkcs5,12L

#define LN_pbes2 "PBES2"

#define NID_pbes2 161

#define OBJ_pbes2 OBJ_pkcs5,13L

#define LN_pbmac1 "PBMAC1"

#define NID_pbmac1 162

#define OBJ_pbmac1 OBJ_pkcs5,14L

#define SN_pkcs7 "pkcs7"

#define NID_pkcs7 20

#define OBJ_pkcs7 OBJ_pkcs,7L

#define LN_pkcs7_data "pkcs7-data"

#define NID_pkcs7_data 21

#define OBJ_pkcs7_data OBJ_pkcs7,1L

#define LN_pkcs7_signed "pkcs7-signedData"

#define NID_pkcs7_signed 22

#define OBJ_pkcs7_signed OBJ_pkcs7,2L

#define LN_pkcs7_enveloped "pkcs7-envelopedData"

#define NID_pkcs7_enveloped 23

#define OBJ_pkcs7_enveloped OBJ_pkcs7,3L

#define LN_pkcs7_signedAndEnveloped "pkcs7-signedAndEnvelopedData"

#define NID_pkcs7_signedAndEnveloped 24

#define OBJ_pkcs7_signedAndEnveloped OBJ_pkcs7,4L

#define LN_pkcs7_digest "pkcs7-digestData"

#define NID_pkcs7_digest 25

#define OBJ_pkcs7_digest OBJ_pkcs7,5L

#define LN_pkcs7_encrypted "pkcs7-encryptedData"

#define NID_pkcs7_encrypted 26

#define OBJ_pkcs7_encrypted OBJ_pkcs7,6L

#define SN_pkcs9 "pkcs9"

#define NID_pkcs9 47

#define OBJ_pkcs9 OBJ_pkcs,9L

#define LN_pkcs9_emailAddress "emailAddress"

#define NID_pkcs9_emailAddress 48

#define OBJ_pkcs9_emailAddress OBJ_pkcs9,1L

#define LN_pkcs9_unstructuredName "unstructuredName"

#define NID_pkcs9_unstructuredName 49

#define OBJ_pkcs9_unstructuredName OBJ_pkcs9,2L

#define LN_pkcs9_contentType "contentType"

#define NID_pkcs9_contentType 50

#define OBJ_pkcs9_contentType OBJ_pkcs9,3L

#define LN_pkcs9_messageDigest "messageDigest"

#define NID_pkcs9_messageDigest 51

#define OBJ_pkcs9_messageDigest OBJ_pkcs9,4L

#define LN_pkcs9_signingTime "signingTime"

#define NID_pkcs9_signingTime 52

#define OBJ_pkcs9_signingTime OBJ_pkcs9,5L

#define LN_pkcs9_countersignature "countersignature"

#define NID_pkcs9_countersignature 53

#define OBJ_pkcs9_countersignature OBJ_pkcs9,6L

#define LN_pkcs9_challengePassword "challengePassword"

#define NID_pkcs9_challengePassword 54

#define OBJ_pkcs9_challengePassword OBJ_pkcs9,7L

#define LN_pkcs9_unstructuredAddress "unstructuredAddress"

#define NID_pkcs9_unstructuredAddress 55

#define OBJ_pkcs9_unstructuredAddress OBJ_pkcs9,8L

#define LN_pkcs9_extCertAttributes "extendedCertificateAttributes"

#define NID_pkcs9_extCertAttributes 56

#define OBJ_pkcs9_extCertAttributes OBJ_pkcs9,9L

#define SN_ext_req "extReq"

#define LN_ext_req "Extension Request"

#define NID_ext_req 172

#define OBJ_ext_req OBJ_pkcs9,14L

#define SN_SMIMECapabilities "SMIME-CAPS"

#define LN_SMIMECapabilities "S/MIME Capabilities"

#define NID_SMIMECapabilities 167

#define OBJ_SMIMECapabilities OBJ_pkcs9,15L

#define SN_SMIME "SMIME"

#define LN_SMIME "S/MIME"

#define NID_SMIME 188

#define OBJ_SMIME OBJ_pkcs9,16L

#define SN_id_smime_mod "id-smime-mod"

#define NID_id_smime_mod 189

#define OBJ_id_smime_mod OBJ_SMIME,0L

#define SN_id_smime_ct "id-smime-ct"

#define NID_id_smime_ct 190

#define OBJ_id_smime_ct OBJ_SMIME,1L

#define SN_id_smime_aa "id-smime-aa"

#define NID_id_smime_aa 191

#define OBJ_id_smime_aa OBJ_SMIME,2L

#define SN_id_smime_alg "id-smime-alg"

#define NID_id_smime_alg 192

#define OBJ_id_smime_alg OBJ_SMIME,3L

#define SN_id_smime_cd "id-smime-cd"

#define NID_id_smime_cd 193

#define OBJ_id_smime_cd OBJ_SMIME,4L

#define SN_id_smime_spq "id-smime-spq"

#define NID_id_smime_spq 194

#define OBJ_id_smime_spq OBJ_SMIME,5L

#define SN_id_smime_cti "id-smime-cti"

#define NID_id_smime_cti 195

#define OBJ_id_smime_cti OBJ_SMIME,6L

#define SN_id_smime_mod_cms "id-smime-mod-cms"

#define NID_id_smime_mod_cms 196

#define OBJ_id_smime_mod_cms OBJ_id_smime_mod,1L

#define SN_id_smime_mod_ess "id-smime-mod-ess"

#define NID_id_smime_mod_ess 197

#define OBJ_id_smime_mod_ess OBJ_id_smime_mod,2L

#define SN_id_smime_mod_oid "id-smime-mod-oid"

#define NID_id_smime_mod_oid 198

#define OBJ_id_smime_mod_oid OBJ_id_smime_mod,3L

#define SN_id_smime_mod_msg_v3 "id-smime-mod-msg-v3"

#define NID_id_smime_mod_msg_v3 199

#define OBJ_id_smime_mod_msg_v3 OBJ_id_smime_mod,4L

#define SN_id_smime_mod_ets_eSignature_88 "id-smime-mod-ets-eSignature-88"

#define NID_id_smime_mod_ets_eSignature_88 200

#define OBJ_id_smime_mod_ets_eSignature_88 OBJ_id_smime_mod,5L

#define SN_id_smime_mod_ets_eSignature_97 "id-smime-mod-ets-eSignature-97"

#define NID_id_smime_mod_ets_eSignature_97 201

#define OBJ_id_smime_mod_ets_eSignature_97 OBJ_id_smime_mod,6L

#define SN_id_smime_mod_ets_eSigPolicy_88 "id-smime-mod-ets-eSigPolicy-88"

#define NID_id_smime_mod_ets_eSigPolicy_88 202

#define OBJ_id_smime_mod_ets_eSigPolicy_88 OBJ_id_smime_mod,7L

#define SN_id_smime_mod_ets_eSigPolicy_97 "id-smime-mod-ets-eSigPolicy-97"

#define NID_id_smime_mod_ets_eSigPolicy_97 203

#define OBJ_id_smime_mod_ets_eSigPolicy_97 OBJ_id_smime_mod,8L

#define SN_id_smime_ct_receipt "id-smime-ct-receipt"

#define NID_id_smime_ct_receipt 204

#define OBJ_id_smime_ct_receipt OBJ_id_smime_ct,1L

#define SN_id_smime_ct_authData "id-smime-ct-authData"

#define NID_id_smime_ct_authData 205

#define OBJ_id_smime_ct_authData OBJ_id_smime_ct,2L

#define SN_id_smime_ct_publishCert "id-smime-ct-publishCert"

#define NID_id_smime_ct_publishCert 206

#define OBJ_id_smime_ct_publishCert OBJ_id_smime_ct,3L

#define SN_id_smime_ct_TSTInfo "id-smime-ct-TSTInfo"

#define NID_id_smime_ct_TSTInfo 207

#define OBJ_id_smime_ct_TSTInfo OBJ_id_smime_ct,4L

#define SN_id_smime_ct_TDTInfo "id-smime-ct-TDTInfo"

#define NID_id_smime_ct_TDTInfo 208

#define OBJ_id_smime_ct_TDTInfo OBJ_id_smime_ct,5L

#define SN_id_smime_ct_contentInfo "id-smime-ct-contentInfo"

#define NID_id_smime_ct_contentInfo 209

#define OBJ_id_smime_ct_contentInfo OBJ_id_smime_ct,6L

#define SN_id_smime_ct_DVCSRequestData "id-smime-ct-DVCSRequestData"

#define NID_id_smime_ct_DVCSRequestData 210

#define OBJ_id_smime_ct_DVCSRequestData OBJ_id_smime_ct,7L

#define SN_id_smime_ct_DVCSResponseData "id-smime-ct-DVCSResponseData"

#define NID_id_smime_ct_DVCSResponseData 211

#define OBJ_id_smime_ct_DVCSResponseData OBJ_id_smime_ct,8L

#define SN_id_smime_ct_compressedData "id-smime-ct-compressedData"

#define NID_id_smime_ct_compressedData 786

#define OBJ_id_smime_ct_compressedData OBJ_id_smime_ct,9L

#define SN_id_smime_ct_contentCollection "id-smime-ct-contentCollection"

#define NID_id_smime_ct_contentCollection 1058

#define OBJ_id_smime_ct_contentCollection OBJ_id_smime_ct,19L

#define SN_id_smime_ct_authEnvelopedData "id-smime-ct-authEnvelopedData"

#define NID_id_smime_ct_authEnvelopedData 1059

#define OBJ_id_smime_ct_authEnvelopedData OBJ_id_smime_ct,23L

#define SN_id_ct_routeOriginAuthz "id-ct-routeOriginAuthz"

#define NID_id_ct_routeOriginAuthz 1234

#define OBJ_id_ct_routeOriginAuthz OBJ_id_smime_ct,24L

#define SN_id_ct_rpkiManifest "id-ct-rpkiManifest"

#define NID_id_ct_rpkiManifest 1235

#define OBJ_id_ct_rpkiManifest OBJ_id_smime_ct,26L

#define SN_id_ct_asciiTextWithCRLF "id-ct-asciiTextWithCRLF"

#define NID_id_ct_asciiTextWithCRLF 787

#define OBJ_id_ct_asciiTextWithCRLF OBJ_id_smime_ct,27L

#define SN_id_ct_xml "id-ct-xml"

#define NID_id_ct_xml 1060

#define OBJ_id_ct_xml OBJ_id_smime_ct,28L

#define SN_id_ct_rpkiGhostbusters "id-ct-rpkiGhostbusters"

#define NID_id_ct_rpkiGhostbusters 1236

#define OBJ_id_ct_rpkiGhostbusters OBJ_id_smime_ct,35L

#define SN_id_ct_resourceTaggedAttest "id-ct-resourceTaggedAttest"

#define NID_id_ct_resourceTaggedAttest 1237

#define OBJ_id_ct_resourceTaggedAttest OBJ_id_smime_ct,36L

#define SN_id_ct_geofeedCSVwithCRLF "id-ct-geofeedCSVwithCRLF"

#define NID_id_ct_geofeedCSVwithCRLF 1246

#define OBJ_id_ct_geofeedCSVwithCRLF OBJ_id_smime_ct,47L

#define SN_id_ct_signedChecklist "id-ct-signedChecklist"

#define NID_id_ct_signedChecklist 1247

#define OBJ_id_ct_signedChecklist OBJ_id_smime_ct,48L

#define SN_id_ct_ASPA "id-ct-ASPA"

#define NID_id_ct_ASPA 1250

#define OBJ_id_ct_ASPA OBJ_id_smime_ct,49L

#define SN_id_ct_signedTAL "id-ct-signedTAL"

#define NID_id_ct_signedTAL 1284

#define OBJ_id_ct_signedTAL OBJ_id_smime_ct,50L

#define SN_id_ct_rpkiSignedPrefixList "id-ct-rpkiSignedPrefixList"

#define NID_id_ct_rpkiSignedPrefixList 1320

#define OBJ_id_ct_rpkiSignedPrefixList OBJ_id_smime_ct,51L

#define SN_id_smime_aa_receiptRequest "id-smime-aa-receiptRequest"

#define NID_id_smime_aa_receiptRequest 212

#define OBJ_id_smime_aa_receiptRequest OBJ_id_smime_aa,1L

#define SN_id_smime_aa_securityLabel "id-smime-aa-securityLabel"

#define NID_id_smime_aa_securityLabel 213

#define OBJ_id_smime_aa_securityLabel OBJ_id_smime_aa,2L

#define SN_id_smime_aa_mlExpandHistory "id-smime-aa-mlExpandHistory"

#define NID_id_smime_aa_mlExpandHistory 214

#define OBJ_id_smime_aa_mlExpandHistory OBJ_id_smime_aa,3L

#define SN_id_smime_aa_contentHint "id-smime-aa-contentHint"

#define NID_id_smime_aa_contentHint 215

#define OBJ_id_smime_aa_contentHint OBJ_id_smime_aa,4L

#define SN_id_smime_aa_msgSigDigest "id-smime-aa-msgSigDigest"

#define NID_id_smime_aa_msgSigDigest 216

#define OBJ_id_smime_aa_msgSigDigest OBJ_id_smime_aa,5L

#define SN_id_smime_aa_encapContentType "id-smime-aa-encapContentType"

#define NID_id_smime_aa_encapContentType 217

#define OBJ_id_smime_aa_encapContentType OBJ_id_smime_aa,6L

#define SN_id_smime_aa_contentIdentifier "id-smime-aa-contentIdentifier"

#define NID_id_smime_aa_contentIdentifier 218

#define OBJ_id_smime_aa_contentIdentifier OBJ_id_smime_aa,7L

#define SN_id_smime_aa_macValue "id-smime-aa-macValue"

#define NID_id_smime_aa_macValue 219

#define OBJ_id_smime_aa_macValue OBJ_id_smime_aa,8L

#define SN_id_smime_aa_equivalentLabels "id-smime-aa-equivalentLabels"

#define NID_id_smime_aa_equivalentLabels 220

#define OBJ_id_smime_aa_equivalentLabels OBJ_id_smime_aa,9L

#define SN_id_smime_aa_contentReference "id-smime-aa-contentReference"

#define NID_id_smime_aa_contentReference 221

#define OBJ_id_smime_aa_contentReference OBJ_id_smime_aa,10L

#define SN_id_smime_aa_encrypKeyPref "id-smime-aa-encrypKeyPref"

#define NID_id_smime_aa_encrypKeyPref 222

#define OBJ_id_smime_aa_encrypKeyPref OBJ_id_smime_aa,11L

#define SN_id_smime_aa_signingCertificate "id-smime-aa-signingCertificate"

#define NID_id_smime_aa_signingCertificate 223

#define OBJ_id_smime_aa_signingCertificate OBJ_id_smime_aa,12L

#define SN_id_smime_aa_smimeEncryptCerts "id-smime-aa-smimeEncryptCerts"

#define NID_id_smime_aa_smimeEncryptCerts 224

#define OBJ_id_smime_aa_smimeEncryptCerts OBJ_id_smime_aa,13L

#define SN_id_smime_aa_timeStampToken "id-smime-aa-timeStampToken"

#define NID_id_smime_aa_timeStampToken 225

#define OBJ_id_smime_aa_timeStampToken OBJ_id_smime_aa,14L

#define SN_id_smime_aa_ets_sigPolicyId "id-smime-aa-ets-sigPolicyId"

#define NID_id_smime_aa_ets_sigPolicyId 226

#define OBJ_id_smime_aa_ets_sigPolicyId OBJ_id_smime_aa,15L

#define SN_id_smime_aa_ets_commitmentType "id-smime-aa-ets-commitmentType"

#define NID_id_smime_aa_ets_commitmentType 227

#define OBJ_id_smime_aa_ets_commitmentType OBJ_id_smime_aa,16L

#define SN_id_smime_aa_ets_signerLocation "id-smime-aa-ets-signerLocation"

#define NID_id_smime_aa_ets_signerLocation 228

#define OBJ_id_smime_aa_ets_signerLocation OBJ_id_smime_aa,17L

#define SN_id_smime_aa_ets_signerAttr "id-smime-aa-ets-signerAttr"

#define NID_id_smime_aa_ets_signerAttr 229

#define OBJ_id_smime_aa_ets_signerAttr OBJ_id_smime_aa,18L

#define SN_id_smime_aa_ets_otherSigCert "id-smime-aa-ets-otherSigCert"

#define NID_id_smime_aa_ets_otherSigCert 230

#define OBJ_id_smime_aa_ets_otherSigCert OBJ_id_smime_aa,19L

#define SN_id_smime_aa_ets_contentTimestamp "id-smime-aa-ets-contentTimestamp"

#define NID_id_smime_aa_ets_contentTimestamp 231

#define OBJ_id_smime_aa_ets_contentTimestamp OBJ_id_smime_aa,20L

#define SN_id_smime_aa_ets_CertificateRefs "id-smime-aa-ets-CertificateRefs"

#define NID_id_smime_aa_ets_CertificateRefs 232

#define OBJ_id_smime_aa_ets_CertificateRefs OBJ_id_smime_aa,21L

#define SN_id_smime_aa_ets_RevocationRefs "id-smime-aa-ets-RevocationRefs"

#define NID_id_smime_aa_ets_RevocationRefs 233

#define OBJ_id_smime_aa_ets_RevocationRefs OBJ_id_smime_aa,22L

#define SN_id_smime_aa_ets_certValues "id-smime-aa-ets-certValues"

#define NID_id_smime_aa_ets_certValues 234

#define OBJ_id_smime_aa_ets_certValues OBJ_id_smime_aa,23L

#define SN_id_smime_aa_ets_revocationValues "id-smime-aa-ets-revocationValues"

#define NID_id_smime_aa_ets_revocationValues 235

#define OBJ_id_smime_aa_ets_revocationValues OBJ_id_smime_aa,24L

#define SN_id_smime_aa_ets_escTimeStamp "id-smime-aa-ets-escTimeStamp"

#define NID_id_smime_aa_ets_escTimeStamp 236

#define OBJ_id_smime_aa_ets_escTimeStamp OBJ_id_smime_aa,25L

#define SN_id_smime_aa_ets_certCRLTimestamp "id-smime-aa-ets-certCRLTimestamp"

#define NID_id_smime_aa_ets_certCRLTimestamp 237

#define OBJ_id_smime_aa_ets_certCRLTimestamp OBJ_id_smime_aa,26L

#define SN_id_smime_aa_ets_archiveTimeStamp "id-smime-aa-ets-archiveTimeStamp"

#define NID_id_smime_aa_ets_archiveTimeStamp 238

#define OBJ_id_smime_aa_ets_archiveTimeStamp OBJ_id_smime_aa,27L

#define SN_id_smime_aa_signatureType "id-smime-aa-signatureType"

#define NID_id_smime_aa_signatureType 239

#define OBJ_id_smime_aa_signatureType OBJ_id_smime_aa,28L

#define SN_id_smime_aa_dvcs_dvc "id-smime-aa-dvcs-dvc"

#define NID_id_smime_aa_dvcs_dvc 240

#define OBJ_id_smime_aa_dvcs_dvc OBJ_id_smime_aa,29L

#define SN_id_aa_ets_attrCertificateRefs "id-aa-ets-attrCertificateRefs"

#define NID_id_aa_ets_attrCertificateRefs 1261

#define OBJ_id_aa_ets_attrCertificateRefs OBJ_id_smime_aa,44L

#define SN_id_aa_ets_attrRevocationRefs "id-aa-ets-attrRevocationRefs"

#define NID_id_aa_ets_attrRevocationRefs 1262

#define OBJ_id_aa_ets_attrRevocationRefs OBJ_id_smime_aa,45L

#define SN_id_smime_aa_signingCertificateV2 "id-smime-aa-signingCertificateV2"

#define NID_id_smime_aa_signingCertificateV2 1086

#define OBJ_id_smime_aa_signingCertificateV2 OBJ_id_smime_aa,47L

#define SN_id_aa_ets_archiveTimestampV2 "id-aa-ets-archiveTimestampV2"

#define NID_id_aa_ets_archiveTimestampV2 1280

#define OBJ_id_aa_ets_archiveTimestampV2 OBJ_id_smime_aa,48L

#define SN_id_smime_alg_ESDHwith3DES "id-smime-alg-ESDHwith3DES"

#define NID_id_smime_alg_ESDHwith3DES 241

#define OBJ_id_smime_alg_ESDHwith3DES OBJ_id_smime_alg,1L

#define SN_id_smime_alg_ESDHwithRC2 "id-smime-alg-ESDHwithRC2"

#define NID_id_smime_alg_ESDHwithRC2 242

#define OBJ_id_smime_alg_ESDHwithRC2 OBJ_id_smime_alg,2L

#define SN_id_smime_alg_3DESwrap "id-smime-alg-3DESwrap"

#define NID_id_smime_alg_3DESwrap 243

#define OBJ_id_smime_alg_3DESwrap OBJ_id_smime_alg,3L

#define SN_id_smime_alg_RC2wrap "id-smime-alg-RC2wrap"

#define NID_id_smime_alg_RC2wrap 244

#define OBJ_id_smime_alg_RC2wrap OBJ_id_smime_alg,4L

#define SN_id_smime_alg_ESDH "id-smime-alg-ESDH"

#define NID_id_smime_alg_ESDH 245

#define OBJ_id_smime_alg_ESDH OBJ_id_smime_alg,5L

#define SN_id_smime_alg_CMS3DESwrap "id-smime-alg-CMS3DESwrap"

#define NID_id_smime_alg_CMS3DESwrap 246

#define OBJ_id_smime_alg_CMS3DESwrap OBJ_id_smime_alg,6L

#define SN_id_smime_alg_CMSRC2wrap "id-smime-alg-CMSRC2wrap"

#define NID_id_smime_alg_CMSRC2wrap 247

#define OBJ_id_smime_alg_CMSRC2wrap OBJ_id_smime_alg,7L

#define SN_id_alg_PWRI_KEK "id-alg-PWRI-KEK"

#define NID_id_alg_PWRI_KEK 893

#define OBJ_id_alg_PWRI_KEK OBJ_id_smime_alg,9L

#define SN_id_smime_cd_ldap "id-smime-cd-ldap"

#define NID_id_smime_cd_ldap 248

#define OBJ_id_smime_cd_ldap OBJ_id_smime_cd,1L

#define SN_id_smime_spq_ets_sqt_uri "id-smime-spq-ets-sqt-uri"

#define NID_id_smime_spq_ets_sqt_uri 249

#define OBJ_id_smime_spq_ets_sqt_uri OBJ_id_smime_spq,1L

#define SN_id_smime_spq_ets_sqt_unotice "id-smime-spq-ets-sqt-unotice"

#define NID_id_smime_spq_ets_sqt_unotice 250

#define OBJ_id_smime_spq_ets_sqt_unotice OBJ_id_smime_spq,2L

#define SN_id_smime_cti_ets_proofOfOrigin "id-smime-cti-ets-proofOfOrigin"

#define NID_id_smime_cti_ets_proofOfOrigin 251

#define OBJ_id_smime_cti_ets_proofOfOrigin OBJ_id_smime_cti,1L

#define SN_id_smime_cti_ets_proofOfReceipt "id-smime-cti-ets-proofOfReceipt"

#define NID_id_smime_cti_ets_proofOfReceipt 252

#define OBJ_id_smime_cti_ets_proofOfReceipt OBJ_id_smime_cti,2L

#define SN_id_smime_cti_ets_proofOfDelivery "id-smime-cti-ets-proofOfDelivery"

#define NID_id_smime_cti_ets_proofOfDelivery 253

#define OBJ_id_smime_cti_ets_proofOfDelivery OBJ_id_smime_cti,3L

#define SN_id_smime_cti_ets_proofOfSender "id-smime-cti-ets-proofOfSender"

#define NID_id_smime_cti_ets_proofOfSender 254

#define OBJ_id_smime_cti_ets_proofOfSender OBJ_id_smime_cti,4L

#define SN_id_smime_cti_ets_proofOfApproval "id-smime-cti-ets-proofOfApproval"

#define NID_id_smime_cti_ets_proofOfApproval 255

#define OBJ_id_smime_cti_ets_proofOfApproval OBJ_id_smime_cti,5L

#define SN_id_smime_cti_ets_proofOfCreation "id-smime-cti-ets-proofOfCreation"

#define NID_id_smime_cti_ets_proofOfCreation 256

#define OBJ_id_smime_cti_ets_proofOfCreation OBJ_id_smime_cti,6L

#define LN_friendlyName "friendlyName"

#define NID_friendlyName 156

#define OBJ_friendlyName OBJ_pkcs9,20L

#define LN_localKeyID "localKeyID"

#define NID_localKeyID 157

#define OBJ_localKeyID OBJ_pkcs9,21L

#define OBJ_ms_corp 1L,3L,6L,1L,4L,1L,311L

#define SN_ms_csp_name "CSPName"

#define LN_ms_csp_name "Microsoft CSP Name"

#define NID_ms_csp_name 417

#define OBJ_ms_csp_name OBJ_ms_corp,17L,1L

#define SN_LocalKeySet "LocalKeySet"

#define LN_LocalKeySet "Microsoft Local Key set"

#define NID_LocalKeySet 856

#define OBJ_LocalKeySet OBJ_ms_corp,17L,2L

#define OBJ_certTypes OBJ_pkcs9,22L

#define LN_x509Certificate "x509Certificate"

#define NID_x509Certificate 158

#define OBJ_x509Certificate OBJ_certTypes,1L

#define LN_sdsiCertificate "sdsiCertificate"

#define NID_sdsiCertificate 159

#define OBJ_sdsiCertificate OBJ_certTypes,2L

#define OBJ_crlTypes OBJ_pkcs9,23L

#define LN_x509Crl "x509Crl"

#define NID_x509Crl 160

#define OBJ_x509Crl OBJ_crlTypes,1L

#define SN_id_aa_CMSAlgorithmProtection "id-aa-CMSAlgorithmProtection"

#define NID_id_aa_CMSAlgorithmProtection 1263

#define OBJ_id_aa_CMSAlgorithmProtection OBJ_pkcs9,52L

#define OBJ_pkcs12 OBJ_pkcs,12L

#define OBJ_pkcs12_pbeids OBJ_pkcs12,1L

#define SN_pbe_WithSHA1And128BitRC4 "PBE-SHA1-RC4-128"

#define LN_pbe_WithSHA1And128BitRC4 "pbeWithSHA1And128BitRC4"

#define NID_pbe_WithSHA1And128BitRC4 144

#define OBJ_pbe_WithSHA1And128BitRC4 OBJ_pkcs12_pbeids,1L

#define SN_pbe_WithSHA1And40BitRC4 "PBE-SHA1-RC4-40"

#define LN_pbe_WithSHA1And40BitRC4 "pbeWithSHA1And40BitRC4"

#define NID_pbe_WithSHA1And40BitRC4 145

#define OBJ_pbe_WithSHA1And40BitRC4 OBJ_pkcs12_pbeids,2L

#define SN_pbe_WithSHA1And3_Key_TripleDES_CBC "PBE-SHA1-3DES"

#define LN_pbe_WithSHA1And3_Key_TripleDES_CBC "pbeWithSHA1And3-KeyTripleDES-CBC"

#define NID_pbe_WithSHA1And3_Key_TripleDES_CBC 146

#define OBJ_pbe_WithSHA1And3_Key_TripleDES_CBC OBJ_pkcs12_pbeids,3L

#define SN_pbe_WithSHA1And2_Key_TripleDES_CBC "PBE-SHA1-2DES"

#define LN_pbe_WithSHA1And2_Key_TripleDES_CBC "pbeWithSHA1And2-KeyTripleDES-CBC"

#define NID_pbe_WithSHA1And2_Key_TripleDES_CBC 147

#define OBJ_pbe_WithSHA1And2_Key_TripleDES_CBC OBJ_pkcs12_pbeids,4L

#define SN_pbe_WithSHA1And128BitRC2_CBC "PBE-SHA1-RC2-128"

#define LN_pbe_WithSHA1And128BitRC2_CBC "pbeWithSHA1And128BitRC2-CBC"

#define NID_pbe_WithSHA1And128BitRC2_CBC 148

#define OBJ_pbe_WithSHA1And128BitRC2_CBC OBJ_pkcs12_pbeids,5L

#define SN_pbe_WithSHA1And40BitRC2_CBC "PBE-SHA1-RC2-40"

#define LN_pbe_WithSHA1And40BitRC2_CBC "pbeWithSHA1And40BitRC2-CBC"

#define NID_pbe_WithSHA1And40BitRC2_CBC 149

#define OBJ_pbe_WithSHA1And40BitRC2_CBC OBJ_pkcs12_pbeids,6L

#define OBJ_pkcs12_Version1 OBJ_pkcs12,10L

#define OBJ_pkcs12_BagIds OBJ_pkcs12_Version1,1L

#define LN_keyBag "keyBag"

#define NID_keyBag 150

#define OBJ_keyBag OBJ_pkcs12_BagIds,1L

#define LN_pkcs8ShroudedKeyBag "pkcs8ShroudedKeyBag"

#define NID_pkcs8ShroudedKeyBag 151

#define OBJ_pkcs8ShroudedKeyBag OBJ_pkcs12_BagIds,2L

#define LN_certBag "certBag"

#define NID_certBag 152

#define OBJ_certBag OBJ_pkcs12_BagIds,3L

#define LN_crlBag "crlBag"

#define NID_crlBag 153

#define OBJ_crlBag OBJ_pkcs12_BagIds,4L

#define LN_secretBag "secretBag"

#define NID_secretBag 154

#define OBJ_secretBag OBJ_pkcs12_BagIds,5L

#define LN_safeContentsBag "safeContentsBag"

#define NID_safeContentsBag 155

#define OBJ_safeContentsBag OBJ_pkcs12_BagIds,6L

#define SN_md2 "MD2"

#define LN_md2 "md2"

#define NID_md2 3

#define OBJ_md2 OBJ_rsadsi,2L,2L

#define SN_md4 "MD4"

#define LN_md4 "md4"

#define NID_md4 257

#define OBJ_md4 OBJ_rsadsi,2L,4L

#define SN_md5 "MD5"

#define LN_md5 "md5"

#define NID_md5 4

#define OBJ_md5 OBJ_rsadsi,2L,5L

#define SN_md5_sha1 "MD5-SHA1"

#define LN_md5_sha1 "md5-sha1"

#define NID_md5_sha1 114

#define LN_hmacWithMD5 "hmacWithMD5"

#define NID_hmacWithMD5 797

#define OBJ_hmacWithMD5 OBJ_rsadsi,2L,6L

#define LN_hmacWithSHA1 "hmacWithSHA1"

#define NID_hmacWithSHA1 163

#define OBJ_hmacWithSHA1 OBJ_rsadsi,2L,7L

#define SN_sm2 "SM2"

#define LN_sm2 "sm2"

#define NID_sm2 1172

#define OBJ_sm2 OBJ_sm_scheme,301L

#define SN_sm3 "SM3"

#define LN_sm3 "sm3"

#define NID_sm3 1143

#define OBJ_sm3 OBJ_sm_scheme,401L

#define SN_sm3WithRSAEncryption "RSA-SM3"

#define LN_sm3WithRSAEncryption "sm3WithRSAEncryption"

#define NID_sm3WithRSAEncryption 1144

#define OBJ_sm3WithRSAEncryption OBJ_sm_scheme,504L

#define SN_SM2_with_SM3 "SM2-SM3"

#define LN_SM2_with_SM3 "SM2-with-SM3"

#define NID_SM2_with_SM3 1204

#define OBJ_SM2_with_SM3 OBJ_sm_scheme,501L

#define LN_hmacWithSM3 "hmacWithSM3"

#define NID_hmacWithSM3 1281

#define OBJ_hmacWithSM3 OBJ_sm3,3L,1L

#define LN_hmacWithSHA224 "hmacWithSHA224"

#define NID_hmacWithSHA224 798

#define OBJ_hmacWithSHA224 OBJ_rsadsi,2L,8L

#define LN_hmacWithSHA256 "hmacWithSHA256"

#define NID_hmacWithSHA256 799

#define OBJ_hmacWithSHA256 OBJ_rsadsi,2L,9L

#define LN_hmacWithSHA384 "hmacWithSHA384"

#define NID_hmacWithSHA384 800

#define OBJ_hmacWithSHA384 OBJ_rsadsi,2L,10L

#define LN_hmacWithSHA512 "hmacWithSHA512"

#define NID_hmacWithSHA512 801

#define OBJ_hmacWithSHA512 OBJ_rsadsi,2L,11L

#define LN_hmacWithSHA512_224 "hmacWithSHA512-224"

#define NID_hmacWithSHA512_224 1193

#define OBJ_hmacWithSHA512_224 OBJ_rsadsi,2L,12L

#define LN_hmacWithSHA512_256 "hmacWithSHA512-256"

#define NID_hmacWithSHA512_256 1194

#define OBJ_hmacWithSHA512_256 OBJ_rsadsi,2L,13L

#define SN_rc2_cbc "RC2-CBC"

#define LN_rc2_cbc "rc2-cbc"

#define NID_rc2_cbc 37

#define OBJ_rc2_cbc OBJ_rsadsi,3L,2L

#define SN_rc2_ecb "RC2-ECB"

#define LN_rc2_ecb "rc2-ecb"

#define NID_rc2_ecb 38

#define SN_rc2_cfb64 "RC2-CFB"

#define LN_rc2_cfb64 "rc2-cfb"

#define NID_rc2_cfb64 39

#define SN_rc2_ofb64 "RC2-OFB"

#define LN_rc2_ofb64 "rc2-ofb"

#define NID_rc2_ofb64 40

#define SN_rc2_40_cbc "RC2-40-CBC"

#define LN_rc2_40_cbc "rc2-40-cbc"

#define NID_rc2_40_cbc 98

#define SN_rc2_64_cbc "RC2-64-CBC"

#define LN_rc2_64_cbc "rc2-64-cbc"

#define NID_rc2_64_cbc 166

#define SN_rc4 "RC4"

#define LN_rc4 "rc4"

#define NID_rc4 5

#define OBJ_rc4 OBJ_rsadsi,3L,4L

#define SN_rc4_40 "RC4-40"

#define LN_rc4_40 "rc4-40"

#define NID_rc4_40 97

#define SN_des_ede3_cbc "DES-EDE3-CBC"

#define LN_des_ede3_cbc "des-ede3-cbc"

#define NID_des_ede3_cbc 44

#define OBJ_des_ede3_cbc OBJ_rsadsi,3L,7L

#define SN_rc5_cbc "RC5-CBC"

#define LN_rc5_cbc "rc5-cbc"

#define NID_rc5_cbc 120

#define OBJ_rc5_cbc OBJ_rsadsi,3L,8L

#define SN_rc5_ecb "RC5-ECB"

#define LN_rc5_ecb "rc5-ecb"

#define NID_rc5_ecb 121

#define SN_rc5_cfb64 "RC5-CFB"

#define LN_rc5_cfb64 "rc5-cfb"

#define NID_rc5_cfb64 122

#define SN_rc5_ofb64 "RC5-OFB"

#define LN_rc5_ofb64 "rc5-ofb"

#define NID_rc5_ofb64 123

#define SN_ms_ext_req "msExtReq"

#define LN_ms_ext_req "Microsoft Extension Request"

#define NID_ms_ext_req 171

#define OBJ_ms_ext_req OBJ_ms_corp,2L,1L,14L

#define SN_ms_code_ind "msCodeInd"

#define LN_ms_code_ind "Microsoft Individual Code Signing"

#define NID_ms_code_ind 134

#define OBJ_ms_code_ind OBJ_ms_corp,2L,1L,21L

#define SN_ms_code_com "msCodeCom"

#define LN_ms_code_com "Microsoft Commercial Code Signing"

#define NID_ms_code_com 135

#define OBJ_ms_code_com OBJ_ms_corp,2L,1L,22L

#define SN_ms_ctl_sign "msCTLSign"

#define LN_ms_ctl_sign "Microsoft Trust List Signing"

#define NID_ms_ctl_sign 136

#define OBJ_ms_ctl_sign OBJ_ms_corp,10L,3L,1L

#define SN_ms_sgc "msSGC"

#define LN_ms_sgc "Microsoft Server Gated Crypto"

#define NID_ms_sgc 137

#define OBJ_ms_sgc OBJ_ms_corp,10L,3L,3L

#define SN_ms_efs "msEFS"

#define LN_ms_efs "Microsoft Encrypted File System"

#define NID_ms_efs 138

#define OBJ_ms_efs OBJ_ms_corp,10L,3L,4L

#define SN_ms_smartcard_login "msSmartcardLogin"

#define LN_ms_smartcard_login "Microsoft Smartcard Login"

#define NID_ms_smartcard_login 648

#define OBJ_ms_smartcard_login OBJ_ms_corp,20L,2L,2L

#define SN_ms_upn "msUPN"

#define LN_ms_upn "Microsoft User Principal Name"

#define NID_ms_upn 649

#define OBJ_ms_upn OBJ_ms_corp,20L,2L,3L

#define SN_ms_ntds_sec_ext "ms-ntds-sec-ext"

#define LN_ms_ntds_sec_ext "Microsoft NTDS CA Extension"

#define NID_ms_ntds_sec_ext 1292

#define OBJ_ms_ntds_sec_ext OBJ_ms_corp,25L,2L

#define SN_ms_ntds_obj_sid "ms-ntds-obj-sid"

#define LN_ms_ntds_obj_sid "Microsoft NTDS AD objectSid"

#define NID_ms_ntds_obj_sid 1291

#define OBJ_ms_ntds_obj_sid OBJ_ms_corp,25L,2L,1L

#define SN_ms_cert_templ "ms-cert-templ"

#define LN_ms_cert_templ "Microsoft certificate template"

#define NID_ms_cert_templ 1293

#define OBJ_ms_cert_templ OBJ_ms_corp,21L,7L

#define SN_ms_app_policies "ms-app-policies"

#define LN_ms_app_policies "Microsoft Application Policies Extension"

#define NID_ms_app_policies 1294

#define OBJ_ms_app_policies OBJ_ms_corp,21L,10L

#define SN_idea_cbc "IDEA-CBC"

#define LN_idea_cbc "idea-cbc"

#define NID_idea_cbc 34

#define OBJ_idea_cbc 1L,3L,6L,1L,4L,1L,188L,7L,1L,1L,2L

#define SN_idea_ecb "IDEA-ECB"

#define LN_idea_ecb "idea-ecb"

#define NID_idea_ecb 36

#define SN_idea_cfb64 "IDEA-CFB"

#define LN_idea_cfb64 "idea-cfb"

#define NID_idea_cfb64 35

#define SN_idea_ofb64 "IDEA-OFB"

#define LN_idea_ofb64 "idea-ofb"

#define NID_idea_ofb64 46

#define SN_bf_cbc "BF-CBC"

#define LN_bf_cbc "bf-cbc"

#define NID_bf_cbc 91

#define OBJ_bf_cbc 1L,3L,6L,1L,4L,1L,3029L,1L,2L

#define SN_bf_ecb "BF-ECB"

#define LN_bf_ecb "bf-ecb"

#define NID_bf_ecb 92

#define SN_bf_cfb64 "BF-CFB"

#define LN_bf_cfb64 "bf-cfb"

#define NID_bf_cfb64 93

#define SN_bf_ofb64 "BF-OFB"

#define LN_bf_ofb64 "bf-ofb"

#define NID_bf_ofb64 94

#define SN_id_pkix "PKIX"

#define NID_id_pkix 127

#define OBJ_id_pkix 1L,3L,6L,1L,5L,5L,7L

#define SN_id_pkix_mod "id-pkix-mod"

#define NID_id_pkix_mod 258

#define OBJ_id_pkix_mod OBJ_id_pkix,0L

#define SN_id_pe "id-pe"

#define NID_id_pe 175

#define OBJ_id_pe OBJ_id_pkix,1L

#define SN_id_qt "id-qt"

#define NID_id_qt 259

#define OBJ_id_qt OBJ_id_pkix,2L

#define SN_id_kp "id-kp"

#define NID_id_kp 128

#define OBJ_id_kp OBJ_id_pkix,3L

#define SN_id_it "id-it"

#define NID_id_it 260

#define OBJ_id_it OBJ_id_pkix,4L

#define SN_id_pkip "id-pkip"

#define NID_id_pkip 261

#define OBJ_id_pkip OBJ_id_pkix,5L

#define SN_id_alg "id-alg"

#define NID_id_alg 262

#define OBJ_id_alg OBJ_id_pkix,6L

#define SN_id_cmc "id-cmc"

#define NID_id_cmc 263

#define OBJ_id_cmc OBJ_id_pkix,7L

#define SN_id_on "id-on"

#define NID_id_on 264

#define OBJ_id_on OBJ_id_pkix,8L

#define SN_id_pda "id-pda"

#define NID_id_pda 265

#define OBJ_id_pda OBJ_id_pkix,9L

#define SN_id_aca "id-aca"

#define NID_id_aca 266

#define OBJ_id_aca OBJ_id_pkix,10L

#define SN_id_qcs "id-qcs"

#define NID_id_qcs 267

#define OBJ_id_qcs OBJ_id_pkix,11L

#define SN_id_cp "id-cp"

#define NID_id_cp 1238

#define OBJ_id_cp OBJ_id_pkix,14L

#define SN_id_cct "id-cct"

#define NID_id_cct 268

#define OBJ_id_cct OBJ_id_pkix,12L

#define SN_id_ppl "id-ppl"

#define NID_id_ppl 662

#define OBJ_id_ppl OBJ_id_pkix,21L

#define SN_id_ad "id-ad"

#define NID_id_ad 176

#define OBJ_id_ad OBJ_id_pkix,48L

#define SN_id_pkix1_explicit_88 "id-pkix1-explicit-88"

#define NID_id_pkix1_explicit_88 269

#define OBJ_id_pkix1_explicit_88 OBJ_id_pkix_mod,1L

#define SN_id_pkix1_implicit_88 "id-pkix1-implicit-88"

#define NID_id_pkix1_implicit_88 270

#define OBJ_id_pkix1_implicit_88 OBJ_id_pkix_mod,2L

#define SN_id_pkix1_explicit_93 "id-pkix1-explicit-93"

#define NID_id_pkix1_explicit_93 271

#define OBJ_id_pkix1_explicit_93 OBJ_id_pkix_mod,3L

#define SN_id_pkix1_implicit_93 "id-pkix1-implicit-93"

#define NID_id_pkix1_implicit_93 272

#define OBJ_id_pkix1_implicit_93 OBJ_id_pkix_mod,4L

#define SN_id_mod_crmf "id-mod-crmf"

#define NID_id_mod_crmf 273

#define OBJ_id_mod_crmf OBJ_id_pkix_mod,5L

#define SN_id_mod_cmc "id-mod-cmc"

#define NID_id_mod_cmc 274

#define OBJ_id_mod_cmc OBJ_id_pkix_mod,6L

#define SN_id_mod_kea_profile_88 "id-mod-kea-profile-88"

#define NID_id_mod_kea_profile_88 275

#define OBJ_id_mod_kea_profile_88 OBJ_id_pkix_mod,7L

#define SN_id_mod_kea_profile_93 "id-mod-kea-profile-93"

#define NID_id_mod_kea_profile_93 276

#define OBJ_id_mod_kea_profile_93 OBJ_id_pkix_mod,8L

#define SN_id_mod_cmp "id-mod-cmp"

#define NID_id_mod_cmp 277

#define OBJ_id_mod_cmp OBJ_id_pkix_mod,9L

#define SN_id_mod_qualified_cert_88 "id-mod-qualified-cert-88"

#define NID_id_mod_qualified_cert_88 278

#define OBJ_id_mod_qualified_cert_88 OBJ_id_pkix_mod,10L

#define SN_id_mod_qualified_cert_93 "id-mod-qualified-cert-93"

#define NID_id_mod_qualified_cert_93 279

#define OBJ_id_mod_qualified_cert_93 OBJ_id_pkix_mod,11L

#define SN_id_mod_attribute_cert "id-mod-attribute-cert"

#define NID_id_mod_attribute_cert 280

#define OBJ_id_mod_attribute_cert OBJ_id_pkix_mod,12L

#define SN_id_mod_timestamp_protocol "id-mod-timestamp-protocol"

#define NID_id_mod_timestamp_protocol 281

#define OBJ_id_mod_timestamp_protocol OBJ_id_pkix_mod,13L

#define SN_id_mod_ocsp "id-mod-ocsp"

#define NID_id_mod_ocsp 282

#define OBJ_id_mod_ocsp OBJ_id_pkix_mod,14L

#define SN_id_mod_dvcs "id-mod-dvcs"

#define NID_id_mod_dvcs 283

#define OBJ_id_mod_dvcs OBJ_id_pkix_mod,15L

#define SN_id_mod_cmp2000 "id-mod-cmp2000"

#define NID_id_mod_cmp2000 284

#define OBJ_id_mod_cmp2000 OBJ_id_pkix_mod,16L

#define SN_id_mod_cmp2000_02 "id-mod-cmp2000-02"

#define NID_id_mod_cmp2000_02 1251

#define OBJ_id_mod_cmp2000_02 OBJ_id_pkix_mod,50L

#define SN_id_mod_cmp2021_88 "id-mod-cmp2021-88"

#define NID_id_mod_cmp2021_88 1252

#define OBJ_id_mod_cmp2021_88 OBJ_id_pkix_mod,99L

#define SN_id_mod_cmp2021_02 "id-mod-cmp2021-02"

#define NID_id_mod_cmp2021_02 1253

#define OBJ_id_mod_cmp2021_02 OBJ_id_pkix_mod,100L

#define SN_info_access "authorityInfoAccess"

#define LN_info_access "Authority Information Access"

#define NID_info_access 177

#define OBJ_info_access OBJ_id_pe,1L

#define SN_biometricInfo "biometricInfo"

#define LN_biometricInfo "Biometric Info"

#define NID_biometricInfo 285

#define OBJ_biometricInfo OBJ_id_pe,2L

#define SN_qcStatements "qcStatements"

#define NID_qcStatements 286

#define OBJ_qcStatements OBJ_id_pe,3L

#define SN_ac_auditEntity "ac-auditEntity"

#define NID_ac_auditEntity 287

#define OBJ_ac_auditEntity OBJ_id_pe,4L

#define SN_ac_targeting "ac-targeting"

#define NID_ac_targeting 288

#define OBJ_ac_targeting OBJ_id_pe,5L

#define SN_aaControls "aaControls"

#define NID_aaControls 289

#define OBJ_aaControls OBJ_id_pe,6L

#define SN_sbgp_ipAddrBlock "sbgp-ipAddrBlock"

#define NID_sbgp_ipAddrBlock 290

#define OBJ_sbgp_ipAddrBlock OBJ_id_pe,7L

#define SN_sbgp_autonomousSysNum "sbgp-autonomousSysNum"

#define NID_sbgp_autonomousSysNum 291

#define OBJ_sbgp_autonomousSysNum OBJ_id_pe,8L

#define SN_sbgp_routerIdentifier "sbgp-routerIdentifier"

#define NID_sbgp_routerIdentifier 292

#define OBJ_sbgp_routerIdentifier OBJ_id_pe,9L

#define SN_ac_proxying "ac-proxying"

#define NID_ac_proxying 397

#define OBJ_ac_proxying OBJ_id_pe,10L

#define SN_sinfo_access "subjectInfoAccess"

#define LN_sinfo_access "Subject Information Access"

#define NID_sinfo_access 398

#define OBJ_sinfo_access OBJ_id_pe,11L

#define SN_proxyCertInfo "proxyCertInfo"

#define LN_proxyCertInfo "Proxy Certificate Information"

#define NID_proxyCertInfo 663

#define OBJ_proxyCertInfo OBJ_id_pe,14L

#define SN_tlsfeature "tlsfeature"

#define LN_tlsfeature "TLS Feature"

#define NID_tlsfeature 1020

#define OBJ_tlsfeature OBJ_id_pe,24L

#define SN_sbgp_ipAddrBlockv2 "sbgp-ipAddrBlockv2"

#define NID_sbgp_ipAddrBlockv2 1239

#define OBJ_sbgp_ipAddrBlockv2 OBJ_id_pe,28L

#define SN_sbgp_autonomousSysNumv2 "sbgp-autonomousSysNumv2"

#define NID_sbgp_autonomousSysNumv2 1240

#define OBJ_sbgp_autonomousSysNumv2 OBJ_id_pe,29L

#define SN_id_qt_cps "id-qt-cps"

#define LN_id_qt_cps "Policy Qualifier CPS"

#define NID_id_qt_cps 164

#define OBJ_id_qt_cps OBJ_id_qt,1L

#define SN_id_qt_unotice "id-qt-unotice"

#define LN_id_qt_unotice "Policy Qualifier User Notice"

#define NID_id_qt_unotice 165

#define OBJ_id_qt_unotice OBJ_id_qt,2L

#define SN_textNotice "textNotice"

#define NID_textNotice 293

#define OBJ_textNotice OBJ_id_qt,3L

#define SN_server_auth "serverAuth"

#define LN_server_auth "TLS Web Server Authentication"

#define NID_server_auth 129

#define OBJ_server_auth OBJ_id_kp,1L

#define SN_client_auth "clientAuth"

#define LN_client_auth "TLS Web Client Authentication"

#define NID_client_auth 130

#define OBJ_client_auth OBJ_id_kp,2L

#define SN_code_sign "codeSigning"

#define LN_code_sign "Code Signing"

#define NID_code_sign 131

#define OBJ_code_sign OBJ_id_kp,3L

#define SN_email_protect "emailProtection"

#define LN_email_protect "E-mail Protection"

#define NID_email_protect 132

#define OBJ_email_protect OBJ_id_kp,4L

#define SN_ipsecEndSystem "ipsecEndSystem"

#define LN_ipsecEndSystem "IPSec End System"

#define NID_ipsecEndSystem 294

#define OBJ_ipsecEndSystem OBJ_id_kp,5L

#define SN_ipsecTunnel "ipsecTunnel"

#define LN_ipsecTunnel "IPSec Tunnel"

#define NID_ipsecTunnel 295

#define OBJ_ipsecTunnel OBJ_id_kp,6L

#define SN_ipsecUser "ipsecUser"

#define LN_ipsecUser "IPSec User"

#define NID_ipsecUser 296

#define OBJ_ipsecUser OBJ_id_kp,7L

#define SN_time_stamp "timeStamping"

#define LN_time_stamp "Time Stamping"

#define NID_time_stamp 133

#define OBJ_time_stamp OBJ_id_kp,8L

#define SN_OCSP_sign "OCSPSigning"

#define LN_OCSP_sign "OCSP Signing"

#define NID_OCSP_sign 180

#define OBJ_OCSP_sign OBJ_id_kp,9L

#define SN_dvcs "DVCS"

#define LN_dvcs "dvcs"

#define NID_dvcs 297

#define OBJ_dvcs OBJ_id_kp,10L

#define SN_ipsec_IKE "ipsecIKE"

#define LN_ipsec_IKE "ipsec Internet Key Exchange"

#define NID_ipsec_IKE 1022

#define OBJ_ipsec_IKE OBJ_id_kp,17L

#define SN_capwapAC "capwapAC"

#define LN_capwapAC "Ctrl/provision WAP Access"

#define NID_capwapAC 1023

#define OBJ_capwapAC OBJ_id_kp,18L

#define SN_capwapWTP "capwapWTP"

#define LN_capwapWTP "Ctrl/Provision WAP Termination"

#define NID_capwapWTP 1024

#define OBJ_capwapWTP OBJ_id_kp,19L

#define SN_sshClient "secureShellClient"

#define LN_sshClient "SSH Client"

#define NID_sshClient 1025

#define OBJ_sshClient OBJ_id_kp,21L

#define SN_sshServer "secureShellServer"

#define LN_sshServer "SSH Server"

#define NID_sshServer 1026

#define OBJ_sshServer OBJ_id_kp,22L

#define SN_sendRouter "sendRouter"

#define LN_sendRouter "Send Router"

#define NID_sendRouter 1027

#define OBJ_sendRouter OBJ_id_kp,23L

#define SN_sendProxiedRouter "sendProxiedRouter"

#define LN_sendProxiedRouter "Send Proxied Router"

#define NID_sendProxiedRouter 1028

#define OBJ_sendProxiedRouter OBJ_id_kp,24L

#define SN_sendOwner "sendOwner"

#define LN_sendOwner "Send Owner"

#define NID_sendOwner 1029

#define OBJ_sendOwner OBJ_id_kp,25L

#define SN_sendProxiedOwner "sendProxiedOwner"

#define LN_sendProxiedOwner "Send Proxied Owner"

#define NID_sendProxiedOwner 1030

#define OBJ_sendProxiedOwner OBJ_id_kp,26L

#define SN_cmcCA "cmcCA"

#define LN_cmcCA "CMC Certificate Authority"

#define NID_cmcCA 1131

#define OBJ_cmcCA OBJ_id_kp,27L

#define SN_cmcRA "cmcRA"

#define LN_cmcRA "CMC Registration Authority"

#define NID_cmcRA 1132

#define OBJ_cmcRA OBJ_id_kp,28L

#define SN_cmcArchive "cmcArchive"

#define LN_cmcArchive "CMC Archive Server"

#define NID_cmcArchive 1219

#define OBJ_cmcArchive OBJ_id_kp,29L

#define SN_id_kp_bgpsec_router "id-kp-bgpsec-router"

#define LN_id_kp_bgpsec_router "BGPsec Router"

#define NID_id_kp_bgpsec_router 1220

#define OBJ_id_kp_bgpsec_router OBJ_id_kp,30L

#define SN_id_kp_BrandIndicatorforMessageIdentification "id-kp-BrandIndicatorforMessageIdentification"

#define LN_id_kp_BrandIndicatorforMessageIdentification "Brand Indicator for Message Identification"

#define NID_id_kp_BrandIndicatorforMessageIdentification 1221

#define OBJ_id_kp_BrandIndicatorforMessageIdentification OBJ_id_kp,31L

#define SN_cmKGA "cmKGA"

#define LN_cmKGA "Certificate Management Key Generation Authority"

#define NID_cmKGA 1222

#define OBJ_cmKGA OBJ_id_kp,32L

#define SN_id_it_caProtEncCert "id-it-caProtEncCert"

#define NID_id_it_caProtEncCert 298

#define OBJ_id_it_caProtEncCert OBJ_id_it,1L

#define SN_id_it_signKeyPairTypes "id-it-signKeyPairTypes"

#define NID_id_it_signKeyPairTypes 299

#define OBJ_id_it_signKeyPairTypes OBJ_id_it,2L

#define SN_id_it_encKeyPairTypes "id-it-encKeyPairTypes"

#define NID_id_it_encKeyPairTypes 300

#define OBJ_id_it_encKeyPairTypes OBJ_id_it,3L

#define SN_id_it_preferredSymmAlg "id-it-preferredSymmAlg"

#define NID_id_it_preferredSymmAlg 301

#define OBJ_id_it_preferredSymmAlg OBJ_id_it,4L

#define SN_id_it_caKeyUpdateInfo "id-it-caKeyUpdateInfo"

#define NID_id_it_caKeyUpdateInfo 302

#define OBJ_id_it_caKeyUpdateInfo OBJ_id_it,5L

#define SN_id_it_currentCRL "id-it-currentCRL"

#define NID_id_it_currentCRL 303

#define OBJ_id_it_currentCRL OBJ_id_it,6L

#define SN_id_it_unsupportedOIDs "id-it-unsupportedOIDs"

#define NID_id_it_unsupportedOIDs 304

#define OBJ_id_it_unsupportedOIDs OBJ_id_it,7L

#define SN_id_it_subscriptionRequest "id-it-subscriptionRequest"

#define NID_id_it_subscriptionRequest 305

#define OBJ_id_it_subscriptionRequest OBJ_id_it,8L

#define SN_id_it_subscriptionResponse "id-it-subscriptionResponse"

#define NID_id_it_subscriptionResponse 306

#define OBJ_id_it_subscriptionResponse OBJ_id_it,9L

#define SN_id_it_keyPairParamReq "id-it-keyPairParamReq"

#define NID_id_it_keyPairParamReq 307

#define OBJ_id_it_keyPairParamReq OBJ_id_it,10L

#define SN_id_it_keyPairParamRep "id-it-keyPairParamRep"

#define NID_id_it_keyPairParamRep 308

#define OBJ_id_it_keyPairParamRep OBJ_id_it,11L

#define SN_id_it_revPassphrase "id-it-revPassphrase"

#define NID_id_it_revPassphrase 309

#define OBJ_id_it_revPassphrase OBJ_id_it,12L

#define SN_id_it_implicitConfirm "id-it-implicitConfirm"

#define NID_id_it_implicitConfirm 310

#define OBJ_id_it_implicitConfirm OBJ_id_it,13L

#define SN_id_it_confirmWaitTime "id-it-confirmWaitTime"

#define NID_id_it_confirmWaitTime 311

#define OBJ_id_it_confirmWaitTime OBJ_id_it,14L

#define SN_id_it_origPKIMessage "id-it-origPKIMessage"

#define NID_id_it_origPKIMessage 312

#define OBJ_id_it_origPKIMessage OBJ_id_it,15L

#define SN_id_it_suppLangTags "id-it-suppLangTags"

#define NID_id_it_suppLangTags 784

#define OBJ_id_it_suppLangTags OBJ_id_it,16L

#define SN_id_it_caCerts "id-it-caCerts"

#define NID_id_it_caCerts 1223

#define OBJ_id_it_caCerts OBJ_id_it,17L

#define SN_id_it_rootCaKeyUpdate "id-it-rootCaKeyUpdate"

#define NID_id_it_rootCaKeyUpdate 1224

#define OBJ_id_it_rootCaKeyUpdate OBJ_id_it,18L

#define SN_id_it_certReqTemplate "id-it-certReqTemplate"

#define NID_id_it_certReqTemplate 1225

#define OBJ_id_it_certReqTemplate OBJ_id_it,19L

#define SN_id_it_rootCaCert "id-it-rootCaCert"

#define NID_id_it_rootCaCert 1254

#define OBJ_id_it_rootCaCert OBJ_id_it,20L

#define SN_id_it_certProfile "id-it-certProfile"

#define NID_id_it_certProfile 1255

#define OBJ_id_it_certProfile OBJ_id_it,21L

#define SN_id_it_crlStatusList "id-it-crlStatusList"

#define NID_id_it_crlStatusList 1256

#define OBJ_id_it_crlStatusList OBJ_id_it,22L

#define SN_id_it_crls "id-it-crls"

#define NID_id_it_crls 1257

#define OBJ_id_it_crls OBJ_id_it,23L

#define SN_id_regCtrl "id-regCtrl"

#define NID_id_regCtrl 313

#define OBJ_id_regCtrl OBJ_id_pkip,1L

#define SN_id_regInfo "id-regInfo"

#define NID_id_regInfo 314

#define OBJ_id_regInfo OBJ_id_pkip,2L

#define SN_id_regCtrl_regToken "id-regCtrl-regToken"

#define NID_id_regCtrl_regToken 315

#define OBJ_id_regCtrl_regToken OBJ_id_regCtrl,1L

#define SN_id_regCtrl_authenticator "id-regCtrl-authenticator"

#define NID_id_regCtrl_authenticator 316

#define OBJ_id_regCtrl_authenticator OBJ_id_regCtrl,2L

#define SN_id_regCtrl_pkiPublicationInfo "id-regCtrl-pkiPublicationInfo"

#define NID_id_regCtrl_pkiPublicationInfo 317

#define OBJ_id_regCtrl_pkiPublicationInfo OBJ_id_regCtrl,3L

#define SN_id_regCtrl_pkiArchiveOptions "id-regCtrl-pkiArchiveOptions"

#define NID_id_regCtrl_pkiArchiveOptions 318

#define OBJ_id_regCtrl_pkiArchiveOptions OBJ_id_regCtrl,4L

#define SN_id_regCtrl_oldCertID "id-regCtrl-oldCertID"

#define NID_id_regCtrl_oldCertID 319

#define OBJ_id_regCtrl_oldCertID OBJ_id_regCtrl,5L

#define SN_id_regCtrl_protocolEncrKey "id-regCtrl-protocolEncrKey"

#define NID_id_regCtrl_protocolEncrKey 320

#define OBJ_id_regCtrl_protocolEncrKey OBJ_id_regCtrl,6L

#define SN_id_regCtrl_altCertTemplate "id-regCtrl-altCertTemplate"

#define NID_id_regCtrl_altCertTemplate 1258

#define OBJ_id_regCtrl_altCertTemplate OBJ_id_regCtrl,7L

#define SN_id_regCtrl_algId "id-regCtrl-algId"

#define NID_id_regCtrl_algId 1259

#define OBJ_id_regCtrl_algId OBJ_id_regCtrl,11L

#define SN_id_regCtrl_rsaKeyLen "id-regCtrl-rsaKeyLen"

#define NID_id_regCtrl_rsaKeyLen 1260

#define OBJ_id_regCtrl_rsaKeyLen OBJ_id_regCtrl,12L

#define SN_id_regInfo_utf8Pairs "id-regInfo-utf8Pairs"

#define NID_id_regInfo_utf8Pairs 321

#define OBJ_id_regInfo_utf8Pairs OBJ_id_regInfo,1L

#define SN_id_regInfo_certReq "id-regInfo-certReq"

#define NID_id_regInfo_certReq 322

#define OBJ_id_regInfo_certReq OBJ_id_regInfo,2L

#define SN_id_alg_des40 "id-alg-des40"

#define NID_id_alg_des40 323

#define OBJ_id_alg_des40 OBJ_id_alg,1L

#define SN_id_alg_noSignature "id-alg-noSignature"

#define NID_id_alg_noSignature 324

#define OBJ_id_alg_noSignature OBJ_id_alg,2L

#define SN_id_alg_dh_sig_hmac_sha1 "id-alg-dh-sig-hmac-sha1"

#define NID_id_alg_dh_sig_hmac_sha1 325

#define OBJ_id_alg_dh_sig_hmac_sha1 OBJ_id_alg,3L

#define SN_id_alg_dh_pop "id-alg-dh-pop"

#define NID_id_alg_dh_pop 326

#define OBJ_id_alg_dh_pop OBJ_id_alg,4L

#define SN_id_cmc_statusInfo "id-cmc-statusInfo"

#define NID_id_cmc_statusInfo 327

#define OBJ_id_cmc_statusInfo OBJ_id_cmc,1L

#define SN_id_cmc_identification "id-cmc-identification"

#define NID_id_cmc_identification 328

#define OBJ_id_cmc_identification OBJ_id_cmc,2L

#define SN_id_cmc_identityProof "id-cmc-identityProof"

#define NID_id_cmc_identityProof 329

#define OBJ_id_cmc_identityProof OBJ_id_cmc,3L

#define SN_id_cmc_dataReturn "id-cmc-dataReturn"

#define NID_id_cmc_dataReturn 330

#define OBJ_id_cmc_dataReturn OBJ_id_cmc,4L

#define SN_id_cmc_transactionId "id-cmc-transactionId"

#define NID_id_cmc_transactionId 331

#define OBJ_id_cmc_transactionId OBJ_id_cmc,5L

#define SN_id_cmc_senderNonce "id-cmc-senderNonce"

#define NID_id_cmc_senderNonce 332

#define OBJ_id_cmc_senderNonce OBJ_id_cmc,6L

#define SN_id_cmc_recipientNonce "id-cmc-recipientNonce"

#define NID_id_cmc_recipientNonce 333

#define OBJ_id_cmc_recipientNonce OBJ_id_cmc,7L

#define SN_id_cmc_addExtensions "id-cmc-addExtensions"

#define NID_id_cmc_addExtensions 334

#define OBJ_id_cmc_addExtensions OBJ_id_cmc,8L

#define SN_id_cmc_encryptedPOP "id-cmc-encryptedPOP"

#define NID_id_cmc_encryptedPOP 335

#define OBJ_id_cmc_encryptedPOP OBJ_id_cmc,9L

#define SN_id_cmc_decryptedPOP "id-cmc-decryptedPOP"

#define NID_id_cmc_decryptedPOP 336

#define OBJ_id_cmc_decryptedPOP OBJ_id_cmc,10L

#define SN_id_cmc_lraPOPWitness "id-cmc-lraPOPWitness"

#define NID_id_cmc_lraPOPWitness 337

#define OBJ_id_cmc_lraPOPWitness OBJ_id_cmc,11L

#define SN_id_cmc_getCert "id-cmc-getCert"

#define NID_id_cmc_getCert 338

#define OBJ_id_cmc_getCert OBJ_id_cmc,15L

#define SN_id_cmc_getCRL "id-cmc-getCRL"

#define NID_id_cmc_getCRL 339

#define OBJ_id_cmc_getCRL OBJ_id_cmc,16L

#define SN_id_cmc_revokeRequest "id-cmc-revokeRequest"

#define NID_id_cmc_revokeRequest 340

#define OBJ_id_cmc_revokeRequest OBJ_id_cmc,17L

#define SN_id_cmc_regInfo "id-cmc-regInfo"

#define NID_id_cmc_regInfo 341

#define OBJ_id_cmc_regInfo OBJ_id_cmc,18L

#define SN_id_cmc_responseInfo "id-cmc-responseInfo"

#define NID_id_cmc_responseInfo 342

#define OBJ_id_cmc_responseInfo OBJ_id_cmc,19L

#define SN_id_cmc_queryPending "id-cmc-queryPending"

#define NID_id_cmc_queryPending 343

#define OBJ_id_cmc_queryPending OBJ_id_cmc,21L

#define SN_id_cmc_popLinkRandom "id-cmc-popLinkRandom"

#define NID_id_cmc_popLinkRandom 344

#define OBJ_id_cmc_popLinkRandom OBJ_id_cmc,22L

#define SN_id_cmc_popLinkWitness "id-cmc-popLinkWitness"

#define NID_id_cmc_popLinkWitness 345

#define OBJ_id_cmc_popLinkWitness OBJ_id_cmc,23L

#define SN_id_cmc_confirmCertAcceptance "id-cmc-confirmCertAcceptance"

#define NID_id_cmc_confirmCertAcceptance 346

#define OBJ_id_cmc_confirmCertAcceptance OBJ_id_cmc,24L

#define SN_id_on_personalData "id-on-personalData"

#define NID_id_on_personalData 347

#define OBJ_id_on_personalData OBJ_id_on,1L

#define SN_id_on_permanentIdentifier "id-on-permanentIdentifier"

#define LN_id_on_permanentIdentifier "Permanent Identifier"

#define NID_id_on_permanentIdentifier 858

#define OBJ_id_on_permanentIdentifier OBJ_id_on,3L

#define SN_XmppAddr "id-on-xmppAddr"

#define LN_XmppAddr "XmppAddr"

#define NID_XmppAddr 1209

#define OBJ_XmppAddr OBJ_id_on,5L

#define SN_SRVName "id-on-dnsSRV"

#define LN_SRVName "SRVName"

#define NID_SRVName 1210

#define OBJ_SRVName OBJ_id_on,7L

#define SN_NAIRealm "id-on-NAIRealm"

#define LN_NAIRealm "NAIRealm"

#define NID_NAIRealm 1211

#define OBJ_NAIRealm OBJ_id_on,8L

#define SN_id_on_SmtpUTF8Mailbox "id-on-SmtpUTF8Mailbox"

#define LN_id_on_SmtpUTF8Mailbox "Smtp UTF8 Mailbox"

#define NID_id_on_SmtpUTF8Mailbox 1208

#define OBJ_id_on_SmtpUTF8Mailbox OBJ_id_on,9L

#define SN_id_pda_dateOfBirth "id-pda-dateOfBirth"

#define NID_id_pda_dateOfBirth 348

#define OBJ_id_pda_dateOfBirth OBJ_id_pda,1L

#define SN_id_pda_placeOfBirth "id-pda-placeOfBirth"

#define NID_id_pda_placeOfBirth 349

#define OBJ_id_pda_placeOfBirth OBJ_id_pda,2L

#define SN_id_pda_gender "id-pda-gender"

#define NID_id_pda_gender 351

#define OBJ_id_pda_gender OBJ_id_pda,3L

#define SN_id_pda_countryOfCitizenship "id-pda-countryOfCitizenship"

#define NID_id_pda_countryOfCitizenship 352

#define OBJ_id_pda_countryOfCitizenship OBJ_id_pda,4L

#define SN_id_pda_countryOfResidence "id-pda-countryOfResidence"

#define NID_id_pda_countryOfResidence 353

#define OBJ_id_pda_countryOfResidence OBJ_id_pda,5L

#define SN_id_aca_authenticationInfo "id-aca-authenticationInfo"

#define NID_id_aca_authenticationInfo 354

#define OBJ_id_aca_authenticationInfo OBJ_id_aca,1L

#define SN_id_aca_accessIdentity "id-aca-accessIdentity"

#define NID_id_aca_accessIdentity 355

#define OBJ_id_aca_accessIdentity OBJ_id_aca,2L

#define SN_id_aca_chargingIdentity "id-aca-chargingIdentity"

#define NID_id_aca_chargingIdentity 356

#define OBJ_id_aca_chargingIdentity OBJ_id_aca,3L

#define SN_id_aca_group "id-aca-group"

#define NID_id_aca_group 357

#define OBJ_id_aca_group OBJ_id_aca,4L

#define SN_id_aca_role "id-aca-role"

#define NID_id_aca_role 358

#define OBJ_id_aca_role OBJ_id_aca,5L

#define SN_id_aca_encAttrs "id-aca-encAttrs"

#define NID_id_aca_encAttrs 399

#define OBJ_id_aca_encAttrs OBJ_id_aca,6L

#define SN_id_qcs_pkixQCSyntax_v1 "id-qcs-pkixQCSyntax-v1"

#define NID_id_qcs_pkixQCSyntax_v1 359

#define OBJ_id_qcs_pkixQCSyntax_v1 OBJ_id_qcs,1L

#define SN_ipAddr_asNumber "ipAddr-asNumber"

#define NID_ipAddr_asNumber 1241

#define OBJ_ipAddr_asNumber OBJ_id_cp,2L

#define SN_ipAddr_asNumberv2 "ipAddr-asNumberv2"

#define NID_ipAddr_asNumberv2 1242

#define OBJ_ipAddr_asNumberv2 OBJ_id_cp,3L

#define SN_id_cct_crs "id-cct-crs"

#define NID_id_cct_crs 360

#define OBJ_id_cct_crs OBJ_id_cct,1L

#define SN_id_cct_PKIData "id-cct-PKIData"

#define NID_id_cct_PKIData 361

#define OBJ_id_cct_PKIData OBJ_id_cct,2L

#define SN_id_cct_PKIResponse "id-cct-PKIResponse"

#define NID_id_cct_PKIResponse 362

#define OBJ_id_cct_PKIResponse OBJ_id_cct,3L

#define SN_id_ppl_anyLanguage "id-ppl-anyLanguage"

#define LN_id_ppl_anyLanguage "Any language"

#define NID_id_ppl_anyLanguage 664

#define OBJ_id_ppl_anyLanguage OBJ_id_ppl,0L

#define SN_id_ppl_inheritAll "id-ppl-inheritAll"

#define LN_id_ppl_inheritAll "Inherit all"

#define NID_id_ppl_inheritAll 665

#define OBJ_id_ppl_inheritAll OBJ_id_ppl,1L

#define SN_Independent "id-ppl-independent"

#define LN_Independent "Independent"

#define NID_Independent 667

#define OBJ_Independent OBJ_id_ppl,2L

#define SN_ad_OCSP "OCSP"

#define LN_ad_OCSP "OCSP"

#define NID_ad_OCSP 178

#define OBJ_ad_OCSP OBJ_id_ad,1L

#define SN_ad_ca_issuers "caIssuers"

#define LN_ad_ca_issuers "CA Issuers"

#define NID_ad_ca_issuers 179

#define OBJ_ad_ca_issuers OBJ_id_ad,2L

#define SN_ad_timeStamping "ad_timestamping"

#define LN_ad_timeStamping "AD Time Stamping"

#define NID_ad_timeStamping 363

#define OBJ_ad_timeStamping OBJ_id_ad,3L

#define SN_ad_dvcs "AD_DVCS"

#define LN_ad_dvcs "ad dvcs"

#define NID_ad_dvcs 364

#define OBJ_ad_dvcs OBJ_id_ad,4L

#define SN_caRepository "caRepository"

#define LN_caRepository "CA Repository"

#define NID_caRepository 785

#define OBJ_caRepository OBJ_id_ad,5L

#define SN_rpkiManifest "rpkiManifest"

#define LN_rpkiManifest "RPKI Manifest"

#define NID_rpkiManifest 1243

#define OBJ_rpkiManifest OBJ_id_ad,10L

#define SN_signedObject "signedObject"

#define LN_signedObject "Signed Object"

#define NID_signedObject 1244

#define OBJ_signedObject OBJ_id_ad,11L

#define SN_rpkiNotify "rpkiNotify"

#define LN_rpkiNotify "RPKI Notify"

#define NID_rpkiNotify 1245

#define OBJ_rpkiNotify OBJ_id_ad,13L

#define OBJ_id_pkix_OCSP OBJ_ad_OCSP

#define SN_id_pkix_OCSP_basic "basicOCSPResponse"

#define LN_id_pkix_OCSP_basic "Basic OCSP Response"

#define NID_id_pkix_OCSP_basic 365

#define OBJ_id_pkix_OCSP_basic OBJ_id_pkix_OCSP,1L

#define SN_id_pkix_OCSP_Nonce "Nonce"

#define LN_id_pkix_OCSP_Nonce "OCSP Nonce"

#define NID_id_pkix_OCSP_Nonce 366

#define OBJ_id_pkix_OCSP_Nonce OBJ_id_pkix_OCSP,2L

#define SN_id_pkix_OCSP_CrlID "CrlID"

#define LN_id_pkix_OCSP_CrlID "OCSP CRL ID"

#define NID_id_pkix_OCSP_CrlID 367

#define OBJ_id_pkix_OCSP_CrlID OBJ_id_pkix_OCSP,3L

#define SN_id_pkix_OCSP_acceptableResponses "acceptableResponses"

#define LN_id_pkix_OCSP_acceptableResponses "Acceptable OCSP Responses"

#define NID_id_pkix_OCSP_acceptableResponses 368

#define OBJ_id_pkix_OCSP_acceptableResponses OBJ_id_pkix_OCSP,4L

#define SN_id_pkix_OCSP_noCheck "noCheck"

#define LN_id_pkix_OCSP_noCheck "OCSP No Check"

#define NID_id_pkix_OCSP_noCheck 369

#define OBJ_id_pkix_OCSP_noCheck OBJ_id_pkix_OCSP,5L

#define SN_id_pkix_OCSP_archiveCutoff "archiveCutoff"

#define LN_id_pkix_OCSP_archiveCutoff "OCSP Archive Cutoff"

#define NID_id_pkix_OCSP_archiveCutoff 370

#define OBJ_id_pkix_OCSP_archiveCutoff OBJ_id_pkix_OCSP,6L

#define SN_id_pkix_OCSP_serviceLocator "serviceLocator"

#define LN_id_pkix_OCSP_serviceLocator "OCSP Service Locator"

#define NID_id_pkix_OCSP_serviceLocator 371

#define OBJ_id_pkix_OCSP_serviceLocator OBJ_id_pkix_OCSP,7L

#define SN_id_pkix_OCSP_extendedStatus "extendedStatus"

#define LN_id_pkix_OCSP_extendedStatus "Extended OCSP Status"

#define NID_id_pkix_OCSP_extendedStatus 372

#define OBJ_id_pkix_OCSP_extendedStatus OBJ_id_pkix_OCSP,8L

#define SN_id_pkix_OCSP_valid "valid"

#define NID_id_pkix_OCSP_valid 373

#define OBJ_id_pkix_OCSP_valid OBJ_id_pkix_OCSP,9L

#define SN_id_pkix_OCSP_path "path"

#define NID_id_pkix_OCSP_path 374

#define OBJ_id_pkix_OCSP_path OBJ_id_pkix_OCSP,10L

#define SN_id_pkix_OCSP_trustRoot "trustRoot"

#define LN_id_pkix_OCSP_trustRoot "Trust Root"

#define NID_id_pkix_OCSP_trustRoot 375

#define OBJ_id_pkix_OCSP_trustRoot OBJ_id_pkix_OCSP,11L

#define SN_algorithm "algorithm"

#define LN_algorithm "algorithm"

#define NID_algorithm 376

#define OBJ_algorithm 1L,3L,14L,3L,2L

#define SN_md5WithRSA "RSA-NP-MD5"

#define LN_md5WithRSA "md5WithRSA"

#define NID_md5WithRSA 104

#define OBJ_md5WithRSA OBJ_algorithm,3L

#define SN_des_ecb "DES-ECB"

#define LN_des_ecb "des-ecb"

#define NID_des_ecb 29

#define OBJ_des_ecb OBJ_algorithm,6L

#define SN_des_cbc "DES-CBC"

#define LN_des_cbc "des-cbc"

#define NID_des_cbc 31

#define OBJ_des_cbc OBJ_algorithm,7L

#define SN_des_ofb64 "DES-OFB"

#define LN_des_ofb64 "des-ofb"

#define NID_des_ofb64 45

#define OBJ_des_ofb64 OBJ_algorithm,8L

#define SN_des_cfb64 "DES-CFB"

#define LN_des_cfb64 "des-cfb"

#define NID_des_cfb64 30

#define OBJ_des_cfb64 OBJ_algorithm,9L

#define SN_rsaSignature "rsaSignature"

#define NID_rsaSignature 377

#define OBJ_rsaSignature OBJ_algorithm,11L

#define SN_dsa_2 "DSA-old"

#define LN_dsa_2 "dsaEncryption-old"

#define NID_dsa_2 67

#define OBJ_dsa_2 OBJ_algorithm,12L

#define SN_dsaWithSHA "DSA-SHA"

#define LN_dsaWithSHA "dsaWithSHA"

#define NID_dsaWithSHA 66

#define OBJ_dsaWithSHA OBJ_algorithm,13L

#define SN_shaWithRSAEncryption "RSA-SHA"

#define LN_shaWithRSAEncryption "shaWithRSAEncryption"

#define NID_shaWithRSAEncryption 42

#define OBJ_shaWithRSAEncryption OBJ_algorithm,15L

#define SN_des_ede_ecb "DES-EDE"

#define LN_des_ede_ecb "des-ede"

#define NID_des_ede_ecb 32

#define OBJ_des_ede_ecb OBJ_algorithm,17L

#define SN_des_ede3_ecb "DES-EDE3"

#define LN_des_ede3_ecb "des-ede3"

#define NID_des_ede3_ecb 33

#define SN_des_ede_cbc "DES-EDE-CBC"

#define LN_des_ede_cbc "des-ede-cbc"

#define NID_des_ede_cbc 43

#define SN_des_ede_cfb64 "DES-EDE-CFB"

#define LN_des_ede_cfb64 "des-ede-cfb"

#define NID_des_ede_cfb64 60

#define SN_des_ede3_cfb64 "DES-EDE3-CFB"

#define LN_des_ede3_cfb64 "des-ede3-cfb"

#define NID_des_ede3_cfb64 61

#define SN_des_ede_ofb64 "DES-EDE-OFB"

#define LN_des_ede_ofb64 "des-ede-ofb"

#define NID_des_ede_ofb64 62

#define SN_des_ede3_ofb64 "DES-EDE3-OFB"

#define LN_des_ede3_ofb64 "des-ede3-ofb"

#define NID_des_ede3_ofb64 63

#define SN_desx_cbc "DESX-CBC"

#define LN_desx_cbc "desx-cbc"

#define NID_desx_cbc 80

#define SN_sha "SHA"

#define LN_sha "sha"

#define NID_sha 41

#define OBJ_sha OBJ_algorithm,18L

#define SN_sha1 "SHA1"

#define LN_sha1 "sha1"

#define NID_sha1 64

#define OBJ_sha1 OBJ_algorithm,26L

#define SN_dsaWithSHA1_2 "DSA-SHA1-old"

#define LN_dsaWithSHA1_2 "dsaWithSHA1-old"

#define NID_dsaWithSHA1_2 70

#define OBJ_dsaWithSHA1_2 OBJ_algorithm,27L

#define SN_sha1WithRSA "RSA-SHA1-2"

#define LN_sha1WithRSA "sha1WithRSA"

#define NID_sha1WithRSA 115

#define OBJ_sha1WithRSA OBJ_algorithm,29L

#define SN_ripemd160 "RIPEMD160"

#define LN_ripemd160 "ripemd160"

#define NID_ripemd160 117

#define OBJ_ripemd160 1L,3L,36L,3L,2L,1L

#define SN_ripemd160WithRSA "RSA-RIPEMD160"

#define LN_ripemd160WithRSA "ripemd160WithRSA"

#define NID_ripemd160WithRSA 119

#define OBJ_ripemd160WithRSA 1L,3L,36L,3L,3L,1L,2L

#define SN_blake2bmac "BLAKE2BMAC"

#define LN_blake2bmac "blake2bmac"

#define NID_blake2bmac 1201

#define OBJ_blake2bmac 1L,3L,6L,1L,4L,1L,1722L,12L,2L,1L

#define SN_blake2smac "BLAKE2SMAC"

#define LN_blake2smac "blake2smac"

#define NID_blake2smac 1202

#define OBJ_blake2smac 1L,3L,6L,1L,4L,1L,1722L,12L,2L,2L

#define SN_blake2b512 "BLAKE2b512"

#define LN_blake2b512 "blake2b512"

#define NID_blake2b512 1056

#define OBJ_blake2b512 OBJ_blake2bmac,16L

#define SN_blake2s256 "BLAKE2s256"

#define LN_blake2s256 "blake2s256"

#define NID_blake2s256 1057

#define OBJ_blake2s256 OBJ_blake2smac,8L

#define SN_sxnet "SXNetID"

#define LN_sxnet "Strong Extranet ID"

#define NID_sxnet 143

#define OBJ_sxnet 1L,3L,101L,1L,4L,1L

#define SN_X500 "X500"

#define LN_X500 "directory services (X.500)"

#define NID_X500 11

#define OBJ_X500 2L,5L

#define SN_X509 "X509"

#define NID_X509 12

#define OBJ_X509 OBJ_X500,4L

#define SN_commonName "CN"

#define LN_commonName "commonName"

#define NID_commonName 13

#define OBJ_commonName OBJ_X509,3L

#define SN_surname "SN"

#define LN_surname "surname"

#define NID_surname 100

#define OBJ_surname OBJ_X509,4L

#define LN_serialNumber "serialNumber"

#define NID_serialNumber 105

#define OBJ_serialNumber OBJ_X509,5L

#define SN_countryName "C"

#define LN_countryName "countryName"

#define NID_countryName 14

#define OBJ_countryName OBJ_X509,6L

#define SN_localityName "L"

#define LN_localityName "localityName"

#define NID_localityName 15

#define OBJ_localityName OBJ_X509,7L

#define SN_stateOrProvinceName "ST"

#define LN_stateOrProvinceName "stateOrProvinceName"

#define NID_stateOrProvinceName 16

#define OBJ_stateOrProvinceName OBJ_X509,8L

#define SN_streetAddress "street"

#define LN_streetAddress "streetAddress"

#define NID_streetAddress 660

#define OBJ_streetAddress OBJ_X509,9L

#define SN_organizationName "O"

#define LN_organizationName "organizationName"

#define NID_organizationName 17

#define OBJ_organizationName OBJ_X509,10L

#define SN_organizationalUnitName "OU"

#define LN_organizationalUnitName "organizationalUnitName"

#define NID_organizationalUnitName 18

#define OBJ_organizationalUnitName OBJ_X509,11L

#define SN_title "title"

#define LN_title "title"

#define NID_title 106

#define OBJ_title OBJ_X509,12L

#define LN_description "description"

#define NID_description 107

#define OBJ_description OBJ_X509,13L

#define LN_searchGuide "searchGuide"

#define NID_searchGuide 859

#define OBJ_searchGuide OBJ_X509,14L

#define LN_businessCategory "businessCategory"

#define NID_businessCategory 860

#define OBJ_businessCategory OBJ_X509,15L

#define LN_postalAddress "postalAddress"

#define NID_postalAddress 861

#define OBJ_postalAddress OBJ_X509,16L

#define LN_postalCode "postalCode"

#define NID_postalCode 661

#define OBJ_postalCode OBJ_X509,17L

#define LN_postOfficeBox "postOfficeBox"

#define NID_postOfficeBox 862

#define OBJ_postOfficeBox OBJ_X509,18L

#define LN_physicalDeliveryOfficeName "physicalDeliveryOfficeName"

#define NID_physicalDeliveryOfficeName 863

#define OBJ_physicalDeliveryOfficeName OBJ_X509,19L

#define LN_telephoneNumber "telephoneNumber"

#define NID_telephoneNumber 864

#define OBJ_telephoneNumber OBJ_X509,20L

#define LN_telexNumber "telexNumber"

#define NID_telexNumber 865

#define OBJ_telexNumber OBJ_X509,21L

#define LN_teletexTerminalIdentifier "teletexTerminalIdentifier"

#define NID_teletexTerminalIdentifier 866

#define OBJ_teletexTerminalIdentifier OBJ_X509,22L

#define LN_facsimileTelephoneNumber "facsimileTelephoneNumber"

#define NID_facsimileTelephoneNumber 867

#define OBJ_facsimileTelephoneNumber OBJ_X509,23L

#define LN_x121Address "x121Address"

#define NID_x121Address 868

#define OBJ_x121Address OBJ_X509,24L

#define LN_internationaliSDNNumber "internationaliSDNNumber"

#define NID_internationaliSDNNumber 869

#define OBJ_internationaliSDNNumber OBJ_X509,25L

#define LN_registeredAddress "registeredAddress"

#define NID_registeredAddress 870

#define OBJ_registeredAddress OBJ_X509,26L

#define LN_destinationIndicator "destinationIndicator"

#define NID_destinationIndicator 871

#define OBJ_destinationIndicator OBJ_X509,27L

#define LN_preferredDeliveryMethod "preferredDeliveryMethod"

#define NID_preferredDeliveryMethod 872

#define OBJ_preferredDeliveryMethod OBJ_X509,28L

#define LN_presentationAddress "presentationAddress"

#define NID_presentationAddress 873

#define OBJ_presentationAddress OBJ_X509,29L

#define LN_supportedApplicationContext "supportedApplicationContext"

#define NID_supportedApplicationContext 874

#define OBJ_supportedApplicationContext OBJ_X509,30L

#define SN_member "member"

#define NID_member 875

#define OBJ_member OBJ_X509,31L

#define SN_owner "owner"

#define NID_owner 876

#define OBJ_owner OBJ_X509,32L

#define LN_roleOccupant "roleOccupant"

#define NID_roleOccupant 877

#define OBJ_roleOccupant OBJ_X509,33L

#define SN_seeAlso "seeAlso"

#define NID_seeAlso 878

#define OBJ_seeAlso OBJ_X509,34L

#define LN_userPassword "userPassword"

#define NID_userPassword 879

#define OBJ_userPassword OBJ_X509,35L

#define LN_userCertificate "userCertificate"

#define NID_userCertificate 880

#define OBJ_userCertificate OBJ_X509,36L

#define LN_cACertificate "cACertificate"

#define NID_cACertificate 881

#define OBJ_cACertificate OBJ_X509,37L

#define LN_authorityRevocationList "authorityRevocationList"

#define NID_authorityRevocationList 882

#define OBJ_authorityRevocationList OBJ_X509,38L

#define LN_certificateRevocationList "certificateRevocationList"

#define NID_certificateRevocationList 883

#define OBJ_certificateRevocationList OBJ_X509,39L

#define LN_crossCertificatePair "crossCertificatePair"

#define NID_crossCertificatePair 884

#define OBJ_crossCertificatePair OBJ_X509,40L

#define SN_name "name"

#define LN_name "name"

#define NID_name 173

#define OBJ_name OBJ_X509,41L

#define SN_givenName "GN"

#define LN_givenName "givenName"

#define NID_givenName 99

#define OBJ_givenName OBJ_X509,42L

#define SN_initials "initials"

#define LN_initials "initials"

#define NID_initials 101

#define OBJ_initials OBJ_X509,43L

#define LN_generationQualifier "generationQualifier"

#define NID_generationQualifier 509

#define OBJ_generationQualifier OBJ_X509,44L

#define LN_x500UniqueIdentifier "x500UniqueIdentifier"

#define NID_x500UniqueIdentifier 503

#define OBJ_x500UniqueIdentifier OBJ_X509,45L

#define SN_dnQualifier "dnQualifier"

#define LN_dnQualifier "dnQualifier"

#define NID_dnQualifier 174

#define OBJ_dnQualifier OBJ_X509,46L

#define LN_enhancedSearchGuide "enhancedSearchGuide"

#define NID_enhancedSearchGuide 885

#define OBJ_enhancedSearchGuide OBJ_X509,47L

#define LN_protocolInformation "protocolInformation"

#define NID_protocolInformation 886

#define OBJ_protocolInformation OBJ_X509,48L

#define LN_distinguishedName "distinguishedName"

#define NID_distinguishedName 887

#define OBJ_distinguishedName OBJ_X509,49L

#define LN_uniqueMember "uniqueMember"

#define NID_uniqueMember 888

#define OBJ_uniqueMember OBJ_X509,50L

#define LN_houseIdentifier "houseIdentifier"

#define NID_houseIdentifier 889

#define OBJ_houseIdentifier OBJ_X509,51L

#define LN_supportedAlgorithms "supportedAlgorithms"

#define NID_supportedAlgorithms 890

#define OBJ_supportedAlgorithms OBJ_X509,52L

#define LN_deltaRevocationList "deltaRevocationList"

#define NID_deltaRevocationList 891

#define OBJ_deltaRevocationList OBJ_X509,53L

#define SN_dmdName "dmdName"

#define NID_dmdName 892

#define OBJ_dmdName OBJ_X509,54L

#define LN_pseudonym "pseudonym"

#define NID_pseudonym 510

#define OBJ_pseudonym OBJ_X509,65L

#define SN_role "role"

#define LN_role "role"

#define NID_role 400

#define OBJ_role OBJ_X509,72L

#define LN_organizationIdentifier "organizationIdentifier"

#define NID_organizationIdentifier 1089

#define OBJ_organizationIdentifier OBJ_X509,97L

#define SN_countryCode3c "c3"

#define LN_countryCode3c "countryCode3c"

#define NID_countryCode3c 1090

#define OBJ_countryCode3c OBJ_X509,98L

#define SN_countryCode3n "n3"

#define LN_countryCode3n "countryCode3n"

#define NID_countryCode3n 1091

#define OBJ_countryCode3n OBJ_X509,99L

#define LN_dnsName "dnsName"

#define NID_dnsName 1092

#define OBJ_dnsName OBJ_X509,100L

#define SN_X500algorithms "X500algorithms"

#define LN_X500algorithms "directory services - algorithms"

#define NID_X500algorithms 378

#define OBJ_X500algorithms OBJ_X500,8L

#define SN_rsa "RSA"

#define LN_rsa "rsa"

#define NID_rsa 19

#define OBJ_rsa OBJ_X500algorithms,1L,1L

#define SN_mdc2WithRSA "RSA-MDC2"

#define LN_mdc2WithRSA "mdc2WithRSA"

#define NID_mdc2WithRSA 96

#define OBJ_mdc2WithRSA OBJ_X500algorithms,3L,100L

#define SN_mdc2 "MDC2"

#define LN_mdc2 "mdc2"

#define NID_mdc2 95

#define OBJ_mdc2 OBJ_X500algorithms,3L,101L

#define SN_id_ce "id-ce"

#define NID_id_ce 81

#define OBJ_id_ce OBJ_X500,29L

#define SN_subject_directory_attributes "subjectDirectoryAttributes"

#define LN_subject_directory_attributes "X509v3 Subject Directory Attributes"

#define NID_subject_directory_attributes 769

#define OBJ_subject_directory_attributes OBJ_id_ce,9L

#define SN_subject_key_identifier "subjectKeyIdentifier"

#define LN_subject_key_identifier "X509v3 Subject Key Identifier"

#define NID_subject_key_identifier 82

#define OBJ_subject_key_identifier OBJ_id_ce,14L

#define SN_key_usage "keyUsage"

#define LN_key_usage "X509v3 Key Usage"

#define NID_key_usage 83

#define OBJ_key_usage OBJ_id_ce,15L

#define SN_private_key_usage_period "privateKeyUsagePeriod"

#define LN_private_key_usage_period "X509v3 Private Key Usage Period"

#define NID_private_key_usage_period 84

#define OBJ_private_key_usage_period OBJ_id_ce,16L

#define SN_subject_alt_name "subjectAltName"

#define LN_subject_alt_name "X509v3 Subject Alternative Name"

#define NID_subject_alt_name 85

#define OBJ_subject_alt_name OBJ_id_ce,17L

#define SN_issuer_alt_name "issuerAltName"

#define LN_issuer_alt_name "X509v3 Issuer Alternative Name"

#define NID_issuer_alt_name 86

#define OBJ_issuer_alt_name OBJ_id_ce,18L

#define SN_basic_constraints "basicConstraints"

#define LN_basic_constraints "X509v3 Basic Constraints"

#define NID_basic_constraints 87

#define OBJ_basic_constraints OBJ_id_ce,19L

#define SN_crl_number "crlNumber"

#define LN_crl_number "X509v3 CRL Number"

#define NID_crl_number 88

#define OBJ_crl_number OBJ_id_ce,20L

#define SN_crl_reason "CRLReason"

#define LN_crl_reason "X509v3 CRL Reason Code"

#define NID_crl_reason 141

#define OBJ_crl_reason OBJ_id_ce,21L

#define SN_invalidity_date "invalidityDate"

#define LN_invalidity_date "Invalidity Date"

#define NID_invalidity_date 142

#define OBJ_invalidity_date OBJ_id_ce,24L

#define SN_delta_crl "deltaCRL"

#define LN_delta_crl "X509v3 Delta CRL Indicator"

#define NID_delta_crl 140

#define OBJ_delta_crl OBJ_id_ce,27L

#define SN_issuing_distribution_point "issuingDistributionPoint"

#define LN_issuing_distribution_point "X509v3 Issuing Distribution Point"

#define NID_issuing_distribution_point 770

#define OBJ_issuing_distribution_point OBJ_id_ce,28L

#define SN_certificate_issuer "certificateIssuer"

#define LN_certificate_issuer "X509v3 Certificate Issuer"

#define NID_certificate_issuer 771

#define OBJ_certificate_issuer OBJ_id_ce,29L

#define SN_name_constraints "nameConstraints"

#define LN_name_constraints "X509v3 Name Constraints"

#define NID_name_constraints 666

#define OBJ_name_constraints OBJ_id_ce,30L

#define SN_crl_distribution_points "crlDistributionPoints"

#define LN_crl_distribution_points "X509v3 CRL Distribution Points"

#define NID_crl_distribution_points 103

#define OBJ_crl_distribution_points OBJ_id_ce,31L

#define SN_certificate_policies "certificatePolicies"

#define LN_certificate_policies "X509v3 Certificate Policies"

#define NID_certificate_policies 89

#define OBJ_certificate_policies OBJ_id_ce,32L

#define SN_any_policy "anyPolicy"

#define LN_any_policy "X509v3 Any Policy"

#define NID_any_policy 746

#define OBJ_any_policy OBJ_certificate_policies,0L

#define SN_policy_mappings "policyMappings"

#define LN_policy_mappings "X509v3 Policy Mappings"

#define NID_policy_mappings 747

#define OBJ_policy_mappings OBJ_id_ce,33L

#define SN_authority_key_identifier "authorityKeyIdentifier"

#define LN_authority_key_identifier "X509v3 Authority Key Identifier"

#define NID_authority_key_identifier 90

#define OBJ_authority_key_identifier OBJ_id_ce,35L

#define SN_policy_constraints "policyConstraints"

#define LN_policy_constraints "X509v3 Policy Constraints"

#define NID_policy_constraints 401

#define OBJ_policy_constraints OBJ_id_ce,36L

#define SN_ext_key_usage "extendedKeyUsage"

#define LN_ext_key_usage "X509v3 Extended Key Usage"

#define NID_ext_key_usage 126

#define OBJ_ext_key_usage OBJ_id_ce,37L

#define SN_authority_attribute_identifier "authorityAttributeIdentifier"

#define LN_authority_attribute_identifier "X509v3 Authority Attribute Identifier"

#define NID_authority_attribute_identifier 1295

#define OBJ_authority_attribute_identifier OBJ_id_ce,38L

#define SN_role_spec_cert_identifier "roleSpecCertIdentifier"

#define LN_role_spec_cert_identifier "X509v3 Role Specification Certificate Identifier"

#define NID_role_spec_cert_identifier 1296

#define OBJ_role_spec_cert_identifier OBJ_id_ce,39L

#define SN_basic_att_constraints "basicAttConstraints"

#define LN_basic_att_constraints "X509v3 Basic Attribute Certificate Constraints"

#define NID_basic_att_constraints 1297

#define OBJ_basic_att_constraints OBJ_id_ce,41L

#define SN_delegated_name_constraints "delegatedNameConstraints"

#define LN_delegated_name_constraints "X509v3 Delegated Name Constraints"

#define NID_delegated_name_constraints 1298

#define OBJ_delegated_name_constraints OBJ_id_ce,42L

#define SN_time_specification "timeSpecification"

#define LN_time_specification "X509v3 Time Specification"

#define NID_time_specification 1299

#define OBJ_time_specification OBJ_id_ce,43L

#define SN_freshest_crl "freshestCRL"

#define LN_freshest_crl "X509v3 Freshest CRL"

#define NID_freshest_crl 857

#define OBJ_freshest_crl OBJ_id_ce,46L

#define SN_attribute_descriptor "attributeDescriptor"

#define LN_attribute_descriptor "X509v3 Attribute Descriptor"

#define NID_attribute_descriptor 1300

#define OBJ_attribute_descriptor OBJ_id_ce,48L

#define SN_user_notice "userNotice"

#define LN_user_notice "X509v3 User Notice"

#define NID_user_notice 1301

#define OBJ_user_notice OBJ_id_ce,49L

#define SN_soa_identifier "sOAIdentifier"

#define LN_soa_identifier "X509v3 Source of Authority Identifier"

#define NID_soa_identifier 1302

#define OBJ_soa_identifier OBJ_id_ce,50L

#define SN_acceptable_cert_policies "acceptableCertPolicies"

#define LN_acceptable_cert_policies "X509v3 Acceptable Certification Policies"

#define NID_acceptable_cert_policies 1303

#define OBJ_acceptable_cert_policies OBJ_id_ce,52L

#define SN_inhibit_any_policy "inhibitAnyPolicy"

#define LN_inhibit_any_policy "X509v3 Inhibit Any Policy"

#define NID_inhibit_any_policy 748

#define OBJ_inhibit_any_policy OBJ_id_ce,54L

#define SN_target_information "targetInformation"

#define LN_target_information "X509v3 AC Targeting"

#define NID_target_information 402

#define OBJ_target_information OBJ_id_ce,55L

#define SN_no_rev_avail "noRevAvail"

#define LN_no_rev_avail "X509v3 No Revocation Available"

#define NID_no_rev_avail 403

#define OBJ_no_rev_avail OBJ_id_ce,56L

#define SN_acceptable_privilege_policies "acceptablePrivPolicies"

#define LN_acceptable_privilege_policies "X509v3 Acceptable Privilege Policies"

#define NID_acceptable_privilege_policies 1304

#define OBJ_acceptable_privilege_policies OBJ_id_ce,57L

#define SN_indirect_issuer "indirectIssuer"

#define LN_indirect_issuer "X509v3 Indirect Issuer"

#define NID_indirect_issuer 1305

#define OBJ_indirect_issuer OBJ_id_ce,61L

#define SN_no_assertion "noAssertion"

#define LN_no_assertion "X509v3 No Assertion"

#define NID_no_assertion 1306

#define OBJ_no_assertion OBJ_id_ce,62L

#define SN_id_aa_issuing_distribution_point "aAissuingDistributionPoint"

#define LN_id_aa_issuing_distribution_point "X509v3 Attribute Authority Issuing Distribution Point"

#define NID_id_aa_issuing_distribution_point 1307

#define OBJ_id_aa_issuing_distribution_point OBJ_id_ce,63L

#define SN_issued_on_behalf_of "issuedOnBehalfOf"

#define LN_issued_on_behalf_of "X509v3 Issued On Behalf Of"

#define NID_issued_on_behalf_of 1308

#define OBJ_issued_on_behalf_of OBJ_id_ce,64L

#define SN_single_use "singleUse"

#define LN_single_use "X509v3 Single Use"

#define NID_single_use 1309

#define OBJ_single_use OBJ_id_ce,65L

#define SN_group_ac "groupAC"

#define LN_group_ac "X509v3 Group Attribute Certificate"

#define NID_group_ac 1310

#define OBJ_group_ac OBJ_id_ce,66L

#define SN_allowed_attribute_assignments "allowedAttributeAssignments"

#define LN_allowed_attribute_assignments "X509v3 Allowed Attribute Assignments"

#define NID_allowed_attribute_assignments 1311

#define OBJ_allowed_attribute_assignments OBJ_id_ce,67L

#define SN_attribute_mappings "attributeMappings"

#define LN_attribute_mappings "X509v3 Attribute Mappings"

#define NID_attribute_mappings 1312

#define OBJ_attribute_mappings OBJ_id_ce,68L

#define SN_holder_name_constraints "holderNameConstraints"

#define LN_holder_name_constraints "X509v3 Holder Name Constraints"

#define NID_holder_name_constraints 1313

#define OBJ_holder_name_constraints OBJ_id_ce,69L

#define SN_authorization_validation "authorizationValidation"

#define LN_authorization_validation "X509v3 Authorization Validation"

#define NID_authorization_validation 1314

#define OBJ_authorization_validation OBJ_id_ce,70L

#define SN_prot_restrict "protRestrict"

#define LN_prot_restrict "X509v3 Protocol Restriction"

#define NID_prot_restrict 1315

#define OBJ_prot_restrict OBJ_id_ce,71L

#define SN_subject_alt_public_key_info "subjectAltPublicKeyInfo"

#define LN_subject_alt_public_key_info "X509v3 Subject Alternative Public Key Info"

#define NID_subject_alt_public_key_info 1316

#define OBJ_subject_alt_public_key_info OBJ_id_ce,72L

#define SN_alt_signature_algorithm "altSignatureAlgorithm"

#define LN_alt_signature_algorithm "X509v3 Alternative Signature Algorithm"

#define NID_alt_signature_algorithm 1317

#define OBJ_alt_signature_algorithm OBJ_id_ce,73L

#define SN_alt_signature_value "altSignatureValue"

#define LN_alt_signature_value "X509v3 Alternative Signature Value"

#define NID_alt_signature_value 1318

#define OBJ_alt_signature_value OBJ_id_ce,74L

#define SN_associated_information "associatedInformation"

#define LN_associated_information "X509v3 Associated Information"

#define NID_associated_information 1319

#define OBJ_associated_information OBJ_id_ce,75L

#define SN_anyExtendedKeyUsage "anyExtendedKeyUsage"

#define LN_anyExtendedKeyUsage "Any Extended Key Usage"

#define NID_anyExtendedKeyUsage 910

#define OBJ_anyExtendedKeyUsage OBJ_ext_key_usage,0L

#define SN_netscape "Netscape"

#define LN_netscape "Netscape Communications Corp."

#define NID_netscape 57

#define OBJ_netscape 2L,16L,840L,1L,113730L

#define SN_netscape_cert_extension "nsCertExt"

#define LN_netscape_cert_extension "Netscape Certificate Extension"

#define NID_netscape_cert_extension 58

#define OBJ_netscape_cert_extension OBJ_netscape,1L

#define SN_netscape_data_type "nsDataType"

#define LN_netscape_data_type "Netscape Data Type"

#define NID_netscape_data_type 59

#define OBJ_netscape_data_type OBJ_netscape,2L

#define SN_netscape_cert_type "nsCertType"

#define LN_netscape_cert_type "Netscape Cert Type"

#define NID_netscape_cert_type 71

#define OBJ_netscape_cert_type OBJ_netscape_cert_extension,1L

#define SN_netscape_base_url "nsBaseUrl"

#define LN_netscape_base_url "Netscape Base Url"

#define NID_netscape_base_url 72

#define OBJ_netscape_base_url OBJ_netscape_cert_extension,2L

#define SN_netscape_revocation_url "nsRevocationUrl"

#define LN_netscape_revocation_url "Netscape Revocation Url"

#define NID_netscape_revocation_url 73

#define OBJ_netscape_revocation_url OBJ_netscape_cert_extension,3L

#define SN_netscape_ca_revocation_url "nsCaRevocationUrl"

#define LN_netscape_ca_revocation_url "Netscape CA Revocation Url"

#define NID_netscape_ca_revocation_url 74

#define OBJ_netscape_ca_revocation_url OBJ_netscape_cert_extension,4L

#define SN_netscape_renewal_url "nsRenewalUrl"

#define LN_netscape_renewal_url "Netscape Renewal Url"

#define NID_netscape_renewal_url 75

#define OBJ_netscape_renewal_url OBJ_netscape_cert_extension,7L

#define SN_netscape_ca_policy_url "nsCaPolicyUrl"

#define LN_netscape_ca_policy_url "Netscape CA Policy Url"

#define NID_netscape_ca_policy_url 76

#define OBJ_netscape_ca_policy_url OBJ_netscape_cert_extension,8L

#define SN_netscape_ssl_server_name "nsSslServerName"

#define LN_netscape_ssl_server_name "Netscape SSL Server Name"

#define NID_netscape_ssl_server_name 77

#define OBJ_netscape_ssl_server_name OBJ_netscape_cert_extension,12L

#define SN_netscape_comment "nsComment"

#define LN_netscape_comment "Netscape Comment"

#define NID_netscape_comment 78

#define OBJ_netscape_comment OBJ_netscape_cert_extension,13L

#define SN_netscape_cert_sequence "nsCertSequence"

#define LN_netscape_cert_sequence "Netscape Certificate Sequence"

#define NID_netscape_cert_sequence 79

#define OBJ_netscape_cert_sequence OBJ_netscape_data_type,5L

#define SN_ns_sgc "nsSGC"

#define LN_ns_sgc "Netscape Server Gated Crypto"

#define NID_ns_sgc 139

#define OBJ_ns_sgc OBJ_netscape,4L,1L

#define SN_org "ORG"

#define LN_org "org"

#define NID_org 379

#define OBJ_org OBJ_iso,3L

#define SN_dod "DOD"

#define LN_dod "dod"

#define NID_dod 380

#define OBJ_dod OBJ_org,6L

#define SN_iana "IANA"

#define LN_iana "iana"

#define NID_iana 381

#define OBJ_iana OBJ_dod,1L

#define OBJ_internet OBJ_iana

#define SN_Directory "directory"

#define LN_Directory "Directory"

#define NID_Directory 382

#define OBJ_Directory OBJ_internet,1L

#define SN_Management "mgmt"

#define LN_Management "Management"

#define NID_Management 383

#define OBJ_Management OBJ_internet,2L

#define SN_Experimental "experimental"

#define LN_Experimental "Experimental"

#define NID_Experimental 384

#define OBJ_Experimental OBJ_internet,3L

#define SN_Private "private"

#define LN_Private "Private"

#define NID_Private 385

#define OBJ_Private OBJ_internet,4L

#define SN_Security "security"

#define LN_Security "Security"

#define NID_Security 386

#define OBJ_Security OBJ_internet,5L

#define SN_SNMPv2 "snmpv2"

#define LN_SNMPv2 "SNMPv2"

#define NID_SNMPv2 387

#define OBJ_SNMPv2 OBJ_internet,6L

#define LN_Mail "Mail"

#define NID_Mail 388

#define OBJ_Mail OBJ_internet,7L

#define SN_Enterprises "enterprises"

#define LN_Enterprises "Enterprises"

#define NID_Enterprises 389

#define OBJ_Enterprises OBJ_Private,1L

#define SN_dcObject "dcobject"

#define LN_dcObject "dcObject"

#define NID_dcObject 390

#define OBJ_dcObject OBJ_Enterprises,1466L,344L

#define SN_mime_mhs "mime-mhs"

#define LN_mime_mhs "MIME MHS"

#define NID_mime_mhs 504

#define OBJ_mime_mhs OBJ_Mail,1L

#define SN_mime_mhs_headings "mime-mhs-headings"

#define LN_mime_mhs_headings "mime-mhs-headings"

#define NID_mime_mhs_headings 505

#define OBJ_mime_mhs_headings OBJ_mime_mhs,1L

#define SN_mime_mhs_bodies "mime-mhs-bodies"

#define LN_mime_mhs_bodies "mime-mhs-bodies"

#define NID_mime_mhs_bodies 506

#define OBJ_mime_mhs_bodies OBJ_mime_mhs,2L

#define SN_id_hex_partial_message "id-hex-partial-message"

#define LN_id_hex_partial_message "id-hex-partial-message"

#define NID_id_hex_partial_message 507

#define OBJ_id_hex_partial_message OBJ_mime_mhs_headings,1L

#define SN_id_hex_multipart_message "id-hex-multipart-message"

#define LN_id_hex_multipart_message "id-hex-multipart-message"

#define NID_id_hex_multipart_message 508

#define OBJ_id_hex_multipart_message OBJ_mime_mhs_headings,2L

#define SN_zlib_compression "ZLIB"

#define LN_zlib_compression "zlib compression"

#define NID_zlib_compression 125

#define OBJ_zlib_compression OBJ_id_smime_alg,8L

#define OBJ_csor 2L,16L,840L,1L,101L,3L

#define OBJ_nistAlgorithms OBJ_csor,4L

#define OBJ_aes OBJ_nistAlgorithms,1L

#define SN_aes_128_ecb "AES-128-ECB"

#define LN_aes_128_ecb "aes-128-ecb"

#define NID_aes_128_ecb 418

#define OBJ_aes_128_ecb OBJ_aes,1L

#define SN_aes_128_cbc "AES-128-CBC"

#define LN_aes_128_cbc "aes-128-cbc"

#define NID_aes_128_cbc 419

#define OBJ_aes_128_cbc OBJ_aes,2L

#define SN_aes_128_ofb128 "AES-128-OFB"

#define LN_aes_128_ofb128 "aes-128-ofb"

#define NID_aes_128_ofb128 420

#define OBJ_aes_128_ofb128 OBJ_aes,3L

#define SN_aes_128_cfb128 "AES-128-CFB"

#define LN_aes_128_cfb128 "aes-128-cfb"

#define NID_aes_128_cfb128 421

#define OBJ_aes_128_cfb128 OBJ_aes,4L

#define SN_id_aes128_wrap "id-aes128-wrap"

#define NID_id_aes128_wrap 788

#define OBJ_id_aes128_wrap OBJ_aes,5L

#define SN_aes_128_gcm "id-aes128-GCM"

#define LN_aes_128_gcm "aes-128-gcm"

#define NID_aes_128_gcm 895

#define OBJ_aes_128_gcm OBJ_aes,6L

#define SN_aes_128_ccm "id-aes128-CCM"

#define LN_aes_128_ccm "aes-128-ccm"

#define NID_aes_128_ccm 896

#define OBJ_aes_128_ccm OBJ_aes,7L

#define SN_id_aes128_wrap_pad "id-aes128-wrap-pad"

#define NID_id_aes128_wrap_pad 897

#define OBJ_id_aes128_wrap_pad OBJ_aes,8L

#define SN_aes_192_ecb "AES-192-ECB"

#define LN_aes_192_ecb "aes-192-ecb"

#define NID_aes_192_ecb 422

#define OBJ_aes_192_ecb OBJ_aes,21L

#define SN_aes_192_cbc "AES-192-CBC"

#define LN_aes_192_cbc "aes-192-cbc"

#define NID_aes_192_cbc 423

#define OBJ_aes_192_cbc OBJ_aes,22L

#define SN_aes_192_ofb128 "AES-192-OFB"

#define LN_aes_192_ofb128 "aes-192-ofb"

#define NID_aes_192_ofb128 424

#define OBJ_aes_192_ofb128 OBJ_aes,23L

#define SN_aes_192_cfb128 "AES-192-CFB"

#define LN_aes_192_cfb128 "aes-192-cfb"

#define NID_aes_192_cfb128 425

#define OBJ_aes_192_cfb128 OBJ_aes,24L

#define SN_id_aes192_wrap "id-aes192-wrap"

#define NID_id_aes192_wrap 789

#define OBJ_id_aes192_wrap OBJ_aes,25L

#define SN_aes_192_gcm "id-aes192-GCM"

#define LN_aes_192_gcm "aes-192-gcm"

#define NID_aes_192_gcm 898

#define OBJ_aes_192_gcm OBJ_aes,26L

#define SN_aes_192_ccm "id-aes192-CCM"

#define LN_aes_192_ccm "aes-192-ccm"

#define NID_aes_192_ccm 899

#define OBJ_aes_192_ccm OBJ_aes,27L

#define SN_id_aes192_wrap_pad "id-aes192-wrap-pad"

#define NID_id_aes192_wrap_pad 900

#define OBJ_id_aes192_wrap_pad OBJ_aes,28L

#define SN_aes_256_ecb "AES-256-ECB"

#define LN_aes_256_ecb "aes-256-ecb"

#define NID_aes_256_ecb 426

#define OBJ_aes_256_ecb OBJ_aes,41L

#define SN_aes_256_cbc "AES-256-CBC"

#define LN_aes_256_cbc "aes-256-cbc"

#define NID_aes_256_cbc 427

#define OBJ_aes_256_cbc OBJ_aes,42L

#define SN_aes_256_ofb128 "AES-256-OFB"

#define LN_aes_256_ofb128 "aes-256-ofb"

#define NID_aes_256_ofb128 428

#define OBJ_aes_256_ofb128 OBJ_aes,43L

#define SN_aes_256_cfb128 "AES-256-CFB"

#define LN_aes_256_cfb128 "aes-256-cfb"

#define NID_aes_256_cfb128 429

#define OBJ_aes_256_cfb128 OBJ_aes,44L

#define SN_id_aes256_wrap "id-aes256-wrap"

#define NID_id_aes256_wrap 790

#define OBJ_id_aes256_wrap OBJ_aes,45L

#define SN_aes_256_gcm "id-aes256-GCM"

#define LN_aes_256_gcm "aes-256-gcm"

#define NID_aes_256_gcm 901

#define OBJ_aes_256_gcm OBJ_aes,46L

#define SN_aes_256_ccm "id-aes256-CCM"

#define LN_aes_256_ccm "aes-256-ccm"

#define NID_aes_256_ccm 902

#define OBJ_aes_256_ccm OBJ_aes,47L

#define SN_id_aes256_wrap_pad "id-aes256-wrap-pad"

#define NID_id_aes256_wrap_pad 903

#define OBJ_id_aes256_wrap_pad OBJ_aes,48L

#define SN_aes_128_xts "AES-128-XTS"

#define LN_aes_128_xts "aes-128-xts"

#define NID_aes_128_xts 913

#define OBJ_aes_128_xts OBJ_ieee_siswg,0L,1L,1L

#define SN_aes_256_xts "AES-256-XTS"

#define LN_aes_256_xts "aes-256-xts"

#define NID_aes_256_xts 914

#define OBJ_aes_256_xts OBJ_ieee_siswg,0L,1L,2L

#define SN_aes_128_cfb1 "AES-128-CFB1"

#define LN_aes_128_cfb1 "aes-128-cfb1"

#define NID_aes_128_cfb1 650

#define SN_aes_192_cfb1 "AES-192-CFB1"

#define LN_aes_192_cfb1 "aes-192-cfb1"

#define NID_aes_192_cfb1 651

#define SN_aes_256_cfb1 "AES-256-CFB1"

#define LN_aes_256_cfb1 "aes-256-cfb1"

#define NID_aes_256_cfb1 652

#define SN_aes_128_cfb8 "AES-128-CFB8"

#define LN_aes_128_cfb8 "aes-128-cfb8"

#define NID_aes_128_cfb8 653

#define SN_aes_192_cfb8 "AES-192-CFB8"

#define LN_aes_192_cfb8 "aes-192-cfb8"

#define NID_aes_192_cfb8 654

#define SN_aes_256_cfb8 "AES-256-CFB8"

#define LN_aes_256_cfb8 "aes-256-cfb8"

#define NID_aes_256_cfb8 655

#define SN_aes_128_ctr "AES-128-CTR"

#define LN_aes_128_ctr "aes-128-ctr"

#define NID_aes_128_ctr 904

#define SN_aes_192_ctr "AES-192-CTR"

#define LN_aes_192_ctr "aes-192-ctr"

#define NID_aes_192_ctr 905

#define SN_aes_256_ctr "AES-256-CTR"

#define LN_aes_256_ctr "aes-256-ctr"

#define NID_aes_256_ctr 906

#define SN_aes_128_ocb "AES-128-OCB"

#define LN_aes_128_ocb "aes-128-ocb"

#define NID_aes_128_ocb 958

#define SN_aes_192_ocb "AES-192-OCB"

#define LN_aes_192_ocb "aes-192-ocb"

#define NID_aes_192_ocb 959

#define SN_aes_256_ocb "AES-256-OCB"

#define LN_aes_256_ocb "aes-256-ocb"

#define NID_aes_256_ocb 960

#define SN_des_cfb1 "DES-CFB1"

#define LN_des_cfb1 "des-cfb1"

#define NID_des_cfb1 656

#define SN_des_cfb8 "DES-CFB8"

#define LN_des_cfb8 "des-cfb8"

#define NID_des_cfb8 657

#define SN_des_ede3_cfb1 "DES-EDE3-CFB1"

#define LN_des_ede3_cfb1 "des-ede3-cfb1"

#define NID_des_ede3_cfb1 658

#define SN_des_ede3_cfb8 "DES-EDE3-CFB8"

#define LN_des_ede3_cfb8 "des-ede3-cfb8"

#define NID_des_ede3_cfb8 659

#define OBJ_nist_hashalgs OBJ_nistAlgorithms,2L

#define SN_sha256 "SHA256"

#define LN_sha256 "sha256"

#define NID_sha256 672

#define OBJ_sha256 OBJ_nist_hashalgs,1L

#define SN_sha384 "SHA384"

#define LN_sha384 "sha384"

#define NID_sha384 673

#define OBJ_sha384 OBJ_nist_hashalgs,2L

#define SN_sha512 "SHA512"

#define LN_sha512 "sha512"

#define NID_sha512 674

#define OBJ_sha512 OBJ_nist_hashalgs,3L

#define SN_sha224 "SHA224"

#define LN_sha224 "sha224"

#define NID_sha224 675

#define OBJ_sha224 OBJ_nist_hashalgs,4L

#define SN_sha512_224 "SHA512-224"

#define LN_sha512_224 "sha512-224"

#define NID_sha512_224 1094

#define OBJ_sha512_224 OBJ_nist_hashalgs,5L

#define SN_sha512_256 "SHA512-256"

#define LN_sha512_256 "sha512-256"

#define NID_sha512_256 1095

#define OBJ_sha512_256 OBJ_nist_hashalgs,6L

#define SN_sha3_224 "SHA3-224"

#define LN_sha3_224 "sha3-224"

#define NID_sha3_224 1096

#define OBJ_sha3_224 OBJ_nist_hashalgs,7L

#define SN_sha3_256 "SHA3-256"

#define LN_sha3_256 "sha3-256"

#define NID_sha3_256 1097

#define OBJ_sha3_256 OBJ_nist_hashalgs,8L

#define SN_sha3_384 "SHA3-384"

#define LN_sha3_384 "sha3-384"

#define NID_sha3_384 1098

#define OBJ_sha3_384 OBJ_nist_hashalgs,9L

#define SN_sha3_512 "SHA3-512"

#define LN_sha3_512 "sha3-512"

#define NID_sha3_512 1099

#define OBJ_sha3_512 OBJ_nist_hashalgs,10L

#define SN_shake128 "SHAKE128"

#define LN_shake128 "shake128"

#define NID_shake128 1100

#define OBJ_shake128 OBJ_nist_hashalgs,11L

#define SN_shake256 "SHAKE256"

#define LN_shake256 "shake256"

#define NID_shake256 1101

#define OBJ_shake256 OBJ_nist_hashalgs,12L

#define SN_hmac_sha3_224 "id-hmacWithSHA3-224"

#define LN_hmac_sha3_224 "hmac-sha3-224"

#define NID_hmac_sha3_224 1102

#define OBJ_hmac_sha3_224 OBJ_nist_hashalgs,13L

#define SN_hmac_sha3_256 "id-hmacWithSHA3-256"

#define LN_hmac_sha3_256 "hmac-sha3-256"

#define NID_hmac_sha3_256 1103

#define OBJ_hmac_sha3_256 OBJ_nist_hashalgs,14L

#define SN_hmac_sha3_384 "id-hmacWithSHA3-384"

#define LN_hmac_sha3_384 "hmac-sha3-384"

#define NID_hmac_sha3_384 1104

#define OBJ_hmac_sha3_384 OBJ_nist_hashalgs,15L

#define SN_hmac_sha3_512 "id-hmacWithSHA3-512"

#define LN_hmac_sha3_512 "hmac-sha3-512"

#define NID_hmac_sha3_512 1105

#define OBJ_hmac_sha3_512 OBJ_nist_hashalgs,16L

#define SN_kmac128 "KMAC128"

#define LN_kmac128 "kmac128"

#define NID_kmac128 1196

#define OBJ_kmac128 OBJ_nist_hashalgs,19L

#define SN_kmac256 "KMAC256"

#define LN_kmac256 "kmac256"

#define NID_kmac256 1197

#define OBJ_kmac256 OBJ_nist_hashalgs,20L

#define OBJ_dsa_with_sha2 OBJ_nistAlgorithms,3L

#define SN_dsa_with_SHA224 "dsa_with_SHA224"

#define NID_dsa_with_SHA224 802

#define OBJ_dsa_with_SHA224 OBJ_dsa_with_sha2,1L

#define SN_dsa_with_SHA256 "dsa_with_SHA256"

#define NID_dsa_with_SHA256 803

#define OBJ_dsa_with_SHA256 OBJ_dsa_with_sha2,2L

#define OBJ_sigAlgs OBJ_nistAlgorithms,3L

#define SN_dsa_with_SHA384 "id-dsa-with-sha384"

#define LN_dsa_with_SHA384 "dsa_with_SHA384"

#define NID_dsa_with_SHA384 1106

#define OBJ_dsa_with_SHA384 OBJ_sigAlgs,3L

#define SN_dsa_with_SHA512 "id-dsa-with-sha512"

#define LN_dsa_with_SHA512 "dsa_with_SHA512"

#define NID_dsa_with_SHA512 1107

#define OBJ_dsa_with_SHA512 OBJ_sigAlgs,4L

#define SN_dsa_with_SHA3_224 "id-dsa-with-sha3-224"

#define LN_dsa_with_SHA3_224 "dsa_with_SHA3-224"

#define NID_dsa_with_SHA3_224 1108

#define OBJ_dsa_with_SHA3_224 OBJ_sigAlgs,5L

#define SN_dsa_with_SHA3_256 "id-dsa-with-sha3-256"

#define LN_dsa_with_SHA3_256 "dsa_with_SHA3-256"

#define NID_dsa_with_SHA3_256 1109

#define OBJ_dsa_with_SHA3_256 OBJ_sigAlgs,6L

#define SN_dsa_with_SHA3_384 "id-dsa-with-sha3-384"

#define LN_dsa_with_SHA3_384 "dsa_with_SHA3-384"

#define NID_dsa_with_SHA3_384 1110

#define OBJ_dsa_with_SHA3_384 OBJ_sigAlgs,7L

#define SN_dsa_with_SHA3_512 "id-dsa-with-sha3-512"

#define LN_dsa_with_SHA3_512 "dsa_with_SHA3-512"

#define NID_dsa_with_SHA3_512 1111

#define OBJ_dsa_with_SHA3_512 OBJ_sigAlgs,8L

#define SN_ecdsa_with_SHA3_224 "id-ecdsa-with-sha3-224"

#define LN_ecdsa_with_SHA3_224 "ecdsa_with_SHA3-224"

#define NID_ecdsa_with_SHA3_224 1112

#define OBJ_ecdsa_with_SHA3_224 OBJ_sigAlgs,9L

#define SN_ecdsa_with_SHA3_256 "id-ecdsa-with-sha3-256"

#define LN_ecdsa_with_SHA3_256 "ecdsa_with_SHA3-256"

#define NID_ecdsa_with_SHA3_256 1113

#define OBJ_ecdsa_with_SHA3_256 OBJ_sigAlgs,10L

#define SN_ecdsa_with_SHA3_384 "id-ecdsa-with-sha3-384"

#define LN_ecdsa_with_SHA3_384 "ecdsa_with_SHA3-384"

#define NID_ecdsa_with_SHA3_384 1114

#define OBJ_ecdsa_with_SHA3_384 OBJ_sigAlgs,11L

#define SN_ecdsa_with_SHA3_512 "id-ecdsa-with-sha3-512"

#define LN_ecdsa_with_SHA3_512 "ecdsa_with_SHA3-512"

#define NID_ecdsa_with_SHA3_512 1115

#define OBJ_ecdsa_with_SHA3_512 OBJ_sigAlgs,12L

#define SN_RSA_SHA3_224 "id-rsassa-pkcs1-v1_5-with-sha3-224"

#define LN_RSA_SHA3_224 "RSA-SHA3-224"

#define NID_RSA_SHA3_224 1116

#define OBJ_RSA_SHA3_224 OBJ_sigAlgs,13L

#define SN_RSA_SHA3_256 "id-rsassa-pkcs1-v1_5-with-sha3-256"

#define LN_RSA_SHA3_256 "RSA-SHA3-256"

#define NID_RSA_SHA3_256 1117

#define OBJ_RSA_SHA3_256 OBJ_sigAlgs,14L

#define SN_RSA_SHA3_384 "id-rsassa-pkcs1-v1_5-with-sha3-384"

#define LN_RSA_SHA3_384 "RSA-SHA3-384"

#define NID_RSA_SHA3_384 1118

#define OBJ_RSA_SHA3_384 OBJ_sigAlgs,15L

#define SN_RSA_SHA3_512 "id-rsassa-pkcs1-v1_5-with-sha3-512"

#define LN_RSA_SHA3_512 "RSA-SHA3-512"

#define NID_RSA_SHA3_512 1119

#define OBJ_RSA_SHA3_512 OBJ_sigAlgs,16L

#define SN_hold_instruction_code "holdInstructionCode"

#define LN_hold_instruction_code "Hold Instruction Code"

#define NID_hold_instruction_code 430

#define OBJ_hold_instruction_code OBJ_id_ce,23L

#define OBJ_holdInstruction OBJ_X9_57,2L

#define SN_hold_instruction_none "holdInstructionNone"

#define LN_hold_instruction_none "Hold Instruction None"

#define NID_hold_instruction_none 431

#define OBJ_hold_instruction_none OBJ_holdInstruction,1L

#define SN_hold_instruction_call_issuer "holdInstructionCallIssuer"

#define LN_hold_instruction_call_issuer "Hold Instruction Call Issuer"

#define NID_hold_instruction_call_issuer 432

#define OBJ_hold_instruction_call_issuer OBJ_holdInstruction,2L

#define SN_hold_instruction_reject "holdInstructionReject"

#define LN_hold_instruction_reject "Hold Instruction Reject"

#define NID_hold_instruction_reject 433

#define OBJ_hold_instruction_reject OBJ_holdInstruction,3L

#define SN_itu_t_identified_organization "itu-t-identified-organization"

#define NID_itu_t_identified_organization 1264

#define OBJ_itu_t_identified_organization OBJ_itu_t,4L

#define SN_etsi "etsi"

#define NID_etsi 1265

#define OBJ_etsi OBJ_itu_t_identified_organization,0L

#define SN_electronic_signature_standard "electronic-signature-standard"

#define NID_electronic_signature_standard 1266

#define OBJ_electronic_signature_standard OBJ_etsi,1733L

#define SN_ess_attributes "ess-attributes"

#define NID_ess_attributes 1267

#define OBJ_ess_attributes OBJ_electronic_signature_standard,2L

#define SN_id_aa_ets_mimeType "id-aa-ets-mimeType"

#define NID_id_aa_ets_mimeType 1268

#define OBJ_id_aa_ets_mimeType OBJ_ess_attributes,1L

#define SN_id_aa_ets_longTermValidation "id-aa-ets-longTermValidation"

#define NID_id_aa_ets_longTermValidation 1269

#define OBJ_id_aa_ets_longTermValidation OBJ_ess_attributes,2L

#define SN_id_aa_ets_SignaturePolicyDocument "id-aa-ets-SignaturePolicyDocument"

#define NID_id_aa_ets_SignaturePolicyDocument 1270

#define OBJ_id_aa_ets_SignaturePolicyDocument OBJ_ess_attributes,3L

#define SN_id_aa_ets_archiveTimestampV3 "id-aa-ets-archiveTimestampV3"

#define NID_id_aa_ets_archiveTimestampV3 1271

#define OBJ_id_aa_ets_archiveTimestampV3 OBJ_ess_attributes,4L

#define SN_id_aa_ATSHashIndex "id-aa-ATSHashIndex"

#define NID_id_aa_ATSHashIndex 1272

#define OBJ_id_aa_ATSHashIndex OBJ_ess_attributes,5L

#define SN_cades "cades"

#define NID_cades 1273

#define OBJ_cades OBJ_etsi,19122L

#define SN_cades_attributes "cades-attributes"

#define NID_cades_attributes 1274

#define OBJ_cades_attributes OBJ_cades,1L

#define SN_id_aa_ets_signerAttrV2 "id-aa-ets-signerAttrV2"

#define NID_id_aa_ets_signerAttrV2 1275

#define OBJ_id_aa_ets_signerAttrV2 OBJ_cades_attributes,1L

#define SN_id_aa_ets_sigPolicyStore "id-aa-ets-sigPolicyStore"

#define NID_id_aa_ets_sigPolicyStore 1276

#define OBJ_id_aa_ets_sigPolicyStore OBJ_cades_attributes,3L

#define SN_id_aa_ATSHashIndex_v2 "id-aa-ATSHashIndex-v2"

#define NID_id_aa_ATSHashIndex_v2 1277

#define OBJ_id_aa_ATSHashIndex_v2 OBJ_cades_attributes,4L

#define SN_id_aa_ATSHashIndex_v3 "id-aa-ATSHashIndex-v3"

#define NID_id_aa_ATSHashIndex_v3 1278

#define OBJ_id_aa_ATSHashIndex_v3 OBJ_cades_attributes,5L

#define SN_signedAssertion "signedAssertion"

#define NID_signedAssertion 1279

#define OBJ_signedAssertion OBJ_cades_attributes,6L

#define SN_data "data"

#define NID_data 434

#define OBJ_data OBJ_itu_t,9L

#define SN_pss "pss"

#define NID_pss 435

#define OBJ_pss OBJ_data,2342L

#define SN_ucl "ucl"

#define NID_ucl 436

#define OBJ_ucl OBJ_pss,19200300L

#define SN_pilot "pilot"

#define NID_pilot 437

#define OBJ_pilot OBJ_ucl,100L

#define LN_pilotAttributeType "pilotAttributeType"

#define NID_pilotAttributeType 438

#define OBJ_pilotAttributeType OBJ_pilot,1L

#define LN_pilotAttributeSyntax "pilotAttributeSyntax"

#define NID_pilotAttributeSyntax 439

#define OBJ_pilotAttributeSyntax OBJ_pilot,3L

#define LN_pilotObjectClass "pilotObjectClass"

#define NID_pilotObjectClass 440

#define OBJ_pilotObjectClass OBJ_pilot,4L

#define LN_pilotGroups "pilotGroups"

#define NID_pilotGroups 441

#define OBJ_pilotGroups OBJ_pilot,10L

#define LN_iA5StringSyntax "iA5StringSyntax"

#define NID_iA5StringSyntax 442

#define OBJ_iA5StringSyntax OBJ_pilotAttributeSyntax,4L

#define LN_caseIgnoreIA5StringSyntax "caseIgnoreIA5StringSyntax"

#define NID_caseIgnoreIA5StringSyntax 443

#define OBJ_caseIgnoreIA5StringSyntax OBJ_pilotAttributeSyntax,5L

#define LN_pilotObject "pilotObject"

#define NID_pilotObject 444

#define OBJ_pilotObject OBJ_pilotObjectClass,3L

#define LN_pilotPerson "pilotPerson"

#define NID_pilotPerson 445

#define OBJ_pilotPerson OBJ_pilotObjectClass,4L

#define SN_account "account"

#define NID_account 446

#define OBJ_account OBJ_pilotObjectClass,5L

#define SN_document "document"

#define NID_document 447

#define OBJ_document OBJ_pilotObjectClass,6L

#define SN_room "room"

#define NID_room 448

#define OBJ_room OBJ_pilotObjectClass,7L

#define LN_documentSeries "documentSeries"

#define NID_documentSeries 449

#define OBJ_documentSeries OBJ_pilotObjectClass,9L

#define SN_Domain "domain"

#define LN_Domain "Domain"

#define NID_Domain 392

#define OBJ_Domain OBJ_pilotObjectClass,13L

#define LN_rFC822localPart "rFC822localPart"

#define NID_rFC822localPart 450

#define OBJ_rFC822localPart OBJ_pilotObjectClass,14L

#define LN_dNSDomain "dNSDomain"

#define NID_dNSDomain 451

#define OBJ_dNSDomain OBJ_pilotObjectClass,15L

#define LN_domainRelatedObject "domainRelatedObject"

#define NID_domainRelatedObject 452

#define OBJ_domainRelatedObject OBJ_pilotObjectClass,17L

#define LN_friendlyCountry "friendlyCountry"

#define NID_friendlyCountry 453

#define OBJ_friendlyCountry OBJ_pilotObjectClass,18L

#define LN_simpleSecurityObject "simpleSecurityObject"

#define NID_simpleSecurityObject 454

#define OBJ_simpleSecurityObject OBJ_pilotObjectClass,19L

#define LN_pilotOrganization "pilotOrganization"

#define NID_pilotOrganization 455

#define OBJ_pilotOrganization OBJ_pilotObjectClass,20L

#define LN_pilotDSA "pilotDSA"

#define NID_pilotDSA 456

#define OBJ_pilotDSA OBJ_pilotObjectClass,21L

#define LN_qualityLabelledData "qualityLabelledData"

#define NID_qualityLabelledData 457

#define OBJ_qualityLabelledData OBJ_pilotObjectClass,22L

#define SN_userId "UID"

#define LN_userId "userId"

#define NID_userId 458

#define OBJ_userId OBJ_pilotAttributeType,1L

#define LN_textEncodedORAddress "textEncodedORAddress"

#define NID_textEncodedORAddress 459

#define OBJ_textEncodedORAddress OBJ_pilotAttributeType,2L

#define SN_rfc822Mailbox "mail"

#define LN_rfc822Mailbox "rfc822Mailbox"

#define NID_rfc822Mailbox 460

#define OBJ_rfc822Mailbox OBJ_pilotAttributeType,3L

#define SN_info "info"

#define NID_info 461

#define OBJ_info OBJ_pilotAttributeType,4L

#define LN_favouriteDrink "favouriteDrink"

#define NID_favouriteDrink 462

#define OBJ_favouriteDrink OBJ_pilotAttributeType,5L

#define LN_roomNumber "roomNumber"

#define NID_roomNumber 463

#define OBJ_roomNumber OBJ_pilotAttributeType,6L

#define SN_photo "photo"

#define NID_photo 464

#define OBJ_photo OBJ_pilotAttributeType,7L

#define LN_userClass "userClass"

#define NID_userClass 465

#define OBJ_userClass OBJ_pilotAttributeType,8L

#define SN_host "host"

#define NID_host 466

#define OBJ_host OBJ_pilotAttributeType,9L

#define SN_manager "manager"

#define NID_manager 467

#define OBJ_manager OBJ_pilotAttributeType,10L

#define LN_documentIdentifier "documentIdentifier"

#define NID_documentIdentifier 468

#define OBJ_documentIdentifier OBJ_pilotAttributeType,11L

#define LN_documentTitle "documentTitle"

#define NID_documentTitle 469

#define OBJ_documentTitle OBJ_pilotAttributeType,12L

#define LN_documentVersion "documentVersion"

#define NID_documentVersion 470

#define OBJ_documentVersion OBJ_pilotAttributeType,13L

#define LN_documentAuthor "documentAuthor"

#define NID_documentAuthor 471

#define OBJ_documentAuthor OBJ_pilotAttributeType,14L

#define LN_documentLocation "documentLocation"

#define NID_documentLocation 472

#define OBJ_documentLocation OBJ_pilotAttributeType,15L

#define LN_homeTelephoneNumber "homeTelephoneNumber"

#define NID_homeTelephoneNumber 473

#define OBJ_homeTelephoneNumber OBJ_pilotAttributeType,20L

#define SN_secretary "secretary"

#define NID_secretary 474

#define OBJ_secretary OBJ_pilotAttributeType,21L

#define LN_otherMailbox "otherMailbox"

#define NID_otherMailbox 475

#define OBJ_otherMailbox OBJ_pilotAttributeType,22L

#define LN_lastModifiedTime "lastModifiedTime"

#define NID_lastModifiedTime 476

#define OBJ_lastModifiedTime OBJ_pilotAttributeType,23L

#define LN_lastModifiedBy "lastModifiedBy"

#define NID_lastModifiedBy 477

#define OBJ_lastModifiedBy OBJ_pilotAttributeType,24L

#define SN_domainComponent "DC"

#define LN_domainComponent "domainComponent"

#define NID_domainComponent 391

#define OBJ_domainComponent OBJ_pilotAttributeType,25L

#define LN_aRecord "aRecord"

#define NID_aRecord 478

#define OBJ_aRecord OBJ_pilotAttributeType,26L

#define LN_pilotAttributeType27 "pilotAttributeType27"

#define NID_pilotAttributeType27 479

#define OBJ_pilotAttributeType27 OBJ_pilotAttributeType,27L

#define LN_mXRecord "mXRecord"

#define NID_mXRecord 480

#define OBJ_mXRecord OBJ_pilotAttributeType,28L

#define LN_nSRecord "nSRecord"

#define NID_nSRecord 481

#define OBJ_nSRecord OBJ_pilotAttributeType,29L

#define LN_sOARecord "sOARecord"

#define NID_sOARecord 482

#define OBJ_sOARecord OBJ_pilotAttributeType,30L

#define LN_cNAMERecord "cNAMERecord"

#define NID_cNAMERecord 483

#define OBJ_cNAMERecord OBJ_pilotAttributeType,31L

#define LN_associatedDomain "associatedDomain"

#define NID_associatedDomain 484

#define OBJ_associatedDomain OBJ_pilotAttributeType,37L

#define LN_associatedName "associatedName"

#define NID_associatedName 485

#define OBJ_associatedName OBJ_pilotAttributeType,38L

#define LN_homePostalAddress "homePostalAddress"

#define NID_homePostalAddress 486

#define OBJ_homePostalAddress OBJ_pilotAttributeType,39L

#define LN_personalTitle "personalTitle"

#define NID_personalTitle 487

#define OBJ_personalTitle OBJ_pilotAttributeType,40L

#define LN_mobileTelephoneNumber "mobileTelephoneNumber"

#define NID_mobileTelephoneNumber 488

#define OBJ_mobileTelephoneNumber OBJ_pilotAttributeType,41L

#define LN_pagerTelephoneNumber "pagerTelephoneNumber"

#define NID_pagerTelephoneNumber 489

#define OBJ_pagerTelephoneNumber OBJ_pilotAttributeType,42L

#define LN_friendlyCountryName "friendlyCountryName"

#define NID_friendlyCountryName 490

#define OBJ_friendlyCountryName OBJ_pilotAttributeType,43L

#define SN_uniqueIdentifier "uid"

#define LN_uniqueIdentifier "uniqueIdentifier"

#define NID_uniqueIdentifier 102

#define OBJ_uniqueIdentifier OBJ_pilotAttributeType,44L

#define LN_organizationalStatus "organizationalStatus"

#define NID_organizationalStatus 491

#define OBJ_organizationalStatus OBJ_pilotAttributeType,45L

#define LN_janetMailbox "janetMailbox"

#define NID_janetMailbox 492

#define OBJ_janetMailbox OBJ_pilotAttributeType,46L

#define LN_mailPreferenceOption "mailPreferenceOption"

#define NID_mailPreferenceOption 493

#define OBJ_mailPreferenceOption OBJ_pilotAttributeType,47L

#define LN_buildingName "buildingName"

#define NID_buildingName 494

#define OBJ_buildingName OBJ_pilotAttributeType,48L

#define LN_dSAQuality "dSAQuality"

#define NID_dSAQuality 495

#define OBJ_dSAQuality OBJ_pilotAttributeType,49L

#define LN_singleLevelQuality "singleLevelQuality"

#define NID_singleLevelQuality 496

#define OBJ_singleLevelQuality OBJ_pilotAttributeType,50L

#define LN_subtreeMinimumQuality "subtreeMinimumQuality"

#define NID_subtreeMinimumQuality 497

#define OBJ_subtreeMinimumQuality OBJ_pilotAttributeType,51L

#define LN_subtreeMaximumQuality "subtreeMaximumQuality"

#define NID_subtreeMaximumQuality 498

#define OBJ_subtreeMaximumQuality OBJ_pilotAttributeType,52L

#define LN_personalSignature "personalSignature"

#define NID_personalSignature 499

#define OBJ_personalSignature OBJ_pilotAttributeType,53L

#define LN_dITRedirect "dITRedirect"

#define NID_dITRedirect 500

#define OBJ_dITRedirect OBJ_pilotAttributeType,54L

#define SN_audio "audio"

#define NID_audio 501

#define OBJ_audio OBJ_pilotAttributeType,55L

#define LN_documentPublisher "documentPublisher"

#define NID_documentPublisher 502

#define OBJ_documentPublisher OBJ_pilotAttributeType,56L

#define SN_id_set "id-set"

#define LN_id_set "Secure Electronic Transactions"

#define NID_id_set 512

#define OBJ_id_set OBJ_international_organizations,42L

#define SN_set_ctype "set-ctype"

#define LN_set_ctype "content types"

#define NID_set_ctype 513

#define OBJ_set_ctype OBJ_id_set,0L

#define SN_set_msgExt "set-msgExt"

#define LN_set_msgExt "message extensions"

#define NID_set_msgExt 514

#define OBJ_set_msgExt OBJ_id_set,1L

#define SN_set_attr "set-attr"

#define NID_set_attr 515

#define OBJ_set_attr OBJ_id_set,3L

#define SN_set_policy "set-policy"

#define NID_set_policy 516

#define OBJ_set_policy OBJ_id_set,5L

#define SN_set_certExt "set-certExt"

#define LN_set_certExt "certificate extensions"

#define NID_set_certExt 517

#define OBJ_set_certExt OBJ_id_set,7L

#define SN_set_brand "set-brand"

#define NID_set_brand 518

#define OBJ_set_brand OBJ_id_set,8L

#define SN_setct_PANData "setct-PANData"

#define NID_setct_PANData 519

#define OBJ_setct_PANData OBJ_set_ctype,0L

#define SN_setct_PANToken "setct-PANToken"

#define NID_setct_PANToken 520

#define OBJ_setct_PANToken OBJ_set_ctype,1L

#define SN_setct_PANOnly "setct-PANOnly"

#define NID_setct_PANOnly 521

#define OBJ_setct_PANOnly OBJ_set_ctype,2L

#define SN_setct_OIData "setct-OIData"

#define NID_setct_OIData 522

#define OBJ_setct_OIData OBJ_set_ctype,3L

#define SN_setct_PI "setct-PI"

#define NID_setct_PI 523

#define OBJ_setct_PI OBJ_set_ctype,4L

#define SN_setct_PIData "setct-PIData"

#define NID_setct_PIData 524

#define OBJ_setct_PIData OBJ_set_ctype,5L

#define SN_setct_PIDataUnsigned "setct-PIDataUnsigned"

#define NID_setct_PIDataUnsigned 525

#define OBJ_setct_PIDataUnsigned OBJ_set_ctype,6L

#define SN_setct_HODInput "setct-HODInput"

#define NID_setct_HODInput 526

#define OBJ_setct_HODInput OBJ_set_ctype,7L

#define SN_setct_AuthResBaggage "setct-AuthResBaggage"

#define NID_setct_AuthResBaggage 527

#define OBJ_setct_AuthResBaggage OBJ_set_ctype,8L

#define SN_setct_AuthRevReqBaggage "setct-AuthRevReqBaggage"

#define NID_setct_AuthRevReqBaggage 528

#define OBJ_setct_AuthRevReqBaggage OBJ_set_ctype,9L

#define SN_setct_AuthRevResBaggage "setct-AuthRevResBaggage"

#define NID_setct_AuthRevResBaggage 529

#define OBJ_setct_AuthRevResBaggage OBJ_set_ctype,10L

#define SN_setct_CapTokenSeq "setct-CapTokenSeq"

#define NID_setct_CapTokenSeq 530

#define OBJ_setct_CapTokenSeq OBJ_set_ctype,11L

#define SN_setct_PInitResData "setct-PInitResData"

#define NID_setct_PInitResData 531

#define OBJ_setct_PInitResData OBJ_set_ctype,12L

#define SN_setct_PI_TBS "setct-PI-TBS"

#define NID_setct_PI_TBS 532

#define OBJ_setct_PI_TBS OBJ_set_ctype,13L

#define SN_setct_PResData "setct-PResData"

#define NID_setct_PResData 533

#define OBJ_setct_PResData OBJ_set_ctype,14L

#define SN_setct_AuthReqTBS "setct-AuthReqTBS"

#define NID_setct_AuthReqTBS 534

#define OBJ_setct_AuthReqTBS OBJ_set_ctype,16L

#define SN_setct_AuthResTBS "setct-AuthResTBS"

#define NID_setct_AuthResTBS 535

#define OBJ_setct_AuthResTBS OBJ_set_ctype,17L

#define SN_setct_AuthResTBSX "setct-AuthResTBSX"

#define NID_setct_AuthResTBSX 536

#define OBJ_setct_AuthResTBSX OBJ_set_ctype,18L

#define SN_setct_AuthTokenTBS "setct-AuthTokenTBS"

#define NID_setct_AuthTokenTBS 537

#define OBJ_setct_AuthTokenTBS OBJ_set_ctype,19L

#define SN_setct_CapTokenData "setct-CapTokenData"

#define NID_setct_CapTokenData 538

#define OBJ_setct_CapTokenData OBJ_set_ctype,20L

#define SN_setct_CapTokenTBS "setct-CapTokenTBS"

#define NID_setct_CapTokenTBS 539

#define OBJ_setct_CapTokenTBS OBJ_set_ctype,21L

#define SN_setct_AcqCardCodeMsg "setct-AcqCardCodeMsg"

#define NID_setct_AcqCardCodeMsg 540

#define OBJ_setct_AcqCardCodeMsg OBJ_set_ctype,22L

#define SN_setct_AuthRevReqTBS "setct-AuthRevReqTBS"

#define NID_setct_AuthRevReqTBS 541

#define OBJ_setct_AuthRevReqTBS OBJ_set_ctype,23L

#define SN_setct_AuthRevResData "setct-AuthRevResData"

#define NID_setct_AuthRevResData 542

#define OBJ_setct_AuthRevResData OBJ_set_ctype,24L

#define SN_setct_AuthRevResTBS "setct-AuthRevResTBS"

#define NID_setct_AuthRevResTBS 543

#define OBJ_setct_AuthRevResTBS OBJ_set_ctype,25L

#define SN_setct_CapReqTBS "setct-CapReqTBS"

#define NID_setct_CapReqTBS 544

#define OBJ_setct_CapReqTBS OBJ_set_ctype,26L

#define SN_setct_CapReqTBSX "setct-CapReqTBSX"

#define NID_setct_CapReqTBSX 545

#define OBJ_setct_CapReqTBSX OBJ_set_ctype,27L

#define SN_setct_CapResData "setct-CapResData"

#define NID_setct_CapResData 546

#define OBJ_setct_CapResData OBJ_set_ctype,28L

#define SN_setct_CapRevReqTBS "setct-CapRevReqTBS"

#define NID_setct_CapRevReqTBS 547

#define OBJ_setct_CapRevReqTBS OBJ_set_ctype,29L

#define SN_setct_CapRevReqTBSX "setct-CapRevReqTBSX"

#define NID_setct_CapRevReqTBSX 548

#define OBJ_setct_CapRevReqTBSX OBJ_set_ctype,30L

#define SN_setct_CapRevResData "setct-CapRevResData"

#define NID_setct_CapRevResData 549

#define OBJ_setct_CapRevResData OBJ_set_ctype,31L

#define SN_setct_CredReqTBS "setct-CredReqTBS"

#define NID_setct_CredReqTBS 550

#define OBJ_setct_CredReqTBS OBJ_set_ctype,32L

#define SN_setct_CredReqTBSX "setct-CredReqTBSX"

#define NID_setct_CredReqTBSX 551

#define OBJ_setct_CredReqTBSX OBJ_set_ctype,33L

#define SN_setct_CredResData "setct-CredResData"

#define NID_setct_CredResData 552

#define OBJ_setct_CredResData OBJ_set_ctype,34L

#define SN_setct_CredRevReqTBS "setct-CredRevReqTBS"

#define NID_setct_CredRevReqTBS 553

#define OBJ_setct_CredRevReqTBS OBJ_set_ctype,35L

#define SN_setct_CredRevReqTBSX "setct-CredRevReqTBSX"

#define NID_setct_CredRevReqTBSX 554

#define OBJ_setct_CredRevReqTBSX OBJ_set_ctype,36L

#define SN_setct_CredRevResData "setct-CredRevResData"

#define NID_setct_CredRevResData 555

#define OBJ_setct_CredRevResData OBJ_set_ctype,37L

#define SN_setct_PCertReqData "setct-PCertReqData"

#define NID_setct_PCertReqData 556

#define OBJ_setct_PCertReqData OBJ_set_ctype,38L

#define SN_setct_PCertResTBS "setct-PCertResTBS"

#define NID_setct_PCertResTBS 557

#define OBJ_setct_PCertResTBS OBJ_set_ctype,39L

#define SN_setct_BatchAdminReqData "setct-BatchAdminReqData"

#define NID_setct_BatchAdminReqData 558

#define OBJ_setct_BatchAdminReqData OBJ_set_ctype,40L

#define SN_setct_BatchAdminResData "setct-BatchAdminResData"

#define NID_setct_BatchAdminResData 559

#define OBJ_setct_BatchAdminResData OBJ_set_ctype,41L

#define SN_setct_CardCInitResTBS "setct-CardCInitResTBS"

#define NID_setct_CardCInitResTBS 560

#define OBJ_setct_CardCInitResTBS OBJ_set_ctype,42L

#define SN_setct_MeAqCInitResTBS "setct-MeAqCInitResTBS"

#define NID_setct_MeAqCInitResTBS 561

#define OBJ_setct_MeAqCInitResTBS OBJ_set_ctype,43L

#define SN_setct_RegFormResTBS "setct-RegFormResTBS"

#define NID_setct_RegFormResTBS 562

#define OBJ_setct_RegFormResTBS OBJ_set_ctype,44L

#define SN_setct_CertReqData "setct-CertReqData"

#define NID_setct_CertReqData 563

#define OBJ_setct_CertReqData OBJ_set_ctype,45L

#define SN_setct_CertReqTBS "setct-CertReqTBS"

#define NID_setct_CertReqTBS 564

#define OBJ_setct_CertReqTBS OBJ_set_ctype,46L

#define SN_setct_CertResData "setct-CertResData"

#define NID_setct_CertResData 565

#define OBJ_setct_CertResData OBJ_set_ctype,47L

#define SN_setct_CertInqReqTBS "setct-CertInqReqTBS"

#define NID_setct_CertInqReqTBS 566

#define OBJ_setct_CertInqReqTBS OBJ_set_ctype,48L

#define SN_setct_ErrorTBS "setct-ErrorTBS"

#define NID_setct_ErrorTBS 567

#define OBJ_setct_ErrorTBS OBJ_set_ctype,49L

#define SN_setct_PIDualSignedTBE "setct-PIDualSignedTBE"

#define NID_setct_PIDualSignedTBE 568

#define OBJ_setct_PIDualSignedTBE OBJ_set_ctype,50L

#define SN_setct_PIUnsignedTBE "setct-PIUnsignedTBE"

#define NID_setct_PIUnsignedTBE 569

#define OBJ_setct_PIUnsignedTBE OBJ_set_ctype,51L

#define SN_setct_AuthReqTBE "setct-AuthReqTBE"

#define NID_setct_AuthReqTBE 570

#define OBJ_setct_AuthReqTBE OBJ_set_ctype,52L

#define SN_setct_AuthResTBE "setct-AuthResTBE"

#define NID_setct_AuthResTBE 571

#define OBJ_setct_AuthResTBE OBJ_set_ctype,53L

#define SN_setct_AuthResTBEX "setct-AuthResTBEX"

#define NID_setct_AuthResTBEX 572

#define OBJ_setct_AuthResTBEX OBJ_set_ctype,54L

#define SN_setct_AuthTokenTBE "setct-AuthTokenTBE"

#define NID_setct_AuthTokenTBE 573

#define OBJ_setct_AuthTokenTBE OBJ_set_ctype,55L

#define SN_setct_CapTokenTBE "setct-CapTokenTBE"

#define NID_setct_CapTokenTBE 574

#define OBJ_setct_CapTokenTBE OBJ_set_ctype,56L

#define SN_setct_CapTokenTBEX "setct-CapTokenTBEX"

#define NID_setct_CapTokenTBEX 575

#define OBJ_setct_CapTokenTBEX OBJ_set_ctype,57L

#define SN_setct_AcqCardCodeMsgTBE "setct-AcqCardCodeMsgTBE"

#define NID_setct_AcqCardCodeMsgTBE 576

#define OBJ_setct_AcqCardCodeMsgTBE OBJ_set_ctype,58L

#define SN_setct_AuthRevReqTBE "setct-AuthRevReqTBE"

#define NID_setct_AuthRevReqTBE 577

#define OBJ_setct_AuthRevReqTBE OBJ_set_ctype,59L

#define SN_setct_AuthRevResTBE "setct-AuthRevResTBE"

#define NID_setct_AuthRevResTBE 578

#define OBJ_setct_AuthRevResTBE OBJ_set_ctype,60L

#define SN_setct_AuthRevResTBEB "setct-AuthRevResTBEB"

#define NID_setct_AuthRevResTBEB 579

#define OBJ_setct_AuthRevResTBEB OBJ_set_ctype,61L

#define SN_setct_CapReqTBE "setct-CapReqTBE"

#define NID_setct_CapReqTBE 580

#define OBJ_setct_CapReqTBE OBJ_set_ctype,62L

#define SN_setct_CapReqTBEX "setct-CapReqTBEX"

#define NID_setct_CapReqTBEX 581

#define OBJ_setct_CapReqTBEX OBJ_set_ctype,63L

#define SN_setct_CapResTBE "setct-CapResTBE"

#define NID_setct_CapResTBE 582

#define OBJ_setct_CapResTBE OBJ_set_ctype,64L

#define SN_setct_CapRevReqTBE "setct-CapRevReqTBE"

#define NID_setct_CapRevReqTBE 583

#define OBJ_setct_CapRevReqTBE OBJ_set_ctype,65L

#define SN_setct_CapRevReqTBEX "setct-CapRevReqTBEX"

#define NID_setct_CapRevReqTBEX 584

#define OBJ_setct_CapRevReqTBEX OBJ_set_ctype,66L

#define SN_setct_CapRevResTBE "setct-CapRevResTBE"

#define NID_setct_CapRevResTBE 585

#define OBJ_setct_CapRevResTBE OBJ_set_ctype,67L

#define SN_setct_CredReqTBE "setct-CredReqTBE"

#define NID_setct_CredReqTBE 586

#define OBJ_setct_CredReqTBE OBJ_set_ctype,68L

#define SN_setct_CredReqTBEX "setct-CredReqTBEX"

#define NID_setct_CredReqTBEX 587

#define OBJ_setct_CredReqTBEX OBJ_set_ctype,69L

#define SN_setct_CredResTBE "setct-CredResTBE"

#define NID_setct_CredResTBE 588

#define OBJ_setct_CredResTBE OBJ_set_ctype,70L

#define SN_setct_CredRevReqTBE "setct-CredRevReqTBE"

#define NID_setct_CredRevReqTBE 589

#define OBJ_setct_CredRevReqTBE OBJ_set_ctype,71L

#define SN_setct_CredRevReqTBEX "setct-CredRevReqTBEX"

#define NID_setct_CredRevReqTBEX 590

#define OBJ_setct_CredRevReqTBEX OBJ_set_ctype,72L

#define SN_setct_CredRevResTBE "setct-CredRevResTBE"

#define NID_setct_CredRevResTBE 591

#define OBJ_setct_CredRevResTBE OBJ_set_ctype,73L

#define SN_setct_BatchAdminReqTBE "setct-BatchAdminReqTBE"

#define NID_setct_BatchAdminReqTBE 592

#define OBJ_setct_BatchAdminReqTBE OBJ_set_ctype,74L

#define SN_setct_BatchAdminResTBE "setct-BatchAdminResTBE"

#define NID_setct_BatchAdminResTBE 593

#define OBJ_setct_BatchAdminResTBE OBJ_set_ctype,75L

#define SN_setct_RegFormReqTBE "setct-RegFormReqTBE"

#define NID_setct_RegFormReqTBE 594

#define OBJ_setct_RegFormReqTBE OBJ_set_ctype,76L

#define SN_setct_CertReqTBE "setct-CertReqTBE"

#define NID_setct_CertReqTBE 595

#define OBJ_setct_CertReqTBE OBJ_set_ctype,77L

#define SN_setct_CertReqTBEX "setct-CertReqTBEX"

#define NID_setct_CertReqTBEX 596

#define OBJ_setct_CertReqTBEX OBJ_set_ctype,78L

#define SN_setct_CertResTBE "setct-CertResTBE"

#define NID_setct_CertResTBE 597

#define OBJ_setct_CertResTBE OBJ_set_ctype,79L

#define SN_setct_CRLNotificationTBS "setct-CRLNotificationTBS"

#define NID_setct_CRLNotificationTBS 598

#define OBJ_setct_CRLNotificationTBS OBJ_set_ctype,80L

#define SN_setct_CRLNotificationResTBS "setct-CRLNotificationResTBS"

#define NID_setct_CRLNotificationResTBS 599

#define OBJ_setct_CRLNotificationResTBS OBJ_set_ctype,81L

#define SN_setct_BCIDistributionTBS "setct-BCIDistributionTBS"

#define NID_setct_BCIDistributionTBS 600

#define OBJ_setct_BCIDistributionTBS OBJ_set_ctype,82L

#define SN_setext_genCrypt "setext-genCrypt"

#define LN_setext_genCrypt "generic cryptogram"

#define NID_setext_genCrypt 601

#define OBJ_setext_genCrypt OBJ_set_msgExt,1L

#define SN_setext_miAuth "setext-miAuth"

#define LN_setext_miAuth "merchant initiated auth"

#define NID_setext_miAuth 602

#define OBJ_setext_miAuth OBJ_set_msgExt,3L

#define SN_setext_pinSecure "setext-pinSecure"

#define NID_setext_pinSecure 603

#define OBJ_setext_pinSecure OBJ_set_msgExt,4L

#define SN_setext_pinAny "setext-pinAny"

#define NID_setext_pinAny 604

#define OBJ_setext_pinAny OBJ_set_msgExt,5L

#define SN_setext_track2 "setext-track2"

#define NID_setext_track2 605

#define OBJ_setext_track2 OBJ_set_msgExt,7L

#define SN_setext_cv "setext-cv"

#define LN_setext_cv "additional verification"

#define NID_setext_cv 606

#define OBJ_setext_cv OBJ_set_msgExt,8L

#define SN_set_policy_root "set-policy-root"

#define NID_set_policy_root 607

#define OBJ_set_policy_root OBJ_set_policy,0L

#define SN_setCext_hashedRoot "setCext-hashedRoot"

#define NID_setCext_hashedRoot 608

#define OBJ_setCext_hashedRoot OBJ_set_certExt,0L

#define SN_setCext_certType "setCext-certType"

#define NID_setCext_certType 609

#define OBJ_setCext_certType OBJ_set_certExt,1L

#define SN_setCext_merchData "setCext-merchData"

#define NID_setCext_merchData 610

#define OBJ_setCext_merchData OBJ_set_certExt,2L

#define SN_setCext_cCertRequired "setCext-cCertRequired"

#define NID_setCext_cCertRequired 611

#define OBJ_setCext_cCertRequired OBJ_set_certExt,3L

#define SN_setCext_tunneling "setCext-tunneling"

#define NID_setCext_tunneling 612

#define OBJ_setCext_tunneling OBJ_set_certExt,4L

#define SN_setCext_setExt "setCext-setExt"

#define NID_setCext_setExt 613

#define OBJ_setCext_setExt OBJ_set_certExt,5L

#define SN_setCext_setQualf "setCext-setQualf"

#define NID_setCext_setQualf 614

#define OBJ_setCext_setQualf OBJ_set_certExt,6L

#define SN_setCext_PGWYcapabilities "setCext-PGWYcapabilities"

#define NID_setCext_PGWYcapabilities 615

#define OBJ_setCext_PGWYcapabilities OBJ_set_certExt,7L

#define SN_setCext_TokenIdentifier "setCext-TokenIdentifier"

#define NID_setCext_TokenIdentifier 616

#define OBJ_setCext_TokenIdentifier OBJ_set_certExt,8L

#define SN_setCext_Track2Data "setCext-Track2Data"

#define NID_setCext_Track2Data 617

#define OBJ_setCext_Track2Data OBJ_set_certExt,9L

#define SN_setCext_TokenType "setCext-TokenType"

#define NID_setCext_TokenType 618

#define OBJ_setCext_TokenType OBJ_set_certExt,10L

#define SN_setCext_IssuerCapabilities "setCext-IssuerCapabilities"

#define NID_setCext_IssuerCapabilities 619

#define OBJ_setCext_IssuerCapabilities OBJ_set_certExt,11L

#define SN_setAttr_Cert "setAttr-Cert"

#define NID_setAttr_Cert 620

#define OBJ_setAttr_Cert OBJ_set_attr,0L

#define SN_setAttr_PGWYcap "setAttr-PGWYcap"

#define LN_setAttr_PGWYcap "payment gateway capabilities"

#define NID_setAttr_PGWYcap 621

#define OBJ_setAttr_PGWYcap OBJ_set_attr,1L

#define SN_setAttr_TokenType "setAttr-TokenType"

#define NID_setAttr_TokenType 622

#define OBJ_setAttr_TokenType OBJ_set_attr,2L

#define SN_setAttr_IssCap "setAttr-IssCap"

#define LN_setAttr_IssCap "issuer capabilities"

#define NID_setAttr_IssCap 623

#define OBJ_setAttr_IssCap OBJ_set_attr,3L

#define SN_set_rootKeyThumb "set-rootKeyThumb"

#define NID_set_rootKeyThumb 624

#define OBJ_set_rootKeyThumb OBJ_setAttr_Cert,0L

#define SN_set_addPolicy "set-addPolicy"

#define NID_set_addPolicy 625

#define OBJ_set_addPolicy OBJ_setAttr_Cert,1L

#define SN_setAttr_Token_EMV "setAttr-Token-EMV"

#define NID_setAttr_Token_EMV 626

#define OBJ_setAttr_Token_EMV OBJ_setAttr_TokenType,1L

#define SN_setAttr_Token_B0Prime "setAttr-Token-B0Prime"

#define NID_setAttr_Token_B0Prime 627

#define OBJ_setAttr_Token_B0Prime OBJ_setAttr_TokenType,2L

#define SN_setAttr_IssCap_CVM "setAttr-IssCap-CVM"

#define NID_setAttr_IssCap_CVM 628

#define OBJ_setAttr_IssCap_CVM OBJ_setAttr_IssCap,3L

#define SN_setAttr_IssCap_T2 "setAttr-IssCap-T2"

#define NID_setAttr_IssCap_T2 629

#define OBJ_setAttr_IssCap_T2 OBJ_setAttr_IssCap,4L

#define SN_setAttr_IssCap_Sig "setAttr-IssCap-Sig"

#define NID_setAttr_IssCap_Sig 630

#define OBJ_setAttr_IssCap_Sig OBJ_setAttr_IssCap,5L

#define SN_setAttr_GenCryptgrm "setAttr-GenCryptgrm"

#define LN_setAttr_GenCryptgrm "generate cryptogram"

#define NID_setAttr_GenCryptgrm 631

#define OBJ_setAttr_GenCryptgrm OBJ_setAttr_IssCap_CVM,1L

#define SN_setAttr_T2Enc "setAttr-T2Enc"

#define LN_setAttr_T2Enc "encrypted track 2"

#define NID_setAttr_T2Enc 632

#define OBJ_setAttr_T2Enc OBJ_setAttr_IssCap_T2,1L

#define SN_setAttr_T2cleartxt "setAttr-T2cleartxt"

#define LN_setAttr_T2cleartxt "cleartext track 2"

#define NID_setAttr_T2cleartxt 633

#define OBJ_setAttr_T2cleartxt OBJ_setAttr_IssCap_T2,2L

#define SN_setAttr_TokICCsig "setAttr-TokICCsig"

#define LN_setAttr_TokICCsig "ICC or token signature"

#define NID_setAttr_TokICCsig 634

#define OBJ_setAttr_TokICCsig OBJ_setAttr_IssCap_Sig,1L

#define SN_setAttr_SecDevSig "setAttr-SecDevSig"

#define LN_setAttr_SecDevSig "secure device signature"

#define NID_setAttr_SecDevSig 635

#define OBJ_setAttr_SecDevSig OBJ_setAttr_IssCap_Sig,2L

#define SN_set_brand_IATA_ATA "set-brand-IATA-ATA"

#define NID_set_brand_IATA_ATA 636

#define OBJ_set_brand_IATA_ATA OBJ_set_brand,1L

#define SN_set_brand_Diners "set-brand-Diners"

#define NID_set_brand_Diners 637

#define OBJ_set_brand_Diners OBJ_set_brand,30L

#define SN_set_brand_AmericanExpress "set-brand-AmericanExpress"

#define NID_set_brand_AmericanExpress 638

#define OBJ_set_brand_AmericanExpress OBJ_set_brand,34L

#define SN_set_brand_JCB "set-brand-JCB"

#define NID_set_brand_JCB 639

#define OBJ_set_brand_JCB OBJ_set_brand,35L

#define SN_set_brand_Visa "set-brand-Visa"

#define NID_set_brand_Visa 640

#define OBJ_set_brand_Visa OBJ_set_brand,4L

#define SN_set_brand_MasterCard "set-brand-MasterCard"

#define NID_set_brand_MasterCard 641

#define OBJ_set_brand_MasterCard OBJ_set_brand,5L

#define SN_set_brand_Novus "set-brand-Novus"

#define NID_set_brand_Novus 642

#define OBJ_set_brand_Novus OBJ_set_brand,6011L

#define SN_des_cdmf "DES-CDMF"

#define LN_des_cdmf "des-cdmf"

#define NID_des_cdmf 643

#define OBJ_des_cdmf OBJ_rsadsi,3L,10L

#define SN_rsaOAEPEncryptionSET "rsaOAEPEncryptionSET"

#define NID_rsaOAEPEncryptionSET 644

#define OBJ_rsaOAEPEncryptionSET OBJ_rsadsi,1L,1L,6L

#define SN_ipsec3 "Oakley-EC2N-3"

#define LN_ipsec3 "ipsec3"

#define NID_ipsec3 749

#define SN_ipsec4 "Oakley-EC2N-4"

#define LN_ipsec4 "ipsec4"

#define NID_ipsec4 750

#define SN_whirlpool "whirlpool"

#define NID_whirlpool 804

#define OBJ_whirlpool OBJ_iso,0L,10118L,3L,0L,55L

#define SN_cryptopro "cryptopro"

#define NID_cryptopro 805

#define OBJ_cryptopro OBJ_member_body,643L,2L,2L

#define SN_cryptocom "cryptocom"

#define NID_cryptocom 806

#define OBJ_cryptocom OBJ_member_body,643L,2L,9L

#define SN_id_tc26 "id-tc26"

#define NID_id_tc26 974

#define OBJ_id_tc26 OBJ_member_body,643L,7L,1L

#define SN_id_GostR3411_94_with_GostR3410_2001 "id-GostR3411-94-with-GostR3410-2001"

#define LN_id_GostR3411_94_with_GostR3410_2001 "GOST R 34.11-94 with GOST R 34.10-2001"

#define NID_id_GostR3411_94_with_GostR3410_2001 807

#define OBJ_id_GostR3411_94_with_GostR3410_2001 OBJ_cryptopro,3L

#define SN_id_GostR3411_94_with_GostR3410_94 "id-GostR3411-94-with-GostR3410-94"

#define LN_id_GostR3411_94_with_GostR3410_94 "GOST R 34.11-94 with GOST R 34.10-94"

#define NID_id_GostR3411_94_with_GostR3410_94 808

#define OBJ_id_GostR3411_94_with_GostR3410_94 OBJ_cryptopro,4L

#define SN_id_GostR3411_94 "md_gost94"

#define LN_id_GostR3411_94 "GOST R 34.11-94"

#define NID_id_GostR3411_94 809

#define OBJ_id_GostR3411_94 OBJ_cryptopro,9L

#define SN_id_HMACGostR3411_94 "id-HMACGostR3411-94"

#define LN_id_HMACGostR3411_94 "HMAC GOST 34.11-94"

#define NID_id_HMACGostR3411_94 810

#define OBJ_id_HMACGostR3411_94 OBJ_cryptopro,10L

#define SN_id_GostR3410_2001 "gost2001"

#define LN_id_GostR3410_2001 "GOST R 34.10-2001"

#define NID_id_GostR3410_2001 811

#define OBJ_id_GostR3410_2001 OBJ_cryptopro,19L

#define SN_id_GostR3410_94 "gost94"

#define LN_id_GostR3410_94 "GOST R 34.10-94"

#define NID_id_GostR3410_94 812

#define OBJ_id_GostR3410_94 OBJ_cryptopro,20L

#define SN_id_Gost28147_89 "gost89"

#define LN_id_Gost28147_89 "GOST 28147-89"

#define NID_id_Gost28147_89 813

#define OBJ_id_Gost28147_89 OBJ_cryptopro,21L

#define SN_gost89_cnt "gost89-cnt"

#define NID_gost89_cnt 814

#define SN_gost89_cnt_12 "gost89-cnt-12"

#define NID_gost89_cnt_12 975

#define SN_gost89_cbc "gost89-cbc"

#define NID_gost89_cbc 1009

#define SN_gost89_ecb "gost89-ecb"

#define NID_gost89_ecb 1010

#define SN_gost89_ctr "gost89-ctr"

#define NID_gost89_ctr 1011

#define SN_id_Gost28147_89_MAC "gost-mac"

#define LN_id_Gost28147_89_MAC "GOST 28147-89 MAC"

#define NID_id_Gost28147_89_MAC 815

#define OBJ_id_Gost28147_89_MAC OBJ_cryptopro,22L

#define SN_gost_mac_12 "gost-mac-12"

#define NID_gost_mac_12 976

#define SN_id_GostR3411_94_prf "prf-gostr3411-94"

#define LN_id_GostR3411_94_prf "GOST R 34.11-94 PRF"

#define NID_id_GostR3411_94_prf 816

#define OBJ_id_GostR3411_94_prf OBJ_cryptopro,23L

#define SN_id_GostR3410_2001DH "id-GostR3410-2001DH"

#define LN_id_GostR3410_2001DH "GOST R 34.10-2001 DH"

#define NID_id_GostR3410_2001DH 817

#define OBJ_id_GostR3410_2001DH OBJ_cryptopro,98L

#define SN_id_GostR3410_94DH "id-GostR3410-94DH"

#define LN_id_GostR3410_94DH "GOST R 34.10-94 DH"

#define NID_id_GostR3410_94DH 818

#define OBJ_id_GostR3410_94DH OBJ_cryptopro,99L

#define SN_id_Gost28147_89_CryptoPro_KeyMeshing "id-Gost28147-89-CryptoPro-KeyMeshing"

#define NID_id_Gost28147_89_CryptoPro_KeyMeshing 819

#define OBJ_id_Gost28147_89_CryptoPro_KeyMeshing OBJ_cryptopro,14L,1L

#define SN_id_Gost28147_89_None_KeyMeshing "id-Gost28147-89-None-KeyMeshing"

#define NID_id_Gost28147_89_None_KeyMeshing 820

#define OBJ_id_Gost28147_89_None_KeyMeshing OBJ_cryptopro,14L,0L

#define SN_id_GostR3411_94_TestParamSet "id-GostR3411-94-TestParamSet"

#define NID_id_GostR3411_94_TestParamSet 821

#define OBJ_id_GostR3411_94_TestParamSet OBJ_cryptopro,30L,0L

#define SN_id_GostR3411_94_CryptoProParamSet "id-GostR3411-94-CryptoProParamSet"

#define NID_id_GostR3411_94_CryptoProParamSet 822

#define OBJ_id_GostR3411_94_CryptoProParamSet OBJ_cryptopro,30L,1L

#define SN_id_Gost28147_89_TestParamSet "id-Gost28147-89-TestParamSet"

#define NID_id_Gost28147_89_TestParamSet 823

#define OBJ_id_Gost28147_89_TestParamSet OBJ_cryptopro,31L,0L

#define SN_id_Gost28147_89_CryptoPro_A_ParamSet "id-Gost28147-89-CryptoPro-A-ParamSet"

#define NID_id_Gost28147_89_CryptoPro_A_ParamSet 824

#define OBJ_id_Gost28147_89_CryptoPro_A_ParamSet OBJ_cryptopro,31L,1L

#define SN_id_Gost28147_89_CryptoPro_B_ParamSet "id-Gost28147-89-CryptoPro-B-ParamSet"

#define NID_id_Gost28147_89_CryptoPro_B_ParamSet 825

#define OBJ_id_Gost28147_89_CryptoPro_B_ParamSet OBJ_cryptopro,31L,2L

#define SN_id_Gost28147_89_CryptoPro_C_ParamSet "id-Gost28147-89-CryptoPro-C-ParamSet"

#define NID_id_Gost28147_89_CryptoPro_C_ParamSet 826

#define OBJ_id_Gost28147_89_CryptoPro_C_ParamSet OBJ_cryptopro,31L,3L

#define SN_id_Gost28147_89_CryptoPro_D_ParamSet "id-Gost28147-89-CryptoPro-D-ParamSet"

#define NID_id_Gost28147_89_CryptoPro_D_ParamSet 827

#define OBJ_id_Gost28147_89_CryptoPro_D_ParamSet OBJ_cryptopro,31L,4L

#define SN_id_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet "id-Gost28147-89-CryptoPro-Oscar-1-1-ParamSet"

#define NID_id_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet 828

#define OBJ_id_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet OBJ_cryptopro,31L,5L

#define SN_id_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet "id-Gost28147-89-CryptoPro-Oscar-1-0-ParamSet"

#define NID_id_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet 829

#define OBJ_id_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet OBJ_cryptopro,31L,6L

#define SN_id_Gost28147_89_CryptoPro_RIC_1_ParamSet "id-Gost28147-89-CryptoPro-RIC-1-ParamSet"

#define NID_id_Gost28147_89_CryptoPro_RIC_1_ParamSet 830

#define OBJ_id_Gost28147_89_CryptoPro_RIC_1_ParamSet OBJ_cryptopro,31L,7L

#define SN_id_GostR3410_94_TestParamSet "id-GostR3410-94-TestParamSet"

#define NID_id_GostR3410_94_TestParamSet 831

#define OBJ_id_GostR3410_94_TestParamSet OBJ_cryptopro,32L,0L

#define SN_id_GostR3410_94_CryptoPro_A_ParamSet "id-GostR3410-94-CryptoPro-A-ParamSet"

#define NID_id_GostR3410_94_CryptoPro_A_ParamSet 832

#define OBJ_id_GostR3410_94_CryptoPro_A_ParamSet OBJ_cryptopro,32L,2L

#define SN_id_GostR3410_94_CryptoPro_B_ParamSet "id-GostR3410-94-CryptoPro-B-ParamSet"

#define NID_id_GostR3410_94_CryptoPro_B_ParamSet 833

#define OBJ_id_GostR3410_94_CryptoPro_B_ParamSet OBJ_cryptopro,32L,3L

#define SN_id_GostR3410_94_CryptoPro_C_ParamSet "id-GostR3410-94-CryptoPro-C-ParamSet"

#define NID_id_GostR3410_94_CryptoPro_C_ParamSet 834

#define OBJ_id_GostR3410_94_CryptoPro_C_ParamSet OBJ_cryptopro,32L,4L

#define SN_id_GostR3410_94_CryptoPro_D_ParamSet "id-GostR3410-94-CryptoPro-D-ParamSet"

#define NID_id_GostR3410_94_CryptoPro_D_ParamSet 835

#define OBJ_id_GostR3410_94_CryptoPro_D_ParamSet OBJ_cryptopro,32L,5L

#define SN_id_GostR3410_94_CryptoPro_XchA_ParamSet "id-GostR3410-94-CryptoPro-XchA-ParamSet"

#define NID_id_GostR3410_94_CryptoPro_XchA_ParamSet 836

#define OBJ_id_GostR3410_94_CryptoPro_XchA_ParamSet OBJ_cryptopro,33L,1L

#define SN_id_GostR3410_94_CryptoPro_XchB_ParamSet "id-GostR3410-94-CryptoPro-XchB-ParamSet"

#define NID_id_GostR3410_94_CryptoPro_XchB_ParamSet 837

#define OBJ_id_GostR3410_94_CryptoPro_XchB_ParamSet OBJ_cryptopro,33L,2L

#define SN_id_GostR3410_94_CryptoPro_XchC_ParamSet "id-GostR3410-94-CryptoPro-XchC-ParamSet"

#define NID_id_GostR3410_94_CryptoPro_XchC_ParamSet 838

#define OBJ_id_GostR3410_94_CryptoPro_XchC_ParamSet OBJ_cryptopro,33L,3L

#define SN_id_GostR3410_2001_TestParamSet "id-GostR3410-2001-TestParamSet"

#define NID_id_GostR3410_2001_TestParamSet 839

#define OBJ_id_GostR3410_2001_TestParamSet OBJ_cryptopro,35L,0L

#define SN_id_GostR3410_2001_CryptoPro_A_ParamSet "id-GostR3410-2001-CryptoPro-A-ParamSet"

#define NID_id_GostR3410_2001_CryptoPro_A_ParamSet 840

#define OBJ_id_GostR3410_2001_CryptoPro_A_ParamSet OBJ_cryptopro,35L,1L

#define SN_id_GostR3410_2001_CryptoPro_B_ParamSet "id-GostR3410-2001-CryptoPro-B-ParamSet"

#define NID_id_GostR3410_2001_CryptoPro_B_ParamSet 841

#define OBJ_id_GostR3410_2001_CryptoPro_B_ParamSet OBJ_cryptopro,35L,2L

#define SN_id_GostR3410_2001_CryptoPro_C_ParamSet "id-GostR3410-2001-CryptoPro-C-ParamSet"

#define NID_id_GostR3410_2001_CryptoPro_C_ParamSet 842

#define OBJ_id_GostR3410_2001_CryptoPro_C_ParamSet OBJ_cryptopro,35L,3L

#define SN_id_GostR3410_2001_CryptoPro_XchA_ParamSet "id-GostR3410-2001-CryptoPro-XchA-ParamSet"

#define NID_id_GostR3410_2001_CryptoPro_XchA_ParamSet 843

#define OBJ_id_GostR3410_2001_CryptoPro_XchA_ParamSet OBJ_cryptopro,36L,0L

#define SN_id_GostR3410_2001_CryptoPro_XchB_ParamSet "id-GostR3410-2001-CryptoPro-XchB-ParamSet"

#define NID_id_GostR3410_2001_CryptoPro_XchB_ParamSet 844

#define OBJ_id_GostR3410_2001_CryptoPro_XchB_ParamSet OBJ_cryptopro,36L,1L

#define SN_id_GostR3410_94_a "id-GostR3410-94-a"

#define NID_id_GostR3410_94_a 845

#define OBJ_id_GostR3410_94_a OBJ_id_GostR3410_94,1L

#define SN_id_GostR3410_94_aBis "id-GostR3410-94-aBis"

#define NID_id_GostR3410_94_aBis 846

#define OBJ_id_GostR3410_94_aBis OBJ_id_GostR3410_94,2L

#define SN_id_GostR3410_94_b "id-GostR3410-94-b"

#define NID_id_GostR3410_94_b 847

#define OBJ_id_GostR3410_94_b OBJ_id_GostR3410_94,3L

#define SN_id_GostR3410_94_bBis "id-GostR3410-94-bBis"

#define NID_id_GostR3410_94_bBis 848

#define OBJ_id_GostR3410_94_bBis OBJ_id_GostR3410_94,4L

#define SN_id_Gost28147_89_cc "id-Gost28147-89-cc"

#define LN_id_Gost28147_89_cc "GOST 28147-89 Cryptocom ParamSet"

#define NID_id_Gost28147_89_cc 849

#define OBJ_id_Gost28147_89_cc OBJ_cryptocom,1L,6L,1L

#define SN_id_GostR3410_94_cc "gost94cc"

#define LN_id_GostR3410_94_cc "GOST 34.10-94 Cryptocom"

#define NID_id_GostR3410_94_cc 850

#define OBJ_id_GostR3410_94_cc OBJ_cryptocom,1L,5L,3L

#define SN_id_GostR3410_2001_cc "gost2001cc"

#define LN_id_GostR3410_2001_cc "GOST 34.10-2001 Cryptocom"

#define NID_id_GostR3410_2001_cc 851

#define OBJ_id_GostR3410_2001_cc OBJ_cryptocom,1L,5L,4L

#define SN_id_GostR3411_94_with_GostR3410_94_cc "id-GostR3411-94-with-GostR3410-94-cc"

#define LN_id_GostR3411_94_with_GostR3410_94_cc "GOST R 34.11-94 with GOST R 34.10-94 Cryptocom"

#define NID_id_GostR3411_94_with_GostR3410_94_cc 852

#define OBJ_id_GostR3411_94_with_GostR3410_94_cc OBJ_cryptocom,1L,3L,3L

#define SN_id_GostR3411_94_with_GostR3410_2001_cc "id-GostR3411-94-with-GostR3410-2001-cc"

#define LN_id_GostR3411_94_with_GostR3410_2001_cc "GOST R 34.11-94 with GOST R 34.10-2001 Cryptocom"

#define NID_id_GostR3411_94_with_GostR3410_2001_cc 853

#define OBJ_id_GostR3411_94_with_GostR3410_2001_cc OBJ_cryptocom,1L,3L,4L

#define SN_id_GostR3410_2001_ParamSet_cc "id-GostR3410-2001-ParamSet-cc"

#define LN_id_GostR3410_2001_ParamSet_cc "GOST R 3410-2001 Parameter Set Cryptocom"

#define NID_id_GostR3410_2001_ParamSet_cc 854

#define OBJ_id_GostR3410_2001_ParamSet_cc OBJ_cryptocom,1L,8L,1L

#define SN_id_tc26_algorithms "id-tc26-algorithms"

#define NID_id_tc26_algorithms 977

#define OBJ_id_tc26_algorithms OBJ_id_tc26,1L

#define SN_id_tc26_sign "id-tc26-sign"

#define NID_id_tc26_sign 978

#define OBJ_id_tc26_sign OBJ_id_tc26_algorithms,1L

#define SN_id_GostR3410_2012_256 "gost2012_256"

#define LN_id_GostR3410_2012_256 "GOST R 34.10-2012 with 256 bit modulus"

#define NID_id_GostR3410_2012_256 979

#define OBJ_id_GostR3410_2012_256 OBJ_id_tc26_sign,1L

#define SN_id_GostR3410_2012_512 "gost2012_512"

#define LN_id_GostR3410_2012_512 "GOST R 34.10-2012 with 512 bit modulus"

#define NID_id_GostR3410_2012_512 980

#define OBJ_id_GostR3410_2012_512 OBJ_id_tc26_sign,2L

#define SN_id_tc26_digest "id-tc26-digest"

#define NID_id_tc26_digest 981

#define OBJ_id_tc26_digest OBJ_id_tc26_algorithms,2L

#define SN_id_GostR3411_2012_256 "md_gost12_256"

#define LN_id_GostR3411_2012_256 "GOST R 34.11-2012 with 256 bit hash"

#define NID_id_GostR3411_2012_256 982

#define OBJ_id_GostR3411_2012_256 OBJ_id_tc26_digest,2L

#define SN_id_GostR3411_2012_512 "md_gost12_512"

#define LN_id_GostR3411_2012_512 "GOST R 34.11-2012 with 512 bit hash"

#define NID_id_GostR3411_2012_512 983

#define OBJ_id_GostR3411_2012_512 OBJ_id_tc26_digest,3L

#define SN_id_tc26_signwithdigest "id-tc26-signwithdigest"

#define NID_id_tc26_signwithdigest 984

#define OBJ_id_tc26_signwithdigest OBJ_id_tc26_algorithms,3L

#define SN_id_tc26_signwithdigest_gost3410_2012_256 "id-tc26-signwithdigest-gost3410-2012-256"

#define LN_id_tc26_signwithdigest_gost3410_2012_256 "GOST R 34.10-2012 with GOST R 34.11-2012 (256 bit)"

#define NID_id_tc26_signwithdigest_gost3410_2012_256 985

#define OBJ_id_tc26_signwithdigest_gost3410_2012_256 OBJ_id_tc26_signwithdigest,2L

#define SN_id_tc26_signwithdigest_gost3410_2012_512 "id-tc26-signwithdigest-gost3410-2012-512"

#define LN_id_tc26_signwithdigest_gost3410_2012_512 "GOST R 34.10-2012 with GOST R 34.11-2012 (512 bit)"

#define NID_id_tc26_signwithdigest_gost3410_2012_512 986

#define OBJ_id_tc26_signwithdigest_gost3410_2012_512 OBJ_id_tc26_signwithdigest,3L

#define SN_id_tc26_mac "id-tc26-mac"

#define NID_id_tc26_mac 987

#define OBJ_id_tc26_mac OBJ_id_tc26_algorithms,4L

#define SN_id_tc26_hmac_gost_3411_2012_256 "id-tc26-hmac-gost-3411-2012-256"

#define LN_id_tc26_hmac_gost_3411_2012_256 "HMAC GOST 34.11-2012 256 bit"

#define NID_id_tc26_hmac_gost_3411_2012_256 988

#define OBJ_id_tc26_hmac_gost_3411_2012_256 OBJ_id_tc26_mac,1L

#define SN_id_tc26_hmac_gost_3411_2012_512 "id-tc26-hmac-gost-3411-2012-512"

#define LN_id_tc26_hmac_gost_3411_2012_512 "HMAC GOST 34.11-2012 512 bit"

#define NID_id_tc26_hmac_gost_3411_2012_512 989

#define OBJ_id_tc26_hmac_gost_3411_2012_512 OBJ_id_tc26_mac,2L

#define SN_id_tc26_cipher "id-tc26-cipher"

#define NID_id_tc26_cipher 990

#define OBJ_id_tc26_cipher OBJ_id_tc26_algorithms,5L

#define SN_id_tc26_cipher_gostr3412_2015_magma "id-tc26-cipher-gostr3412-2015-magma"

#define NID_id_tc26_cipher_gostr3412_2015_magma 1173

#define OBJ_id_tc26_cipher_gostr3412_2015_magma OBJ_id_tc26_cipher,1L

#define SN_magma_ctr_acpkm "magma-ctr-acpkm"

#define NID_magma_ctr_acpkm 1174

#define OBJ_magma_ctr_acpkm OBJ_id_tc26_cipher_gostr3412_2015_magma,1L

#define SN_magma_ctr_acpkm_omac "magma-ctr-acpkm-omac"

#define NID_magma_ctr_acpkm_omac 1175

#define OBJ_magma_ctr_acpkm_omac OBJ_id_tc26_cipher_gostr3412_2015_magma,2L

#define SN_id_tc26_cipher_gostr3412_2015_kuznyechik "id-tc26-cipher-gostr3412-2015-kuznyechik"

#define NID_id_tc26_cipher_gostr3412_2015_kuznyechik 1176

#define OBJ_id_tc26_cipher_gostr3412_2015_kuznyechik OBJ_id_tc26_cipher,2L

#define SN_kuznyechik_ctr_acpkm "kuznyechik-ctr-acpkm"

#define NID_kuznyechik_ctr_acpkm 1177

#define OBJ_kuznyechik_ctr_acpkm OBJ_id_tc26_cipher_gostr3412_2015_kuznyechik,1L

#define SN_kuznyechik_ctr_acpkm_omac "kuznyechik-ctr-acpkm-omac"

#define NID_kuznyechik_ctr_acpkm_omac 1178

#define OBJ_kuznyechik_ctr_acpkm_omac OBJ_id_tc26_cipher_gostr3412_2015_kuznyechik,2L

#define SN_id_tc26_agreement "id-tc26-agreement"

#define NID_id_tc26_agreement 991

#define OBJ_id_tc26_agreement OBJ_id_tc26_algorithms,6L

#define SN_id_tc26_agreement_gost_3410_2012_256 "id-tc26-agreement-gost-3410-2012-256"

#define NID_id_tc26_agreement_gost_3410_2012_256 992

#define OBJ_id_tc26_agreement_gost_3410_2012_256 OBJ_id_tc26_agreement,1L

#define SN_id_tc26_agreement_gost_3410_2012_512 "id-tc26-agreement-gost-3410-2012-512"

#define NID_id_tc26_agreement_gost_3410_2012_512 993

#define OBJ_id_tc26_agreement_gost_3410_2012_512 OBJ_id_tc26_agreement,2L

#define SN_id_tc26_wrap "id-tc26-wrap"

#define NID_id_tc26_wrap 1179

#define OBJ_id_tc26_wrap OBJ_id_tc26_algorithms,7L

#define SN_id_tc26_wrap_gostr3412_2015_magma "id-tc26-wrap-gostr3412-2015-magma"

#define NID_id_tc26_wrap_gostr3412_2015_magma 1180

#define OBJ_id_tc26_wrap_gostr3412_2015_magma OBJ_id_tc26_wrap,1L

#define SN_magma_kexp15 "magma-kexp15"

#define NID_magma_kexp15 1181

#define OBJ_magma_kexp15 OBJ_id_tc26_wrap_gostr3412_2015_magma,1L

#define SN_id_tc26_wrap_gostr3412_2015_kuznyechik "id-tc26-wrap-gostr3412-2015-kuznyechik"

#define NID_id_tc26_wrap_gostr3412_2015_kuznyechik 1182

#define OBJ_id_tc26_wrap_gostr3412_2015_kuznyechik OBJ_id_tc26_wrap,2L

#define SN_kuznyechik_kexp15 "kuznyechik-kexp15"

#define NID_kuznyechik_kexp15 1183

#define OBJ_kuznyechik_kexp15 OBJ_id_tc26_wrap_gostr3412_2015_kuznyechik,1L

#define SN_id_tc26_constants "id-tc26-constants"

#define NID_id_tc26_constants 994

#define OBJ_id_tc26_constants OBJ_id_tc26,2L

#define SN_id_tc26_sign_constants "id-tc26-sign-constants"

#define NID_id_tc26_sign_constants 995

#define OBJ_id_tc26_sign_constants OBJ_id_tc26_constants,1L

#define SN_id_tc26_gost_3410_2012_256_constants "id-tc26-gost-3410-2012-256-constants"

#define NID_id_tc26_gost_3410_2012_256_constants 1147

#define OBJ_id_tc26_gost_3410_2012_256_constants OBJ_id_tc26_sign_constants,1L

#define SN_id_tc26_gost_3410_2012_256_paramSetA "id-tc26-gost-3410-2012-256-paramSetA"

#define LN_id_tc26_gost_3410_2012_256_paramSetA "GOST R 34.10-2012 (256 bit) ParamSet A"

#define NID_id_tc26_gost_3410_2012_256_paramSetA 1148

#define OBJ_id_tc26_gost_3410_2012_256_paramSetA OBJ_id_tc26_gost_3410_2012_256_constants,1L

#define SN_id_tc26_gost_3410_2012_256_paramSetB "id-tc26-gost-3410-2012-256-paramSetB"

#define LN_id_tc26_gost_3410_2012_256_paramSetB "GOST R 34.10-2012 (256 bit) ParamSet B"

#define NID_id_tc26_gost_3410_2012_256_paramSetB 1184

#define OBJ_id_tc26_gost_3410_2012_256_paramSetB OBJ_id_tc26_gost_3410_2012_256_constants,2L

#define SN_id_tc26_gost_3410_2012_256_paramSetC "id-tc26-gost-3410-2012-256-paramSetC"

#define LN_id_tc26_gost_3410_2012_256_paramSetC "GOST R 34.10-2012 (256 bit) ParamSet C"

#define NID_id_tc26_gost_3410_2012_256_paramSetC 1185

#define OBJ_id_tc26_gost_3410_2012_256_paramSetC OBJ_id_tc26_gost_3410_2012_256_constants,3L

#define SN_id_tc26_gost_3410_2012_256_paramSetD "id-tc26-gost-3410-2012-256-paramSetD"

#define LN_id_tc26_gost_3410_2012_256_paramSetD "GOST R 34.10-2012 (256 bit) ParamSet D"

#define NID_id_tc26_gost_3410_2012_256_paramSetD 1186

#define OBJ_id_tc26_gost_3410_2012_256_paramSetD OBJ_id_tc26_gost_3410_2012_256_constants,4L

#define SN_id_tc26_gost_3410_2012_512_constants "id-tc26-gost-3410-2012-512-constants"

#define NID_id_tc26_gost_3410_2012_512_constants 996

#define OBJ_id_tc26_gost_3410_2012_512_constants OBJ_id_tc26_sign_constants,2L

#define SN_id_tc26_gost_3410_2012_512_paramSetTest "id-tc26-gost-3410-2012-512-paramSetTest"

#define LN_id_tc26_gost_3410_2012_512_paramSetTest "GOST R 34.10-2012 (512 bit) testing parameter set"

#define NID_id_tc26_gost_3410_2012_512_paramSetTest 997

#define OBJ_id_tc26_gost_3410_2012_512_paramSetTest OBJ_id_tc26_gost_3410_2012_512_constants,0L

#define SN_id_tc26_gost_3410_2012_512_paramSetA "id-tc26-gost-3410-2012-512-paramSetA"

#define LN_id_tc26_gost_3410_2012_512_paramSetA "GOST R 34.10-2012 (512 bit) ParamSet A"

#define NID_id_tc26_gost_3410_2012_512_paramSetA 998

#define OBJ_id_tc26_gost_3410_2012_512_paramSetA OBJ_id_tc26_gost_3410_2012_512_constants,1L

#define SN_id_tc26_gost_3410_2012_512_paramSetB "id-tc26-gost-3410-2012-512-paramSetB"

#define LN_id_tc26_gost_3410_2012_512_paramSetB "GOST R 34.10-2012 (512 bit) ParamSet B"

#define NID_id_tc26_gost_3410_2012_512_paramSetB 999

#define OBJ_id_tc26_gost_3410_2012_512_paramSetB OBJ_id_tc26_gost_3410_2012_512_constants,2L

#define SN_id_tc26_gost_3410_2012_512_paramSetC "id-tc26-gost-3410-2012-512-paramSetC"

#define LN_id_tc26_gost_3410_2012_512_paramSetC "GOST R 34.10-2012 (512 bit) ParamSet C"

#define NID_id_tc26_gost_3410_2012_512_paramSetC 1149

#define OBJ_id_tc26_gost_3410_2012_512_paramSetC OBJ_id_tc26_gost_3410_2012_512_constants,3L

#define SN_id_tc26_digest_constants "id-tc26-digest-constants"

#define NID_id_tc26_digest_constants 1000

#define OBJ_id_tc26_digest_constants OBJ_id_tc26_constants,2L

#define SN_id_tc26_cipher_constants "id-tc26-cipher-constants"

#define NID_id_tc26_cipher_constants 1001

#define OBJ_id_tc26_cipher_constants OBJ_id_tc26_constants,5L

#define SN_id_tc26_gost_28147_constants "id-tc26-gost-28147-constants"

#define NID_id_tc26_gost_28147_constants 1002

#define OBJ_id_tc26_gost_28147_constants OBJ_id_tc26_cipher_constants,1L

#define SN_id_tc26_gost_28147_param_Z "id-tc26-gost-28147-param-Z"

#define LN_id_tc26_gost_28147_param_Z "GOST 28147-89 TC26 parameter set"

#define NID_id_tc26_gost_28147_param_Z 1003

#define OBJ_id_tc26_gost_28147_param_Z OBJ_id_tc26_gost_28147_constants,1L

#define SN_INN "INN"

#define LN_INN "INN"

#define NID_INN 1004

#define OBJ_INN OBJ_member_body,643L,3L,131L,1L,1L

#define SN_OGRN "OGRN"

#define LN_OGRN "OGRN"

#define NID_OGRN 1005

#define OBJ_OGRN OBJ_member_body,643L,100L,1L

#define SN_SNILS "SNILS"

#define LN_SNILS "SNILS"

#define NID_SNILS 1006

#define OBJ_SNILS OBJ_member_body,643L,100L,3L

#define SN_OGRNIP "OGRNIP"

#define LN_OGRNIP "OGRNIP"

#define NID_OGRNIP 1226

#define OBJ_OGRNIP OBJ_member_body,643L,100L,5L

#define SN_subjectSignTool "subjectSignTool"

#define LN_subjectSignTool "Signing Tool of Subject"

#define NID_subjectSignTool 1007

#define OBJ_subjectSignTool OBJ_member_body,643L,100L,111L

#define SN_issuerSignTool "issuerSignTool"

#define LN_issuerSignTool "Signing Tool of Issuer"

#define NID_issuerSignTool 1008

#define OBJ_issuerSignTool OBJ_member_body,643L,100L,112L

#define SN_classSignTool "classSignTool"

#define LN_classSignTool "Class of Signing Tool"

#define NID_classSignTool 1227

#define OBJ_classSignTool OBJ_member_body,643L,100L,113L

#define SN_classSignToolKC1 "classSignToolKC1"

#define LN_classSignToolKC1 "Class of Signing Tool KC1"

#define NID_classSignToolKC1 1228

#define OBJ_classSignToolKC1 OBJ_member_body,643L,100L,113L,1L

#define SN_classSignToolKC2 "classSignToolKC2"

#define LN_classSignToolKC2 "Class of Signing Tool KC2"

#define NID_classSignToolKC2 1229

#define OBJ_classSignToolKC2 OBJ_member_body,643L,100L,113L,2L

#define SN_classSignToolKC3 "classSignToolKC3"

#define LN_classSignToolKC3 "Class of Signing Tool KC3"

#define NID_classSignToolKC3 1230

#define OBJ_classSignToolKC3 OBJ_member_body,643L,100L,113L,3L

#define SN_classSignToolKB1 "classSignToolKB1"

#define LN_classSignToolKB1 "Class of Signing Tool KB1"

#define NID_classSignToolKB1 1231

#define OBJ_classSignToolKB1 OBJ_member_body,643L,100L,113L,4L

#define SN_classSignToolKB2 "classSignToolKB2"

#define LN_classSignToolKB2 "Class of Signing Tool KB2"

#define NID_classSignToolKB2 1232

#define OBJ_classSignToolKB2 OBJ_member_body,643L,100L,113L,5L

#define SN_classSignToolKA1 "classSignToolKA1"

#define LN_classSignToolKA1 "Class of Signing Tool KA1"

#define NID_classSignToolKA1 1233

#define OBJ_classSignToolKA1 OBJ_member_body,643L,100L,113L,6L

#define SN_kuznyechik_ecb "kuznyechik-ecb"

#define NID_kuznyechik_ecb 1012

#define SN_kuznyechik_ctr "kuznyechik-ctr"

#define NID_kuznyechik_ctr 1013

#define SN_kuznyechik_ofb "kuznyechik-ofb"

#define NID_kuznyechik_ofb 1014

#define SN_kuznyechik_cbc "kuznyechik-cbc"

#define NID_kuznyechik_cbc 1015

#define SN_kuznyechik_cfb "kuznyechik-cfb"

#define NID_kuznyechik_cfb 1016

#define SN_kuznyechik_mac "kuznyechik-mac"

#define NID_kuznyechik_mac 1017

#define SN_magma_ecb "magma-ecb"

#define NID_magma_ecb 1187

#define SN_magma_ctr "magma-ctr"

#define NID_magma_ctr 1188

#define SN_magma_ofb "magma-ofb"

#define NID_magma_ofb 1189

#define SN_magma_cbc "magma-cbc"

#define NID_magma_cbc 1190

#define SN_magma_cfb "magma-cfb"

#define NID_magma_cfb 1191

#define SN_magma_mac "magma-mac"

#define NID_magma_mac 1192

#define SN_camellia_128_cbc "CAMELLIA-128-CBC"

#define LN_camellia_128_cbc "camellia-128-cbc"

#define NID_camellia_128_cbc 751

#define OBJ_camellia_128_cbc 1L,2L,392L,200011L,61L,1L,1L,1L,2L

#define SN_camellia_192_cbc "CAMELLIA-192-CBC"

#define LN_camellia_192_cbc "camellia-192-cbc"

#define NID_camellia_192_cbc 752

#define OBJ_camellia_192_cbc 1L,2L,392L,200011L,61L,1L,1L,1L,3L

#define SN_camellia_256_cbc "CAMELLIA-256-CBC"

#define LN_camellia_256_cbc "camellia-256-cbc"

#define NID_camellia_256_cbc 753

#define OBJ_camellia_256_cbc 1L,2L,392L,200011L,61L,1L,1L,1L,4L

#define SN_id_camellia128_wrap "id-camellia128-wrap"

#define NID_id_camellia128_wrap 907

#define OBJ_id_camellia128_wrap 1L,2L,392L,200011L,61L,1L,1L,3L,2L

#define SN_id_camellia192_wrap "id-camellia192-wrap"

#define NID_id_camellia192_wrap 908

#define OBJ_id_camellia192_wrap 1L,2L,392L,200011L,61L,1L,1L,3L,3L

#define SN_id_camellia256_wrap "id-camellia256-wrap"

#define NID_id_camellia256_wrap 909

#define OBJ_id_camellia256_wrap 1L,2L,392L,200011L,61L,1L,1L,3L,4L

#define OBJ_ntt_ds 0L,3L,4401L,5L

#define OBJ_camellia OBJ_ntt_ds,3L,1L,9L

#define SN_camellia_128_ecb "CAMELLIA-128-ECB"

#define LN_camellia_128_ecb "camellia-128-ecb"

#define NID_camellia_128_ecb 754

#define OBJ_camellia_128_ecb OBJ_camellia,1L

#define SN_camellia_128_ofb128 "CAMELLIA-128-OFB"

#define LN_camellia_128_ofb128 "camellia-128-ofb"

#define NID_camellia_128_ofb128 766

#define OBJ_camellia_128_ofb128 OBJ_camellia,3L

#define SN_camellia_128_cfb128 "CAMELLIA-128-CFB"

#define LN_camellia_128_cfb128 "camellia-128-cfb"

#define NID_camellia_128_cfb128 757

#define OBJ_camellia_128_cfb128 OBJ_camellia,4L

#define SN_camellia_128_gcm "CAMELLIA-128-GCM"

#define LN_camellia_128_gcm "camellia-128-gcm"

#define NID_camellia_128_gcm 961

#define OBJ_camellia_128_gcm OBJ_camellia,6L

#define SN_camellia_128_ccm "CAMELLIA-128-CCM"

#define LN_camellia_128_ccm "camellia-128-ccm"

#define NID_camellia_128_ccm 962

#define OBJ_camellia_128_ccm OBJ_camellia,7L

#define SN_camellia_128_ctr "CAMELLIA-128-CTR"

#define LN_camellia_128_ctr "camellia-128-ctr"

#define NID_camellia_128_ctr 963

#define OBJ_camellia_128_ctr OBJ_camellia,9L

#define SN_camellia_128_cmac "CAMELLIA-128-CMAC"

#define LN_camellia_128_cmac "camellia-128-cmac"

#define NID_camellia_128_cmac 964

#define OBJ_camellia_128_cmac OBJ_camellia,10L

#define SN_camellia_192_ecb "CAMELLIA-192-ECB"

#define LN_camellia_192_ecb "camellia-192-ecb"

#define NID_camellia_192_ecb 755

#define OBJ_camellia_192_ecb OBJ_camellia,21L

#define SN_camellia_192_ofb128 "CAMELLIA-192-OFB"

#define LN_camellia_192_ofb128 "camellia-192-ofb"

#define NID_camellia_192_ofb128 767

#define OBJ_camellia_192_ofb128 OBJ_camellia,23L

#define SN_camellia_192_cfb128 "CAMELLIA-192-CFB"

#define LN_camellia_192_cfb128 "camellia-192-cfb"

#define NID_camellia_192_cfb128 758

#define OBJ_camellia_192_cfb128 OBJ_camellia,24L

#define SN_camellia_192_gcm "CAMELLIA-192-GCM"

#define LN_camellia_192_gcm "camellia-192-gcm"

#define NID_camellia_192_gcm 965

#define OBJ_camellia_192_gcm OBJ_camellia,26L

#define SN_camellia_192_ccm "CAMELLIA-192-CCM"

#define LN_camellia_192_ccm "camellia-192-ccm"

#define NID_camellia_192_ccm 966

#define OBJ_camellia_192_ccm OBJ_camellia,27L

#define SN_camellia_192_ctr "CAMELLIA-192-CTR"

#define LN_camellia_192_ctr "camellia-192-ctr"

#define NID_camellia_192_ctr 967

#define OBJ_camellia_192_ctr OBJ_camellia,29L

#define SN_camellia_192_cmac "CAMELLIA-192-CMAC"

#define LN_camellia_192_cmac "camellia-192-cmac"

#define NID_camellia_192_cmac 968

#define OBJ_camellia_192_cmac OBJ_camellia,30L

#define SN_camellia_256_ecb "CAMELLIA-256-ECB"

#define LN_camellia_256_ecb "camellia-256-ecb"

#define NID_camellia_256_ecb 756

#define OBJ_camellia_256_ecb OBJ_camellia,41L

#define SN_camellia_256_ofb128 "CAMELLIA-256-OFB"

#define LN_camellia_256_ofb128 "camellia-256-ofb"

#define NID_camellia_256_ofb128 768

#define OBJ_camellia_256_ofb128 OBJ_camellia,43L

#define SN_camellia_256_cfb128 "CAMELLIA-256-CFB"

#define LN_camellia_256_cfb128 "camellia-256-cfb"

#define NID_camellia_256_cfb128 759

#define OBJ_camellia_256_cfb128 OBJ_camellia,44L

#define SN_camellia_256_gcm "CAMELLIA-256-GCM"

#define LN_camellia_256_gcm "camellia-256-gcm"

#define NID_camellia_256_gcm 969

#define OBJ_camellia_256_gcm OBJ_camellia,46L

#define SN_camellia_256_ccm "CAMELLIA-256-CCM"

#define LN_camellia_256_ccm "camellia-256-ccm"

#define NID_camellia_256_ccm 970

#define OBJ_camellia_256_ccm OBJ_camellia,47L

#define SN_camellia_256_ctr "CAMELLIA-256-CTR"

#define LN_camellia_256_ctr "camellia-256-ctr"

#define NID_camellia_256_ctr 971

#define OBJ_camellia_256_ctr OBJ_camellia,49L

#define SN_camellia_256_cmac "CAMELLIA-256-CMAC"

#define LN_camellia_256_cmac "camellia-256-cmac"

#define NID_camellia_256_cmac 972

#define OBJ_camellia_256_cmac OBJ_camellia,50L

#define SN_camellia_128_cfb1 "CAMELLIA-128-CFB1"

#define LN_camellia_128_cfb1 "camellia-128-cfb1"

#define NID_camellia_128_cfb1 760

#define SN_camellia_192_cfb1 "CAMELLIA-192-CFB1"

#define LN_camellia_192_cfb1 "camellia-192-cfb1"

#define NID_camellia_192_cfb1 761

#define SN_camellia_256_cfb1 "CAMELLIA-256-CFB1"

#define LN_camellia_256_cfb1 "camellia-256-cfb1"

#define NID_camellia_256_cfb1 762

#define SN_camellia_128_cfb8 "CAMELLIA-128-CFB8"

#define LN_camellia_128_cfb8 "camellia-128-cfb8"

#define NID_camellia_128_cfb8 763

#define SN_camellia_192_cfb8 "CAMELLIA-192-CFB8"

#define LN_camellia_192_cfb8 "camellia-192-cfb8"

#define NID_camellia_192_cfb8 764

#define SN_camellia_256_cfb8 "CAMELLIA-256-CFB8"

#define LN_camellia_256_cfb8 "camellia-256-cfb8"

#define NID_camellia_256_cfb8 765

#define OBJ_aria 1L,2L,410L,200046L,1L,1L

#define SN_aria_128_ecb "ARIA-128-ECB"

#define LN_aria_128_ecb "aria-128-ecb"

#define NID_aria_128_ecb 1065

#define OBJ_aria_128_ecb OBJ_aria,1L

#define SN_aria_128_cbc "ARIA-128-CBC"

#define LN_aria_128_cbc "aria-128-cbc"

#define NID_aria_128_cbc 1066

#define OBJ_aria_128_cbc OBJ_aria,2L

#define SN_aria_128_cfb128 "ARIA-128-CFB"

#define LN_aria_128_cfb128 "aria-128-cfb"

#define NID_aria_128_cfb128 1067

#define OBJ_aria_128_cfb128 OBJ_aria,3L

#define SN_aria_128_ofb128 "ARIA-128-OFB"

#define LN_aria_128_ofb128 "aria-128-ofb"

#define NID_aria_128_ofb128 1068

#define OBJ_aria_128_ofb128 OBJ_aria,4L

#define SN_aria_128_ctr "ARIA-128-CTR"

#define LN_aria_128_ctr "aria-128-ctr"

#define NID_aria_128_ctr 1069

#define OBJ_aria_128_ctr OBJ_aria,5L

#define SN_aria_192_ecb "ARIA-192-ECB"

#define LN_aria_192_ecb "aria-192-ecb"

#define NID_aria_192_ecb 1070

#define OBJ_aria_192_ecb OBJ_aria,6L

#define SN_aria_192_cbc "ARIA-192-CBC"

#define LN_aria_192_cbc "aria-192-cbc"

#define NID_aria_192_cbc 1071

#define OBJ_aria_192_cbc OBJ_aria,7L

#define SN_aria_192_cfb128 "ARIA-192-CFB"

#define LN_aria_192_cfb128 "aria-192-cfb"

#define NID_aria_192_cfb128 1072

#define OBJ_aria_192_cfb128 OBJ_aria,8L

#define SN_aria_192_ofb128 "ARIA-192-OFB"

#define LN_aria_192_ofb128 "aria-192-ofb"

#define NID_aria_192_ofb128 1073

#define OBJ_aria_192_ofb128 OBJ_aria,9L

#define SN_aria_192_ctr "ARIA-192-CTR"

#define LN_aria_192_ctr "aria-192-ctr"

#define NID_aria_192_ctr 1074

#define OBJ_aria_192_ctr OBJ_aria,10L

#define SN_aria_256_ecb "ARIA-256-ECB"

#define LN_aria_256_ecb "aria-256-ecb"

#define NID_aria_256_ecb 1075

#define OBJ_aria_256_ecb OBJ_aria,11L

#define SN_aria_256_cbc "ARIA-256-CBC"

#define LN_aria_256_cbc "aria-256-cbc"

#define NID_aria_256_cbc 1076

#define OBJ_aria_256_cbc OBJ_aria,12L

#define SN_aria_256_cfb128 "ARIA-256-CFB"

#define LN_aria_256_cfb128 "aria-256-cfb"

#define NID_aria_256_cfb128 1077

#define OBJ_aria_256_cfb128 OBJ_aria,13L

#define SN_aria_256_ofb128 "ARIA-256-OFB"

#define LN_aria_256_ofb128 "aria-256-ofb"

#define NID_aria_256_ofb128 1078

#define OBJ_aria_256_ofb128 OBJ_aria,14L

#define SN_aria_256_ctr "ARIA-256-CTR"

#define LN_aria_256_ctr "aria-256-ctr"

#define NID_aria_256_ctr 1079

#define OBJ_aria_256_ctr OBJ_aria,15L

#define SN_aria_128_cfb1 "ARIA-128-CFB1"

#define LN_aria_128_cfb1 "aria-128-cfb1"

#define NID_aria_128_cfb1 1080

#define SN_aria_192_cfb1 "ARIA-192-CFB1"

#define LN_aria_192_cfb1 "aria-192-cfb1"

#define NID_aria_192_cfb1 1081

#define SN_aria_256_cfb1 "ARIA-256-CFB1"

#define LN_aria_256_cfb1 "aria-256-cfb1"

#define NID_aria_256_cfb1 1082

#define SN_aria_128_cfb8 "ARIA-128-CFB8"

#define LN_aria_128_cfb8 "aria-128-cfb8"

#define NID_aria_128_cfb8 1083

#define SN_aria_192_cfb8 "ARIA-192-CFB8"

#define LN_aria_192_cfb8 "aria-192-cfb8"

#define NID_aria_192_cfb8 1084

#define SN_aria_256_cfb8 "ARIA-256-CFB8"

#define LN_aria_256_cfb8 "aria-256-cfb8"

#define NID_aria_256_cfb8 1085

#define SN_aria_128_ccm "ARIA-128-CCM"

#define LN_aria_128_ccm "aria-128-ccm"

#define NID_aria_128_ccm 1120

#define OBJ_aria_128_ccm OBJ_aria,37L

#define SN_aria_192_ccm "ARIA-192-CCM"

#define LN_aria_192_ccm "aria-192-ccm"

#define NID_aria_192_ccm 1121

#define OBJ_aria_192_ccm OBJ_aria,38L

#define SN_aria_256_ccm "ARIA-256-CCM"

#define LN_aria_256_ccm "aria-256-ccm"

#define NID_aria_256_ccm 1122

#define OBJ_aria_256_ccm OBJ_aria,39L

#define SN_aria_128_gcm "ARIA-128-GCM"

#define LN_aria_128_gcm "aria-128-gcm"

#define NID_aria_128_gcm 1123

#define OBJ_aria_128_gcm OBJ_aria,34L

#define SN_aria_192_gcm "ARIA-192-GCM"

#define LN_aria_192_gcm "aria-192-gcm"

#define NID_aria_192_gcm 1124

#define OBJ_aria_192_gcm OBJ_aria,35L

#define SN_aria_256_gcm "ARIA-256-GCM"

#define LN_aria_256_gcm "aria-256-gcm"

#define NID_aria_256_gcm 1125

#define OBJ_aria_256_gcm OBJ_aria,36L

#define SN_kisa "KISA"

#define LN_kisa "kisa"

#define NID_kisa 773

#define OBJ_kisa OBJ_member_body,410L,200004L

#define SN_seed_ecb "SEED-ECB"

#define LN_seed_ecb "seed-ecb"

#define NID_seed_ecb 776

#define OBJ_seed_ecb OBJ_kisa,1L,3L

#define SN_seed_cbc "SEED-CBC"

#define LN_seed_cbc "seed-cbc"

#define NID_seed_cbc 777

#define OBJ_seed_cbc OBJ_kisa,1L,4L

#define SN_seed_cfb128 "SEED-CFB"

#define LN_seed_cfb128 "seed-cfb"

#define NID_seed_cfb128 779

#define OBJ_seed_cfb128 OBJ_kisa,1L,5L

#define SN_seed_ofb128 "SEED-OFB"

#define LN_seed_ofb128 "seed-ofb"

#define NID_seed_ofb128 778

#define OBJ_seed_ofb128 OBJ_kisa,1L,6L

#define SN_sm4_ecb "SM4-ECB"

#define LN_sm4_ecb "sm4-ecb"

#define NID_sm4_ecb 1133

#define OBJ_sm4_ecb OBJ_sm_scheme,104L,1L

#define SN_sm4_cbc "SM4-CBC"

#define LN_sm4_cbc "sm4-cbc"

#define NID_sm4_cbc 1134

#define OBJ_sm4_cbc OBJ_sm_scheme,104L,2L

#define SN_sm4_ofb128 "SM4-OFB"

#define LN_sm4_ofb128 "sm4-ofb"

#define NID_sm4_ofb128 1135

#define OBJ_sm4_ofb128 OBJ_sm_scheme,104L,3L

#define SN_sm4_cfb128 "SM4-CFB"

#define LN_sm4_cfb128 "sm4-cfb"

#define NID_sm4_cfb128 1137

#define OBJ_sm4_cfb128 OBJ_sm_scheme,104L,4L

#define SN_sm4_cfb1 "SM4-CFB1"

#define LN_sm4_cfb1 "sm4-cfb1"

#define NID_sm4_cfb1 1136

#define OBJ_sm4_cfb1 OBJ_sm_scheme,104L,5L

#define SN_sm4_cfb8 "SM4-CFB8"

#define LN_sm4_cfb8 "sm4-cfb8"

#define NID_sm4_cfb8 1138

#define OBJ_sm4_cfb8 OBJ_sm_scheme,104L,6L

#define SN_sm4_ctr "SM4-CTR"

#define LN_sm4_ctr "sm4-ctr"

#define NID_sm4_ctr 1139

#define OBJ_sm4_ctr OBJ_sm_scheme,104L,7L

#define SN_sm4_gcm "SM4-GCM"

#define LN_sm4_gcm "sm4-gcm"

#define NID_sm4_gcm 1248

#define OBJ_sm4_gcm OBJ_sm_scheme,104L,8L

#define SN_sm4_ccm "SM4-CCM"

#define LN_sm4_ccm "sm4-ccm"

#define NID_sm4_ccm 1249

#define OBJ_sm4_ccm OBJ_sm_scheme,104L,9L

#define SN_sm4_xts "SM4-XTS"

#define LN_sm4_xts "sm4-xts"

#define NID_sm4_xts 1290

#define OBJ_sm4_xts OBJ_sm_scheme,104L,10L

#define SN_hmac "HMAC"

#define LN_hmac "hmac"

#define NID_hmac 855

#define SN_cmac "CMAC"

#define LN_cmac "cmac"

#define NID_cmac 894

#define SN_rc4_hmac_md5 "RC4-HMAC-MD5"

#define LN_rc4_hmac_md5 "rc4-hmac-md5"

#define NID_rc4_hmac_md5 915

#define SN_aes_128_cbc_hmac_sha1 "AES-128-CBC-HMAC-SHA1"

#define LN_aes_128_cbc_hmac_sha1 "aes-128-cbc-hmac-sha1"

#define NID_aes_128_cbc_hmac_sha1 916

#define SN_aes_192_cbc_hmac_sha1 "AES-192-CBC-HMAC-SHA1"

#define LN_aes_192_cbc_hmac_sha1 "aes-192-cbc-hmac-sha1"

#define NID_aes_192_cbc_hmac_sha1 917

#define SN_aes_256_cbc_hmac_sha1 "AES-256-CBC-HMAC-SHA1"

#define LN_aes_256_cbc_hmac_sha1 "aes-256-cbc-hmac-sha1"

#define NID_aes_256_cbc_hmac_sha1 918

#define SN_aes_128_cbc_hmac_sha256 "AES-128-CBC-HMAC-SHA256"

#define LN_aes_128_cbc_hmac_sha256 "aes-128-cbc-hmac-sha256"

#define NID_aes_128_cbc_hmac_sha256 948

#define SN_aes_192_cbc_hmac_sha256 "AES-192-CBC-HMAC-SHA256"

#define LN_aes_192_cbc_hmac_sha256 "aes-192-cbc-hmac-sha256"

#define NID_aes_192_cbc_hmac_sha256 949

#define SN_aes_256_cbc_hmac_sha256 "AES-256-CBC-HMAC-SHA256"

#define LN_aes_256_cbc_hmac_sha256 "aes-256-cbc-hmac-sha256"

#define NID_aes_256_cbc_hmac_sha256 950

#define SN_chacha20_poly1305 "ChaCha20-Poly1305"

#define LN_chacha20_poly1305 "chacha20-poly1305"

#define NID_chacha20_poly1305 1018

#define SN_chacha20 "ChaCha20"

#define LN_chacha20 "chacha20"

#define NID_chacha20 1019

#define SN_dhpublicnumber "dhpublicnumber"

#define LN_dhpublicnumber "X9.42 DH"

#define NID_dhpublicnumber 920

#define OBJ_dhpublicnumber OBJ_ISO_US,10046L,2L,1L

#define SN_brainpoolP160r1 "brainpoolP160r1"

#define NID_brainpoolP160r1 921

#define OBJ_brainpoolP160r1 1L,3L,36L,3L,3L,2L,8L,1L,1L,1L

#define SN_brainpoolP160t1 "brainpoolP160t1"

#define NID_brainpoolP160t1 922

#define OBJ_brainpoolP160t1 1L,3L,36L,3L,3L,2L,8L,1L,1L,2L

#define SN_brainpoolP192r1 "brainpoolP192r1"

#define NID_brainpoolP192r1 923

#define OBJ_brainpoolP192r1 1L,3L,36L,3L,3L,2L,8L,1L,1L,3L

#define SN_brainpoolP192t1 "brainpoolP192t1"

#define NID_brainpoolP192t1 924

#define OBJ_brainpoolP192t1 1L,3L,36L,3L,3L,2L,8L,1L,1L,4L

#define SN_brainpoolP224r1 "brainpoolP224r1"

#define NID_brainpoolP224r1 925

#define OBJ_brainpoolP224r1 1L,3L,36L,3L,3L,2L,8L,1L,1L,5L

#define SN_brainpoolP224t1 "brainpoolP224t1"

#define NID_brainpoolP224t1 926

#define OBJ_brainpoolP224t1 1L,3L,36L,3L,3L,2L,8L,1L,1L,6L

#define SN_brainpoolP256r1 "brainpoolP256r1"

#define NID_brainpoolP256r1 927

#define OBJ_brainpoolP256r1 1L,3L,36L,3L,3L,2L,8L,1L,1L,7L

#define SN_brainpoolP256r1tls13 "brainpoolP256r1tls13"

#define NID_brainpoolP256r1tls13 1285

#define SN_brainpoolP256t1 "brainpoolP256t1"

#define NID_brainpoolP256t1 928

#define OBJ_brainpoolP256t1 1L,3L,36L,3L,3L,2L,8L,1L,1L,8L

#define SN_brainpoolP320r1 "brainpoolP320r1"

#define NID_brainpoolP320r1 929

#define OBJ_brainpoolP320r1 1L,3L,36L,3L,3L,2L,8L,1L,1L,9L

#define SN_brainpoolP320t1 "brainpoolP320t1"

#define NID_brainpoolP320t1 930

#define OBJ_brainpoolP320t1 1L,3L,36L,3L,3L,2L,8L,1L,1L,10L

#define SN_brainpoolP384r1 "brainpoolP384r1"

#define NID_brainpoolP384r1 931

#define OBJ_brainpoolP384r1 1L,3L,36L,3L,3L,2L,8L,1L,1L,11L

#define SN_brainpoolP384r1tls13 "brainpoolP384r1tls13"

#define NID_brainpoolP384r1tls13 1286

#define SN_brainpoolP384t1 "brainpoolP384t1"

#define NID_brainpoolP384t1 932

#define OBJ_brainpoolP384t1 1L,3L,36L,3L,3L,2L,8L,1L,1L,12L

#define SN_brainpoolP512r1 "brainpoolP512r1"

#define NID_brainpoolP512r1 933

#define OBJ_brainpoolP512r1 1L,3L,36L,3L,3L,2L,8L,1L,1L,13L

#define SN_brainpoolP512r1tls13 "brainpoolP512r1tls13"

#define NID_brainpoolP512r1tls13 1287

#define SN_brainpoolP512t1 "brainpoolP512t1"

#define NID_brainpoolP512t1 934

#define OBJ_brainpoolP512t1 1L,3L,36L,3L,3L,2L,8L,1L,1L,14L

#define OBJ_x9_63_scheme 1L,3L,133L,16L,840L,63L,0L

#define OBJ_secg_scheme OBJ_certicom_arc,1L

#define SN_dhSinglePass_stdDH_sha1kdf_scheme "dhSinglePass-stdDH-sha1kdf-scheme"

#define NID_dhSinglePass_stdDH_sha1kdf_scheme 936

#define OBJ_dhSinglePass_stdDH_sha1kdf_scheme OBJ_x9_63_scheme,2L

#define SN_dhSinglePass_stdDH_sha224kdf_scheme "dhSinglePass-stdDH-sha224kdf-scheme"

#define NID_dhSinglePass_stdDH_sha224kdf_scheme 937

#define OBJ_dhSinglePass_stdDH_sha224kdf_scheme OBJ_secg_scheme,11L,0L

#define SN_dhSinglePass_stdDH_sha256kdf_scheme "dhSinglePass-stdDH-sha256kdf-scheme"

#define NID_dhSinglePass_stdDH_sha256kdf_scheme 938

#define OBJ_dhSinglePass_stdDH_sha256kdf_scheme OBJ_secg_scheme,11L,1L

#define SN_dhSinglePass_stdDH_sha384kdf_scheme "dhSinglePass-stdDH-sha384kdf-scheme"

#define NID_dhSinglePass_stdDH_sha384kdf_scheme 939

#define OBJ_dhSinglePass_stdDH_sha384kdf_scheme OBJ_secg_scheme,11L,2L

#define SN_dhSinglePass_stdDH_sha512kdf_scheme "dhSinglePass-stdDH-sha512kdf-scheme"

#define NID_dhSinglePass_stdDH_sha512kdf_scheme 940

#define OBJ_dhSinglePass_stdDH_sha512kdf_scheme OBJ_secg_scheme,11L,3L

#define SN_dhSinglePass_cofactorDH_sha1kdf_scheme "dhSinglePass-cofactorDH-sha1kdf-scheme"

#define NID_dhSinglePass_cofactorDH_sha1kdf_scheme 941

#define OBJ_dhSinglePass_cofactorDH_sha1kdf_scheme OBJ_x9_63_scheme,3L

#define SN_dhSinglePass_cofactorDH_sha224kdf_scheme "dhSinglePass-cofactorDH-sha224kdf-scheme"

#define NID_dhSinglePass_cofactorDH_sha224kdf_scheme 942

#define OBJ_dhSinglePass_cofactorDH_sha224kdf_scheme OBJ_secg_scheme,14L,0L

#define SN_dhSinglePass_cofactorDH_sha256kdf_scheme "dhSinglePass-cofactorDH-sha256kdf-scheme"

#define NID_dhSinglePass_cofactorDH_sha256kdf_scheme 943

#define OBJ_dhSinglePass_cofactorDH_sha256kdf_scheme OBJ_secg_scheme,14L,1L

#define SN_dhSinglePass_cofactorDH_sha384kdf_scheme "dhSinglePass-cofactorDH-sha384kdf-scheme"

#define NID_dhSinglePass_cofactorDH_sha384kdf_scheme 944

#define OBJ_dhSinglePass_cofactorDH_sha384kdf_scheme OBJ_secg_scheme,14L,2L

#define SN_dhSinglePass_cofactorDH_sha512kdf_scheme "dhSinglePass-cofactorDH-sha512kdf-scheme"

#define NID_dhSinglePass_cofactorDH_sha512kdf_scheme 945

#define OBJ_dhSinglePass_cofactorDH_sha512kdf_scheme OBJ_secg_scheme,14L,3L

#define SN_dh_std_kdf "dh-std-kdf"

#define NID_dh_std_kdf 946

#define SN_dh_cofactor_kdf "dh-cofactor-kdf"

#define NID_dh_cofactor_kdf 947

#define SN_ct_precert_scts "ct_precert_scts"

#define LN_ct_precert_scts "CT Precertificate SCTs"

#define NID_ct_precert_scts 951

#define OBJ_ct_precert_scts 1L,3L,6L,1L,4L,1L,11129L,2L,4L,2L

#define SN_ct_precert_poison "ct_precert_poison"

#define LN_ct_precert_poison "CT Precertificate Poison"

#define NID_ct_precert_poison 952

#define OBJ_ct_precert_poison 1L,3L,6L,1L,4L,1L,11129L,2L,4L,3L

#define SN_ct_precert_signer "ct_precert_signer"

#define LN_ct_precert_signer "CT Precertificate Signer"

#define NID_ct_precert_signer 953

#define OBJ_ct_precert_signer 1L,3L,6L,1L,4L,1L,11129L,2L,4L,4L

#define SN_ct_cert_scts "ct_cert_scts"

#define LN_ct_cert_scts "CT Certificate SCTs"

#define NID_ct_cert_scts 954

#define OBJ_ct_cert_scts 1L,3L,6L,1L,4L,1L,11129L,2L,4L,5L

#define SN_jurisdictionLocalityName "jurisdictionL"

#define LN_jurisdictionLocalityName "jurisdictionLocalityName"

#define NID_jurisdictionLocalityName 955

#define OBJ_jurisdictionLocalityName OBJ_ms_corp,60L,2L,1L,1L

#define SN_jurisdictionStateOrProvinceName "jurisdictionST"

#define LN_jurisdictionStateOrProvinceName "jurisdictionStateOrProvinceName"

#define NID_jurisdictionStateOrProvinceName 956

#define OBJ_jurisdictionStateOrProvinceName OBJ_ms_corp,60L,2L,1L,2L

#define SN_jurisdictionCountryName "jurisdictionC"

#define LN_jurisdictionCountryName "jurisdictionCountryName"

#define NID_jurisdictionCountryName 957

#define OBJ_jurisdictionCountryName OBJ_ms_corp,60L,2L,1L,3L

#define SN_id_scrypt "id-scrypt"

#define LN_id_scrypt "scrypt"

#define NID_id_scrypt 973

#define OBJ_id_scrypt 1L,3L,6L,1L,4L,1L,11591L,4L,11L

#define SN_tls1_prf "TLS1-PRF"

#define LN_tls1_prf "tls1-prf"

#define NID_tls1_prf 1021

#define SN_hkdf "HKDF"

#define LN_hkdf "hkdf"

#define NID_hkdf 1036

#define SN_sshkdf "SSHKDF"

#define LN_sshkdf "sshkdf"

#define NID_sshkdf 1203

#define SN_sskdf "SSKDF"

#define LN_sskdf "sskdf"

#define NID_sskdf 1205

#define SN_x942kdf "X942KDF"

#define LN_x942kdf "x942kdf"

#define NID_x942kdf 1207

#define SN_x963kdf "X963KDF"

#define LN_x963kdf "x963kdf"

#define NID_x963kdf 1206

#define SN_id_pkinit "id-pkinit"

#define NID_id_pkinit 1031

#define OBJ_id_pkinit 1L,3L,6L,1L,5L,2L,3L

#define SN_pkInitClientAuth "pkInitClientAuth"

#define LN_pkInitClientAuth "PKINIT Client Auth"

#define NID_pkInitClientAuth 1032

#define OBJ_pkInitClientAuth OBJ_id_pkinit,4L

#define SN_pkInitKDC "pkInitKDC"

#define LN_pkInitKDC "Signing KDC Response"

#define NID_pkInitKDC 1033

#define OBJ_pkInitKDC OBJ_id_pkinit,5L

#define SN_X25519 "X25519"

#define NID_X25519 1034

#define OBJ_X25519 1L,3L,101L,110L

#define SN_X448 "X448"

#define NID_X448 1035

#define OBJ_X448 1L,3L,101L,111L

#define SN_ED25519 "ED25519"

#define NID_ED25519 1087

#define OBJ_ED25519 1L,3L,101L,112L

#define SN_ED448 "ED448"

#define NID_ED448 1088

#define OBJ_ED448 1L,3L,101L,113L

#define SN_kx_rsa "KxRSA"

#define LN_kx_rsa "kx-rsa"

#define NID_kx_rsa 1037

#define SN_kx_ecdhe "KxECDHE"

#define LN_kx_ecdhe "kx-ecdhe"

#define NID_kx_ecdhe 1038

#define SN_kx_dhe "KxDHE"

#define LN_kx_dhe "kx-dhe"

#define NID_kx_dhe 1039

#define SN_kx_ecdhe_psk "KxECDHE-PSK"

#define LN_kx_ecdhe_psk "kx-ecdhe-psk"

#define NID_kx_ecdhe_psk 1040

#define SN_kx_dhe_psk "KxDHE-PSK"

#define LN_kx_dhe_psk "kx-dhe-psk"

#define NID_kx_dhe_psk 1041

#define SN_kx_rsa_psk "KxRSA_PSK"

#define LN_kx_rsa_psk "kx-rsa-psk"

#define NID_kx_rsa_psk 1042

#define SN_kx_psk "KxPSK"

#define LN_kx_psk "kx-psk"

#define NID_kx_psk 1043

#define SN_kx_srp "KxSRP"

#define LN_kx_srp "kx-srp"

#define NID_kx_srp 1044

#define SN_kx_gost "KxGOST"

#define LN_kx_gost "kx-gost"

#define NID_kx_gost 1045

#define SN_kx_gost18 "KxGOST18"

#define LN_kx_gost18 "kx-gost18"

#define NID_kx_gost18 1218

#define SN_kx_any "KxANY"

#define LN_kx_any "kx-any"

#define NID_kx_any 1063

#define SN_auth_rsa "AuthRSA"

#define LN_auth_rsa "auth-rsa"

#define NID_auth_rsa 1046

#define SN_auth_ecdsa "AuthECDSA"

#define LN_auth_ecdsa "auth-ecdsa"

#define NID_auth_ecdsa 1047

#define SN_auth_psk "AuthPSK"

#define LN_auth_psk "auth-psk"

#define NID_auth_psk 1048

#define SN_auth_dss "AuthDSS"

#define LN_auth_dss "auth-dss"

#define NID_auth_dss 1049

#define SN_auth_gost01 "AuthGOST01"

#define LN_auth_gost01 "auth-gost01"

#define NID_auth_gost01 1050

#define SN_auth_gost12 "AuthGOST12"

#define LN_auth_gost12 "auth-gost12"

#define NID_auth_gost12 1051

#define SN_auth_srp "AuthSRP"

#define LN_auth_srp "auth-srp"

#define NID_auth_srp 1052

#define SN_auth_null "AuthNULL"

#define LN_auth_null "auth-null"

#define NID_auth_null 1053

#define SN_auth_any "AuthANY"

#define LN_auth_any "auth-any"

#define NID_auth_any 1064

#define SN_poly1305 "Poly1305"

#define LN_poly1305 "poly1305"

#define NID_poly1305 1061

#define SN_siphash "SipHash"

#define LN_siphash "siphash"

#define NID_siphash 1062

#define SN_ffdhe2048 "ffdhe2048"

#define NID_ffdhe2048 1126

#define SN_ffdhe3072 "ffdhe3072"

#define NID_ffdhe3072 1127

#define SN_ffdhe4096 "ffdhe4096"

#define NID_ffdhe4096 1128

#define SN_ffdhe6144 "ffdhe6144"

#define NID_ffdhe6144 1129

#define SN_ffdhe8192 "ffdhe8192"

#define NID_ffdhe8192 1130

#define SN_modp_1536 "modp_1536"

#define NID_modp_1536 1212

#define SN_modp_2048 "modp_2048"

#define NID_modp_2048 1213

#define SN_modp_3072 "modp_3072"

#define NID_modp_3072 1214

#define SN_modp_4096 "modp_4096"

#define NID_modp_4096 1215

#define SN_modp_6144 "modp_6144"

#define NID_modp_6144 1216

#define SN_modp_8192 "modp_8192"

#define NID_modp_8192 1217

#define SN_ISO_UA "ISO-UA"

#define NID_ISO_UA 1150

#define OBJ_ISO_UA OBJ_member_body,804L

#define SN_ua_pki "ua-pki"

#define NID_ua_pki 1151

#define OBJ_ua_pki OBJ_ISO_UA,2L,1L,1L,1L

#define SN_dstu28147 "dstu28147"

#define LN_dstu28147 "DSTU Gost 28147-2009"

#define NID_dstu28147 1152

#define OBJ_dstu28147 OBJ_ua_pki,1L,1L,1L

#define SN_dstu28147_ofb "dstu28147-ofb"

#define LN_dstu28147_ofb "DSTU Gost 28147-2009 OFB mode"

#define NID_dstu28147_ofb 1153

#define OBJ_dstu28147_ofb OBJ_dstu28147,2L

#define SN_dstu28147_cfb "dstu28147-cfb"

#define LN_dstu28147_cfb "DSTU Gost 28147-2009 CFB mode"

#define NID_dstu28147_cfb 1154

#define OBJ_dstu28147_cfb OBJ_dstu28147,3L

#define SN_dstu28147_wrap "dstu28147-wrap"

#define LN_dstu28147_wrap "DSTU Gost 28147-2009 key wrap"

#define NID_dstu28147_wrap 1155

#define OBJ_dstu28147_wrap OBJ_dstu28147,5L

#define SN_hmacWithDstu34311 "hmacWithDstu34311"

#define LN_hmacWithDstu34311 "HMAC DSTU Gost 34311-95"

#define NID_hmacWithDstu34311 1156

#define OBJ_hmacWithDstu34311 OBJ_ua_pki,1L,1L,2L

#define SN_dstu34311 "dstu34311"

#define LN_dstu34311 "DSTU Gost 34311-95"

#define NID_dstu34311 1157

#define OBJ_dstu34311 OBJ_ua_pki,1L,2L,1L

#define SN_dstu4145le "dstu4145le"

#define LN_dstu4145le "DSTU 4145-2002 little endian"

#define NID_dstu4145le 1158

#define OBJ_dstu4145le OBJ_ua_pki,1L,3L,1L,1L

#define SN_dstu4145be "dstu4145be"

#define LN_dstu4145be "DSTU 4145-2002 big endian"

#define NID_dstu4145be 1159

#define OBJ_dstu4145be OBJ_dstu4145le,1L,1L

#define SN_uacurve0 "uacurve0"

#define LN_uacurve0 "DSTU curve 0"

#define NID_uacurve0 1160

#define OBJ_uacurve0 OBJ_dstu4145le,2L,0L

#define SN_uacurve1 "uacurve1"

#define LN_uacurve1 "DSTU curve 1"

#define NID_uacurve1 1161

#define OBJ_uacurve1 OBJ_dstu4145le,2L,1L

#define SN_uacurve2 "uacurve2"

#define LN_uacurve2 "DSTU curve 2"

#define NID_uacurve2 1162

#define OBJ_uacurve2 OBJ_dstu4145le,2L,2L

#define SN_uacurve3 "uacurve3"

#define LN_uacurve3 "DSTU curve 3"

#define NID_uacurve3 1163

#define OBJ_uacurve3 OBJ_dstu4145le,2L,3L

#define SN_uacurve4 "uacurve4"

#define LN_uacurve4 "DSTU curve 4"

#define NID_uacurve4 1164

#define OBJ_uacurve4 OBJ_dstu4145le,2L,4L

#define SN_uacurve5 "uacurve5"

#define LN_uacurve5 "DSTU curve 5"

#define NID_uacurve5 1165

#define OBJ_uacurve5 OBJ_dstu4145le,2L,5L

#define SN_uacurve6 "uacurve6"

#define LN_uacurve6 "DSTU curve 6"

#define NID_uacurve6 1166

#define OBJ_uacurve6 OBJ_dstu4145le,2L,6L

#define SN_uacurve7 "uacurve7"

#define LN_uacurve7 "DSTU curve 7"

#define NID_uacurve7 1167

#define OBJ_uacurve7 OBJ_dstu4145le,2L,7L

#define SN_uacurve8 "uacurve8"

#define LN_uacurve8 "DSTU curve 8"

#define NID_uacurve8 1168

#define OBJ_uacurve8 OBJ_dstu4145le,2L,8L

#define SN_uacurve9 "uacurve9"

#define LN_uacurve9 "DSTU curve 9"

#define NID_uacurve9 1169

#define OBJ_uacurve9 OBJ_dstu4145le,2L,9L

#define SN_aes_128_siv "AES-128-SIV"

#define LN_aes_128_siv "aes-128-siv"

#define NID_aes_128_siv 1198

#define SN_aes_192_siv "AES-192-SIV"

#define LN_aes_192_siv "aes-192-siv"

#define NID_aes_192_siv 1199

#define SN_aes_256_siv "AES-256-SIV"

#define LN_aes_256_siv "aes-256-siv"

#define NID_aes_256_siv 1200

#define SN_oracle "oracle-organization"

#define LN_oracle "Oracle organization"

#define NID_oracle 1282

#define OBJ_oracle OBJ_joint_iso_itu_t,16L,840L,1L,113894L

#define SN_oracle_jdk_trustedkeyusage "oracle-jdk-trustedkeyusage"

#define LN_oracle_jdk_trustedkeyusage "Trusted key usage (Oracle)"

#define NID_oracle_jdk_trustedkeyusage 1283

#define OBJ_oracle_jdk_trustedkeyusage OBJ_oracle,746875L,1L,1L

#define SN_brotli "brotli"

#define LN_brotli "Brotli compression"

#define NID_brotli 1288

#define SN_zstd "zstd"

#define LN_zstd "Zstandard compression"

#define NID_zstd 1289

#define SN_id_tc26_cipher_gostr3412_2015_magma_ctracpkm SN_magma_ctr_acpkm

#define NID_id_tc26_cipher_gostr3412_2015_magma_ctracpkm NID_magma_ctr_acpkm

#define OBJ_id_tc26_cipher_gostr3412_2015_magma_ctracpkm OBJ_magma_ctr_acpkm

#define SN_id_tc26_cipher_gostr3412_2015_magma_ctracpkm_omac SN_magma_ctr_acpkm_omac

#define NID_id_tc26_cipher_gostr3412_2015_magma_ctracpkm_omac NID_magma_ctr_acpkm_omac

#define OBJ_id_tc26_cipher_gostr3412_2015_magma_ctracpkm_omac OBJ_magma_ctr_acpkm_omac

#define SN_id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm SN_kuznyechik_ctr_acpkm

#define NID_id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm NID_kuznyechik_ctr_acpkm

#define OBJ_id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm OBJ_kuznyechik_ctr_acpkm

#define SN_id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm_omac SN_kuznyechik_ctr_acpkm_omac

#define NID_id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm_omac NID_kuznyechik_ctr_acpkm_omac

#define OBJ_id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm_omac OBJ_kuznyechik_ctr_acpkm_omac

#define SN_id_tc26_wrap_gostr3412_2015_magma_kexp15 SN_magma_kexp15

#define NID_id_tc26_wrap_gostr3412_2015_magma_kexp15 NID_magma_kexp15

#define OBJ_id_tc26_wrap_gostr3412_2015_magma_kexp15 OBJ_magma_kexp15

#define SN_id_tc26_wrap_gostr3412_2015_kuznyechik_kexp15 SN_kuznyechik_kexp15

#define NID_id_tc26_wrap_gostr3412_2015_kuznyechik_kexp15 NID_kuznyechik_kexp15

#define OBJ_id_tc26_wrap_gostr3412_2015_kuznyechik_kexp15 OBJ_kuznyechik_kexp15

#define SN_grasshopper_ecb SN_kuznyechik_ecb

#define NID_grasshopper_ecb NID_kuznyechik_ecb

#define SN_grasshopper_ctr SN_kuznyechik_ctr

#define NID_grasshopper_ctr NID_kuznyechik_ctr

#define SN_grasshopper_ofb SN_kuznyechik_ofb

#define NID_grasshopper_ofb NID_kuznyechik_ofb

#define SN_grasshopper_cbc SN_kuznyechik_cbc

#define NID_grasshopper_cbc NID_kuznyechik_cbc

#define SN_grasshopper_cfb SN_kuznyechik_cfb

#define NID_grasshopper_cfb NID_kuznyechik_cfb

#define SN_grasshopper_mac SN_kuznyechik_mac

#define NID_grasshopper_mac NID_kuznyechik_mac

#define OPENSSL_OCSP_H 

#define HEADER_OCSP_H 

#define OCSP_REVOKED_STATUS_NOSTATUS -1

#define OCSP_REVOKED_STATUS_UNSPECIFIED 0

#define OCSP_REVOKED_STATUS_KEYCOMPROMISE 1

#define OCSP_REVOKED_STATUS_CACOMPROMISE 2

#define OCSP_REVOKED_STATUS_AFFILIATIONCHANGED 3

#define OCSP_REVOKED_STATUS_SUPERSEDED 4

#define OCSP_REVOKED_STATUS_CESSATIONOFOPERATION 5

#define OCSP_REVOKED_STATUS_CERTIFICATEHOLD 6

#define OCSP_REVOKED_STATUS_REMOVEFROMCRL 8

#define OCSP_REVOKED_STATUS_PRIVILEGEWITHDRAWN 9

#define OCSP_REVOKED_STATUS_AACOMPROMISE 10

#define OCSP_DEFAULT_NONCE_LENGTH 16

#define OCSP_NOCERTS 0x1

#define OCSP_NOINTERN 0x2

#define OCSP_NOSIGS 0x4

#define OCSP_NOCHAIN 0x8

#define OCSP_NOVERIFY 0x10

#define OCSP_NOEXPLICIT 0x20

#define OCSP_NOCASIGN 0x40

#define OCSP_NODELEGATED 0x80

#define OCSP_NOCHECKS 0x100

#define OCSP_TRUSTOTHER 0x200

#define OCSP_RESPID_KEY 0x400

#define OCSP_NOTIME 0x800

#define OCSP_PARTIAL_CHAIN 0x1000

#define OCSP_RESPONSE_STATUS_SUCCESSFUL 0

#define OCSP_RESPONSE_STATUS_MALFORMEDREQUEST 1

#define OCSP_RESPONSE_STATUS_INTERNALERROR 2

#define OCSP_RESPONSE_STATUS_TRYLATER 3

#define OCSP_RESPONSE_STATUS_SIGREQUIRED 5

#define OCSP_RESPONSE_STATUS_UNAUTHORIZED 6

#define V_OCSP_RESPID_NAME 0

#define V_OCSP_RESPID_KEY 1

#define V_OCSP_CERTSTATUS_GOOD 0

#define V_OCSP_CERTSTATUS_REVOKED 1

#define V_OCSP_CERTSTATUS_UNKNOWN 2

#define PEM_STRING_OCSP_REQUEST "OCSP REQUEST"

#define PEM_STRING_OCSP_RESPONSE "OCSP RESPONSE"

#define d2i_OCSP_REQUEST_bio (bp,p) ASN1_d2i_bio_of(OCSP_REQUEST,OCSP_REQUEST_new,d2i_OCSP_REQUEST,bp,p)

#define d2i_OCSP_RESPONSE_bio (bp,p) ASN1_d2i_bio_of(OCSP_RESPONSE,OCSP_RESPONSE_new,d2i_OCSP_RESPONSE,bp,p)

#define PEM_read_bio_OCSP_REQUEST (bp,x,cb) (OCSP_REQUEST *)PEM_ASN1_read_bio(\
	(char *(*)())d2i_OCSP_REQUEST,PEM_STRING_OCSP_REQUEST, \\
	bp,(char **)(x),cb,NULL)

#define PEM_read_bio_OCSP_RESPONSE (bp,x,cb) (OCSP_RESPONSE *)PEM_ASN1_read_bio(\
	(char *(*)())d2i_OCSP_RESPONSE,PEM_STRING_OCSP_RESPONSE, \\
	bp,(char **)(x),cb,NULL)

#define PEM_write_bio_OCSP_REQUEST (bp,o)\
	PEM_ASN1_write_bio((int (*)())i2d_OCSP_REQUEST,PEM_STRING_OCSP_REQUEST,\\
	bp,(char *)(o), NULL,NULL,0,NULL,NULL)

#define PEM_write_bio_OCSP_RESPONSE (bp,o)\
	PEM_ASN1_write_bio((int (*)())i2d_OCSP_RESPONSE,PEM_STRING_OCSP_RESPONSE,\\
	bp,(char *)(o), NULL,NULL,0,NULL,NULL)

#define i2d_OCSP_RESPONSE_bio (bp,o) ASN1_i2d_bio_of(OCSP_RESPONSE,i2d_OCSP_RESPONSE,bp,o)

#define i2d_OCSP_REQUEST_bio (bp,o) ASN1_i2d_bio_of(OCSP_REQUEST,i2d_OCSP_REQUEST,bp,o)

#define ASN1_BIT_STRING_digest (data,type,md,len)\
	ASN1_item_digest(ASN1_ITEM_rptr(ASN1_BIT_STRING),type,data,md,len)

#define OCSP_CERTSTATUS_dup (cs)\
	(OCSP_CERTSTATUS*)ASN1_dup((i2d_of_void *)i2d_OCSP_CERTSTATUS,\\
	(d2i_of_void *)d2i_OCSP_CERTSTATUS,(char *)(cs))

#define OCSP_REQ_CTX_new (io, buf_size)\
	OSSL_HTTP_REQ_CTX_new(io, io, buf_size)

#define OCSP_REQ_CTX_free OSSL_HTTP_REQ_CTX_free

#define OCSP_REQ_CTX_http (rctx, op, path)\
	(OSSL_HTTP_REQ_CTX_set_expected(rctx, NULL, 1  , 0, 0) && \\
	OSSL_HTTP_REQ_CTX_set_request_line(rctx, strcmp(op, "POST") == 0, \\
	NULL, NULL, path))

#define OCSP_REQ_CTX_add1_header OSSL_HTTP_REQ_CTX_add1_header

#define OCSP_REQ_CTX_i2d (r, it, req)\
	OSSL_HTTP_REQ_CTX_set1_req(r, "application/ocsp-request", it, req)

#define OCSP_REQ_CTX_set1_req (r, req)\
	OCSP_REQ_CTX_i2d(r, ASN1_ITEM_rptr(OCSP_REQUEST), (ASN1_VALUE *)(req))

#define OCSP_REQ_CTX_nbio OSSL_HTTP_REQ_CTX_nbio

#define OCSP_REQ_CTX_nbio_d2i OSSL_HTTP_REQ_CTX_nbio_d2i

#define OCSP_sendreq_nbio (p, r)\
	OSSL_HTTP_REQ_CTX_nbio_d2i(r, (ASN1_VALUE **)(p), \\
	ASN1_ITEM_rptr(OCSP_RESPONSE))

#define OCSP_REQ_CTX_get0_mem_bio OSSL_HTTP_REQ_CTX_get0_mem_bio

#define OCSP_set_max_response_length OSSL_HTTP_REQ_CTX_set_max_response_length

#define OCSP_parse_url (url, host, port, path, ssl)\
	OSSL_HTTP_parse_url(url, ssl, NULL, host, port, NULL, path, NULL, NULL)

#define OPENSSL_OCSPERR_H 

#define OCSP_R_CERTIFICATE_VERIFY_ERROR 101

#define OCSP_R_DIGEST_ERR 102

#define OCSP_R_DIGEST_NAME_ERR 106

#define OCSP_R_DIGEST_SIZE_ERR 107

#define OCSP_R_ERROR_IN_NEXTUPDATE_FIELD 122

#define OCSP_R_ERROR_IN_THISUPDATE_FIELD 123

#define OCSP_R_MISSING_OCSPSIGNING_USAGE 103

#define OCSP_R_NEXTUPDATE_BEFORE_THISUPDATE 124

#define OCSP_R_NOT_BASIC_RESPONSE 104

#define OCSP_R_NO_CERTIFICATES_IN_CHAIN 105

#define OCSP_R_NO_RESPONSE_DATA 108

#define OCSP_R_NO_REVOKED_TIME 109

#define OCSP_R_NO_SIGNER_KEY 130

#define OCSP_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE 110

#define OCSP_R_REQUEST_NOT_SIGNED 128

#define OCSP_R_RESPONSE_CONTAINS_NO_REVOCATION_DATA 111

#define OCSP_R_ROOT_CA_NOT_TRUSTED 112

#define OCSP_R_SIGNATURE_FAILURE 117

#define OCSP_R_SIGNER_CERTIFICATE_NOT_FOUND 118

#define OCSP_R_STATUS_EXPIRED 125

#define OCSP_R_STATUS_NOT_YET_VALID 126

#define OCSP_R_STATUS_TOO_OLD 127

#define OCSP_R_UNKNOWN_MESSAGE_DIGEST 119

#define OCSP_R_UNKNOWN_NID 120

#define OCSP_R_UNSUPPORTED_REQUESTORNAME_TYPE 129

#define OPENSSL_OPENSSLCONF_H 

#define OPENSSL_OPENSSLV_H 

#define OPENSSL_VERSION_MAJOR {- $config{major} -}

#define OPENSSL_VERSION_MINOR {- $config{minor} -}

#define OPENSSL_VERSION_PATCH {- $config{patch} -}

#define OPENSSL_VERSION_PRE_RELEASE "{- $config{prerelease} -}"

#define OPENSSL_VERSION_BUILD_METADATA "{- $config{build_metadata} -}"

#define OPENSSL_SHLIB_VERSION {- $config{shlib_version} -}

#define OPENSSL_VERSION_PREREQ (maj,min)\
	((OPENSSL_VERSION_MAJOR << 16) + OPENSSL_VERSION_MINOR >= ((maj) << 16) + (min))

#define OPENSSL_VERSION_STR "{- $config{version} -}"

#define OPENSSL_FULL_VERSION_STR "{- $config{full_version} -}"

#define OPENSSL_RELEASE_DATE "{- $config{release_date} -}"

#define OPENSSL_VERSION_TEXT "OpenSSL {- "$config{full_version} $config{release_date}" -}"

#define _OPENSSL_VERSION_PRE_RELEASE 0x0L

#define OPENSSL_VERSION_NUMBER \
	( (OPENSSL_VERSION_MAJOR<<28)        \\
	|(OPENSSL_VERSION_MINOR<<20)       \\
	|(OPENSSL_VERSION_PATCH<<4)        \\
	|_OPENSSL_VERSION_PRE_RELEASE )

#define HEADER_OPENSSLV_H 

#define OPENSSL_PARAMS_H 

#define OSSL_PARAM_UNMODIFIED ((size_t)-1)

#define OSSL_PARAM_END \
	{ NULL, 0, NULL, 0, 0 }

#define OSSL_PARAM_DEFN (key, type, addr, sz)\
	{ (key), (type), (addr), (sz), OSSL_PARAM_UNMODIFIED }

#define OSSL_PARAM_int (key, addr)\
	OSSL_PARAM_DEFN((key), OSSL_PARAM_INTEGER, (addr), sizeof(int))

#define OSSL_PARAM_uint (key, addr)\
	OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (addr), \\
	sizeof(unsigned int))

#define OSSL_PARAM_long (key, addr)\
	OSSL_PARAM_DEFN((key), OSSL_PARAM_INTEGER, (addr), sizeof(long int))

#define OSSL_PARAM_ulong (key, addr)\
	OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (addr), \\
	sizeof(unsigned long int))

#define OSSL_PARAM_int32 (key, addr)\
	OSSL_PARAM_DEFN((key), OSSL_PARAM_INTEGER, (addr), sizeof(int32_t))

#define OSSL_PARAM_uint32 (key, addr)\
	OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (addr), \\
	sizeof(uint32_t))

#define OSSL_PARAM_int64 (key, addr)\
	OSSL_PARAM_DEFN((key), OSSL_PARAM_INTEGER, (addr), sizeof(int64_t))

#define OSSL_PARAM_uint64 (key, addr)\
	OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (addr), \\
	sizeof(uint64_t))

#define OSSL_PARAM_size_t (key, addr)\
	OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (addr), sizeof(size_t))

#define OSSL_PARAM_time_t (key, addr)\
	OSSL_PARAM_DEFN((key), OSSL_PARAM_INTEGER, (addr), sizeof(time_t))

#define OSSL_PARAM_double (key, addr)\
	OSSL_PARAM_DEFN((key), OSSL_PARAM_REAL, (addr), sizeof(double))

#define OSSL_PARAM_BN (key, bn, sz)\
	OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (bn), (sz))

#define OSSL_PARAM_utf8_string (key, addr, sz)\
	OSSL_PARAM_DEFN((key), OSSL_PARAM_UTF8_STRING, (addr), sz)

#define OSSL_PARAM_octet_string (key, addr, sz)\
	OSSL_PARAM_DEFN((key), OSSL_PARAM_OCTET_STRING, (addr), sz)

#define OSSL_PARAM_utf8_ptr (key, addr, sz)\
	OSSL_PARAM_DEFN((key), OSSL_PARAM_UTF8_PTR, (addr), sz)

#define OSSL_PARAM_octet_ptr (key, addr, sz)\
	OSSL_PARAM_DEFN((key), OSSL_PARAM_OCTET_PTR, (addr), sz)

#define OPENSSL_PARAM_BUILD_H 

#define OPENSSL_PEM_H 

#define HEADER_PEM_H 

#define PEM_BUFSIZE 1024

#define PEM_STRING_X509_OLD "X509 CERTIFICATE"

#define PEM_STRING_X509 "CERTIFICATE"

#define PEM_STRING_X509_TRUSTED "TRUSTED CERTIFICATE"

#define PEM_STRING_X509_REQ_OLD "NEW CERTIFICATE REQUEST"

#define PEM_STRING_X509_REQ "CERTIFICATE REQUEST"

#define PEM_STRING_X509_CRL "X509 CRL"

#define PEM_STRING_EVP_PKEY "ANY PRIVATE KEY"

#define PEM_STRING_PUBLIC "PUBLIC KEY"

#define PEM_STRING_RSA "RSA PRIVATE KEY"

#define PEM_STRING_RSA_PUBLIC "RSA PUBLIC KEY"

#define PEM_STRING_DSA "DSA PRIVATE KEY"

#define PEM_STRING_DSA_PUBLIC "DSA PUBLIC KEY"

#define PEM_STRING_PKCS7 "PKCS7"

#define PEM_STRING_PKCS7_SIGNED "PKCS #7 SIGNED DATA"

#define PEM_STRING_PKCS8 "ENCRYPTED PRIVATE KEY"

#define PEM_STRING_PKCS8INF "PRIVATE KEY"

#define PEM_STRING_DHPARAMS "DH PARAMETERS"

#define PEM_STRING_DHXPARAMS "X9.42 DH PARAMETERS"

#define PEM_STRING_SSL_SESSION "SSL SESSION PARAMETERS"

#define PEM_STRING_DSAPARAMS "DSA PARAMETERS"

#define PEM_STRING_ECDSA_PUBLIC "ECDSA PUBLIC KEY"

#define PEM_STRING_ECPARAMETERS "EC PARAMETERS"

#define PEM_STRING_ECPRIVATEKEY "EC PRIVATE KEY"

#define PEM_STRING_PARAMETERS "PARAMETERS"

#define PEM_STRING_CMS "CMS"

#define PEM_STRING_SM2PARAMETERS "SM2 PARAMETERS"

#define PEM_TYPE_ENCRYPTED 10

#define PEM_TYPE_MIC_ONLY 20

#define PEM_TYPE_MIC_CLEAR 30

#define PEM_TYPE_CLEAR 40

#define PEM_read_cb_fnsig (name, type, INTYPE, readname)\
	type *PEM_##readname##_##name(INTYPE *out, type **x,                \\
	pem_password_cb *cb, void *u)

#define PEM_read_cb_ex_fnsig (name, type, INTYPE, readname)\
	type *PEM_##readname##_##name##_ex(INTYPE *out, type **x,           \\
	pem_password_cb *cb, void *u,    \\
	OSSL_LIB_CTX *libctx,            \\
	const char *propq)

#define PEM_write_fnsig (name, type, OUTTYPE, writename)\
	int PEM_##writename##_##name(OUTTYPE *out, const type *x)

#define PEM_write_cb_fnsig (name, type, OUTTYPE, writename)\
	int PEM_##writename##_##name(OUTTYPE *out, const type *x,           \\
	const EVP_CIPHER *enc,                 \\
	const unsigned char *kstr, int klen,   \\
	pem_password_cb *cb, void *u)

#define PEM_write_ex_fnsig (name, type, OUTTYPE, writename)\
	int PEM_##writename##_##name##_ex(OUTTYPE *out, const type *x,      \\
	OSSL_LIB_CTX *libctx,             \\
	const char *propq)

#define PEM_write_cb_ex_fnsig (name, type, OUTTYPE, writename)\
	int PEM_##writename##_##name##_ex(OUTTYPE *out, const type *x,      \\
	const EVP_CIPHER *enc,            \\
	const unsigned char *kstr, int klen, \\
	pem_password_cb *cb, void *u,     \\
	OSSL_LIB_CTX *libctx,             \\
	const char *propq)

#define IMPLEMENT_PEM_read_fp (name, type, str, asn1)

#define IMPLEMENT_PEM_write_fp (name, type, str, asn1)

#define IMPLEMENT_PEM_write_fp_const (name, type, str, asn1)

#define IMPLEMENT_PEM_write_cb_fp (name, type, str, asn1)

#define IMPLEMENT_PEM_write_cb_fp_const (name, type, str, asn1)

#define IMPLEMENT_PEM_read_bio (name, type, str, asn1)\
	type *PEM_read_bio_##name(BIO *bp, type **x,                        \\
	pem_password_cb *cb, void *u)             \\
	{                                                                   \\
	return PEM_ASN1_read_bio((d2i_of_void *)d2i_##asn1, str, bp,    \\
	(void **)x, cb, u);                    \\
	}

#define IMPLEMENT_PEM_write_bio (name, type, str, asn1)\
	PEM_write_fnsig(name, type, BIO, write_bio)                         \\
	{                                                                   \\
	return PEM_ASN1_write_bio((i2d_of_void *)i2d_##asn1, str, out,  \\
	x, NULL,NULL,0,NULL,NULL);            \\
	}

#define IMPLEMENT_PEM_write_bio_const (name, type, str, asn1)\
	IMPLEMENT_PEM_write_bio(name, type, str, asn1)

#define IMPLEMENT_PEM_write_cb_bio (name, type, str, asn1)\
	PEM_write_cb_fnsig(name, type, BIO, write_bio)                      \\
	{                                                                   \\
	return PEM_ASN1_write_bio((i2d_of_void *)i2d_##asn1, str, out,  \\
	x, enc, kstr, klen, cb, u);           \\
	}

#define IMPLEMENT_PEM_write_cb_bio_const (name, type, str, asn1)\
	IMPLEMENT_PEM_write_cb_bio(name, type, str, asn1)

#define IMPLEMENT_PEM_write (name, type, str, asn1)\
	IMPLEMENT_PEM_write_bio(name, type, str, asn1) \\
	IMPLEMENT_PEM_write_fp(name, type, str, asn1)

#define IMPLEMENT_PEM_write_const (name, type, str, asn1)\
	IMPLEMENT_PEM_write_bio_const(name, type, str, asn1) \\
	IMPLEMENT_PEM_write_fp_const(name, type, str, asn1)

#define IMPLEMENT_PEM_write_cb (name, type, str, asn1)\
	IMPLEMENT_PEM_write_cb_bio(name, type, str, asn1) \\
	IMPLEMENT_PEM_write_cb_fp(name, type, str, asn1)

#define IMPLEMENT_PEM_write_cb_const (name, type, str, asn1)\
	IMPLEMENT_PEM_write_cb_bio_const(name, type, str, asn1) \\
	IMPLEMENT_PEM_write_cb_fp_const(name, type, str, asn1)

#define IMPLEMENT_PEM_read (name, type, str, asn1)\
	IMPLEMENT_PEM_read_bio(name, type, str, asn1) \\
	IMPLEMENT_PEM_read_fp(name, type, str, asn1)

#define IMPLEMENT_PEM_rw (name, type, str, asn1)\
	IMPLEMENT_PEM_read(name, type, str, asn1) \\
	IMPLEMENT_PEM_write(name, type, str, asn1)

#define IMPLEMENT_PEM_rw_const (name, type, str, asn1)\
	IMPLEMENT_PEM_read(name, type, str, asn1) \\
	IMPLEMENT_PEM_write_const(name, type, str, asn1)

#define IMPLEMENT_PEM_rw_cb (name, type, str, asn1)\
	IMPLEMENT_PEM_read(name, type, str, asn1) \\
	IMPLEMENT_PEM_write_cb(name, type, str, asn1)

#define DECLARE_PEM_read_fp_attr (attr, name, type)

#define DECLARE_PEM_read_fp_ex_attr (attr, name, type)

#define DECLARE_PEM_write_fp_attr (attr, name, type)

#define DECLARE_PEM_write_fp_ex_attr (attr, name, type)

#define DECLARE_PEM_write_fp_const_attr (attr, name, type)

#define DECLARE_PEM_write_cb_fp_attr (attr, name, type)

#define DECLARE_PEM_write_cb_fp_ex_attr (attr, name, type)

#define DECLARE_PEM_read_fp (name, type)\
	DECLARE_PEM_read_fp_attr(extern, name, type)

#define DECLARE_PEM_write_fp (name, type)\
	DECLARE_PEM_write_fp_attr(extern, name, type)

#define DECLARE_PEM_write_fp_const (name, type)\
	DECLARE_PEM_write_fp_const_attr(extern, name, type)

#define DECLARE_PEM_write_cb_fp (name, type)\
	DECLARE_PEM_write_cb_fp_attr(extern, name, type)

#define DECLARE_PEM_read_bio_attr (attr, name, type)\
	attr PEM_read_cb_fnsig(name, type, BIO, read_bio);

#define DECLARE_PEM_read_bio_ex_attr (attr, name, type)\
	attr PEM_read_cb_fnsig(name, type, BIO, read_bio);                      \\
	attr PEM_read_cb_ex_fnsig(name, type, BIO, read_bio);

#define DECLARE_PEM_read_bio (name, type)\
	DECLARE_PEM_read_bio_attr(extern, name, type)

#define DECLARE_PEM_read_bio_ex (name, type)\
	DECLARE_PEM_read_bio_ex_attr(extern, name, type)

#define DECLARE_PEM_write_bio_attr (attr, name, type)\
	attr PEM_write_fnsig(name, type, BIO, write_bio);

#define DECLARE_PEM_write_bio_ex_attr (attr, name, type)\
	attr PEM_write_fnsig(name, type, BIO, write_bio);                       \\
	attr PEM_write_ex_fnsig(name, type, BIO, write_bio);

#define DECLARE_PEM_write_bio (name, type)\
	DECLARE_PEM_write_bio_attr(extern, name, type)

#define DECLARE_PEM_write_bio_ex (name, type)\
	DECLARE_PEM_write_bio_ex_attr(extern, name, type)

#define DECLARE_PEM_write_bio_const_attr (attr, name, type)\
	attr PEM_write_fnsig(name, type, BIO, write_bio);

#define DECLARE_PEM_write_bio_const (name, type)\
	DECLARE_PEM_write_bio_const_attr(extern, name, type)

#define DECLARE_PEM_write_cb_bio_attr (attr, name, type)\
	attr PEM_write_cb_fnsig(name, type, BIO, write_bio);

#define DECLARE_PEM_write_cb_bio_ex_attr (attr, name, type)\
	attr PEM_write_cb_fnsig(name, type, BIO, write_bio);                    \\
	attr PEM_write_cb_ex_fnsig(name, type, BIO, write_bio);

#define DECLARE_PEM_write_cb_bio (name, type)\
	DECLARE_PEM_write_cb_bio_attr(extern, name, type)

#define DECLARE_PEM_write_cb_ex_bio (name, type)\
	DECLARE_PEM_write_cb_bio_ex_attr(extern, name, type)

#define DECLARE_PEM_write_attr (attr, name, type)\
	DECLARE_PEM_write_bio_attr(attr, name, type)                            \\
	DECLARE_PEM_write_fp_attr(attr, name, type)

#define DECLARE_PEM_write_ex_attr (attr, name, type)\
	DECLARE_PEM_write_bio_ex_attr(attr, name, type)                         \\
	DECLARE_PEM_write_fp_ex_attr(attr, name, type)

#define DECLARE_PEM_write (name, type)\
	DECLARE_PEM_write_attr(extern, name, type)

#define DECLARE_PEM_write_ex (name, type)\
	DECLARE_PEM_write_ex_attr(extern, name, type)

#define DECLARE_PEM_write_const_attr (attr, name, type)\
	DECLARE_PEM_write_bio_const_attr(attr, name, type)                      \\
	DECLARE_PEM_write_fp_const_attr(attr, name, type)

#define DECLARE_PEM_write_const (name, type)\
	DECLARE_PEM_write_const_attr(extern, name, type)

#define DECLARE_PEM_write_cb_attr (attr, name, type)\
	DECLARE_PEM_write_cb_bio_attr(attr, name, type)                         \\
	DECLARE_PEM_write_cb_fp_attr(attr, name, type)

#define DECLARE_PEM_write_cb_ex_attr (attr, name, type)\
	DECLARE_PEM_write_cb_bio_ex_attr(attr, name, type)                      \\
	DECLARE_PEM_write_cb_fp_ex_attr(attr, name, type)

#define DECLARE_PEM_write_cb (name, type)\
	DECLARE_PEM_write_cb_attr(extern, name, type)

#define DECLARE_PEM_write_cb_ex (name, type)\
	DECLARE_PEM_write_cb_ex_attr(extern, name, type)

#define DECLARE_PEM_read_attr (attr, name, type)\
	DECLARE_PEM_read_bio_attr(attr, name, type)                             \\
	DECLARE_PEM_read_fp_attr(attr, name, type)

#define DECLARE_PEM_read_ex_attr (attr, name, type)\
	DECLARE_PEM_read_bio_ex_attr(attr, name, type)                          \\
	DECLARE_PEM_read_fp_ex_attr(attr, name, type)

#define DECLARE_PEM_read (name, type)\
	DECLARE_PEM_read_attr(extern, name, type)

#define DECLARE_PEM_read_ex (name, type)\
	DECLARE_PEM_read_ex_attr(extern, name, type)

#define DECLARE_PEM_rw_attr (attr, name, type)\
	DECLARE_PEM_read_attr(attr, name, type)                                 \\
	DECLARE_PEM_write_attr(attr, name, type)

#define DECLARE_PEM_rw_ex_attr (attr, name, type)\
	DECLARE_PEM_read_ex_attr(attr, name, type)                              \\
	DECLARE_PEM_write_ex_attr(attr, name, type)

#define DECLARE_PEM_rw (name, type)\
	DECLARE_PEM_rw_attr(extern, name, type)

#define DECLARE_PEM_rw_ex (name, type)\
	DECLARE_PEM_rw_ex_attr(extern, name, type)

#define DECLARE_PEM_rw_const_attr (attr, name, type)\
	DECLARE_PEM_read_attr(attr, name, type)                                 \\
	DECLARE_PEM_write_const_attr(attr, name, type)

#define DECLARE_PEM_rw_const (name, type)\
	DECLARE_PEM_rw_const_attr(extern, name, type)

#define DECLARE_PEM_rw_cb_attr (attr, name, type)\
	DECLARE_PEM_read_attr(attr, name, type)                                 \\
	DECLARE_PEM_write_cb_attr(attr, name, type)

#define DECLARE_PEM_rw_cb_ex_attr (attr, name, type)\
	DECLARE_PEM_read_ex_attr(attr, name, type)                              \\
	DECLARE_PEM_write_cb_ex_attr(attr, name, type)

#define DECLARE_PEM_rw_cb (name, type)\
	DECLARE_PEM_rw_cb_attr(extern, name, type)

#define DECLARE_PEM_rw_cb_ex (name, type)\
	DECLARE_PEM_rw_cb_ex_attr(extern, name, type)

#define PEM_FLAG_SECURE 0x1

#define PEM_FLAG_EAY_COMPATIBLE 0x2

#define PEM_FLAG_ONLY_B64 0x4

#define OPENSSL_PEM2_H 

#define HEADER_PEM2_H 

#define OPENSSL_PEMERR_H 

#define PEM_R_BAD_BASE64_DECODE 100

#define PEM_R_BAD_DECRYPT 101

#define PEM_R_BAD_END_LINE 102

#define PEM_R_BAD_IV_CHARS 103

#define PEM_R_BAD_MAGIC_NUMBER 116

#define PEM_R_BAD_PASSWORD_READ 104

#define PEM_R_BAD_VERSION_NUMBER 117

#define PEM_R_BIO_WRITE_FAILURE 118

#define PEM_R_CIPHER_IS_NULL 127

#define PEM_R_ERROR_CONVERTING_PRIVATE_KEY 115

#define PEM_R_EXPECTING_DSS_KEY_BLOB 131

#define PEM_R_EXPECTING_PRIVATE_KEY_BLOB 119

#define PEM_R_EXPECTING_PUBLIC_KEY_BLOB 120

#define PEM_R_EXPECTING_RSA_KEY_BLOB 132

#define PEM_R_HEADER_TOO_LONG 128

#define PEM_R_INCONSISTENT_HEADER 121

#define PEM_R_KEYBLOB_HEADER_PARSE_ERROR 122

#define PEM_R_KEYBLOB_TOO_SHORT 123

#define PEM_R_MISSING_DEK_IV 129

#define PEM_R_NOT_DEK_INFO 105

#define PEM_R_NOT_ENCRYPTED 106

#define PEM_R_NOT_PROC_TYPE 107

#define PEM_R_NO_START_LINE 108

#define PEM_R_PROBLEMS_GETTING_PASSWORD 109

#define PEM_R_PVK_DATA_TOO_SHORT 124

#define PEM_R_PVK_TOO_SHORT 125

#define PEM_R_READ_KEY 111

#define PEM_R_SHORT_HEADER 112

#define PEM_R_UNEXPECTED_DEK_IV 130

#define PEM_R_UNSUPPORTED_CIPHER 113

#define PEM_R_UNSUPPORTED_ENCRYPTION 114

#define PEM_R_UNSUPPORTED_KEY_COMPONENTS 126

#define PEM_R_UNSUPPORTED_PUBLIC_KEY_TYPE 110

#define OPENSSL_PKCS12_H 

#define HEADER_PKCS12_H 

#define PKCS12_KEY_ID 1

#define PKCS12_IV_ID 2

#define PKCS12_MAC_ID 3

#define PKCS12_DEFAULT_ITER PKCS5_DEFAULT_ITER

#define PKCS12_MAC_KEY_LENGTH 20

#define PKCS12_SALT_LEN 8

#define PKCS12_key_gen PKCS12_key_gen_utf8

#define PKCS12_add_friendlyname PKCS12_add_friendlyname_utf8

#define KEY_EX 0x10

#define KEY_SIG 0x80

#define PKCS12_ERROR 0

#define PKCS12_OK 1

#define M_PKCS12_bag_type PKCS12_bag_type

#define M_PKCS12_cert_bag_type PKCS12_cert_bag_type

#define M_PKCS12_crl_bag_type PKCS12_cert_bag_type

#define PKCS12_certbag2x509 PKCS12_SAFEBAG_get1_cert

#define PKCS12_certbag2scrl PKCS12_SAFEBAG_get1_crl

#define PKCS12_bag_type PKCS12_SAFEBAG_get_nid

#define PKCS12_cert_bag_type PKCS12_SAFEBAG_get_bag_nid

#define PKCS12_x5092certbag PKCS12_SAFEBAG_create_cert

#define PKCS12_x509crl2certbag PKCS12_SAFEBAG_create_crl

#define PKCS12_MAKE_KEYBAG PKCS12_SAFEBAG_create0_p8inf

#define PKCS12_MAKE_SHKEYBAG PKCS12_SAFEBAG_create_pkcs8_encrypt

#define OPENSSL_PKCS12ERR_H 

#define PKCS12_R_CALLBACK_FAILED 115

#define PKCS12_R_CANT_PACK_STRUCTURE 100

#define PKCS12_R_CONTENT_TYPE_NOT_DATA 121

#define PKCS12_R_DECODE_ERROR 101

#define PKCS12_R_ENCODE_ERROR 102

#define PKCS12_R_ENCRYPT_ERROR 103

#define PKCS12_R_ERROR_SETTING_ENCRYPTED_DATA_TYPE 120

#define PKCS12_R_INVALID_NULL_ARGUMENT 104

#define PKCS12_R_INVALID_NULL_PKCS12_POINTER 105

#define PKCS12_R_INVALID_TYPE 112

#define PKCS12_R_IV_GEN_ERROR 106

#define PKCS12_R_KEY_GEN_ERROR 107

#define PKCS12_R_MAC_ABSENT 108

#define PKCS12_R_MAC_GENERATION_ERROR 109

#define PKCS12_R_MAC_SETUP_ERROR 110

#define PKCS12_R_MAC_STRING_SET_ERROR 111

#define PKCS12_R_MAC_VERIFY_FAILURE 113

#define PKCS12_R_PARSE_ERROR 114

#define PKCS12_R_PKCS12_CIPHERFINAL_ERROR 116

#define PKCS12_R_UNKNOWN_DIGEST_ALGORITHM 118

#define PKCS12_R_UNSUPPORTED_PKCS12_MODE 119

#define OPENSSL_PKCS7_H 

#define HEADER_PKCS7_H 

#define PKCS7_S_HEADER 0

#define PKCS7_S_BODY 1

#define PKCS7_S_TAIL 2

#define PKCS7_OP_SET_DETACHED_SIGNATURE 1

#define PKCS7_OP_GET_DETACHED_SIGNATURE 2

#define PKCS7_get_signed_attributes (si) ((si)->auth_attr)

#define PKCS7_get_attributes (si)        ((si)->unauth_attr)

#define PKCS7_type_is_signed (a) (OBJ_obj2nid((a)->type) == NID_pkcs7_signed)

#define PKCS7_type_is_encrypted (a) (OBJ_obj2nid((a)->type) == NID_pkcs7_encrypted)

#define PKCS7_type_is_enveloped (a) (OBJ_obj2nid((a)->type) == NID_pkcs7_enveloped)

#define PKCS7_type_is_signedAndEnveloped (a)\
	(OBJ_obj2nid((a)->type) == NID_pkcs7_signedAndEnveloped)

#define PKCS7_type_is_data (a)   (OBJ_obj2nid((a)->type) == NID_pkcs7_data)

#define PKCS7_type_is_digest (a)   (OBJ_obj2nid((a)->type) == NID_pkcs7_digest)

#define PKCS7_set_detached (p,v)\
	PKCS7_ctrl(p,PKCS7_OP_SET_DETACHED_SIGNATURE,v,NULL)

#define PKCS7_get_detached (p)\
	PKCS7_ctrl(p,PKCS7_OP_GET_DETACHED_SIGNATURE,0,NULL)

#define PKCS7_is_detached (p7) (PKCS7_type_is_signed(p7) && PKCS7_get_detached(p7))

#define PKCS7_TEXT 0x1

#define PKCS7_NOCERTS 0x2

#define PKCS7_NOSIGS 0x4

#define PKCS7_NOCHAIN 0x8

#define PKCS7_NOINTERN 0x10

#define PKCS7_NOVERIFY 0x20

#define PKCS7_DETACHED 0x40

#define PKCS7_BINARY 0x80

#define PKCS7_NOATTR 0x100

#define PKCS7_NOSMIMECAP 0x200

#define PKCS7_NOOLDMIMETYPE 0x400

#define PKCS7_CRLFEOL 0x800

#define PKCS7_STREAM 0x1000

#define PKCS7_NOCRL 0x2000

#define PKCS7_PARTIAL 0x4000

#define PKCS7_REUSE_DIGEST 0x8000

#define PKCS7_NO_DUAL_CONTENT 0x10000

#define SMIME_TEXT PKCS7_TEXT

#define SMIME_NOCERTS PKCS7_NOCERTS

#define SMIME_NOSIGS PKCS7_NOSIGS

#define SMIME_NOCHAIN PKCS7_NOCHAIN

#define SMIME_NOINTERN PKCS7_NOINTERN

#define SMIME_NOVERIFY PKCS7_NOVERIFY

#define SMIME_DETACHED PKCS7_DETACHED

#define SMIME_BINARY PKCS7_BINARY

#define SMIME_NOATTR PKCS7_NOATTR

#define SMIME_ASCIICRLF 0x80000

#define OPENSSL_PKCS7ERR_H 

#define PKCS7_R_CERTIFICATE_VERIFY_ERROR 117

#define PKCS7_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER 144

#define PKCS7_R_CIPHER_NOT_INITIALIZED 116

#define PKCS7_R_CONTENT_AND_DATA_PRESENT 118

#define PKCS7_R_CTRL_ERROR 152

#define PKCS7_R_DECRYPT_ERROR 119

#define PKCS7_R_DIGEST_FAILURE 101

#define PKCS7_R_ENCRYPTION_CTRL_FAILURE 149

#define PKCS7_R_ENCRYPTION_NOT_SUPPORTED_FOR_THIS_KEY_TYPE 150

#define PKCS7_R_ERROR_ADDING_RECIPIENT 120

#define PKCS7_R_ERROR_SETTING_CIPHER 121

#define PKCS7_R_INVALID_NULL_POINTER 143

#define PKCS7_R_INVALID_SIGNED_DATA_TYPE 155

#define PKCS7_R_NO_CONTENT 122

#define PKCS7_R_NO_DEFAULT_DIGEST 151

#define PKCS7_R_NO_MATCHING_DIGEST_TYPE_FOUND 154

#define PKCS7_R_NO_RECIPIENT_MATCHES_CERTIFICATE 115

#define PKCS7_R_NO_SIGNATURES_ON_DATA 123

#define PKCS7_R_NO_SIGNERS 142

#define PKCS7_R_OPERATION_NOT_SUPPORTED_ON_THIS_TYPE 104

#define PKCS7_R_PKCS7_ADD_SIGNATURE_ERROR 124

#define PKCS7_R_PKCS7_ADD_SIGNER_ERROR 153

#define PKCS7_R_PKCS7_DATASIGN 145

#define PKCS7_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE 127

#define PKCS7_R_SIGNATURE_FAILURE 105

#define PKCS7_R_SIGNER_CERTIFICATE_NOT_FOUND 128

#define PKCS7_R_SIGNING_CTRL_FAILURE 147

#define PKCS7_R_SIGNING_NOT_SUPPORTED_FOR_THIS_KEY_TYPE 148

#define PKCS7_R_SMIME_TEXT_ERROR 129

#define PKCS7_R_UNABLE_TO_FIND_CERTIFICATE 106

#define PKCS7_R_UNABLE_TO_FIND_MEM_BIO 107

#define PKCS7_R_UNABLE_TO_FIND_MESSAGE_DIGEST 108

#define PKCS7_R_UNKNOWN_DIGEST_TYPE 109

#define PKCS7_R_UNKNOWN_OPERATION 110

#define PKCS7_R_UNSUPPORTED_CIPHER_TYPE 111

#define PKCS7_R_UNSUPPORTED_CONTENT_TYPE 112

#define PKCS7_R_WRONG_CONTENT_TYPE 113

#define PKCS7_R_WRONG_PKCS7_TYPE 114

#define OPENSSL_PROVERR_H 

#define PROV_R_ADDITIONAL_INPUT_TOO_LONG 184

#define PROV_R_ALGORITHM_MISMATCH 173

#define PROV_R_ALREADY_INSTANTIATED 185

#define PROV_R_BAD_DECRYPT 100

#define PROV_R_BAD_ENCODING 141

#define PROV_R_BAD_LENGTH 142

#define PROV_R_BAD_TLS_CLIENT_VERSION 161

#define PROV_R_BN_ERROR 160

#define PROV_R_CIPHER_OPERATION_FAILED 102

#define PROV_R_DERIVATION_FUNCTION_INIT_FAILED 205

#define PROV_R_DIGEST_NOT_ALLOWED 174

#define PROV_R_EMS_NOT_ENABLED 233

#define PROV_R_ENTROPY_SOURCE_STRENGTH_TOO_WEAK 186

#define PROV_R_ERROR_INSTANTIATING_DRBG 188

#define PROV_R_ERROR_RETRIEVING_ENTROPY 189

#define PROV_R_ERROR_RETRIEVING_NONCE 190

#define PROV_R_FAILED_DURING_DERIVATION 164

#define PROV_R_FAILED_TO_CREATE_LOCK 180

#define PROV_R_FAILED_TO_DECRYPT 162

#define PROV_R_FAILED_TO_GENERATE_KEY 121

#define PROV_R_FAILED_TO_GET_PARAMETER 103

#define PROV_R_FAILED_TO_SET_PARAMETER 104

#define PROV_R_FAILED_TO_SIGN 175

#define PROV_R_FIPS_MODULE_CONDITIONAL_ERROR 227

#define PROV_R_FIPS_MODULE_ENTERING_ERROR_STATE 224

#define PROV_R_FIPS_MODULE_IN_ERROR_STATE 225

#define PROV_R_GENERATE_ERROR 191

#define PROV_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE 165

#define PROV_R_INDICATOR_INTEGRITY_FAILURE 210

#define PROV_R_INSUFFICIENT_DRBG_STRENGTH 181

#define PROV_R_INVALID_AAD 108

#define PROV_R_INVALID_AEAD 231

#define PROV_R_INVALID_CONFIG_DATA 211

#define PROV_R_INVALID_CONSTANT_LENGTH 157

#define PROV_R_INVALID_CURVE 176

#define PROV_R_INVALID_CUSTOM_LENGTH 111

#define PROV_R_INVALID_DATA 115

#define PROV_R_INVALID_DIGEST 122

#define PROV_R_INVALID_DIGEST_LENGTH 166

#define PROV_R_INVALID_DIGEST_SIZE 218

#define PROV_R_INVALID_INPUT_LENGTH 230

#define PROV_R_INVALID_ITERATION_COUNT 123

#define PROV_R_INVALID_IV_LENGTH 109

#define PROV_R_INVALID_KDF 232

#define PROV_R_INVALID_KEY 158

#define PROV_R_INVALID_KEY_LENGTH 105

#define PROV_R_INVALID_MAC 151

#define PROV_R_INVALID_MEMORY_SIZE 235

#define PROV_R_INVALID_MGF1_MD 167

#define PROV_R_INVALID_MODE 125

#define PROV_R_INVALID_OUTPUT_LENGTH 217

#define PROV_R_INVALID_PADDING_MODE 168

#define PROV_R_INVALID_PUBINFO 198

#define PROV_R_INVALID_SALT_LENGTH 112

#define PROV_R_INVALID_SEED_LENGTH 154

#define PROV_R_INVALID_SIGNATURE_SIZE 179

#define PROV_R_INVALID_STATE 212

#define PROV_R_INVALID_TAG 110

#define PROV_R_INVALID_TAG_LENGTH 118

#define PROV_R_INVALID_THREAD_POOL_SIZE 234

#define PROV_R_INVALID_UKM_LENGTH 200

#define PROV_R_INVALID_X931_DIGEST 170

#define PROV_R_IN_ERROR_STATE 192

#define PROV_R_KEY_SETUP_FAILED 101

#define PROV_R_KEY_SIZE_TOO_SMALL 171

#define PROV_R_LENGTH_TOO_LARGE 202

#define PROV_R_MISMATCHING_DOMAIN_PARAMETERS 203

#define PROV_R_MISSING_CEK_ALG 144

#define PROV_R_MISSING_CIPHER 155

#define PROV_R_MISSING_CONFIG_DATA 213

#define PROV_R_MISSING_CONSTANT 156

#define PROV_R_MISSING_KEY 128

#define PROV_R_MISSING_MAC 150

#define PROV_R_MISSING_MESSAGE_DIGEST 129

#define PROV_R_MISSING_OID 209

#define PROV_R_MISSING_PASS 130

#define PROV_R_MISSING_SALT 131

#define PROV_R_MISSING_SECRET 132

#define PROV_R_MISSING_SEED 140

#define PROV_R_MISSING_SESSION_ID 133

#define PROV_R_MISSING_TYPE 134

#define PROV_R_MISSING_XCGHASH 135

#define PROV_R_MODULE_INTEGRITY_FAILURE 214

#define PROV_R_NOT_A_PRIVATE_KEY 221

#define PROV_R_NOT_A_PUBLIC_KEY 220

#define PROV_R_NOT_INSTANTIATED 193

#define PROV_R_NOT_PARAMETERS 226

#define PROV_R_NOT_SUPPORTED 136

#define PROV_R_NOT_XOF_OR_INVALID_LENGTH 113

#define PROV_R_NO_KEY_SET 114

#define PROV_R_NO_PARAMETERS_SET 177

#define PROV_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE 178

#define PROV_R_OUTPUT_BUFFER_TOO_SMALL 106

#define PROV_R_PARENT_CANNOT_GENERATE_RANDOM_NUMBERS 228

#define PROV_R_PARENT_CANNOT_SUPPLY_ENTROPY_SEED 187

#define PROV_R_PARENT_LOCKING_NOT_ENABLED 182

#define PROV_R_PARENT_STRENGTH_TOO_WEAK 194

#define PROV_R_PATH_MUST_BE_ABSOLUTE 219

#define PROV_R_PERSONALISATION_STRING_TOO_LONG 195

#define PROV_R_PSS_SALTLEN_TOO_SMALL 172

#define PROV_R_REQUEST_TOO_LARGE_FOR_DRBG 196

#define PROV_R_REQUIRE_CTR_MODE_CIPHER 206

#define PROV_R_RESEED_ERROR 197

#define PROV_R_SEARCH_ONLY_SUPPORTED_FOR_DIRECTORIES 222

#define PROV_R_SEED_SOURCES_MUST_NOT_HAVE_A_PARENT 229

#define PROV_R_SELF_TEST_KAT_FAILURE 215

#define PROV_R_SELF_TEST_POST_FAILURE 216

#define PROV_R_TAG_NOT_NEEDED 120

#define PROV_R_TAG_NOT_SET 119

#define PROV_R_TOO_MANY_RECORDS 126

#define PROV_R_UNABLE_TO_FIND_CIPHERS 207

#define PROV_R_UNABLE_TO_GET_PARENT_STRENGTH 199

#define PROV_R_UNABLE_TO_GET_PASSPHRASE 159

#define PROV_R_UNABLE_TO_INITIALISE_CIPHERS 208

#define PROV_R_UNABLE_TO_LOAD_SHA256 147

#define PROV_R_UNABLE_TO_LOCK_PARENT 201

#define PROV_R_UNABLE_TO_RESEED 204

#define PROV_R_UNSUPPORTED_CEK_ALG 145

#define PROV_R_UNSUPPORTED_KEY_SIZE 153

#define PROV_R_UNSUPPORTED_MAC_TYPE 137

#define PROV_R_UNSUPPORTED_NUMBER_OF_ROUNDS 152

#define PROV_R_URI_AUTHORITY_UNSUPPORTED 223

#define PROV_R_VALUE_ERROR 138

#define PROV_R_WRONG_FINAL_BLOCK_LENGTH 107

#define PROV_R_WRONG_OUTPUT_BUFFER_SIZE 139

#define PROV_R_XOF_DIGESTS_NOT_ALLOWED 183

#define PROV_R_XTS_DATA_UNIT_IS_TOO_LARGE 148

#define PROV_R_XTS_DUPLICATED_KEYS 149

#define OPENSSL_PROVIDER_H 

#define OPENSSL_PROV_SSL_H 

#define SSL_MAX_MASTER_KEY_LENGTH 48

#define SSL3_VERSION 0x0300

#define TLS1_VERSION 0x0301

#define TLS1_1_VERSION 0x0302

#define TLS1_2_VERSION 0x0303

#define TLS1_3_VERSION 0x0304

#define DTLS1_VERSION 0xFEFF

#define DTLS1_2_VERSION 0xFEFD

#define DTLS1_BAD_VER 0x0100

#define OSSL_QUIC1_VERSION 0x0000001

#define OPENSSL_QUIC_H 

#define OSSL_QUIC_ERR_NO_ERROR 0x00

#define OSSL_QUIC_ERR_INTERNAL_ERROR 0x01

#define OSSL_QUIC_ERR_CONNECTION_REFUSED 0x02

#define OSSL_QUIC_ERR_FLOW_CONTROL_ERROR 0x03

#define OSSL_QUIC_ERR_STREAM_LIMIT_ERROR 0x04

#define OSSL_QUIC_ERR_STREAM_STATE_ERROR 0x05

#define OSSL_QUIC_ERR_FINAL_SIZE_ERROR 0x06

#define OSSL_QUIC_ERR_FRAME_ENCODING_ERROR 0x07

#define OSSL_QUIC_ERR_TRANSPORT_PARAMETER_ERROR 0x08

#define OSSL_QUIC_ERR_CONNECTION_ID_LIMIT_ERROR 0x09

#define OSSL_QUIC_ERR_PROTOCOL_VIOLATION 0x0A

#define OSSL_QUIC_ERR_INVALID_TOKEN 0x0B

#define OSSL_QUIC_ERR_APPLICATION_ERROR 0x0C

#define OSSL_QUIC_ERR_CRYPTO_BUFFER_EXCEEDED 0x0D

#define OSSL_QUIC_ERR_KEY_UPDATE_ERROR 0x0E

#define OSSL_QUIC_ERR_AEAD_LIMIT_REACHED 0x0F

#define OSSL_QUIC_ERR_NO_VIABLE_PATH 0x10

#define OSSL_QUIC_ERR_CRYPTO_ERR_BEGIN 0x0100

#define OSSL_QUIC_ERR_CRYPTO_ERR_END 0x01FF

#define OSSL_QUIC_ERR_CRYPTO_ERR (X)\
	(OSSL_QUIC_ERR_CRYPTO_ERR_BEGIN + (X))

#define OSSL_QUIC_LOCAL_ERR_IDLE_TIMEOUT \
	((uint64_t)0xFFFFFFFFFFFFFFFFULL)

#define OPENSSL_RAND_H 

#define HEADER_RAND_H 

#define RAND_DRBG_STRENGTH 256

#define RAND_cleanup () while(0) continue

#define OPENSSL_RANDERR_H 

#define RAND_R_ADDITIONAL_INPUT_TOO_LONG 102

#define RAND_R_ALREADY_INSTANTIATED 103

#define RAND_R_ARGUMENT_OUT_OF_RANGE 105

#define RAND_R_CANNOT_OPEN_FILE 121

#define RAND_R_DRBG_ALREADY_INITIALIZED 129

#define RAND_R_DRBG_NOT_INITIALISED 104

#define RAND_R_ENTROPY_INPUT_TOO_LONG 106

#define RAND_R_ENTROPY_OUT_OF_RANGE 124

#define RAND_R_ERROR_ENTROPY_POOL_WAS_IGNORED 127

#define RAND_R_ERROR_INITIALISING_DRBG 107

#define RAND_R_ERROR_INSTANTIATING_DRBG 108

#define RAND_R_ERROR_RETRIEVING_ADDITIONAL_INPUT 109

#define RAND_R_ERROR_RETRIEVING_ENTROPY 110

#define RAND_R_ERROR_RETRIEVING_NONCE 111

#define RAND_R_FAILED_TO_CREATE_LOCK 126

#define RAND_R_FUNC_NOT_IMPLEMENTED 101

#define RAND_R_FWRITE_ERROR 123

#define RAND_R_GENERATE_ERROR 112

#define RAND_R_INSUFFICIENT_DRBG_STRENGTH 139

#define RAND_R_INTERNAL_ERROR 113

#define RAND_R_INVALID_PROPERTY_QUERY 137

#define RAND_R_IN_ERROR_STATE 114

#define RAND_R_NOT_A_REGULAR_FILE 122

#define RAND_R_NOT_INSTANTIATED 115

#define RAND_R_NO_DRBG_IMPLEMENTATION_SELECTED 128

#define RAND_R_PARENT_LOCKING_NOT_ENABLED 130

#define RAND_R_PARENT_STRENGTH_TOO_WEAK 131

#define RAND_R_PERSONALISATION_STRING_TOO_LONG 116

#define RAND_R_PREDICTION_RESISTANCE_NOT_SUPPORTED 133

#define RAND_R_PRNG_NOT_SEEDED 100

#define RAND_R_RANDOM_POOL_OVERFLOW 125

#define RAND_R_RANDOM_POOL_UNDERFLOW 134

#define RAND_R_REQUEST_TOO_LARGE_FOR_DRBG 117

#define RAND_R_RESEED_ERROR 118

#define RAND_R_SELFTEST_FAILURE 119

#define RAND_R_TOO_LITTLE_NONCE_REQUESTED 135

#define RAND_R_TOO_MUCH_NONCE_REQUESTED 136

#define RAND_R_UNABLE_TO_CREATE_DRBG 143

#define RAND_R_UNABLE_TO_FETCH_DRBG 144

#define RAND_R_UNABLE_TO_GET_PARENT_RESEED_PROP_COUNTER 141

#define RAND_R_UNABLE_TO_GET_PARENT_STRENGTH 138

#define RAND_R_UNABLE_TO_LOCK_PARENT 140

#define RAND_R_UNSUPPORTED_DRBG_FLAGS 132

#define RAND_R_UNSUPPORTED_DRBG_TYPE 120

#define OPENSSL_RC2_H 

#define HEADER_RC2_H 

#define RC2_BLOCK 8

#define RC2_KEY_LENGTH 16

#define RC2_ENCRYPT 1

#define RC2_DECRYPT 0

#define OPENSSL_RC4_H 

#define HEADER_RC4_H 

#define OPENSSL_RC5_H 

#define HEADER_RC5_H 

#define RC5_32_BLOCK 8

#define RC5_32_KEY_LENGTH 16

#define RC5_ENCRYPT 1

#define RC5_DECRYPT 0

#define RC5_32_INT unsigned int

#define RC5_8_ROUNDS 8

#define RC5_12_ROUNDS 12

#define RC5_16_ROUNDS 16

#define OPENSSL_RIPEMD_H 

#define HEADER_RIPEMD_H 

#define RIPEMD160_DIGEST_LENGTH 20

#define RIPEMD160_LONG unsigned int

#define RIPEMD160_CBLOCK 64

#define RIPEMD160_LBLOCK (RIPEMD160_CBLOCK/4)

#define OPENSSL_RSA_H 

#define HEADER_RSA_H 

#define OPENSSL_RSA_MAX_MODULUS_BITS 16384

#define RSA_3 0x3L

#define RSA_F4 0x10001L

#define OPENSSL_RSA_FIPS_MIN_MODULUS_BITS 2048

#define OPENSSL_RSA_SMALL_MODULUS_BITS 3072

#define OPENSSL_RSA_MAX_PUBEXP_BITS 64

#define RSA_ASN1_VERSION_DEFAULT 0

#define RSA_ASN1_VERSION_MULTI 1

#define RSA_DEFAULT_PRIME_NUM 2

#define RSA_METHOD_FLAG_NO_CHECK 0x0001

#define RSA_FLAG_CACHE_PUBLIC 0x0002

#define RSA_FLAG_CACHE_PRIVATE 0x0004

#define RSA_FLAG_BLINDING 0x0008

#define RSA_FLAG_THREAD_SAFE 0x0010

#define RSA_FLAG_EXT_PKEY 0x0020

#define RSA_FLAG_NO_BLINDING 0x0080

#define RSA_FLAG_NO_CONSTTIME 0x0000

#define RSA_FLAG_NO_EXP_CONSTTIME RSA_FLAG_NO_CONSTTIME

#define RSA_FLAG_TYPE_MASK 0xF000

#define RSA_FLAG_TYPE_RSA 0x0000

#define RSA_FLAG_TYPE_RSASSAPSS 0x1000

#define RSA_FLAG_TYPE_RSAESOAEP 0x2000

#define RSA_PSS_SALTLEN_DIGEST -1

#define RSA_PSS_SALTLEN_AUTO -2

#define RSA_PSS_SALTLEN_MAX -3

#define RSA_PSS_SALTLEN_AUTO_DIGEST_MAX -4

#define RSA_PSS_SALTLEN_MAX_SIGN -2

#define EVP_PKEY_CTRL_RSA_PADDING (EVP_PKEY_ALG_CTRL + 1)

#define EVP_PKEY_CTRL_RSA_PSS_SALTLEN (EVP_PKEY_ALG_CTRL + 2)

#define EVP_PKEY_CTRL_RSA_KEYGEN_BITS (EVP_PKEY_ALG_CTRL + 3)

#define EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP (EVP_PKEY_ALG_CTRL + 4)

#define EVP_PKEY_CTRL_RSA_MGF1_MD (EVP_PKEY_ALG_CTRL + 5)

#define EVP_PKEY_CTRL_GET_RSA_PADDING (EVP_PKEY_ALG_CTRL + 6)

#define EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN (EVP_PKEY_ALG_CTRL + 7)

#define EVP_PKEY_CTRL_GET_RSA_MGF1_MD (EVP_PKEY_ALG_CTRL + 8)

#define EVP_PKEY_CTRL_RSA_OAEP_MD (EVP_PKEY_ALG_CTRL + 9)

#define EVP_PKEY_CTRL_RSA_OAEP_LABEL (EVP_PKEY_ALG_CTRL + 10)

#define EVP_PKEY_CTRL_GET_RSA_OAEP_MD (EVP_PKEY_ALG_CTRL + 11)

#define EVP_PKEY_CTRL_GET_RSA_OAEP_LABEL (EVP_PKEY_ALG_CTRL + 12)

#define EVP_PKEY_CTRL_RSA_KEYGEN_PRIMES (EVP_PKEY_ALG_CTRL + 13)

#define EVP_PKEY_CTRL_RSA_IMPLICIT_REJECTION (EVP_PKEY_ALG_CTRL + 14)

#define RSA_PKCS1_PADDING 1

#define RSA_NO_PADDING 3

#define RSA_PKCS1_OAEP_PADDING 4

#define RSA_X931_PADDING 5

#define RSA_PKCS1_PSS_PADDING 6

#define RSA_PKCS1_WITH_TLS_PADDING 7

#define RSA_PKCS1_NO_IMPLICIT_REJECT_PADDING 8

#define RSA_PKCS1_PADDING_SIZE 11

#define RSA_set_app_data (s,arg)         RSA_set_ex_data(s,0,arg)

#define RSA_get_app_data (s)             RSA_get_ex_data(s,0)

#define EVP_RSA_gen (bits)\
	EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)(0 + (bits)))

#define RSA_get_ex_new_index (l, p, newf, dupf, freef)\
	CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_RSA, l, p, newf, dupf, freef)

#define RSA_FLAG_FIPS_METHOD 0x0400

#define RSA_FLAG_NON_FIPS_ALLOW 0x0400

#define RSA_FLAG_CHECKED 0x0800

#define OPENSSL_RSAERR_H 

#define RSA_R_ALGORITHM_MISMATCH 100

#define RSA_R_BAD_E_VALUE 101

#define RSA_R_BAD_FIXED_HEADER_DECRYPT 102

#define RSA_R_BAD_PAD_BYTE_COUNT 103

#define RSA_R_BAD_SIGNATURE 104

#define RSA_R_BLOCK_TYPE_IS_NOT_01 106

#define RSA_R_BLOCK_TYPE_IS_NOT_02 107

#define RSA_R_DATA_GREATER_THAN_MOD_LEN 108

#define RSA_R_DATA_TOO_LARGE 109

#define RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE 110

#define RSA_R_DATA_TOO_LARGE_FOR_MODULUS 132

#define RSA_R_DATA_TOO_SMALL 111

#define RSA_R_DATA_TOO_SMALL_FOR_KEY_SIZE 122

#define RSA_R_DIGEST_DOES_NOT_MATCH 158

#define RSA_R_DIGEST_NOT_ALLOWED 145

#define RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY 112

#define RSA_R_DMP1_NOT_CONGRUENT_TO_D 124

#define RSA_R_DMQ1_NOT_CONGRUENT_TO_D 125

#define RSA_R_D_E_NOT_CONGRUENT_TO_1 123

#define RSA_R_FIRST_OCTET_INVALID 133

#define RSA_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE 144

#define RSA_R_INVALID_DIGEST 157

#define RSA_R_INVALID_DIGEST_LENGTH 143

#define RSA_R_INVALID_HEADER 137

#define RSA_R_INVALID_KEYPAIR 171

#define RSA_R_INVALID_KEY_LENGTH 173

#define RSA_R_INVALID_LABEL 160

#define RSA_R_INVALID_LENGTH 181

#define RSA_R_INVALID_MESSAGE_LENGTH 131

#define RSA_R_INVALID_MGF1_MD 156

#define RSA_R_INVALID_MODULUS 174

#define RSA_R_INVALID_MULTI_PRIME_KEY 167

#define RSA_R_INVALID_OAEP_PARAMETERS 161

#define RSA_R_INVALID_PADDING 138

#define RSA_R_INVALID_PADDING_MODE 141

#define RSA_R_INVALID_PSS_PARAMETERS 149

#define RSA_R_INVALID_PSS_SALTLEN 146

#define RSA_R_INVALID_REQUEST 175

#define RSA_R_INVALID_SALT_LENGTH 150

#define RSA_R_INVALID_STRENGTH 176

#define RSA_R_INVALID_TRAILER 139

#define RSA_R_INVALID_X931_DIGEST 142

#define RSA_R_IQMP_NOT_INVERSE_OF_Q 126

#define RSA_R_KEY_PRIME_NUM_INVALID 165

#define RSA_R_KEY_SIZE_TOO_SMALL 120

#define RSA_R_LAST_OCTET_INVALID 134

#define RSA_R_MGF1_DIGEST_NOT_ALLOWED 152

#define RSA_R_MISSING_PRIVATE_KEY 179

#define RSA_R_MODULUS_TOO_LARGE 105

#define RSA_R_MP_COEFFICIENT_NOT_INVERSE_OF_R 168

#define RSA_R_MP_EXPONENT_NOT_CONGRUENT_TO_D 169

#define RSA_R_MP_R_NOT_PRIME 170

#define RSA_R_NO_PUBLIC_EXPONENT 140

#define RSA_R_NULL_BEFORE_BLOCK_MISSING 113

#define RSA_R_N_DOES_NOT_EQUAL_PRODUCT_OF_PRIMES 172

#define RSA_R_N_DOES_NOT_EQUAL_P_Q 127

#define RSA_R_OAEP_DECODING_ERROR 121

#define RSA_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE 148

#define RSA_R_PADDING_CHECK_FAILED 114

#define RSA_R_PAIRWISE_TEST_FAILURE 177

#define RSA_R_PKCS_DECODING_ERROR 159

#define RSA_R_PSS_SALTLEN_TOO_SMALL 164

#define RSA_R_PUB_EXPONENT_OUT_OF_RANGE 178

#define RSA_R_P_NOT_PRIME 128

#define RSA_R_Q_NOT_PRIME 129

#define RSA_R_RANDOMNESS_SOURCE_STRENGTH_INSUFFICIENT 180

#define RSA_R_RSA_OPERATIONS_NOT_SUPPORTED 130

#define RSA_R_SLEN_CHECK_FAILED 136

#define RSA_R_SLEN_RECOVERY_FAILED 135

#define RSA_R_SSLV3_ROLLBACK_ATTACK 115

#define RSA_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD 116

#define RSA_R_UNKNOWN_ALGORITHM_TYPE 117

#define RSA_R_UNKNOWN_DIGEST 166

#define RSA_R_UNKNOWN_MASK_DIGEST 151

#define RSA_R_UNKNOWN_PADDING_TYPE 118

#define RSA_R_UNSUPPORTED_ENCRYPTION_TYPE 162

#define RSA_R_UNSUPPORTED_LABEL_SOURCE 163

#define RSA_R_UNSUPPORTED_MASK_ALGORITHM 153

#define RSA_R_UNSUPPORTED_MASK_PARAMETER 154

#define RSA_R_UNSUPPORTED_SIGNATURE_TYPE 155

#define RSA_R_VALUE_MISSING 147

#define RSA_R_WRONG_SIGNATURE_LENGTH 119

#define OPENSSL_SAFESTACK_H 

#define HEADER_SAFESTACK_H 

#define STACK_OF(TYPE) TYPE

#define SKM_DEFINE_STACK_OF_INTERNAL (t1, t2, t3)\
	STACK_OF(t1); \\
	typedef int (*sk_##t1##_compfunc)(const t3 * const *a, const t3 *const *b); \\
	typedef void (*sk_##t1##_freefunc)(t3 *a); \\
	typedef t3 * (*sk_##t1##_copyfunc)(const t3 *a); \\
	static ossl_unused ossl_inline t2 *ossl_check_##t1##_type(t2 *ptr) \\
	{ \\
	return ptr; \\
	} \\
	static ossl_unused ossl_inline const OPENSSL_STACK *ossl_check_const_##t1##_sk_type(const STACK_OF(t1) *sk) \\
	{ \\
	return (const OPENSSL_STACK *)sk; \\
	} \\
	static ossl_unused ossl_inline OPENSSL_STACK *ossl_check_##t1##_sk_type(STACK_OF(t1) *sk) \\
	{ \\
	return (OPENSSL_STACK *)sk; \\
	} \\
	static ossl_unused ossl_inline OPENSSL_sk_compfunc ossl_check_##t1##_compfunc_type(sk_##t1##_compfunc cmp) \\
	{ \\
	return (OPENSSL_sk_compfunc)cmp; \\
	} \\
	static ossl_unused ossl_inline OPENSSL_sk_copyfunc ossl_check_##t1##_copyfunc_type(sk_##t1##_copyfunc cpy) \\
	{ \\
	return (OPENSSL_sk_copyfunc)cpy; \\
	} \\
	static ossl_unused ossl_inline OPENSSL_sk_freefunc ossl_check_##t1##_freefunc_type(sk_##t1##_freefunc fr) \\
	{ \\
	return (OPENSSL_sk_freefunc)fr; \\
	}

#define SKM_DEFINE_STACK_OF (t1, t2, t3)\
	STACK_OF(t1); \\
	typedef int (*sk_##t1##_compfunc)(const t3 * const *a, const t3 *const *b); \\
	typedef void (*sk_##t1##_freefunc)(t3 *a); \\
	typedef t3 * (*sk_##t1##_copyfunc)(const t3 *a); \\
	static ossl_unused ossl_inline int sk_##t1##_num(const STACK_OF(t1) *sk) \\
	{ \\
	return OPENSSL_sk_num((const OPENSSL_STACK *)sk); \\
	} \\
	static ossl_unused ossl_inline t2 *sk_##t1##_value(const STACK_OF(t1) *sk, int idx) \\
	{ \\
	return (t2 *)OPENSSL_sk_value((const OPENSSL_STACK *)sk, idx); \\
	} \\
	static ossl_unused ossl_inline STACK_OF(t1) *sk_##t1##_new(sk_##t1##_compfunc compare) \\
	{ \\
	return (STACK_OF(t1) *)OPENSSL_sk_new((OPENSSL_sk_compfunc)compare); \\
	} \\
	static ossl_unused ossl_inline STACK_OF(t1) *sk_##t1##_new_null(void) \\
	{ \\
	return (STACK_OF(t1) *)OPENSSL_sk_new_null(); \\
	} \\
	static ossl_unused ossl_inline STACK_OF(t1) *sk_##t1##_new_reserve(sk_##t1##_compfunc compare, int n) \\
	{ \\
	return (STACK_OF(t1) *)OPENSSL_sk_new_reserve((OPENSSL_sk_compfunc)compare, n); \\
	} \\
	static ossl_unused ossl_inline int sk_##t1##_reserve(STACK_OF(t1) *sk, int n) \\
	{ \\
	return OPENSSL_sk_reserve((OPENSSL_STACK *)sk, n); \\
	} \\
	static ossl_unused ossl_inline void sk_##t1##_free(STACK_OF(t1) *sk) \\
	{ \\
	OPENSSL_sk_free((OPENSSL_STACK *)sk); \\
	} \\
	static ossl_unused ossl_inline void sk_##t1##_zero(STACK_OF(t1) *sk) \\
	{ \\
	OPENSSL_sk_zero((OPENSSL_STACK *)sk); \\
	} \\
	static ossl_unused ossl_inline t2 *sk_##t1##_delete(STACK_OF(t1) *sk, int i) \\
	{ \\
	return (t2 *)OPENSSL_sk_delete((OPENSSL_STACK *)sk, i); \\
	} \\
	static ossl_unused ossl_inline t2 *sk_##t1##_delete_ptr(STACK_OF(t1) *sk, t2 *ptr) \\
	{ \\
	return (t2 *)OPENSSL_sk_delete_ptr((OPENSSL_STACK *)sk, \\
	(const void *)ptr); \\
	} \\
	static ossl_unused ossl_inline int sk_##t1##_push(STACK_OF(t1) *sk, t2 *ptr) \\
	{ \\
	return OPENSSL_sk_push((OPENSSL_STACK *)sk, (const void *)ptr); \\
	} \\
	static ossl_unused ossl_inline int sk_##t1##_unshift(STACK_OF(t1) *sk, t2 *ptr) \\
	{ \\
	return OPENSSL_sk_unshift((OPENSSL_STACK *)sk, (const void *)ptr); \\
	} \\
	static ossl_unused ossl_inline t2 *sk_##t1##_pop(STACK_OF(t1) *sk) \\
	{ \\
	return (t2 *)OPENSSL_sk_pop((OPENSSL_STACK *)sk); \\
	} \\
	static ossl_unused ossl_inline t2 *sk_##t1##_shift(STACK_OF(t1) *sk) \\
	{ \\
	return (t2 *)OPENSSL_sk_shift((OPENSSL_STACK *)sk); \\
	} \\
	static ossl_unused ossl_inline void sk_##t1##_pop_free(STACK_OF(t1) *sk, sk_##t1##_freefunc freefunc) \\
	{ \\
	OPENSSL_sk_pop_free((OPENSSL_STACK *)sk, (OPENSSL_sk_freefunc)freefunc); \\
	} \\
	static ossl_unused ossl_inline int sk_##t1##_insert(STACK_OF(t1) *sk, t2 *ptr, int idx) \\
	{ \\
	return OPENSSL_sk_insert((OPENSSL_STACK *)sk, (const void *)ptr, idx); \\
	} \\
	static ossl_unused ossl_inline t2 *sk_##t1##_set(STACK_OF(t1) *sk, int idx, t2 *ptr) \\
	{ \\
	return (t2 *)OPENSSL_sk_set((OPENSSL_STACK *)sk, idx, (const void *)ptr); \\
	} \\
	static ossl_unused ossl_inline int sk_##t1##_find(STACK_OF(t1) *sk, t2 *ptr) \\
	{ \\
	return OPENSSL_sk_find((OPENSSL_STACK *)sk, (const void *)ptr); \\
	} \\
	static ossl_unused ossl_inline int sk_##t1##_find_ex(STACK_OF(t1) *sk, t2 *ptr) \\
	{ \\
	return OPENSSL_sk_find_ex((OPENSSL_STACK *)sk, (const void *)ptr); \\
	} \\
	static ossl_unused ossl_inline int sk_##t1##_find_all(STACK_OF(t1) *sk, t2 *ptr, int *pnum) \\
	{ \\
	return OPENSSL_sk_find_all((OPENSSL_STACK *)sk, (const void *)ptr, pnum); \\
	} \\
	static ossl_unused ossl_inline void sk_##t1##_sort(STACK_OF(t1) *sk) \\
	{ \\
	OPENSSL_sk_sort((OPENSSL_STACK *)sk); \\
	} \\
	static ossl_unused ossl_inline int sk_##t1##_is_sorted(const STACK_OF(t1) *sk) \\
	{ \\
	return OPENSSL_sk_is_sorted((const OPENSSL_STACK *)sk); \\
	} \\
	static ossl_unused ossl_inline STACK_OF(t1) * sk_##t1##_dup(const STACK_OF(t1) *sk) \\
	{ \\
	return (STACK_OF(t1) *)OPENSSL_sk_dup((const OPENSSL_STACK *)sk); \\
	} \\
	static ossl_unused ossl_inline STACK_OF(t1) *sk_##t1##_deep_copy(const STACK_OF(t1) *sk, \\
	sk_##t1##_copyfunc copyfunc, \\
	sk_##t1##_freefunc freefunc) \\
	{ \\
	return (STACK_OF(t1) *)OPENSSL_sk_deep_copy((const OPENSSL_STACK *)sk, \\
	(OPENSSL_sk_copyfunc)copyfunc, \\
	(OPENSSL_sk_freefunc)freefunc); \\
	} \\
	static ossl_unused ossl_inline sk_##t1##_compfunc sk_##t1##_set_cmp_func(STACK_OF(t1) *sk, sk_##t1##_compfunc compare) \\
	{ \\
	return (sk_##t1##_compfunc)OPENSSL_sk_set_cmp_func((OPENSSL_STACK *)sk, (OPENSSL_sk_compfunc)compare); \\
	}

#define DEFINE_STACK_OF (t) SKM_DEFINE_STACK_OF(t, t, t)

#define DEFINE_STACK_OF_CONST (t) SKM_DEFINE_STACK_OF(t, const t, t)

#define DEFINE_SPECIAL_STACK_OF (t1, t2) SKM_DEFINE_STACK_OF(t1, t2, t2)

#define DEFINE_SPECIAL_STACK_OF_CONST (t1, t2)\
	SKM_DEFINE_STACK_OF(t1, const t2, t2)

#define OPENSSL_SEED_H 

#define HEADER_SEED_H 

#define SEED_BLOCK_SIZE 16

#define SEED_KEY_LENGTH 16

#define SEED_LONG 1

#define OPENSSL_SELF_TEST_H 

#define OSSL_SELF_TEST_PHASE_NONE "None"

#define OSSL_SELF_TEST_PHASE_START "Start"

#define OSSL_SELF_TEST_PHASE_CORRUPT "Corrupt"

#define OSSL_SELF_TEST_PHASE_PASS "Pass"

#define OSSL_SELF_TEST_PHASE_FAIL "Fail"

#define OSSL_SELF_TEST_TYPE_NONE "None"

#define OSSL_SELF_TEST_TYPE_MODULE_INTEGRITY "Module_Integrity"

#define OSSL_SELF_TEST_TYPE_INSTALL_INTEGRITY "Install_Integrity"

#define OSSL_SELF_TEST_TYPE_CRNG "Continuous_RNG_Test"

#define OSSL_SELF_TEST_TYPE_PCT "Conditional_PCT"

#define OSSL_SELF_TEST_TYPE_PCT_KAT "Conditional_KAT"

#define OSSL_SELF_TEST_TYPE_KAT_INTEGRITY "KAT_Integrity"

#define OSSL_SELF_TEST_TYPE_KAT_CIPHER "KAT_Cipher"

#define OSSL_SELF_TEST_TYPE_KAT_ASYM_CIPHER "KAT_AsymmetricCipher"

#define OSSL_SELF_TEST_TYPE_KAT_DIGEST "KAT_Digest"

#define OSSL_SELF_TEST_TYPE_KAT_SIGNATURE "KAT_Signature"

#define OSSL_SELF_TEST_TYPE_PCT_SIGNATURE "PCT_Signature"

#define OSSL_SELF_TEST_TYPE_KAT_KDF "KAT_KDF"

#define OSSL_SELF_TEST_TYPE_KAT_KA "KAT_KA"

#define OSSL_SELF_TEST_TYPE_DRBG "DRBG"

#define OSSL_SELF_TEST_DESC_NONE "None"

#define OSSL_SELF_TEST_DESC_INTEGRITY_HMAC "HMAC"

#define OSSL_SELF_TEST_DESC_PCT_RSA_PKCS1 "RSA"

#define OSSL_SELF_TEST_DESC_PCT_ECDSA "ECDSA"

#define OSSL_SELF_TEST_DESC_PCT_EDDSA "EDDSA"

#define OSSL_SELF_TEST_DESC_PCT_DSA "DSA"

#define OSSL_SELF_TEST_DESC_CIPHER_AES_GCM "AES_GCM"

#define OSSL_SELF_TEST_DESC_CIPHER_AES_ECB "AES_ECB_Decrypt"

#define OSSL_SELF_TEST_DESC_CIPHER_TDES "TDES"

#define OSSL_SELF_TEST_DESC_ASYM_RSA_ENC "RSA_Encrypt"

#define OSSL_SELF_TEST_DESC_ASYM_RSA_DEC "RSA_Decrypt"

#define OSSL_SELF_TEST_DESC_MD_SHA1 "SHA1"

#define OSSL_SELF_TEST_DESC_MD_SHA2 "SHA2"

#define OSSL_SELF_TEST_DESC_MD_SHA3 "SHA3"

#define OSSL_SELF_TEST_DESC_SIGN_DSA "DSA"

#define OSSL_SELF_TEST_DESC_SIGN_RSA "RSA"

#define OSSL_SELF_TEST_DESC_SIGN_ECDSA "ECDSA"

#define OSSL_SELF_TEST_DESC_DRBG_CTR "CTR"

#define OSSL_SELF_TEST_DESC_DRBG_HASH "HASH"

#define OSSL_SELF_TEST_DESC_DRBG_HMAC "HMAC"

#define OSSL_SELF_TEST_DESC_KA_DH "DH"

#define OSSL_SELF_TEST_DESC_KA_ECDH "ECDH"

#define OSSL_SELF_TEST_DESC_KDF_HKDF "HKDF"

#define OSSL_SELF_TEST_DESC_KDF_SSKDF "SSKDF"

#define OSSL_SELF_TEST_DESC_KDF_X963KDF "X963KDF"

#define OSSL_SELF_TEST_DESC_KDF_X942KDF "X942KDF"

#define OSSL_SELF_TEST_DESC_KDF_PBKDF2 "PBKDF2"

#define OSSL_SELF_TEST_DESC_KDF_SSHKDF "SSHKDF"

#define OSSL_SELF_TEST_DESC_KDF_TLS12_PRF "TLS12_PRF"

#define OSSL_SELF_TEST_DESC_KDF_KBKDF "KBKDF"

#define OSSL_SELF_TEST_DESC_KDF_KBKDF_KMAC "KBKDF_KMAC"

#define OSSL_SELF_TEST_DESC_KDF_TLS13_EXTRACT "TLS13_KDF_EXTRACT"

#define OSSL_SELF_TEST_DESC_KDF_TLS13_EXPAND "TLS13_KDF_EXPAND"

#define OSSL_SELF_TEST_DESC_RNG "RNG"

#define OPENSSL_SHA_H 

#define HEADER_SHA_H 

#define SHA_DIGEST_LENGTH 20

#define SHA_LONG unsigned int

#define SHA_LBLOCK 16

#define SHA_CBLOCK (SHA_LBLOCK*4)

#define SHA_LAST_BLOCK (SHA_CBLOCK-8)

#define SHA256_CBLOCK (SHA_LBLOCK*4)

#define SHA256_192_DIGEST_LENGTH 24

#define SHA224_DIGEST_LENGTH 28

#define SHA256_DIGEST_LENGTH 32

#define SHA384_DIGEST_LENGTH 48

#define SHA512_DIGEST_LENGTH 64

#define SHA512_CBLOCK (SHA_LBLOCK*8)

#define SHA_LONG64 uint64_t

#define OPENSSL_SRP_H 

#define HEADER_SRP_H 

#define SRP_NO_ERROR 0

#define SRP_ERR_VBASE_INCOMPLETE_FILE 1

#define SRP_ERR_VBASE_BN_LIB 2

#define SRP_ERR_OPEN_FILE 3

#define SRP_ERR_MEMORY 4

#define DB_srptype 0

#define DB_srpverifier 1

#define DB_srpsalt 2

#define DB_srpid 3

#define DB_srpgN 4

#define DB_srpinfo 5

#define DB_NUMBER 6

#define DB_SRP_INDEX 'I'

#define DB_SRP_VALID 'V'

#define DB_SRP_REVOKED 'R'

#define DB_SRP_MODIF 'v'

#define SRP_MINIMAL_N 1024

#define OPENSSL_SRTP_H 

#define HEADER_D1_SRTP_H 

#define SRTP_AES128_CM_SHA1_80 0x0001

#define SRTP_AES128_CM_SHA1_32 0x0002

#define SRTP_AES128_F8_SHA1_80 0x0003

#define SRTP_AES128_F8_SHA1_32 0x0004

#define SRTP_NULL_SHA1_80 0x0005

#define SRTP_NULL_SHA1_32 0x0006

#define SRTP_AEAD_AES_128_GCM 0x0007

#define SRTP_AEAD_AES_256_GCM 0x0008

#define SRTP_DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM 0x0009

#define SRTP_DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM 0x000A

#define SRTP_ARIA_128_CTR_HMAC_SHA1_80 0x000B

#define SRTP_ARIA_128_CTR_HMAC_SHA1_32 0x000C

#define SRTP_ARIA_256_CTR_HMAC_SHA1_80 0x000D

#define SRTP_ARIA_256_CTR_HMAC_SHA1_32 0x000E

#define SRTP_AEAD_ARIA_128_GCM 0x000F

#define SRTP_AEAD_ARIA_256_GCM 0x0010

#define OPENSSL_SSL_H 

#define HEADER_SSL_H 

#define SSL_SESSION_ASN1_VERSION 0x0001

#define SSL_MAX_SSL_SESSION_ID_LENGTH 32

#define SSL_MAX_SID_CTX_LENGTH 32

#define SSL_MIN_RSA_MODULUS_LENGTH_IN_BYTES (512/8)

#define SSL_MAX_KEY_ARG_LENGTH 8

#define SSL_MAX_PIPELINES 32

#define SSL_TXT_LOW "LOW"

#define SSL_TXT_MEDIUM "MEDIUM"

#define SSL_TXT_HIGH "HIGH"

#define SSL_TXT_FIPS "FIPS"

#define SSL_TXT_aNULL "aNULL"

#define SSL_TXT_eNULL "eNULL"

#define SSL_TXT_NULL "NULL"

#define SSL_TXT_kRSA "kRSA"

#define SSL_TXT_kDHr "kDHr"

#define SSL_TXT_kDHd "kDHd"

#define SSL_TXT_kDH "kDH"

#define SSL_TXT_kEDH "kEDH"

#define SSL_TXT_kDHE "kDHE"

#define SSL_TXT_kECDHr "kECDHr"

#define SSL_TXT_kECDHe "kECDHe"

#define SSL_TXT_kECDH "kECDH"

#define SSL_TXT_kEECDH "kEECDH"

#define SSL_TXT_kECDHE "kECDHE"

#define SSL_TXT_kPSK "kPSK"

#define SSL_TXT_kRSAPSK "kRSAPSK"

#define SSL_TXT_kECDHEPSK "kECDHEPSK"

#define SSL_TXT_kDHEPSK "kDHEPSK"

#define SSL_TXT_kGOST "kGOST"

#define SSL_TXT_kGOST18 "kGOST18"

#define SSL_TXT_kSRP "kSRP"

#define SSL_TXT_aRSA "aRSA"

#define SSL_TXT_aDSS "aDSS"

#define SSL_TXT_aDH "aDH"

#define SSL_TXT_aECDH "aECDH"

#define SSL_TXT_aECDSA "aECDSA"

#define SSL_TXT_aPSK "aPSK"

#define SSL_TXT_aGOST94 "aGOST94"

#define SSL_TXT_aGOST01 "aGOST01"

#define SSL_TXT_aGOST12 "aGOST12"

#define SSL_TXT_aGOST "aGOST"

#define SSL_TXT_aSRP "aSRP"

#define SSL_TXT_DSS "DSS"

#define SSL_TXT_DH "DH"

#define SSL_TXT_DHE "DHE"

#define SSL_TXT_EDH "EDH"

#define SSL_TXT_ADH "ADH"

#define SSL_TXT_RSA "RSA"

#define SSL_TXT_ECDH "ECDH"

#define SSL_TXT_EECDH "EECDH"

#define SSL_TXT_ECDHE "ECDHE"

#define SSL_TXT_AECDH "AECDH"

#define SSL_TXT_ECDSA "ECDSA"

#define SSL_TXT_PSK "PSK"

#define SSL_TXT_SRP "SRP"

#define SSL_TXT_DES "DES"

#define SSL_TXT_3DES "3DES"

#define SSL_TXT_RC4 "RC4"

#define SSL_TXT_RC2 "RC2"

#define SSL_TXT_IDEA "IDEA"

#define SSL_TXT_SEED "SEED"

#define SSL_TXT_AES128 "AES128"

#define SSL_TXT_AES256 "AES256"

#define SSL_TXT_AES "AES"

#define SSL_TXT_AES_GCM "AESGCM"

#define SSL_TXT_AES_CCM "AESCCM"

#define SSL_TXT_AES_CCM_8 "AESCCM8"

#define SSL_TXT_CAMELLIA128 "CAMELLIA128"

#define SSL_TXT_CAMELLIA256 "CAMELLIA256"

#define SSL_TXT_CAMELLIA "CAMELLIA"

#define SSL_TXT_CHACHA20 "CHACHA20"

#define SSL_TXT_GOST "GOST89"

#define SSL_TXT_ARIA "ARIA"

#define SSL_TXT_ARIA_GCM "ARIAGCM"

#define SSL_TXT_ARIA128 "ARIA128"

#define SSL_TXT_ARIA256 "ARIA256"

#define SSL_TXT_GOST2012_GOST8912_GOST8912 "GOST2012-GOST8912-GOST8912"

#define SSL_TXT_CBC "CBC"

#define SSL_TXT_MD5 "MD5"

#define SSL_TXT_SHA1 "SHA1"

#define SSL_TXT_SHA "SHA"

#define SSL_TXT_GOST94 "GOST94"

#define SSL_TXT_GOST89MAC "GOST89MAC"

#define SSL_TXT_GOST12 "GOST12"

#define SSL_TXT_GOST89MAC12 "GOST89MAC12"

#define SSL_TXT_SHA256 "SHA256"

#define SSL_TXT_SHA384 "SHA384"

#define SSL_TXT_SSLV3 "SSLv3"

#define SSL_TXT_TLSV1 "TLSv1"

#define SSL_TXT_TLSV1_1 "TLSv1.1"

#define SSL_TXT_TLSV1_2 "TLSv1.2"

#define SSL_TXT_ALL "ALL"

#define SSL_TXT_CMPALL "COMPLEMENTOFALL"

#define SSL_TXT_CMPDEF "COMPLEMENTOFDEFAULT"

#define SSL_DEFAULT_CIPHER_LIST "ALL:!COMPLEMENTOFDEFAULT:!eNULL"

#define TLS_DEFAULT_CIPHERSUITES "TLS_AES_256_GCM_SHA384:"\
	"TLS_CHACHA20_POLY1305_SHA256:" \\
	"TLS_AES_128_GCM_SHA256"

#define SSL_SENT_SHUTDOWN 1

#define SSL_RECEIVED_SHUTDOWN 2

#define SSL_FILETYPE_ASN1 X509_FILETYPE_ASN1

#define SSL_FILETYPE_PEM X509_FILETYPE_PEM

#define SSL_EXT_TLS_ONLY 0x00001

#define SSL_EXT_DTLS_ONLY 0x00002

#define SSL_EXT_TLS_IMPLEMENTATION_ONLY 0x00004

#define SSL_EXT_SSL3_ALLOWED 0x00008

#define SSL_EXT_TLS1_2_AND_BELOW_ONLY 0x00010

#define SSL_EXT_TLS1_3_ONLY 0x00020

#define SSL_EXT_IGNORE_ON_RESUMPTION 0x00040

#define SSL_EXT_CLIENT_HELLO 0x00080

#define SSL_EXT_TLS1_2_SERVER_HELLO 0x00100

#define SSL_EXT_TLS1_3_SERVER_HELLO 0x00200

#define SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS 0x00400

#define SSL_EXT_TLS1_3_HELLO_RETRY_REQUEST 0x00800

#define SSL_EXT_TLS1_3_CERTIFICATE 0x01000

#define SSL_EXT_TLS1_3_NEW_SESSION_TICKET 0x02000

#define SSL_EXT_TLS1_3_CERTIFICATE_REQUEST 0x04000

#define SSL_EXT_TLS1_3_CERTIFICATE_COMPRESSION 0x08000

#define SSL_EXT_TLS1_3_RAW_PUBLIC_KEY 0x10000

#define SSL_OP_BIT (n)  ((uint64_t)1 << (uint64_t)n)

#define SSL_OP_NO_EXTENDED_MASTER_SECRET SSL_OP_BIT(0)

#define SSL_OP_CLEANSE_PLAINTEXT SSL_OP_BIT(1)

#define SSL_OP_LEGACY_SERVER_CONNECT SSL_OP_BIT(2)

#define SSL_OP_ENABLE_KTLS SSL_OP_BIT(3)

#define SSL_OP_TLSEXT_PADDING SSL_OP_BIT(4)

#define SSL_OP_SAFARI_ECDHE_ECDSA_BUG SSL_OP_BIT(6)

#define SSL_OP_IGNORE_UNEXPECTED_EOF SSL_OP_BIT(7)

#define SSL_OP_ALLOW_CLIENT_RENEGOTIATION SSL_OP_BIT(8)

#define SSL_OP_DISABLE_TLSEXT_CA_NAMES SSL_OP_BIT(9)

#define SSL_OP_ALLOW_NO_DHE_KEX SSL_OP_BIT(10)

#define SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS SSL_OP_BIT(11)

#define SSL_OP_NO_QUERY_MTU SSL_OP_BIT(12)

#define SSL_OP_COOKIE_EXCHANGE SSL_OP_BIT(13)

#define SSL_OP_NO_TICKET SSL_OP_BIT(14)

#define SSL_OP_CISCO_ANYCONNECT SSL_OP_BIT(15)

#define SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION SSL_OP_BIT(16)

#define SSL_OP_NO_COMPRESSION SSL_OP_BIT(17)

#define SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION SSL_OP_BIT(18)

#define SSL_OP_NO_ENCRYPT_THEN_MAC SSL_OP_BIT(19)

#define SSL_OP_ENABLE_MIDDLEBOX_COMPAT SSL_OP_BIT(20)

#define SSL_OP_PRIORITIZE_CHACHA SSL_OP_BIT(21)

#define SSL_OP_CIPHER_SERVER_PREFERENCE SSL_OP_BIT(22)

#define SSL_OP_TLS_ROLLBACK_BUG SSL_OP_BIT(23)

#define SSL_OP_NO_ANTI_REPLAY SSL_OP_BIT(24)

#define SSL_OP_NO_SSLv3 SSL_OP_BIT(25)

#define SSL_OP_NO_TLSv1 SSL_OP_BIT(26)

#define SSL_OP_NO_TLSv1_2 SSL_OP_BIT(27)

#define SSL_OP_NO_TLSv1_1 SSL_OP_BIT(28)

#define SSL_OP_NO_TLSv1_3 SSL_OP_BIT(29)

#define SSL_OP_NO_DTLSv1 SSL_OP_BIT(26)

#define SSL_OP_NO_DTLSv1_2 SSL_OP_BIT(27)

#define SSL_OP_NO_RENEGOTIATION SSL_OP_BIT(30)

#define SSL_OP_CRYPTOPRO_TLSEXT_BUG SSL_OP_BIT(31)

#define SSL_OP_NO_TX_CERTIFICATE_COMPRESSION SSL_OP_BIT(32)

#define SSL_OP_NO_RX_CERTIFICATE_COMPRESSION SSL_OP_BIT(33)

#define SSL_OP_ENABLE_KTLS_TX_ZEROCOPY_SENDFILE SSL_OP_BIT(34)

#define SSL_OP_PREFER_NO_DHE_KEX SSL_OP_BIT(35)

#define SSL_OP_NO_SSL_MASK \
	( SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 \\
	| SSL_OP_NO_TLSv1_2 | SSL_OP_NO_TLSv1_3 )

#define SSL_OP_NO_DTLS_MASK \
	( SSL_OP_NO_DTLSv1 | SSL_OP_NO_DTLSv1_2 )

#define SSL_OP_ALL \
	( SSL_OP_CRYPTOPRO_TLSEXT_BUG | SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS \\
	| SSL_OP_TLSEXT_PADDING | SSL_OP_SAFARI_ECDHE_ECDSA_BUG )

#define SSL_OP_MICROSOFT_SESS_ID_BUG 0x0

#define SSL_OP_NETSCAPE_CHALLENGE_BUG 0x0

#define SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG 0x0

#define SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG 0x0

#define SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER 0x0

#define SSL_OP_MSIE_SSLV2_RSA_PADDING 0x0

#define SSL_OP_SSLEAY_080_CLIENT_DH_BUG 0x0

#define SSL_OP_TLS_D5_BUG 0x0

#define SSL_OP_TLS_BLOCK_PADDING_BUG 0x0

#define SSL_OP_SINGLE_ECDH_USE 0x0

#define SSL_OP_SINGLE_DH_USE 0x0

#define SSL_OP_EPHEMERAL_RSA 0x0

#define SSL_OP_NO_SSLv2 0x0

#define SSL_OP_PKCS1_CHECK_1 0x0

#define SSL_OP_PKCS1_CHECK_2 0x0

#define SSL_OP_NETSCAPE_CA_DN_BUG 0x0

#define SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG 0x0

#define SSL_MODE_ENABLE_PARTIAL_WRITE 0x00000001U

#define SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER 0x00000002U

#define SSL_MODE_AUTO_RETRY 0x00000004U

#define SSL_MODE_NO_AUTO_CHAIN 0x00000008U

#define SSL_MODE_RELEASE_BUFFERS 0x00000010U

#define SSL_MODE_SEND_CLIENTHELLO_TIME 0x00000020U

#define SSL_MODE_SEND_SERVERHELLO_TIME 0x00000040U

#define SSL_MODE_SEND_FALLBACK_SCSV 0x00000080U

#define SSL_MODE_ASYNC 0x00000100U

#define SSL_MODE_DTLS_SCTP_LABEL_LENGTH_BUG 0x00000400U

#define SSL_CERT_FLAG_TLS_STRICT 0x00000001U

#define SSL_CERT_FLAG_SUITEB_128_LOS_ONLY 0x10000

#define SSL_CERT_FLAG_SUITEB_192_LOS 0x20000

#define SSL_CERT_FLAG_SUITEB_128_LOS 0x30000

#define SSL_CERT_FLAG_BROKEN_PROTOCOL 0x10000000

#define SSL_BUILD_CHAIN_FLAG_UNTRUSTED 0x1

#define SSL_BUILD_CHAIN_FLAG_NO_ROOT 0x2

#define SSL_BUILD_CHAIN_FLAG_CHECK 0x4

#define SSL_BUILD_CHAIN_FLAG_IGNORE_ERROR 0x8

#define SSL_BUILD_CHAIN_FLAG_CLEAR_ERROR 0x10

#define CERT_PKEY_VALID 0x1

#define CERT_PKEY_SIGN 0x2

#define CERT_PKEY_EE_SIGNATURE 0x10

#define CERT_PKEY_CA_SIGNATURE 0x20

#define CERT_PKEY_EE_PARAM 0x40

#define CERT_PKEY_CA_PARAM 0x80

#define CERT_PKEY_EXPLICIT_SIGN 0x100

#define CERT_PKEY_ISSUER_NAME 0x200

#define CERT_PKEY_CERT_TYPE 0x400

#define CERT_PKEY_SUITEB 0x800

#define CERT_PKEY_RPK 0x1000

#define SSL_CONF_FLAG_CMDLINE 0x1

#define SSL_CONF_FLAG_FILE 0x2

#define SSL_CONF_FLAG_CLIENT 0x4

#define SSL_CONF_FLAG_SERVER 0x8

#define SSL_CONF_FLAG_SHOW_ERRORS 0x10

#define SSL_CONF_FLAG_CERTIFICATE 0x20

#define SSL_CONF_FLAG_REQUIRE_PRIVATE 0x40

#define SSL_CONF_TYPE_UNKNOWN 0x0

#define SSL_CONF_TYPE_STRING 0x1

#define SSL_CONF_TYPE_FILE 0x2

#define SSL_CONF_TYPE_DIR 0x3

#define SSL_CONF_TYPE_NONE 0x4

#define SSL_CONF_TYPE_STORE 0x5

#define SSL_COOKIE_LENGTH 4096

#define SSL_CTX_set_mode (ctx,op)\
	SSL_CTX_ctrl((ctx),SSL_CTRL_MODE,(op),NULL)

#define SSL_CTX_clear_mode (ctx,op)\
	SSL_CTX_ctrl((ctx),SSL_CTRL_CLEAR_MODE,(op),NULL)

#define SSL_CTX_get_mode (ctx)\
	SSL_CTX_ctrl((ctx),SSL_CTRL_MODE,0,NULL)

#define SSL_clear_mode (ssl,op)\
	SSL_ctrl((ssl),SSL_CTRL_CLEAR_MODE,(op),NULL)

#define SSL_set_mode (ssl,op)\
	SSL_ctrl((ssl),SSL_CTRL_MODE,(op),NULL)

#define SSL_get_mode (ssl)\
	SSL_ctrl((ssl),SSL_CTRL_MODE,0,NULL)

#define SSL_set_mtu (ssl, mtu)\
	SSL_ctrl((ssl),SSL_CTRL_SET_MTU,(mtu),NULL)

#define DTLS_set_link_mtu (ssl, mtu)\
	SSL_ctrl((ssl),DTLS_CTRL_SET_LINK_MTU,(mtu),NULL)

#define DTLS_get_link_min_mtu (ssl)\
	SSL_ctrl((ssl),DTLS_CTRL_GET_LINK_MIN_MTU,0,NULL)

#define SSL_get_secure_renegotiation_support (ssl)\
	SSL_ctrl((ssl), SSL_CTRL_GET_RI_SUPPORT, 0, NULL)

#define SSL_CTX_set_cert_flags (ctx,op)\
	SSL_CTX_ctrl((ctx),SSL_CTRL_CERT_FLAGS,(op),NULL)

#define SSL_set_cert_flags (s,op)\
	SSL_ctrl((s),SSL_CTRL_CERT_FLAGS,(op),NULL)

#define SSL_CTX_clear_cert_flags (ctx,op)\
	SSL_CTX_ctrl((ctx),SSL_CTRL_CLEAR_CERT_FLAGS,(op),NULL)

#define SSL_clear_cert_flags (s,op)\
	SSL_ctrl((s),SSL_CTRL_CLEAR_CERT_FLAGS,(op),NULL)

#define SSL_CTX_set_msg_callback_arg (ctx, arg) SSL_CTX_ctrl((ctx), SSL_CTRL_SET_MSG_CALLBACK_ARG, 0, (arg))

#define SSL_set_msg_callback_arg (ssl, arg) SSL_ctrl((ssl), SSL_CTRL_SET_MSG_CALLBACK_ARG, 0, (arg))

#define SSL_get_extms_support (s)\
	SSL_ctrl((s),SSL_CTRL_GET_EXTMS_SUPPORT,0,NULL)

#define SSL_MAX_CERT_LIST_DEFAULT (1024*100)

#define SSL_SESSION_CACHE_MAX_SIZE_DEFAULT (1024*20)

#define SSL_SESS_CACHE_OFF 0x0000

#define SSL_SESS_CACHE_CLIENT 0x0001

#define SSL_SESS_CACHE_SERVER 0x0002

#define SSL_SESS_CACHE_BOTH (SSL_SESS_CACHE_CLIENT|SSL_SESS_CACHE_SERVER)

#define SSL_SESS_CACHE_NO_AUTO_CLEAR 0x0080

#define SSL_SESS_CACHE_NO_INTERNAL_LOOKUP 0x0100

#define SSL_SESS_CACHE_NO_INTERNAL_STORE 0x0200

#define SSL_SESS_CACHE_NO_INTERNAL \
	(SSL_SESS_CACHE_NO_INTERNAL_LOOKUP|SSL_SESS_CACHE_NO_INTERNAL_STORE)

#define SSL_SESS_CACHE_UPDATE_TIME 0x0400

#define SSL_CTX_sess_number (ctx)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_NUMBER,0,NULL)

#define SSL_CTX_sess_connect (ctx)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_CONNECT,0,NULL)

#define SSL_CTX_sess_connect_good (ctx)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_CONNECT_GOOD,0,NULL)

#define SSL_CTX_sess_connect_renegotiate (ctx)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_CONNECT_RENEGOTIATE,0,NULL)

#define SSL_CTX_sess_accept (ctx)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_ACCEPT,0,NULL)

#define SSL_CTX_sess_accept_renegotiate (ctx)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_ACCEPT_RENEGOTIATE,0,NULL)

#define SSL_CTX_sess_accept_good (ctx)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_ACCEPT_GOOD,0,NULL)

#define SSL_CTX_sess_hits (ctx)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_HIT,0,NULL)

#define SSL_CTX_sess_cb_hits (ctx)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_CB_HIT,0,NULL)

#define SSL_CTX_sess_misses (ctx)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_MISSES,0,NULL)

#define SSL_CTX_sess_timeouts (ctx)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_TIMEOUTS,0,NULL)

#define SSL_CTX_sess_cache_full (ctx)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_CACHE_FULL,0,NULL)

#define SSL_CTX_set_npn_advertised_cb SSL_CTX_set_next_protos_advertised_cb

#define SSL_CTX_set_npn_select_cb SSL_CTX_set_next_proto_select_cb

#define SSL_get0_npn_negotiated SSL_get0_next_proto_negotiated

#define OPENSSL_NPN_UNSUPPORTED 0

#define OPENSSL_NPN_NEGOTIATED 1

#define OPENSSL_NPN_NO_OVERLAP 2

#define PSK_MAX_IDENTITY_LEN 256

#define PSK_MAX_PSK_LEN 512

#define SSL_NOTHING 1

#define SSL_WRITING 2

#define SSL_READING 3

#define SSL_X509_LOOKUP 4

#define SSL_ASYNC_PAUSED 5

#define SSL_ASYNC_NO_JOBS 6

#define SSL_CLIENT_HELLO_CB 7

#define SSL_RETRY_VERIFY 8

#define SSL_want_nothing (s)         (SSL_want(s) == SSL_NOTHING)

#define SSL_want_read (s)            (SSL_want(s) == SSL_READING)

#define SSL_want_write (s)           (SSL_want(s) == SSL_WRITING)

#define SSL_want_x509_lookup (s)     (SSL_want(s) == SSL_X509_LOOKUP)

#define SSL_want_retry_verify (s)    (SSL_want(s) == SSL_RETRY_VERIFY)

#define SSL_want_async (s)           (SSL_want(s) == SSL_ASYNC_PAUSED)

#define SSL_want_async_job (s)       (SSL_want(s) == SSL_ASYNC_NO_JOBS)

#define SSL_want_client_hello_cb (s) (SSL_want(s) == SSL_CLIENT_HELLO_CB)

#define SSL_MAC_FLAG_READ_MAC_STREAM 1

#define SSL_MAC_FLAG_WRITE_MAC_STREAM 2

#define SSL_MAC_FLAG_READ_MAC_TLSTREE 4

#define SSL_MAC_FLAG_WRITE_MAC_TLSTREE 8

#define SSL_set_app_data (s,arg)         (SSL_set_ex_data(s,0,(char *)(arg)))

#define SSL_get_app_data (s)             (SSL_get_ex_data(s,0))

#define SSL_SESSION_set_app_data (s,a)   (SSL_SESSION_set_ex_data(s,0,\
	(char *)(a)))

#define SSL_SESSION_get_app_data (s)     (SSL_SESSION_get_ex_data(s,0))

#define SSL_CTX_get_app_data (ctx)       (SSL_CTX_get_ex_data(ctx,0))

#define SSL_CTX_set_app_data (ctx,arg)   (SSL_CTX_set_ex_data(ctx,0,\
	(char *)(arg)))

#define SSL_KEY_UPDATE_NONE -1

#define SSL_KEY_UPDATE_NOT_REQUESTED 0

#define SSL_KEY_UPDATE_REQUESTED 1

#define SSL_ST_CONNECT 0x1000

#define SSL_ST_ACCEPT 0x2000

#define SSL_ST_MASK 0x0FFF

#define SSL_CB_LOOP 0x01

#define SSL_CB_EXIT 0x02

#define SSL_CB_READ 0x04

#define SSL_CB_WRITE 0x08

#define SSL_CB_ALERT 0x4000

#define SSL_CB_READ_ALERT (SSL_CB_ALERT|SSL_CB_READ)

#define SSL_CB_WRITE_ALERT (SSL_CB_ALERT|SSL_CB_WRITE)

#define SSL_CB_ACCEPT_LOOP (SSL_ST_ACCEPT|SSL_CB_LOOP)

#define SSL_CB_ACCEPT_EXIT (SSL_ST_ACCEPT|SSL_CB_EXIT)

#define SSL_CB_CONNECT_LOOP (SSL_ST_CONNECT|SSL_CB_LOOP)

#define SSL_CB_CONNECT_EXIT (SSL_ST_CONNECT|SSL_CB_EXIT)

#define SSL_CB_HANDSHAKE_START 0x10

#define SSL_CB_HANDSHAKE_DONE 0x20

#define SSL_in_connect_init (a)          (SSL_in_init(a) && !SSL_is_server(a))

#define SSL_in_accept_init (a)           (SSL_in_init(a) && SSL_is_server(a))

#define SSL_ST_READ_HEADER 0xF0

#define SSL_ST_READ_BODY 0xF1

#define SSL_ST_READ_DONE 0xF2

#define SSL_VERIFY_NONE 0x00

#define SSL_VERIFY_PEER 0x01

#define SSL_VERIFY_FAIL_IF_NO_PEER_CERT 0x02

#define SSL_VERIFY_CLIENT_ONCE 0x04

#define SSL_VERIFY_POST_HANDSHAKE 0x08

#define OpenSSL_add_ssl_algorithms ()   SSL_library_init()

#define SSLeay_add_ssl_algorithms ()    SSL_library_init()

#define SSL_get_cipher (s)\
	SSL_CIPHER_get_name(SSL_get_current_cipher(s))

#define SSL_get_cipher_bits (s,np)\
	SSL_CIPHER_get_bits(SSL_get_current_cipher(s),np)

#define SSL_get_cipher_version (s)\
	SSL_CIPHER_get_version(SSL_get_current_cipher(s))

#define SSL_get_cipher_name (s)\
	SSL_CIPHER_get_name(SSL_get_current_cipher(s))

#define SSL_get_time (a)         SSL_SESSION_get_time(a)

#define SSL_set_time (a,b)       SSL_SESSION_set_time((a),(b))

#define SSL_get_timeout (a)      SSL_SESSION_get_timeout(a)

#define SSL_set_timeout (a,b)    SSL_SESSION_set_timeout((a),(b))

#define d2i_SSL_SESSION_bio (bp,s_id) ASN1_d2i_bio_of(SSL_SESSION,SSL_SESSION_new,d2i_SSL_SESSION,bp,s_id)

#define i2d_SSL_SESSION_bio (bp,s_id) ASN1_i2d_bio_of(SSL_SESSION,i2d_SSL_SESSION,bp,s_id)

#define SSL_AD_REASON_OFFSET 1000

#define SSL_AD_CLOSE_NOTIFY SSL3_AD_CLOSE_NOTIFY

#define SSL_AD_UNEXPECTED_MESSAGE SSL3_AD_UNEXPECTED_MESSAGE

#define SSL_AD_BAD_RECORD_MAC SSL3_AD_BAD_RECORD_MAC

#define SSL_AD_DECRYPTION_FAILED TLS1_AD_DECRYPTION_FAILED

#define SSL_AD_RECORD_OVERFLOW TLS1_AD_RECORD_OVERFLOW

#define SSL_AD_DECOMPRESSION_FAILURE SSL3_AD_DECOMPRESSION_FAILURE

#define SSL_AD_HANDSHAKE_FAILURE SSL3_AD_HANDSHAKE_FAILURE

#define SSL_AD_NO_CERTIFICATE SSL3_AD_NO_CERTIFICATE

#define SSL_AD_BAD_CERTIFICATE SSL3_AD_BAD_CERTIFICATE

#define SSL_AD_UNSUPPORTED_CERTIFICATE SSL3_AD_UNSUPPORTED_CERTIFICATE

#define SSL_AD_CERTIFICATE_REVOKED SSL3_AD_CERTIFICATE_REVOKED

#define SSL_AD_CERTIFICATE_EXPIRED SSL3_AD_CERTIFICATE_EXPIRED

#define SSL_AD_CERTIFICATE_UNKNOWN SSL3_AD_CERTIFICATE_UNKNOWN

#define SSL_AD_ILLEGAL_PARAMETER SSL3_AD_ILLEGAL_PARAMETER

#define SSL_AD_UNKNOWN_CA TLS1_AD_UNKNOWN_CA

#define SSL_AD_ACCESS_DENIED TLS1_AD_ACCESS_DENIED

#define SSL_AD_DECODE_ERROR TLS1_AD_DECODE_ERROR

#define SSL_AD_DECRYPT_ERROR TLS1_AD_DECRYPT_ERROR

#define SSL_AD_EXPORT_RESTRICTION TLS1_AD_EXPORT_RESTRICTION

#define SSL_AD_PROTOCOL_VERSION TLS1_AD_PROTOCOL_VERSION

#define SSL_AD_INSUFFICIENT_SECURITY TLS1_AD_INSUFFICIENT_SECURITY

#define SSL_AD_INTERNAL_ERROR TLS1_AD_INTERNAL_ERROR

#define SSL_AD_USER_CANCELLED TLS1_AD_USER_CANCELLED

#define SSL_AD_NO_RENEGOTIATION TLS1_AD_NO_RENEGOTIATION

#define SSL_AD_MISSING_EXTENSION TLS13_AD_MISSING_EXTENSION

#define SSL_AD_CERTIFICATE_REQUIRED TLS13_AD_CERTIFICATE_REQUIRED

#define SSL_AD_UNSUPPORTED_EXTENSION TLS1_AD_UNSUPPORTED_EXTENSION

#define SSL_AD_CERTIFICATE_UNOBTAINABLE TLS1_AD_CERTIFICATE_UNOBTAINABLE

#define SSL_AD_UNRECOGNIZED_NAME TLS1_AD_UNRECOGNIZED_NAME

#define SSL_AD_BAD_CERTIFICATE_STATUS_RESPONSE TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE

#define SSL_AD_BAD_CERTIFICATE_HASH_VALUE TLS1_AD_BAD_CERTIFICATE_HASH_VALUE

#define SSL_AD_UNKNOWN_PSK_IDENTITY TLS1_AD_UNKNOWN_PSK_IDENTITY

#define SSL_AD_INAPPROPRIATE_FALLBACK TLS1_AD_INAPPROPRIATE_FALLBACK

#define SSL_AD_NO_APPLICATION_PROTOCOL TLS1_AD_NO_APPLICATION_PROTOCOL

#define SSL_ERROR_NONE 0

#define SSL_ERROR_SSL 1

#define SSL_ERROR_WANT_READ 2

#define SSL_ERROR_WANT_WRITE 3

#define SSL_ERROR_WANT_X509_LOOKUP 4

#define SSL_ERROR_SYSCALL 5

#define SSL_ERROR_ZERO_RETURN 6

#define SSL_ERROR_WANT_CONNECT 7

#define SSL_ERROR_WANT_ACCEPT 8

#define SSL_ERROR_WANT_ASYNC 9

#define SSL_ERROR_WANT_ASYNC_JOB 10

#define SSL_ERROR_WANT_CLIENT_HELLO_CB 11

#define SSL_ERROR_WANT_RETRY_VERIFY 12

#define SSL_CTRL_SET_TMP_DH 3

#define SSL_CTRL_SET_TMP_ECDH 4

#define SSL_CTRL_SET_TMP_DH_CB 6

#define SSL_CTRL_GET_CLIENT_CERT_REQUEST 9

#define SSL_CTRL_GET_NUM_RENEGOTIATIONS 10

#define SSL_CTRL_CLEAR_NUM_RENEGOTIATIONS 11

#define SSL_CTRL_GET_TOTAL_RENEGOTIATIONS 12

#define SSL_CTRL_GET_FLAGS 13

#define SSL_CTRL_EXTRA_CHAIN_CERT 14

#define SSL_CTRL_SET_MSG_CALLBACK 15

#define SSL_CTRL_SET_MSG_CALLBACK_ARG 16

#define SSL_CTRL_SET_MTU 17

#define SSL_CTRL_SESS_NUMBER 20

#define SSL_CTRL_SESS_CONNECT 21

#define SSL_CTRL_SESS_CONNECT_GOOD 22

#define SSL_CTRL_SESS_CONNECT_RENEGOTIATE 23

#define SSL_CTRL_SESS_ACCEPT 24

#define SSL_CTRL_SESS_ACCEPT_GOOD 25

#define SSL_CTRL_SESS_ACCEPT_RENEGOTIATE 26

#define SSL_CTRL_SESS_HIT 27

#define SSL_CTRL_SESS_CB_HIT 28

#define SSL_CTRL_SESS_MISSES 29

#define SSL_CTRL_SESS_TIMEOUTS 30

#define SSL_CTRL_SESS_CACHE_FULL 31

#define SSL_CTRL_MODE 33

#define SSL_CTRL_GET_READ_AHEAD 40

#define SSL_CTRL_SET_READ_AHEAD 41

#define SSL_CTRL_SET_SESS_CACHE_SIZE 42

#define SSL_CTRL_GET_SESS_CACHE_SIZE 43

#define SSL_CTRL_SET_SESS_CACHE_MODE 44

#define SSL_CTRL_GET_SESS_CACHE_MODE 45

#define SSL_CTRL_GET_MAX_CERT_LIST 50

#define SSL_CTRL_SET_MAX_CERT_LIST 51

#define SSL_CTRL_SET_MAX_SEND_FRAGMENT 52

#define SSL_CTRL_SET_TLSEXT_SERVERNAME_CB 53

#define SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG 54

#define SSL_CTRL_SET_TLSEXT_HOSTNAME 55

#define SSL_CTRL_SET_TLSEXT_DEBUG_CB 56

#define SSL_CTRL_SET_TLSEXT_DEBUG_ARG 57

#define SSL_CTRL_GET_TLSEXT_TICKET_KEYS 58

#define SSL_CTRL_SET_TLSEXT_TICKET_KEYS 59

#define SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB 63

#define SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG 64

#define SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE 65

#define SSL_CTRL_GET_TLSEXT_STATUS_REQ_EXTS 66

#define SSL_CTRL_SET_TLSEXT_STATUS_REQ_EXTS 67

#define SSL_CTRL_GET_TLSEXT_STATUS_REQ_IDS 68

#define SSL_CTRL_SET_TLSEXT_STATUS_REQ_IDS 69

#define SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP 70

#define SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP 71

#define SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB 72

#define SSL_CTRL_SET_TLS_EXT_SRP_USERNAME_CB 75

#define SSL_CTRL_SET_SRP_VERIFY_PARAM_CB 76

#define SSL_CTRL_SET_SRP_GIVE_CLIENT_PWD_CB 77

#define SSL_CTRL_SET_SRP_ARG 78

#define SSL_CTRL_SET_TLS_EXT_SRP_USERNAME 79

#define SSL_CTRL_SET_TLS_EXT_SRP_STRENGTH 80

#define SSL_CTRL_SET_TLS_EXT_SRP_PASSWORD 81

#define DTLS_CTRL_GET_TIMEOUT 73

#define DTLS_CTRL_HANDLE_TIMEOUT 74

#define SSL_CTRL_GET_RI_SUPPORT 76

#define SSL_CTRL_CLEAR_MODE 78

#define SSL_CTRL_SET_NOT_RESUMABLE_SESS_CB 79

#define SSL_CTRL_GET_EXTRA_CHAIN_CERTS 82

#define SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS 83

#define SSL_CTRL_CHAIN 88

#define SSL_CTRL_CHAIN_CERT 89

#define SSL_CTRL_GET_GROUPS 90

#define SSL_CTRL_SET_GROUPS 91

#define SSL_CTRL_SET_GROUPS_LIST 92

#define SSL_CTRL_GET_SHARED_GROUP 93

#define SSL_CTRL_SET_SIGALGS 97

#define SSL_CTRL_SET_SIGALGS_LIST 98

#define SSL_CTRL_CERT_FLAGS 99

#define SSL_CTRL_CLEAR_CERT_FLAGS 100

#define SSL_CTRL_SET_CLIENT_SIGALGS 101

#define SSL_CTRL_SET_CLIENT_SIGALGS_LIST 102

#define SSL_CTRL_GET_CLIENT_CERT_TYPES 103

#define SSL_CTRL_SET_CLIENT_CERT_TYPES 104

#define SSL_CTRL_BUILD_CERT_CHAIN 105

#define SSL_CTRL_SET_VERIFY_CERT_STORE 106

#define SSL_CTRL_SET_CHAIN_CERT_STORE 107

#define SSL_CTRL_GET_PEER_SIGNATURE_NID 108

#define SSL_CTRL_GET_PEER_TMP_KEY 109

#define SSL_CTRL_GET_RAW_CIPHERLIST 110

#define SSL_CTRL_GET_EC_POINT_FORMATS 111

#define SSL_CTRL_GET_CHAIN_CERTS 115

#define SSL_CTRL_SELECT_CURRENT_CERT 116

#define SSL_CTRL_SET_CURRENT_CERT 117

#define SSL_CTRL_SET_DH_AUTO 118

#define DTLS_CTRL_SET_LINK_MTU 120

#define DTLS_CTRL_GET_LINK_MIN_MTU 121

#define SSL_CTRL_GET_EXTMS_SUPPORT 122

#define SSL_CTRL_SET_MIN_PROTO_VERSION 123

#define SSL_CTRL_SET_MAX_PROTO_VERSION 124

#define SSL_CTRL_SET_SPLIT_SEND_FRAGMENT 125

#define SSL_CTRL_SET_MAX_PIPELINES 126

#define SSL_CTRL_GET_TLSEXT_STATUS_REQ_TYPE 127

#define SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB 128

#define SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB_ARG 129

#define SSL_CTRL_GET_MIN_PROTO_VERSION 130

#define SSL_CTRL_GET_MAX_PROTO_VERSION 131

#define SSL_CTRL_GET_SIGNATURE_NID 132

#define SSL_CTRL_GET_TMP_KEY 133

#define SSL_CTRL_GET_NEGOTIATED_GROUP 134

#define SSL_CTRL_GET_IANA_GROUPS 135

#define SSL_CTRL_SET_RETRY_VERIFY 136

#define SSL_CTRL_GET_VERIFY_CERT_STORE 137

#define SSL_CTRL_GET_CHAIN_CERT_STORE 138

#define SSL_CERT_SET_FIRST 1

#define SSL_CERT_SET_NEXT 2

#define SSL_CERT_SET_SERVER 3

#define DTLSv1_get_timeout (ssl, arg)\
	SSL_ctrl(ssl,DTLS_CTRL_GET_TIMEOUT,0, (void *)(arg))

#define DTLSv1_handle_timeout (ssl)\
	SSL_ctrl(ssl,DTLS_CTRL_HANDLE_TIMEOUT,0, NULL)

#define SSL_num_renegotiations (ssl)\
	SSL_ctrl((ssl),SSL_CTRL_GET_NUM_RENEGOTIATIONS,0,NULL)

#define SSL_clear_num_renegotiations (ssl)\
	SSL_ctrl((ssl),SSL_CTRL_CLEAR_NUM_RENEGOTIATIONS,0,NULL)

#define SSL_total_renegotiations (ssl)\
	SSL_ctrl((ssl),SSL_CTRL_GET_TOTAL_RENEGOTIATIONS,0,NULL)

#define SSL_CTX_set_tmp_dh (ctx,dh)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_TMP_DH,0,(char *)(dh))

#define SSL_CTX_set_dh_auto (ctx, onoff)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_DH_AUTO,onoff,NULL)

#define SSL_set_dh_auto (s, onoff)\
	SSL_ctrl(s,SSL_CTRL_SET_DH_AUTO,onoff,NULL)

#define SSL_set_tmp_dh (ssl,dh)\
	SSL_ctrl(ssl,SSL_CTRL_SET_TMP_DH,0,(char *)(dh))

#define SSL_CTX_set_tmp_ecdh (ctx,ecdh)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_TMP_ECDH,0,(char *)(ecdh))

#define SSL_set_tmp_ecdh (ssl,ecdh)\
	SSL_ctrl(ssl,SSL_CTRL_SET_TMP_ECDH,0,(char *)(ecdh))

#define SSL_CTX_add_extra_chain_cert (ctx,x509)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_EXTRA_CHAIN_CERT,0,(char *)(x509))

#define SSL_CTX_get_extra_chain_certs (ctx,px509)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_GET_EXTRA_CHAIN_CERTS,0,px509)

#define SSL_CTX_get_extra_chain_certs_only (ctx,px509)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_GET_EXTRA_CHAIN_CERTS,1,px509)

#define SSL_CTX_clear_extra_chain_certs (ctx)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS,0,NULL)

#define SSL_CTX_set0_chain (ctx,sk)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_CHAIN,0,(char *)(sk))

#define SSL_CTX_set1_chain (ctx,sk)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_CHAIN,1,(char *)(sk))

#define SSL_CTX_add0_chain_cert (ctx,x509)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_CHAIN_CERT,0,(char *)(x509))

#define SSL_CTX_add1_chain_cert (ctx,x509)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_CHAIN_CERT,1,(char *)(x509))

#define SSL_CTX_get0_chain_certs (ctx,px509)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_GET_CHAIN_CERTS,0,px509)

#define SSL_CTX_clear_chain_certs (ctx)\
	SSL_CTX_set0_chain(ctx,NULL)

#define SSL_CTX_build_cert_chain (ctx, flags)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_BUILD_CERT_CHAIN, flags, NULL)

#define SSL_CTX_select_current_cert (ctx,x509)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_SELECT_CURRENT_CERT,0,(char *)(x509))

#define SSL_CTX_set_current_cert (ctx, op)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CURRENT_CERT, op, NULL)

#define SSL_CTX_set0_verify_cert_store (ctx,st)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_VERIFY_CERT_STORE,0,(char *)(st))

#define SSL_CTX_set1_verify_cert_store (ctx,st)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_VERIFY_CERT_STORE,1,(char *)(st))

#define SSL_CTX_get0_verify_cert_store (ctx,st)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_GET_VERIFY_CERT_STORE,0,(char *)(st))

#define SSL_CTX_set0_chain_cert_store (ctx,st)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CHAIN_CERT_STORE,0,(char *)(st))

#define SSL_CTX_set1_chain_cert_store (ctx,st)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CHAIN_CERT_STORE,1,(char *)(st))

#define SSL_CTX_get0_chain_cert_store (ctx,st)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_GET_CHAIN_CERT_STORE,0,(char *)(st))

#define SSL_set0_chain (s,sk)\
	SSL_ctrl(s,SSL_CTRL_CHAIN,0,(char *)(sk))

#define SSL_set1_chain (s,sk)\
	SSL_ctrl(s,SSL_CTRL_CHAIN,1,(char *)(sk))

#define SSL_add0_chain_cert (s,x509)\
	SSL_ctrl(s,SSL_CTRL_CHAIN_CERT,0,(char *)(x509))

#define SSL_add1_chain_cert (s,x509)\
	SSL_ctrl(s,SSL_CTRL_CHAIN_CERT,1,(char *)(x509))

#define SSL_get0_chain_certs (s,px509)\
	SSL_ctrl(s,SSL_CTRL_GET_CHAIN_CERTS,0,px509)

#define SSL_clear_chain_certs (s)\
	SSL_set0_chain(s,NULL)

#define SSL_build_cert_chain (s, flags)\
	SSL_ctrl(s,SSL_CTRL_BUILD_CERT_CHAIN, flags, NULL)

#define SSL_select_current_cert (s,x509)\
	SSL_ctrl(s,SSL_CTRL_SELECT_CURRENT_CERT,0,(char *)(x509))

#define SSL_set_current_cert (s,op)\
	SSL_ctrl(s,SSL_CTRL_SET_CURRENT_CERT, op, NULL)

#define SSL_set0_verify_cert_store (s,st)\
	SSL_ctrl(s,SSL_CTRL_SET_VERIFY_CERT_STORE,0,(char *)(st))

#define SSL_set1_verify_cert_store (s,st)\
	SSL_ctrl(s,SSL_CTRL_SET_VERIFY_CERT_STORE,1,(char *)(st))

#define SSL_get0_verify_cert_store (s,st)\
	SSL_ctrl(s,SSL_CTRL_GET_VERIFY_CERT_STORE,0,(char *)(st))

#define SSL_set0_chain_cert_store (s,st)\
	SSL_ctrl(s,SSL_CTRL_SET_CHAIN_CERT_STORE,0,(char *)(st))

#define SSL_set1_chain_cert_store (s,st)\
	SSL_ctrl(s,SSL_CTRL_SET_CHAIN_CERT_STORE,1,(char *)(st))

#define SSL_get0_chain_cert_store (s,st)\
	SSL_ctrl(s,SSL_CTRL_GET_CHAIN_CERT_STORE,0,(char *)(st))

#define SSL_get1_groups (s, glist)\
	SSL_ctrl(s,SSL_CTRL_GET_GROUPS,0,(int*)(glist))

#define SSL_get0_iana_groups (s, plst)\
	SSL_ctrl(s,SSL_CTRL_GET_IANA_GROUPS,0,(uint16_t **)(plst))

#define SSL_CTX_set1_groups (ctx, glist, glistlen)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_GROUPS,glistlen,(int *)(glist))

#define SSL_CTX_set1_groups_list (ctx, s)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_GROUPS_LIST,0,(char *)(s))

#define SSL_set1_groups (s, glist, glistlen)\
	SSL_ctrl(s,SSL_CTRL_SET_GROUPS,glistlen,(char *)(glist))

#define SSL_set1_groups_list (s, str)\
	SSL_ctrl(s,SSL_CTRL_SET_GROUPS_LIST,0,(char *)(str))

#define SSL_get_shared_group (s, n)\
	SSL_ctrl(s,SSL_CTRL_GET_SHARED_GROUP,n,NULL)

#define SSL_get_negotiated_group (s)\
	SSL_ctrl(s,SSL_CTRL_GET_NEGOTIATED_GROUP,0,NULL)

#define SSL_CTX_set1_sigalgs (ctx, slist, slistlen)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_SIGALGS,slistlen,(int *)(slist))

#define SSL_CTX_set1_sigalgs_list (ctx, s)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_SIGALGS_LIST,0,(char *)(s))

#define SSL_set1_sigalgs (s, slist, slistlen)\
	SSL_ctrl(s,SSL_CTRL_SET_SIGALGS,slistlen,(int *)(slist))

#define SSL_set1_sigalgs_list (s, str)\
	SSL_ctrl(s,SSL_CTRL_SET_SIGALGS_LIST,0,(char *)(str))

#define SSL_CTX_set1_client_sigalgs (ctx, slist, slistlen)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CLIENT_SIGALGS,slistlen,(int *)(slist))

#define SSL_CTX_set1_client_sigalgs_list (ctx, s)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CLIENT_SIGALGS_LIST,0,(char *)(s))

#define SSL_set1_client_sigalgs (s, slist, slistlen)\
	SSL_ctrl(s,SSL_CTRL_SET_CLIENT_SIGALGS,slistlen,(int *)(slist))

#define SSL_set1_client_sigalgs_list (s, str)\
	SSL_ctrl(s,SSL_CTRL_SET_CLIENT_SIGALGS_LIST,0,(char *)(str))

#define SSL_get0_certificate_types (s, clist)\
	SSL_ctrl(s, SSL_CTRL_GET_CLIENT_CERT_TYPES, 0, (char *)(clist))

#define SSL_CTX_set1_client_certificate_types (ctx, clist, clistlen)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CLIENT_CERT_TYPES,clistlen, \\
	(char *)(clist))

#define SSL_set1_client_certificate_types (s, clist, clistlen)\
	SSL_ctrl(s,SSL_CTRL_SET_CLIENT_CERT_TYPES,clistlen,(char *)(clist))

#define SSL_get_signature_nid (s, pn)\
	SSL_ctrl(s,SSL_CTRL_GET_SIGNATURE_NID,0,pn)

#define SSL_get_peer_signature_nid (s, pn)\
	SSL_ctrl(s,SSL_CTRL_GET_PEER_SIGNATURE_NID,0,pn)

#define SSL_get_peer_tmp_key (s, pk)\
	SSL_ctrl(s,SSL_CTRL_GET_PEER_TMP_KEY,0,pk)

#define SSL_get_tmp_key (s, pk)\
	SSL_ctrl(s,SSL_CTRL_GET_TMP_KEY,0,pk)

#define SSL_get0_raw_cipherlist (s, plst)\
	SSL_ctrl(s,SSL_CTRL_GET_RAW_CIPHERLIST,0,plst)

#define SSL_get0_ec_point_formats (s, plst)\
	SSL_ctrl(s,SSL_CTRL_GET_EC_POINT_FORMATS,0,plst)

#define SSL_CTX_set_min_proto_version (ctx, version)\
	SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, version, NULL)

#define SSL_CTX_set_max_proto_version (ctx, version)\
	SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_PROTO_VERSION, version, NULL)

#define SSL_CTX_get_min_proto_version (ctx)\
	SSL_CTX_ctrl(ctx, SSL_CTRL_GET_MIN_PROTO_VERSION, 0, NULL)

#define SSL_CTX_get_max_proto_version (ctx)\
	SSL_CTX_ctrl(ctx, SSL_CTRL_GET_MAX_PROTO_VERSION, 0, NULL)

#define SSL_set_min_proto_version (s, version)\
	SSL_ctrl(s, SSL_CTRL_SET_MIN_PROTO_VERSION, version, NULL)

#define SSL_set_max_proto_version (s, version)\
	SSL_ctrl(s, SSL_CTRL_SET_MAX_PROTO_VERSION, version, NULL)

#define SSL_get_min_proto_version (s)\
	SSL_ctrl(s, SSL_CTRL_GET_MIN_PROTO_VERSION, 0, NULL)

#define SSL_get_max_proto_version (s)\
	SSL_ctrl(s, SSL_CTRL_GET_MAX_PROTO_VERSION, 0, NULL)

#define SSL_CTRL_GET_SERVER_TMP_KEY \
	SSL_CTRL_GET_PEER_TMP_KEY

#define SSL_get_server_tmp_key (s, pk)\
	SSL_get_peer_tmp_key(s, pk)

#define SSL_CTRL_GET_CURVES SSL_CTRL_GET_GROUPS

#define SSL_CTRL_SET_CURVES SSL_CTRL_SET_GROUPS

#define SSL_CTRL_SET_CURVES_LIST SSL_CTRL_SET_GROUPS_LIST

#define SSL_CTRL_GET_SHARED_CURVE SSL_CTRL_GET_SHARED_GROUP

#define SSL_get1_curves SSL_get1_groups

#define SSL_CTX_set1_curves SSL_CTX_set1_groups

#define SSL_CTX_set1_curves_list SSL_CTX_set1_groups_list

#define SSL_set1_curves SSL_set1_groups

#define SSL_set1_curves_list SSL_set1_groups_list

#define SSL_get_shared_curve SSL_get_shared_group

#define SSL_CTX_need_tmp_RSA (ctx)                0

#define SSL_CTX_set_tmp_rsa (ctx,rsa)             1

#define SSL_need_tmp_RSA (ssl)                    0

#define SSL_set_tmp_rsa (ssl,rsa)                 1

#define SSL_CTX_set_ecdh_auto (dummy, onoff)      ((onoff) != 0)

#define SSL_set_ecdh_auto (dummy, onoff)          ((onoff) != 0)

#define SSL_CTX_set_tmp_rsa_callback (ctx, cb)    while(0) (cb)(NULL, 0, 0)

#define SSL_set_tmp_rsa_callback (ssl, cb)        while(0) (cb)(NULL, 0, 0)

#define SSL_SERVERINFOV1 1

#define SSL_SERVERINFOV2 2

#define SSL_load_error_strings ()\
	OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS \\
	| OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL)

#define SSL_get_peer_certificate SSL_get1_peer_certificate

#define SSL_CLIENT_HELLO_SUCCESS 1

#define SSL_CLIENT_HELLO_ERROR 0

#define SSL_CLIENT_HELLO_RETRY (-1)

#define SSL_READ_EARLY_DATA_ERROR 0

#define SSL_READ_EARLY_DATA_SUCCESS 1

#define SSL_READ_EARLY_DATA_FINISH 2

#define SSL_WRITE_FLAG_CONCLUDE (1U << 0)

#define SSL_EARLY_DATA_NOT_SENT 0

#define SSL_EARLY_DATA_REJECTED 1

#define SSL_EARLY_DATA_ACCEPTED 2

#define SSLv23_method TLS_method

#define SSLv23_server_method TLS_server_method

#define SSLv23_client_method TLS_client_method

#define SSL_library_init () OPENSSL_init_ssl(0, NULL)

#define SSL_get0_session SSL_get_session

#define SSL_get_ex_new_index (l, p, newf, dupf, freef)\
	CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL, l, p, newf, dupf, freef)

#define SSL_SESSION_get_ex_new_index (l, p, newf, dupf, freef)\
	CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL_SESSION, l, p, newf, dupf, freef)

#define SSL_CTX_get_ex_new_index (l, p, newf, dupf, freef)\
	CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL_CTX, l, p, newf, dupf, freef)

#define SSL_CTX_sess_set_cache_size (ctx,t)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_SESS_CACHE_SIZE,t,NULL)

#define SSL_CTX_sess_get_cache_size (ctx)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_GET_SESS_CACHE_SIZE,0,NULL)

#define SSL_CTX_set_session_cache_mode (ctx,m)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_SESS_CACHE_MODE,m,NULL)

#define SSL_CTX_get_session_cache_mode (ctx)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_GET_SESS_CACHE_MODE,0,NULL)

#define SSL_CTX_get_default_read_ahead (ctx) SSL_CTX_get_read_ahead(ctx)

#define SSL_CTX_set_default_read_ahead (ctx,m) SSL_CTX_set_read_ahead(ctx,m)

#define SSL_CTX_get_read_ahead (ctx)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_GET_READ_AHEAD,0,NULL)

#define SSL_CTX_set_read_ahead (ctx,m)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_READ_AHEAD,m,NULL)

#define SSL_CTX_get_max_cert_list (ctx)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_GET_MAX_CERT_LIST,0,NULL)

#define SSL_CTX_set_max_cert_list (ctx,m)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_MAX_CERT_LIST,m,NULL)

#define SSL_get_max_cert_list (ssl)\
	SSL_ctrl(ssl,SSL_CTRL_GET_MAX_CERT_LIST,0,NULL)

#define SSL_set_max_cert_list (ssl,m)\
	SSL_ctrl(ssl,SSL_CTRL_SET_MAX_CERT_LIST,m,NULL)

#define SSL_CTX_set_max_send_fragment (ctx,m)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_MAX_SEND_FRAGMENT,m,NULL)

#define SSL_set_max_send_fragment (ssl,m)\
	SSL_ctrl(ssl,SSL_CTRL_SET_MAX_SEND_FRAGMENT,m,NULL)

#define SSL_CTX_set_split_send_fragment (ctx,m)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_SPLIT_SEND_FRAGMENT,m,NULL)

#define SSL_set_split_send_fragment (ssl,m)\
	SSL_ctrl(ssl,SSL_CTRL_SET_SPLIT_SEND_FRAGMENT,m,NULL)

#define SSL_CTX_set_max_pipelines (ctx,m)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_MAX_PIPELINES,m,NULL)

#define SSL_set_max_pipelines (ssl,m)\
	SSL_ctrl(ssl,SSL_CTRL_SET_MAX_PIPELINES,m,NULL)

#define SSL_set_retry_verify (ssl)\
	(SSL_ctrl(ssl,SSL_CTRL_SET_RETRY_VERIFY,0,NULL) > 0)

#define SSL_COMP_free_compression_methods () while(0) continue

#define SSL_STREAM_TYPE_NONE 0

#define SSL_STREAM_TYPE_READ (1U << 0)

#define SSL_STREAM_TYPE_WRITE (1U << 1)

#define SSL_STREAM_TYPE_BIDI (SSL_STREAM_TYPE_READ | SSL_STREAM_TYPE_WRITE)

#define SSL_DEFAULT_STREAM_MODE_NONE 0

#define SSL_DEFAULT_STREAM_MODE_AUTO_BIDI 1

#define SSL_DEFAULT_STREAM_MODE_AUTO_UNI 2

#define SSL_STREAM_FLAG_UNI (1U << 0)

#define SSL_STREAM_FLAG_NO_BLOCK (1U << 1)

#define SSL_STREAM_FLAG_ADVANCE (1U << 2)

#define SSL_INCOMING_STREAM_POLICY_AUTO 0

#define SSL_INCOMING_STREAM_POLICY_ACCEPT 1

#define SSL_INCOMING_STREAM_POLICY_REJECT 2

#define SSL_ACCEPT_STREAM_NO_BLOCK (1U << 0)

#define SSL_SHUTDOWN_FLAG_RAPID (1U << 0)

#define SSL_SHUTDOWN_FLAG_NO_STREAM_FLUSH (1U << 1)

#define SSL_SHUTDOWN_FLAG_NO_BLOCK (1U << 2)

#define SSL_SHUTDOWN_FLAG_WAIT_PEER (1U << 3)

#define SSL_STREAM_STATE_NONE 0

#define SSL_STREAM_STATE_OK 1

#define SSL_STREAM_STATE_WRONG_DIR 2

#define SSL_STREAM_STATE_FINISHED 3

#define SSL_STREAM_STATE_RESET_LOCAL 4

#define SSL_STREAM_STATE_RESET_REMOTE 5

#define SSL_STREAM_STATE_CONN_CLOSED 6

#define SSL_CONN_CLOSE_FLAG_LOCAL (1U << 0)

#define SSL_CONN_CLOSE_FLAG_TRANSPORT (1U << 1)

#define SSL_VALUE_CLASS_GENERIC 0

#define SSL_VALUE_CLASS_FEATURE_REQUEST 1

#define SSL_VALUE_CLASS_FEATURE_PEER_REQUEST 2

#define SSL_VALUE_CLASS_FEATURE_NEGOTIATED 3

#define SSL_VALUE_NONE 0

#define SSL_VALUE_QUIC_STREAM_BIDI_LOCAL_AVAIL 1

#define SSL_VALUE_QUIC_STREAM_BIDI_REMOTE_AVAIL 2

#define SSL_VALUE_QUIC_STREAM_UNI_LOCAL_AVAIL 3

#define SSL_VALUE_QUIC_STREAM_UNI_REMOTE_AVAIL 4

#define SSL_VALUE_QUIC_IDLE_TIMEOUT 5

#define SSL_VALUE_EVENT_HANDLING_MODE 6

#define SSL_VALUE_STREAM_WRITE_BUF_SIZE 7

#define SSL_VALUE_STREAM_WRITE_BUF_USED 8

#define SSL_VALUE_STREAM_WRITE_BUF_AVAIL 9

#define SSL_VALUE_EVENT_HANDLING_MODE_INHERIT 0

#define SSL_VALUE_EVENT_HANDLING_MODE_IMPLICIT 1

#define SSL_VALUE_EVENT_HANDLING_MODE_EXPLICIT 2

#define SSL_get_generic_value_uint (ssl, id, v)\
	SSL_get_value_uint((ssl), SSL_VALUE_CLASS_GENERIC, (id), (v))

#define SSL_set_generic_value_uint (ssl, id, v)\
	SSL_set_value_uint((ssl), SSL_VALUE_CLASS_GENERIC, (id), (v))

#define SSL_get_feature_request_uint (ssl, id, v)\
	SSL_get_value_uint((ssl), SSL_VALUE_CLASS_FEATURE_REQUEST, (id), (v))

#define SSL_set_feature_request_uint (ssl, id, v)\
	SSL_set_value_uint((ssl), SSL_VALUE_CLASS_FEATURE_REQUEST, (id), (v))

#define SSL_get_feature_peer_request_uint (ssl, id, v)\
	SSL_get_value_uint((ssl), SSL_VALUE_CLASS_FEATURE_PEER_REQUEST, (id), (v))

#define SSL_get_feature_negotiated_uint (ssl, id, v)\
	SSL_get_value_uint((ssl), SSL_VALUE_CLASS_FEATURE_NEGOTIATED, (id), (v))

#define SSL_get_quic_stream_bidi_local_avail (ssl, value)\
	SSL_get_generic_value_uint((ssl), SSL_VALUE_QUIC_STREAM_BIDI_LOCAL_AVAIL, \\
	(value))

#define SSL_get_quic_stream_bidi_remote_avail (ssl, value)\
	SSL_get_generic_value_uint((ssl), SSL_VALUE_QUIC_STREAM_BIDI_REMOTE_AVAIL, \\
	(value))

#define SSL_get_quic_stream_uni_local_avail (ssl, value)\
	SSL_get_generic_value_uint((ssl), SSL_VALUE_QUIC_STREAM_UNI_LOCAL_AVAIL, \\
	(value))

#define SSL_get_quic_stream_uni_remote_avail (ssl, value)\
	SSL_get_generic_value_uint((ssl), SSL_VALUE_QUIC_STREAM_UNI_REMOTE_AVAIL, \\
	(value))

#define SSL_get_event_handling_mode (ssl, value)\
	SSL_get_generic_value_uint((ssl), SSL_VALUE_EVENT_HANDLING_MODE, \\
	(value))

#define SSL_set_event_handling_mode (ssl, value)\
	SSL_set_generic_value_uint((ssl), SSL_VALUE_EVENT_HANDLING_MODE, \\
	(value))

#define SSL_get_stream_write_buf_size (ssl, value)\
	SSL_get_generic_value_uint((ssl), SSL_VALUE_STREAM_WRITE_BUF_SIZE, \\
	(value))

#define SSL_get_stream_write_buf_used (ssl, value)\
	SSL_get_generic_value_uint((ssl), SSL_VALUE_STREAM_WRITE_BUF_USED, \\
	(value))

#define SSL_get_stream_write_buf_avail (ssl, value)\
	SSL_get_generic_value_uint((ssl), SSL_VALUE_STREAM_WRITE_BUF_AVAIL, \\
	(value))

#define SSL_POLL_EVENT_NONE 0

#define SSL_POLL_EVENT_F (1U <<  0)

#define SSL_POLL_EVENT_EL (1U <<  1)

#define SSL_POLL_EVENT_EC (1U <<  2)

#define SSL_POLL_EVENT_ECD (1U <<  3)

#define SSL_POLL_EVENT_ER (1U <<  4)

#define SSL_POLL_EVENT_EW (1U <<  5)

#define SSL_POLL_EVENT_R (1U <<  6)

#define SSL_POLL_EVENT_W (1U <<  7)

#define SSL_POLL_EVENT_IC (1U <<  8)

#define SSL_POLL_EVENT_ISB (1U <<  9)

#define SSL_POLL_EVENT_ISU (1U << 10)

#define SSL_POLL_EVENT_OSB (1U << 11)

#define SSL_POLL_EVENT_OSU (1U << 12)

#define SSL_POLL_EVENT_RW (SSL_POLL_EVENT_R | SSL_POLL_EVENT_W)

#define SSL_POLL_EVENT_RE (SSL_POLL_EVENT_R | SSL_POLL_EVENT_ER)

#define SSL_POLL_EVENT_WE (SSL_POLL_EVENT_W | SSL_POLL_EVENT_EW)

#define SSL_POLL_EVENT_RWE (SSL_POLL_EVENT_RE | SSL_POLL_EVENT_WE)

#define SSL_POLL_EVENT_E (SSL_POLL_EVENT_EL | SSL_POLL_EVENT_EC\
	| SSL_POLL_EVENT_ER | SSL_POLL_EVENT_EW)

#define SSL_POLL_EVENT_IS (SSL_POLL_EVENT_ISB | SSL_POLL_EVENT_ISU)

#define SSL_POLL_EVENT_ISE (SSL_POLL_EVENT_IS | SSL_POLL_EVENT_EC)

#define SSL_POLL_EVENT_I (SSL_POLL_EVENT_IS | SSL_POLL_EVENT_IC)

#define SSL_POLL_EVENT_OS (SSL_POLL_EVENT_OSB | SSL_POLL_EVENT_OSU)

#define SSL_POLL_EVENT_OSE (SSL_POLL_EVENT_OS | SSL_POLL_EVENT_EC)

#define SSL_POLL_FLAG_NO_HANDLE_EVENTS (1U << 0)

#define SSL_cache_hit (s) SSL_session_reused(s)

#define SSL_disable_ct (s)\
	((void) SSL_set_validation_callback((s), NULL, NULL))

#define SSL_CTX_disable_ct (ctx)\
	((void) SSL_CTX_set_validation_callback((ctx), NULL, NULL))

#define SSL_SECOP_OTHER_TYPE 0xffff0000

#define SSL_SECOP_OTHER_NONE 0

#define SSL_SECOP_OTHER_CIPHER (1 << 16)

#define SSL_SECOP_OTHER_CURVE (2 << 16)

#define SSL_SECOP_OTHER_DH (3 << 16)

#define SSL_SECOP_OTHER_PKEY (4 << 16)

#define SSL_SECOP_OTHER_SIGALG (5 << 16)

#define SSL_SECOP_OTHER_CERT (6 << 16)

#define SSL_SECOP_PEER 0x1000

#define SSL_SECOP_CIPHER_SUPPORTED (1 | SSL_SECOP_OTHER_CIPHER)

#define SSL_SECOP_CIPHER_SHARED (2 | SSL_SECOP_OTHER_CIPHER)

#define SSL_SECOP_CIPHER_CHECK (3 | SSL_SECOP_OTHER_CIPHER)

#define SSL_SECOP_CURVE_SUPPORTED (4 | SSL_SECOP_OTHER_CURVE)

#define SSL_SECOP_CURVE_SHARED (5 | SSL_SECOP_OTHER_CURVE)

#define SSL_SECOP_CURVE_CHECK (6 | SSL_SECOP_OTHER_CURVE)

#define SSL_SECOP_TMP_DH (7 | SSL_SECOP_OTHER_PKEY)

#define SSL_SECOP_VERSION (9 | SSL_SECOP_OTHER_NONE)

#define SSL_SECOP_TICKET (10 | SSL_SECOP_OTHER_NONE)

#define SSL_SECOP_SIGALG_SUPPORTED (11 | SSL_SECOP_OTHER_SIGALG)

#define SSL_SECOP_SIGALG_SHARED (12 | SSL_SECOP_OTHER_SIGALG)

#define SSL_SECOP_SIGALG_CHECK (13 | SSL_SECOP_OTHER_SIGALG)

#define SSL_SECOP_SIGALG_MASK (14 | SSL_SECOP_OTHER_SIGALG)

#define SSL_SECOP_COMPRESSION (15 | SSL_SECOP_OTHER_NONE)

#define SSL_SECOP_EE_KEY (16 | SSL_SECOP_OTHER_CERT)

#define SSL_SECOP_CA_KEY (17 | SSL_SECOP_OTHER_CERT)

#define SSL_SECOP_CA_MD (18 | SSL_SECOP_OTHER_CERT)

#define SSL_SECOP_PEER_EE_KEY (SSL_SECOP_EE_KEY | SSL_SECOP_PEER)

#define SSL_SECOP_PEER_CA_KEY (SSL_SECOP_CA_KEY | SSL_SECOP_PEER)

#define SSL_SECOP_PEER_CA_MD (SSL_SECOP_CA_MD | SSL_SECOP_PEER)

#define OPENSSL_INIT_NO_LOAD_SSL_STRINGS 0x00100000L

#define OPENSSL_INIT_LOAD_SSL_STRINGS 0x00200000L

#define OPENSSL_INIT_SSL_DEFAULT \
	(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS)

#define SSL_TICKET_FATAL_ERR_MALLOC 0

#define SSL_TICKET_FATAL_ERR_OTHER 1

#define SSL_TICKET_NONE 2

#define SSL_TICKET_EMPTY 3

#define SSL_TICKET_NO_DECRYPT 4

#define SSL_TICKET_SUCCESS 5

#define SSL_TICKET_SUCCESS_RENEW 6

#define SSL_TICKET_RETURN_ABORT 0

#define SSL_TICKET_RETURN_IGNORE 1

#define SSL_TICKET_RETURN_IGNORE_RENEW 2

#define SSL_TICKET_RETURN_USE 3

#define SSL_TICKET_RETURN_USE_RENEW 4

#define OPENSSL_SSL2_H 

#define HEADER_SSL2_H 

#define SSL2_VERSION 0x0002

#define SSL2_MT_CLIENT_HELLO 1

#define OPENSSL_SSL3_H 

#define HEADER_SSL3_H 

#define SSL3_CK_SCSV 0x030000FF

#define SSL3_CK_FALLBACK_SCSV 0x03005600

#define SSL3_CK_RSA_NULL_MD5 0x03000001

#define SSL3_CK_RSA_NULL_SHA 0x03000002

#define SSL3_CK_RSA_RC4_40_MD5 0x03000003

#define SSL3_CK_RSA_RC4_128_MD5 0x03000004

#define SSL3_CK_RSA_RC4_128_SHA 0x03000005

#define SSL3_CK_RSA_RC2_40_MD5 0x03000006

#define SSL3_CK_RSA_IDEA_128_SHA 0x03000007

#define SSL3_CK_RSA_DES_40_CBC_SHA 0x03000008

#define SSL3_CK_RSA_DES_64_CBC_SHA 0x03000009

#define SSL3_CK_RSA_DES_192_CBC3_SHA 0x0300000A

#define SSL3_CK_DH_DSS_DES_40_CBC_SHA 0x0300000B

#define SSL3_CK_DH_DSS_DES_64_CBC_SHA 0x0300000C

#define SSL3_CK_DH_DSS_DES_192_CBC3_SHA 0x0300000D

#define SSL3_CK_DH_RSA_DES_40_CBC_SHA 0x0300000E

#define SSL3_CK_DH_RSA_DES_64_CBC_SHA 0x0300000F

#define SSL3_CK_DH_RSA_DES_192_CBC3_SHA 0x03000010

#define SSL3_CK_DHE_DSS_DES_40_CBC_SHA 0x03000011

#define SSL3_CK_EDH_DSS_DES_40_CBC_SHA SSL3_CK_DHE_DSS_DES_40_CBC_SHA

#define SSL3_CK_DHE_DSS_DES_64_CBC_SHA 0x03000012

#define SSL3_CK_EDH_DSS_DES_64_CBC_SHA SSL3_CK_DHE_DSS_DES_64_CBC_SHA

#define SSL3_CK_DHE_DSS_DES_192_CBC3_SHA 0x03000013

#define SSL3_CK_EDH_DSS_DES_192_CBC3_SHA SSL3_CK_DHE_DSS_DES_192_CBC3_SHA

#define SSL3_CK_DHE_RSA_DES_40_CBC_SHA 0x03000014

#define SSL3_CK_EDH_RSA_DES_40_CBC_SHA SSL3_CK_DHE_RSA_DES_40_CBC_SHA

#define SSL3_CK_DHE_RSA_DES_64_CBC_SHA 0x03000015

#define SSL3_CK_EDH_RSA_DES_64_CBC_SHA SSL3_CK_DHE_RSA_DES_64_CBC_SHA

#define SSL3_CK_DHE_RSA_DES_192_CBC3_SHA 0x03000016

#define SSL3_CK_EDH_RSA_DES_192_CBC3_SHA SSL3_CK_DHE_RSA_DES_192_CBC3_SHA

#define SSL3_CK_ADH_RC4_40_MD5 0x03000017

#define SSL3_CK_ADH_RC4_128_MD5 0x03000018

#define SSL3_CK_ADH_DES_40_CBC_SHA 0x03000019

#define SSL3_CK_ADH_DES_64_CBC_SHA 0x0300001A

#define SSL3_CK_ADH_DES_192_CBC_SHA 0x0300001B

#define SSL3_RFC_RSA_NULL_MD5 "TLS_RSA_WITH_NULL_MD5"

#define SSL3_RFC_RSA_NULL_SHA "TLS_RSA_WITH_NULL_SHA"

#define SSL3_RFC_RSA_DES_192_CBC3_SHA "TLS_RSA_WITH_3DES_EDE_CBC_SHA"

#define SSL3_RFC_DHE_DSS_DES_192_CBC3_SHA "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"

#define SSL3_RFC_DHE_RSA_DES_192_CBC3_SHA "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"

#define SSL3_RFC_ADH_DES_192_CBC_SHA "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA"

#define SSL3_RFC_RSA_IDEA_128_SHA "TLS_RSA_WITH_IDEA_CBC_SHA"

#define SSL3_RFC_RSA_RC4_128_MD5 "TLS_RSA_WITH_RC4_128_MD5"

#define SSL3_RFC_RSA_RC4_128_SHA "TLS_RSA_WITH_RC4_128_SHA"

#define SSL3_RFC_ADH_RC4_128_MD5 "TLS_DH_anon_WITH_RC4_128_MD5"

#define SSL3_TXT_RSA_NULL_MD5 "NULL-MD5"

#define SSL3_TXT_RSA_NULL_SHA "NULL-SHA"

#define SSL3_TXT_RSA_RC4_40_MD5 "EXP-RC4-MD5"

#define SSL3_TXT_RSA_RC4_128_MD5 "RC4-MD5"

#define SSL3_TXT_RSA_RC4_128_SHA "RC4-SHA"

#define SSL3_TXT_RSA_RC2_40_MD5 "EXP-RC2-CBC-MD5"

#define SSL3_TXT_RSA_IDEA_128_SHA "IDEA-CBC-SHA"

#define SSL3_TXT_RSA_DES_40_CBC_SHA "EXP-DES-CBC-SHA"

#define SSL3_TXT_RSA_DES_64_CBC_SHA "DES-CBC-SHA"

#define SSL3_TXT_RSA_DES_192_CBC3_SHA "DES-CBC3-SHA"

#define SSL3_TXT_DH_DSS_DES_40_CBC_SHA "EXP-DH-DSS-DES-CBC-SHA"

#define SSL3_TXT_DH_DSS_DES_64_CBC_SHA "DH-DSS-DES-CBC-SHA"

#define SSL3_TXT_DH_DSS_DES_192_CBC3_SHA "DH-DSS-DES-CBC3-SHA"

#define SSL3_TXT_DH_RSA_DES_40_CBC_SHA "EXP-DH-RSA-DES-CBC-SHA"

#define SSL3_TXT_DH_RSA_DES_64_CBC_SHA "DH-RSA-DES-CBC-SHA"

#define SSL3_TXT_DH_RSA_DES_192_CBC3_SHA "DH-RSA-DES-CBC3-SHA"

#define SSL3_TXT_DHE_DSS_DES_40_CBC_SHA "EXP-DHE-DSS-DES-CBC-SHA"

#define SSL3_TXT_DHE_DSS_DES_64_CBC_SHA "DHE-DSS-DES-CBC-SHA"

#define SSL3_TXT_DHE_DSS_DES_192_CBC3_SHA "DHE-DSS-DES-CBC3-SHA"

#define SSL3_TXT_DHE_RSA_DES_40_CBC_SHA "EXP-DHE-RSA-DES-CBC-SHA"

#define SSL3_TXT_DHE_RSA_DES_64_CBC_SHA "DHE-RSA-DES-CBC-SHA"

#define SSL3_TXT_DHE_RSA_DES_192_CBC3_SHA "DHE-RSA-DES-CBC3-SHA"

#define SSL3_TXT_EDH_DSS_DES_40_CBC_SHA "EXP-EDH-DSS-DES-CBC-SHA"

#define SSL3_TXT_EDH_DSS_DES_64_CBC_SHA "EDH-DSS-DES-CBC-SHA"

#define SSL3_TXT_EDH_DSS_DES_192_CBC3_SHA "EDH-DSS-DES-CBC3-SHA"

#define SSL3_TXT_EDH_RSA_DES_40_CBC_SHA "EXP-EDH-RSA-DES-CBC-SHA"

#define SSL3_TXT_EDH_RSA_DES_64_CBC_SHA "EDH-RSA-DES-CBC-SHA"

#define SSL3_TXT_EDH_RSA_DES_192_CBC3_SHA "EDH-RSA-DES-CBC3-SHA"

#define SSL3_TXT_ADH_RC4_40_MD5 "EXP-ADH-RC4-MD5"

#define SSL3_TXT_ADH_RC4_128_MD5 "ADH-RC4-MD5"

#define SSL3_TXT_ADH_DES_40_CBC_SHA "EXP-ADH-DES-CBC-SHA"

#define SSL3_TXT_ADH_DES_64_CBC_SHA "ADH-DES-CBC-SHA"

#define SSL3_TXT_ADH_DES_192_CBC_SHA "ADH-DES-CBC3-SHA"

#define SSL3_SSL_SESSION_ID_LENGTH 32

#define SSL3_MAX_SSL_SESSION_ID_LENGTH 32

#define SSL3_MASTER_SECRET_SIZE 48

#define SSL3_RANDOM_SIZE 32

#define SSL3_SESSION_ID_SIZE 32

#define SSL3_RT_HEADER_LENGTH 5

#define SSL3_HM_HEADER_LENGTH 4

#define SSL3_ALIGN_PAYLOAD 8

#define SSL3_RT_MAX_MD_SIZE 64

#define SSL_RT_MAX_CIPHER_BLOCK_SIZE 16

#define SSL3_RT_MAX_EXTRA (16384)

#define SSL3_RT_MAX_PLAIN_LENGTH 16384

#define SSL3_RT_MAX_COMPRESSED_OVERHEAD 1024

#define SSL3_RT_MAX_ENCRYPTED_OVERHEAD (256 + SSL3_RT_MAX_MD_SIZE)

#define SSL3_RT_MAX_TLS13_ENCRYPTED_OVERHEAD 256

#define SSL3_RT_SEND_MAX_ENCRYPTED_OVERHEAD \
	(SSL_RT_MAX_CIPHER_BLOCK_SIZE + SSL3_RT_MAX_MD_SIZE)

#define SSL3_RT_MAX_COMPRESSED_LENGTH SSL3_RT_MAX_PLAIN_LENGTH

#define SSL3_RT_MAX_ENCRYPTED_LENGTH \
	(SSL3_RT_MAX_ENCRYPTED_OVERHEAD+SSL3_RT_MAX_COMPRESSED_LENGTH)

#define SSL3_RT_MAX_TLS13_ENCRYPTED_LENGTH \
	(SSL3_RT_MAX_PLAIN_LENGTH + SSL3_RT_MAX_TLS13_ENCRYPTED_OVERHEAD)

#define SSL3_RT_MAX_PACKET_SIZE \
	(SSL3_RT_MAX_ENCRYPTED_LENGTH+SSL3_RT_HEADER_LENGTH)

#define SSL3_MD_CLIENT_FINISHED_CONST "\x43\x4C\x4E\x54"

#define SSL3_MD_SERVER_FINISHED_CONST "\x53\x52\x56\x52"

#define SSL3_VERSION_MAJOR 0x03

#define SSL3_VERSION_MINOR 0x00

#define SSL3_RT_CHANGE_CIPHER_SPEC 20

#define SSL3_RT_ALERT 21

#define SSL3_RT_HANDSHAKE 22

#define SSL3_RT_APPLICATION_DATA 23

#define TLS1_RT_CRYPTO 0x1000

#define TLS1_RT_CRYPTO_PREMASTER (TLS1_RT_CRYPTO | 0x1)

#define TLS1_RT_CRYPTO_CLIENT_RANDOM (TLS1_RT_CRYPTO | 0x2)

#define TLS1_RT_CRYPTO_SERVER_RANDOM (TLS1_RT_CRYPTO | 0x3)

#define TLS1_RT_CRYPTO_MASTER (TLS1_RT_CRYPTO | 0x4)

#define TLS1_RT_CRYPTO_READ 0x0000

#define TLS1_RT_CRYPTO_WRITE 0x0100

#define TLS1_RT_CRYPTO_MAC (TLS1_RT_CRYPTO | 0x5)

#define TLS1_RT_CRYPTO_KEY (TLS1_RT_CRYPTO | 0x6)

#define TLS1_RT_CRYPTO_IV (TLS1_RT_CRYPTO | 0x7)

#define TLS1_RT_CRYPTO_FIXED_IV (TLS1_RT_CRYPTO | 0x8)

#define SSL3_RT_HEADER 0x100

#define SSL3_RT_INNER_CONTENT_TYPE 0x101

#define SSL3_RT_QUIC_DATAGRAM 0x200

#define SSL3_RT_QUIC_PACKET 0x201

#define SSL3_RT_QUIC_FRAME_FULL 0x202

#define SSL3_RT_QUIC_FRAME_HEADER 0x203

#define SSL3_RT_QUIC_FRAME_PADDING 0x204

#define SSL3_AL_WARNING 1

#define SSL3_AL_FATAL 2

#define SSL3_AD_CLOSE_NOTIFY 0

#define SSL3_AD_UNEXPECTED_MESSAGE 10

#define SSL3_AD_BAD_RECORD_MAC 20

#define SSL3_AD_DECOMPRESSION_FAILURE 30

#define SSL3_AD_HANDSHAKE_FAILURE 40

#define SSL3_AD_NO_CERTIFICATE 41

#define SSL3_AD_BAD_CERTIFICATE 42

#define SSL3_AD_UNSUPPORTED_CERTIFICATE 43

#define SSL3_AD_CERTIFICATE_REVOKED 44

#define SSL3_AD_CERTIFICATE_EXPIRED 45

#define SSL3_AD_CERTIFICATE_UNKNOWN 46

#define SSL3_AD_ILLEGAL_PARAMETER 47

#define TLS1_HB_REQUEST 1

#define TLS1_HB_RESPONSE 2

#define SSL3_CT_RSA_SIGN 1

#define SSL3_CT_DSS_SIGN 2

#define SSL3_CT_RSA_FIXED_DH 3

#define SSL3_CT_DSS_FIXED_DH 4

#define SSL3_CT_RSA_EPHEMERAL_DH 5

#define SSL3_CT_DSS_EPHEMERAL_DH 6

#define SSL3_CT_FORTEZZA_DMS 20

#define SSL3_CT_NUMBER 12

#define SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS 0x0001

#define TLS1_FLAGS_TLS_PADDING_BUG 0x0

#define TLS1_FLAGS_SKIP_CERT_VERIFY 0x0010

#define TLS1_FLAGS_ENCRYPT_THEN_MAC_READ 0x0100

#define TLS1_FLAGS_ENCRYPT_THEN_MAC TLS1_FLAGS_ENCRYPT_THEN_MAC_READ

#define TLS1_FLAGS_RECEIVED_EXTMS 0x0200

#define TLS1_FLAGS_ENCRYPT_THEN_MAC_WRITE 0x0400

#define TLS1_FLAGS_STATELESS 0x0800

#define TLS1_FLAGS_REQUIRED_EXTMS 0x1000

#define SSL3_MT_HELLO_REQUEST 0

#define SSL3_MT_CLIENT_HELLO 1

#define SSL3_MT_SERVER_HELLO 2

#define SSL3_MT_NEWSESSION_TICKET 4

#define SSL3_MT_END_OF_EARLY_DATA 5

#define SSL3_MT_ENCRYPTED_EXTENSIONS 8

#define SSL3_MT_CERTIFICATE 11

#define SSL3_MT_SERVER_KEY_EXCHANGE 12

#define SSL3_MT_CERTIFICATE_REQUEST 13

#define SSL3_MT_SERVER_DONE 14

#define SSL3_MT_CERTIFICATE_VERIFY 15

#define SSL3_MT_CLIENT_KEY_EXCHANGE 16

#define SSL3_MT_FINISHED 20

#define SSL3_MT_CERTIFICATE_URL 21

#define SSL3_MT_CERTIFICATE_STATUS 22

#define SSL3_MT_SUPPLEMENTAL_DATA 23

#define SSL3_MT_KEY_UPDATE 24

#define SSL3_MT_COMPRESSED_CERTIFICATE 25

#define SSL3_MT_NEXT_PROTO 67

#define SSL3_MT_MESSAGE_HASH 254

#define DTLS1_MT_HELLO_VERIFY_REQUEST 3

#define SSL3_MT_CHANGE_CIPHER_SPEC 0x0101

#define SSL3_MT_CCS 1

#define SSL3_CC_READ 0x001

#define SSL3_CC_WRITE 0x002

#define SSL3_CC_CLIENT 0x010

#define SSL3_CC_SERVER 0x020

#define SSL3_CC_EARLY 0x040

#define SSL3_CC_HANDSHAKE 0x080

#define SSL3_CC_APPLICATION 0x100

#define SSL3_CHANGE_CIPHER_CLIENT_WRITE (SSL3_CC_CLIENT|SSL3_CC_WRITE)

#define SSL3_CHANGE_CIPHER_SERVER_READ (SSL3_CC_SERVER|SSL3_CC_READ)

#define SSL3_CHANGE_CIPHER_CLIENT_READ (SSL3_CC_CLIENT|SSL3_CC_READ)

#define SSL3_CHANGE_CIPHER_SERVER_WRITE (SSL3_CC_SERVER|SSL3_CC_WRITE)

#define OPENSSL_SSLERR_H 

#define SSL_R_APPLICATION_DATA_AFTER_CLOSE_NOTIFY 291

#define SSL_R_APP_DATA_IN_HANDSHAKE 100

#define SSL_R_ATTEMPT_TO_REUSE_SESSION_IN_DIFFERENT_CONTEXT 272

#define SSL_R_AT_LEAST_TLS_1_2_NEEDED_IN_SUITEB_MODE 158

#define SSL_R_BAD_CERTIFICATE 348

#define SSL_R_BAD_CHANGE_CIPHER_SPEC 103

#define SSL_R_BAD_CIPHER 186

#define SSL_R_BAD_COMPRESSION_ALGORITHM 326

#define SSL_R_BAD_DATA 390

#define SSL_R_BAD_DATA_RETURNED_BY_CALLBACK 106

#define SSL_R_BAD_DECOMPRESSION 107

#define SSL_R_BAD_DH_VALUE 102

#define SSL_R_BAD_DIGEST_LENGTH 111

#define SSL_R_BAD_EARLY_DATA 233

#define SSL_R_BAD_ECC_CERT 304

#define SSL_R_BAD_ECPOINT 306

#define SSL_R_BAD_EXTENSION 110

#define SSL_R_BAD_HANDSHAKE_LENGTH 332

#define SSL_R_BAD_HANDSHAKE_STATE 236

#define SSL_R_BAD_HELLO_REQUEST 105

#define SSL_R_BAD_HRR_VERSION 263

#define SSL_R_BAD_KEY_SHARE 108

#define SSL_R_BAD_KEY_UPDATE 122

#define SSL_R_BAD_LEGACY_VERSION 292

#define SSL_R_BAD_LENGTH 271

#define SSL_R_BAD_PACKET 240

#define SSL_R_BAD_PACKET_LENGTH 115

#define SSL_R_BAD_PROTOCOL_VERSION_NUMBER 116

#define SSL_R_BAD_PSK 219

#define SSL_R_BAD_PSK_IDENTITY 114

#define SSL_R_BAD_RECORD_TYPE 443

#define SSL_R_BAD_RSA_ENCRYPT 119

#define SSL_R_BAD_SIGNATURE 123

#define SSL_R_BAD_SRP_A_LENGTH 347

#define SSL_R_BAD_SRP_PARAMETERS 371

#define SSL_R_BAD_SRTP_MKI_VALUE 352

#define SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST 353

#define SSL_R_BAD_SSL_FILETYPE 124

#define SSL_R_BAD_VALUE 384

#define SSL_R_BAD_WRITE_RETRY 127

#define SSL_R_BINDER_DOES_NOT_VERIFY 253

#define SSL_R_BIO_NOT_SET 128

#define SSL_R_BLOCK_CIPHER_PAD_IS_WRONG 129

#define SSL_R_BN_LIB 130

#define SSL_R_CALLBACK_FAILED 234

#define SSL_R_CANNOT_CHANGE_CIPHER 109

#define SSL_R_CANNOT_GET_GROUP_NAME 299

#define SSL_R_CA_DN_LENGTH_MISMATCH 131

#define SSL_R_CA_KEY_TOO_SMALL 397

#define SSL_R_CA_MD_TOO_WEAK 398

#define SSL_R_CCS_RECEIVED_EARLY 133

#define SSL_R_CERTIFICATE_VERIFY_FAILED 134

#define SSL_R_CERT_CB_ERROR 377

#define SSL_R_CERT_LENGTH_MISMATCH 135

#define SSL_R_CIPHERSUITE_DIGEST_HAS_CHANGED 218

#define SSL_R_CIPHER_CODE_WRONG_LENGTH 137

#define SSL_R_CLIENTHELLO_TLSEXT 226

#define SSL_R_COMPRESSED_LENGTH_TOO_LONG 140

#define SSL_R_COMPRESSION_DISABLED 343

#define SSL_R_COMPRESSION_FAILURE 141

#define SSL_R_COMPRESSION_ID_NOT_WITHIN_PRIVATE_RANGE 307

#define SSL_R_COMPRESSION_LIBRARY_ERROR 142

#define SSL_R_CONNECTION_TYPE_NOT_SET 144

#define SSL_R_CONN_USE_ONLY 356

#define SSL_R_CONTEXT_NOT_DANE_ENABLED 167

#define SSL_R_COOKIE_GEN_CALLBACK_FAILURE 400

#define SSL_R_COOKIE_MISMATCH 308

#define SSL_R_COPY_PARAMETERS_FAILED 296

#define SSL_R_CUSTOM_EXT_HANDLER_ALREADY_INSTALLED 206

#define SSL_R_DANE_ALREADY_ENABLED 172

#define SSL_R_DANE_CANNOT_OVERRIDE_MTYPE_FULL 173

#define SSL_R_DANE_NOT_ENABLED 175

#define SSL_R_DANE_TLSA_BAD_CERTIFICATE 180

#define SSL_R_DANE_TLSA_BAD_CERTIFICATE_USAGE 184

#define SSL_R_DANE_TLSA_BAD_DATA_LENGTH 189

#define SSL_R_DANE_TLSA_BAD_DIGEST_LENGTH 192

#define SSL_R_DANE_TLSA_BAD_MATCHING_TYPE 200

#define SSL_R_DANE_TLSA_BAD_PUBLIC_KEY 201

#define SSL_R_DANE_TLSA_BAD_SELECTOR 202

#define SSL_R_DANE_TLSA_NULL_DATA 203

#define SSL_R_DATA_BETWEEN_CCS_AND_FINISHED 145

#define SSL_R_DATA_LENGTH_TOO_LONG 146

#define SSL_R_DECRYPTION_FAILED 147

#define SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC 281

#define SSL_R_DH_KEY_TOO_SMALL 394

#define SSL_R_DH_PUBLIC_VALUE_LENGTH_IS_WRONG 148

#define SSL_R_DIGEST_CHECK_FAILED 149

#define SSL_R_DTLS_MESSAGE_TOO_BIG 334

#define SSL_R_DUPLICATE_COMPRESSION_ID 309

#define SSL_R_ECC_CERT_NOT_FOR_SIGNING 318

#define SSL_R_ECDH_REQUIRED_FOR_SUITEB_MODE 374

#define SSL_R_EE_KEY_TOO_SMALL 399

#define SSL_R_EMPTY_RAW_PUBLIC_KEY 349

#define SSL_R_EMPTY_SRTP_PROTECTION_PROFILE_LIST 354

#define SSL_R_ENCRYPTED_LENGTH_TOO_LONG 150

#define SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST 151

#define SSL_R_ERROR_SETTING_TLSA_BASE_DOMAIN 204

#define SSL_R_EXCEEDS_MAX_FRAGMENT_SIZE 194

#define SSL_R_EXCESSIVE_MESSAGE_SIZE 152

#define SSL_R_EXTENSION_NOT_RECEIVED 279

#define SSL_R_EXTRA_DATA_IN_MESSAGE 153

#define SSL_R_EXT_LENGTH_MISMATCH 163

#define SSL_R_FAILED_TO_GET_PARAMETER 316

#define SSL_R_FAILED_TO_INIT_ASYNC 405

#define SSL_R_FEATURE_NEGOTIATION_NOT_COMPLETE 417

#define SSL_R_FEATURE_NOT_RENEGOTIABLE 413

#define SSL_R_FRAGMENTED_CLIENT_HELLO 401

#define SSL_R_GOT_A_FIN_BEFORE_A_CCS 154

#define SSL_R_HTTPS_PROXY_REQUEST 155

#define SSL_R_HTTP_REQUEST 156

#define SSL_R_ILLEGAL_POINT_COMPRESSION 162

#define SSL_R_ILLEGAL_SUITEB_DIGEST 380

#define SSL_R_INAPPROPRIATE_FALLBACK 373

#define SSL_R_INCONSISTENT_COMPRESSION 340

#define SSL_R_INCONSISTENT_EARLY_DATA_ALPN 222

#define SSL_R_INCONSISTENT_EARLY_DATA_SNI 231

#define SSL_R_INCONSISTENT_EXTMS 104

#define SSL_R_INSUFFICIENT_SECURITY 241

#define SSL_R_INVALID_ALERT 205

#define SSL_R_INVALID_CCS_MESSAGE 260

#define SSL_R_INVALID_CERTIFICATE_OR_ALG 238

#define SSL_R_INVALID_COMMAND 280

#define SSL_R_INVALID_COMPRESSION_ALGORITHM 341

#define SSL_R_INVALID_CONFIG 283

#define SSL_R_INVALID_CONFIGURATION_NAME 113

#define SSL_R_INVALID_CONTEXT 282

#define SSL_R_INVALID_CT_VALIDATION_TYPE 212

#define SSL_R_INVALID_KEY_UPDATE_TYPE 120

#define SSL_R_INVALID_MAX_EARLY_DATA 174

#define SSL_R_INVALID_NULL_CMD_NAME 385

#define SSL_R_INVALID_RAW_PUBLIC_KEY 350

#define SSL_R_INVALID_RECORD 317

#define SSL_R_INVALID_SEQUENCE_NUMBER 402

#define SSL_R_INVALID_SERVERINFO_DATA 388

#define SSL_R_INVALID_SESSION_ID 999

#define SSL_R_INVALID_SRP_USERNAME 357

#define SSL_R_INVALID_STATUS_RESPONSE 328

#define SSL_R_INVALID_TICKET_KEYS_LENGTH 325

#define SSL_R_LEGACY_SIGALG_DISALLOWED_OR_UNSUPPORTED 333

#define SSL_R_LENGTH_MISMATCH 159

#define SSL_R_LENGTH_TOO_LONG 404

#define SSL_R_LENGTH_TOO_SHORT 160

#define SSL_R_LIBRARY_BUG 274

#define SSL_R_LIBRARY_HAS_NO_CIPHERS 161

#define SSL_R_MAXIMUM_ENCRYPTED_PKTS_REACHED 395

#define SSL_R_MISSING_DSA_SIGNING_CERT 165

#define SSL_R_MISSING_ECDSA_SIGNING_CERT 381

#define SSL_R_MISSING_FATAL 256

#define SSL_R_MISSING_PARAMETERS 290

#define SSL_R_MISSING_PSK_KEX_MODES_EXTENSION 310

#define SSL_R_MISSING_RSA_CERTIFICATE 168

#define SSL_R_MISSING_RSA_ENCRYPTING_CERT 169

#define SSL_R_MISSING_RSA_SIGNING_CERT 170

#define SSL_R_MISSING_SIGALGS_EXTENSION 112

#define SSL_R_MISSING_SIGNING_CERT 221

#define SSL_R_MISSING_SRP_PARAM 358

#define SSL_R_MISSING_SUPPORTED_GROUPS_EXTENSION 209

#define SSL_R_MISSING_TMP_DH_KEY 171

#define SSL_R_MISSING_TMP_ECDH_KEY 311

#define SSL_R_MIXED_HANDSHAKE_AND_NON_HANDSHAKE_DATA 293

#define SSL_R_NOT_ON_RECORD_BOUNDARY 182

#define SSL_R_NOT_REPLACING_CERTIFICATE 289

#define SSL_R_NOT_SERVER 284

#define SSL_R_NO_APPLICATION_PROTOCOL 235

#define SSL_R_NO_CERTIFICATES_RETURNED 176

#define SSL_R_NO_CERTIFICATE_ASSIGNED 177

#define SSL_R_NO_CERTIFICATE_SET 179

#define SSL_R_NO_CHANGE_FOLLOWING_HRR 214

#define SSL_R_NO_CIPHERS_AVAILABLE 181

#define SSL_R_NO_CIPHERS_SPECIFIED 183

#define SSL_R_NO_CIPHER_MATCH 185

#define SSL_R_NO_CLIENT_CERT_METHOD 331

#define SSL_R_NO_COMPRESSION_SPECIFIED 187

#define SSL_R_NO_COOKIE_CALLBACK_SET 287

#define SSL_R_NO_GOST_CERTIFICATE_SENT_BY_PEER 330

#define SSL_R_NO_METHOD_SPECIFIED 188

#define SSL_R_NO_PEM_EXTENSIONS 389

#define SSL_R_NO_PRIVATE_KEY_ASSIGNED 190

#define SSL_R_NO_PROTOCOLS_AVAILABLE 191

#define SSL_R_NO_RENEGOTIATION 339

#define SSL_R_NO_REQUIRED_DIGEST 324

#define SSL_R_NO_SHARED_CIPHER 193

#define SSL_R_NO_SHARED_GROUPS 410

#define SSL_R_NO_SHARED_SIGNATURE_ALGORITHMS 376

#define SSL_R_NO_SRTP_PROFILES 359

#define SSL_R_NO_STREAM 355

#define SSL_R_NO_SUITABLE_DIGEST_ALGORITHM 297

#define SSL_R_NO_SUITABLE_GROUPS 295

#define SSL_R_NO_SUITABLE_KEY_SHARE 101

#define SSL_R_NO_SUITABLE_RECORD_LAYER 322

#define SSL_R_NO_SUITABLE_SIGNATURE_ALGORITHM 118

#define SSL_R_NO_VALID_SCTS 216

#define SSL_R_NO_VERIFY_COOKIE_CALLBACK 403

#define SSL_R_NULL_SSL_CTX 195

#define SSL_R_NULL_SSL_METHOD_PASSED 196

#define SSL_R_OCSP_CALLBACK_FAILURE 305

#define SSL_R_OLD_SESSION_CIPHER_NOT_RETURNED 197

#define SSL_R_OLD_SESSION_COMPRESSION_ALGORITHM_NOT_RETURNED 344

#define SSL_R_OVERFLOW_ERROR 237

#define SSL_R_PACKET_LENGTH_TOO_LONG 198

#define SSL_R_PARSE_TLSEXT 227

#define SSL_R_PATH_TOO_LONG 270

#define SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE 199

#define SSL_R_PEM_NAME_BAD_PREFIX 391

#define SSL_R_PEM_NAME_TOO_SHORT 392

#define SSL_R_PIPELINE_FAILURE 406

#define SSL_R_POLL_REQUEST_NOT_SUPPORTED 418

#define SSL_R_POST_HANDSHAKE_AUTH_ENCODING_ERR 278

#define SSL_R_PRIVATE_KEY_MISMATCH 288

#define SSL_R_PROTOCOL_IS_SHUTDOWN 207

#define SSL_R_PSK_IDENTITY_NOT_FOUND 223

#define SSL_R_PSK_NO_CLIENT_CB 224

#define SSL_R_PSK_NO_SERVER_CB 225

#define SSL_R_QUIC_HANDSHAKE_LAYER_ERROR 393

#define SSL_R_QUIC_NETWORK_ERROR 387

#define SSL_R_QUIC_PROTOCOL_ERROR 382

#define SSL_R_READ_BIO_NOT_SET 211

#define SSL_R_READ_TIMEOUT_EXPIRED 312

#define SSL_R_RECORDS_NOT_RELEASED 321

#define SSL_R_RECORD_LAYER_FAILURE 313

#define SSL_R_RECORD_LENGTH_MISMATCH 213

#define SSL_R_RECORD_TOO_SMALL 298

#define SSL_R_REMOTE_PEER_ADDRESS_NOT_SET 346

#define SSL_R_RENEGOTIATE_EXT_TOO_LONG 335

#define SSL_R_RENEGOTIATION_ENCODING_ERR 336

#define SSL_R_RENEGOTIATION_MISMATCH 337

#define SSL_R_REQUEST_PENDING 285

#define SSL_R_REQUEST_SENT 286

#define SSL_R_REQUIRED_CIPHER_MISSING 215

#define SSL_R_REQUIRED_COMPRESSION_ALGORITHM_MISSING 342

#define SSL_R_SCSV_RECEIVED_WHEN_RENEGOTIATING 345

#define SSL_R_SCT_VERIFICATION_FAILED 208

#define SSL_R_SEQUENCE_CTR_WRAPPED 327

#define SSL_R_SERVERHELLO_TLSEXT 275

#define SSL_R_SESSION_ID_CONTEXT_UNINITIALIZED 277

#define SSL_R_SHUTDOWN_WHILE_IN_INIT 407

#define SSL_R_SIGNATURE_ALGORITHMS_ERROR 360

#define SSL_R_SIGNATURE_FOR_NON_SIGNING_CERTIFICATE 220

#define SSL_R_SRP_A_CALC 361

#define SSL_R_SRTP_COULD_NOT_ALLOCATE_PROFILES 362

#define SSL_R_SRTP_PROTECTION_PROFILE_LIST_TOO_LONG 363

#define SSL_R_SRTP_UNKNOWN_PROTECTION_PROFILE 364

#define SSL_R_SSL3_EXT_INVALID_MAX_FRAGMENT_LENGTH 232

#define SSL_R_SSL3_EXT_INVALID_SERVERNAME 319

#define SSL_R_SSL3_EXT_INVALID_SERVERNAME_TYPE 320

#define SSL_R_SSL3_SESSION_ID_TOO_LONG 300

#define SSL_R_SSLV3_ALERT_BAD_CERTIFICATE 1042

#define SSL_R_SSLV3_ALERT_BAD_RECORD_MAC 1020

#define SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED 1045

#define SSL_R_SSLV3_ALERT_CERTIFICATE_REVOKED 1044

#define SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN 1046

#define SSL_R_SSLV3_ALERT_DECOMPRESSION_FAILURE 1030

#define SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE 1040

#define SSL_R_SSLV3_ALERT_ILLEGAL_PARAMETER 1047

#define SSL_R_SSLV3_ALERT_NO_CERTIFICATE 1041

#define SSL_R_SSLV3_ALERT_UNEXPECTED_MESSAGE 1010

#define SSL_R_SSLV3_ALERT_UNSUPPORTED_CERTIFICATE 1043

#define SSL_R_SSL_COMMAND_SECTION_EMPTY 117

#define SSL_R_SSL_COMMAND_SECTION_NOT_FOUND 125

#define SSL_R_SSL_CTX_HAS_NO_DEFAULT_SSL_VERSION 228

#define SSL_R_SSL_HANDSHAKE_FAILURE 229

#define SSL_R_SSL_LIBRARY_HAS_NO_CIPHERS 230

#define SSL_R_SSL_NEGATIVE_LENGTH 372

#define SSL_R_SSL_SECTION_EMPTY 126

#define SSL_R_SSL_SECTION_NOT_FOUND 136

#define SSL_R_SSL_SESSION_ID_CALLBACK_FAILED 301

#define SSL_R_SSL_SESSION_ID_CONFLICT 302

#define SSL_R_SSL_SESSION_ID_CONTEXT_TOO_LONG 273

#define SSL_R_SSL_SESSION_ID_HAS_BAD_LENGTH 303

#define SSL_R_SSL_SESSION_ID_TOO_LONG 408

#define SSL_R_SSL_SESSION_VERSION_MISMATCH 210

#define SSL_R_STILL_IN_INIT 121

#define SSL_R_STREAM_COUNT_LIMITED 411

#define SSL_R_STREAM_FINISHED 365

#define SSL_R_STREAM_RECV_ONLY 366

#define SSL_R_STREAM_RESET 375

#define SSL_R_STREAM_SEND_ONLY 379

#define SSL_R_TLSV13_ALERT_CERTIFICATE_REQUIRED 1116

#define SSL_R_TLSV13_ALERT_MISSING_EXTENSION 1109

#define SSL_R_TLSV1_ALERT_ACCESS_DENIED 1049

#define SSL_R_TLSV1_ALERT_DECODE_ERROR 1050

#define SSL_R_TLSV1_ALERT_DECRYPTION_FAILED 1021

#define SSL_R_TLSV1_ALERT_DECRYPT_ERROR 1051

#define SSL_R_TLSV1_ALERT_EXPORT_RESTRICTION 1060

#define SSL_R_TLSV1_ALERT_INAPPROPRIATE_FALLBACK 1086

#define SSL_R_TLSV1_ALERT_INSUFFICIENT_SECURITY 1071

#define SSL_R_TLSV1_ALERT_INTERNAL_ERROR 1080

#define SSL_R_TLSV1_ALERT_NO_RENEGOTIATION 1100

#define SSL_R_TLSV1_ALERT_PROTOCOL_VERSION 1070

#define SSL_R_TLSV1_ALERT_RECORD_OVERFLOW 1022

#define SSL_R_TLSV1_ALERT_UNKNOWN_CA 1048

#define SSL_R_TLSV1_ALERT_USER_CANCELLED 1090

#define SSL_R_TLSV1_BAD_CERTIFICATE_HASH_VALUE 1114

#define SSL_R_TLSV1_BAD_CERTIFICATE_STATUS_RESPONSE 1113

#define SSL_R_TLSV1_CERTIFICATE_UNOBTAINABLE 1111

#define SSL_R_TLSV1_UNRECOGNIZED_NAME 1112

#define SSL_R_TLSV1_UNSUPPORTED_EXTENSION 1110

#define SSL_R_TLS_ILLEGAL_EXPORTER_LABEL 367

#define SSL_R_TLS_INVALID_ECPOINTFORMAT_LIST 157

#define SSL_R_TOO_MANY_KEY_UPDATES 132

#define SSL_R_TOO_MANY_WARN_ALERTS 409

#define SSL_R_TOO_MUCH_EARLY_DATA 164

#define SSL_R_UNABLE_TO_FIND_ECDH_PARAMETERS 314

#define SSL_R_UNABLE_TO_FIND_PUBLIC_KEY_PARAMETERS 239

#define SSL_R_UNABLE_TO_LOAD_SSL3_MD5_ROUTINES 242

#define SSL_R_UNABLE_TO_LOAD_SSL3_SHA1_ROUTINES 243

#define SSL_R_UNEXPECTED_CCS_MESSAGE 262

#define SSL_R_UNEXPECTED_END_OF_EARLY_DATA 178

#define SSL_R_UNEXPECTED_EOF_WHILE_READING 294

#define SSL_R_UNEXPECTED_MESSAGE 244

#define SSL_R_UNEXPECTED_RECORD 245

#define SSL_R_UNINITIALIZED 276

#define SSL_R_UNKNOWN_ALERT_TYPE 246

#define SSL_R_UNKNOWN_CERTIFICATE_TYPE 247

#define SSL_R_UNKNOWN_CIPHER_RETURNED 248

#define SSL_R_UNKNOWN_CIPHER_TYPE 249

#define SSL_R_UNKNOWN_CMD_NAME 386

#define SSL_R_UNKNOWN_COMMAND 139

#define SSL_R_UNKNOWN_DIGEST 368

#define SSL_R_UNKNOWN_KEY_EXCHANGE_TYPE 250

#define SSL_R_UNKNOWN_MANDATORY_PARAMETER 323

#define SSL_R_UNKNOWN_PKEY_TYPE 251

#define SSL_R_UNKNOWN_PROTOCOL 252

#define SSL_R_UNKNOWN_SSL_VERSION 254

#define SSL_R_UNKNOWN_STATE 255

#define SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED 338

#define SSL_R_UNSOLICITED_EXTENSION 217

#define SSL_R_UNSUPPORTED_COMPRESSION_ALGORITHM 257

#define SSL_R_UNSUPPORTED_CONFIG_VALUE 414

#define SSL_R_UNSUPPORTED_CONFIG_VALUE_CLASS 415

#define SSL_R_UNSUPPORTED_CONFIG_VALUE_OP 416

#define SSL_R_UNSUPPORTED_ELLIPTIC_CURVE 315

#define SSL_R_UNSUPPORTED_PROTOCOL 258

#define SSL_R_UNSUPPORTED_SSL_VERSION 259

#define SSL_R_UNSUPPORTED_STATUS_TYPE 329

#define SSL_R_UNSUPPORTED_WRITE_FLAG 412

#define SSL_R_USE_SRTP_NOT_NEGOTIATED 369

#define SSL_R_VERSION_TOO_HIGH 166

#define SSL_R_VERSION_TOO_LOW 396

#define SSL_R_WRONG_CERTIFICATE_TYPE 383

#define SSL_R_WRONG_CIPHER_RETURNED 261

#define SSL_R_WRONG_CURVE 378

#define SSL_R_WRONG_RPK_TYPE 351

#define SSL_R_WRONG_SIGNATURE_LENGTH 264

#define SSL_R_WRONG_SIGNATURE_SIZE 265

#define SSL_R_WRONG_SIGNATURE_TYPE 370

#define SSL_R_WRONG_SSL_VERSION 266

#define SSL_R_WRONG_VERSION_NUMBER 267

#define SSL_R_X509_LIB 268

#define SSL_R_X509_VERIFICATION_SETUP_PROBLEMS 269

#define OPENSSL_SSLERR_LEGACY_H 

#define SSL_F_ADD_CLIENT_KEY_SHARE_EXT 0

#define SSL_F_ADD_KEY_SHARE 0

#define SSL_F_BYTES_TO_CIPHER_LIST 0

#define SSL_F_CHECK_SUITEB_CIPHER_LIST 0

#define SSL_F_CIPHERSUITE_CB 0

#define SSL_F_CONSTRUCT_CA_NAMES 0

#define SSL_F_CONSTRUCT_KEY_EXCHANGE_TBS 0

#define SSL_F_CONSTRUCT_STATEFUL_TICKET 0

#define SSL_F_CONSTRUCT_STATELESS_TICKET 0

#define SSL_F_CREATE_SYNTHETIC_MESSAGE_HASH 0

#define SSL_F_CREATE_TICKET_PREQUEL 0

#define SSL_F_CT_MOVE_SCTS 0

#define SSL_F_CT_STRICT 0

#define SSL_F_CUSTOM_EXT_ADD 0

#define SSL_F_CUSTOM_EXT_PARSE 0

#define SSL_F_D2I_SSL_SESSION 0

#define SSL_F_DANE_CTX_ENABLE 0

#define SSL_F_DANE_MTYPE_SET 0

#define SSL_F_DANE_TLSA_ADD 0

#define SSL_F_DERIVE_SECRET_KEY_AND_IV 0

#define SSL_F_DO_DTLS1_WRITE 0

#define SSL_F_DO_SSL3_WRITE 0

#define SSL_F_DTLS1_BUFFER_RECORD 0

#define SSL_F_DTLS1_CHECK_TIMEOUT_NUM 0

#define SSL_F_DTLS1_HEARTBEAT 0

#define SSL_F_DTLS1_HM_FRAGMENT_NEW 0

#define SSL_F_DTLS1_PREPROCESS_FRAGMENT 0

#define SSL_F_DTLS1_PROCESS_BUFFERED_RECORDS 0

#define SSL_F_DTLS1_PROCESS_RECORD 0

#define SSL_F_DTLS1_READ_BYTES 0

#define SSL_F_DTLS1_READ_FAILED 0

#define SSL_F_DTLS1_RETRANSMIT_MESSAGE 0

#define SSL_F_DTLS1_WRITE_APP_DATA_BYTES 0

#define SSL_F_DTLS1_WRITE_BYTES 0

#define SSL_F_DTLSV1_LISTEN 0

#define SSL_F_DTLS_CONSTRUCT_CHANGE_CIPHER_SPEC 0

#define SSL_F_DTLS_CONSTRUCT_HELLO_VERIFY_REQUEST 0

#define SSL_F_DTLS_GET_REASSEMBLED_MESSAGE 0

#define SSL_F_DTLS_PROCESS_HELLO_VERIFY 0

#define SSL_F_DTLS_RECORD_LAYER_NEW 0

#define SSL_F_DTLS_WAIT_FOR_DRY 0

#define SSL_F_EARLY_DATA_COUNT_OK 0

#define SSL_F_FINAL_EARLY_DATA 0

#define SSL_F_FINAL_EC_PT_FORMATS 0

#define SSL_F_FINAL_EMS 0

#define SSL_F_FINAL_KEY_SHARE 0

#define SSL_F_FINAL_MAXFRAGMENTLEN 0

#define SSL_F_FINAL_RENEGOTIATE 0

#define SSL_F_FINAL_SERVER_NAME 0

#define SSL_F_FINAL_SIG_ALGS 0

#define SSL_F_GET_CERT_VERIFY_TBS_DATA 0

#define SSL_F_NSS_KEYLOG_INT 0

#define SSL_F_OPENSSL_INIT_SSL 0

#define SSL_F_OSSL_STATEM_CLIENT13_READ_TRANSITION 0

#define SSL_F_OSSL_STATEM_CLIENT13_WRITE_TRANSITION 0

#define SSL_F_OSSL_STATEM_CLIENT_CONSTRUCT_MESSAGE 0

#define SSL_F_OSSL_STATEM_CLIENT_POST_PROCESS_MESSAGE 0

#define SSL_F_OSSL_STATEM_CLIENT_PROCESS_MESSAGE 0

#define SSL_F_OSSL_STATEM_CLIENT_READ_TRANSITION 0

#define SSL_F_OSSL_STATEM_CLIENT_WRITE_TRANSITION 0

#define SSL_F_OSSL_STATEM_SERVER13_READ_TRANSITION 0

#define SSL_F_OSSL_STATEM_SERVER13_WRITE_TRANSITION 0

#define SSL_F_OSSL_STATEM_SERVER_CONSTRUCT_MESSAGE 0

#define SSL_F_OSSL_STATEM_SERVER_POST_PROCESS_MESSAGE 0

#define SSL_F_OSSL_STATEM_SERVER_POST_WORK 0

#define SSL_F_OSSL_STATEM_SERVER_PRE_WORK 0

#define SSL_F_OSSL_STATEM_SERVER_PROCESS_MESSAGE 0

#define SSL_F_OSSL_STATEM_SERVER_READ_TRANSITION 0

#define SSL_F_OSSL_STATEM_SERVER_WRITE_TRANSITION 0

#define SSL_F_PARSE_CA_NAMES 0

#define SSL_F_PITEM_NEW 0

#define SSL_F_PQUEUE_NEW 0

#define SSL_F_PROCESS_KEY_SHARE_EXT 0

#define SSL_F_READ_STATE_MACHINE 0

#define SSL_F_SET_CLIENT_CIPHERSUITE 0

#define SSL_F_SRP_GENERATE_CLIENT_MASTER_SECRET 0

#define SSL_F_SRP_GENERATE_SERVER_MASTER_SECRET 0

#define SSL_F_SRP_VERIFY_SERVER_PARAM 0

#define SSL_F_SSL3_CHANGE_CIPHER_STATE 0

#define SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM 0

#define SSL_F_SSL3_CTRL 0

#define SSL_F_SSL3_CTX_CTRL 0

#define SSL_F_SSL3_DIGEST_CACHED_RECORDS 0

#define SSL_F_SSL3_DO_CHANGE_CIPHER_SPEC 0

#define SSL_F_SSL3_ENC 0

#define SSL_F_SSL3_FINAL_FINISH_MAC 0

#define SSL_F_SSL3_FINISH_MAC 0

#define SSL_F_SSL3_GENERATE_KEY_BLOCK 0

#define SSL_F_SSL3_GENERATE_MASTER_SECRET 0

#define SSL_F_SSL3_GET_RECORD 0

#define SSL_F_SSL3_INIT_FINISHED_MAC 0

#define SSL_F_SSL3_OUTPUT_CERT_CHAIN 0

#define SSL_F_SSL3_READ_BYTES 0

#define SSL_F_SSL3_READ_N 0

#define SSL_F_SSL3_SETUP_KEY_BLOCK 0

#define SSL_F_SSL3_SETUP_READ_BUFFER 0

#define SSL_F_SSL3_SETUP_WRITE_BUFFER 0

#define SSL_F_SSL3_WRITE_BYTES 0

#define SSL_F_SSL3_WRITE_PENDING 0

#define SSL_F_SSL_ADD_CERT_CHAIN 0

#define SSL_F_SSL_ADD_CERT_TO_BUF 0

#define SSL_F_SSL_ADD_CERT_TO_WPACKET 0

#define SSL_F_SSL_ADD_CLIENTHELLO_RENEGOTIATE_EXT 0

#define SSL_F_SSL_ADD_CLIENTHELLO_TLSEXT 0

#define SSL_F_SSL_ADD_CLIENTHELLO_USE_SRTP_EXT 0

#define SSL_F_SSL_ADD_DIR_CERT_SUBJECTS_TO_STACK 0

#define SSL_F_SSL_ADD_FILE_CERT_SUBJECTS_TO_STACK 0

#define SSL_F_SSL_ADD_SERVERHELLO_RENEGOTIATE_EXT 0

#define SSL_F_SSL_ADD_SERVERHELLO_TLSEXT 0

#define SSL_F_SSL_ADD_SERVERHELLO_USE_SRTP_EXT 0

#define SSL_F_SSL_BUILD_CERT_CHAIN 0

#define SSL_F_SSL_BYTES_TO_CIPHER_LIST 0

#define SSL_F_SSL_CACHE_CIPHERLIST 0

#define SSL_F_SSL_CERT_ADD0_CHAIN_CERT 0

#define SSL_F_SSL_CERT_DUP 0

#define SSL_F_SSL_CERT_NEW 0

#define SSL_F_SSL_CERT_SET0_CHAIN 0

#define SSL_F_SSL_CHECK_PRIVATE_KEY 0

#define SSL_F_SSL_CHECK_SERVERHELLO_TLSEXT 0

#define SSL_F_SSL_CHECK_SRP_EXT_CLIENTHELLO 0

#define SSL_F_SSL_CHECK_SRVR_ECC_CERT_AND_ALG 0

#define SSL_F_SSL_CHOOSE_CLIENT_VERSION 0

#define SSL_F_SSL_CIPHER_DESCRIPTION 0

#define SSL_F_SSL_CIPHER_LIST_TO_BYTES 0

#define SSL_F_SSL_CIPHER_PROCESS_RULESTR 0

#define SSL_F_SSL_CIPHER_STRENGTH_SORT 0

#define SSL_F_SSL_CLEAR 0

#define SSL_F_SSL_CLIENT_HELLO_GET1_EXTENSIONS_PRESENT 0

#define SSL_F_SSL_COMP_ADD_COMPRESSION_METHOD 0

#define SSL_F_SSL_CONF_CMD 0

#define SSL_F_SSL_CREATE_CIPHER_LIST 0

#define SSL_F_SSL_CTRL 0

#define SSL_F_SSL_CTX_CHECK_PRIVATE_KEY 0

#define SSL_F_SSL_CTX_ENABLE_CT 0

#define SSL_F_SSL_CTX_MAKE_PROFILES 0

#define SSL_F_SSL_CTX_NEW 0

#define SSL_F_SSL_CTX_SET_ALPN_PROTOS 0

#define SSL_F_SSL_CTX_SET_CIPHER_LIST 0

#define SSL_F_SSL_CTX_SET_CLIENT_CERT_ENGINE 0

#define SSL_F_SSL_CTX_SET_CT_VALIDATION_CALLBACK 0

#define SSL_F_SSL_CTX_SET_SESSION_ID_CONTEXT 0

#define SSL_F_SSL_CTX_SET_SSL_VERSION 0

#define SSL_F_SSL_CTX_SET_TLSEXT_MAX_FRAGMENT_LENGTH 0

#define SSL_F_SSL_CTX_USE_CERTIFICATE 0

#define SSL_F_SSL_CTX_USE_CERTIFICATE_ASN1 0

#define SSL_F_SSL_CTX_USE_CERTIFICATE_FILE 0

#define SSL_F_SSL_CTX_USE_PRIVATEKEY 0

#define SSL_F_SSL_CTX_USE_PRIVATEKEY_ASN1 0

#define SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE 0

#define SSL_F_SSL_CTX_USE_PSK_IDENTITY_HINT 0

#define SSL_F_SSL_CTX_USE_RSAPRIVATEKEY 0

#define SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_ASN1 0

#define SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_FILE 0

#define SSL_F_SSL_CTX_USE_SERVERINFO 0

#define SSL_F_SSL_CTX_USE_SERVERINFO_EX 0

#define SSL_F_SSL_CTX_USE_SERVERINFO_FILE 0

#define SSL_F_SSL_DANE_DUP 0

#define SSL_F_SSL_DANE_ENABLE 0

#define SSL_F_SSL_DERIVE 0

#define SSL_F_SSL_DO_CONFIG 0

#define SSL_F_SSL_DO_HANDSHAKE 0

#define SSL_F_SSL_DUP_CA_LIST 0

#define SSL_F_SSL_ENABLE_CT 0

#define SSL_F_SSL_GENERATE_PKEY_GROUP 0

#define SSL_F_SSL_GENERATE_SESSION_ID 0

#define SSL_F_SSL_GET_NEW_SESSION 0

#define SSL_F_SSL_GET_PREV_SESSION 0

#define SSL_F_SSL_GET_SERVER_CERT_INDEX 0

#define SSL_F_SSL_GET_SIGN_PKEY 0

#define SSL_F_SSL_HANDSHAKE_HASH 0

#define SSL_F_SSL_INIT_WBIO_BUFFER 0

#define SSL_F_SSL_KEY_UPDATE 0

#define SSL_F_SSL_LOAD_CLIENT_CA_FILE 0

#define SSL_F_SSL_LOG_MASTER_SECRET 0

#define SSL_F_SSL_LOG_RSA_CLIENT_KEY_EXCHANGE 0

#define SSL_F_SSL_MODULE_INIT 0

#define SSL_F_SSL_NEW 0

#define SSL_F_SSL_NEXT_PROTO_VALIDATE 0

#define SSL_F_SSL_PARSE_CLIENTHELLO_RENEGOTIATE_EXT 0

#define SSL_F_SSL_PARSE_CLIENTHELLO_TLSEXT 0

#define SSL_F_SSL_PARSE_CLIENTHELLO_USE_SRTP_EXT 0

#define SSL_F_SSL_PARSE_SERVERHELLO_RENEGOTIATE_EXT 0

#define SSL_F_SSL_PARSE_SERVERHELLO_TLSEXT 0

#define SSL_F_SSL_PARSE_SERVERHELLO_USE_SRTP_EXT 0

#define SSL_F_SSL_PEEK 0

#define SSL_F_SSL_PEEK_EX 0

#define SSL_F_SSL_PEEK_INTERNAL 0

#define SSL_F_SSL_READ 0

#define SSL_F_SSL_READ_EARLY_DATA 0

#define SSL_F_SSL_READ_EX 0

#define SSL_F_SSL_READ_INTERNAL 0

#define SSL_F_SSL_RENEGOTIATE 0

#define SSL_F_SSL_RENEGOTIATE_ABBREVIATED 0

#define SSL_F_SSL_SCAN_CLIENTHELLO_TLSEXT 0

#define SSL_F_SSL_SCAN_SERVERHELLO_TLSEXT 0

#define SSL_F_SSL_SESSION_DUP 0

#define SSL_F_SSL_SESSION_NEW 0

#define SSL_F_SSL_SESSION_PRINT_FP 0

#define SSL_F_SSL_SESSION_SET1_ID 0

#define SSL_F_SSL_SESSION_SET1_ID_CONTEXT 0

#define SSL_F_SSL_SET_ALPN_PROTOS 0

#define SSL_F_SSL_SET_CERT 0

#define SSL_F_SSL_SET_CERT_AND_KEY 0

#define SSL_F_SSL_SET_CIPHER_LIST 0

#define SSL_F_SSL_SET_CT_VALIDATION_CALLBACK 0

#define SSL_F_SSL_SET_FD 0

#define SSL_F_SSL_SET_PKEY 0

#define SSL_F_SSL_SET_RFD 0

#define SSL_F_SSL_SET_SESSION 0

#define SSL_F_SSL_SET_SESSION_ID_CONTEXT 0

#define SSL_F_SSL_SET_SESSION_TICKET_EXT 0

#define SSL_F_SSL_SET_TLSEXT_MAX_FRAGMENT_LENGTH 0

#define SSL_F_SSL_SET_WFD 0

#define SSL_F_SSL_SHUTDOWN 0

#define SSL_F_SSL_SRP_CTX_INIT 0

#define SSL_F_SSL_START_ASYNC_JOB 0

#define SSL_F_SSL_UNDEFINED_FUNCTION 0

#define SSL_F_SSL_UNDEFINED_VOID_FUNCTION 0

#define SSL_F_SSL_USE_CERTIFICATE 0

#define SSL_F_SSL_USE_CERTIFICATE_ASN1 0

#define SSL_F_SSL_USE_CERTIFICATE_FILE 0

#define SSL_F_SSL_USE_PRIVATEKEY 0

#define SSL_F_SSL_USE_PRIVATEKEY_ASN1 0

#define SSL_F_SSL_USE_PRIVATEKEY_FILE 0

#define SSL_F_SSL_USE_PSK_IDENTITY_HINT 0

#define SSL_F_SSL_USE_RSAPRIVATEKEY 0

#define SSL_F_SSL_USE_RSAPRIVATEKEY_ASN1 0

#define SSL_F_SSL_USE_RSAPRIVATEKEY_FILE 0

#define SSL_F_SSL_VALIDATE_CT 0

#define SSL_F_SSL_VERIFY_CERT_CHAIN 0

#define SSL_F_SSL_VERIFY_CLIENT_POST_HANDSHAKE 0

#define SSL_F_SSL_WRITE 0

#define SSL_F_SSL_WRITE_EARLY_DATA 0

#define SSL_F_SSL_WRITE_EARLY_FINISH 0

#define SSL_F_SSL_WRITE_EX 0

#define SSL_F_SSL_WRITE_INTERNAL 0

#define SSL_F_STATE_MACHINE 0

#define SSL_F_TLS12_CHECK_PEER_SIGALG 0

#define SSL_F_TLS12_COPY_SIGALGS 0

#define SSL_F_TLS13_CHANGE_CIPHER_STATE 0

#define SSL_F_TLS13_ENC 0

#define SSL_F_TLS13_FINAL_FINISH_MAC 0

#define SSL_F_TLS13_GENERATE_SECRET 0

#define SSL_F_TLS13_HKDF_EXPAND 0

#define SSL_F_TLS13_RESTORE_HANDSHAKE_DIGEST_FOR_PHA 0

#define SSL_F_TLS13_SAVE_HANDSHAKE_DIGEST_FOR_PHA 0

#define SSL_F_TLS13_SETUP_KEY_BLOCK 0

#define SSL_F_TLS1_CHANGE_CIPHER_STATE 0

#define SSL_F_TLS1_CHECK_DUPLICATE_EXTENSIONS 0

#define SSL_F_TLS1_ENC 0

#define SSL_F_TLS1_EXPORT_KEYING_MATERIAL 0

#define SSL_F_TLS1_GET_CURVELIST 0

#define SSL_F_TLS1_PRF 0

#define SSL_F_TLS1_SAVE_U16 0

#define SSL_F_TLS1_SETUP_KEY_BLOCK 0

#define SSL_F_TLS1_SET_GROUPS 0

#define SSL_F_TLS1_SET_RAW_SIGALGS 0

#define SSL_F_TLS1_SET_SERVER_SIGALGS 0

#define SSL_F_TLS1_SET_SHARED_SIGALGS 0

#define SSL_F_TLS1_SET_SIGALGS 0

#define SSL_F_TLS_CHOOSE_SIGALG 0

#define SSL_F_TLS_CLIENT_KEY_EXCHANGE_POST_WORK 0

#define SSL_F_TLS_COLLECT_EXTENSIONS 0

#define SSL_F_TLS_CONSTRUCT_CERTIFICATE_AUTHORITIES 0

#define SSL_F_TLS_CONSTRUCT_CERTIFICATE_REQUEST 0

#define SSL_F_TLS_CONSTRUCT_CERT_STATUS 0

#define SSL_F_TLS_CONSTRUCT_CERT_STATUS_BODY 0

#define SSL_F_TLS_CONSTRUCT_CERT_VERIFY 0

#define SSL_F_TLS_CONSTRUCT_CHANGE_CIPHER_SPEC 0

#define SSL_F_TLS_CONSTRUCT_CKE_DHE 0

#define SSL_F_TLS_CONSTRUCT_CKE_ECDHE 0

#define SSL_F_TLS_CONSTRUCT_CKE_GOST 0

#define SSL_F_TLS_CONSTRUCT_CKE_PSK_PREAMBLE 0

#define SSL_F_TLS_CONSTRUCT_CKE_RSA 0

#define SSL_F_TLS_CONSTRUCT_CKE_SRP 0

#define SSL_F_TLS_CONSTRUCT_CLIENT_CERTIFICATE 0

#define SSL_F_TLS_CONSTRUCT_CLIENT_HELLO 0

#define SSL_F_TLS_CONSTRUCT_CLIENT_KEY_EXCHANGE 0

#define SSL_F_TLS_CONSTRUCT_CLIENT_VERIFY 0

#define SSL_F_TLS_CONSTRUCT_CTOS_ALPN 0

#define SSL_F_TLS_CONSTRUCT_CTOS_CERTIFICATE 0

#define SSL_F_TLS_CONSTRUCT_CTOS_COOKIE 0

#define SSL_F_TLS_CONSTRUCT_CTOS_EARLY_DATA 0

#define SSL_F_TLS_CONSTRUCT_CTOS_EC_PT_FORMATS 0

#define SSL_F_TLS_CONSTRUCT_CTOS_EMS 0

#define SSL_F_TLS_CONSTRUCT_CTOS_ETM 0

#define SSL_F_TLS_CONSTRUCT_CTOS_HELLO 0

#define SSL_F_TLS_CONSTRUCT_CTOS_KEY_EXCHANGE 0

#define SSL_F_TLS_CONSTRUCT_CTOS_KEY_SHARE 0

#define SSL_F_TLS_CONSTRUCT_CTOS_MAXFRAGMENTLEN 0

#define SSL_F_TLS_CONSTRUCT_CTOS_NPN 0

#define SSL_F_TLS_CONSTRUCT_CTOS_PADDING 0

#define SSL_F_TLS_CONSTRUCT_CTOS_POST_HANDSHAKE_AUTH 0

#define SSL_F_TLS_CONSTRUCT_CTOS_PSK 0

#define SSL_F_TLS_CONSTRUCT_CTOS_PSK_KEX_MODES 0

#define SSL_F_TLS_CONSTRUCT_CTOS_RENEGOTIATE 0

#define SSL_F_TLS_CONSTRUCT_CTOS_SCT 0

#define SSL_F_TLS_CONSTRUCT_CTOS_SERVER_NAME 0

#define SSL_F_TLS_CONSTRUCT_CTOS_SESSION_TICKET 0

#define SSL_F_TLS_CONSTRUCT_CTOS_SIG_ALGS 0

#define SSL_F_TLS_CONSTRUCT_CTOS_SRP 0

#define SSL_F_TLS_CONSTRUCT_CTOS_STATUS_REQUEST 0

#define SSL_F_TLS_CONSTRUCT_CTOS_SUPPORTED_GROUPS 0

#define SSL_F_TLS_CONSTRUCT_CTOS_SUPPORTED_VERSIONS 0

#define SSL_F_TLS_CONSTRUCT_CTOS_USE_SRTP 0

#define SSL_F_TLS_CONSTRUCT_CTOS_VERIFY 0

#define SSL_F_TLS_CONSTRUCT_ENCRYPTED_EXTENSIONS 0

#define SSL_F_TLS_CONSTRUCT_END_OF_EARLY_DATA 0

#define SSL_F_TLS_CONSTRUCT_EXTENSIONS 0

#define SSL_F_TLS_CONSTRUCT_FINISHED 0

#define SSL_F_TLS_CONSTRUCT_HELLO_REQUEST 0

#define SSL_F_TLS_CONSTRUCT_HELLO_RETRY_REQUEST 0

#define SSL_F_TLS_CONSTRUCT_KEY_UPDATE 0

#define SSL_F_TLS_CONSTRUCT_NEW_SESSION_TICKET 0

#define SSL_F_TLS_CONSTRUCT_NEXT_PROTO 0

#define SSL_F_TLS_CONSTRUCT_SERVER_CERTIFICATE 0

#define SSL_F_TLS_CONSTRUCT_SERVER_HELLO 0

#define SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE 0

#define SSL_F_TLS_CONSTRUCT_STOC_ALPN 0

#define SSL_F_TLS_CONSTRUCT_STOC_CERTIFICATE 0

#define SSL_F_TLS_CONSTRUCT_STOC_COOKIE 0

#define SSL_F_TLS_CONSTRUCT_STOC_CRYPTOPRO_BUG 0

#define SSL_F_TLS_CONSTRUCT_STOC_DONE 0

#define SSL_F_TLS_CONSTRUCT_STOC_EARLY_DATA 0

#define SSL_F_TLS_CONSTRUCT_STOC_EARLY_DATA_INFO 0

#define SSL_F_TLS_CONSTRUCT_STOC_EC_PT_FORMATS 0

#define SSL_F_TLS_CONSTRUCT_STOC_EMS 0

#define SSL_F_TLS_CONSTRUCT_STOC_ETM 0

#define SSL_F_TLS_CONSTRUCT_STOC_HELLO 0

#define SSL_F_TLS_CONSTRUCT_STOC_KEY_EXCHANGE 0

#define SSL_F_TLS_CONSTRUCT_STOC_KEY_SHARE 0

#define SSL_F_TLS_CONSTRUCT_STOC_MAXFRAGMENTLEN 0

#define SSL_F_TLS_CONSTRUCT_STOC_NEXT_PROTO_NEG 0

#define SSL_F_TLS_CONSTRUCT_STOC_PSK 0

#define SSL_F_TLS_CONSTRUCT_STOC_RENEGOTIATE 0

#define SSL_F_TLS_CONSTRUCT_STOC_SERVER_NAME 0

#define SSL_F_TLS_CONSTRUCT_STOC_SESSION_TICKET 0

#define SSL_F_TLS_CONSTRUCT_STOC_STATUS_REQUEST 0

#define SSL_F_TLS_CONSTRUCT_STOC_SUPPORTED_GROUPS 0

#define SSL_F_TLS_CONSTRUCT_STOC_SUPPORTED_VERSIONS 0

#define SSL_F_TLS_CONSTRUCT_STOC_USE_SRTP 0

#define SSL_F_TLS_EARLY_POST_PROCESS_CLIENT_HELLO 0

#define SSL_F_TLS_FINISH_HANDSHAKE 0

#define SSL_F_TLS_GET_MESSAGE_BODY 0

#define SSL_F_TLS_GET_MESSAGE_HEADER 0

#define SSL_F_TLS_HANDLE_ALPN 0

#define SSL_F_TLS_HANDLE_STATUS_REQUEST 0

#define SSL_F_TLS_PARSE_CERTIFICATE_AUTHORITIES 0

#define SSL_F_TLS_PARSE_CLIENTHELLO_TLSEXT 0

#define SSL_F_TLS_PARSE_CTOS_ALPN 0

#define SSL_F_TLS_PARSE_CTOS_COOKIE 0

#define SSL_F_TLS_PARSE_CTOS_EARLY_DATA 0

#define SSL_F_TLS_PARSE_CTOS_EC_PT_FORMATS 0

#define SSL_F_TLS_PARSE_CTOS_EMS 0

#define SSL_F_TLS_PARSE_CTOS_KEY_SHARE 0

#define SSL_F_TLS_PARSE_CTOS_MAXFRAGMENTLEN 0

#define SSL_F_TLS_PARSE_CTOS_POST_HANDSHAKE_AUTH 0

#define SSL_F_TLS_PARSE_CTOS_PSK 0

#define SSL_F_TLS_PARSE_CTOS_PSK_KEX_MODES 0

#define SSL_F_TLS_PARSE_CTOS_RENEGOTIATE 0

#define SSL_F_TLS_PARSE_CTOS_SERVER_NAME 0

#define SSL_F_TLS_PARSE_CTOS_SESSION_TICKET 0

#define SSL_F_TLS_PARSE_CTOS_SIG_ALGS 0

#define SSL_F_TLS_PARSE_CTOS_SIG_ALGS_CERT 0

#define SSL_F_TLS_PARSE_CTOS_SRP 0

#define SSL_F_TLS_PARSE_CTOS_STATUS_REQUEST 0

#define SSL_F_TLS_PARSE_CTOS_SUPPORTED_GROUPS 0

#define SSL_F_TLS_PARSE_CTOS_USE_SRTP 0

#define SSL_F_TLS_PARSE_STOC_ALPN 0

#define SSL_F_TLS_PARSE_STOC_COOKIE 0

#define SSL_F_TLS_PARSE_STOC_EARLY_DATA 0

#define SSL_F_TLS_PARSE_STOC_EARLY_DATA_INFO 0

#define SSL_F_TLS_PARSE_STOC_EC_PT_FORMATS 0

#define SSL_F_TLS_PARSE_STOC_KEY_SHARE 0

#define SSL_F_TLS_PARSE_STOC_MAXFRAGMENTLEN 0

#define SSL_F_TLS_PARSE_STOC_NPN 0

#define SSL_F_TLS_PARSE_STOC_PSK 0

#define SSL_F_TLS_PARSE_STOC_RENEGOTIATE 0

#define SSL_F_TLS_PARSE_STOC_SCT 0

#define SSL_F_TLS_PARSE_STOC_SERVER_NAME 0

#define SSL_F_TLS_PARSE_STOC_SESSION_TICKET 0

#define SSL_F_TLS_PARSE_STOC_STATUS_REQUEST 0

#define SSL_F_TLS_PARSE_STOC_SUPPORTED_VERSIONS 0

#define SSL_F_TLS_PARSE_STOC_USE_SRTP 0

#define SSL_F_TLS_POST_PROCESS_CLIENT_HELLO 0

#define SSL_F_TLS_POST_PROCESS_CLIENT_KEY_EXCHANGE 0

#define SSL_F_TLS_PREPARE_CLIENT_CERTIFICATE 0

#define SSL_F_TLS_PROCESS_AS_HELLO_RETRY_REQUEST 0

#define SSL_F_TLS_PROCESS_CERTIFICATE_REQUEST 0

#define SSL_F_TLS_PROCESS_CERT_STATUS 0

#define SSL_F_TLS_PROCESS_CERT_STATUS_BODY 0

#define SSL_F_TLS_PROCESS_CERT_VERIFY 0

#define SSL_F_TLS_PROCESS_CHANGE_CIPHER_SPEC 0

#define SSL_F_TLS_PROCESS_CKE_DHE 0

#define SSL_F_TLS_PROCESS_CKE_ECDHE 0

#define SSL_F_TLS_PROCESS_CKE_GOST 0

#define SSL_F_TLS_PROCESS_CKE_PSK_PREAMBLE 0

#define SSL_F_TLS_PROCESS_CKE_RSA 0

#define SSL_F_TLS_PROCESS_CKE_SRP 0

#define SSL_F_TLS_PROCESS_CLIENT_CERTIFICATE 0

#define SSL_F_TLS_PROCESS_CLIENT_HELLO 0

#define SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE 0

#define SSL_F_TLS_PROCESS_ENCRYPTED_EXTENSIONS 0

#define SSL_F_TLS_PROCESS_END_OF_EARLY_DATA 0

#define SSL_F_TLS_PROCESS_FINISHED 0

#define SSL_F_TLS_PROCESS_HELLO_REQ 0

#define SSL_F_TLS_PROCESS_HELLO_RETRY_REQUEST 0

#define SSL_F_TLS_PROCESS_INITIAL_SERVER_FLIGHT 0

#define SSL_F_TLS_PROCESS_KEY_EXCHANGE 0

#define SSL_F_TLS_PROCESS_KEY_UPDATE 0

#define SSL_F_TLS_PROCESS_NEW_SESSION_TICKET 0

#define SSL_F_TLS_PROCESS_NEXT_PROTO 0

#define SSL_F_TLS_PROCESS_SERVER_CERTIFICATE 0

#define SSL_F_TLS_PROCESS_SERVER_DONE 0

#define SSL_F_TLS_PROCESS_SERVER_HELLO 0

#define SSL_F_TLS_PROCESS_SKE_DHE 0

#define SSL_F_TLS_PROCESS_SKE_ECDHE 0

#define SSL_F_TLS_PROCESS_SKE_PSK_PREAMBLE 0

#define SSL_F_TLS_PROCESS_SKE_SRP 0

#define SSL_F_TLS_PSK_DO_BINDER 0

#define SSL_F_TLS_SCAN_CLIENTHELLO_TLSEXT 0

#define SSL_F_TLS_SETUP_HANDSHAKE 0

#define SSL_F_USE_CERTIFICATE_CHAIN_FILE 0

#define SSL_F_WPACKET_INTERN_INIT_LEN 0

#define SSL_F_WPACKET_START_SUB_PACKET_LEN__ 0

#define SSL_F_WRITE_STATE_MACHINE 0

#define OPENSSL_STACK_H 

#define HEADER_STACK_H 

#define _STACK OPENSSL_STACK

#define sk_num OPENSSL_sk_num

#define sk_value OPENSSL_sk_value

#define sk_set OPENSSL_sk_set

#define sk_new OPENSSL_sk_new

#define sk_new_null OPENSSL_sk_new_null

#define sk_free OPENSSL_sk_free

#define sk_pop_free OPENSSL_sk_pop_free

#define sk_deep_copy OPENSSL_sk_deep_copy

#define sk_insert OPENSSL_sk_insert

#define sk_delete OPENSSL_sk_delete

#define sk_delete_ptr OPENSSL_sk_delete_ptr

#define sk_find OPENSSL_sk_find

#define sk_find_ex OPENSSL_sk_find_ex

#define sk_push OPENSSL_sk_push

#define sk_unshift OPENSSL_sk_unshift

#define sk_shift OPENSSL_sk_shift

#define sk_pop OPENSSL_sk_pop

#define sk_zero OPENSSL_sk_zero

#define sk_set_cmp_func OPENSSL_sk_set_cmp_func

#define sk_dup OPENSSL_sk_dup

#define sk_sort OPENSSL_sk_sort

#define sk_is_sorted OPENSSL_sk_is_sorted

#define OPENSSL_STORE_H 

#define HEADER_OSSL_STORE_H 

#define OSSL_STORE_C_USE_SECMEM 1

#define OSSL_STORE_C_CUSTOM_START 100

#define OSSL_STORE_INFO_NAME 1

#define OSSL_STORE_INFO_PARAMS 2

#define OSSL_STORE_INFO_PUBKEY 3

#define OSSL_STORE_INFO_PKEY 4

#define OSSL_STORE_INFO_CERT 5

#define OSSL_STORE_INFO_CRL 6

#define OSSL_STORE_SEARCH_BY_NAME 1

#define OSSL_STORE_SEARCH_BY_ISSUER_SERIAL 2

#define OSSL_STORE_SEARCH_BY_KEY_FINGERPRINT 3

#define OSSL_STORE_SEARCH_BY_ALIAS 4

#define OPENSSL_STOREERR_H 

#define OSSL_STORE_R_AMBIGUOUS_CONTENT_TYPE 107

#define OSSL_STORE_R_BAD_PASSWORD_READ 115

#define OSSL_STORE_R_ERROR_VERIFYING_PKCS12_MAC 113

#define OSSL_STORE_R_FINGERPRINT_SIZE_DOES_NOT_MATCH_DIGEST 121

#define OSSL_STORE_R_INVALID_SCHEME 106

#define OSSL_STORE_R_IS_NOT_A 112

#define OSSL_STORE_R_LOADER_INCOMPLETE 116

#define OSSL_STORE_R_LOADING_STARTED 117

#define OSSL_STORE_R_NOT_A_CERTIFICATE 100

#define OSSL_STORE_R_NOT_A_CRL 101

#define OSSL_STORE_R_NOT_A_NAME 103

#define OSSL_STORE_R_NOT_A_PRIVATE_KEY 102

#define OSSL_STORE_R_NOT_A_PUBLIC_KEY 122

#define OSSL_STORE_R_NOT_PARAMETERS 104

#define OSSL_STORE_R_NO_LOADERS_FOUND 123

#define OSSL_STORE_R_PASSPHRASE_CALLBACK_ERROR 114

#define OSSL_STORE_R_PATH_MUST_BE_ABSOLUTE 108

#define OSSL_STORE_R_SEARCH_ONLY_SUPPORTED_FOR_DIRECTORIES 119

#define OSSL_STORE_R_UI_PROCESS_INTERRUPTED_OR_CANCELLED 109

#define OSSL_STORE_R_UNREGISTERED_SCHEME 105

#define OSSL_STORE_R_UNSUPPORTED_CONTENT_TYPE 110

#define OSSL_STORE_R_UNSUPPORTED_OPERATION 118

#define OSSL_STORE_R_UNSUPPORTED_SEARCH_TYPE 120

#define OSSL_STORE_R_URI_AUTHORITY_UNSUPPORTED 111

#define OPENSSL_SYMHACKS_H 

#define HEADER_SYMHACKS_H 

#define ERR_load_CRYPTO_strings ERR_load_CRYPTOlib_strings

#define OCSP_crlID_new OCSP_crlID2_new

#define d2i_ECPARAMETERS d2i_UC_ECPARAMETERS

#define i2d_ECPARAMETERS i2d_UC_ECPARAMETERS

#define d2i_ECPKPARAMETERS d2i_UC_ECPKPARAMETERS

#define i2d_ECPKPARAMETERS i2d_UC_ECPKPARAMETERS

#define OPENSSL_THREAD_H 

#define OSSL_THREAD_SUPPORT_FLAG_THREAD_POOL (1U<<0)

#define OSSL_THREAD_SUPPORT_FLAG_DEFAULT_SPAWN (1U<<1)

#define OPENSSL_TLS1_H 

#define HEADER_TLS1_H 

#define OPENSSL_TLS_SECURITY_LEVEL 2

#define TLS_MAX_VERSION TLS1_3_VERSION

#define TLS_ANY_VERSION 0x10000

#define TLS1_VERSION_MAJOR 0x03

#define TLS1_VERSION_MINOR 0x01

#define TLS1_1_VERSION_MAJOR 0x03

#define TLS1_1_VERSION_MINOR 0x02

#define TLS1_2_VERSION_MAJOR 0x03

#define TLS1_2_VERSION_MINOR 0x03

#define TLS1_get_version (s)\
	((SSL_version(s) >> 8) == TLS1_VERSION_MAJOR ? SSL_version(s) : 0)

#define TLS1_get_client_version (s)\
	((SSL_client_version(s) >> 8) == TLS1_VERSION_MAJOR ? SSL_client_version(s) : 0)

#define TLS1_AD_DECRYPTION_FAILED 21

#define TLS1_AD_RECORD_OVERFLOW 22

#define TLS1_AD_UNKNOWN_CA 48

#define TLS1_AD_ACCESS_DENIED 49

#define TLS1_AD_DECODE_ERROR 50

#define TLS1_AD_DECRYPT_ERROR 51

#define TLS1_AD_EXPORT_RESTRICTION 60

#define TLS1_AD_PROTOCOL_VERSION 70

#define TLS1_AD_INSUFFICIENT_SECURITY 71

#define TLS1_AD_INTERNAL_ERROR 80

#define TLS1_AD_INAPPROPRIATE_FALLBACK 86

#define TLS1_AD_USER_CANCELLED 90

#define TLS1_AD_NO_RENEGOTIATION 100

#define TLS13_AD_MISSING_EXTENSION 109

#define TLS13_AD_CERTIFICATE_REQUIRED 116

#define TLS1_AD_UNSUPPORTED_EXTENSION 110

#define TLS1_AD_CERTIFICATE_UNOBTAINABLE 111

#define TLS1_AD_UNRECOGNIZED_NAME 112

#define TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE 113

#define TLS1_AD_BAD_CERTIFICATE_HASH_VALUE 114

#define TLS1_AD_UNKNOWN_PSK_IDENTITY 115

#define TLS1_AD_NO_APPLICATION_PROTOCOL 120

#define TLSEXT_TYPE_server_name 0

#define TLSEXT_TYPE_max_fragment_length 1

#define TLSEXT_TYPE_client_certificate_url 2

#define TLSEXT_TYPE_trusted_ca_keys 3

#define TLSEXT_TYPE_truncated_hmac 4

#define TLSEXT_TYPE_status_request 5

#define TLSEXT_TYPE_user_mapping 6

#define TLSEXT_TYPE_client_authz 7

#define TLSEXT_TYPE_server_authz 8

#define TLSEXT_TYPE_cert_type 9

#define TLSEXT_TYPE_supported_groups 10

#define TLSEXT_TYPE_elliptic_curves TLSEXT_TYPE_supported_groups

#define TLSEXT_TYPE_ec_point_formats 11

#define TLSEXT_TYPE_srp 12

#define TLSEXT_TYPE_signature_algorithms 13

#define TLSEXT_TYPE_use_srtp 14

#define TLSEXT_TYPE_application_layer_protocol_negotiation 16

#define TLSEXT_TYPE_signed_certificate_timestamp 18

#define TLSEXT_TYPE_client_cert_type 19

#define TLSEXT_TYPE_server_cert_type 20

#define TLSEXT_TYPE_padding 21

#define TLSEXT_TYPE_encrypt_then_mac 22

#define TLSEXT_TYPE_extended_master_secret 23

#define TLSEXT_TYPE_compress_certificate 27

#define TLSEXT_TYPE_session_ticket 35

#define TLSEXT_TYPE_psk 41

#define TLSEXT_TYPE_early_data 42

#define TLSEXT_TYPE_supported_versions 43

#define TLSEXT_TYPE_cookie 44

#define TLSEXT_TYPE_psk_kex_modes 45

#define TLSEXT_TYPE_certificate_authorities 47

#define TLSEXT_TYPE_post_handshake_auth 49

#define TLSEXT_TYPE_signature_algorithms_cert 50

#define TLSEXT_TYPE_key_share 51

#define TLSEXT_TYPE_quic_transport_parameters 57

#define TLSEXT_TYPE_renegotiate 0xff01

#define TLSEXT_TYPE_next_proto_neg 13172

#define TLSEXT_NAMETYPE_host_name 0

#define TLSEXT_STATUSTYPE_ocsp 1

#define TLSEXT_ECPOINTFORMAT_first 0

#define TLSEXT_ECPOINTFORMAT_uncompressed 0

#define TLSEXT_ECPOINTFORMAT_ansiX962_compressed_prime 1

#define TLSEXT_ECPOINTFORMAT_ansiX962_compressed_char2 2

#define TLSEXT_ECPOINTFORMAT_last 2

#define TLSEXT_signature_anonymous 0

#define TLSEXT_signature_rsa 1

#define TLSEXT_signature_dsa 2

#define TLSEXT_signature_ecdsa 3

#define TLSEXT_signature_gostr34102001 237

#define TLSEXT_signature_gostr34102012_256 238

#define TLSEXT_signature_gostr34102012_512 239

#define TLSEXT_signature_num 7

#define TLSEXT_hash_none 0

#define TLSEXT_hash_md5 1

#define TLSEXT_hash_sha1 2

#define TLSEXT_hash_sha224 3

#define TLSEXT_hash_sha256 4

#define TLSEXT_hash_sha384 5

#define TLSEXT_hash_sha512 6

#define TLSEXT_hash_gostr3411 237

#define TLSEXT_hash_gostr34112012_256 238

#define TLSEXT_hash_gostr34112012_512 239

#define TLSEXT_hash_num 10

#define TLSEXT_comp_cert_none 0

#define TLSEXT_comp_cert_zlib 1

#define TLSEXT_comp_cert_brotli 2

#define TLSEXT_comp_cert_zstd 3

#define TLSEXT_comp_cert_limit 4

#define TLSEXT_nid_unknown 0x1000000

#define TLSEXT_curve_P_256 23

#define TLSEXT_curve_P_384 24

#define TLSEXT_max_fragment_length_DISABLED 0

#define TLSEXT_max_fragment_length_512 1

#define TLSEXT_max_fragment_length_1024 2

#define TLSEXT_max_fragment_length_2048 3

#define TLSEXT_max_fragment_length_4096 4

#define TLSEXT_cert_type_x509 0

#define TLSEXT_cert_type_pgp 1

#define TLSEXT_cert_type_rpk 2

#define TLSEXT_cert_type_1609dot2 3

#define TLSEXT_MAXLEN_host_name 255

#define SSL_set_tlsext_host_name (s,name)\
	SSL_ctrl(s,SSL_CTRL_SET_TLSEXT_HOSTNAME,TLSEXT_NAMETYPE_host_name,\\
	(void *)name)

#define SSL_set_tlsext_debug_callback (ssl, cb)\
	SSL_callback_ctrl(ssl,SSL_CTRL_SET_TLSEXT_DEBUG_CB,\\
	(void (*)(void))cb)

#define SSL_set_tlsext_debug_arg (ssl, arg)\
	SSL_ctrl(ssl,SSL_CTRL_SET_TLSEXT_DEBUG_ARG,0,arg)

#define SSL_get_tlsext_status_type (ssl)\
	SSL_ctrl(ssl,SSL_CTRL_GET_TLSEXT_STATUS_REQ_TYPE,0,NULL)

#define SSL_set_tlsext_status_type (ssl, type)\
	SSL_ctrl(ssl,SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE,type,NULL)

#define SSL_get_tlsext_status_exts (ssl, arg)\
	SSL_ctrl(ssl,SSL_CTRL_GET_TLSEXT_STATUS_REQ_EXTS,0,arg)

#define SSL_set_tlsext_status_exts (ssl, arg)\
	SSL_ctrl(ssl,SSL_CTRL_SET_TLSEXT_STATUS_REQ_EXTS,0,arg)

#define SSL_get_tlsext_status_ids (ssl, arg)\
	SSL_ctrl(ssl,SSL_CTRL_GET_TLSEXT_STATUS_REQ_IDS,0,arg)

#define SSL_set_tlsext_status_ids (ssl, arg)\
	SSL_ctrl(ssl,SSL_CTRL_SET_TLSEXT_STATUS_REQ_IDS,0,arg)

#define SSL_get_tlsext_status_ocsp_resp (ssl, arg)\
	SSL_ctrl(ssl,SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP,0,arg)

#define SSL_set_tlsext_status_ocsp_resp (ssl, arg, arglen)\
	SSL_ctrl(ssl,SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP,arglen,arg)

#define SSL_CTX_set_tlsext_servername_callback (ctx, cb)\
	SSL_CTX_callback_ctrl(ctx,SSL_CTRL_SET_TLSEXT_SERVERNAME_CB,\\
	(void (*)(void))cb)

#define SSL_TLSEXT_ERR_OK 0

#define SSL_TLSEXT_ERR_ALERT_WARNING 1

#define SSL_TLSEXT_ERR_ALERT_FATAL 2

#define SSL_TLSEXT_ERR_NOACK 3

#define SSL_CTX_set_tlsext_servername_arg (ctx, arg)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG,0,arg)

#define SSL_CTX_get_tlsext_ticket_keys (ctx, keys, keylen)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_GET_TLSEXT_TICKET_KEYS,keylen,keys)

#define SSL_CTX_set_tlsext_ticket_keys (ctx, keys, keylen)\
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_TLSEXT_TICKET_KEYS,keylen,keys)

#define SSL_CTX_get_tlsext_status_cb (ssl, cb)\
	SSL_CTX_ctrl(ssl,SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB,0,(void *)cb)

#define SSL_CTX_set_tlsext_status_cb (ssl, cb)\
	SSL_CTX_callback_ctrl(ssl,SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB,\\
	(void (*)(void))cb)

#define SSL_CTX_get_tlsext_status_arg (ssl, arg)\
	SSL_CTX_ctrl(ssl,SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB_ARG,0,arg)

#define SSL_CTX_set_tlsext_status_arg (ssl, arg)\
	SSL_CTX_ctrl(ssl,SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG,0,arg)

#define SSL_CTX_set_tlsext_status_type (ssl, type)\
	SSL_CTX_ctrl(ssl,SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE,type,NULL)

#define SSL_CTX_get_tlsext_status_type (ssl)\
	SSL_CTX_ctrl(ssl,SSL_CTRL_GET_TLSEXT_STATUS_REQ_TYPE,0,NULL)

#define SSL_CTX_set_tlsext_ticket_key_cb (ssl, cb)\
	SSL_CTX_callback_ctrl(ssl,SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB,\\
	(void (*)(void))cb)

#define TLS1_CK_PSK_WITH_RC4_128_SHA 0x0300008A

#define TLS1_CK_PSK_WITH_3DES_EDE_CBC_SHA 0x0300008B

#define TLS1_CK_PSK_WITH_AES_128_CBC_SHA 0x0300008C

#define TLS1_CK_PSK_WITH_AES_256_CBC_SHA 0x0300008D

#define TLS1_CK_DHE_PSK_WITH_RC4_128_SHA 0x0300008E

#define TLS1_CK_DHE_PSK_WITH_3DES_EDE_CBC_SHA 0x0300008F

#define TLS1_CK_DHE_PSK_WITH_AES_128_CBC_SHA 0x03000090

#define TLS1_CK_DHE_PSK_WITH_AES_256_CBC_SHA 0x03000091

#define TLS1_CK_RSA_PSK_WITH_RC4_128_SHA 0x03000092

#define TLS1_CK_RSA_PSK_WITH_3DES_EDE_CBC_SHA 0x03000093

#define TLS1_CK_RSA_PSK_WITH_AES_128_CBC_SHA 0x03000094

#define TLS1_CK_RSA_PSK_WITH_AES_256_CBC_SHA 0x03000095

#define TLS1_CK_PSK_WITH_AES_128_GCM_SHA256 0x030000A8

#define TLS1_CK_PSK_WITH_AES_256_GCM_SHA384 0x030000A9

#define TLS1_CK_DHE_PSK_WITH_AES_128_GCM_SHA256 0x030000AA

#define TLS1_CK_DHE_PSK_WITH_AES_256_GCM_SHA384 0x030000AB

#define TLS1_CK_RSA_PSK_WITH_AES_128_GCM_SHA256 0x030000AC

#define TLS1_CK_RSA_PSK_WITH_AES_256_GCM_SHA384 0x030000AD

#define TLS1_CK_PSK_WITH_AES_128_CBC_SHA256 0x030000AE

#define TLS1_CK_PSK_WITH_AES_256_CBC_SHA384 0x030000AF

#define TLS1_CK_PSK_WITH_NULL_SHA256 0x030000B0

#define TLS1_CK_PSK_WITH_NULL_SHA384 0x030000B1

#define TLS1_CK_DHE_PSK_WITH_AES_128_CBC_SHA256 0x030000B2

#define TLS1_CK_DHE_PSK_WITH_AES_256_CBC_SHA384 0x030000B3

#define TLS1_CK_DHE_PSK_WITH_NULL_SHA256 0x030000B4

#define TLS1_CK_DHE_PSK_WITH_NULL_SHA384 0x030000B5

#define TLS1_CK_RSA_PSK_WITH_AES_128_CBC_SHA256 0x030000B6

#define TLS1_CK_RSA_PSK_WITH_AES_256_CBC_SHA384 0x030000B7

#define TLS1_CK_RSA_PSK_WITH_NULL_SHA256 0x030000B8

#define TLS1_CK_RSA_PSK_WITH_NULL_SHA384 0x030000B9

#define TLS1_CK_PSK_WITH_NULL_SHA 0x0300002C

#define TLS1_CK_DHE_PSK_WITH_NULL_SHA 0x0300002D

#define TLS1_CK_RSA_PSK_WITH_NULL_SHA 0x0300002E

#define TLS1_CK_RSA_WITH_AES_128_SHA 0x0300002F

#define TLS1_CK_DH_DSS_WITH_AES_128_SHA 0x03000030

#define TLS1_CK_DH_RSA_WITH_AES_128_SHA 0x03000031

#define TLS1_CK_DHE_DSS_WITH_AES_128_SHA 0x03000032

#define TLS1_CK_DHE_RSA_WITH_AES_128_SHA 0x03000033

#define TLS1_CK_ADH_WITH_AES_128_SHA 0x03000034

#define TLS1_CK_RSA_WITH_AES_256_SHA 0x03000035

#define TLS1_CK_DH_DSS_WITH_AES_256_SHA 0x03000036

#define TLS1_CK_DH_RSA_WITH_AES_256_SHA 0x03000037

#define TLS1_CK_DHE_DSS_WITH_AES_256_SHA 0x03000038

#define TLS1_CK_DHE_RSA_WITH_AES_256_SHA 0x03000039

#define TLS1_CK_ADH_WITH_AES_256_SHA 0x0300003A

#define TLS1_CK_RSA_WITH_NULL_SHA256 0x0300003B

#define TLS1_CK_RSA_WITH_AES_128_SHA256 0x0300003C

#define TLS1_CK_RSA_WITH_AES_256_SHA256 0x0300003D

#define TLS1_CK_DH_DSS_WITH_AES_128_SHA256 0x0300003E

#define TLS1_CK_DH_RSA_WITH_AES_128_SHA256 0x0300003F

#define TLS1_CK_DHE_DSS_WITH_AES_128_SHA256 0x03000040

#define TLS1_CK_RSA_WITH_CAMELLIA_128_CBC_SHA 0x03000041

#define TLS1_CK_DH_DSS_WITH_CAMELLIA_128_CBC_SHA 0x03000042

#define TLS1_CK_DH_RSA_WITH_CAMELLIA_128_CBC_SHA 0x03000043

#define TLS1_CK_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA 0x03000044

#define TLS1_CK_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA 0x03000045

#define TLS1_CK_ADH_WITH_CAMELLIA_128_CBC_SHA 0x03000046

#define TLS1_CK_DHE_RSA_WITH_AES_128_SHA256 0x03000067

#define TLS1_CK_DH_DSS_WITH_AES_256_SHA256 0x03000068

#define TLS1_CK_DH_RSA_WITH_AES_256_SHA256 0x03000069

#define TLS1_CK_DHE_DSS_WITH_AES_256_SHA256 0x0300006A

#define TLS1_CK_DHE_RSA_WITH_AES_256_SHA256 0x0300006B

#define TLS1_CK_ADH_WITH_AES_128_SHA256 0x0300006C

#define TLS1_CK_ADH_WITH_AES_256_SHA256 0x0300006D

#define TLS1_CK_RSA_WITH_CAMELLIA_256_CBC_SHA 0x03000084

#define TLS1_CK_DH_DSS_WITH_CAMELLIA_256_CBC_SHA 0x03000085

#define TLS1_CK_DH_RSA_WITH_CAMELLIA_256_CBC_SHA 0x03000086

#define TLS1_CK_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA 0x03000087

#define TLS1_CK_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA 0x03000088

#define TLS1_CK_ADH_WITH_CAMELLIA_256_CBC_SHA 0x03000089

#define TLS1_CK_RSA_WITH_SEED_SHA 0x03000096

#define TLS1_CK_DH_DSS_WITH_SEED_SHA 0x03000097

#define TLS1_CK_DH_RSA_WITH_SEED_SHA 0x03000098

#define TLS1_CK_DHE_DSS_WITH_SEED_SHA 0x03000099

#define TLS1_CK_DHE_RSA_WITH_SEED_SHA 0x0300009A

#define TLS1_CK_ADH_WITH_SEED_SHA 0x0300009B

#define TLS1_CK_RSA_WITH_AES_128_GCM_SHA256 0x0300009C

#define TLS1_CK_RSA_WITH_AES_256_GCM_SHA384 0x0300009D

#define TLS1_CK_DHE_RSA_WITH_AES_128_GCM_SHA256 0x0300009E

#define TLS1_CK_DHE_RSA_WITH_AES_256_GCM_SHA384 0x0300009F

#define TLS1_CK_DH_RSA_WITH_AES_128_GCM_SHA256 0x030000A0

#define TLS1_CK_DH_RSA_WITH_AES_256_GCM_SHA384 0x030000A1

#define TLS1_CK_DHE_DSS_WITH_AES_128_GCM_SHA256 0x030000A2

#define TLS1_CK_DHE_DSS_WITH_AES_256_GCM_SHA384 0x030000A3

#define TLS1_CK_DH_DSS_WITH_AES_128_GCM_SHA256 0x030000A4

#define TLS1_CK_DH_DSS_WITH_AES_256_GCM_SHA384 0x030000A5

#define TLS1_CK_ADH_WITH_AES_128_GCM_SHA256 0x030000A6

#define TLS1_CK_ADH_WITH_AES_256_GCM_SHA384 0x030000A7

#define TLS1_CK_RSA_WITH_AES_128_CCM 0x0300C09C

#define TLS1_CK_RSA_WITH_AES_256_CCM 0x0300C09D

#define TLS1_CK_DHE_RSA_WITH_AES_128_CCM 0x0300C09E

#define TLS1_CK_DHE_RSA_WITH_AES_256_CCM 0x0300C09F

#define TLS1_CK_RSA_WITH_AES_128_CCM_8 0x0300C0A0

#define TLS1_CK_RSA_WITH_AES_256_CCM_8 0x0300C0A1

#define TLS1_CK_DHE_RSA_WITH_AES_128_CCM_8 0x0300C0A2

#define TLS1_CK_DHE_RSA_WITH_AES_256_CCM_8 0x0300C0A3

#define TLS1_CK_PSK_WITH_AES_128_CCM 0x0300C0A4

#define TLS1_CK_PSK_WITH_AES_256_CCM 0x0300C0A5

#define TLS1_CK_DHE_PSK_WITH_AES_128_CCM 0x0300C0A6

#define TLS1_CK_DHE_PSK_WITH_AES_256_CCM 0x0300C0A7

#define TLS1_CK_PSK_WITH_AES_128_CCM_8 0x0300C0A8

#define TLS1_CK_PSK_WITH_AES_256_CCM_8 0x0300C0A9

#define TLS1_CK_DHE_PSK_WITH_AES_128_CCM_8 0x0300C0AA

#define TLS1_CK_DHE_PSK_WITH_AES_256_CCM_8 0x0300C0AB

#define TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CCM 0x0300C0AC

#define TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CCM 0x0300C0AD

#define TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CCM_8 0x0300C0AE

#define TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CCM_8 0x0300C0AF

#define TLS1_CK_RSA_WITH_CAMELLIA_128_CBC_SHA256 0x030000BA

#define TLS1_CK_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 0x030000BB

#define TLS1_CK_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 0x030000BC

#define TLS1_CK_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 0x030000BD

#define TLS1_CK_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 0x030000BE

#define TLS1_CK_ADH_WITH_CAMELLIA_128_CBC_SHA256 0x030000BF

#define TLS1_CK_RSA_WITH_CAMELLIA_256_CBC_SHA256 0x030000C0

#define TLS1_CK_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 0x030000C1

#define TLS1_CK_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 0x030000C2

#define TLS1_CK_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 0x030000C3

#define TLS1_CK_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 0x030000C4

#define TLS1_CK_ADH_WITH_CAMELLIA_256_CBC_SHA256 0x030000C5

#define TLS1_CK_ECDH_ECDSA_WITH_NULL_SHA 0x0300C001

#define TLS1_CK_ECDH_ECDSA_WITH_RC4_128_SHA 0x0300C002

#define TLS1_CK_ECDH_ECDSA_WITH_DES_192_CBC3_SHA 0x0300C003

#define TLS1_CK_ECDH_ECDSA_WITH_AES_128_CBC_SHA 0x0300C004

#define TLS1_CK_ECDH_ECDSA_WITH_AES_256_CBC_SHA 0x0300C005

#define TLS1_CK_ECDHE_ECDSA_WITH_NULL_SHA 0x0300C006

#define TLS1_CK_ECDHE_ECDSA_WITH_RC4_128_SHA 0x0300C007

#define TLS1_CK_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA 0x0300C008

#define TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CBC_SHA 0x0300C009

#define TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CBC_SHA 0x0300C00A

#define TLS1_CK_ECDH_RSA_WITH_NULL_SHA 0x0300C00B

#define TLS1_CK_ECDH_RSA_WITH_RC4_128_SHA 0x0300C00C

#define TLS1_CK_ECDH_RSA_WITH_DES_192_CBC3_SHA 0x0300C00D

#define TLS1_CK_ECDH_RSA_WITH_AES_128_CBC_SHA 0x0300C00E

#define TLS1_CK_ECDH_RSA_WITH_AES_256_CBC_SHA 0x0300C00F

#define TLS1_CK_ECDHE_RSA_WITH_NULL_SHA 0x0300C010

#define TLS1_CK_ECDHE_RSA_WITH_RC4_128_SHA 0x0300C011

#define TLS1_CK_ECDHE_RSA_WITH_DES_192_CBC3_SHA 0x0300C012

#define TLS1_CK_ECDHE_RSA_WITH_AES_128_CBC_SHA 0x0300C013

#define TLS1_CK_ECDHE_RSA_WITH_AES_256_CBC_SHA 0x0300C014

#define TLS1_CK_ECDH_anon_WITH_NULL_SHA 0x0300C015

#define TLS1_CK_ECDH_anon_WITH_RC4_128_SHA 0x0300C016

#define TLS1_CK_ECDH_anon_WITH_DES_192_CBC3_SHA 0x0300C017

#define TLS1_CK_ECDH_anon_WITH_AES_128_CBC_SHA 0x0300C018

#define TLS1_CK_ECDH_anon_WITH_AES_256_CBC_SHA 0x0300C019

#define TLS1_CK_SRP_SHA_WITH_3DES_EDE_CBC_SHA 0x0300C01A

#define TLS1_CK_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA 0x0300C01B

#define TLS1_CK_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA 0x0300C01C

#define TLS1_CK_SRP_SHA_WITH_AES_128_CBC_SHA 0x0300C01D

#define TLS1_CK_SRP_SHA_RSA_WITH_AES_128_CBC_SHA 0x0300C01E

#define TLS1_CK_SRP_SHA_DSS_WITH_AES_128_CBC_SHA 0x0300C01F

#define TLS1_CK_SRP_SHA_WITH_AES_256_CBC_SHA 0x0300C020

#define TLS1_CK_SRP_SHA_RSA_WITH_AES_256_CBC_SHA 0x0300C021

#define TLS1_CK_SRP_SHA_DSS_WITH_AES_256_CBC_SHA 0x0300C022

#define TLS1_CK_ECDHE_ECDSA_WITH_AES_128_SHA256 0x0300C023

#define TLS1_CK_ECDHE_ECDSA_WITH_AES_256_SHA384 0x0300C024

#define TLS1_CK_ECDH_ECDSA_WITH_AES_128_SHA256 0x0300C025

#define TLS1_CK_ECDH_ECDSA_WITH_AES_256_SHA384 0x0300C026

#define TLS1_CK_ECDHE_RSA_WITH_AES_128_SHA256 0x0300C027

#define TLS1_CK_ECDHE_RSA_WITH_AES_256_SHA384 0x0300C028

#define TLS1_CK_ECDH_RSA_WITH_AES_128_SHA256 0x0300C029

#define TLS1_CK_ECDH_RSA_WITH_AES_256_SHA384 0x0300C02A

#define TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 0x0300C02B

#define TLS1_CK_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 0x0300C02C

#define TLS1_CK_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 0x0300C02D

#define TLS1_CK_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 0x0300C02E

#define TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256 0x0300C02F

#define TLS1_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384 0x0300C030

#define TLS1_CK_ECDH_RSA_WITH_AES_128_GCM_SHA256 0x0300C031

#define TLS1_CK_ECDH_RSA_WITH_AES_256_GCM_SHA384 0x0300C032

#define TLS1_CK_ECDHE_PSK_WITH_RC4_128_SHA 0x0300C033

#define TLS1_CK_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA 0x0300C034

#define TLS1_CK_ECDHE_PSK_WITH_AES_128_CBC_SHA 0x0300C035

#define TLS1_CK_ECDHE_PSK_WITH_AES_256_CBC_SHA 0x0300C036

#define TLS1_CK_ECDHE_PSK_WITH_AES_128_CBC_SHA256 0x0300C037

#define TLS1_CK_ECDHE_PSK_WITH_AES_256_CBC_SHA384 0x0300C038

#define TLS1_CK_ECDHE_PSK_WITH_NULL_SHA 0x0300C039

#define TLS1_CK_ECDHE_PSK_WITH_NULL_SHA256 0x0300C03A

#define TLS1_CK_ECDHE_PSK_WITH_NULL_SHA384 0x0300C03B

#define TLS1_CK_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 0x0300C072

#define TLS1_CK_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 0x0300C073

#define TLS1_CK_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 0x0300C074

#define TLS1_CK_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 0x0300C075

#define TLS1_CK_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 0x0300C076

#define TLS1_CK_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 0x0300C077

#define TLS1_CK_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 0x0300C078

#define TLS1_CK_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 0x0300C079

#define TLS1_CK_PSK_WITH_CAMELLIA_128_CBC_SHA256 0x0300C094

#define TLS1_CK_PSK_WITH_CAMELLIA_256_CBC_SHA384 0x0300C095

#define TLS1_CK_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 0x0300C096

#define TLS1_CK_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 0x0300C097

#define TLS1_CK_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 0x0300C098

#define TLS1_CK_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 0x0300C099

#define TLS1_CK_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 0x0300C09A

#define TLS1_CK_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 0x0300C09B

#define TLS1_CK_ECDHE_RSA_WITH_CHACHA20_POLY1305 0x0300CCA8

#define TLS1_CK_ECDHE_ECDSA_WITH_CHACHA20_POLY1305 0x0300CCA9

#define TLS1_CK_DHE_RSA_WITH_CHACHA20_POLY1305 0x0300CCAA

#define TLS1_CK_PSK_WITH_CHACHA20_POLY1305 0x0300CCAB

#define TLS1_CK_ECDHE_PSK_WITH_CHACHA20_POLY1305 0x0300CCAC

#define TLS1_CK_DHE_PSK_WITH_CHACHA20_POLY1305 0x0300CCAD

#define TLS1_CK_RSA_PSK_WITH_CHACHA20_POLY1305 0x0300CCAE

#define TLS1_3_CK_AES_128_GCM_SHA256 0x03001301

#define TLS1_3_CK_AES_256_GCM_SHA384 0x03001302

#define TLS1_3_CK_CHACHA20_POLY1305_SHA256 0x03001303

#define TLS1_3_CK_AES_128_CCM_SHA256 0x03001304

#define TLS1_3_CK_AES_128_CCM_8_SHA256 0x03001305

#define TLS1_CK_RSA_WITH_ARIA_128_GCM_SHA256 0x0300C050

#define TLS1_CK_RSA_WITH_ARIA_256_GCM_SHA384 0x0300C051

#define TLS1_CK_DHE_RSA_WITH_ARIA_128_GCM_SHA256 0x0300C052

#define TLS1_CK_DHE_RSA_WITH_ARIA_256_GCM_SHA384 0x0300C053

#define TLS1_CK_DH_RSA_WITH_ARIA_128_GCM_SHA256 0x0300C054

#define TLS1_CK_DH_RSA_WITH_ARIA_256_GCM_SHA384 0x0300C055

#define TLS1_CK_DHE_DSS_WITH_ARIA_128_GCM_SHA256 0x0300C056

#define TLS1_CK_DHE_DSS_WITH_ARIA_256_GCM_SHA384 0x0300C057

#define TLS1_CK_DH_DSS_WITH_ARIA_128_GCM_SHA256 0x0300C058

#define TLS1_CK_DH_DSS_WITH_ARIA_256_GCM_SHA384 0x0300C059

#define TLS1_CK_DH_anon_WITH_ARIA_128_GCM_SHA256 0x0300C05A

#define TLS1_CK_DH_anon_WITH_ARIA_256_GCM_SHA384 0x0300C05B

#define TLS1_CK_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 0x0300C05C

#define TLS1_CK_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 0x0300C05D

#define TLS1_CK_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 0x0300C05E

#define TLS1_CK_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 0x0300C05F

#define TLS1_CK_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 0x0300C060

#define TLS1_CK_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 0x0300C061

#define TLS1_CK_ECDH_RSA_WITH_ARIA_128_GCM_SHA256 0x0300C062

#define TLS1_CK_ECDH_RSA_WITH_ARIA_256_GCM_SHA384 0x0300C063

#define TLS1_CK_PSK_WITH_ARIA_128_GCM_SHA256 0x0300C06A

#define TLS1_CK_PSK_WITH_ARIA_256_GCM_SHA384 0x0300C06B

#define TLS1_CK_DHE_PSK_WITH_ARIA_128_GCM_SHA256 0x0300C06C

#define TLS1_CK_DHE_PSK_WITH_ARIA_256_GCM_SHA384 0x0300C06D

#define TLS1_CK_RSA_PSK_WITH_ARIA_128_GCM_SHA256 0x0300C06E

#define TLS1_CK_RSA_PSK_WITH_ARIA_256_GCM_SHA384 0x0300C06F

#define TLS1_RFC_RSA_WITH_AES_128_SHA "TLS_RSA_WITH_AES_128_CBC_SHA"

#define TLS1_RFC_DHE_DSS_WITH_AES_128_SHA "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"

#define TLS1_RFC_DHE_RSA_WITH_AES_128_SHA "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"

#define TLS1_RFC_ADH_WITH_AES_128_SHA "TLS_DH_anon_WITH_AES_128_CBC_SHA"

#define TLS1_RFC_RSA_WITH_AES_256_SHA "TLS_RSA_WITH_AES_256_CBC_SHA"

#define TLS1_RFC_DHE_DSS_WITH_AES_256_SHA "TLS_DHE_DSS_WITH_AES_256_CBC_SHA"

#define TLS1_RFC_DHE_RSA_WITH_AES_256_SHA "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"

#define TLS1_RFC_ADH_WITH_AES_256_SHA "TLS_DH_anon_WITH_AES_256_CBC_SHA"

#define TLS1_RFC_RSA_WITH_NULL_SHA256 "TLS_RSA_WITH_NULL_SHA256"

#define TLS1_RFC_RSA_WITH_AES_128_SHA256 "TLS_RSA_WITH_AES_128_CBC_SHA256"

#define TLS1_RFC_RSA_WITH_AES_256_SHA256 "TLS_RSA_WITH_AES_256_CBC_SHA256"

#define TLS1_RFC_DHE_DSS_WITH_AES_128_SHA256 "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"

#define TLS1_RFC_DHE_RSA_WITH_AES_128_SHA256 "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"

#define TLS1_RFC_DHE_DSS_WITH_AES_256_SHA256 "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"

#define TLS1_RFC_DHE_RSA_WITH_AES_256_SHA256 "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"

#define TLS1_RFC_ADH_WITH_AES_128_SHA256 "TLS_DH_anon_WITH_AES_128_CBC_SHA256"

#define TLS1_RFC_ADH_WITH_AES_256_SHA256 "TLS_DH_anon_WITH_AES_256_CBC_SHA256"

#define TLS1_RFC_RSA_WITH_AES_128_GCM_SHA256 "TLS_RSA_WITH_AES_128_GCM_SHA256"

#define TLS1_RFC_RSA_WITH_AES_256_GCM_SHA384 "TLS_RSA_WITH_AES_256_GCM_SHA384"

#define TLS1_RFC_DHE_RSA_WITH_AES_128_GCM_SHA256 "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"

#define TLS1_RFC_DHE_RSA_WITH_AES_256_GCM_SHA384 "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"

#define TLS1_RFC_DHE_DSS_WITH_AES_128_GCM_SHA256 "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256"

#define TLS1_RFC_DHE_DSS_WITH_AES_256_GCM_SHA384 "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384"

#define TLS1_RFC_ADH_WITH_AES_128_GCM_SHA256 "TLS_DH_anon_WITH_AES_128_GCM_SHA256"

#define TLS1_RFC_ADH_WITH_AES_256_GCM_SHA384 "TLS_DH_anon_WITH_AES_256_GCM_SHA384"

#define TLS1_RFC_RSA_WITH_AES_128_CCM "TLS_RSA_WITH_AES_128_CCM"

#define TLS1_RFC_RSA_WITH_AES_256_CCM "TLS_RSA_WITH_AES_256_CCM"

#define TLS1_RFC_DHE_RSA_WITH_AES_128_CCM "TLS_DHE_RSA_WITH_AES_128_CCM"

#define TLS1_RFC_DHE_RSA_WITH_AES_256_CCM "TLS_DHE_RSA_WITH_AES_256_CCM"

#define TLS1_RFC_RSA_WITH_AES_128_CCM_8 "TLS_RSA_WITH_AES_128_CCM_8"

#define TLS1_RFC_RSA_WITH_AES_256_CCM_8 "TLS_RSA_WITH_AES_256_CCM_8"

#define TLS1_RFC_DHE_RSA_WITH_AES_128_CCM_8 "TLS_DHE_RSA_WITH_AES_128_CCM_8"

#define TLS1_RFC_DHE_RSA_WITH_AES_256_CCM_8 "TLS_DHE_RSA_WITH_AES_256_CCM_8"

#define TLS1_RFC_PSK_WITH_AES_128_CCM "TLS_PSK_WITH_AES_128_CCM"

#define TLS1_RFC_PSK_WITH_AES_256_CCM "TLS_PSK_WITH_AES_256_CCM"

#define TLS1_RFC_DHE_PSK_WITH_AES_128_CCM "TLS_DHE_PSK_WITH_AES_128_CCM"

#define TLS1_RFC_DHE_PSK_WITH_AES_256_CCM "TLS_DHE_PSK_WITH_AES_256_CCM"

#define TLS1_RFC_PSK_WITH_AES_128_CCM_8 "TLS_PSK_WITH_AES_128_CCM_8"

#define TLS1_RFC_PSK_WITH_AES_256_CCM_8 "TLS_PSK_WITH_AES_256_CCM_8"

#define TLS1_RFC_DHE_PSK_WITH_AES_128_CCM_8 "TLS_PSK_DHE_WITH_AES_128_CCM_8"

#define TLS1_RFC_DHE_PSK_WITH_AES_256_CCM_8 "TLS_PSK_DHE_WITH_AES_256_CCM_8"

#define TLS1_RFC_ECDHE_ECDSA_WITH_AES_128_CCM "TLS_ECDHE_ECDSA_WITH_AES_128_CCM"

#define TLS1_RFC_ECDHE_ECDSA_WITH_AES_256_CCM "TLS_ECDHE_ECDSA_WITH_AES_256_CCM"

#define TLS1_RFC_ECDHE_ECDSA_WITH_AES_128_CCM_8 "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8"

#define TLS1_RFC_ECDHE_ECDSA_WITH_AES_256_CCM_8 "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8"

#define TLS1_3_RFC_AES_128_GCM_SHA256 "TLS_AES_128_GCM_SHA256"

#define TLS1_3_RFC_AES_256_GCM_SHA384 "TLS_AES_256_GCM_SHA384"

#define TLS1_3_RFC_CHACHA20_POLY1305_SHA256 "TLS_CHACHA20_POLY1305_SHA256"

#define TLS1_3_RFC_AES_128_CCM_SHA256 "TLS_AES_128_CCM_SHA256"

#define TLS1_3_RFC_AES_128_CCM_8_SHA256 "TLS_AES_128_CCM_8_SHA256"

#define TLS1_RFC_ECDHE_ECDSA_WITH_NULL_SHA "TLS_ECDHE_ECDSA_WITH_NULL_SHA"

#define TLS1_RFC_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"

#define TLS1_RFC_ECDHE_ECDSA_WITH_AES_128_CBC_SHA "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"

#define TLS1_RFC_ECDHE_ECDSA_WITH_AES_256_CBC_SHA "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"

#define TLS1_RFC_ECDHE_RSA_WITH_NULL_SHA "TLS_ECDHE_RSA_WITH_NULL_SHA"

#define TLS1_RFC_ECDHE_RSA_WITH_DES_192_CBC3_SHA "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"

#define TLS1_RFC_ECDHE_RSA_WITH_AES_128_CBC_SHA "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"

#define TLS1_RFC_ECDHE_RSA_WITH_AES_256_CBC_SHA "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"

#define TLS1_RFC_ECDH_anon_WITH_NULL_SHA "TLS_ECDH_anon_WITH_NULL_SHA"

#define TLS1_RFC_ECDH_anon_WITH_DES_192_CBC3_SHA "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA"

#define TLS1_RFC_ECDH_anon_WITH_AES_128_CBC_SHA "TLS_ECDH_anon_WITH_AES_128_CBC_SHA"

#define TLS1_RFC_ECDH_anon_WITH_AES_256_CBC_SHA "TLS_ECDH_anon_WITH_AES_256_CBC_SHA"

#define TLS1_RFC_ECDHE_ECDSA_WITH_AES_128_SHA256 "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"

#define TLS1_RFC_ECDHE_ECDSA_WITH_AES_256_SHA384 "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"

#define TLS1_RFC_ECDHE_RSA_WITH_AES_128_SHA256 "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"

#define TLS1_RFC_ECDHE_RSA_WITH_AES_256_SHA384 "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"

#define TLS1_RFC_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"

#define TLS1_RFC_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"

#define TLS1_RFC_ECDHE_RSA_WITH_AES_128_GCM_SHA256 "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"

#define TLS1_RFC_ECDHE_RSA_WITH_AES_256_GCM_SHA384 "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"

#define TLS1_RFC_PSK_WITH_NULL_SHA "TLS_PSK_WITH_NULL_SHA"

#define TLS1_RFC_DHE_PSK_WITH_NULL_SHA "TLS_DHE_PSK_WITH_NULL_SHA"

#define TLS1_RFC_RSA_PSK_WITH_NULL_SHA "TLS_RSA_PSK_WITH_NULL_SHA"

#define TLS1_RFC_PSK_WITH_3DES_EDE_CBC_SHA "TLS_PSK_WITH_3DES_EDE_CBC_SHA"

#define TLS1_RFC_PSK_WITH_AES_128_CBC_SHA "TLS_PSK_WITH_AES_128_CBC_SHA"

#define TLS1_RFC_PSK_WITH_AES_256_CBC_SHA "TLS_PSK_WITH_AES_256_CBC_SHA"

#define TLS1_RFC_DHE_PSK_WITH_3DES_EDE_CBC_SHA "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA"

#define TLS1_RFC_DHE_PSK_WITH_AES_128_CBC_SHA "TLS_DHE_PSK_WITH_AES_128_CBC_SHA"

#define TLS1_RFC_DHE_PSK_WITH_AES_256_CBC_SHA "TLS_DHE_PSK_WITH_AES_256_CBC_SHA"

#define TLS1_RFC_RSA_PSK_WITH_3DES_EDE_CBC_SHA "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA"

#define TLS1_RFC_RSA_PSK_WITH_AES_128_CBC_SHA "TLS_RSA_PSK_WITH_AES_128_CBC_SHA"

#define TLS1_RFC_RSA_PSK_WITH_AES_256_CBC_SHA "TLS_RSA_PSK_WITH_AES_256_CBC_SHA"

#define TLS1_RFC_PSK_WITH_AES_128_GCM_SHA256 "TLS_PSK_WITH_AES_128_GCM_SHA256"

#define TLS1_RFC_PSK_WITH_AES_256_GCM_SHA384 "TLS_PSK_WITH_AES_256_GCM_SHA384"

#define TLS1_RFC_DHE_PSK_WITH_AES_128_GCM_SHA256 "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256"

#define TLS1_RFC_DHE_PSK_WITH_AES_256_GCM_SHA384 "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384"

#define TLS1_RFC_RSA_PSK_WITH_AES_128_GCM_SHA256 "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256"

#define TLS1_RFC_RSA_PSK_WITH_AES_256_GCM_SHA384 "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384"

#define TLS1_RFC_PSK_WITH_AES_128_CBC_SHA256 "TLS_PSK_WITH_AES_128_CBC_SHA256"

#define TLS1_RFC_PSK_WITH_AES_256_CBC_SHA384 "TLS_PSK_WITH_AES_256_CBC_SHA384"

#define TLS1_RFC_PSK_WITH_NULL_SHA256 "TLS_PSK_WITH_NULL_SHA256"

#define TLS1_RFC_PSK_WITH_NULL_SHA384 "TLS_PSK_WITH_NULL_SHA384"

#define TLS1_RFC_DHE_PSK_WITH_AES_128_CBC_SHA256 "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256"

#define TLS1_RFC_DHE_PSK_WITH_AES_256_CBC_SHA384 "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384"

#define TLS1_RFC_DHE_PSK_WITH_NULL_SHA256 "TLS_DHE_PSK_WITH_NULL_SHA256"

#define TLS1_RFC_DHE_PSK_WITH_NULL_SHA384 "TLS_DHE_PSK_WITH_NULL_SHA384"

#define TLS1_RFC_RSA_PSK_WITH_AES_128_CBC_SHA256 "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256"

#define TLS1_RFC_RSA_PSK_WITH_AES_256_CBC_SHA384 "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384"

#define TLS1_RFC_RSA_PSK_WITH_NULL_SHA256 "TLS_RSA_PSK_WITH_NULL_SHA256"

#define TLS1_RFC_RSA_PSK_WITH_NULL_SHA384 "TLS_RSA_PSK_WITH_NULL_SHA384"

#define TLS1_RFC_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA"

#define TLS1_RFC_ECDHE_PSK_WITH_AES_128_CBC_SHA "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA"

#define TLS1_RFC_ECDHE_PSK_WITH_AES_256_CBC_SHA "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA"

#define TLS1_RFC_ECDHE_PSK_WITH_AES_128_CBC_SHA256 "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256"

#define TLS1_RFC_ECDHE_PSK_WITH_AES_256_CBC_SHA384 "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384"

#define TLS1_RFC_ECDHE_PSK_WITH_NULL_SHA "TLS_ECDHE_PSK_WITH_NULL_SHA"

#define TLS1_RFC_ECDHE_PSK_WITH_NULL_SHA256 "TLS_ECDHE_PSK_WITH_NULL_SHA256"

#define TLS1_RFC_ECDHE_PSK_WITH_NULL_SHA384 "TLS_ECDHE_PSK_WITH_NULL_SHA384"

#define TLS1_RFC_SRP_SHA_WITH_3DES_EDE_CBC_SHA "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA"

#define TLS1_RFC_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA"

#define TLS1_RFC_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA"

#define TLS1_RFC_SRP_SHA_WITH_AES_128_CBC_SHA "TLS_SRP_SHA_WITH_AES_128_CBC_SHA"

#define TLS1_RFC_SRP_SHA_RSA_WITH_AES_128_CBC_SHA "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA"

#define TLS1_RFC_SRP_SHA_DSS_WITH_AES_128_CBC_SHA "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA"

#define TLS1_RFC_SRP_SHA_WITH_AES_256_CBC_SHA "TLS_SRP_SHA_WITH_AES_256_CBC_SHA"

#define TLS1_RFC_SRP_SHA_RSA_WITH_AES_256_CBC_SHA "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA"

#define TLS1_RFC_SRP_SHA_DSS_WITH_AES_256_CBC_SHA "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA"

#define TLS1_RFC_DHE_RSA_WITH_CHACHA20_POLY1305 "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"

#define TLS1_RFC_ECDHE_RSA_WITH_CHACHA20_POLY1305 "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"

#define TLS1_RFC_ECDHE_ECDSA_WITH_CHACHA20_POLY1305 "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"

#define TLS1_RFC_PSK_WITH_CHACHA20_POLY1305 "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256"

#define TLS1_RFC_ECDHE_PSK_WITH_CHACHA20_POLY1305 "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256"

#define TLS1_RFC_DHE_PSK_WITH_CHACHA20_POLY1305 "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256"

#define TLS1_RFC_RSA_PSK_WITH_CHACHA20_POLY1305 "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256"

#define TLS1_RFC_RSA_WITH_CAMELLIA_128_CBC_SHA256 "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256"

#define TLS1_RFC_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256"

#define TLS1_RFC_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"

#define TLS1_RFC_ADH_WITH_CAMELLIA_128_CBC_SHA256 "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256"

#define TLS1_RFC_RSA_WITH_CAMELLIA_256_CBC_SHA256 "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256"

#define TLS1_RFC_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256"

#define TLS1_RFC_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256"

#define TLS1_RFC_ADH_WITH_CAMELLIA_256_CBC_SHA256 "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256"

#define TLS1_RFC_RSA_WITH_CAMELLIA_256_CBC_SHA "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"

#define TLS1_RFC_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA"

#define TLS1_RFC_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"

#define TLS1_RFC_ADH_WITH_CAMELLIA_256_CBC_SHA "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA"

#define TLS1_RFC_RSA_WITH_CAMELLIA_128_CBC_SHA "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"

#define TLS1_RFC_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA"

#define TLS1_RFC_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA"

#define TLS1_RFC_ADH_WITH_CAMELLIA_128_CBC_SHA "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA"

#define TLS1_RFC_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"

#define TLS1_RFC_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"

#define TLS1_RFC_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"

#define TLS1_RFC_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384"

#define TLS1_RFC_PSK_WITH_CAMELLIA_128_CBC_SHA256 "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256"

#define TLS1_RFC_PSK_WITH_CAMELLIA_256_CBC_SHA384 "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384"

#define TLS1_RFC_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256"

#define TLS1_RFC_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384"

#define TLS1_RFC_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256"

#define TLS1_RFC_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384"

#define TLS1_RFC_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256"

#define TLS1_RFC_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384"

#define TLS1_RFC_RSA_WITH_SEED_SHA "TLS_RSA_WITH_SEED_CBC_SHA"

#define TLS1_RFC_DHE_DSS_WITH_SEED_SHA "TLS_DHE_DSS_WITH_SEED_CBC_SHA"

#define TLS1_RFC_DHE_RSA_WITH_SEED_SHA "TLS_DHE_RSA_WITH_SEED_CBC_SHA"

#define TLS1_RFC_ADH_WITH_SEED_SHA "TLS_DH_anon_WITH_SEED_CBC_SHA"

#define TLS1_RFC_ECDHE_PSK_WITH_RC4_128_SHA "TLS_ECDHE_PSK_WITH_RC4_128_SHA"

#define TLS1_RFC_ECDH_anon_WITH_RC4_128_SHA "TLS_ECDH_anon_WITH_RC4_128_SHA"

#define TLS1_RFC_ECDHE_ECDSA_WITH_RC4_128_SHA "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"

#define TLS1_RFC_ECDHE_RSA_WITH_RC4_128_SHA "TLS_ECDHE_RSA_WITH_RC4_128_SHA"

#define TLS1_RFC_PSK_WITH_RC4_128_SHA "TLS_PSK_WITH_RC4_128_SHA"

#define TLS1_RFC_RSA_PSK_WITH_RC4_128_SHA "TLS_RSA_PSK_WITH_RC4_128_SHA"

#define TLS1_RFC_DHE_PSK_WITH_RC4_128_SHA "TLS_DHE_PSK_WITH_RC4_128_SHA"

#define TLS1_RFC_RSA_WITH_ARIA_128_GCM_SHA256 "TLS_RSA_WITH_ARIA_128_GCM_SHA256"

#define TLS1_RFC_RSA_WITH_ARIA_256_GCM_SHA384 "TLS_RSA_WITH_ARIA_256_GCM_SHA384"

#define TLS1_RFC_DHE_RSA_WITH_ARIA_128_GCM_SHA256 "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256"

#define TLS1_RFC_DHE_RSA_WITH_ARIA_256_GCM_SHA384 "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384"

#define TLS1_RFC_DH_RSA_WITH_ARIA_128_GCM_SHA256 "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256"

#define TLS1_RFC_DH_RSA_WITH_ARIA_256_GCM_SHA384 "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384"

#define TLS1_RFC_DHE_DSS_WITH_ARIA_128_GCM_SHA256 "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256"

#define TLS1_RFC_DHE_DSS_WITH_ARIA_256_GCM_SHA384 "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384"

#define TLS1_RFC_DH_DSS_WITH_ARIA_128_GCM_SHA256 "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256"

#define TLS1_RFC_DH_DSS_WITH_ARIA_256_GCM_SHA384 "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384"

#define TLS1_RFC_DH_anon_WITH_ARIA_128_GCM_SHA256 "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256"

#define TLS1_RFC_DH_anon_WITH_ARIA_256_GCM_SHA384 "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384"

#define TLS1_RFC_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256"

#define TLS1_RFC_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384"

#define TLS1_RFC_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256"

#define TLS1_RFC_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384"

#define TLS1_RFC_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256"

#define TLS1_RFC_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384"

#define TLS1_RFC_ECDH_RSA_WITH_ARIA_128_GCM_SHA256 "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256"

#define TLS1_RFC_ECDH_RSA_WITH_ARIA_256_GCM_SHA384 "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384"

#define TLS1_RFC_PSK_WITH_ARIA_128_GCM_SHA256 "TLS_PSK_WITH_ARIA_128_GCM_SHA256"

#define TLS1_RFC_PSK_WITH_ARIA_256_GCM_SHA384 "TLS_PSK_WITH_ARIA_256_GCM_SHA384"

#define TLS1_RFC_DHE_PSK_WITH_ARIA_128_GCM_SHA256 "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256"

#define TLS1_RFC_DHE_PSK_WITH_ARIA_256_GCM_SHA384 "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384"

#define TLS1_RFC_RSA_PSK_WITH_ARIA_128_GCM_SHA256 "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256"

#define TLS1_RFC_RSA_PSK_WITH_ARIA_256_GCM_SHA384 "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384"

#define TLS1_TXT_DHE_DSS_WITH_RC4_128_SHA "DHE-DSS-RC4-SHA"

#define TLS1_TXT_PSK_WITH_NULL_SHA "PSK-NULL-SHA"

#define TLS1_TXT_DHE_PSK_WITH_NULL_SHA "DHE-PSK-NULL-SHA"

#define TLS1_TXT_RSA_PSK_WITH_NULL_SHA "RSA-PSK-NULL-SHA"

#define TLS1_TXT_RSA_WITH_AES_128_SHA "AES128-SHA"

#define TLS1_TXT_DH_DSS_WITH_AES_128_SHA "DH-DSS-AES128-SHA"

#define TLS1_TXT_DH_RSA_WITH_AES_128_SHA "DH-RSA-AES128-SHA"

#define TLS1_TXT_DHE_DSS_WITH_AES_128_SHA "DHE-DSS-AES128-SHA"

#define TLS1_TXT_DHE_RSA_WITH_AES_128_SHA "DHE-RSA-AES128-SHA"

#define TLS1_TXT_ADH_WITH_AES_128_SHA "ADH-AES128-SHA"

#define TLS1_TXT_RSA_WITH_AES_256_SHA "AES256-SHA"

#define TLS1_TXT_DH_DSS_WITH_AES_256_SHA "DH-DSS-AES256-SHA"

#define TLS1_TXT_DH_RSA_WITH_AES_256_SHA "DH-RSA-AES256-SHA"

#define TLS1_TXT_DHE_DSS_WITH_AES_256_SHA "DHE-DSS-AES256-SHA"

#define TLS1_TXT_DHE_RSA_WITH_AES_256_SHA "DHE-RSA-AES256-SHA"

#define TLS1_TXT_ADH_WITH_AES_256_SHA "ADH-AES256-SHA"

#define TLS1_TXT_ECDH_ECDSA_WITH_NULL_SHA "ECDH-ECDSA-NULL-SHA"

#define TLS1_TXT_ECDH_ECDSA_WITH_RC4_128_SHA "ECDH-ECDSA-RC4-SHA"

#define TLS1_TXT_ECDH_ECDSA_WITH_DES_192_CBC3_SHA "ECDH-ECDSA-DES-CBC3-SHA"

#define TLS1_TXT_ECDH_ECDSA_WITH_AES_128_CBC_SHA "ECDH-ECDSA-AES128-SHA"

#define TLS1_TXT_ECDH_ECDSA_WITH_AES_256_CBC_SHA "ECDH-ECDSA-AES256-SHA"

#define TLS1_TXT_ECDHE_ECDSA_WITH_NULL_SHA "ECDHE-ECDSA-NULL-SHA"

#define TLS1_TXT_ECDHE_ECDSA_WITH_RC4_128_SHA "ECDHE-ECDSA-RC4-SHA"

#define TLS1_TXT_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA "ECDHE-ECDSA-DES-CBC3-SHA"

#define TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_CBC_SHA "ECDHE-ECDSA-AES128-SHA"

#define TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_CBC_SHA "ECDHE-ECDSA-AES256-SHA"

#define TLS1_TXT_ECDH_RSA_WITH_NULL_SHA "ECDH-RSA-NULL-SHA"

#define TLS1_TXT_ECDH_RSA_WITH_RC4_128_SHA "ECDH-RSA-RC4-SHA"

#define TLS1_TXT_ECDH_RSA_WITH_DES_192_CBC3_SHA "ECDH-RSA-DES-CBC3-SHA"

#define TLS1_TXT_ECDH_RSA_WITH_AES_128_CBC_SHA "ECDH-RSA-AES128-SHA"

#define TLS1_TXT_ECDH_RSA_WITH_AES_256_CBC_SHA "ECDH-RSA-AES256-SHA"

#define TLS1_TXT_ECDHE_RSA_WITH_NULL_SHA "ECDHE-RSA-NULL-SHA"

#define TLS1_TXT_ECDHE_RSA_WITH_RC4_128_SHA "ECDHE-RSA-RC4-SHA"

#define TLS1_TXT_ECDHE_RSA_WITH_DES_192_CBC3_SHA "ECDHE-RSA-DES-CBC3-SHA"

#define TLS1_TXT_ECDHE_RSA_WITH_AES_128_CBC_SHA "ECDHE-RSA-AES128-SHA"

#define TLS1_TXT_ECDHE_RSA_WITH_AES_256_CBC_SHA "ECDHE-RSA-AES256-SHA"

#define TLS1_TXT_ECDH_anon_WITH_NULL_SHA "AECDH-NULL-SHA"

#define TLS1_TXT_ECDH_anon_WITH_RC4_128_SHA "AECDH-RC4-SHA"

#define TLS1_TXT_ECDH_anon_WITH_DES_192_CBC3_SHA "AECDH-DES-CBC3-SHA"

#define TLS1_TXT_ECDH_anon_WITH_AES_128_CBC_SHA "AECDH-AES128-SHA"

#define TLS1_TXT_ECDH_anon_WITH_AES_256_CBC_SHA "AECDH-AES256-SHA"

#define TLS1_TXT_PSK_WITH_RC4_128_SHA "PSK-RC4-SHA"

#define TLS1_TXT_PSK_WITH_3DES_EDE_CBC_SHA "PSK-3DES-EDE-CBC-SHA"

#define TLS1_TXT_PSK_WITH_AES_128_CBC_SHA "PSK-AES128-CBC-SHA"

#define TLS1_TXT_PSK_WITH_AES_256_CBC_SHA "PSK-AES256-CBC-SHA"

#define TLS1_TXT_DHE_PSK_WITH_RC4_128_SHA "DHE-PSK-RC4-SHA"

#define TLS1_TXT_DHE_PSK_WITH_3DES_EDE_CBC_SHA "DHE-PSK-3DES-EDE-CBC-SHA"

#define TLS1_TXT_DHE_PSK_WITH_AES_128_CBC_SHA "DHE-PSK-AES128-CBC-SHA"

#define TLS1_TXT_DHE_PSK_WITH_AES_256_CBC_SHA "DHE-PSK-AES256-CBC-SHA"

#define TLS1_TXT_RSA_PSK_WITH_RC4_128_SHA "RSA-PSK-RC4-SHA"

#define TLS1_TXT_RSA_PSK_WITH_3DES_EDE_CBC_SHA "RSA-PSK-3DES-EDE-CBC-SHA"

#define TLS1_TXT_RSA_PSK_WITH_AES_128_CBC_SHA "RSA-PSK-AES128-CBC-SHA"

#define TLS1_TXT_RSA_PSK_WITH_AES_256_CBC_SHA "RSA-PSK-AES256-CBC-SHA"

#define TLS1_TXT_PSK_WITH_AES_128_GCM_SHA256 "PSK-AES128-GCM-SHA256"

#define TLS1_TXT_PSK_WITH_AES_256_GCM_SHA384 "PSK-AES256-GCM-SHA384"

#define TLS1_TXT_DHE_PSK_WITH_AES_128_GCM_SHA256 "DHE-PSK-AES128-GCM-SHA256"

#define TLS1_TXT_DHE_PSK_WITH_AES_256_GCM_SHA384 "DHE-PSK-AES256-GCM-SHA384"

#define TLS1_TXT_RSA_PSK_WITH_AES_128_GCM_SHA256 "RSA-PSK-AES128-GCM-SHA256"

#define TLS1_TXT_RSA_PSK_WITH_AES_256_GCM_SHA384 "RSA-PSK-AES256-GCM-SHA384"

#define TLS1_TXT_PSK_WITH_AES_128_CBC_SHA256 "PSK-AES128-CBC-SHA256"

#define TLS1_TXT_PSK_WITH_AES_256_CBC_SHA384 "PSK-AES256-CBC-SHA384"

#define TLS1_TXT_PSK_WITH_NULL_SHA256 "PSK-NULL-SHA256"

#define TLS1_TXT_PSK_WITH_NULL_SHA384 "PSK-NULL-SHA384"

#define TLS1_TXT_DHE_PSK_WITH_AES_128_CBC_SHA256 "DHE-PSK-AES128-CBC-SHA256"

#define TLS1_TXT_DHE_PSK_WITH_AES_256_CBC_SHA384 "DHE-PSK-AES256-CBC-SHA384"

#define TLS1_TXT_DHE_PSK_WITH_NULL_SHA256 "DHE-PSK-NULL-SHA256"

#define TLS1_TXT_DHE_PSK_WITH_NULL_SHA384 "DHE-PSK-NULL-SHA384"

#define TLS1_TXT_RSA_PSK_WITH_AES_128_CBC_SHA256 "RSA-PSK-AES128-CBC-SHA256"

#define TLS1_TXT_RSA_PSK_WITH_AES_256_CBC_SHA384 "RSA-PSK-AES256-CBC-SHA384"

#define TLS1_TXT_RSA_PSK_WITH_NULL_SHA256 "RSA-PSK-NULL-SHA256"

#define TLS1_TXT_RSA_PSK_WITH_NULL_SHA384 "RSA-PSK-NULL-SHA384"

#define TLS1_TXT_SRP_SHA_WITH_3DES_EDE_CBC_SHA "SRP-3DES-EDE-CBC-SHA"

#define TLS1_TXT_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA "SRP-RSA-3DES-EDE-CBC-SHA"

#define TLS1_TXT_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA "SRP-DSS-3DES-EDE-CBC-SHA"

#define TLS1_TXT_SRP_SHA_WITH_AES_128_CBC_SHA "SRP-AES-128-CBC-SHA"

#define TLS1_TXT_SRP_SHA_RSA_WITH_AES_128_CBC_SHA "SRP-RSA-AES-128-CBC-SHA"

#define TLS1_TXT_SRP_SHA_DSS_WITH_AES_128_CBC_SHA "SRP-DSS-AES-128-CBC-SHA"

#define TLS1_TXT_SRP_SHA_WITH_AES_256_CBC_SHA "SRP-AES-256-CBC-SHA"

#define TLS1_TXT_SRP_SHA_RSA_WITH_AES_256_CBC_SHA "SRP-RSA-AES-256-CBC-SHA"

#define TLS1_TXT_SRP_SHA_DSS_WITH_AES_256_CBC_SHA "SRP-DSS-AES-256-CBC-SHA"

#define TLS1_TXT_RSA_WITH_CAMELLIA_128_CBC_SHA "CAMELLIA128-SHA"

#define TLS1_TXT_DH_DSS_WITH_CAMELLIA_128_CBC_SHA "DH-DSS-CAMELLIA128-SHA"

#define TLS1_TXT_DH_RSA_WITH_CAMELLIA_128_CBC_SHA "DH-RSA-CAMELLIA128-SHA"

#define TLS1_TXT_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA "DHE-DSS-CAMELLIA128-SHA"

#define TLS1_TXT_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA "DHE-RSA-CAMELLIA128-SHA"

#define TLS1_TXT_ADH_WITH_CAMELLIA_128_CBC_SHA "ADH-CAMELLIA128-SHA"

#define TLS1_TXT_RSA_WITH_CAMELLIA_256_CBC_SHA "CAMELLIA256-SHA"

#define TLS1_TXT_DH_DSS_WITH_CAMELLIA_256_CBC_SHA "DH-DSS-CAMELLIA256-SHA"

#define TLS1_TXT_DH_RSA_WITH_CAMELLIA_256_CBC_SHA "DH-RSA-CAMELLIA256-SHA"

#define TLS1_TXT_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA "DHE-DSS-CAMELLIA256-SHA"

#define TLS1_TXT_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA "DHE-RSA-CAMELLIA256-SHA"

#define TLS1_TXT_ADH_WITH_CAMELLIA_256_CBC_SHA "ADH-CAMELLIA256-SHA"

#define TLS1_TXT_RSA_WITH_CAMELLIA_128_CBC_SHA256 "CAMELLIA128-SHA256"

#define TLS1_TXT_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 "DH-DSS-CAMELLIA128-SHA256"

#define TLS1_TXT_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 "DH-RSA-CAMELLIA128-SHA256"

#define TLS1_TXT_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 "DHE-DSS-CAMELLIA128-SHA256"

#define TLS1_TXT_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 "DHE-RSA-CAMELLIA128-SHA256"

#define TLS1_TXT_ADH_WITH_CAMELLIA_128_CBC_SHA256 "ADH-CAMELLIA128-SHA256"

#define TLS1_TXT_RSA_WITH_CAMELLIA_256_CBC_SHA256 "CAMELLIA256-SHA256"

#define TLS1_TXT_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 "DH-DSS-CAMELLIA256-SHA256"

#define TLS1_TXT_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 "DH-RSA-CAMELLIA256-SHA256"

#define TLS1_TXT_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 "DHE-DSS-CAMELLIA256-SHA256"

#define TLS1_TXT_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 "DHE-RSA-CAMELLIA256-SHA256"

#define TLS1_TXT_ADH_WITH_CAMELLIA_256_CBC_SHA256 "ADH-CAMELLIA256-SHA256"

#define TLS1_TXT_PSK_WITH_CAMELLIA_128_CBC_SHA256 "PSK-CAMELLIA128-SHA256"

#define TLS1_TXT_PSK_WITH_CAMELLIA_256_CBC_SHA384 "PSK-CAMELLIA256-SHA384"

#define TLS1_TXT_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 "DHE-PSK-CAMELLIA128-SHA256"

#define TLS1_TXT_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 "DHE-PSK-CAMELLIA256-SHA384"

#define TLS1_TXT_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 "RSA-PSK-CAMELLIA128-SHA256"

#define TLS1_TXT_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 "RSA-PSK-CAMELLIA256-SHA384"

#define TLS1_TXT_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 "ECDHE-PSK-CAMELLIA128-SHA256"

#define TLS1_TXT_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 "ECDHE-PSK-CAMELLIA256-SHA384"

#define TLS1_TXT_RSA_WITH_SEED_SHA "SEED-SHA"

#define TLS1_TXT_DH_DSS_WITH_SEED_SHA "DH-DSS-SEED-SHA"

#define TLS1_TXT_DH_RSA_WITH_SEED_SHA "DH-RSA-SEED-SHA"

#define TLS1_TXT_DHE_DSS_WITH_SEED_SHA "DHE-DSS-SEED-SHA"

#define TLS1_TXT_DHE_RSA_WITH_SEED_SHA "DHE-RSA-SEED-SHA"

#define TLS1_TXT_ADH_WITH_SEED_SHA "ADH-SEED-SHA"

#define TLS1_TXT_RSA_WITH_NULL_SHA256 "NULL-SHA256"

#define TLS1_TXT_RSA_WITH_AES_128_SHA256 "AES128-SHA256"

#define TLS1_TXT_RSA_WITH_AES_256_SHA256 "AES256-SHA256"

#define TLS1_TXT_DH_DSS_WITH_AES_128_SHA256 "DH-DSS-AES128-SHA256"

#define TLS1_TXT_DH_RSA_WITH_AES_128_SHA256 "DH-RSA-AES128-SHA256"

#define TLS1_TXT_DHE_DSS_WITH_AES_128_SHA256 "DHE-DSS-AES128-SHA256"

#define TLS1_TXT_DHE_RSA_WITH_AES_128_SHA256 "DHE-RSA-AES128-SHA256"

#define TLS1_TXT_DH_DSS_WITH_AES_256_SHA256 "DH-DSS-AES256-SHA256"

#define TLS1_TXT_DH_RSA_WITH_AES_256_SHA256 "DH-RSA-AES256-SHA256"

#define TLS1_TXT_DHE_DSS_WITH_AES_256_SHA256 "DHE-DSS-AES256-SHA256"

#define TLS1_TXT_DHE_RSA_WITH_AES_256_SHA256 "DHE-RSA-AES256-SHA256"

#define TLS1_TXT_ADH_WITH_AES_128_SHA256 "ADH-AES128-SHA256"

#define TLS1_TXT_ADH_WITH_AES_256_SHA256 "ADH-AES256-SHA256"

#define TLS1_TXT_RSA_WITH_AES_128_GCM_SHA256 "AES128-GCM-SHA256"

#define TLS1_TXT_RSA_WITH_AES_256_GCM_SHA384 "AES256-GCM-SHA384"

#define TLS1_TXT_DHE_RSA_WITH_AES_128_GCM_SHA256 "DHE-RSA-AES128-GCM-SHA256"

#define TLS1_TXT_DHE_RSA_WITH_AES_256_GCM_SHA384 "DHE-RSA-AES256-GCM-SHA384"

#define TLS1_TXT_DH_RSA_WITH_AES_128_GCM_SHA256 "DH-RSA-AES128-GCM-SHA256"

#define TLS1_TXT_DH_RSA_WITH_AES_256_GCM_SHA384 "DH-RSA-AES256-GCM-SHA384"

#define TLS1_TXT_DHE_DSS_WITH_AES_128_GCM_SHA256 "DHE-DSS-AES128-GCM-SHA256"

#define TLS1_TXT_DHE_DSS_WITH_AES_256_GCM_SHA384 "DHE-DSS-AES256-GCM-SHA384"

#define TLS1_TXT_DH_DSS_WITH_AES_128_GCM_SHA256 "DH-DSS-AES128-GCM-SHA256"

#define TLS1_TXT_DH_DSS_WITH_AES_256_GCM_SHA384 "DH-DSS-AES256-GCM-SHA384"

#define TLS1_TXT_ADH_WITH_AES_128_GCM_SHA256 "ADH-AES128-GCM-SHA256"

#define TLS1_TXT_ADH_WITH_AES_256_GCM_SHA384 "ADH-AES256-GCM-SHA384"

#define TLS1_TXT_RSA_WITH_AES_128_CCM "AES128-CCM"

#define TLS1_TXT_RSA_WITH_AES_256_CCM "AES256-CCM"

#define TLS1_TXT_DHE_RSA_WITH_AES_128_CCM "DHE-RSA-AES128-CCM"

#define TLS1_TXT_DHE_RSA_WITH_AES_256_CCM "DHE-RSA-AES256-CCM"

#define TLS1_TXT_RSA_WITH_AES_128_CCM_8 "AES128-CCM8"

#define TLS1_TXT_RSA_WITH_AES_256_CCM_8 "AES256-CCM8"

#define TLS1_TXT_DHE_RSA_WITH_AES_128_CCM_8 "DHE-RSA-AES128-CCM8"

#define TLS1_TXT_DHE_RSA_WITH_AES_256_CCM_8 "DHE-RSA-AES256-CCM8"

#define TLS1_TXT_PSK_WITH_AES_128_CCM "PSK-AES128-CCM"

#define TLS1_TXT_PSK_WITH_AES_256_CCM "PSK-AES256-CCM"

#define TLS1_TXT_DHE_PSK_WITH_AES_128_CCM "DHE-PSK-AES128-CCM"

#define TLS1_TXT_DHE_PSK_WITH_AES_256_CCM "DHE-PSK-AES256-CCM"

#define TLS1_TXT_PSK_WITH_AES_128_CCM_8 "PSK-AES128-CCM8"

#define TLS1_TXT_PSK_WITH_AES_256_CCM_8 "PSK-AES256-CCM8"

#define TLS1_TXT_DHE_PSK_WITH_AES_128_CCM_8 "DHE-PSK-AES128-CCM8"

#define TLS1_TXT_DHE_PSK_WITH_AES_256_CCM_8 "DHE-PSK-AES256-CCM8"

#define TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_CCM "ECDHE-ECDSA-AES128-CCM"

#define TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_CCM "ECDHE-ECDSA-AES256-CCM"

#define TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_CCM_8 "ECDHE-ECDSA-AES128-CCM8"

#define TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_CCM_8 "ECDHE-ECDSA-AES256-CCM8"

#define TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_SHA256 "ECDHE-ECDSA-AES128-SHA256"

#define TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_SHA384 "ECDHE-ECDSA-AES256-SHA384"

#define TLS1_TXT_ECDH_ECDSA_WITH_AES_128_SHA256 "ECDH-ECDSA-AES128-SHA256"

#define TLS1_TXT_ECDH_ECDSA_WITH_AES_256_SHA384 "ECDH-ECDSA-AES256-SHA384"

#define TLS1_TXT_ECDHE_RSA_WITH_AES_128_SHA256 "ECDHE-RSA-AES128-SHA256"

#define TLS1_TXT_ECDHE_RSA_WITH_AES_256_SHA384 "ECDHE-RSA-AES256-SHA384"

#define TLS1_TXT_ECDH_RSA_WITH_AES_128_SHA256 "ECDH-RSA-AES128-SHA256"

#define TLS1_TXT_ECDH_RSA_WITH_AES_256_SHA384 "ECDH-RSA-AES256-SHA384"

#define TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 "ECDHE-ECDSA-AES128-GCM-SHA256"

#define TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 "ECDHE-ECDSA-AES256-GCM-SHA384"

#define TLS1_TXT_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 "ECDH-ECDSA-AES128-GCM-SHA256"

#define TLS1_TXT_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 "ECDH-ECDSA-AES256-GCM-SHA384"

#define TLS1_TXT_ECDHE_RSA_WITH_AES_128_GCM_SHA256 "ECDHE-RSA-AES128-GCM-SHA256"

#define TLS1_TXT_ECDHE_RSA_WITH_AES_256_GCM_SHA384 "ECDHE-RSA-AES256-GCM-SHA384"

#define TLS1_TXT_ECDH_RSA_WITH_AES_128_GCM_SHA256 "ECDH-RSA-AES128-GCM-SHA256"

#define TLS1_TXT_ECDH_RSA_WITH_AES_256_GCM_SHA384 "ECDH-RSA-AES256-GCM-SHA384"

#define TLS1_TXT_ECDHE_PSK_WITH_RC4_128_SHA "ECDHE-PSK-RC4-SHA"

#define TLS1_TXT_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA "ECDHE-PSK-3DES-EDE-CBC-SHA"

#define TLS1_TXT_ECDHE_PSK_WITH_AES_128_CBC_SHA "ECDHE-PSK-AES128-CBC-SHA"

#define TLS1_TXT_ECDHE_PSK_WITH_AES_256_CBC_SHA "ECDHE-PSK-AES256-CBC-SHA"

#define TLS1_TXT_ECDHE_PSK_WITH_AES_128_CBC_SHA256 "ECDHE-PSK-AES128-CBC-SHA256"

#define TLS1_TXT_ECDHE_PSK_WITH_AES_256_CBC_SHA384 "ECDHE-PSK-AES256-CBC-SHA384"

#define TLS1_TXT_ECDHE_PSK_WITH_NULL_SHA "ECDHE-PSK-NULL-SHA"

#define TLS1_TXT_ECDHE_PSK_WITH_NULL_SHA256 "ECDHE-PSK-NULL-SHA256"

#define TLS1_TXT_ECDHE_PSK_WITH_NULL_SHA384 "ECDHE-PSK-NULL-SHA384"

#define TLS1_TXT_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 "ECDHE-ECDSA-CAMELLIA128-SHA256"

#define TLS1_TXT_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 "ECDHE-ECDSA-CAMELLIA256-SHA384"

#define TLS1_TXT_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 "ECDH-ECDSA-CAMELLIA128-SHA256"

#define TLS1_TXT_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 "ECDH-ECDSA-CAMELLIA256-SHA384"

#define TLS1_TXT_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 "ECDHE-RSA-CAMELLIA128-SHA256"

#define TLS1_TXT_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 "ECDHE-RSA-CAMELLIA256-SHA384"

#define TLS1_TXT_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 "ECDH-RSA-CAMELLIA128-SHA256"

#define TLS1_TXT_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 "ECDH-RSA-CAMELLIA256-SHA384"

#define TLS1_TXT_ECDHE_RSA_WITH_CHACHA20_POLY1305 "ECDHE-RSA-CHACHA20-POLY1305"

#define TLS1_TXT_ECDHE_ECDSA_WITH_CHACHA20_POLY1305 "ECDHE-ECDSA-CHACHA20-POLY1305"

#define TLS1_TXT_DHE_RSA_WITH_CHACHA20_POLY1305 "DHE-RSA-CHACHA20-POLY1305"

#define TLS1_TXT_PSK_WITH_CHACHA20_POLY1305 "PSK-CHACHA20-POLY1305"

#define TLS1_TXT_ECDHE_PSK_WITH_CHACHA20_POLY1305 "ECDHE-PSK-CHACHA20-POLY1305"

#define TLS1_TXT_DHE_PSK_WITH_CHACHA20_POLY1305 "DHE-PSK-CHACHA20-POLY1305"

#define TLS1_TXT_RSA_PSK_WITH_CHACHA20_POLY1305 "RSA-PSK-CHACHA20-POLY1305"

#define TLS1_TXT_RSA_WITH_ARIA_128_GCM_SHA256 "ARIA128-GCM-SHA256"

#define TLS1_TXT_RSA_WITH_ARIA_256_GCM_SHA384 "ARIA256-GCM-SHA384"

#define TLS1_TXT_DHE_RSA_WITH_ARIA_128_GCM_SHA256 "DHE-RSA-ARIA128-GCM-SHA256"

#define TLS1_TXT_DHE_RSA_WITH_ARIA_256_GCM_SHA384 "DHE-RSA-ARIA256-GCM-SHA384"

#define TLS1_TXT_DH_RSA_WITH_ARIA_128_GCM_SHA256 "DH-RSA-ARIA128-GCM-SHA256"

#define TLS1_TXT_DH_RSA_WITH_ARIA_256_GCM_SHA384 "DH-RSA-ARIA256-GCM-SHA384"

#define TLS1_TXT_DHE_DSS_WITH_ARIA_128_GCM_SHA256 "DHE-DSS-ARIA128-GCM-SHA256"

#define TLS1_TXT_DHE_DSS_WITH_ARIA_256_GCM_SHA384 "DHE-DSS-ARIA256-GCM-SHA384"

#define TLS1_TXT_DH_DSS_WITH_ARIA_128_GCM_SHA256 "DH-DSS-ARIA128-GCM-SHA256"

#define TLS1_TXT_DH_DSS_WITH_ARIA_256_GCM_SHA384 "DH-DSS-ARIA256-GCM-SHA384"

#define TLS1_TXT_DH_anon_WITH_ARIA_128_GCM_SHA256 "ADH-ARIA128-GCM-SHA256"

#define TLS1_TXT_DH_anon_WITH_ARIA_256_GCM_SHA384 "ADH-ARIA256-GCM-SHA384"

#define TLS1_TXT_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 "ECDHE-ECDSA-ARIA128-GCM-SHA256"

#define TLS1_TXT_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 "ECDHE-ECDSA-ARIA256-GCM-SHA384"

#define TLS1_TXT_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 "ECDH-ECDSA-ARIA128-GCM-SHA256"

#define TLS1_TXT_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 "ECDH-ECDSA-ARIA256-GCM-SHA384"

#define TLS1_TXT_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 "ECDHE-ARIA128-GCM-SHA256"

#define TLS1_TXT_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 "ECDHE-ARIA256-GCM-SHA384"

#define TLS1_TXT_ECDH_RSA_WITH_ARIA_128_GCM_SHA256 "ECDH-ARIA128-GCM-SHA256"

#define TLS1_TXT_ECDH_RSA_WITH_ARIA_256_GCM_SHA384 "ECDH-ARIA256-GCM-SHA384"

#define TLS1_TXT_PSK_WITH_ARIA_128_GCM_SHA256 "PSK-ARIA128-GCM-SHA256"

#define TLS1_TXT_PSK_WITH_ARIA_256_GCM_SHA384 "PSK-ARIA256-GCM-SHA384"

#define TLS1_TXT_DHE_PSK_WITH_ARIA_128_GCM_SHA256 "DHE-PSK-ARIA128-GCM-SHA256"

#define TLS1_TXT_DHE_PSK_WITH_ARIA_256_GCM_SHA384 "DHE-PSK-ARIA256-GCM-SHA384"

#define TLS1_TXT_RSA_PSK_WITH_ARIA_128_GCM_SHA256 "RSA-PSK-ARIA128-GCM-SHA256"

#define TLS1_TXT_RSA_PSK_WITH_ARIA_256_GCM_SHA384 "RSA-PSK-ARIA256-GCM-SHA384"

#define TLS_CT_RSA_SIGN 1

#define TLS_CT_DSS_SIGN 2

#define TLS_CT_RSA_FIXED_DH 3

#define TLS_CT_DSS_FIXED_DH 4

#define TLS_CT_ECDSA_SIGN 64

#define TLS_CT_RSA_FIXED_ECDH 65

#define TLS_CT_ECDSA_FIXED_ECDH 66

#define TLS_CT_GOST01_SIGN 22

#define TLS_CT_GOST12_IANA_SIGN 67

#define TLS_CT_GOST12_IANA_512_SIGN 68

#define TLS_CT_GOST12_LEGACY_SIGN 238

#define TLS_CT_GOST12_LEGACY_512_SIGN 239

#define TLS_CT_GOST12_SIGN TLS_CT_GOST12_LEGACY_SIGN

#define TLS_CT_GOST12_512_SIGN TLS_CT_GOST12_LEGACY_512_SIGN

#define TLS_CT_NUMBER 12

#define TLS1_FINISH_MAC_LENGTH 12

#define TLS_MD_MAX_CONST_SIZE 22

#define TLS_MD_CLIENT_FINISH_CONST "\x63\x6c\x69\x65\x6e\x74\x20\x66\x69\x6e\x69\x73\x68\x65\x64"

#define TLS_MD_CLIENT_FINISH_CONST_SIZE 15

#define TLS_MD_SERVER_FINISH_CONST "\x73\x65\x72\x76\x65\x72\x20\x66\x69\x6e\x69\x73\x68\x65\x64"

#define TLS_MD_SERVER_FINISH_CONST_SIZE 15

#define TLS_MD_SERVER_WRITE_KEY_CONST "\x73\x65\x72\x76\x65\x72\x20\x77\x72\x69\x74\x65\x20\x6b\x65\x79"

#define TLS_MD_SERVER_WRITE_KEY_CONST_SIZE 16

#define TLS_MD_KEY_EXPANSION_CONST "\x6b\x65\x79\x20\x65\x78\x70\x61\x6e\x73\x69\x6f\x6e"

#define TLS_MD_KEY_EXPANSION_CONST_SIZE 13

#define TLS_MD_CLIENT_WRITE_KEY_CONST "\x63\x6c\x69\x65\x6e\x74\x20\x77\x72\x69\x74\x65\x20\x6b\x65\x79"

#define TLS_MD_CLIENT_WRITE_KEY_CONST_SIZE 16

#define TLS_MD_IV_BLOCK_CONST "\x49\x56\x20\x62\x6c\x6f\x63\x6b"

#define TLS_MD_IV_BLOCK_CONST_SIZE 8

#define TLS_MD_MASTER_SECRET_CONST "\x6d\x61\x73\x74\x65\x72\x20\x73\x65\x63\x72\x65\x74"

#define TLS_MD_MASTER_SECRET_CONST_SIZE 13

#define TLS_MD_EXTENDED_MASTER_SECRET_CONST "\x65\x78\x74\x65\x6e\x64\x65\x64\x20\x6d\x61\x73\x74\x65\x72\x20\x73\x65\x63\x72\x65\x74"

#define TLS_MD_EXTENDED_MASTER_SECRET_CONST_SIZE 22

#define OPENSSL_TRACE_H 

#define OSSL_TRACE_CATEGORY_ALL 0

#define OSSL_TRACE_CATEGORY_TRACE 1

#define OSSL_TRACE_CATEGORY_INIT 2

#define OSSL_TRACE_CATEGORY_TLS 3

#define OSSL_TRACE_CATEGORY_TLS_CIPHER 4

#define OSSL_TRACE_CATEGORY_CONF 5

#define OSSL_TRACE_CATEGORY_ENGINE_TABLE 6

#define OSSL_TRACE_CATEGORY_ENGINE_REF_COUNT 7

#define OSSL_TRACE_CATEGORY_PKCS5V2 8

#define OSSL_TRACE_CATEGORY_PKCS12_KEYGEN 9

#define OSSL_TRACE_CATEGORY_PKCS12_DECRYPT 10

#define OSSL_TRACE_CATEGORY_X509V3_POLICY 11

#define OSSL_TRACE_CATEGORY_BN_CTX 12

#define OSSL_TRACE_CATEGORY_CMP 13

#define OSSL_TRACE_CATEGORY_STORE 14

#define OSSL_TRACE_CATEGORY_DECODER 15

#define OSSL_TRACE_CATEGORY_ENCODER 16

#define OSSL_TRACE_CATEGORY_REF_COUNT 17

#define OSSL_TRACE_CATEGORY_HTTP 18

#define OSSL_TRACE_CATEGORY_NUM 19

#define OSSL_TRACE_CTRL_BEGIN 0

#define OSSL_TRACE_CTRL_WRITE 1

#define OSSL_TRACE_CTRL_END 2

#define OSSL_TRACE_BEGIN (category)\
	do { \\
	BIO *trc_out = OSSL_trace_begin(OSSL_TRACE_CATEGORY_##category); \\
	\\
	if (trc_out != NULL)

#define OSSL_TRACE_END (category)\
	OSSL_trace_end(OSSL_TRACE_CATEGORY_##category, trc_out); \\
	} while (0)

#define OSSL_TRACE_CANCEL (category)\
	OSSL_trace_end(OSSL_TRACE_CATEGORY_##category, trc_out) \\
	# else

#define OSSL_TRACE_ENABLED (category)\
	OSSL_trace_enabled(OSSL_TRACE_CATEGORY_##category)

#define OSSL_TRACEV (category, args)\
	OSSL_TRACE_BEGIN(category) \\
	BIO_printf args; \\
	OSSL_TRACE_END(category)

#define OSSL_TRACE (category, text)\
	OSSL_TRACEV(category, (trc_out, "%s", text))

#define OSSL_TRACE1 (category, format, arg1)\
	OSSL_TRACEV(category, (trc_out, format, arg1))

#define OSSL_TRACE2 (category, format, arg1, arg2)\
	OSSL_TRACEV(category, (trc_out, format, arg1, arg2))

#define OSSL_TRACE3 (category, format, arg1, arg2, arg3)\
	OSSL_TRACEV(category, (trc_out, format, arg1, arg2, arg3))

#define OSSL_TRACE4 (category, format, arg1, arg2, arg3, arg4)\
	OSSL_TRACEV(category, (trc_out, format, arg1, arg2, arg3, arg4))

#define OSSL_TRACE5 (category, format, arg1, arg2, arg3, arg4, arg5)\
	OSSL_TRACEV(category, (trc_out, format, arg1, arg2, arg3, arg4, arg5))

#define OSSL_TRACE6 (category, format, arg1, arg2, arg3, arg4, arg5, arg6)\
	OSSL_TRACEV(category, (trc_out, format, arg1, arg2, arg3, arg4, arg5, arg6))

#define OSSL_TRACE7 (category, format, arg1, arg2, arg3, arg4, arg5, arg6, arg7)\
	OSSL_TRACEV(category, (trc_out, format, arg1, arg2, arg3, arg4, arg5, arg6, arg7))

#define OSSL_TRACE8 (category, format, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)\
	OSSL_TRACEV(category, (trc_out, format, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8))

#define OSSL_TRACE9 (category, format, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9)\
	OSSL_TRACEV(category, (trc_out, format, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9))

#define OSSL_TRACE_STRING_MAX 80

#define OSSL_TRACE_STRING (category, text, full, data, len)\
	OSSL_TRACE_BEGIN(category) { \\
	OSSL_trace_string(trc_out, text, full, data, len);  \\
	} OSSL_TRACE_END(category)

#define OPENSSL_TS_H 

#define HEADER_TS_H 

#define TS_STATUS_GRANTED 0

#define TS_STATUS_GRANTED_WITH_MODS 1

#define TS_STATUS_REJECTION 2

#define TS_STATUS_WAITING 3

#define TS_STATUS_REVOCATION_WARNING 4

#define TS_STATUS_REVOCATION_NOTIFICATION 5

#define TS_INFO_BAD_ALG 0

#define TS_INFO_BAD_REQUEST 2

#define TS_INFO_BAD_DATA_FORMAT 5

#define TS_INFO_TIME_NOT_AVAILABLE 14

#define TS_INFO_UNACCEPTED_POLICY 15

#define TS_INFO_UNACCEPTED_EXTENSION 16

#define TS_INFO_ADD_INFO_NOT_AVAILABLE 17

#define TS_INFO_SYSTEM_FAILURE 25

#define TS_TSA_NAME 0x01

#define TS_ORDERING 0x02

#define TS_ESS_CERT_ID_CHAIN 0x04

#define TS_MAX_CLOCK_PRECISION_DIGITS 6

#define TS_MAX_STATUS_LENGTH (1024 * 1024)

#define TS_VFY_SIGNATURE (1u << 0)

#define TS_VFY_VERSION (1u << 1)

#define TS_VFY_POLICY (1u << 2)

#define TS_VFY_IMPRINT (1u << 3)

#define TS_VFY_DATA (1u << 4)

#define TS_VFY_NONCE (1u << 5)

#define TS_VFY_SIGNER (1u << 6)

#define TS_VFY_TSA_NAME (1u << 7)

#define TS_VFY_ALL_IMPRINT (TS_VFY_SIGNATURE\
	| TS_VFY_VERSION       \\
	| TS_VFY_POLICY        \\
	| TS_VFY_IMPRINT       \\
	| TS_VFY_NONCE         \\
	| TS_VFY_SIGNER        \\
	| TS_VFY_TSA_NAME)

#define TS_VFY_ALL_DATA (TS_VFY_SIGNATURE\
	| TS_VFY_VERSION       \\
	| TS_VFY_POLICY        \\
	| TS_VFY_DATA          \\
	| TS_VFY_NONCE         \\
	| TS_VFY_SIGNER        \\
	| TS_VFY_TSA_NAME)

#define TS_VERIFY_CTS_set_certs (ctx, cert) TS_VERIFY_CTX_set_certs(ctx,cert)

#define OPENSSL_TSERR_H 

#define TS_R_BAD_PKCS7_TYPE 132

#define TS_R_BAD_TYPE 133

#define TS_R_CANNOT_LOAD_CERT 137

#define TS_R_CANNOT_LOAD_KEY 138

#define TS_R_CERTIFICATE_VERIFY_ERROR 100

#define TS_R_COULD_NOT_SET_ENGINE 127

#define TS_R_COULD_NOT_SET_TIME 115

#define TS_R_DETACHED_CONTENT 134

#define TS_R_ESS_ADD_SIGNING_CERT_ERROR 116

#define TS_R_ESS_ADD_SIGNING_CERT_V2_ERROR 139

#define TS_R_ESS_SIGNING_CERTIFICATE_ERROR 101

#define TS_R_INVALID_NULL_POINTER 102

#define TS_R_INVALID_SIGNER_CERTIFICATE_PURPOSE 117

#define TS_R_MESSAGE_IMPRINT_MISMATCH 103

#define TS_R_NONCE_MISMATCH 104

#define TS_R_NONCE_NOT_RETURNED 105

#define TS_R_NO_CONTENT 106

#define TS_R_NO_TIME_STAMP_TOKEN 107

#define TS_R_PKCS7_ADD_SIGNATURE_ERROR 118

#define TS_R_PKCS7_ADD_SIGNED_ATTR_ERROR 119

#define TS_R_PKCS7_TO_TS_TST_INFO_FAILED 129

#define TS_R_POLICY_MISMATCH 108

#define TS_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE 120

#define TS_R_RESPONSE_SETUP_ERROR 121

#define TS_R_SIGNATURE_FAILURE 109

#define TS_R_THERE_MUST_BE_ONE_SIGNER 110

#define TS_R_TIME_SYSCALL_ERROR 122

#define TS_R_TOKEN_NOT_PRESENT 130

#define TS_R_TOKEN_PRESENT 131

#define TS_R_TSA_NAME_MISMATCH 111

#define TS_R_TSA_UNTRUSTED 112

#define TS_R_TST_INFO_SETUP_ERROR 123

#define TS_R_TS_DATASIGN 124

#define TS_R_UNACCEPTABLE_POLICY 125

#define TS_R_UNSUPPORTED_MD_ALGORITHM 126

#define TS_R_UNSUPPORTED_VERSION 113

#define TS_R_VAR_BAD_VALUE 135

#define TS_R_VAR_LOOKUP_FAILURE 136

#define TS_R_WRONG_CONTENT_TYPE 114

#define OPENSSL_TXT_DB_H 

#define HEADER_TXT_DB_H 

#define DB_ERROR_OK 0

#define DB_ERROR_MALLOC 1

#define DB_ERROR_INDEX_CLASH 2

#define DB_ERROR_INDEX_OUT_OF_RANGE 3

#define DB_ERROR_NO_INDEX 4

#define DB_ERROR_INSERT_INDEX_CLASH 5

#define DB_ERROR_WRONG_NUM_FIELDS 6

#define WINCRYPT_USE_SYMBOL_PREFIX 

#define OPENSSL_TYPES_H 

#define ASN1_INTEGER ASN1_STRING

#define ASN1_ENUMERATED ASN1_STRING

#define ASN1_BIT_STRING ASN1_STRING

#define ASN1_OCTET_STRING ASN1_STRING

#define ASN1_PRINTABLESTRING ASN1_STRING

#define ASN1_T61STRING ASN1_STRING

#define ASN1_IA5STRING ASN1_STRING

#define ASN1_UTCTIME ASN1_STRING

#define ASN1_GENERALIZEDTIME ASN1_STRING

#define ASN1_TIME ASN1_STRING

#define ASN1_GENERALSTRING ASN1_STRING

#define ASN1_UNIVERSALSTRING ASN1_STRING

#define ASN1_BMPSTRING ASN1_STRING

#define ASN1_VISIBLESTRING ASN1_STRING

#define ASN1_UTF8STRING ASN1_STRING

#define UI_INPUT_FLAG_ECHO 0x01

#define UI_INPUT_FLAG_DEFAULT_PWD 0x02

#define UI_INPUT_FLAG_USER_BASE 16

#define UI_CTRL_PRINT_ERRORS 1

#define UI_CTRL_IS_REDOABLE 2

#define UI_set_app_data (s,arg)         UI_set_ex_data(s,0,arg)

#define UI_get_app_data (s)             UI_get_ex_data(s,0)

#define UI_get_ex_new_index (l, p, newf, dupf, freef)\
	CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_UI, l, p, newf, dupf, freef)

#define OPENSSL_UIERR_H 

#define UI_R_COMMON_OK_AND_CANCEL_CHARACTERS 104

#define UI_R_INDEX_TOO_LARGE 102

#define UI_R_INDEX_TOO_SMALL 103

#define UI_R_NO_RESULT_BUFFER 105

#define UI_R_PROCESSING_ERROR 107

#define UI_R_RESULT_TOO_LARGE 100

#define UI_R_RESULT_TOO_SMALL 101

#define UI_R_SYSASSIGN_ERROR 109

#define UI_R_SYSDASSGN_ERROR 110

#define UI_R_SYSQIOW_ERROR 111

#define UI_R_UNKNOWN_CONTROL_COMMAND 106

#define UI_R_UNKNOWN_TTYGET_ERRNO_VALUE 108

#define UI_R_USER_DATA_DUPLICATION_UNSUPPORTED 112

#define OPENSSL_WHRLPOOL_H 

#define HEADER_WHRLPOOL_H 

#define WHIRLPOOL_DIGEST_LENGTH (512/8)

#define WHIRLPOOL_BBLOCK 512

#define WHIRLPOOL_COUNTER (256/8)

#define OPENSSL_X509_H 

#define HEADER_X509_H 

#define X509_SIG_INFO_VALID 0x1

#define X509_SIG_INFO_TLS 0x2

#define X509_FILETYPE_PEM 1

#define X509_FILETYPE_ASN1 2

#define X509_FILETYPE_DEFAULT 3

#define X509v3_KU_DIGITAL_SIGNATURE 0x0080

#define X509v3_KU_NON_REPUDIATION 0x0040

#define X509v3_KU_KEY_ENCIPHERMENT 0x0020

#define X509v3_KU_DATA_ENCIPHERMENT 0x0010

#define X509v3_KU_KEY_AGREEMENT 0x0008

#define X509v3_KU_KEY_CERT_SIGN 0x0004

#define X509v3_KU_CRL_SIGN 0x0002

#define X509v3_KU_ENCIPHER_ONLY 0x0001

#define X509v3_KU_DECIPHER_ONLY 0x8000

#define X509v3_KU_UNDEF 0xffff

#define X509_EX_V_NETSCAPE_HACK 0x8000

#define X509_EX_V_INIT 0x0001

#define X509_FLAG_COMPAT 0

#define X509_FLAG_NO_HEADER 1L

#define X509_FLAG_NO_VERSION (1L << 1)

#define X509_FLAG_NO_SERIAL (1L << 2)

#define X509_FLAG_NO_SIGNAME (1L << 3)

#define X509_FLAG_NO_ISSUER (1L << 4)

#define X509_FLAG_NO_VALIDITY (1L << 5)

#define X509_FLAG_NO_SUBJECT (1L << 6)

#define X509_FLAG_NO_PUBKEY (1L << 7)

#define X509_FLAG_NO_EXTENSIONS (1L << 8)

#define X509_FLAG_NO_SIGDUMP (1L << 9)

#define X509_FLAG_NO_AUX (1L << 10)

#define X509_FLAG_NO_ATTRIBUTES (1L << 11)

#define X509_FLAG_NO_IDS (1L << 12)

#define X509_FLAG_EXTENSIONS_ONLY_KID (1L << 13)

#define XN_FLAG_SEP_MASK (0xf << 16)

#define XN_FLAG_COMPAT 0

#define XN_FLAG_SEP_COMMA_PLUS (1 << 16)

#define XN_FLAG_SEP_CPLUS_SPC (2 << 16)

#define XN_FLAG_SEP_SPLUS_SPC (3 << 16)

#define XN_FLAG_SEP_MULTILINE (4 << 16)

#define XN_FLAG_DN_REV (1 << 20)

#define XN_FLAG_FN_MASK (0x3 << 21)

#define XN_FLAG_FN_SN 0

#define XN_FLAG_FN_LN (1 << 21)

#define XN_FLAG_FN_OID (2 << 21)

#define XN_FLAG_FN_NONE (3 << 21)

#define XN_FLAG_SPC_EQ (1 << 23)

#define XN_FLAG_DUMP_UNKNOWN_FIELDS (1 << 24)

#define XN_FLAG_FN_ALIGN (1 << 25)

#define XN_FLAG_RFC2253 (ASN1_STRFLGS_RFC2253 |\
	XN_FLAG_SEP_COMMA_PLUS | \\
	XN_FLAG_DN_REV | \\
	XN_FLAG_FN_SN | \\
	XN_FLAG_DUMP_UNKNOWN_FIELDS)

#define XN_FLAG_ONELINE (ASN1_STRFLGS_RFC2253 |\
	ASN1_STRFLGS_ESC_QUOTE | \\
	XN_FLAG_SEP_CPLUS_SPC | \\
	XN_FLAG_SPC_EQ | \\
	XN_FLAG_FN_SN)

#define XN_FLAG_MULTILINE (ASN1_STRFLGS_ESC_CTRL |\
	ASN1_STRFLGS_ESC_MSB | \\
	XN_FLAG_SEP_MULTILINE | \\
	XN_FLAG_SPC_EQ | \\
	XN_FLAG_FN_LN | \\
	XN_FLAG_FN_ALIGN)

#define X509_EXT_PACK_UNKNOWN 1

#define X509_EXT_PACK_STRING 2

#define X509_extract_key (x)     X509_get_pubkey(x)

#define X509_REQ_extract_key (a) X509_REQ_get_pubkey(a)

#define X509_name_cmp (a,b)      X509_NAME_cmp((a),(b))

#define X509_http_nbio (rctx, pcert)\
	OSSL_HTTP_REQ_CTX_nbio_d2i(rctx, pcert, ASN1_ITEM_rptr(X509))

#define X509_CRL_http_nbio (rctx, pcrl)\
	OSSL_HTTP_REQ_CTX_nbio_d2i(rctx, pcrl, ASN1_ITEM_rptr(X509_CRL))

#define X509_get_ex_new_index (l, p, newf, dupf, freef)\
	CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_X509, l, p, newf, dupf, freef)

#define X509_VERSION_1 0

#define X509_VERSION_2 1

#define X509_VERSION_3 2

#define X509_get_notBefore X509_getm_notBefore

#define X509_get_notAfter X509_getm_notAfter

#define X509_set_notBefore X509_set1_notBefore

#define X509_set_notAfter X509_set1_notAfter

#define X509_REQ_VERSION_1 0

#define X509_CRL_VERSION_1 0

#define X509_CRL_VERSION_2 1

#define X509_CRL_set_lastUpdate X509_CRL_set1_lastUpdate

#define X509_CRL_set_nextUpdate X509_CRL_set1_nextUpdate

#define X509_ADD_FLAG_DEFAULT 0

#define X509_ADD_FLAG_UP_REF 0x1

#define X509_ADD_FLAG_PREPEND 0x2

#define X509_ADD_FLAG_NO_DUP 0x4

#define X509_ADD_FLAG_NO_SS 0x8

#define X509_NAME_hash (x) X509_NAME_hash_ex(x, NULL, NULL, NULL)

#define OPENSSL_X509ERR_H 

#define X509_R_AKID_MISMATCH 110

#define X509_R_BAD_SELECTOR 133

#define X509_R_BAD_X509_FILETYPE 100

#define X509_R_BASE64_DECODE_ERROR 118

#define X509_R_CANT_CHECK_DH_KEY 114

#define X509_R_CERTIFICATE_VERIFICATION_FAILED 139

#define X509_R_CERT_ALREADY_IN_HASH_TABLE 101

#define X509_R_CRL_ALREADY_DELTA 127

#define X509_R_CRL_VERIFY_FAILURE 131

#define X509_R_DUPLICATE_ATTRIBUTE 140

#define X509_R_ERROR_GETTING_MD_BY_NID 141

#define X509_R_ERROR_USING_SIGINF_SET 142

#define X509_R_IDP_MISMATCH 128

#define X509_R_INVALID_ATTRIBUTES 138

#define X509_R_INVALID_DIRECTORY 113

#define X509_R_INVALID_DISTPOINT 143

#define X509_R_INVALID_FIELD_NAME 119

#define X509_R_INVALID_TRUST 123

#define X509_R_ISSUER_MISMATCH 129

#define X509_R_KEY_TYPE_MISMATCH 115

#define X509_R_KEY_VALUES_MISMATCH 116

#define X509_R_LOADING_CERT_DIR 103

#define X509_R_LOADING_DEFAULTS 104

#define X509_R_METHOD_NOT_SUPPORTED 124

#define X509_R_NAME_TOO_LONG 134

#define X509_R_NEWER_CRL_NOT_NEWER 132

#define X509_R_NO_CERTIFICATE_FOUND 135

#define X509_R_NO_CERTIFICATE_OR_CRL_FOUND 136

#define X509_R_NO_CERT_SET_FOR_US_TO_VERIFY 105

#define X509_R_NO_CRL_FOUND 137

#define X509_R_NO_CRL_NUMBER 130

#define X509_R_PUBLIC_KEY_DECODE_ERROR 125

#define X509_R_PUBLIC_KEY_ENCODE_ERROR 126

#define X509_R_SHOULD_RETRY 106

#define X509_R_UNABLE_TO_FIND_PARAMETERS_IN_CHAIN 107

#define X509_R_UNABLE_TO_GET_CERTS_PUBLIC_KEY 108

#define X509_R_UNKNOWN_KEY_TYPE 117

#define X509_R_UNKNOWN_NID 109

#define X509_R_UNKNOWN_PURPOSE_ID 121

#define X509_R_UNKNOWN_SIGID_ALGS 144

#define X509_R_UNKNOWN_TRUST_ID 120

#define X509_R_UNSUPPORTED_ALGORITHM 111

#define X509_R_WRONG_LOOKUP_TYPE 112

#define X509_R_WRONG_TYPE 122

#define OPENSSL_X509V3_H 

#define HEADER_X509V3_H 

#define X509V3_CTX_TEST 0x1

#define CTX_TEST X509V3_CTX_TEST

#define X509V3_CTX_REPLACE 0x2

#define X509V3_EXT_DYNAMIC 0x1

#define X509V3_EXT_CTX_DEP 0x2

#define X509V3_EXT_MULTILINE 0x4

#define GEN_OTHERNAME 0

#define GEN_EMAIL 1

#define GEN_DNS 2

#define GEN_X400 3

#define GEN_DIRNAME 4

#define GEN_EDIPARTY 5

#define GEN_URI 6

#define GEN_IPADD 7

#define GEN_RID 8

#define CRLDP_ALL_REASONS 0x807f

#define CRL_REASON_NONE -1

#define CRL_REASON_UNSPECIFIED 0

#define CRL_REASON_KEY_COMPROMISE 1

#define CRL_REASON_CA_COMPROMISE 2

#define CRL_REASON_AFFILIATION_CHANGED 3

#define CRL_REASON_SUPERSEDED 4

#define CRL_REASON_CESSATION_OF_OPERATION 5

#define CRL_REASON_CERTIFICATE_HOLD 6

#define CRL_REASON_REMOVE_FROM_CRL 8

#define CRL_REASON_PRIVILEGE_WITHDRAWN 9

#define CRL_REASON_AA_COMPROMISE 10

#define IDP_PRESENT 0x1

#define IDP_INVALID 0x2

#define IDP_ONLYUSER 0x4

#define IDP_ONLYCA 0x8

#define IDP_ONLYATTR 0x10

#define IDP_INDIRECT 0x20

#define IDP_REASONS 0x40

#define X509V3_conf_err (val) ERR_add_error_data(6,\
	"section:", (val)->section, \\
	",name:", (val)->name, ",value:", (val)->value)

#define X509V3_set_ctx_test (ctx)\
	X509V3_set_ctx(ctx, NULL, NULL, NULL, NULL, X509V3_CTX_TEST)

#define X509V3_set_ctx_nodb (ctx) (ctx)->db = NULL;

#define EXT_BITSTRING (nid, table) { nid, 0, ASN1_ITEM_ref(ASN1_BIT_STRING),\
	0,0,0,0, \\
	0,0, \\
	(X509V3_EXT_I2V)i2v_ASN1_BIT_STRING, \\
	(X509V3_EXT_V2I)v2i_ASN1_BIT_STRING, \\
	NULL, NULL, \\
	table}

#define EXT_IA5STRING (nid) { nid, 0, ASN1_ITEM_ref(ASN1_IA5STRING),\
	0,0,0,0, \\
	(X509V3_EXT_I2S)i2s_ASN1_IA5STRING, \\
	(X509V3_EXT_S2I)s2i_ASN1_IA5STRING, \\
	0,0,0,0, \\
	NULL}

#define EXT_UTF8STRING (nid) { nid, 0, ASN1_ITEM_ref(ASN1_UTF8STRING),\
	0,0,0,0, \\
	(X509V3_EXT_I2S)i2s_ASN1_UTF8STRING, \\
	(X509V3_EXT_S2I)s2i_ASN1_UTF8STRING, \\
	0,0,0,0, \\
	NULL}

#define EXT_END { -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

#define EXFLAG_BCONS 0x1

#define EXFLAG_KUSAGE 0x2

#define EXFLAG_XKUSAGE 0x4

#define EXFLAG_NSCERT 0x8

#define EXFLAG_CA 0x10

#define EXFLAG_SI 0x20

#define EXFLAG_V1 0x40

#define EXFLAG_INVALID 0x80

#define EXFLAG_SET 0x100

#define EXFLAG_CRITICAL 0x200

#define EXFLAG_PROXY 0x400

#define EXFLAG_INVALID_POLICY 0x800

#define EXFLAG_FRESHEST 0x1000

#define EXFLAG_SS 0x2000

#define EXFLAG_BCONS_CRITICAL 0x10000

#define EXFLAG_AKID_CRITICAL 0x20000

#define EXFLAG_SKID_CRITICAL 0x40000

#define EXFLAG_SAN_CRITICAL 0x80000

#define EXFLAG_NO_FINGERPRINT 0x100000

#define KU_DIGITAL_SIGNATURE 0x0080

#define KU_NON_REPUDIATION 0x0040

#define KU_KEY_ENCIPHERMENT 0x0020

#define KU_DATA_ENCIPHERMENT 0x0010

#define KU_KEY_AGREEMENT 0x0008

#define KU_KEY_CERT_SIGN 0x0004

#define KU_CRL_SIGN 0x0002

#define KU_ENCIPHER_ONLY 0x0001

#define KU_DECIPHER_ONLY 0x8000

#define NS_SSL_CLIENT 0x80

#define NS_SSL_SERVER 0x40

#define NS_SMIME 0x20

#define NS_OBJSIGN 0x10

#define NS_SSL_CA 0x04

#define NS_SMIME_CA 0x02

#define NS_OBJSIGN_CA 0x01

#define NS_ANY_CA (NS_SSL_CA|NS_SMIME_CA|NS_OBJSIGN_CA)

#define XKU_SSL_SERVER 0x1

#define XKU_SSL_CLIENT 0x2

#define XKU_SMIME 0x4

#define XKU_CODE_SIGN 0x8

#define XKU_SGC 0x10

#define XKU_OCSP_SIGN 0x20

#define XKU_TIMESTAMP 0x40

#define XKU_DVCS 0x80

#define XKU_ANYEKU 0x100

#define X509_PURPOSE_DYNAMIC 0x1

#define X509_PURPOSE_DYNAMIC_NAME 0x2

#define X509_PURPOSE_SSL_CLIENT 1

#define X509_PURPOSE_SSL_SERVER 2

#define X509_PURPOSE_NS_SSL_SERVER 3

#define X509_PURPOSE_SMIME_SIGN 4

#define X509_PURPOSE_SMIME_ENCRYPT 5

#define X509_PURPOSE_CRL_SIGN 6

#define X509_PURPOSE_ANY 7

#define X509_PURPOSE_OCSP_HELPER 8

#define X509_PURPOSE_TIMESTAMP_SIGN 9

#define X509_PURPOSE_CODE_SIGN 10

#define X509_PURPOSE_MIN 1

#define X509_PURPOSE_MAX 10

#define X509V3_EXT_UNKNOWN_MASK (0xfL << 16)

#define X509V3_EXT_DEFAULT 0

#define X509V3_EXT_ERROR_UNKNOWN (1L << 16)

#define X509V3_EXT_PARSE_UNKNOWN (2L << 16)

#define X509V3_EXT_DUMP_UNKNOWN (3L << 16)

#define X509V3_ADD_OP_MASK 0xfL

#define X509V3_ADD_DEFAULT 0L

#define X509V3_ADD_APPEND 1L

#define X509V3_ADD_REPLACE 2L

#define X509V3_ADD_REPLACE_EXISTING 3L

#define X509V3_ADD_KEEP_EXISTING 4L

#define X509V3_ADD_DELETE 5L

#define X509V3_ADD_SILENT 0x10

#define hex_to_string OPENSSL_buf2hexstr

#define string_to_hex OPENSSL_hexstr2buf

#define X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT 0x1

#define X509_CHECK_FLAG_NO_WILDCARDS 0x2

#define X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS 0x4

#define X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS 0x8

#define X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS 0x10

#define X509_CHECK_FLAG_NEVER_CHECK_SUBJECT 0x20

#define _X509_CHECK_FLAG_DOT_SUBDOMAINS 0x8000

#define ASIdOrRange_id 0

#define ASIdOrRange_range 1

#define ASIdentifierChoice_inherit 0

#define ASIdentifierChoice_asIdsOrRanges 1

#define IPAddressOrRange_addressPrefix 0

#define IPAddressOrRange_addressRange 1

#define IPAddressChoice_inherit 0

#define IPAddressChoice_addressesOrRanges 1

#define V3_ASID_ASNUM 0

#define V3_ASID_RDI 1

#define IANA_AFI_IPV4 1

#define IANA_AFI_IPV6 2

#define OPENSSL_X509V3ERR_H 

#define X509V3_R_BAD_IP_ADDRESS 118

#define X509V3_R_BAD_OBJECT 119

#define X509V3_R_BAD_OPTION 170

#define X509V3_R_BAD_VALUE 171

#define X509V3_R_BN_DEC2BN_ERROR 100

#define X509V3_R_BN_TO_ASN1_INTEGER_ERROR 101

#define X509V3_R_DIRNAME_ERROR 149

#define X509V3_R_DISTPOINT_ALREADY_SET 160

#define X509V3_R_DUPLICATE_ZONE_ID 133

#define X509V3_R_EMPTY_KEY_USAGE 169

#define X509V3_R_ERROR_CONVERTING_ZONE 131

#define X509V3_R_ERROR_CREATING_EXTENSION 144

#define X509V3_R_ERROR_IN_EXTENSION 128

#define X509V3_R_EXPECTED_A_SECTION_NAME 137

#define X509V3_R_EXTENSION_EXISTS 145

#define X509V3_R_EXTENSION_NAME_ERROR 115

#define X509V3_R_EXTENSION_NOT_FOUND 102

#define X509V3_R_EXTENSION_SETTING_NOT_SUPPORTED 103

#define X509V3_R_EXTENSION_VALUE_ERROR 116

#define X509V3_R_ILLEGAL_EMPTY_EXTENSION 151

#define X509V3_R_INCORRECT_POLICY_SYNTAX_TAG 152

#define X509V3_R_INVALID_ASNUMBER 162

#define X509V3_R_INVALID_ASRANGE 163

#define X509V3_R_INVALID_BOOLEAN_STRING 104

#define X509V3_R_INVALID_CERTIFICATE 158

#define X509V3_R_INVALID_EMPTY_NAME 108

#define X509V3_R_INVALID_EXTENSION_STRING 105

#define X509V3_R_INVALID_INHERITANCE 165

#define X509V3_R_INVALID_IPADDRESS 166

#define X509V3_R_INVALID_MULTIPLE_RDNS 161

#define X509V3_R_INVALID_NAME 106

#define X509V3_R_INVALID_NULL_ARGUMENT 107

#define X509V3_R_INVALID_NULL_VALUE 109

#define X509V3_R_INVALID_NUMBER 140

#define X509V3_R_INVALID_NUMBERS 141

#define X509V3_R_INVALID_OBJECT_IDENTIFIER 110

#define X509V3_R_INVALID_OPTION 138

#define X509V3_R_INVALID_POLICY_IDENTIFIER 134

#define X509V3_R_INVALID_PROXY_POLICY_SETTING 153

#define X509V3_R_INVALID_PURPOSE 146

#define X509V3_R_INVALID_SAFI 164

#define X509V3_R_INVALID_SECTION 135

#define X509V3_R_INVALID_SYNTAX 143

#define X509V3_R_ISSUER_DECODE_ERROR 126

#define X509V3_R_MISSING_VALUE 124

#define X509V3_R_NEED_ORGANIZATION_AND_NUMBERS 142

#define X509V3_R_NEGATIVE_PATHLEN 168

#define X509V3_R_NO_CONFIG_DATABASE 136

#define X509V3_R_NO_ISSUER_CERTIFICATE 121

#define X509V3_R_NO_ISSUER_DETAILS 127

#define X509V3_R_NO_POLICY_IDENTIFIER 139

#define X509V3_R_NO_PROXY_CERT_POLICY_LANGUAGE_DEFINED 154

#define X509V3_R_NO_PUBLIC_KEY 114

#define X509V3_R_NO_SUBJECT_DETAILS 125

#define X509V3_R_OPERATION_NOT_DEFINED 148

#define X509V3_R_OTHERNAME_ERROR 147

#define X509V3_R_POLICY_LANGUAGE_ALREADY_DEFINED 155

#define X509V3_R_POLICY_PATH_LENGTH 156

#define X509V3_R_POLICY_PATH_LENGTH_ALREADY_DEFINED 157

#define X509V3_R_POLICY_WHEN_PROXY_LANGUAGE_REQUIRES_NO_POLICY 159

#define X509V3_R_SECTION_NOT_FOUND 150

#define X509V3_R_UNABLE_TO_GET_ISSUER_DETAILS 122

#define X509V3_R_UNABLE_TO_GET_ISSUER_KEYID 123

#define X509V3_R_UNKNOWN_BIT_STRING_ARGUMENT 111

#define X509V3_R_UNKNOWN_EXTENSION 129

#define X509V3_R_UNKNOWN_EXTENSION_NAME 130

#define X509V3_R_UNKNOWN_OPTION 120

#define X509V3_R_UNKNOWN_VALUE 172

#define X509V3_R_UNSUPPORTED_OPTION 117

#define X509V3_R_UNSUPPORTED_TYPE 167

#define X509V3_R_USER_TOO_LONG 132

#define OPENSSL_X509_VFY_H 

#define HEADER_X509_VFY_H 

#define X509_LU_RETRY -1

#define X509_LU_FAIL 0

#define X509_TRUST_DEFAULT 0

#define X509_TRUST_COMPAT 1

#define X509_TRUST_SSL_CLIENT 2

#define X509_TRUST_SSL_SERVER 3

#define X509_TRUST_EMAIL 4

#define X509_TRUST_OBJECT_SIGN 5

#define X509_TRUST_OCSP_SIGN 6

#define X509_TRUST_OCSP_REQUEST 7

#define X509_TRUST_TSA 8

#define X509_TRUST_MIN 1

#define X509_TRUST_MAX 8

#define X509_TRUST_DYNAMIC (1U << 0)

#define X509_TRUST_DYNAMIC_NAME (1U << 1)

#define X509_TRUST_NO_SS_COMPAT (1U << 2)

#define X509_TRUST_DO_SS_COMPAT (1U << 3)

#define X509_TRUST_OK_ANY_EKU (1U << 4)

#define X509_TRUST_TRUSTED 1

#define X509_TRUST_REJECTED 2

#define X509_TRUST_UNTRUSTED 3

#define X509_STORE_CTX_set_app_data (ctx,data)\
	X509_STORE_CTX_set_ex_data(ctx,0,data)

#define X509_STORE_CTX_get_app_data (ctx)\
	X509_STORE_CTX_get_ex_data(ctx,0)

#define X509_L_FILE_LOAD 1

#define X509_L_ADD_DIR 2

#define X509_L_ADD_STORE 3

#define X509_L_LOAD_STORE 4

// #define X509_LOOKUP_load_file (x,name,type)\
// 	X509_LOOKUP_ctrl((x),X509_L_FILE_LOAD,(name),(long)(type),NULL)

#define X509_LOOKUP_add_dir (x,name,type)\
	X509_LOOKUP_ctrl((x),X509_L_ADD_DIR,(name),(long)(type),NULL)

#define X509_LOOKUP_add_store (x,name)\
	X509_LOOKUP_ctrl((x),X509_L_ADD_STORE,(name),0,NULL)

#define X509_LOOKUP_load_store (x,name)\
	X509_LOOKUP_ctrl((x),X509_L_LOAD_STORE,(name),0,NULL)

#define X509_LOOKUP_load_file_ex (x, name, type, libctx, propq)\
	X509_LOOKUP_ctrl_ex((x), X509_L_FILE_LOAD, (name), (long)(type), NULL,\\
	(libctx), (propq))

#define X509_LOOKUP_load_store_ex (x, name, libctx, propq)\
	X509_LOOKUP_ctrl_ex((x), X509_L_LOAD_STORE, (name), 0, NULL,          \\
	(libctx), (propq))

#define X509_LOOKUP_add_store_ex (x, name, libctx, propq)\
	X509_LOOKUP_ctrl_ex((x), X509_L_ADD_STORE, (name), 0, NULL,           \\
	(libctx), (propq))

#define X509_V_OK 0

#define X509_V_ERR_UNSPECIFIED 1

#define X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT 2

#define X509_V_ERR_UNABLE_TO_GET_CRL 3

#define X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE 4

#define X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE 5

#define X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY 6

#define X509_V_ERR_CERT_SIGNATURE_FAILURE 7

#define X509_V_ERR_CRL_SIGNATURE_FAILURE 8

#define X509_V_ERR_CERT_NOT_YET_VALID 9

#define X509_V_ERR_CERT_HAS_EXPIRED 10

#define X509_V_ERR_CRL_NOT_YET_VALID 11

#define X509_V_ERR_CRL_HAS_EXPIRED 12

#define X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD 13

#define X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD 14

#define X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD 15

#define X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD 16

#define X509_V_ERR_OUT_OF_MEM 17

#define X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT 18

#define X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN 19

#define X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY 20

#define X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE 21

#define X509_V_ERR_CERT_CHAIN_TOO_LONG 22

#define X509_V_ERR_CERT_REVOKED 23

#define X509_V_ERR_NO_ISSUER_PUBLIC_KEY 24

#define X509_V_ERR_PATH_LENGTH_EXCEEDED 25

#define X509_V_ERR_INVALID_PURPOSE 26

#define X509_V_ERR_CERT_UNTRUSTED 27

#define X509_V_ERR_CERT_REJECTED 28

#define X509_V_ERR_SUBJECT_ISSUER_MISMATCH 29

#define X509_V_ERR_AKID_SKID_MISMATCH 30

#define X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH 31

#define X509_V_ERR_KEYUSAGE_NO_CERTSIGN 32

#define X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER 33

#define X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION 34

#define X509_V_ERR_KEYUSAGE_NO_CRL_SIGN 35

#define X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION 36

#define X509_V_ERR_INVALID_NON_CA 37

#define X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED 38

#define X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE 39

#define X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED 40

#define X509_V_ERR_INVALID_EXTENSION 41

#define X509_V_ERR_INVALID_POLICY_EXTENSION 42

#define X509_V_ERR_NO_EXPLICIT_POLICY 43

#define X509_V_ERR_DIFFERENT_CRL_SCOPE 44

#define X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE 45

#define X509_V_ERR_UNNESTED_RESOURCE 46

#define X509_V_ERR_PERMITTED_VIOLATION 47

#define X509_V_ERR_EXCLUDED_VIOLATION 48

#define X509_V_ERR_SUBTREE_MINMAX 49

#define X509_V_ERR_APPLICATION_VERIFICATION 50

#define X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE 51

#define X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX 52

#define X509_V_ERR_UNSUPPORTED_NAME_SYNTAX 53

#define X509_V_ERR_CRL_PATH_VALIDATION_ERROR 54

#define X509_V_ERR_PATH_LOOP 55

#define X509_V_ERR_SUITE_B_INVALID_VERSION 56

#define X509_V_ERR_SUITE_B_INVALID_ALGORITHM 57

#define X509_V_ERR_SUITE_B_INVALID_CURVE 58

#define X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM 59

#define X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED 60

#define X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256 61

#define X509_V_ERR_HOSTNAME_MISMATCH 62

#define X509_V_ERR_EMAIL_MISMATCH 63

#define X509_V_ERR_IP_ADDRESS_MISMATCH 64

#define X509_V_ERR_DANE_NO_MATCH 65

#define X509_V_ERR_EE_KEY_TOO_SMALL 66

#define X509_V_ERR_CA_KEY_TOO_SMALL 67

#define X509_V_ERR_CA_MD_TOO_WEAK 68

#define X509_V_ERR_INVALID_CALL 69

#define X509_V_ERR_STORE_LOOKUP 70

#define X509_V_ERR_NO_VALID_SCTS 71

#define X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION 72

#define X509_V_ERR_OCSP_VERIFY_NEEDED 73

#define X509_V_ERR_OCSP_VERIFY_FAILED 74

#define X509_V_ERR_OCSP_CERT_UNKNOWN 75

#define X509_V_ERR_UNSUPPORTED_SIGNATURE_ALGORITHM 76

#define X509_V_ERR_SIGNATURE_ALGORITHM_MISMATCH 77

#define X509_V_ERR_SIGNATURE_ALGORITHM_INCONSISTENCY 78

#define X509_V_ERR_INVALID_CA 79

#define X509_V_ERR_PATHLEN_INVALID_FOR_NON_CA 80

#define X509_V_ERR_PATHLEN_WITHOUT_KU_KEY_CERT_SIGN 81

#define X509_V_ERR_KU_KEY_CERT_SIGN_INVALID_FOR_NON_CA 82

#define X509_V_ERR_ISSUER_NAME_EMPTY 83

#define X509_V_ERR_SUBJECT_NAME_EMPTY 84

#define X509_V_ERR_MISSING_AUTHORITY_KEY_IDENTIFIER 85

#define X509_V_ERR_MISSING_SUBJECT_KEY_IDENTIFIER 86

#define X509_V_ERR_EMPTY_SUBJECT_ALT_NAME 87

#define X509_V_ERR_EMPTY_SUBJECT_SAN_NOT_CRITICAL 88

#define X509_V_ERR_CA_BCONS_NOT_CRITICAL 89

#define X509_V_ERR_AUTHORITY_KEY_IDENTIFIER_CRITICAL 90

#define X509_V_ERR_SUBJECT_KEY_IDENTIFIER_CRITICAL 91

#define X509_V_ERR_CA_CERT_MISSING_KEY_USAGE 92

#define X509_V_ERR_EXTENSIONS_REQUIRE_VERSION_3 93

#define X509_V_ERR_EC_KEY_EXPLICIT_PARAMS 94

#define X509_V_ERR_RPK_UNTRUSTED 95

#define X509_V_FLAG_CB_ISSUER_CHECK 0x0

#define X509_V_FLAG_USE_CHECK_TIME 0x2

#define X509_V_FLAG_CRL_CHECK 0x4

#define X509_V_FLAG_CRL_CHECK_ALL 0x8

#define X509_V_FLAG_IGNORE_CRITICAL 0x10

#define X509_V_FLAG_X509_STRICT 0x20

#define X509_V_FLAG_ALLOW_PROXY_CERTS 0x40

#define X509_V_FLAG_POLICY_CHECK 0x80

#define X509_V_FLAG_EXPLICIT_POLICY 0x100

#define X509_V_FLAG_INHIBIT_ANY 0x200

#define X509_V_FLAG_INHIBIT_MAP 0x400

#define X509_V_FLAG_NOTIFY_POLICY 0x800

#define X509_V_FLAG_EXTENDED_CRL_SUPPORT 0x1000

#define X509_V_FLAG_USE_DELTAS 0x2000

#define X509_V_FLAG_CHECK_SS_SIGNATURE 0x4000

#define X509_V_FLAG_TRUSTED_FIRST 0x8000

#define X509_V_FLAG_SUITEB_128_LOS_ONLY 0x10000

#define X509_V_FLAG_SUITEB_192_LOS 0x20000

#define X509_V_FLAG_SUITEB_128_LOS 0x30000

#define X509_V_FLAG_PARTIAL_CHAIN 0x80000

#define X509_V_FLAG_NO_ALT_CHAINS 0x100000

#define X509_V_FLAG_NO_CHECK_TIME 0x200000

#define X509_VP_FLAG_DEFAULT 0x1

#define X509_VP_FLAG_OVERWRITE 0x2

#define X509_VP_FLAG_RESET_FLAGS 0x4

#define X509_VP_FLAG_LOCKED 0x8

#define X509_VP_FLAG_ONCE 0x10

#define X509_V_FLAG_POLICY_MASK (X509_V_FLAG_POLICY_CHECK\
	| X509_V_FLAG_EXPLICIT_POLICY \\
	| X509_V_FLAG_INHIBIT_ANY \\
	| X509_V_FLAG_INHIBIT_MAP)

#define X509_STORE_set_verify_func (ctx, func)\
	X509_STORE_set_verify((ctx),(func))

#define X509_STORE_set_verify_cb_func (ctx,func)\
	X509_STORE_set_verify_cb((ctx),(func))

#define X509_STORE_set_lookup_crls_cb (ctx, func)\
	X509_STORE_set_lookup_crls((ctx), (func))

#define X509_STORE_get_ex_new_index (l, p, newf, dupf, freef)\
	CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_X509_STORE, l, p, newf, dupf, freef)

#define X509_STORE_CTX_get_chain X509_STORE_CTX_get0_chain

#define X509_STORE_CTX_set_chain X509_STORE_CTX_set0_untrusted

#define X509_STORE_CTX_trusted_stack X509_STORE_CTX_set0_trusted_stack

#define X509_STORE_get_by_subject X509_STORE_CTX_get_by_subject

#define X509_STORE_get1_certs X509_STORE_CTX_get1_certs

#define X509_STORE_get1_crls X509_STORE_CTX_get1_crls

#define X509_STORE_get1_cert X509_STORE_CTX_get1_certs

#define X509_STORE_get1_crl X509_STORE_CTX_get1_crls

#define X509_STORE_CTX_get_ex_new_index (l, p, newf, dupf, freef)\
	CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_X509_STORE_CTX, l, p, newf, dupf, freef)

#define DANE_FLAG_NO_DANE_EE_NAMECHECKS (1L << 0)

#define X509_PCY_TREE_FAILURE -2

#define X509_PCY_TREE_INVALID -1

#define X509_PCY_TREE_INTERNAL 0

#define X509_PCY_TREE_VALID 1

#define X509_PCY_TREE_EMPTY 2

#define X509_PCY_TREE_EXPLICIT 4

// Simple Typedefs
typedef struct aes_key_st AES_KEY;

typedef struct ASN1_TEMPLATE_st ASN1_TEMPLATE;

typedef struct ASN1_TLC_st ASN1_TLC;

typedef struct ASN1_VALUE_st ASN1_VALUE;

typedef struct ASN1_ADB_TABLE_st ASN1_ADB_TABLE;

typedef struct ASN1_ADB_st ASN1_ADB;

typedef struct async_job_st ASYNC_JOB;

typedef struct async_wait_ctx_st ASYNC_WAIT_CTX;

typedef struct bio_addrinfo_st BIO_ADDRINFO;

typedef struct bio_method_st BIO_METHOD;

typedef struct camellia_key_st CAMELLIA_KEY;

typedef struct CMAC_CTX_st CMAC_CTX;

typedef struct ossl_cmp_ctx_st OSSL_CMP_CTX;

typedef struct ossl_cmp_pkiheader_st OSSL_CMP_PKIHEADER;

typedef struct ossl_cmp_msg_st OSSL_CMP_MSG;

typedef struct ossl_cmp_certstatus_st OSSL_CMP_CERTSTATUS;

typedef struct ossl_cmp_itav_st OSSL_CMP_ITAV;

typedef struct ossl_cmp_revrepcontent_st OSSL_CMP_REVREPCONTENT;

typedef struct ossl_cmp_pkisi_st OSSL_CMP_PKISI;

typedef struct ossl_cmp_certrepmessage_st OSSL_CMP_CERTREPMESSAGE;

typedef struct ossl_cmp_pollrep_st OSSL_CMP_POLLREP;

typedef struct ossl_cmp_certresponse_st OSSL_CMP_CERTRESPONSE;

typedef struct ossl_cmp_srv_ctx_st OSSL_CMP_SRV_CTX;

typedef struct CMS_EnvelopedData_st CMS_EnvelopedData;

typedef struct CMS_ContentInfo_st CMS_ContentInfo;

typedef struct CMS_SignerInfo_st CMS_SignerInfo;

typedef struct CMS_SignedData_st CMS_SignedData;

typedef struct CMS_CertificateChoices CMS_CertificateChoices;

typedef struct CMS_RevocationInfoChoice_st CMS_RevocationInfoChoice;

typedef struct CMS_RecipientInfo_st CMS_RecipientInfo;

typedef struct CMS_ReceiptRequest_st CMS_ReceiptRequest;

typedef struct CMS_Receipt_st CMS_Receipt;

typedef struct CMS_RecipientEncryptedKey_st CMS_RecipientEncryptedKey;

typedef struct CMS_OtherKeyAttribute_st CMS_OtherKeyAttribute;

typedef struct conf_method_st CONF_METHOD;

typedef struct conf_imodule_st CONF_IMODULE;

typedef struct conf_module_st CONF_MODULE;

typedef struct ossl_core_handle_st OSSL_CORE_HANDLE;

typedef struct openssl_core_ctx_st OPENSSL_CORE_CTX;

typedef struct ossl_core_bio_st OSSL_CORE_BIO;

typedef struct ossl_crmf_encryptedvalue_st OSSL_CRMF_ENCRYPTEDVALUE;

typedef struct ossl_crmf_msg_st OSSL_CRMF_MSG;

typedef struct ossl_crmf_attributetypeandvalue_st OSSL_CRMF_ATTRIBUTETYPEANDVALUE;

typedef struct ossl_crmf_pbmparameter_st OSSL_CRMF_PBMPARAMETER;

typedef struct ossl_crmf_poposigningkey_st OSSL_CRMF_POPOSIGNINGKEY;

typedef struct ossl_crmf_certrequest_st OSSL_CRMF_CERTREQUEST;

typedef struct ossl_crmf_certid_st OSSL_CRMF_CERTID;

typedef struct ossl_crmf_pkipublicationinfo_st OSSL_CRMF_PKIPUBLICATIONINFO;

typedef struct ossl_crmf_singlepubinfo_st OSSL_CRMF_SINGLEPUBINFO;

typedef struct ossl_crmf_certtemplate_st OSSL_CRMF_CERTTEMPLATE;

typedef struct ossl_crmf_optionalvalidity_st OSSL_CRMF_OPTIONALVALIDITY;

typedef struct ossl_decoder_instance_st OSSL_DECODER_INSTANCE;

typedef struct DSA_SIG_st DSA_SIG;

typedef struct ec_method_st EC_METHOD;

typedef struct ec_group_st EC_GROUP;

typedef struct ec_point_st EC_POINT;

typedef struct ecpk_parameters_st ECPKPARAMETERS;

typedef struct ec_parameters_st ECPARAMETERS;

typedef struct ECDSA_SIG_st ECDSA_SIG;

typedef struct ossl_encoder_instance_st OSSL_ENCODER_INSTANCE;

typedef struct ESS_issuer_serial ESS_ISSUER_SERIAL;

typedef struct ESS_cert_id ESS_CERT_ID;

typedef struct ESS_signing_cert ESS_SIGNING_CERT;

typedef struct ESS_signing_cert_v2_st ESS_SIGNING_CERT_V2;

typedef struct ESS_cert_id_v2_st ESS_CERT_ID_V2;

typedef struct ossl_hpke_ctx_st OSSL_HPKE_CTX;

typedef struct lhash_node_st OPENSSL_LH_NODE;

typedef struct lhash_st OPENSSL_LHASH;

typedef struct gcm128_context GCM128_CONTEXT;

typedef struct ccm128_context CCM128_CONTEXT;

typedef struct xts128_context XTS128_CONTEXT;

typedef struct ocb128_context OCB128_CONTEXT;

typedef struct ocsp_cert_id_st OCSP_CERTID;

typedef struct ocsp_one_request_st OCSP_ONEREQ;

typedef struct ocsp_req_info_st OCSP_REQINFO;

typedef struct ocsp_signature_st OCSP_SIGNATURE;

typedef struct ocsp_request_st OCSP_REQUEST;

typedef struct ocsp_resp_bytes_st OCSP_RESPBYTES;

typedef struct ocsp_revoked_info_st OCSP_REVOKEDINFO;

typedef struct ocsp_cert_status_st OCSP_CERTSTATUS;

typedef struct ocsp_single_response_st OCSP_SINGLERESP;

typedef struct ocsp_response_data_st OCSP_RESPDATA;

typedef struct ocsp_basic_response_st OCSP_BASICRESP;

typedef struct ocsp_crl_id_st OCSP_CRLID;

typedef struct ocsp_service_locator_st OCSP_SERVICELOC;

typedef struct PKCS12_MAC_DATA_st PKCS12_MAC_DATA;

typedef struct PKCS12_st PKCS12;

typedef struct PKCS12_SAFEBAG_st PKCS12_SAFEBAG;

typedef struct pkcs12_bag_st PKCS12_BAGS;

typedef struct ssl_st *ssl_crock_st;

typedef struct tls_session_ticket_ext_st TLS_SESSION_TICKET_EXT;

typedef struct ssl_method_st SSL_METHOD;

typedef struct ssl_cipher_st SSL_CIPHER;

typedef struct ssl_session_st SSL_SESSION;

typedef struct tls_sigalgs_st TLS_SIGALGS;

typedef struct ssl_conf_ctx_st SSL_CONF_CTX;

typedef struct ssl_comp_st SSL_COMP;

typedef struct stack_st OPENSSL_STACK;

typedef struct ossl_store_ctx_st OSSL_STORE_CTX;

typedef struct ossl_store_loader_st OSSL_STORE_LOADER;

typedef struct ossl_store_loader_ctx_st OSSL_STORE_LOADER_CTX;

typedef struct TS_msg_imprint_st TS_MSG_IMPRINT;

typedef struct TS_req_st TS_REQ;

typedef struct TS_accuracy_st TS_ACCURACY;

typedef struct TS_tst_info_st TS_TST_INFO;

typedef struct TS_status_info_st TS_STATUS_INFO;

typedef struct TS_resp_st TS_RESP;

typedef struct TS_resp_ctx TS_RESP_CTX;

typedef struct TS_verify_ctx TS_VERIFY_CTX;

typedef struct ossl_provider_st OSSL_PROVIDER;

typedef struct asn1_string_st ASN1_INTEGER;

typedef struct asn1_string_st ASN1_ENUMERATED;

typedef struct asn1_string_st ASN1_BIT_STRING;

typedef struct asn1_string_st ASN1_OCTET_STRING;

typedef struct asn1_string_st ASN1_PRINTABLESTRING;

typedef struct asn1_string_st ASN1_T61STRING;

typedef struct asn1_string_st ASN1_IA5STRING;

typedef struct asn1_string_st ASN1_GENERALSTRING;

typedef struct asn1_string_st ASN1_UNIVERSALSTRING;

typedef struct asn1_string_st ASN1_BMPSTRING;

typedef struct asn1_string_st ASN1_UTCTIME;

typedef struct asn1_string_st ASN1_TIME;

typedef struct asn1_string_st ASN1_GENERALIZEDTIME;

typedef struct asn1_string_st ASN1_VISIBLESTRING;

typedef struct asn1_string_st ASN1_UTF8STRING;

typedef struct asn1_string_st ASN1_STRING;

typedef struct asn1_type_st ASN1_TYPE;

typedef struct asn1_object_st ASN1_OBJECT;

typedef struct asn1_string_table_st ASN1_STRING_TABLE;

typedef struct ASN1_ITEM_st ASN1_ITEM;

typedef struct asn1_pctx_st ASN1_PCTX;

typedef struct asn1_sctx_st ASN1_SCTX;

typedef struct bignum_st BIGNUM;

typedef struct bignum_ctx BN_CTX;

typedef struct bn_blinding_st BN_BLINDING;

typedef struct bn_mont_ctx_st BN_MONT_CTX;

typedef struct bn_recp_ctx_st BN_RECP_CTX;

typedef struct bn_gencb_st BN_GENCB;

typedef struct buf_mem_st BUF_MEM;

typedef struct err_state_st ERR_STATE;

typedef struct evp_cipher_st EVP_CIPHER;

typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;

typedef struct evp_md_st EVP_MD;

typedef struct evp_md_ctx_st EVP_MD_CTX;

typedef struct evp_mac_st EVP_MAC;

typedef struct evp_mac_ctx_st EVP_MAC_CTX;

typedef struct evp_pkey_st EVP_PKEY;

typedef struct evp_pkey_asn1_method_st EVP_PKEY_ASN1_METHOD;

typedef struct evp_pkey_method_st EVP_PKEY_METHOD;

typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;

typedef struct evp_keymgmt_st EVP_KEYMGMT;

typedef struct evp_kdf_st EVP_KDF;

typedef struct evp_kdf_ctx_st EVP_KDF_CTX;

typedef struct evp_rand_st EVP_RAND;

typedef struct evp_rand_ctx_st EVP_RAND_CTX;

typedef struct evp_keyexch_st EVP_KEYEXCH;

typedef struct evp_signature_st EVP_SIGNATURE;

typedef struct evp_asym_cipher_st EVP_ASYM_CIPHER;

typedef struct evp_kem_st EVP_KEM;

typedef struct evp_Encode_Ctx_st EVP_ENCODE_CTX;

typedef struct hmac_ctx_st HMAC_CTX;

typedef struct dh_st DH;

typedef struct dh_method DH_METHOD;

typedef struct dsa_st DSA;

typedef struct dsa_method DSA_METHOD;

typedef struct rsa_st RSA;

typedef struct rsa_meth_st RSA_METHOD;

typedef struct rsa_pss_params_st RSA_PSS_PARAMS;

typedef struct ec_key_st EC_KEY;

typedef struct ec_key_method_st EC_KEY_METHOD;

typedef struct rand_meth_st RAND_METHOD;

typedef struct rand_drbg_st RAND_DRBG;

typedef struct ssl_dane_st SSL_DANE;

typedef struct x509_st X509;

typedef struct X509_algor_st X509_ALGOR;

typedef struct X509_crl_st X509_CRL;

typedef struct x509_crl_method_st X509_CRL_METHOD;

typedef struct x509_revoked_st X509_REVOKED;

typedef struct X509_name_st X509_NAME;

typedef struct X509_pubkey_st X509_PUBKEY;

typedef struct x509_store_st X509_STORE;

typedef struct x509_store_ctx_st X509_STORE_CTX;

typedef struct x509_object_st X509_OBJECT;

typedef struct x509_lookup_st X509_LOOKUP;

typedef struct x509_lookup_method_st X509_LOOKUP_METHOD;

typedef struct X509_VERIFY_PARAM_st X509_VERIFY_PARAM;

typedef struct x509_sig_info_st X509_SIG_INFO;

typedef struct pkcs8_priv_key_info_st PKCS8_PRIV_KEY_INFO;

typedef struct v3_ext_ctx X509V3_CTX;

typedef struct conf_st CONF;

typedef struct ossl_init_settings_st OPENSSL_INIT_SETTINGS;

typedef struct ui_st UI;

typedef struct ui_method_st UI_METHOD;

typedef struct engine_st ENGINE;

typedef struct ssl_st SSL;

typedef struct ssl_ctx_st SSL_CTX;

typedef struct comp_ctx_st COMP_CTX;

typedef struct comp_method_st COMP_METHOD;

typedef struct X509_POLICY_NODE_st X509_POLICY_NODE;

typedef struct X509_POLICY_LEVEL_st X509_POLICY_LEVEL;

typedef struct X509_POLICY_TREE_st X509_POLICY_TREE;

typedef struct X509_POLICY_CACHE_st X509_POLICY_CACHE;

typedef struct AUTHORITY_KEYID_st AUTHORITY_KEYID;

typedef struct DIST_POINT_st DIST_POINT;

typedef struct ISSUING_DIST_POINT_st ISSUING_DIST_POINT;

typedef struct NAME_CONSTRAINTS_st NAME_CONSTRAINTS;

typedef struct crypto_ex_data_st CRYPTO_EX_DATA;

typedef struct ossl_http_req_ctx_st OSSL_HTTP_REQ_CTX;

typedef struct ocsp_response_st OCSP_RESPONSE;

typedef struct ocsp_responder_id_st OCSP_RESPID;

typedef struct sct_st SCT;

typedef struct sct_ctx_st SCT_CTX;

typedef struct ctlog_st CTLOG;

typedef struct ctlog_store_st CTLOG_STORE;

typedef struct ct_policy_eval_ctx_st CT_POLICY_EVAL_CTX;

typedef struct ossl_store_info_st OSSL_STORE_INFO;

typedef struct ossl_store_search_st OSSL_STORE_SEARCH;

typedef struct ossl_lib_ctx_st OSSL_LIB_CTX;

typedef struct ossl_dispatch_st OSSL_DISPATCH;

typedef struct ossl_item_st OSSL_ITEM;

typedef struct ossl_algorithm_st OSSL_ALGORITHM;

typedef struct ossl_param_st OSSL_PARAM;

typedef struct ossl_param_bld_st OSSL_PARAM_BLD;

typedef struct ossl_encoder_st OSSL_ENCODER;

typedef struct ossl_encoder_ctx_st OSSL_ENCODER_CTX;

typedef struct ossl_decoder_st OSSL_DECODER;

typedef struct ossl_decoder_ctx_st OSSL_DECODER_CTX;

typedef struct ossl_self_test_st OSSL_SELF_TEST;

typedef struct ui_string_st UI_STRING;

typedef struct X509_sig_st X509_SIG;

typedef struct X509_name_entry_st X509_NAME_ENTRY;

typedef struct X509_extension_st X509_EXTENSION;

typedef struct x509_attributes_st X509_ATTRIBUTE;

typedef struct X509_req_info_st X509_REQ_INFO;

typedef struct X509_req_st X509_REQ;

typedef struct x509_cert_aux_st X509_CERT_AUX;

typedef struct x509_cinf_st X509_CINF;

typedef struct X509_crl_info_st X509_CRL_INFO;

typedef struct v3_ext_method X509V3_EXT_METHOD;

typedef struct NamingAuthority_st NAMING_AUTHORITY;

typedef struct ProfessionInfo_st PROFESSION_INFO;

typedef struct Admissions_st ADMISSIONS;

typedef struct AdmissionSyntax_st ADMISSION_SYNTAX;

typedef void *d2i_of_void(void **, const unsigned char **, long);

typedef int i2d_of_void(const void *, unsigned char **);

typedef const ASN1_ITEM *ASN1_ITEM_EXP (void);

// typedef STACK_OF(ASN1_TYPE) ASN1_SEQUENCE_ANY;

typedef int ASN1_ex_new_func(ASN1_VALUE **pval, const ASN1_ITEM *it);

typedef void ASN1_ex_free_func(ASN1_VALUE **pval, const ASN1_ITEM *it);

typedef int (*ASYNC_callback_fn)(void *arg);

typedef void *(*ASYNC_stack_alloc_fn)(size_t *num);

typedef void (*ASYNC_stack_free_fn)(void *addr);

typedef union bio_addr_st BIO_ADDR;

typedef int BIO_info_cb(BIO *, int, int);

typedef BIO_info_cb bio_info_cb;

typedef unsigned int KEY_TABLE_TYPE[CAMELLIA_TABLE_WORD_LEN];

typedef ASN1_BIT_STRING OSSL_CMP_PKIFAILUREINFO;

typedef ASN1_INTEGER OSSL_CMP_PKISTATUS;

// typedef STACK_OF(OSSL_CMP_POLLREP) OSSL_CMP_POLLREPCONTENT;

typedef STACK_OF(ASN1_UTF8STRING) OSSL_CMP_PKIFREETEXT;

typedef int OSSL_CMP_severity;

typedef int conf_init_func (CONF_IMODULE *md, const CONF *cnf);

typedef void conf_finish_func (CONF_IMODULE *md);

typedef void (*OSSL_thread_stop_handler_fn)(void *arg);

typedef int (OSSL_CALLBACK)(const OSSL_PARAM params[], void *arg);

// typedef STACK_OF(OSSL_CRMF_MSG) OSSL_CRMF_MSGS;

typedef void CRYPTO_RWLOCK;

typedef void *(*CRYPTO_malloc_fn)(size_t num, const char *file, int line);

typedef void (*CRYPTO_free_fn)(void *addr, const char *file, int line);

typedef LONG CRYPTO_ONCE;

typedef unsigned int CRYPTO_THREAD_LOCAL;

typedef unsigned int CRYPTO_THREAD_ID;

typedef void OSSL_DECODER_CLEANUP(void *construct_data);

typedef unsigned int DES_LONG;

typedef unsigned char DES_cblock[8];

typedef   unsigned char const_DES_cblock[8];

typedef void OSSL_ENCODER_CLEANUP(void *construct_data);

typedef int (*ENGINE_GEN_FUNC_PTR) (void);

typedef int (*ENGINE_GEN_INT_FUNC_PTR) (ENGINE *);

typedef void *(*dyn_MEM_malloc_fn) (size_t, const char *, int);

typedef void *(*dyn_MEM_realloc_fn) (void *, size_t, const char *, int);

typedef void (*dyn_MEM_free_fn) (void *, const char *, int);

typedef unsigned long (*dynamic_v_check_fn) (unsigned long ossl_version);

typedef int EVP_PKEY_gen_cb(EVP_PKEY_CTX *ctx);

typedef intmax_t ossl_intmax_t;

typedef uintmax_t ossl_uintmax_t;

typedef int64_t ossl_intmax_t;

typedef uint64_t ossl_uintmax_t;

typedef BIO *(*OSSL_HTTP_bio_cb_t)(BIO *bio, void *arg, int connect, int detail);

typedef unsigned int IDEA_INT;

typedef int (*OPENSSL_LH_COMPFUNC) (const void *, const void *);

typedef int (*OPENSSL_LH_COMPFUNCTHUNK) (const void *, const void *, OPENSSL_LH_COMPFUNC cfn);

typedef unsigned long (*OPENSSL_LH_HASHFUNC) (const void *);

typedef unsigned long (*OPENSSL_LH_HASHFUNCTHUNK) (const void *, OPENSSL_LH_HASHFUNC hfn);

typedef void (*OPENSSL_LH_DOALL_FUNC) (void *);

typedef void (*OPENSSL_LH_DOALL_FUNC_THUNK) (void *, OPENSSL_LH_DOALL_FUNC doall);

typedef void (*OPENSSL_LH_DOALL_FUNCARG) (void *, void *);

typedef void (*OPENSSL_LH_DOALL_FUNCARG_THUNK) (void *, void *, OPENSSL_LH_DOALL_FUNCARG doall);

typedef unsigned char MD2_INT;

typedef OSSL_HTTP_REQ_CTX OCSP_REQ_CTX;

typedef int PKCS12_create_cb(PKCS12_SAFEBAG *bag, void *cbarg);

typedef unsigned int RC2_INT;

typedef char *OPENSSL_STRING;

typedef const char *OPENSSL_CSTRING;

typedef void *OPENSSL_BLOCK;

typedef int (*SSL_verify_cb)(int preverify_ok, X509_STORE_CTX *x509_ctx);

typedef int (*SSL_async_callback_fn)(SSL *s, void *arg);

typedef void (*SSL_CTX_keylog_cb_func)(const SSL *ssl, const char *line);

typedef int (*SSL_client_hello_cb_fn) (SSL *s, int *al, void *arg);

typedef int SSL_TICKET_STATUS;

typedef int SSL_TICKET_RETURN;

typedef int (*SSL_CTX_generate_session_ticket_fn)(SSL *s, void *arg);

typedef unsigned int (*DTLS_timer_cb)(SSL *s, unsigned int timer_us);

typedef int (*SSL_allow_early_data_cb_fn)(SSL *s, void *arg);

typedef int (*OPENSSL_sk_compfunc)(const void *, const void *);

typedef void (*OPENSSL_sk_freefunc)(void *);

typedef void *(*OPENSSL_sk_copyfunc)(const void *);

typedef int (*OSSL_STORE_eof_fn)(OSSL_STORE_LOADER_CTX *ctx);

typedef int (*OSSL_STORE_error_fn)(OSSL_STORE_LOADER_CTX *ctx);

typedef int (*OSSL_STORE_close_fn)(OSSL_STORE_LOADER_CTX *ctx);

typedef ASN1_INTEGER *(*TS_serial_cb) (struct TS_resp_ctx *, void *);

typedef OPENSSL_STRING *OPENSSL_PSTRING;

typedef int ASN1_BOOLEAN;

typedef int ASN1_NULL;

typedef int pem_password_cb (char *buf, int size, int rwflag, void *userdata);

typedef STACK_OF(X509_ALGOR) X509_ALGORS;

typedef STACK_OF(X509_EXTENSION) X509_EXTENSIONS;

typedef struct {
	char *section;
	char *name;
	char *value;
	} CONF_VALUE;

struct conf_st {
    CONF_METHOD *meth;
    void *meth_data;
    LHASH_OF(CONF_VALUE) *data;
    int flag_dollarid;
    int flag_abspath;
    char *includedir;
    OSSL_LIB_CTX *libctx;
};

typedef void *(*X509V3_EXT_NEW)(void);
typedef void (*X509V3_EXT_FREE) (void *);
typedef void *(*X509V3_EXT_D2I)(void *, const unsigned char **, long);
typedef int (*X509V3_EXT_I2D) (const void *, unsigned char **);
typedef STACK_OF(CONF_VALUE) *
    (*X509V3_EXT_I2V) (const struct v3_ext_method *method, void *ext,
                       STACK_OF(CONF_VALUE) *extlist);
typedef void *(*X509V3_EXT_V2I)(const struct v3_ext_method *method,
                                struct v3_ext_ctx *ctx,
                                STACK_OF(CONF_VALUE) *values);
typedef char *(*X509V3_EXT_I2S)(const struct v3_ext_method *method,
                                void *ext);
typedef void *(*X509V3_EXT_S2I)(const struct v3_ext_method *method,
                                struct v3_ext_ctx *ctx, const char *str);
typedef int (*X509V3_EXT_I2R) (const struct v3_ext_method *method, void *ext,
                               BIO *out, int indent);
typedef void *(*X509V3_EXT_R2I)(const struct v3_ext_method *method,
                                struct v3_ext_ctx *ctx, const char *str);

typedef struct X509V3_CONF_METHOD_st {
    char *(*get_string) (void *db, const char *section, const char *value);
    STACK_OF(CONF_VALUE) *(*get_section) (void *db, const char *section);
    void (*free_string) (void *db, char *string);
    void (*free_section) (void *db, STACK_OF(CONF_VALUE) *section);
} X509V3_CONF_METHOD;

// typedef int X509V3_EXT_I2S;
// typedef int X509V3_EXT_S2I;
// typedef int X509V3_EXT_I2V;
// typedef int X509V3_EXT_V2I;
// typedef int X509V3_EXT_I2R;
// typedef int X509V3_EXT_R2I;

typedef struct BIT_STRING_BITNAME_st {
	int bitnum;
	const char *lname;
	const char *sname;
	} BIT_STRING_BITNAME;
typedef BIT_STRING_BITNAME ENUMERATED_NAMES;

// typedef STACK_OF(ACCESS_DESCRIPTION) AUTHORITY_INFO_ACCESS;

// typedef STACK_OF(ASN1_OBJECT) EXTENDED_KEY_USAGE;

// typedef STACK_OF(ASN1_INTEGER) TLS_FEATURE;

typedef struct EDIPartyName_st {
    ASN1_STRING *nameAssigner;
    ASN1_STRING *partyName;
} EDIPARTYNAME;

typedef struct otherName_st {
    ASN1_OBJECT *type_id;
    ASN1_TYPE *value;
} OTHERNAME;

typedef struct GENERAL_NAME_st {
# define GEN_OTHERNAME   0
# define GEN_EMAIL       1
# define GEN_DNS         2
# define GEN_X400        3
# define GEN_DIRNAME     4
# define GEN_EDIPARTY    5
# define GEN_URI         6
# define GEN_IPADD       7
# define GEN_RID         8
    int type;
    union {
        char *ptr;
        OTHERNAME *otherName;   /* otherName */
        ASN1_IA5STRING *rfc822Name;
        ASN1_IA5STRING *dNSName;
        ASN1_STRING *x400Address;
        X509_NAME *directoryName;
        EDIPARTYNAME *ediPartyName;
        ASN1_IA5STRING *uniformResourceIdentifier;
        ASN1_OCTET_STRING *iPAddress;
        ASN1_OBJECT *registeredID;
        /* Old names */
        ASN1_OCTET_STRING *ip;  /* iPAddress */
        X509_NAME *dirn;        /* dirn */
        ASN1_IA5STRING *ia5;    /* rfc822Name, dNSName,
                                 * uniformResourceIdentifier */
        ASN1_OBJECT *rid;       /* registeredID */
        ASN1_TYPE *other;       /* x400Address */
    } d;
} GENERAL_NAME;

typedef struct NOTICEREF_st {
	ASN1_STRING *organization;
	STACK_OF(ASN1_INTEGER) *noticenos;
	} NOTICEREF;

typedef struct USERNOTICE_st {
	NOTICEREF *noticeref;
	ASN1_STRING *exptext;
	} USERNOTICE;

typedef struct POLICYQUALINFO_st {
	ASN1_OBJECT *pqualid;
	union {
	ASN1_IA5STRING *cpsuri;
	USERNOTICE *usernotice;
	ASN1_TYPE *other;
	} d;
	} POLICYQUALINFO;

typedef STACK_OF(GENERAL_NAME) GENERAL_NAMES;

typedef STACK_OF(DIST_POINT) CRL_DIST_POINTS;

typedef struct POLICYINFO_st {
	ASN1_OBJECT *policyid;
	STACK_OF(POLICYQUALINFO) *qualifiers;
	} POLICYINFO;

typedef STACK_OF(POLICYINFO) CERTIFICATEPOLICIES;

typedef struct POLICY_MAPPING_st {
	ASN1_OBJECT *issuerDomainPolicy;
	ASN1_OBJECT *subjectDomainPolicy;
	} POLICY_MAPPING;

typedef STACK_OF(POLICY_MAPPING) POLICY_MAPPINGS;

typedef struct ASRange_st {
	ASN1_INTEGER *min, *max;
	} ASRange;

typedef struct ASIdOrRange_st {
	int type;
	union {
	ASN1_INTEGER *id;
	ASRange *range;
	} u;
	} ASIdOrRange;

typedef STACK_OF(ASIdOrRange) ASIdOrRanges;

typedef struct IPAddressRange_st {
	ASN1_BIT_STRING *min, *max;
	} IPAddressRange;

typedef struct IPAddressOrRange_st {
	int type;
	union {
	ASN1_BIT_STRING *addressPrefix;
	IPAddressRange *addressRange;
	} u;
	} IPAddressOrRange;

typedef STACK_OF(IPAddressOrRange) IPAddressOrRanges;
typedef struct IPAddressChoice_st {
	int type;
	union {
	ASN1_NULL *inherit;
	IPAddressOrRanges *addressesOrRanges;
	} u;
	} IPAddressChoice;

typedef struct IPAddressFamily_st {
	ASN1_OCTET_STRING *addressFamily;
	IPAddressChoice *ipAddressChoice;
	} IPAddressFamily;


typedef STACK_OF(IPAddressFamily) IPAddrBlocks;

typedef STACK_OF(PROFESSION_INFO) PROFESSION_INFOS;

typedef int (*X509_STORE_CTX_verify_cb)(int, X509_STORE_CTX *);

typedef int (*X509_STORE_CTX_verify_fn)(X509_STORE_CTX *);

typedef int (*X509_STORE_CTX_check_revocation_fn)(X509_STORE_CTX *ctx);

typedef int (*X509_STORE_CTX_check_crl_fn)(X509_STORE_CTX *ctx, X509_CRL *crl);

typedef int (*X509_STORE_CTX_check_policy_fn)(X509_STORE_CTX *ctx);

typedef int (*X509_STORE_CTX_cleanup_fn)(X509_STORE_CTX *ctx);

// Structures
struct aes_key_st {
    #  ifdef AES_LONG
    unsigned long rd_key[4 * (AES_MAXNR + 1)];
    #  else
    unsigned int rd_key[4 * (AES_MAXNR + 1)];
    #  endif
    int rounds;
};

struct asn1_string_st {
    int length;
    int type;
    unsigned char *data;
    long flags;
};

struct asn1_string_table_st {
    int nid;
    long minsize;
    long maxsize;
    unsigned long mask;
    unsigned long flags;
};

struct asn1_type_st {
    int type;
    union {;
    char *ptr;
    ASN1_BOOLEAN boolean;
    ASN1_STRING *asn1_string;
    ASN1_OBJECT *object;
    ASN1_INTEGER *integer;
    ASN1_ENUMERATED *enumerated;
    ASN1_BIT_STRING *bit_string;
    ASN1_OCTET_STRING *octet_string;
    ASN1_PRINTABLESTRING *printablestring;
    ASN1_T61STRING *t61string;
    ASN1_IA5STRING *ia5string;
    ASN1_GENERALSTRING *generalstring;
    ASN1_BMPSTRING *bmpstring;
    ASN1_UNIVERSALSTRING *universalstring;
    ASN1_UTCTIME *utctime;
    ASN1_GENERALIZEDTIME *generalizedtime;
    ASN1_VISIBLESTRING *visiblestring;
    ASN1_UTF8STRING *utf8string;
    ASN1_STRING *set;
    ASN1_STRING *sequence;
    ASN1_VALUE *asn1_value;
    } value;
};

struct ASN1_TEMPLATE_st {
    unsigned long flags;
    long tag;
    unsigned long offset;
    const char *field_name;
    ASN1_ITEM_EXP *item;
};

struct ASN1_ADB_st {
    unsigned long flags;
    unsigned long offset;
    int (*adb_cb)(long *psel);
    const ASN1_ADB_TABLE *tbl;
    long tblcount;
    const ASN1_TEMPLATE *default_tt;
    const ASN1_TEMPLATE *null_tt;
};

struct ASN1_ADB_TABLE_st {
    long value;
    const ASN1_TEMPLATE tt;
};

struct ASN1_ITEM_st {
    char itype;
    long utype;
    const ASN1_TEMPLATE *templates;
    long tcount;
    const void *funcs;
    long size;
    const char *sname;
};

struct ASN1_TLC_st {
    char valid;
    int ret;
    long plen;
    int ptag;
    int pclass;
    int hdrlen;
};

struct bio_dgram_sctp_sndinfo {
    uint16_t snd_sid;
    uint16_t snd_flags;
    uint32_t snd_ppid;
    uint32_t snd_context;
};

struct bio_dgram_sctp_rcvinfo {
    uint16_t rcv_sid;
    uint16_t rcv_ssn;
    uint16_t rcv_flags;
    uint32_t rcv_ppid;
    uint32_t rcv_tsn;
    uint32_t rcv_cumtsn;
    uint32_t rcv_context;
};

struct bio_dgram_sctp_prinfo {
    uint16_t pr_policy;
    uint32_t pr_value;
};

struct buf_mem_st {
    size_t length;
    char *data;
    size_t max;
    unsigned long flags;
};

struct camellia_key_st {
    union {;
    double d;
    KEY_TABLE_TYPE rd_key;
    } u;
    int grand_rounds;
};

struct conf_method_st {
    const char *name;
    CONF *(*create) (CONF_METHOD *meth);
    int (*init) (CONF *conf);
    int (*destroy) (CONF *conf);
    int (*destroy_data) (CONF *conf);
    int (*load_bio) (CONF *conf, BIO *bp, long *eline);
    int (*dump) (const CONF *conf, BIO *bp);
    int (*is_number) (const CONF *conf, char c);
    int (*to_int) (const CONF *conf, char c);
    int (*load) (CONF *conf, const char *name, long *eline);
};

struct ossl_dispatch_st {
    int function_id;
    void (*function)(void);
};

struct ossl_item_st {
    unsigned int id;
    void *ptr;
};

struct ossl_algorithm_st {
    const char *algorithm_names;
    const char *property_definition;
    const OSSL_DISPATCH *implementation;
    const char *algorithm_description;
};

struct crypto_ex_data_st {
    OSSL_LIB_CTX *ctx;
    STACK_OF(void) *sk;
};

struct err_state_st {
    int err_flags[ERR_NUM_ERRORS];
    int err_marks[ERR_NUM_ERRORS];
    unsigned long err_buffer[ERR_NUM_ERRORS];
    char *err_data[ERR_NUM_ERRORS];
    size_t err_data_size[ERR_NUM_ERRORS];
    int err_data_flags[ERR_NUM_ERRORS];
    char *err_file[ERR_NUM_ERRORS];
    int err_line[ERR_NUM_ERRORS];
    char *err_func[ERR_NUM_ERRORS];
    int top, bottom;
};

struct rsa_st {
};

struct dsa_st {
};

struct dh_st {
};

struct ec_key_st {
};

struct rand_meth_st {
    int (*seed) (const void *buf, int num);
    int (*bytes) (unsigned char *buf, int num);
    void (*cleanup) (void);
    int (*add) (const void *buf, int num, double randomness);
    int (*pseudorand) (unsigned char *buf, int num);
    int (*status) (void);
};

struct rsa_pss_params_st {
    X509_ALGOR *hashAlgorithm;
    X509_ALGOR *maskGenAlgorithm;
    ASN1_INTEGER *saltLength;
    ASN1_INTEGER *trailerField;
    X509_ALGOR *maskHash;
};

struct tls_session_ticket_ext_st {
    unsigned short length;
    void *data;
};

struct TS_resp_ctx {
};

struct X509_algor_st {
    ASN1_OBJECT *algorithm;
    ASN1_TYPE *parameter;
};

struct v3_ext_method {
    int ext_nid;
    int ext_flags;
    ASN1_ITEM_EXP *it;
    X509V3_EXT_NEW ext_new;
    X509V3_EXT_FREE ext_free;
    X509V3_EXT_D2I d2i;
    X509V3_EXT_I2D i2d;
    X509V3_EXT_I2S i2s;
    X509V3_EXT_S2I s2i;
    X509V3_EXT_I2V i2v;
    X509V3_EXT_V2I v2i;
    X509V3_EXT_I2R i2r;
    X509V3_EXT_R2I r2i;
    void *usr_data;
};

struct v3_ext_ctx {
    # ifndef OPENSSL_NO_DEPRECATED_3_0
    # endif
    int flags;
    X509 *issuer_cert;
    X509 *subject_cert;
    X509_REQ *subject_req;
    X509_CRL *crl;
    X509V3_CONF_METHOD *db_meth;
    void *db;
    EVP_PKEY *issuer_pkey;
};

typedef struct GENERAL_SUBTREE_st {
    GENERAL_NAME *base;
    ASN1_INTEGER *minimum;
    ASN1_INTEGER *maximum;
} GENERAL_SUBTREE;

typedef struct DIST_POINT_NAME_st {
    int type;
    union {
        GENERAL_NAMES *fullname;
        STACK_OF(X509_NAME_ENTRY) *relativename;
    } name;
    X509_NAME *dpname;
} DIST_POINT_NAME;

struct DIST_POINT_st {
    DIST_POINT_NAME *distpoint;
    ASN1_BIT_STRING *reasons;
    GENERAL_NAMES *CRLissuer;
    int dp_reasons;
};

struct AUTHORITY_KEYID_st {
    ASN1_OCTET_STRING *keyid;
    GENERAL_NAMES *issuer;
    ASN1_INTEGER *serial;
};

struct NAME_CONSTRAINTS_st {
    STACK_OF(GENERAL_SUBTREE) *permittedSubtrees;
    STACK_OF(GENERAL_SUBTREE) *excludedSubtrees;
};

struct ISSUING_DIST_POINT_st {
    DIST_POINT_NAME *distpoint;
    int onlyuser;
    int onlyCA;
    ASN1_BIT_STRING *onlysomereasons;
    int indirectCRL;
    int onlyattr;
};

// Typedefs
typedef struct ASN1_ENCODING_st {
	unsigned char *enc;
	long len;
	int modified;
	} ASN1_ENCODING;

typedef int ASN1_ex_d2i(ASN1_VALUE **pval, const unsigned char **in, long len,
	const ASN1_ITEM *it, int tag, int aclass, char opt,
	ASN1_TLC *ctx);

typedef int ASN1_ex_d2i_ex(ASN1_VALUE **pval, const unsigned char **in, long len,
	const ASN1_ITEM *it, int tag, int aclass, char opt,
	ASN1_TLC *ctx, OSSL_LIB_CTX *libctx,
	const char *propq);

typedef int ASN1_ex_i2d(const ASN1_VALUE **pval, unsigned char **out,
	const ASN1_ITEM *it, int tag, int aclass);

typedef int ASN1_ex_new_ex_func(ASN1_VALUE **pval, const ASN1_ITEM *it,
	OSSL_LIB_CTX *libctx, const char *propq);

typedef int ASN1_ex_print_func(BIO *out, const ASN1_VALUE **pval,
	int indent, const char *fname,
	const ASN1_PCTX *pctx);

typedef int ASN1_primitive_i2c(const ASN1_VALUE **pval, unsigned char *cont,
	int *putype, const ASN1_ITEM *it);

typedef int ASN1_primitive_c2i(ASN1_VALUE **pval, const unsigned char *cont,
	int len, int utype, char *free_cont,
	const ASN1_ITEM *it);

typedef int ASN1_primitive_print(BIO *out, const ASN1_VALUE **pval,
	const ASN1_ITEM *it, int indent,
	const ASN1_PCTX *pctx);

typedef struct ASN1_EXTERN_FUNCS_st {
	void *app_data;
	ASN1_ex_new_func *asn1_ex_new;
	ASN1_ex_free_func *asn1_ex_free;
	ASN1_ex_free_func *asn1_ex_clear;
	ASN1_ex_d2i *asn1_ex_d2i;
	ASN1_ex_i2d *asn1_ex_i2d;
	ASN1_ex_print_func *asn1_ex_print;
	ASN1_ex_new_ex_func *asn1_ex_new_ex;
	ASN1_ex_d2i_ex *asn1_ex_d2i_ex;
	} ASN1_EXTERN_FUNCS;

typedef struct ASN1_PRIMITIVE_FUNCS_st {
	void *app_data;
	unsigned long flags;
	ASN1_ex_new_func *prim_new;
	ASN1_ex_free_func *prim_free;
	ASN1_ex_free_func *prim_clear;
	ASN1_primitive_c2i *prim_c2i;
	ASN1_primitive_i2c *prim_i2c;
	ASN1_primitive_print *prim_print;
	} ASN1_PRIMITIVE_FUNCS;

typedef int ASN1_aux_cb(int operation, ASN1_VALUE **in, const ASN1_ITEM *it,
	void *exarg);

typedef int ASN1_aux_const_cb(int operation, const ASN1_VALUE **in,
	const ASN1_ITEM *it, void *exarg);

typedef struct ASN1_AUX_st {
	void *app_data;
	int flags;
	int ref_offset;
	int ref_lock;
	ASN1_aux_cb *asn1_cb;
	int enc_offset;
	ASN1_aux_const_cb *asn1_const_cb;
	} ASN1_AUX;

typedef struct ASN1_PRINT_ARG_st {
	BIO *out;
	int indent;
	const ASN1_PCTX *pctx;
	} ASN1_PRINT_ARG;

typedef struct ASN1_STREAM_ARG_st {
	BIO *out;
	BIO *ndef_bio;
	unsigned char **boundary;
	} ASN1_STREAM_ARG;

typedef long (*BIO_callback_fn)(BIO *b, int oper, const char *argp, int argi,
	long argl, long ret);

typedef long (*BIO_callback_fn_ex)(BIO *b, int oper, const char *argp,
	size_t len, int argi,
	long argl, int ret, size_t *processed);

typedef int asn1_ps_func (BIO *b, unsigned char **pbuf, int *plen,
	void *parg);

typedef void (*BIO_dgram_sctp_notification_handler_fn) (BIO *b,
	void *context,
	void *buf);

typedef struct bio_msg_st {
	void *data;
	size_t data_len;
	BIO_ADDR *peer, *local;
	uint64_t flags;
	} BIO_MSG;

typedef struct bio_mmsg_cb_args_st {
	BIO_MSG    *msg;
	size_t      stride, num_msg;
	uint64_t    flags;
	size_t     *msgs_processed;
	} BIO_MMSG_CB_ARGS;

typedef struct bio_poll_descriptor_st {
	uint32_t type;
	union {
	int         fd;
	void        *custom;
	uintptr_t   custom_ui;
	SSL         *ssl;
	} value;
	} BIO_POLL_DESCRIPTOR;

typedef struct bf_key_st {
	BF_LONG P[BF_ROUNDS + 2];
	BF_LONG S[4 * 256];
	} BF_KEY;

typedef struct cast_key_st {
	CAST_LONG data[32];
	int short_key;
	} CAST_KEY;

typedef OSSL_CMP_MSG *(*OSSL_CMP_transfer_cb_t) (OSSL_CMP_CTX *ctx,
	const OSSL_CMP_MSG *req);

typedef int (*OSSL_CMP_certConf_cb_t) (OSSL_CMP_CTX *ctx, X509 *cert,
	int fail_info, const char **txt);

typedef OSSL_CMP_PKISI *(*OSSL_CMP_SRV_cert_request_cb_t)
	(OSSL_CMP_SRV_CTX *srv_ctx, const OSSL_CMP_MSG *req, int certReqId,
	const OSSL_CRMF_MSG *crm, const X509_REQ *p10cr,
	X509 **certOut, STACK_OF(X509) **chainOut, STACK_OF(X509) **caPubs);

typedef OSSL_CMP_PKISI *(*OSSL_CMP_SRV_rr_cb_t)(OSSL_CMP_SRV_CTX *srv_ctx,
	const OSSL_CMP_MSG *req,
	const X509_NAME *issuer,
	const ASN1_INTEGER *serial);

typedef int (*OSSL_CMP_SRV_genm_cb_t)(OSSL_CMP_SRV_CTX *srv_ctx,
	const OSSL_CMP_MSG *req,
	const STACK_OF(OSSL_CMP_ITAV) *in,
	STACK_OF(OSSL_CMP_ITAV) **out);

typedef void (*OSSL_CMP_SRV_error_cb_t)(OSSL_CMP_SRV_CTX *srv_ctx,
	const OSSL_CMP_MSG *req,
	const OSSL_CMP_PKISI *statusInfo,
	const ASN1_INTEGER *errorCode,
	const OSSL_CMP_PKIFREETEXT *errDetails);

typedef int (*OSSL_CMP_SRV_certConf_cb_t)(OSSL_CMP_SRV_CTX *srv_ctx,
	const OSSL_CMP_MSG *req,
	int certReqId,
	const ASN1_OCTET_STRING *certHash,
	const OSSL_CMP_PKISI *si);

typedef int (*OSSL_CMP_SRV_pollReq_cb_t)(OSSL_CMP_SRV_CTX *srv_ctx,
	const OSSL_CMP_MSG *req, int certReqId,
	OSSL_CMP_MSG **certReq,
	int64_t *check_after);

typedef int (*OSSL_CMP_SRV_delayed_delivery_cb_t)(OSSL_CMP_SRV_CTX *srv_ctx,
	const OSSL_CMP_MSG *req);

typedef int (*OSSL_CMP_SRV_clean_transaction_cb_t)(OSSL_CMP_SRV_CTX *srv_ctx,
	const ASN1_OCTET_STRING *id);

typedef int (*OSSL_CMP_log_cb_t)(const char *func, const char *file, int line,
	OSSL_CMP_severity level, const char *msg);

typedef int (OSSL_provider_init_fn)(const OSSL_CORE_HANDLE *handle,
	const OSSL_DISPATCH *in,
	const OSSL_DISPATCH **out,
	void **provctx);

typedef int (OSSL_INOUT_CALLBACK)(const OSSL_PARAM in_params[],
	OSSL_PARAM out_params[], void *arg);

typedef int (OSSL_PASSPHRASE_CALLBACK)(char *pass, size_t pass_size,
	size_t *pass_len,
	const OSSL_PARAM params[], void *arg);

typedef struct {
	int dummy;
	} CRYPTO_dynlock;

typedef void CRYPTO_EX_new (void *parent, void *ptr, CRYPTO_EX_DATA *ad,
	int idx, long argl, void *argp);

typedef void CRYPTO_EX_free (void *parent, void *ptr, CRYPTO_EX_DATA *ad,
	int idx, long argl, void *argp);

typedef int CRYPTO_EX_dup (CRYPTO_EX_DATA *to, const CRYPTO_EX_DATA *from,
	void **from_d, int idx, long argl, void *argp);

typedef struct crypto_threadid_st {
	int dummy;
	} CRYPTO_THREADID;

typedef void *(*CRYPTO_realloc_fn)(void *addr, size_t num, const char *file,
	int line);

typedef enum {
	CT_LOG_ENTRY_TYPE_NOT_SET = -1,
	CT_LOG_ENTRY_TYPE_X509 = 0,
	CT_LOG_ENTRY_TYPE_PRECERT = 1
	} ct_log_entry_type_t;

typedef enum {
	SCT_VERSION_NOT_SET = -1,
	SCT_VERSION_V1 = 0
	} sct_version_t;

typedef enum {
	SCT_SOURCE_UNKNOWN,
	SCT_SOURCE_TLS_EXTENSION,
	SCT_SOURCE_X509V3_EXTENSION,
	SCT_SOURCE_OCSP_STAPLED_RESPONSE
	} sct_source_t;

typedef enum {
	SCT_VALIDATION_STATUS_NOT_SET,
	SCT_VALIDATION_STATUS_UNKNOWN_LOG,
	SCT_VALIDATION_STATUS_VALID,
	SCT_VALIDATION_STATUS_INVALID,
	SCT_VALIDATION_STATUS_UNVERIFIED,
	SCT_VALIDATION_STATUS_UNKNOWN_VERSION
	} sct_validation_status_t;

typedef int OSSL_DECODER_CONSTRUCT(OSSL_DECODER_INSTANCE *decoder_inst,
	const OSSL_PARAM *params,
	void *construct_data);

typedef struct DES_ks {
	union {
	DES_cblock cblock;
	DES_LONG deslong[2];
	} ks[16];
	} DES_key_schedule;

typedef enum {
	POINT_CONVERSION_COMPRESSED = 2,
	POINT_CONVERSION_UNCOMPRESSED = 4,
	POINT_CONVERSION_HYBRID = 6
	} point_conversion_form_t;

typedef struct {
	int nid;
	const char *comment;
	} EC_builtin_curve;

typedef const void *OSSL_ENCODER_CONSTRUCT(OSSL_ENCODER_INSTANCE *encoder_inst,
	void *construct_data);

typedef struct ENGINE_CMD_DEFN_st {
	unsigned int cmd_num;
	const char *cmd_name;
	const char *cmd_desc;
	unsigned int cmd_flags;
	} ENGINE_CMD_DEFN;

typedef int (*ENGINE_CTRL_FUNC_PTR) (ENGINE *, int, long, void *,
	void (*f) (void));

typedef EVP_PKEY *(*ENGINE_LOAD_KEY_PTR)(ENGINE *, const char *,
	UI_METHOD *ui_method,
	void *callback_data);

typedef int (*ENGINE_SSL_CLIENT_CERT_PTR) (ENGINE *, SSL *ssl,
	STACK_OF(X509_NAME) *ca_dn,
	X509 **pcert, EVP_PKEY **pkey,
	STACK_OF(X509) **pother,
	UI_METHOD *ui_method,
	void *callback_data);

typedef int (*ENGINE_CIPHERS_PTR) (ENGINE *, const EVP_CIPHER **,
	const int **, int);

typedef int (*ENGINE_DIGESTS_PTR) (ENGINE *, const EVP_MD **, const int **,
	int);

typedef int (*ENGINE_PKEY_METHS_PTR) (ENGINE *, EVP_PKEY_METHOD **,
	const int **, int);

typedef int (*ENGINE_PKEY_ASN1_METHS_PTR) (ENGINE *, EVP_PKEY_ASN1_METHOD **,
	const int **, int);

typedef struct st_dynamic_MEM_fns {
	dyn_MEM_malloc_fn malloc_fn;
	dyn_MEM_realloc_fn realloc_fn;
	dyn_MEM_free_fn free_fn;
	} dynamic_MEM_fns;

typedef struct st_dynamic_fns {
	void *static_state;
	dynamic_MEM_fns mem_fns;
	} dynamic_fns;

typedef int (*dynamic_bind_engine) (ENGINE *e, const char *id,
	const dynamic_fns *fns);

typedef struct ERR_string_data_st {
	unsigned long error;
	const char *string;
	} ERR_STRING_DATA;

typedef struct {
	unsigned char *out;
	const unsigned char *inp;
	size_t len;
	unsigned int interleave;
	} EVP_CTRL_TLS1_1_MULTIBLOCK_PARAM;

typedef struct evp_cipher_info_st {
	const EVP_CIPHER *cipher;
	unsigned char iv[EVP_MAX_IV_LENGTH];
	} EVP_CIPHER_INFO;

typedef int (EVP_PBE_KEYGEN) (EVP_CIPHER_CTX *ctx, const char *pass,
	int passlen, ASN1_TYPE *param,
	const EVP_CIPHER *cipher, const EVP_MD *md,
	int en_de);

typedef int (EVP_PBE_KEYGEN_EX) (EVP_CIPHER_CTX *ctx, const char *pass,
	int passlen, ASN1_TYPE *param,
	const EVP_CIPHER *cipher, const EVP_MD *md,
	int en_de, OSSL_LIB_CTX *libctx, const char *propq);

typedef struct {
	uint16_t    kem_id;
	uint16_t    kdf_id;
	uint16_t    aead_id;
	} OSSL_HPKE_SUITE;

typedef struct idea_key_st {
	IDEA_INT data[9][6];
	} IDEA_KEY_SCHEDULE;

typedef struct MD2state_st {
	unsigned int num;
	unsigned char data[MD2_BLOCK];
	MD2_INT cksm[MD2_BLOCK];
	MD2_INT state[MD2_BLOCK];
	} MD2_CTX;

typedef struct MD4state_st {
	MD4_LONG A, B, C, D;
	MD4_LONG Nl, Nh;
	MD4_LONG data[MD4_LBLOCK];
	unsigned int num;
	} MD4_CTX;

typedef struct MD5state_st {
	MD5_LONG A, B, C, D;
	MD5_LONG Nl, Nh;
	MD5_LONG data[MD5_LBLOCK];
	unsigned int num;
	} MD5_CTX;

typedef struct mdc2_ctx_st {
	unsigned int num;
	unsigned char data[MDC2_BLOCK];
	DES_cblock h, hh;
	unsigned int pad_type;
	} MDC2_CTX;

typedef void (*block128_f) (const unsigned char in[16],
	unsigned char out[16], const void *key);

typedef void (*cbc128_f) (const unsigned char *in, unsigned char *out,
	size_t len, const void *key,
	unsigned char ivec[16], int enc);

typedef void (*ecb128_f) (const unsigned char *in, unsigned char *out,
	size_t len, const void *key,
	int enc);

typedef void (*ctr128_f) (const unsigned char *in, unsigned char *out,
	size_t blocks, const void *key,
	const unsigned char ivec[16]);

typedef void (*ccm128_f) (const unsigned char *in, unsigned char *out,
	size_t blocks, const void *key,
	const unsigned char ivec[16],
	unsigned char cmac[16]);

typedef void (*ocb128_f) (const unsigned char *in, unsigned char *out,
	size_t blocks, const void *key,
	size_t start_block_num,
	unsigned char offset_i[16],
	const unsigned char L_[][16],
	unsigned char checksum[16]);

typedef struct obj_name_st {
	int type;
	int alias;
	const char *name;
	const char *data;
	} OBJ_NAME;

typedef struct PKCS7_CTX_st {
	OSSL_LIB_CTX *libctx;
	char *propq;
	} PKCS7_CTX;

typedef struct pkcs7_issuer_and_serial_st {
	X509_NAME *issuer;
	ASN1_INTEGER *serial;
	} PKCS7_ISSUER_AND_SERIAL;

typedef struct pkcs7_signer_info_st {
	ASN1_INTEGER *version;
	PKCS7_ISSUER_AND_SERIAL *issuer_and_serial;
	X509_ALGOR *digest_alg;
	STACK_OF(X509_ATTRIBUTE) *auth_attr;
	X509_ALGOR *digest_enc_alg;
	ASN1_OCTET_STRING *enc_digest;
	STACK_OF(X509_ATTRIBUTE) *unauth_attr;
	EVP_PKEY *pkey;
	const PKCS7_CTX *ctx;
	} PKCS7_SIGNER_INFO;

typedef struct pkcs7_recip_info_st {
	ASN1_INTEGER *version;
	PKCS7_ISSUER_AND_SERIAL *issuer_and_serial;
	X509_ALGOR *key_enc_algor;
	ASN1_OCTET_STRING *enc_key;
	X509 *cert;
	const PKCS7_CTX *ctx;
	} PKCS7_RECIP_INFO;

typedef struct pkcs7_signed_st {
	ASN1_INTEGER *version;
	STACK_OF(X509_ALGOR) *md_algs;
	STACK_OF(X509) *cert;
	STACK_OF(X509_CRL) *crl;
	STACK_OF(PKCS7_SIGNER_INFO) *signer_info;
	struct pkcs7_st *contents;
	} PKCS7_SIGNED;

typedef struct pkcs7_enc_content_st {
	ASN1_OBJECT *content_type;
	X509_ALGOR *algorithm;
	ASN1_OCTET_STRING *enc_data;
	const EVP_CIPHER *cipher;
	const PKCS7_CTX *ctx;
	} PKCS7_ENC_CONTENT;

typedef struct pkcs7_enveloped_st {
	ASN1_INTEGER *version;
	STACK_OF(PKCS7_RECIP_INFO) *recipientinfo;
	PKCS7_ENC_CONTENT *enc_data;
	} PKCS7_ENVELOPE;

typedef struct pkcs7_signedandenveloped_st {
	ASN1_INTEGER *version;
	STACK_OF(X509_ALGOR) *md_algs;
	STACK_OF(X509) *cert;
	STACK_OF(X509_CRL) *crl;
	STACK_OF(PKCS7_SIGNER_INFO) *signer_info;
	PKCS7_ENC_CONTENT *enc_data;
	STACK_OF(PKCS7_RECIP_INFO) *recipientinfo;
	} PKCS7_SIGN_ENVELOPE;

typedef struct pkcs7_digest_st {
	ASN1_INTEGER *version;
	X509_ALGOR *md;
	struct pkcs7_st *contents;
	ASN1_OCTET_STRING *digest;
	} PKCS7_DIGEST;

typedef struct pkcs7_encrypted_st {
	ASN1_INTEGER *version;
	PKCS7_ENC_CONTENT *enc_data;
	} PKCS7_ENCRYPT;

typedef struct pkcs7_st {
	unsigned char *asn1;
	long length;
	int state;
	int detached;
	ASN1_OBJECT *type;
	union {
	char *ptr;
	ASN1_OCTET_STRING *data;
	PKCS7_SIGNED *sign;
	PKCS7_ENVELOPE *enveloped;
	PKCS7_SIGN_ENVELOPE *signed_and_enveloped;
	PKCS7_DIGEST *digest;
	PKCS7_ENCRYPT *encrypted;
	ASN1_TYPE *other;
	} d;
	PKCS7_CTX ctx;
	} PKCS7;

typedef struct rc2_key_st {
	RC2_INT data[64];
	} RC2_KEY;

typedef struct rc4_key_st {
	RC4_INT x, y;
	RC4_INT data[256];
	} RC4_KEY;

typedef struct rc5_key_st {
	int rounds;
	RC5_32_INT data[2 * (RC5_16_ROUNDS + 1)];
	} RC5_32_KEY;

typedef struct RIPEMD160state_st {
	RIPEMD160_LONG A, B, C, D, E;
	RIPEMD160_LONG Nl, Nh;
	RIPEMD160_LONG data[RIPEMD160_LBLOCK];
	unsigned int num;
	} RIPEMD160_CTX;

typedef struct rsa_oaep_params_st {
	X509_ALGOR *hashFunc;
	X509_ALGOR *maskGenFunc;
	X509_ALGOR *pSourceFunc;
	X509_ALGOR *maskHash;
	} RSA_OAEP_PARAMS;

typedef struct seed_key_st {
	#   ifdef SEED_LONG
	unsigned long data[32];
	#   else
	unsigned int data[32];
	#   endif
	} SEED_KEY_SCHEDULE;

typedef struct SHAstate_st {
	SHA_LONG h0, h1, h2, h3, h4;
	SHA_LONG Nl, Nh;
	SHA_LONG data[SHA_LBLOCK];
	unsigned int num;
	} SHA_CTX;

typedef struct SHA256state_st {
	SHA_LONG h[8];
	SHA_LONG Nl, Nh;
	SHA_LONG data[SHA_LBLOCK];
	unsigned int num, md_len;
	} SHA256_CTX;

typedef struct SHA512state_st {
	SHA_LONG64 h[8];
	SHA_LONG64 Nl, Nh;
	union {
	SHA_LONG64 d[SHA_LBLOCK];
	unsigned char p[SHA512_CBLOCK];
	} u;
	unsigned int num, md_len;
	} SHA512_CTX;

typedef struct SRP_gN_cache_st {
	char *b64_bn;
	BIGNUM *bn;
	} SRP_gN_cache;

typedef struct SRP_user_pwd_st {
	char *id;
	BIGNUM *s;
	BIGNUM *v;
	const BIGNUM *g;
	const BIGNUM *N;
	char *info;
	} SRP_user_pwd;

typedef struct SRP_VBASE_st {
	STACK_OF(SRP_user_pwd) *users_pwd;
	STACK_OF(SRP_gN_cache) *gN_cache;
	char *seed_key;
	const BIGNUM *default_g;
	const BIGNUM *default_N;
	} SRP_VBASE;

typedef struct SRP_gN_st {
	char *id;
	const BIGNUM *g;
	const BIGNUM *N;
	} SRP_gN;

typedef struct srtp_protection_profile_st {
	const char *name;
	unsigned long id;
	} SRTP_PROTECTION_PROFILE;

typedef int (*tls_session_ticket_ext_cb_fn)(SSL *s, const unsigned char *data,
	int len, void *arg);

typedef int (*tls_session_secret_cb_fn)(SSL *s, void *secret, int *secret_len,
	STACK_OF(SSL_CIPHER) *peer_ciphers,
	const SSL_CIPHER **cipher, void *arg);

typedef int (*custom_ext_add_cb)(SSL *s, unsigned int ext_type,
	const unsigned char **out, size_t *outlen,
	int *al, void *add_arg);

typedef void (*custom_ext_free_cb)(SSL *s, unsigned int ext_type,
	const unsigned char *out, void *add_arg);

typedef int (*custom_ext_parse_cb)(SSL *s, unsigned int ext_type,
	const unsigned char *in, size_t inlen,
	int *al, void *parse_arg);

typedef int (*SSL_custom_ext_add_cb_ex)(SSL *s, unsigned int ext_type,
	unsigned int context,
	const unsigned char **out,
	size_t *outlen, X509 *x,
	size_t chainidx,
	int *al, void *add_arg);

typedef void (*SSL_custom_ext_free_cb_ex)(SSL *s, unsigned int ext_type,
	unsigned int context,
	const unsigned char *out,
	void *add_arg);

typedef int (*SSL_custom_ext_parse_cb_ex)(SSL *s, unsigned int ext_type,
	unsigned int context,
	const unsigned char *in,
	size_t inlen, X509 *x,
	size_t chainidx,
	int *al, void *parse_arg);

typedef int (*GEN_SESSION_CB) (SSL *ssl, unsigned char *id,
	unsigned int *id_len);

typedef int (*SSL_CTX_npn_advertised_cb_func)(SSL *ssl,
	const unsigned char **out,
	unsigned int *outlen,
	void *arg);

typedef int (*SSL_CTX_npn_select_cb_func)(SSL *s,
	unsigned char **out,
	unsigned char *outlen,
	const unsigned char *in,
	unsigned int inlen,
	void *arg);

typedef int (*SSL_CTX_alpn_select_cb_func)(SSL *ssl,
	const unsigned char **out,
	unsigned char *outlen,
	const unsigned char *in,
	unsigned int inlen,
	void *arg);

typedef unsigned int (*SSL_psk_client_cb_func)(SSL *ssl,
	const char *hint,
	char *identity,
	unsigned int max_identity_len,
	unsigned char *psk,
	unsigned int max_psk_len);

typedef unsigned int (*SSL_psk_server_cb_func)(SSL *ssl,
	const char *identity,
	unsigned char *psk,
	unsigned int max_psk_len);

typedef int (*SSL_psk_find_session_cb_func)(SSL *ssl,
	const unsigned char *identity,
	size_t identity_len,
	SSL_SESSION **sess);

typedef int (*SSL_psk_use_session_cb_func)(SSL *ssl, const EVP_MD *md,
	const unsigned char **id,
	size_t *idlen,
	SSL_SESSION **sess);

typedef enum {
	TLS_ST_BEFORE,
	TLS_ST_OK,
	DTLS_ST_CR_HELLO_VERIFY_REQUEST,
	TLS_ST_CR_SRVR_HELLO,
	TLS_ST_CR_CERT,
	TLS_ST_CR_COMP_CERT,
	TLS_ST_CR_CERT_STATUS,
	TLS_ST_CR_KEY_EXCH,
	TLS_ST_CR_CERT_REQ,
	TLS_ST_CR_SRVR_DONE,
	TLS_ST_CR_SESSION_TICKET,
	TLS_ST_CR_CHANGE,
	TLS_ST_CR_FINISHED,
	TLS_ST_CW_CLNT_HELLO,
	TLS_ST_CW_CERT,
	TLS_ST_CW_COMP_CERT,
	TLS_ST_CW_KEY_EXCH,
	TLS_ST_CW_CERT_VRFY,
	TLS_ST_CW_CHANGE,
	TLS_ST_CW_NEXT_PROTO,
	TLS_ST_CW_FINISHED,
	TLS_ST_SW_HELLO_REQ,
	TLS_ST_SR_CLNT_HELLO,
	DTLS_ST_SW_HELLO_VERIFY_REQUEST,
	TLS_ST_SW_SRVR_HELLO,
	TLS_ST_SW_CERT,
	TLS_ST_SW_COMP_CERT,
	TLS_ST_SW_KEY_EXCH,
	TLS_ST_SW_CERT_REQ,
	TLS_ST_SW_SRVR_DONE,
	TLS_ST_SR_CERT,
	TLS_ST_SR_COMP_CERT,
	TLS_ST_SR_KEY_EXCH,
	TLS_ST_SR_CERT_VRFY,
	TLS_ST_SR_NEXT_PROTO,
	TLS_ST_SR_CHANGE,
	TLS_ST_SR_FINISHED,
	TLS_ST_SW_SESSION_TICKET,
	TLS_ST_SW_CERT_STATUS,
	TLS_ST_SW_CHANGE,
	TLS_ST_SW_FINISHED,
	TLS_ST_SW_ENCRYPTED_EXTENSIONS,
	TLS_ST_CR_ENCRYPTED_EXTENSIONS,
	TLS_ST_CR_CERT_VRFY,
	TLS_ST_SW_CERT_VRFY,
	TLS_ST_CR_HELLO_REQ,
	TLS_ST_SW_KEY_UPDATE,
	TLS_ST_CW_KEY_UPDATE,
	TLS_ST_SR_KEY_UPDATE,
	TLS_ST_CR_KEY_UPDATE,
	TLS_ST_EARLY_DATA,
	TLS_ST_PENDING_EARLY_DATA_END,
	TLS_ST_CW_END_OF_EARLY_DATA,
	TLS_ST_SR_END_OF_EARLY_DATA
	} OSSL_HANDSHAKE_STATE;

typedef struct ssl_shutdown_ex_args_st {
	uint64_t    quic_error_code;
	const char  *quic_reason;
	} SSL_SHUTDOWN_EX_ARGS;

typedef struct ssl_stream_reset_args_st {
	uint64_t quic_error_code;
	} SSL_STREAM_RESET_ARGS;

typedef struct ssl_conn_close_info_st {
	uint64_t    error_code, frame_type;
	const char  *reason;
	size_t      reason_len;
	uint32_t    flags;
	} SSL_CONN_CLOSE_INFO;

typedef struct ssl_poll_item_st {
	BIO_POLL_DESCRIPTOR desc;
	uint64_t            events, revents;
	} SSL_POLL_ITEM;

typedef int (*ssl_ct_validation_cb)(const CT_POLICY_EVAL_CTX *ctx,
	const STACK_OF(SCT) *scts, void *arg);

typedef SSL_TICKET_RETURN (*SSL_CTX_decrypt_session_ticket_fn)(SSL *s, SSL_SESSION *ss,
	const unsigned char *keyname,
	size_t keyname_length,
	SSL_TICKET_STATUS status,
	void *arg);

typedef OSSL_STORE_INFO *(*OSSL_STORE_post_process_info_fn)(OSSL_STORE_INFO *,
	void *);

typedef OSSL_STORE_LOADER_CTX *(*OSSL_STORE_open_fn)
	(const OSSL_STORE_LOADER *loader, const char *uri,
	const UI_METHOD *ui_method, void *ui_data);

typedef OSSL_STORE_LOADER_CTX *(*OSSL_STORE_open_ex_fn)
	(const OSSL_STORE_LOADER *loader,
	const char *uri, OSSL_LIB_CTX *libctx, const char *propq,
	const UI_METHOD *ui_method, void *ui_data);

typedef OSSL_STORE_LOADER_CTX *(*OSSL_STORE_attach_fn)
	(const OSSL_STORE_LOADER *loader, BIO *bio,
	OSSL_LIB_CTX *libctx, const char *propq,
	const UI_METHOD *ui_method, void *ui_data);

typedef struct {
   unsigned int gp_offset;
   unsigned int fp_offset;
   void *overflow_arg_area;
   void *reg_save_area;
} va_list[1];
typedef int (*OSSL_STORE_ctrl_fn)
	(OSSL_STORE_LOADER_CTX *ctx, int cmd, va_list args);

typedef int (*OSSL_STORE_expect_fn)
	(OSSL_STORE_LOADER_CTX *ctx, int expected);

typedef int (*OSSL_STORE_find_fn)
	(OSSL_STORE_LOADER_CTX *ctx, const OSSL_STORE_SEARCH *criteria);

typedef OSSL_STORE_INFO *(*OSSL_STORE_load_fn)
	(OSSL_STORE_LOADER_CTX *ctx, const UI_METHOD *ui_method, void *ui_data);

typedef size_t (*OSSL_trace_cb)(const char *buffer, size_t count,
	int category, int cmd, void *data);

typedef int (*TS_time_cb) (struct TS_resp_ctx *, void *, long *sec,
	long *usec);

typedef int (*TS_extension_cb) (struct TS_resp_ctx *, X509_EXTENSION *,
	void *);

typedef struct txt_db_st {
	int num_fields;
	STACK_OF(OPENSSL_PSTRING) *data;
	LHASH_OF(OPENSSL_STRING) **index;
	int (**qual) (OPENSSL_STRING *);
	long error;
	long arg1;
	long arg2;
	OPENSSL_STRING *arg_row;
	} TXT_DB;

typedef struct {
	union {
	unsigned char c[WHIRLPOOL_DIGEST_LENGTH];
	double q[WHIRLPOOL_DIGEST_LENGTH / sizeof(double)];
	} H;
	unsigned char data[WHIRLPOOL_BBLOCK / 8];
	unsigned int bitoff;
	size_t bitlen[WHIRLPOOL_COUNTER / sizeof(size_t)];
	} WHIRLPOOL_CTX;

typedef struct X509_val_st {
	ASN1_TIME *notBefore;
	ASN1_TIME *notAfter;
	} X509_VAL;

typedef struct private_key_st {
	int version;
	X509_ALGOR *enc_algor;
	ASN1_OCTET_STRING *enc_pkey;
	EVP_PKEY *dec_pkey;
	int key_length;
	char *key_data;
	int key_free;
	EVP_CIPHER_INFO cipher;
	} X509_PKEY;

typedef struct X509_info_st {
	X509 *x509;
	X509_CRL *crl;
	X509_PKEY *x_pkey;
	EVP_CIPHER_INFO enc_cipher;
	int enc_len;
	char *enc_data;
	} X509_INFO;

typedef struct Netscape_spkac_st {
	X509_PUBKEY *pubkey;
	ASN1_IA5STRING *challenge;
	} NETSCAPE_SPKAC;

typedef struct Netscape_spki_st {
	NETSCAPE_SPKAC *spkac;
	X509_ALGOR sig_algor;
	ASN1_BIT_STRING *signature;
	} NETSCAPE_SPKI;

typedef struct Netscape_certificate_sequence {
	ASN1_OBJECT *type;
	STACK_OF(X509) *certs;
	} NETSCAPE_CERT_SEQUENCE;

typedef struct PBEPARAM_st {
	ASN1_OCTET_STRING *salt;
	ASN1_INTEGER *iter;
	} PBEPARAM;

typedef struct PBE2PARAM_st {
	X509_ALGOR *keyfunc;
	X509_ALGOR *encryption;
	} PBE2PARAM;

typedef struct PBKDF2PARAM_st {
	ASN1_TYPE *salt;
	ASN1_INTEGER *iter;
	ASN1_INTEGER *keylength;
	X509_ALGOR *prf;
	} PBKDF2PARAM;

typedef struct SCRYPT_PARAMS_st {
	ASN1_OCTET_STRING *salt;
	ASN1_INTEGER *costParameter;
	ASN1_INTEGER *blockSize;
	ASN1_INTEGER *parallelizationParameter;
	ASN1_INTEGER *keyLength;
	} SCRYPT_PARAMS;

typedef STACK_OF(CONF_VALUE) *
	(*X509V3_EXT_I2V) (const struct v3_ext_method *method, void *ext,
	STACK_OF(CONF_VALUE) *extlist);

typedef void *(*X509V3_EXT_V2I)(const struct v3_ext_method *method,
	struct v3_ext_ctx *ctx,
	STACK_OF(CONF_VALUE) *values);

typedef char *(*X509V3_EXT_I2S)(const struct v3_ext_method *method,
	void *ext);

typedef void *(*X509V3_EXT_S2I)(const struct v3_ext_method *method,
	struct v3_ext_ctx *ctx, const char *str);

typedef int (*X509V3_EXT_I2R) (const struct v3_ext_method *method, void *ext,
	BIO *out, int indent);

typedef void *(*X509V3_EXT_R2I)(const struct v3_ext_method *method,
	struct v3_ext_ctx *ctx, const char *str);

typedef struct BASIC_CONSTRAINTS_st {
	int ca;
	ASN1_INTEGER *pathlen;
	} BASIC_CONSTRAINTS;

typedef struct PKEY_USAGE_PERIOD_st {
	ASN1_GENERALIZEDTIME *notBefore;
	ASN1_GENERALIZEDTIME *notAfter;
	} PKEY_USAGE_PERIOD;

typedef struct ACCESS_DESCRIPTION_st {
	ASN1_OBJECT *method;
	GENERAL_NAME *location;
	} ACCESS_DESCRIPTION;

typedef struct SXNET_ID_st {
	ASN1_INTEGER *zone;
	ASN1_OCTET_STRING *user;
	} SXNETID;

typedef struct SXNET_st {
	ASN1_INTEGER *version;
	STACK_OF(SXNETID) *ids;
	} SXNET;

typedef struct ISSUER_SIGN_TOOL_st {
	ASN1_UTF8STRING *signTool;
	ASN1_UTF8STRING *cATool;
	ASN1_UTF8STRING *signToolCert;
	ASN1_UTF8STRING *cAToolCert;
	} ISSUER_SIGN_TOOL;

typedef struct POLICY_CONSTRAINTS_st {
	ASN1_INTEGER *requireExplicitPolicy;
	ASN1_INTEGER *inhibitPolicyMapping;
	} POLICY_CONSTRAINTS;

typedef struct PROXY_POLICY_st {
	ASN1_OBJECT *policyLanguage;
	ASN1_OCTET_STRING *policy;
	} PROXY_POLICY;

typedef struct PROXY_CERT_INFO_EXTENSION_st {
	ASN1_INTEGER *pcPathLengthConstraint;
	PROXY_POLICY *proxyPolicy;
	} PROXY_CERT_INFO_EXTENSION;

typedef struct x509_purpose_st {
	int purpose;
	int trust;
	int flags;
	int (*check_purpose) (const struct x509_purpose_st *, const X509 *, int);
	char *name;
	char *sname;
	void *usr_data;
	} X509_PURPOSE;

typedef struct ASIdentifierChoice_st {
	int type;
	union {
	ASN1_NULL *inherit;
	ASIdOrRanges *asIdsOrRanges;
	} u;
	} ASIdentifierChoice;

typedef struct ASIdentifiers_st {
	ASIdentifierChoice *asnum, *rdi;
	} ASIdentifiers;

typedef enum {
	X509_LU_NONE = 0,
	X509_LU_X509, X509_LU_CRL
	} X509_LOOKUP_TYPE;

typedef struct x509_trust_st {
	int trust;
	int flags;
	int (*check_trust) (struct x509_trust_st *, X509 *, int);
	char *name;
	int arg1;
	void *arg2;
	} X509_TRUST;

typedef int (*X509_STORE_CTX_get_issuer_fn)(X509 **issuer,
	X509_STORE_CTX *ctx, X509 *x);

typedef int (*X509_STORE_CTX_check_issued_fn)(X509_STORE_CTX *ctx,
	X509 *x, X509 *issuer);

typedef int (*X509_STORE_CTX_get_crl_fn)(X509_STORE_CTX *ctx,
	X509_CRL **crl, X509 *x);

typedef int (*X509_STORE_CTX_cert_crl_fn)(X509_STORE_CTX *ctx,
	X509_CRL *crl, X509 *x);

typedef STACK_OF(X509)
	*(*X509_STORE_CTX_lookup_certs_fn)(X509_STORE_CTX *ctx,
	const X509_NAME *nm);

typedef STACK_OF(X509_CRL)
	*(*X509_STORE_CTX_lookup_crls_fn)(const X509_STORE_CTX *ctx,
	const X509_NAME *nm);

typedef int (*X509_LOOKUP_ctrl_fn)(X509_LOOKUP *ctx, int cmd, const char *argc,
	long argl, char **ret);

typedef int (*X509_LOOKUP_ctrl_ex_fn)(
	X509_LOOKUP *ctx, int cmd, const char *argc, long argl, char **ret,
	OSSL_LIB_CTX *libctx, const char *propq);

typedef int (*X509_LOOKUP_get_by_subject_fn)(X509_LOOKUP *ctx,
	X509_LOOKUP_TYPE type,
	const X509_NAME *name,
	X509_OBJECT *ret);

typedef int (*X509_LOOKUP_get_by_subject_ex_fn)(X509_LOOKUP *ctx,
	X509_LOOKUP_TYPE type,
	const X509_NAME *name,
	X509_OBJECT *ret,
	OSSL_LIB_CTX *libctx,
	const char *propq);

typedef int (*X509_LOOKUP_get_by_issuer_serial_fn)(X509_LOOKUP *ctx,
	X509_LOOKUP_TYPE type,
	const X509_NAME *name,
	const ASN1_INTEGER *serial,
	X509_OBJECT *ret);

typedef int (*X509_LOOKUP_get_by_fingerprint_fn)(X509_LOOKUP *ctx,
	X509_LOOKUP_TYPE type,
	const unsigned char* bytes,
	int len,
	X509_OBJECT *ret);

typedef int (*X509_LOOKUP_get_by_alias_fn)(X509_LOOKUP *ctx,
	X509_LOOKUP_TYPE type,
	const char *str,
	int len,
	X509_OBJECT *ret);

// Functions
int ASN1_TYPE_get(const ASN1_TYPE *a);
void ASN1_TYPE_set(ASN1_TYPE *a, int type, void *value);
int ASN1_TYPE_set1(ASN1_TYPE *a, int type, const void *value);
int ASN1_TYPE_cmp(const ASN1_TYPE *a, const ASN1_TYPE *b);
void *ASN1_TYPE_unpack_sequence(const ASN1_ITEM *it, const ASN1_TYPE *t);
void ASN1_STRING_free(ASN1_STRING *a);
void ASN1_STRING_clear_free(ASN1_STRING *a);
int ASN1_STRING_copy(ASN1_STRING *dst, const ASN1_STRING *str);
int ASN1_STRING_cmp(const ASN1_STRING *a, const ASN1_STRING *b);
int ASN1_STRING_set(ASN1_STRING *str, const void *data, int len);
void ASN1_STRING_set0(ASN1_STRING *str, void *data, int len);
int ASN1_STRING_length(const ASN1_STRING *x);
int ASN1_STRING_type(const ASN1_STRING *x);
int ASN1_BIT_STRING_set(ASN1_BIT_STRING *a, unsigned char *d, int length);
int ASN1_BIT_STRING_set_bit(ASN1_BIT_STRING *a, int n, int value);
int ASN1_BIT_STRING_get_bit(const ASN1_BIT_STRING *a, int n);
int ASN1_BIT_STRING_num_asc(const char *name, BIT_STRING_BITNAME *tbl);
int ASN1_INTEGER_cmp(const ASN1_INTEGER *x, const ASN1_INTEGER *y);
int ASN1_UTCTIME_check(const ASN1_UTCTIME *a);
int ASN1_UTCTIME_set_string(ASN1_UTCTIME *s, const char *str);
int ASN1_UTCTIME_cmp_time_t(const ASN1_UTCTIME *s, time_t t);
int ASN1_GENERALIZEDTIME_check(const ASN1_GENERALIZEDTIME *a);
int ASN1_GENERALIZEDTIME_set_string(ASN1_GENERALIZEDTIME *s, const char *str);
int UTF8_getc(const unsigned char *str, int len, unsigned long *val);
int UTF8_putc(unsigned char *str, int len, unsigned long value);
int ASN1_TIME_check(const ASN1_TIME *t);
int ASN1_TIME_set_string(ASN1_TIME *s, const char *str);
int ASN1_TIME_set_string_X509(ASN1_TIME *s, const char *str);
int ASN1_TIME_to_tm(const ASN1_TIME *s, struct tm *tm);
int ASN1_TIME_normalize(ASN1_TIME *s);
int ASN1_TIME_cmp_time_t(const ASN1_TIME *s, time_t t);
int ASN1_TIME_compare(const ASN1_TIME *a, const ASN1_TIME *b);
int i2a_ASN1_INTEGER(BIO *bp, const ASN1_INTEGER *a);
int a2i_ASN1_INTEGER(BIO *bp, ASN1_INTEGER *bs, char *buf, int size);
int i2a_ASN1_ENUMERATED(BIO *bp, const ASN1_ENUMERATED *a);
int a2i_ASN1_ENUMERATED(BIO *bp, ASN1_ENUMERATED *bs, char *buf, int size);
int i2a_ASN1_OBJECT(BIO *bp, const ASN1_OBJECT *a);
int a2i_ASN1_STRING(BIO *bp, ASN1_STRING *bs, char *buf, int size);
int i2a_ASN1_STRING(BIO *bp, const ASN1_STRING *a, int type);
int i2t_ASN1_OBJECT(char *buf, int buf_len, const ASN1_OBJECT *a);
int a2d_ASN1_OBJECT(unsigned char *out, int olen, const char *buf, int num);
int ASN1_INTEGER_get_int64(int64_t *pr, const ASN1_INTEGER *a);
int ASN1_INTEGER_set_int64(ASN1_INTEGER *a, int64_t r);
int ASN1_INTEGER_get_uint64(uint64_t *pr, const ASN1_INTEGER *a);
int ASN1_INTEGER_set_uint64(ASN1_INTEGER *a, uint64_t r);
int ASN1_INTEGER_set(ASN1_INTEGER *a, long v);
long ASN1_INTEGER_get(const ASN1_INTEGER *a);
int ASN1_ENUMERATED_get_int64(int64_t *pr, const ASN1_ENUMERATED *a);
int ASN1_ENUMERATED_set_int64(ASN1_ENUMERATED *a, int64_t r);
int ASN1_ENUMERATED_set(ASN1_ENUMERATED *a, long v);
long ASN1_ENUMERATED_get(const ASN1_ENUMERATED *a);
int ASN1_PRINTABLE_type(const unsigned char *s, int max);
unsigned long ASN1_tag2bit(int tag);
int ASN1_check_infinite_end(unsigned char **p, long len);
int ASN1_const_check_infinite_end(const unsigned char **p, long len);
int ASN1_put_eoc(unsigned char **pp);
int ASN1_object_size(int constructed, int length, int tag);
void *ASN1_dup(i2d_of_void *i2d, d2i_of_void *d2i, const void *x);
void *ASN1_item_dup(const ASN1_ITEM *it, const void *x);
void *ASN1_d2i_fp(void *(*xnew) (void), d2i_of_void *d2i, FILE *in, void **x);
void *ASN1_item_d2i_fp(const ASN1_ITEM *it, FILE *in, void *x);
int ASN1_i2d_fp(i2d_of_void *i2d, FILE *out, const void *x);
int ASN1_item_i2d_fp(const ASN1_ITEM *it, FILE *out, const void *x);
int ASN1_STRING_print_ex_fp(FILE *fp, const ASN1_STRING *str, unsigned long flags);
int ASN1_STRING_to_UTF8(unsigned char **out, const ASN1_STRING *in);
void *ASN1_d2i_bio(void *(*xnew) (void), d2i_of_void *d2i, BIO *in, void **x);
void *ASN1_item_d2i_bio(const ASN1_ITEM *it, BIO *in, void *pval);
int ASN1_i2d_bio(i2d_of_void *i2d, BIO *out, const void *x);
int ASN1_item_i2d_bio(const ASN1_ITEM *it, BIO *out, const void *x);
int ASN1_UTCTIME_print(BIO *fp, const ASN1_UTCTIME *a);
int ASN1_GENERALIZEDTIME_print(BIO *fp, const ASN1_GENERALIZEDTIME *a);
int ASN1_TIME_print(BIO *bp, const ASN1_TIME *tm);
int ASN1_TIME_print_ex(BIO *bp, const ASN1_TIME *tm, unsigned long flags);
int ASN1_STRING_print(BIO *bp, const ASN1_STRING *v);
int ASN1_STRING_print_ex(BIO *out, const ASN1_STRING *str, unsigned long flags);
int ASN1_buf_print(BIO *bp, const unsigned char *buf, size_t buflen, int off);
int ASN1_parse(BIO *bp, const unsigned char *pp, long len, int indent);
int ASN1_UNIVERSALSTRING_to_string(ASN1_UNIVERSALSTRING *s);
int ASN1_TYPE_set_octetstring(ASN1_TYPE *a, unsigned char *data, int len);
int ASN1_TYPE_get_octetstring(const ASN1_TYPE *a, unsigned char *data, int max_len);
void *ASN1_item_unpack(const ASN1_STRING *oct, const ASN1_ITEM *it);
void ASN1_STRING_set_default_mask(unsigned long mask);
int ASN1_STRING_set_default_mask_asc(const char *p);
unsigned long ASN1_STRING_get_default_mask(void);
int ASN1_STRING_TABLE_add(int, long, long, unsigned long, unsigned long);
void ASN1_STRING_TABLE_cleanup(void);
void ASN1_item_free(ASN1_VALUE *val, const ASN1_ITEM *it);
int ASN1_item_i2d(const ASN1_VALUE *val, unsigned char **out, const ASN1_ITEM *it);
void ASN1_add_oid_module(void);
void ASN1_add_stable_module(void);
int ASN1_str2mask(const char *str, unsigned long *pmask);
void ASN1_PCTX_free(ASN1_PCTX *p);
unsigned long ASN1_PCTX_get_flags(const ASN1_PCTX *p);
void ASN1_PCTX_set_flags(ASN1_PCTX *p, unsigned long flags);
unsigned long ASN1_PCTX_get_nm_flags(const ASN1_PCTX *p);
void ASN1_PCTX_set_nm_flags(ASN1_PCTX *p, unsigned long flags);
unsigned long ASN1_PCTX_get_cert_flags(const ASN1_PCTX *p);
void ASN1_PCTX_set_cert_flags(ASN1_PCTX *p, unsigned long flags);
unsigned long ASN1_PCTX_get_oid_flags(const ASN1_PCTX *p);
void ASN1_PCTX_set_oid_flags(ASN1_PCTX *p, unsigned long flags);
unsigned long ASN1_PCTX_get_str_flags(const ASN1_PCTX *p);
void ASN1_PCTX_set_str_flags(ASN1_PCTX *p, unsigned long flags);
void ASN1_SCTX_free(ASN1_SCTX *p);
unsigned long ASN1_SCTX_get_flags(ASN1_SCTX *p);
void ASN1_SCTX_set_app_data(ASN1_SCTX *p, void *data);
void *ASN1_SCTX_get_app_data(ASN1_SCTX *p);
int SMIME_crlf_copy(BIO *in, BIO *out, int flags);
int SMIME_text(BIO *in, BIO *out);
int ASN1_item_ex_new(ASN1_VALUE **pval, const ASN1_ITEM *it);
void ASN1_item_ex_free(ASN1_VALUE **pval, const ASN1_ITEM *it);
int ASYNC_init_thread(size_t max_size, size_t init_size);
void ASYNC_cleanup_thread(void);
void ASYNC_WAIT_CTX_free(ASYNC_WAIT_CTX *ctx);
int ASYNC_WAIT_CTX_set_status(ASYNC_WAIT_CTX *ctx, int status);
int ASYNC_WAIT_CTX_get_status(ASYNC_WAIT_CTX *ctx);
int ASYNC_WAIT_CTX_clear_fd(ASYNC_WAIT_CTX *ctx, const void *key);
int ASYNC_is_capable(void);
int ASYNC_pause_job(void);
void ASYNC_block_pause(void);
void ASYNC_unblock_pause(void);
int BIO_get_new_index(void);
void BIO_set_flags(BIO *b, int flags);
int BIO_test_flags(const BIO *b, int flags);
void BIO_clear_flags(BIO *b, int flags);
void BIO_set_callback_ex(BIO *b, BIO_callback_fn_ex callback);
char *BIO_get_callback_arg(const BIO *b);
void BIO_set_callback_arg(BIO *b, char *arg);
int BIO_method_type(const BIO *b);
int BIO_read_filename(BIO *b, const char *name);
int BIO_ctrl_reset_read_request(BIO *b);
int BIO_set_ex_data(BIO *bio, int idx, void *data);
void *BIO_get_ex_data(const BIO *bio, int idx);
int BIO_free(BIO *a);
void BIO_set_data(BIO *a, void *ptr);
void *BIO_get_data(BIO *a);
void BIO_set_init(BIO *a, int init);
int BIO_get_init(BIO *a);
void BIO_set_shutdown(BIO *a, int shut);
int BIO_get_shutdown(BIO *a);
void BIO_vfree(BIO *a);
int BIO_up_ref(BIO *a);
int BIO_read(BIO *b, void *data, int dlen);
int BIO_read_ex(BIO *b, void *data, size_t dlen, size_t *readbytes);
int BIO_gets(BIO *bp, char *buf, int size);
int BIO_get_line(BIO *bio, char *buf, int size);
int BIO_write(BIO *b, const void *data, int dlen);
int BIO_write_ex(BIO *b, const void *data, size_t dlen, size_t *written);
int BIO_puts(BIO *bp, const char *buf);
int BIO_indent(BIO *b, int indent, int max);
long BIO_ctrl(BIO *bp, int cmd, long larg, void *parg);
long BIO_callback_ctrl(BIO *b, int cmd, BIO_info_cb *fp);
void *BIO_ptr_ctrl(BIO *bp, int cmd, long larg);
long BIO_int_ctrl(BIO *bp, int cmd, long larg, int iarg);
void BIO_free_all(BIO *a);
void BIO_set_next(BIO *b, BIO *next);
int BIO_get_retry_reason(BIO *bio);
void BIO_set_retry_reason(BIO *bio, int reason);
int BIO_nread0(BIO *bio, char **buf);
int BIO_nread(BIO *bio, char **buf, int num);
int BIO_nwrite0(BIO *bio, char **buf);
int BIO_nwrite(BIO *bio, char **buf, int num);
int BIO_dgram_non_fatal_error(int error);
int BIO_dgram_is_sctp(BIO *bio);
int BIO_dgram_sctp_wait_for_dry(BIO *b);
int BIO_dgram_sctp_msg_waiting(BIO *b);
int BIO_sock_should_retry(int i);
int BIO_sock_non_fatal_error(int error);
int BIO_err_is_non_fatal(unsigned int errcode);
int BIO_socket_wait(int fd, int for_read, time_t max_time);
int BIO_wait(BIO *bio, time_t max_time, unsigned int nap_milliseconds);
int BIO_do_connect_retry(BIO *bio, int timeout, int nap_milliseconds);
int BIO_fd_should_retry(int i);
int BIO_fd_non_fatal_error(int error);
int BIO_dump(BIO *b, const void *bytes, int len);
int BIO_dump_indent(BIO *b, const void *bytes, int len, int indent);
int BIO_dump_fp(FILE *fp, const void *s, int len);
int BIO_dump_indent_fp(FILE *fp, const void *s, int len, int indent);
int BIO_ADDR_copy(BIO_ADDR *dst, const BIO_ADDR *src);
void BIO_ADDR_free(BIO_ADDR *);
void BIO_ADDR_clear(BIO_ADDR *ap);
int BIO_ADDR_family(const BIO_ADDR *ap);
int BIO_ADDR_rawaddress(const BIO_ADDR *ap, void *p, size_t *l);
unsigned short BIO_ADDR_rawport(const BIO_ADDR *ap);
char *BIO_ADDR_hostname_string(const BIO_ADDR *ap, int numeric);
char *BIO_ADDR_service_string(const BIO_ADDR *ap, int numeric);
char *BIO_ADDR_path_string(const BIO_ADDR *ap);
int BIO_ADDRINFO_family(const BIO_ADDRINFO *bai);
int BIO_ADDRINFO_socktype(const BIO_ADDRINFO *bai);
int BIO_ADDRINFO_protocol(const BIO_ADDRINFO *bai);
void BIO_ADDRINFO_free(BIO_ADDRINFO *bai);
int BIO_sock_error(int sock);
int BIO_socket_ioctl(int fd, long type, void *arg);
int BIO_socket_nbio(int fd, int mode);
int BIO_sock_init(void);
int BIO_set_tcp_ndelay(int sock, int turn_on);
int BIO_socket(int domain, int socktype, int protocol, int options);
int BIO_connect(int sock, const BIO_ADDR *addr, int options);
int BIO_bind(int sock, const BIO_ADDR *addr, int options);
int BIO_listen(int sock, const BIO_ADDR *addr, int options);
int BIO_accept_ex(int accept_sock, BIO_ADDR *addr, int options);
int BIO_closesocket(int sock);
void BIO_copy_next_retry(BIO *b);
void BIO_meth_free(BIO_METHOD *biom);
int (*BIO_meth_get_write(const BIO_METHOD *biom)) (BIO *, const char *, int);
int (*BIO_meth_get_read(const BIO_METHOD *biom)) (BIO *, char *, int);
int (*BIO_meth_get_read_ex(const BIO_METHOD *biom)) (BIO *, char *, size_t, size_t *);
int (*BIO_meth_get_puts(const BIO_METHOD *biom)) (BIO *, const char *);
int (*BIO_meth_get_gets(const BIO_METHOD *biom)) (BIO *, char *, int);
long (*BIO_meth_get_ctrl(const BIO_METHOD *biom)) (BIO *, int, long, void *);
int (*BIO_meth_get_create(const BIO_METHOD *bion)) (BIO *);
int BIO_meth_set_create(BIO_METHOD *biom, int (*create) (BIO *));
int (*BIO_meth_get_destroy(const BIO_METHOD *biom)) (BIO *);
int BIO_meth_set_destroy(BIO_METHOD *biom, int (*destroy) (BIO *));
void BN_set_flags(BIGNUM *b, int n);
int BN_get_flags(const BIGNUM *b, int n);
void BN_with_flags(BIGNUM *dest, const BIGNUM *b, int flags);
int BN_GENCB_call(BN_GENCB *cb, int a, int b);
void BN_GENCB_free(BN_GENCB *cb);
void *BN_GENCB_get_arg(BN_GENCB *cb);
int BN_abs_is_word(const BIGNUM *a, const BN_ULONG w);
int BN_is_zero(const BIGNUM *a);
int BN_is_one(const BIGNUM *a);
int BN_is_word(const BIGNUM *a, const BN_ULONG w);
int BN_is_odd(const BIGNUM *a);
void BN_zero_ex(BIGNUM *a);
char *BN_options(void);
void BN_CTX_free(BN_CTX *c);
void BN_CTX_start(BN_CTX *ctx);
void BN_CTX_end(BN_CTX *ctx);
int BN_rand(BIGNUM *rnd, int bits, int top, int bottom);
int BN_priv_rand(BIGNUM *rnd, int bits, int top, int bottom);
int BN_rand_range(BIGNUM *rnd, const BIGNUM *range);
int BN_priv_rand_range(BIGNUM *rnd, const BIGNUM *range);
int BN_pseudo_rand(BIGNUM *rnd, int bits, int top, int bottom);
int BN_pseudo_rand_range(BIGNUM *rnd, const BIGNUM *range);
int BN_num_bits(const BIGNUM *a);
int BN_num_bits_word(BN_ULONG l);
int BN_security_bits(int L, int N);
void BN_clear_free(BIGNUM *a);
void BN_swap(BIGNUM *a, BIGNUM *b);
int BN_bn2bin(const BIGNUM *a, unsigned char *to);
int BN_bn2binpad(const BIGNUM *a, unsigned char *to, int tolen);
int BN_signed_bn2bin(const BIGNUM *a, unsigned char *to, int tolen);
int BN_bn2lebinpad(const BIGNUM *a, unsigned char *to, int tolen);
int BN_signed_bn2lebin(const BIGNUM *a, unsigned char *to, int tolen);
int BN_bn2nativepad(const BIGNUM *a, unsigned char *to, int tolen);
int BN_signed_bn2native(const BIGNUM *a, unsigned char *to, int tolen);
int BN_bn2mpi(const BIGNUM *a, unsigned char *to);
int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_usub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_uadd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
int BN_sqr(BIGNUM *r, const BIGNUM *a, BN_CTX *ctx);
void BN_set_negative(BIGNUM *b, int n);
int BN_is_negative(const BIGNUM *b);
int BN_nnmod(BIGNUM *r, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx);
int BN_mod_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx);
int BN_mod_lshift1(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx);
int BN_mod_lshift1_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *m);
int BN_mod_lshift_quick(BIGNUM *r, const BIGNUM *a, int n, const BIGNUM *m);
int BN_mul_word(BIGNUM *a, BN_ULONG w);
int BN_add_word(BIGNUM *a, BN_ULONG w);
int BN_sub_word(BIGNUM *a, BN_ULONG w);
int BN_set_word(BIGNUM *a, BN_ULONG w);
int BN_cmp(const BIGNUM *a, const BIGNUM *b);
void BN_free(BIGNUM *a);
int BN_is_bit_set(const BIGNUM *a, int n);
int BN_lshift(BIGNUM *r, const BIGNUM *a, int n);
int BN_lshift1(BIGNUM *r, const BIGNUM *a);
int BN_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int BN_mask_bits(BIGNUM *a, int n);
int BN_print_fp(FILE *fp, const BIGNUM *a);
int BN_print(BIO *bio, const BIGNUM *a);
int BN_reciprocal(BIGNUM *r, const BIGNUM *m, int len, BN_CTX *ctx);
int BN_rshift(BIGNUM *r, const BIGNUM *a, int n);
int BN_rshift1(BIGNUM *r, const BIGNUM *a);
void BN_clear(BIGNUM *a);
int BN_ucmp(const BIGNUM *a, const BIGNUM *b);
int BN_set_bit(BIGNUM *a, int n);
int BN_clear_bit(BIGNUM *a, int n);
char *BN_bn2hex(const BIGNUM *a);
char *BN_bn2dec(const BIGNUM *a);
int BN_hex2bn(BIGNUM **a, const char *str);
int BN_dec2bn(BIGNUM **a, const char *str);
int BN_asc2bn(BIGNUM **a, const char *str);
int BN_gcd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
int BN_kronecker(const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
int BN_are_coprime(BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
void BN_consttime_swap(BN_ULONG swap, BIGNUM *a, BIGNUM *b, int nwords);
int BN_is_prime_ex(const BIGNUM *p, int nchecks, BN_CTX *ctx, BN_GENCB *cb);
int BN_check_prime(const BIGNUM *p, BN_CTX *ctx, BN_GENCB *cb);
int BN_X931_generate_Xpq(BIGNUM *Xp, BIGNUM *Xq, int nbits, BN_CTX *ctx);
void BN_MONT_CTX_free(BN_MONT_CTX *mont);
int BN_MONT_CTX_set(BN_MONT_CTX *mont, const BIGNUM *mod, BN_CTX *ctx);
void BN_BLINDING_free(BN_BLINDING *b);
int BN_BLINDING_update(BN_BLINDING *b, BN_CTX *ctx);
int BN_BLINDING_convert(BIGNUM *n, BN_BLINDING *b, BN_CTX *ctx);
int BN_BLINDING_invert(BIGNUM *n, BN_BLINDING *b, BN_CTX *ctx);
int BN_BLINDING_convert_ex(BIGNUM *n, BIGNUM *r, BN_BLINDING *b, BN_CTX *);
int BN_BLINDING_is_current_thread(BN_BLINDING *b);
void BN_BLINDING_set_current_thread(BN_BLINDING *b);
int BN_BLINDING_lock(BN_BLINDING *b);
int BN_BLINDING_unlock(BN_BLINDING *b);
unsigned long BN_BLINDING_get_flags(const BN_BLINDING *);
void BN_BLINDING_set_flags(BN_BLINDING *, unsigned long);
void BN_set_params(int mul, int high, int low, int mont);
int BN_get_params(int which);
void BN_RECP_CTX_free(BN_RECP_CTX *recp);
int BN_RECP_CTX_set(BN_RECP_CTX *recp, const BIGNUM *rdiv, BN_CTX *ctx);
int BN_GF2m_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_GF2m_mod(BIGNUM *r, const BIGNUM *a, const BIGNUM *p);
int BN_GF2m_mod_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int BN_GF2m_mod_inv(BIGNUM *r, const BIGNUM *b, const BIGNUM *p, BN_CTX *ctx);
int BN_GF2m_mod_arr(BIGNUM *r, const BIGNUM *a, const int p[]);
int BN_GF2m_poly2arr(const BIGNUM *a, int p[], int max);
int BN_GF2m_arr2poly(const int p[], BIGNUM *a);
int BN_nist_mod_192(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int BN_nist_mod_224(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int BN_nist_mod_256(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int BN_nist_mod_384(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int BN_nist_mod_521(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int BN_bntest_rand(BIGNUM *rnd, int bits, int top, int bottom);
void BUF_MEM_free(BUF_MEM *a);
void BUF_reverse(unsigned char *out, const unsigned char *in, size_t siz);
void CAST_set_key(CAST_KEY *key, int len, const unsigned char *data);
void CAST_encrypt(CAST_LONG *data, const CAST_KEY *key);
void CAST_decrypt(CAST_LONG *data, const CAST_KEY *key);
void OSSL_CMP_ITAV_free(OSSL_CMP_ITAV *itav);
int OSSL_CMP_ITAV_get0_caCerts(const OSSL_CMP_ITAV *itav, STACK_OF(X509) **out);
int OSSL_CMP_ITAV_get0_rootCaCert(const OSSL_CMP_ITAV *itav, X509 **out);
void OSSL_CMP_MSG_free(OSSL_CMP_MSG *msg);
void OSSL_CMP_CTX_free(OSSL_CMP_CTX *ctx);
int OSSL_CMP_CTX_reinit(OSSL_CMP_CTX *ctx);
int OSSL_CMP_CTX_set_option(OSSL_CMP_CTX *ctx, int opt, int val);
int OSSL_CMP_CTX_get_option(const OSSL_CMP_CTX *ctx, int opt);
int OSSL_CMP_CTX_set_log_cb(OSSL_CMP_CTX *ctx, OSSL_CMP_log_cb_t cb);
void OSSL_CMP_CTX_print_errors(const OSSL_CMP_CTX *ctx);
int OSSL_CMP_CTX_set1_serverPath(OSSL_CMP_CTX *ctx, const char *path);
int OSSL_CMP_CTX_set1_server(OSSL_CMP_CTX *ctx, const char *address);
int OSSL_CMP_CTX_set_serverPort(OSSL_CMP_CTX *ctx, int port);
int OSSL_CMP_CTX_set1_proxy(OSSL_CMP_CTX *ctx, const char *name);
int OSSL_CMP_CTX_set1_no_proxy(OSSL_CMP_CTX *ctx, const char *names);
int OSSL_CMP_CTX_set_http_cb(OSSL_CMP_CTX *ctx, OSSL_HTTP_bio_cb_t cb);
int OSSL_CMP_CTX_set_http_cb_arg(OSSL_CMP_CTX *ctx, void *arg);
void *OSSL_CMP_CTX_get_http_cb_arg(const OSSL_CMP_CTX *ctx);
int OSSL_CMP_CTX_set_transfer_cb(OSSL_CMP_CTX *ctx, OSSL_CMP_transfer_cb_t cb);
int OSSL_CMP_CTX_set_transfer_cb_arg(OSSL_CMP_CTX *ctx, void *arg);
void *OSSL_CMP_CTX_get_transfer_cb_arg(const OSSL_CMP_CTX *ctx);
int OSSL_CMP_CTX_set1_srvCert(OSSL_CMP_CTX *ctx, X509 *cert);
int OSSL_CMP_CTX_set1_expected_sender(OSSL_CMP_CTX *ctx, const X509_NAME *name);
int OSSL_CMP_CTX_set0_trustedStore(OSSL_CMP_CTX *ctx, X509_STORE *store);
int OSSL_CMP_CTX_set1_untrusted(OSSL_CMP_CTX *ctx, STACK_OF(X509) *certs);
int OSSL_CMP_CTX_set1_cert(OSSL_CMP_CTX *ctx, X509 *cert);
int OSSL_CMP_CTX_set1_pkey(OSSL_CMP_CTX *ctx, EVP_PKEY *pkey);
int OSSL_CMP_CTX_set1_recipient(OSSL_CMP_CTX *ctx, const X509_NAME *name);
int OSSL_CMP_CTX_push0_geninfo_ITAV(OSSL_CMP_CTX *ctx, OSSL_CMP_ITAV *itav);
int OSSL_CMP_CTX_reset_geninfo_ITAVs(OSSL_CMP_CTX *ctx);
int OSSL_CMP_CTX_set0_newPkey(OSSL_CMP_CTX *ctx, int priv, EVP_PKEY *pkey);
int OSSL_CMP_CTX_set1_issuer(OSSL_CMP_CTX *ctx, const X509_NAME *name);
int OSSL_CMP_CTX_set1_serialNumber(OSSL_CMP_CTX *ctx, const ASN1_INTEGER *sn);
int OSSL_CMP_CTX_set1_subjectName(OSSL_CMP_CTX *ctx, const X509_NAME *name);
int OSSL_CMP_CTX_set0_reqExtensions(OSSL_CMP_CTX *ctx, X509_EXTENSIONS *exts);
int OSSL_CMP_CTX_reqExtensions_have_SAN(OSSL_CMP_CTX *ctx);
int OSSL_CMP_CTX_push0_policy(OSSL_CMP_CTX *ctx, POLICYINFO *pinfo);
int OSSL_CMP_CTX_set1_oldCert(OSSL_CMP_CTX *ctx, X509 *cert);
int OSSL_CMP_CTX_set1_p10CSR(OSSL_CMP_CTX *ctx, const X509_REQ *csr);
int OSSL_CMP_CTX_push0_genm_ITAV(OSSL_CMP_CTX *ctx, OSSL_CMP_ITAV *itav);
int OSSL_CMP_CTX_set_certConf_cb(OSSL_CMP_CTX *ctx, OSSL_CMP_certConf_cb_t cb);
int OSSL_CMP_CTX_set_certConf_cb_arg(OSSL_CMP_CTX *ctx, void *arg);
void *OSSL_CMP_CTX_get_certConf_cb_arg(const OSSL_CMP_CTX *ctx);
int OSSL_CMP_CTX_get_status(const OSSL_CMP_CTX *ctx);
int OSSL_CMP_CTX_get_failInfoCode(const OSSL_CMP_CTX *ctx);
int OSSL_CMP_MSG_get_bodytype(const OSSL_CMP_MSG *msg);
int OSSL_CMP_MSG_update_transactionID(OSSL_CMP_CTX *ctx, OSSL_CMP_MSG *msg);
int OSSL_CMP_MSG_update_recipNonce(OSSL_CMP_CTX *ctx, OSSL_CMP_MSG *msg);
int OSSL_CMP_MSG_write(const char *file, const OSSL_CMP_MSG *msg);
int i2d_OSSL_CMP_MSG_bio(BIO *bio, const OSSL_CMP_MSG *msg);
int OSSL_CMP_validate_msg(OSSL_CMP_CTX *ctx, const OSSL_CMP_MSG *msg);
void OSSL_CMP_SRV_CTX_free(OSSL_CMP_SRV_CTX *srv_ctx);
void *OSSL_CMP_SRV_CTX_get0_custom_ctx(const OSSL_CMP_SRV_CTX *srv_ctx);
int OSSL_CMP_SRV_CTX_set_accept_unprotected(OSSL_CMP_SRV_CTX *srv_ctx, int val);
int OSSL_CMP_SRV_CTX_set_accept_raverified(OSSL_CMP_SRV_CTX *srv_ctx, int val);
int OSSL_CMP_exec_RR_ses(OSSL_CMP_CTX *ctx);
int OSSL_CMP_get1_caCerts(OSSL_CMP_CTX *ctx, STACK_OF(X509) **out);
int  OSSL_CMP_log_open(void);
void OSSL_CMP_log_close(void);
void OSSL_CMP_print_errors_cb(OSSL_CMP_log_cb_t log_fn);
int CMS_dataFinal(CMS_ContentInfo *cms, BIO *bio);
int CMS_is_detached(CMS_ContentInfo *cms);
int CMS_set_detached(CMS_ContentInfo *cms, int detached);
int CMS_stream(unsigned char ***boundary, CMS_ContentInfo *cms);
int i2d_CMS_bio(BIO *bp, CMS_ContentInfo *cms);
int i2d_CMS_bio_stream(BIO *out, CMS_ContentInfo *cms, BIO *in, int flags);
int SMIME_write_CMS(BIO *bio, CMS_ContentInfo *cms, BIO *data, int flags);
int CMS_data(CMS_ContentInfo *cms, BIO *out, unsigned int flags);
int CMS_decrypt_set1_pkey(CMS_ContentInfo *cms, EVP_PKEY *pk, X509 *cert);
int CMS_RecipientInfo_type(CMS_RecipientInfo *ri);
int CMS_RecipientInfo_set0_pkey(CMS_RecipientInfo *ri, EVP_PKEY *pkey);
int CMS_RecipientInfo_ktri_cert_cmp(CMS_RecipientInfo *ri, X509 *cert);
int CMS_RecipientInfo_decrypt(CMS_ContentInfo *cms, CMS_RecipientInfo *ri);
int CMS_RecipientInfo_encrypt(const CMS_ContentInfo *cms, CMS_RecipientInfo *ri);
int CMS_set1_eContentType(CMS_ContentInfo *cms, const ASN1_OBJECT *oid);
int CMS_add0_cert(CMS_ContentInfo *cms, X509 *cert);
int CMS_add1_cert(CMS_ContentInfo *cms, X509 *cert);
int CMS_add0_crl(CMS_ContentInfo *cms, X509_CRL *crl);
int CMS_add1_crl(CMS_ContentInfo *cms, X509_CRL *crl);
int CMS_SignedData_init(CMS_ContentInfo *cms);
void CMS_SignerInfo_set1_signer_cert(CMS_SignerInfo *si, X509 *signer);
int CMS_SignerInfo_cert_cmp(CMS_SignerInfo *si, X509 *cert);
int CMS_SignerInfo_sign(CMS_SignerInfo *si);
int CMS_SignerInfo_verify(CMS_SignerInfo *si);
int CMS_SignerInfo_verify_content(CMS_SignerInfo *si, BIO *chain);
int CMS_add_smimecap(CMS_SignerInfo *si, STACK_OF(X509_ALGOR) *algs);
int CMS_add_standard_smimecap(STACK_OF(X509_ALGOR) **smcap);
int CMS_signed_get_attr_count(const CMS_SignerInfo *si);
int CMS_signed_add1_attr(CMS_SignerInfo *si, X509_ATTRIBUTE *attr);
int CMS_unsigned_get_attr_count(const CMS_SignerInfo *si);
int CMS_unsigned_add1_attr(CMS_SignerInfo *si, X509_ATTRIBUTE *attr);
int CMS_get1_ReceiptRequest(CMS_SignerInfo *si, CMS_ReceiptRequest **prr);
int CMS_add1_ReceiptRequest(CMS_SignerInfo *si, CMS_ReceiptRequest *rr);
int CMS_RecipientInfo_kari_orig_id_cmp(CMS_RecipientInfo *ri, X509 *cert);
int CMS_RecipientInfo_kari_set0_pkey(CMS_RecipientInfo *ri, EVP_PKEY *pk);
int CMS_RecipientInfo_kari_set0_pkey_and_peer(CMS_RecipientInfo *ri, EVP_PKEY *pk, X509 *peer);
int COMP_CTX_get_type(const COMP_CTX* comp);
int COMP_get_type(const COMP_METHOD *meth);
void COMP_CTX_free(COMP_CTX *ctx);
int CONF_set_default_method(CONF_METHOD *meth);
void CONF_set_nconf(CONF *conf, LHASH_OF(CONF_VALUE) *hash);
void CONF_free(LHASH_OF(CONF_VALUE) *conf);
int CONF_dump_fp(LHASH_OF(CONF_VALUE) *conf, FILE *out);
int CONF_dump_bio(LHASH_OF(CONF_VALUE) *conf, BIO *out);
void NCONF_free(CONF *conf);
void NCONF_free_data(CONF *conf);
int NCONF_load(CONF *conf, const char *file, long *eline);
int NCONF_load_fp(CONF *conf, FILE *fp, long *eline);
int NCONF_load_bio(CONF *conf, BIO *bp, long *eline);
char *NCONF_get_string(const CONF *conf, const char *group, const char *name);
int NCONF_dump_fp(const CONF *conf, FILE *out);
int NCONF_dump_bio(const CONF *conf, BIO *out);
void CONF_modules_unload(int all);
void CONF_modules_finish(void);
void *CONF_imodule_get_usr_data(const CONF_IMODULE *md);
void CONF_imodule_set_usr_data(CONF_IMODULE *md, void *usr_data);
unsigned long CONF_imodule_get_flags(const CONF_IMODULE *md);
void CONF_imodule_set_flags(CONF_IMODULE *md, unsigned long flags);
void *CONF_module_get_usr_data(CONF_MODULE *pmod);
void CONF_module_set_usr_data(CONF_MODULE *pmod, void *usr_data);
char *CONF_get1_default_config_file(void);
void OPENSSL_load_builtin_modules(void);
int _CONF_add_string(CONF *conf, CONF_VALUE *section, CONF_VALUE *value);
int _CONF_new_data(CONF *conf);
void _CONF_free_data(CONF *conf);
int OSSL_CRMF_MSG_set_certReqId(OSSL_CRMF_MSG *crm, int rid);
int OSSL_CRMF_MSG_get_certReqId(const OSSL_CRMF_MSG *crm);
int OSSL_CRMF_MSG_set0_extensions(OSSL_CRMF_MSG *crm, X509_EXTENSIONS *exts);
int OSSL_CRMF_MSG_push0_extension(OSSL_CRMF_MSG *crm, X509_EXTENSION *ext);
int CRYPTO_THREAD_unlock(CRYPTO_RWLOCK *lock);
void CRYPTO_THREAD_lock_free(CRYPTO_RWLOCK *lock);
int CRYPTO_atomic_add(int *val, int amount, int *ret, CRYPTO_RWLOCK *lock);
int CRYPTO_atomic_load(uint64_t *val, uint64_t *ret, CRYPTO_RWLOCK *lock);
int CRYPTO_atomic_load_int(int *val, int *ret, CRYPTO_RWLOCK *lock);
char *OPENSSL_buf2hexstr(const unsigned char *buf, long buflen);
unsigned char *OPENSSL_hexstr2buf(const char *str, long *buflen);
int OPENSSL_hexchar2int(unsigned char c);
int OPENSSL_strcasecmp(const char *s1, const char *s2);
int OPENSSL_strncasecmp(const char *s1, const char *s2, size_t n);
unsigned int OPENSSL_version_major(void);
unsigned int OPENSSL_version_minor(void);
unsigned int OPENSSL_version_patch(void);
unsigned long OpenSSL_version_num(void);
int OPENSSL_issetugid(void);
int CRYPTO_free_ex_index(int class_index, int idx);
int CRYPTO_new_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad);
void CRYPTO_free_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad);
int CRYPTO_set_ex_data(CRYPTO_EX_DATA *ad, int idx, void *val);
void *CRYPTO_get_ex_data(const CRYPTO_EX_DATA *ad, int idx);
void CRYPTO_free(void *ptr, const char *file, int line);
void CRYPTO_clear_free(void *ptr, size_t num, const char *file, int line);
void *CRYPTO_realloc(void *addr, size_t num, const char *file, int line);
int CRYPTO_secure_malloc_init(size_t sz, size_t minsize);
int CRYPTO_secure_malloc_done(void);
void CRYPTO_secure_free(void *ptr, const char *file, int line);
int CRYPTO_secure_allocated(const void *ptr);
int CRYPTO_secure_malloc_initialized(void);
void OPENSSL_cleanse(void *ptr, size_t len);
void CRYPTO_get_alloc_counts(int *mcount, int *rcount, int *fcount);
int OPENSSL_isservice(void);
void OPENSSL_init(void);
int OPENSSL_gmtime_adj(struct tm *tm, int offset_day, long offset_sec);
int CRYPTO_memcmp(const void * in_a, const void * in_b, size_t len);
void OPENSSL_cleanup(void);
int OPENSSL_init_crypto(uint64_t opts, const OPENSSL_INIT_SETTINGS *settings);
int OPENSSL_atexit(void (*handler)(void));
void OPENSSL_thread_stop(void);
void OPENSSL_thread_stop_ex(OSSL_LIB_CTX *ctx);
void OPENSSL_INIT_free(OPENSSL_INIT_SETTINGS *settings);
int CRYPTO_THREAD_run_once(CRYPTO_ONCE *once, void (*init)(void));
int CRYPTO_THREAD_init_local(CRYPTO_THREAD_LOCAL *key, void (*cleanup)(void *));
void *CRYPTO_THREAD_get_local(CRYPTO_THREAD_LOCAL *key);
int CRYPTO_THREAD_set_local(CRYPTO_THREAD_LOCAL *key, void *val);
int CRYPTO_THREAD_cleanup_local(CRYPTO_THREAD_LOCAL *key);
int CRYPTO_THREAD_compare_id(CRYPTO_THREAD_ID a, CRYPTO_THREAD_ID b);
int OSSL_LIB_CTX_load_config(OSSL_LIB_CTX *ctx, const char *config_file);
void OSSL_LIB_CTX_free(OSSL_LIB_CTX *);
void OSSL_sleep(uint64_t millis);
void CT_POLICY_EVAL_CTX_free(CT_POLICY_EVAL_CTX *ctx);
int CT_POLICY_EVAL_CTX_set1_cert(CT_POLICY_EVAL_CTX *ctx, X509 *cert);
int CT_POLICY_EVAL_CTX_set1_issuer(CT_POLICY_EVAL_CTX *ctx, X509 *issuer);
void CT_POLICY_EVAL_CTX_set_time(CT_POLICY_EVAL_CTX *ctx, uint64_t time_in_ms);
void SCT_free(SCT *sct);
void SCT_LIST_free(STACK_OF(SCT) *a);
void SCT_set_timestamp(SCT *sct, uint64_t timestamp);
int SCT_get_signature_nid(const SCT *sct);
void SCT_set0_extensions(SCT *sct, unsigned char *ext, size_t ext_len);
void SCT_set0_signature(SCT *sct, unsigned char *sig, size_t sig_len);
void SCT_print(const SCT *sct, BIO *out, int indent, const CTLOG_STORE *logs);
void CTLOG_free(CTLOG *log);
void CTLOG_STORE_free(CTLOG_STORE *store);
int OSSL_DECODER_up_ref(OSSL_DECODER *encoder);
void OSSL_DECODER_free(OSSL_DECODER *encoder);
int OSSL_DECODER_is_a(const OSSL_DECODER *encoder, const char *name);
int OSSL_DECODER_get_params(OSSL_DECODER *decoder, OSSL_PARAM params[]);
void OSSL_DECODER_CTX_free(OSSL_DECODER_CTX *ctx);
int OSSL_DECODER_CTX_set_selection(OSSL_DECODER_CTX *ctx, int selection);
int OSSL_DECODER_CTX_add_decoder(OSSL_DECODER_CTX *ctx, OSSL_DECODER *decoder);
int OSSL_DECODER_CTX_get_num_decoders(OSSL_DECODER_CTX *ctx);
void *OSSL_DECODER_CTX_get_construct_data(OSSL_DECODER_CTX *ctx);
int OSSL_DECODER_from_bio(OSSL_DECODER_CTX *ctx, BIO *in);
int OSSL_DECODER_from_fp(OSSL_DECODER_CTX *ctx, FILE *in);
void DES_encrypt1(DES_LONG *data, DES_key_schedule *ks, int enc);
void DES_encrypt2(DES_LONG *data, DES_key_schedule *ks, int enc);
char *DES_fcrypt(const char *buf, const char *salt, char *ret);
char *DES_crypt(const char *buf, const char *salt);
int DES_set_key(const_DES_cblock *key, DES_key_schedule *schedule);
int DES_key_sched(const_DES_cblock *key, DES_key_schedule *schedule);
int DES_set_key_checked(const_DES_cblock *key, DES_key_schedule *schedule);
void DES_set_key_unchecked(const_DES_cblock *key, DES_key_schedule *schedule);
void DES_string_to_2keys(const char *str, DES_cblock *key1, DES_cblock *key2);
int EVP_PKEY_CTX_set_dh_paramgen_type(EVP_PKEY_CTX *ctx, int typ);
int EVP_PKEY_CTX_set_dh_paramgen_gindex(EVP_PKEY_CTX *ctx, int gindex);
int EVP_PKEY_CTX_set_dh_paramgen_prime_len(EVP_PKEY_CTX *ctx, int pbits);
int EVP_PKEY_CTX_set_dh_paramgen_subprime_len(EVP_PKEY_CTX *ctx, int qlen);
int EVP_PKEY_CTX_set_dh_paramgen_generator(EVP_PKEY_CTX *ctx, int gen);
int EVP_PKEY_CTX_set_dh_nid(EVP_PKEY_CTX *ctx, int nid);
int EVP_PKEY_CTX_set_dh_rfc5114(EVP_PKEY_CTX *ctx, int gen);
int EVP_PKEY_CTX_set_dhx_rfc5114(EVP_PKEY_CTX *ctx, int gen);
int EVP_PKEY_CTX_set_dh_pad(EVP_PKEY_CTX *ctx, int pad);
int EVP_PKEY_CTX_set_dh_kdf_type(EVP_PKEY_CTX *ctx, int kdf);
int EVP_PKEY_CTX_get_dh_kdf_type(EVP_PKEY_CTX *ctx);
int EVP_PKEY_CTX_set0_dh_kdf_oid(EVP_PKEY_CTX *ctx, ASN1_OBJECT *oid);
int EVP_PKEY_CTX_get0_dh_kdf_oid(EVP_PKEY_CTX *ctx, ASN1_OBJECT **oid);
int EVP_PKEY_CTX_set_dh_kdf_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);
int EVP_PKEY_CTX_get_dh_kdf_md(EVP_PKEY_CTX *ctx, const EVP_MD **md);
int EVP_PKEY_CTX_set_dh_kdf_outlen(EVP_PKEY_CTX *ctx, int len);
int EVP_PKEY_CTX_get_dh_kdf_outlen(EVP_PKEY_CTX *ctx, int *len);
int EVP_PKEY_CTX_set0_dh_kdf_ukm(EVP_PKEY_CTX *ctx, unsigned char *ukm, int len);
int EVP_PKEY_CTX_get0_dh_kdf_ukm(EVP_PKEY_CTX *ctx, unsigned char **ukm);
int EVP_PKEY_CTX_set_dsa_paramgen_bits(EVP_PKEY_CTX *ctx, int nbits);
int EVP_PKEY_CTX_set_dsa_paramgen_q_bits(EVP_PKEY_CTX *ctx, int qbits);
int EVP_PKEY_CTX_set_dsa_paramgen_gindex(EVP_PKEY_CTX *ctx, int gindex);
int EVP_PKEY_CTX_set_dsa_paramgen_type(EVP_PKEY_CTX *ctx, const char *name);
int EVP_PKEY_CTX_set_dsa_paramgen_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);
void DSA_SIG_free(DSA_SIG *a);
void DSA_SIG_get0(const DSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps);
int DSA_SIG_set0(DSA_SIG *sig, BIGNUM *r, BIGNUM *s);
void *ebcdic2ascii(void *dest, const void *srce, size_t count);
void *ascii2ebcdic(void *dest, const void *srce, size_t count);
int EVP_PKEY_CTX_set_ec_paramgen_curve_nid(EVP_PKEY_CTX *ctx, int nid);
int EVP_PKEY_CTX_set_ec_param_enc(EVP_PKEY_CTX *ctx, int param_enc);
int EVP_PKEY_CTX_set_ecdh_cofactor_mode(EVP_PKEY_CTX *ctx, int cofactor_mode);
int EVP_PKEY_CTX_get_ecdh_cofactor_mode(EVP_PKEY_CTX *ctx);
int EVP_PKEY_CTX_set_ecdh_kdf_type(EVP_PKEY_CTX *ctx, int kdf);
int EVP_PKEY_CTX_get_ecdh_kdf_type(EVP_PKEY_CTX *ctx);
int EVP_PKEY_CTX_set_ecdh_kdf_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);
int EVP_PKEY_CTX_get_ecdh_kdf_md(EVP_PKEY_CTX *ctx, const EVP_MD **md);
int EVP_PKEY_CTX_set_ecdh_kdf_outlen(EVP_PKEY_CTX *ctx, int len);
int EVP_PKEY_CTX_get_ecdh_kdf_outlen(EVP_PKEY_CTX *ctx, int *len);
int EVP_PKEY_CTX_get0_ecdh_kdf_ukm(EVP_PKEY_CTX *ctx, unsigned char **ukm);
void EC_GROUP_free(EC_GROUP *group);
int EC_GROUP_copy(EC_GROUP *dst, const EC_GROUP *src);
int EC_GROUP_get_order(const EC_GROUP *group, BIGNUM *order, BN_CTX *ctx);
int EC_GROUP_order_bits(const EC_GROUP *group);
void EC_GROUP_set_curve_name(EC_GROUP *group, int nid);
int EC_GROUP_get_curve_name(const EC_GROUP *group);
int EC_GROUP_get_field_type(const EC_GROUP *group);
void EC_GROUP_set_asn1_flag(EC_GROUP *group, int flag);
int EC_GROUP_get_asn1_flag(const EC_GROUP *group);
unsigned char *EC_GROUP_get0_seed(const EC_GROUP *x);
int EC_GROUP_get_degree(const EC_GROUP *group);
int EC_GROUP_check(const EC_GROUP *group, BN_CTX *ctx);
int EC_GROUP_check_discriminant(const EC_GROUP *group, BN_CTX *ctx);
int EC_GROUP_cmp(const EC_GROUP *a, const EC_GROUP *b, BN_CTX *ctx);
int EC_curve_nist2nid(const char *name);
void EC_POINT_free(EC_POINT *point);
void EC_POINT_clear_free(EC_POINT *point);
int EC_POINT_copy(EC_POINT *dst, const EC_POINT *src);
int EC_POINT_set_to_infinity(const EC_GROUP *group, EC_POINT *point);
int EC_POINT_invert(const EC_GROUP *group, EC_POINT *a, BN_CTX *ctx);
int EC_POINT_is_at_infinity(const EC_GROUP *group, const EC_POINT *p);
int EC_GROUP_get_basis_type(const EC_GROUP *);
int EC_GROUP_get_trinomial_basis(const EC_GROUP *, unsigned int *k);
int i2d_ECPKParameters(const EC_GROUP *, unsigned char **out);
void ECDSA_SIG_free(ECDSA_SIG *sig);
void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps);
int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s);
int OSSL_ENCODER_up_ref(OSSL_ENCODER *encoder);
void OSSL_ENCODER_free(OSSL_ENCODER *encoder);
int OSSL_ENCODER_is_a(const OSSL_ENCODER *encoder, const char *name);
int OSSL_ENCODER_get_params(OSSL_ENCODER *encoder, OSSL_PARAM params[]);
void OSSL_ENCODER_CTX_free(OSSL_ENCODER_CTX *ctx);
int OSSL_ENCODER_CTX_set_selection(OSSL_ENCODER_CTX *ctx, int selection);
int OSSL_ENCODER_CTX_add_encoder(OSSL_ENCODER_CTX *ctx, OSSL_ENCODER *encoder);
int OSSL_ENCODER_CTX_get_num_encoders(OSSL_ENCODER_CTX *ctx);
int OSSL_ENCODER_to_bio(OSSL_ENCODER_CTX *ctx, BIO *out);
int OSSL_ENCODER_to_fp(OSSL_ENCODER_CTX *ctx, FILE *fp);
int ENGINE_set_destroy_function(ENGINE *e,ENGINE_GEN_INT_FUNC_PTR destroy_f);
int ENGINE_set_init_function(ENGINE *e, ENGINE_GEN_INT_FUNC_PTR init_f);
int ENGINE_set_finish_function(ENGINE *e, ENGINE_GEN_INT_FUNC_PTR finish_f);
int ENGINE_set_ctrl_function(ENGINE *e, ENGINE_CTRL_FUNC_PTR ctrl_f);
int ENGINE_set_load_privkey_function(ENGINE *e, ENGINE_LOAD_KEY_PTR loadpriv_f);
int ENGINE_set_load_pubkey_function(ENGINE *e, ENGINE_LOAD_KEY_PTR loadpub_f);
int ENGINE_set_ciphers(ENGINE *e, ENGINE_CIPHERS_PTR f);
int ENGINE_set_digests(ENGINE *e, ENGINE_DIGESTS_PTR f);
int ENGINE_set_pkey_meths(ENGINE *e, ENGINE_PKEY_METHS_PTR f);
int ENGINE_set_pkey_asn1_meths(ENGINE *e, ENGINE_PKEY_ASN1_METHS_PTR f);
void *ENGINE_get_static_state(void);
void ERR_new(void);
void ERR_set_debug(const char *file, int line, const char *func);
void ERR_set_error(int lib, int reason, const char *fmt, ...);
void ERR_vset_error(int lib, int reason, const char *fmt, va_list args);
void ERR_set_error_data(char *data, int flags);
unsigned long ERR_get_error(void);
unsigned long ERR_get_error_line(const char **file, int *line);
unsigned long ERR_peek_error(void);
unsigned long ERR_peek_error_line(const char **file, int *line);
unsigned long ERR_peek_error_func(const char **func);
unsigned long ERR_peek_error_data(const char **data, int *flags);
unsigned long ERR_peek_last_error(void);
unsigned long ERR_peek_last_error_line(const char **file, int *line);
unsigned long ERR_peek_last_error_func(const char **func);
unsigned long ERR_peek_last_error_data(const char **data, int *flags);
void ERR_clear_error(void);
char *ERR_error_string(unsigned long e, char *buf);
void ERR_error_string_n(unsigned long e, char *buf, size_t len);
void ERR_print_errors_fp(FILE *fp);
void ERR_print_errors(BIO *bp);
void ERR_add_error_data(int num, ...);
void ERR_add_error_vdata(int num, va_list args);
void ERR_add_error_txt(const char *sepr, const char *txt);
void ERR_add_error_mem_bio(const char *sep, BIO *bio);
int ERR_load_strings(int lib, ERR_STRING_DATA *str);
int ERR_load_strings_const(const ERR_STRING_DATA *str);
int ERR_unload_strings(int lib, ERR_STRING_DATA *str);
int ERR_get_next_error_library(void);
int ERR_set_mark(void);
int ERR_pop_to_mark(void);
int ERR_clear_last_mark(void);
int ERR_count_to_mark(void);
int ERR_pop(void);
void OSSL_ERR_STATE_save(ERR_STATE *es);
void OSSL_ERR_STATE_save_to_mark(ERR_STATE *es);
void OSSL_ERR_STATE_restore(const ERR_STATE *es);
void OSSL_ERR_STATE_free(ERR_STATE *es);
int EVP_set_default_properties(OSSL_LIB_CTX *libctx, const char *propq);
int EVP_default_properties_is_fips_enabled(OSSL_LIB_CTX *libctx);
int EVP_default_properties_enable_fips(OSSL_LIB_CTX *libctx, int enable);
int EVP_MD_meth_set_input_blocksize(EVP_MD *md, int blocksize);
int EVP_MD_meth_set_result_size(EVP_MD *md, int resultsize);
int EVP_MD_meth_set_app_datasize(EVP_MD *md, int datasize);
int EVP_MD_meth_set_flags(EVP_MD *md, unsigned long flags);
int EVP_MD_meth_set_init(EVP_MD *md, int (*init)(EVP_MD_CTX *ctx));
int EVP_MD_meth_set_cleanup(EVP_MD *md, int (*cleanup)(EVP_MD_CTX *ctx));
int (*EVP_MD_meth_get_init(const EVP_MD *md))(EVP_MD_CTX *ctx);
int (*EVP_MD_meth_get_cleanup(const EVP_MD *md))(EVP_MD_CTX *ctx);
void EVP_CIPHER_meth_free(EVP_CIPHER *cipher);
int EVP_CIPHER_meth_set_iv_length(EVP_CIPHER *cipher, int iv_len);
int EVP_CIPHER_meth_set_flags(EVP_CIPHER *cipher, unsigned long flags);
int EVP_CIPHER_meth_set_impl_ctx_size(EVP_CIPHER *cipher, int ctx_size);
int EVP_MD_get_type(const EVP_MD *md);
int EVP_MD_is_a(const EVP_MD *md, const char *name);
int EVP_MD_get_pkey_type(const EVP_MD *md);
int EVP_MD_get_size(const EVP_MD *md);
int EVP_MD_get_block_size(const EVP_MD *md);
unsigned long EVP_MD_get_flags(const EVP_MD *md);
void EVP_MD_CTX_set_pkey_ctx(EVP_MD_CTX *ctx, EVP_PKEY_CTX *pctx);
void *EVP_MD_CTX_get0_md_data(const EVP_MD_CTX *ctx);
int EVP_CIPHER_get_nid(const EVP_CIPHER *cipher);
int EVP_CIPHER_is_a(const EVP_CIPHER *cipher, const char *name);
int EVP_CIPHER_get_block_size(const EVP_CIPHER *cipher);
int EVP_CIPHER_impl_ctx_size(const EVP_CIPHER *cipher);
int EVP_CIPHER_get_key_length(const EVP_CIPHER *cipher);
int EVP_CIPHER_get_iv_length(const EVP_CIPHER *cipher);
unsigned long EVP_CIPHER_get_flags(const EVP_CIPHER *cipher);
int EVP_CIPHER_get_mode(const EVP_CIPHER *cipher);
int EVP_CIPHER_get_type(const EVP_CIPHER *cipher);
int EVP_CIPHER_up_ref(EVP_CIPHER *cipher);
void EVP_CIPHER_free(EVP_CIPHER *cipher);
int EVP_CIPHER_CTX_is_encrypting(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_get_nid(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_get_block_size(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_get_key_length(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_get_iv_length(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_get_tag_length(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_get_updated_iv(EVP_CIPHER_CTX *ctx, void *buf, size_t len);
int EVP_CIPHER_CTX_get_original_iv(EVP_CIPHER_CTX *ctx, void *buf, size_t len);
unsigned char *EVP_CIPHER_CTX_buf_noconst(EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_get_num(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_set_num(EVP_CIPHER_CTX *ctx, int num);
int EVP_CIPHER_CTX_copy(EVP_CIPHER_CTX *out, const EVP_CIPHER_CTX *in);
void *EVP_CIPHER_CTX_get_app_data(const EVP_CIPHER_CTX *ctx);
void EVP_CIPHER_CTX_set_app_data(EVP_CIPHER_CTX *ctx, void *data);
void *EVP_CIPHER_CTX_get_cipher_data(const EVP_CIPHER_CTX *ctx);
void *EVP_CIPHER_CTX_set_cipher_data(EVP_CIPHER_CTX *ctx, void *cipher_data);
void BIO_set_md(BIO *, const EVP_MD *md);
int EVP_MD_get_params(const EVP_MD *digest, OSSL_PARAM params[]);
int EVP_MD_CTX_set_params(EVP_MD_CTX *ctx, const OSSL_PARAM params[]);
int EVP_MD_CTX_get_params(EVP_MD_CTX *ctx, OSSL_PARAM params[]);
int EVP_MD_CTX_ctrl(EVP_MD_CTX *ctx, int cmd, int p1, void *p2);
int EVP_MD_CTX_reset(EVP_MD_CTX *ctx);
void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
void EVP_MD_CTX_set_flags(EVP_MD_CTX *ctx, int flags);
void EVP_MD_CTX_clear_flags(EVP_MD_CTX *ctx, int flags);
int EVP_MD_CTX_test_flags(const EVP_MD_CTX *ctx, int flags);
int EVP_MD_up_ref(EVP_MD *md);
void EVP_MD_free(EVP_MD *md);
int EVP_read_pw_string(char *buf, int length, const char *prompt, int verify);
void EVP_set_pw_prompt(const char *prompt);
char *EVP_get_pw_prompt(void);
void EVP_CIPHER_CTX_set_flags(EVP_CIPHER_CTX *ctx, int flags);
void EVP_CIPHER_CTX_clear_flags(EVP_CIPHER_CTX *ctx, int flags);
int EVP_CIPHER_CTX_test_flags(const EVP_CIPHER_CTX *ctx, int flags);
int EVP_DigestVerifyUpdate(EVP_MD_CTX *ctx, const void *data, size_t dsize);
void EVP_ENCODE_CTX_free(EVP_ENCODE_CTX *ctx);
int EVP_ENCODE_CTX_copy(EVP_ENCODE_CTX *dctx, const EVP_ENCODE_CTX *sctx);
int EVP_ENCODE_CTX_num(EVP_ENCODE_CTX *ctx);
void EVP_EncodeInit(EVP_ENCODE_CTX *ctx);
void EVP_EncodeFinal(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl);
int EVP_EncodeBlock(unsigned char *t, const unsigned char *f, int n);
void EVP_DecodeInit(EVP_ENCODE_CTX *ctx);
int EVP_DecodeBlock(unsigned char *t, const unsigned char *f, int n);
int EVP_CIPHER_CTX_reset(EVP_CIPHER_CTX *c);
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *c);
int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *x, int keylen);
int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *c, int pad);
int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
int EVP_CIPHER_CTX_rand_key(EVP_CIPHER_CTX *ctx, unsigned char *key);
int EVP_CIPHER_get_params(EVP_CIPHER *cipher, OSSL_PARAM params[]);
int EVP_CIPHER_CTX_set_params(EVP_CIPHER_CTX *ctx, const OSSL_PARAM params[]);
int EVP_CIPHER_CTX_get_params(EVP_CIPHER_CTX *ctx, OSSL_PARAM params[]);
int EVP_add_cipher(const EVP_CIPHER *cipher);
int EVP_add_digest(const EVP_MD *digest);
int EVP_MAC_up_ref(EVP_MAC *mac);
void EVP_MAC_free(EVP_MAC *mac);
int EVP_MAC_is_a(const EVP_MAC *mac, const char *name);
int EVP_MAC_get_params(EVP_MAC *mac, OSSL_PARAM params[]);
void EVP_MAC_CTX_free(EVP_MAC_CTX *ctx);
int EVP_MAC_CTX_get_params(EVP_MAC_CTX *ctx, OSSL_PARAM params[]);
int EVP_MAC_CTX_set_params(EVP_MAC_CTX *ctx, const OSSL_PARAM params[]);
int EVP_MAC_update(EVP_MAC_CTX *ctx, const unsigned char *data, size_t datalen);
int EVP_MAC_finalXOF(EVP_MAC_CTX *ctx, unsigned char *out, size_t outsize);
int EVP_RAND_up_ref(EVP_RAND *rand);
void EVP_RAND_free(EVP_RAND *rand);
int EVP_RAND_is_a(const EVP_RAND *rand, const char *name);
int EVP_RAND_get_params(EVP_RAND *rand, OSSL_PARAM params[]);
int EVP_RAND_CTX_up_ref(EVP_RAND_CTX *ctx);
void EVP_RAND_CTX_free(EVP_RAND_CTX *ctx);
int EVP_RAND_CTX_get_params(EVP_RAND_CTX *ctx, OSSL_PARAM params[]);
int EVP_RAND_CTX_set_params(EVP_RAND_CTX *ctx, const OSSL_PARAM params[]);
int EVP_RAND_uninstantiate(EVP_RAND_CTX *ctx);
int EVP_RAND_verify_zeroization(EVP_RAND_CTX *ctx);
unsigned int EVP_RAND_get_strength(EVP_RAND_CTX *ctx);
int EVP_RAND_get_state(EVP_RAND_CTX *ctx);
int EVP_PKEY_is_a(const EVP_PKEY *pkey, const char *name);
int EVP_PKEY_type(int type);
int EVP_PKEY_get_id(const EVP_PKEY *pkey);
int EVP_PKEY_get_base_id(const EVP_PKEY *pkey);
int EVP_PKEY_get_bits(const EVP_PKEY *pkey);
int EVP_PKEY_get_security_bits(const EVP_PKEY *pkey);
int EVP_PKEY_get_size(const EVP_PKEY *pkey);
int EVP_PKEY_can_sign(const EVP_PKEY *pkey);
int EVP_PKEY_set_type(EVP_PKEY *pkey, int type);
int EVP_PKEY_set_type_str(EVP_PKEY *pkey, const char *str, int len);
int EVP_PKEY_set_type_by_keymgmt(EVP_PKEY *pkey, EVP_KEYMGMT *keymgmt);
int EVP_PKEY_set1_engine(EVP_PKEY *pkey, ENGINE *e);
int EVP_PKEY_assign(EVP_PKEY *pkey, int type, void *key);
void *EVP_PKEY_get0(const EVP_PKEY *pkey);
int EVP_PKEY_set1_RSA(EVP_PKEY *pkey, struct rsa_st *key);
int EVP_PKEY_set1_DSA(EVP_PKEY *pkey, struct dsa_st *key);
int EVP_PKEY_set1_EC_KEY(EVP_PKEY *pkey, struct ec_key_st *key);
int EVP_PKEY_up_ref(EVP_PKEY *pkey);
void EVP_PKEY_free(EVP_PKEY *pkey);
int i2d_PublicKey(const EVP_PKEY *a, unsigned char **pp);
int i2d_PrivateKey(const EVP_PKEY *a, unsigned char **pp);
int i2d_KeyParams(const EVP_PKEY *a, unsigned char **pp);
int i2d_KeyParams_bio(BIO *bp, const EVP_PKEY *pkey);
int EVP_PKEY_copy_parameters(EVP_PKEY *to, const EVP_PKEY *from);
int EVP_PKEY_missing_parameters(const EVP_PKEY *pkey);
int EVP_PKEY_save_parameters(EVP_PKEY *pkey, int mode);
int EVP_PKEY_parameters_eq(const EVP_PKEY *a, const EVP_PKEY *b);
int EVP_PKEY_eq(const EVP_PKEY *a, const EVP_PKEY *b);
int EVP_PKEY_cmp_parameters(const EVP_PKEY *a, const EVP_PKEY *b);
int EVP_PKEY_cmp(const EVP_PKEY *a, const EVP_PKEY *b);
int EVP_PKEY_get_default_digest_nid(EVP_PKEY *pkey, int *pnid);
int EVP_CIPHER_param_to_asn1(EVP_CIPHER_CTX *c, ASN1_TYPE *type);
int EVP_CIPHER_asn1_to_param(EVP_CIPHER_CTX *c, ASN1_TYPE *type);
int EVP_CIPHER_set_asn1_iv(EVP_CIPHER_CTX *c, ASN1_TYPE *type);
int EVP_CIPHER_get_asn1_iv(EVP_CIPHER_CTX *c, ASN1_TYPE *type);
void PKCS5_PBE_add(void);
void EVP_PBE_cleanup(void);
int EVP_PBE_get(int *ptype, int *ppbe_nid, size_t num);
int EVP_PKEY_asn1_get_count(void);
int EVP_PKEY_asn1_add0(const EVP_PKEY_ASN1_METHOD *ameth);
int EVP_PKEY_asn1_add_alias(int to, int from);
void EVP_PKEY_asn1_free(EVP_PKEY_ASN1_METHOD *ameth);
int EVP_PKEY_CTX_get_signature_md(EVP_PKEY_CTX *ctx, const EVP_MD **md);
int EVP_PKEY_CTX_set_signature_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);
int EVP_PKEY_CTX_set1_id(EVP_PKEY_CTX *ctx, const void *id, int len);
int EVP_PKEY_CTX_get1_id(EVP_PKEY_CTX *ctx, void *id);
int EVP_PKEY_CTX_get1_id_len(EVP_PKEY_CTX *ctx, size_t *id_len);
int EVP_PKEY_CTX_set_kem_op(EVP_PKEY_CTX *ctx, const char *op);
int EVP_KEYMGMT_up_ref(EVP_KEYMGMT *keymgmt);
void EVP_KEYMGMT_free(EVP_KEYMGMT *keymgmt);
int EVP_KEYMGMT_is_a(const EVP_KEYMGMT *keymgmt, const char *name);
void EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx);
int EVP_PKEY_CTX_is_a(EVP_PKEY_CTX *ctx, const char *keytype);
int EVP_PKEY_CTX_get_params(EVP_PKEY_CTX *ctx, OSSL_PARAM *params);
int EVP_PKEY_CTX_set_params(EVP_PKEY_CTX *ctx, const OSSL_PARAM *params);
int EVP_PKEY_CTX_str2ctrl(EVP_PKEY_CTX *ctx, int cmd, const char *str);
int EVP_PKEY_CTX_hex2ctrl(EVP_PKEY_CTX *ctx, int cmd, const char *hex);
int EVP_PKEY_CTX_md(EVP_PKEY_CTX *ctx, int optype, int cmd, const char *md);
int EVP_PKEY_CTX_get_operation(EVP_PKEY_CTX *ctx);
void EVP_PKEY_CTX_set0_keygen_info(EVP_PKEY_CTX *ctx, int *dat, int datlen);
void EVP_PKEY_CTX_set_data(EVP_PKEY_CTX *ctx, void *data);
void *EVP_PKEY_CTX_get_data(const EVP_PKEY_CTX *ctx);
void EVP_PKEY_CTX_set_app_data(EVP_PKEY_CTX *ctx, void *data);
void *EVP_PKEY_CTX_get_app_data(EVP_PKEY_CTX *ctx);
void EVP_SIGNATURE_free(EVP_SIGNATURE *signature);
int EVP_SIGNATURE_up_ref(EVP_SIGNATURE *signature);
int EVP_SIGNATURE_is_a(const EVP_SIGNATURE *signature, const char *name);
void EVP_ASYM_CIPHER_free(EVP_ASYM_CIPHER *cipher);
int EVP_ASYM_CIPHER_up_ref(EVP_ASYM_CIPHER *cipher);
int EVP_ASYM_CIPHER_is_a(const EVP_ASYM_CIPHER *cipher, const char *name);
void EVP_KEM_free(EVP_KEM *wrap);
int EVP_KEM_up_ref(EVP_KEM *wrap);
int EVP_KEM_is_a(const EVP_KEM *wrap, const char *name);
int EVP_PKEY_sign_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_sign_init_ex(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[]);
int EVP_PKEY_verify_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_verify_init_ex(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[]);
int EVP_PKEY_verify_recover_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_encrypt_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_encrypt_init_ex(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[]);
int EVP_PKEY_decrypt_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_decrypt_init_ex(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[]);
int EVP_PKEY_derive_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_derive_init_ex(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[]);
int EVP_PKEY_derive_set_peer(EVP_PKEY_CTX *ctx, EVP_PKEY *peer);
int EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
int EVP_PKEY_encapsulate_init(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[]);
int EVP_PKEY_decapsulate_init(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[]);
int EVP_PKEY_fromdata_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_todata(const EVP_PKEY *pkey, int selection, OSSL_PARAM **params);
int EVP_PKEY_get_params(const EVP_PKEY *pkey, OSSL_PARAM params[]);
int EVP_PKEY_set_params(EVP_PKEY *pkey, OSSL_PARAM params[]);
int EVP_PKEY_set_int_param(EVP_PKEY *pkey, const char *key_name, int in);
int EVP_PKEY_set_size_t_param(EVP_PKEY *pkey, const char *key_name, size_t in);
int EVP_PKEY_get_ec_point_conv_form(const EVP_PKEY *pkey);
int EVP_PKEY_get_field_type(const EVP_PKEY *pkey);
int EVP_PKEY_paramgen_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey);
int EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey);
int EVP_PKEY_generate(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey);
int EVP_PKEY_check(EVP_PKEY_CTX *ctx);
int EVP_PKEY_public_check(EVP_PKEY_CTX *ctx);
int EVP_PKEY_public_check_quick(EVP_PKEY_CTX *ctx);
int EVP_PKEY_param_check(EVP_PKEY_CTX *ctx);
int EVP_PKEY_param_check_quick(EVP_PKEY_CTX *ctx);
int EVP_PKEY_private_check(EVP_PKEY_CTX *ctx);
int EVP_PKEY_pairwise_check(EVP_PKEY_CTX *ctx);
int EVP_PKEY_set_ex_data(EVP_PKEY *key, int idx, void *arg);
void *EVP_PKEY_get_ex_data(const EVP_PKEY *key, int idx);
void EVP_PKEY_CTX_set_cb(EVP_PKEY_CTX *ctx, EVP_PKEY_gen_cb *cb);
int EVP_PKEY_CTX_get_keygen_info(EVP_PKEY_CTX *ctx, int idx);
void EVP_KEYEXCH_free(EVP_KEYEXCH *exchange);
int EVP_KEYEXCH_up_ref(EVP_KEYEXCH *exchange);
int EVP_KEYEXCH_is_a(const EVP_KEYEXCH *keyexch, const char *name);
void EVP_add_alg_module(void);
int EVP_PKEY_CTX_set_group_name(EVP_PKEY_CTX *ctx, const char *name);
int EVP_PKEY_CTX_get_group_name(EVP_PKEY_CTX *ctx, char *name, size_t namelen);
void OSSL_HPKE_CTX_free(OSSL_HPKE_CTX *ctx);
int OSSL_HPKE_CTX_set1_authpriv(OSSL_HPKE_CTX *ctx, EVP_PKEY *priv);
int OSSL_HPKE_CTX_set_seq(OSSL_HPKE_CTX *ctx, uint64_t seq);
int OSSL_HPKE_CTX_get_seq(OSSL_HPKE_CTX *ctx, uint64_t *seq);
int OSSL_HPKE_suite_check(OSSL_HPKE_SUITE suite);
int OSSL_HPKE_str2suite(const char *str, OSSL_HPKE_SUITE *suite);
void OSSL_HTTP_REQ_CTX_free(OSSL_HTTP_REQ_CTX *rctx);
int OSSL_HTTP_REQ_CTX_nbio(OSSL_HTTP_REQ_CTX *rctx);
int OSSL_HTTP_is_alive(const OSSL_HTTP_REQ_CTX *rctx);
int OSSL_HTTP_close(OSSL_HTTP_REQ_CTX *rctx, int ok);
int EVP_KDF_up_ref(EVP_KDF *kdf);
void EVP_KDF_free(EVP_KDF *kdf);
void EVP_KDF_CTX_free(EVP_KDF_CTX *ctx);
int EVP_KDF_is_a(const EVP_KDF *kdf, const char *name);
void EVP_KDF_CTX_reset(EVP_KDF_CTX *ctx);
int EVP_KDF_get_params(EVP_KDF *kdf, OSSL_PARAM params[]);
int EVP_KDF_CTX_get_params(EVP_KDF_CTX *ctx, OSSL_PARAM params[]);
int EVP_KDF_CTX_set_params(EVP_KDF_CTX *ctx, const OSSL_PARAM params[]);
int EVP_PKEY_CTX_set_tls1_prf_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);
int EVP_PKEY_CTX_set_hkdf_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);
int EVP_PKEY_CTX_set_hkdf_mode(EVP_PKEY_CTX *ctx, int mode);
int EVP_PKEY_CTX_set_scrypt_N(EVP_PKEY_CTX *ctx, uint64_t n);
int EVP_PKEY_CTX_set_scrypt_r(EVP_PKEY_CTX *ctx, uint64_t r);
int EVP_PKEY_CTX_set_scrypt_p(EVP_PKEY_CTX *ctx, uint64_t p);
int OPENSSL_LH_error(OPENSSL_LHASH *lh);
void OPENSSL_LH_free(OPENSSL_LHASH *lh);
void OPENSSL_LH_flush(OPENSSL_LHASH *lh);
void *OPENSSL_LH_insert(OPENSSL_LHASH *lh, void *data);
void *OPENSSL_LH_delete(OPENSSL_LHASH *lh, const void *data);
void *OPENSSL_LH_retrieve(OPENSSL_LHASH *lh, const void *data);
void OPENSSL_LH_doall(OPENSSL_LHASH *lh, OPENSSL_LH_DOALL_FUNC func);
unsigned long OPENSSL_LH_strhash(const char *c);
unsigned long OPENSSL_LH_num_items(const OPENSSL_LHASH *lh);
unsigned long OPENSSL_LH_get_down_load(const OPENSSL_LHASH *lh);
void OPENSSL_LH_set_down_load(OPENSSL_LHASH *lh, unsigned long down_load);
void CRYPTO_gcm128_init(GCM128_CONTEXT *ctx, void *key, block128_f block);
void CRYPTO_gcm128_tag(GCM128_CONTEXT *ctx, unsigned char *tag, size_t len);
void CRYPTO_gcm128_release(GCM128_CONTEXT *ctx);
int CRYPTO_ocb128_tag(OCB128_CONTEXT *ctx, unsigned char *tag, size_t len);
void CRYPTO_ocb128_cleanup(OCB128_CONTEXT *ctx);
int OBJ_NAME_init(void);
int OBJ_NAME_add(const char *name, int type, const char *data);
int OBJ_NAME_remove(const char *name, int type);
void OBJ_NAME_cleanup(int type);
int OBJ_obj2nid(const ASN1_OBJECT *o);
int OBJ_obj2txt(char *buf, int buf_len, const ASN1_OBJECT *a, int no_name);
int OBJ_txt2nid(const char *s);
int OBJ_ln2nid(const char *s);
int OBJ_sn2nid(const char *s);
int OBJ_cmp(const ASN1_OBJECT *a, const ASN1_OBJECT *b);
int OBJ_new_nid(int num);
int OBJ_add_object(const ASN1_OBJECT *obj);
int OBJ_create(const char *oid, const char *sn, const char *ln);
int OBJ_create_objects(BIO *in);
int OBJ_find_sigid_algs(int signid, int *pdig_nid, int *ppkey_nid);
int OBJ_find_sigid_by_algs(int *psignid, int dig_nid, int pkey_nid);
int OBJ_add_sigid(int signid, int dig_id, int pkey_id);
void OBJ_sigid_free(void);
int OCSP_request_add1_nonce(OCSP_REQUEST *req, unsigned char *val, int len);
int OCSP_basic_add1_nonce(OCSP_BASICRESP *resp, unsigned char *val, int len);
int OCSP_check_nonce(OCSP_REQUEST *req, OCSP_BASICRESP *bs);
int OCSP_copy_nonce(OCSP_BASICRESP *resp, OCSP_REQUEST *req);
int OCSP_request_set1_name(OCSP_REQUEST *req, const X509_NAME *nm);
int OCSP_request_add1_cert(OCSP_REQUEST *req, X509 *cert);
int OCSP_response_status(OCSP_RESPONSE *resp);
int OCSP_resp_count(OCSP_BASICRESP *bs);
int OCSP_resp_find(OCSP_BASICRESP *bs, OCSP_CERTID *id, int last);
int OCSP_id_issuer_cmp(const OCSP_CERTID *a, const OCSP_CERTID *b);
int OCSP_id_cmp(const OCSP_CERTID *a, const OCSP_CERTID *b);
int OCSP_request_onereq_count(OCSP_REQUEST *req);
int OCSP_request_is_signed(OCSP_REQUEST *req);
int OCSP_basic_add1_cert(OCSP_BASICRESP *resp, X509 *cert);
int OCSP_RESPID_set_by_name(OCSP_RESPID *respid, X509 *cert);
int OCSP_RESPID_set_by_key(OCSP_RESPID *respid, X509 *cert);
int OCSP_RESPID_match(OCSP_RESPID *respid, X509 *cert);
int OCSP_REQUEST_get_ext_count(OCSP_REQUEST *x);
int OCSP_REQUEST_get_ext_by_NID(OCSP_REQUEST *x, int nid, int lastpos);
int OCSP_REQUEST_get_ext_by_critical(OCSP_REQUEST *x, int crit, int lastpos);
int OCSP_REQUEST_add_ext(OCSP_REQUEST *x, X509_EXTENSION *ex, int loc);
int OCSP_ONEREQ_get_ext_count(OCSP_ONEREQ *x);
int OCSP_ONEREQ_get_ext_by_NID(OCSP_ONEREQ *x, int nid, int lastpos);
int OCSP_ONEREQ_get_ext_by_OBJ(OCSP_ONEREQ *x, const ASN1_OBJECT *obj, int lastpos);
int OCSP_ONEREQ_get_ext_by_critical(OCSP_ONEREQ *x, int crit, int lastpos);
void *OCSP_ONEREQ_get1_ext_d2i(OCSP_ONEREQ *x, int nid, int *crit, int *idx);
int OCSP_ONEREQ_add_ext(OCSP_ONEREQ *x, X509_EXTENSION *ex, int loc);
int OCSP_BASICRESP_get_ext_count(OCSP_BASICRESP *x);
int OCSP_BASICRESP_get_ext_by_NID(OCSP_BASICRESP *x, int nid, int lastpos);
int OCSP_BASICRESP_add_ext(OCSP_BASICRESP *x, X509_EXTENSION *ex, int loc);
int OCSP_SINGLERESP_get_ext_count(OCSP_SINGLERESP *x);
int OCSP_SINGLERESP_get_ext_by_NID(OCSP_SINGLERESP *x, int nid, int lastpos);
int OCSP_SINGLERESP_add_ext(OCSP_SINGLERESP *x, X509_EXTENSION *ex, int loc);
int OCSP_REQUEST_print(BIO *bp, OCSP_REQUEST *a, unsigned long flags);
int OCSP_RESPONSE_print(BIO *bp, OCSP_RESPONSE *o, unsigned long flags);
int OSSL_PARAM_get_int(const OSSL_PARAM *p, int *val);
int OSSL_PARAM_get_uint(const OSSL_PARAM *p, unsigned int *val);
int OSSL_PARAM_get_long(const OSSL_PARAM *p, long int *val);
int OSSL_PARAM_get_ulong(const OSSL_PARAM *p, unsigned long int *val);
int OSSL_PARAM_get_int32(const OSSL_PARAM *p, int32_t *val);
int OSSL_PARAM_get_uint32(const OSSL_PARAM *p, uint32_t *val);
int OSSL_PARAM_get_int64(const OSSL_PARAM *p, int64_t *val);
int OSSL_PARAM_get_uint64(const OSSL_PARAM *p, uint64_t *val);
int OSSL_PARAM_get_size_t(const OSSL_PARAM *p, size_t *val);
int OSSL_PARAM_get_time_t(const OSSL_PARAM *p, time_t *val);
int OSSL_PARAM_set_int(OSSL_PARAM *p, int val);
int OSSL_PARAM_set_uint(OSSL_PARAM *p, unsigned int val);
int OSSL_PARAM_set_long(OSSL_PARAM *p, long int val);
int OSSL_PARAM_set_ulong(OSSL_PARAM *p, unsigned long int val);
int OSSL_PARAM_set_int32(OSSL_PARAM *p, int32_t val);
int OSSL_PARAM_set_uint32(OSSL_PARAM *p, uint32_t val);
int OSSL_PARAM_set_int64(OSSL_PARAM *p, int64_t val);
int OSSL_PARAM_set_uint64(OSSL_PARAM *p, uint64_t val);
int OSSL_PARAM_set_size_t(OSSL_PARAM *p, size_t val);
int OSSL_PARAM_set_time_t(OSSL_PARAM *p, time_t val);
int OSSL_PARAM_get_double(const OSSL_PARAM *p, double *val);
int OSSL_PARAM_set_double(OSSL_PARAM *p, double val);
int OSSL_PARAM_get_BN(const OSSL_PARAM *p, BIGNUM **val);
int OSSL_PARAM_set_BN(OSSL_PARAM *p, const BIGNUM *val);
int OSSL_PARAM_get_utf8_string(const OSSL_PARAM *p, char **val, size_t max_len);
int OSSL_PARAM_set_utf8_string(OSSL_PARAM *p, const char *val);
int OSSL_PARAM_set_octet_string(OSSL_PARAM *p, const void *val, size_t len);
int OSSL_PARAM_get_utf8_ptr(const OSSL_PARAM *p, const char **val);
int OSSL_PARAM_set_utf8_ptr(OSSL_PARAM *p, const char *val);
int OSSL_PARAM_get_utf8_string_ptr(const OSSL_PARAM *p, const char **val);
int OSSL_PARAM_modified(const OSSL_PARAM *p);
void OSSL_PARAM_set_all_unmodified(OSSL_PARAM *p);
void OSSL_PARAM_free(OSSL_PARAM *p);
void OSSL_PARAM_BLD_free(OSSL_PARAM_BLD *bld);
int OSSL_PARAM_BLD_push_int(OSSL_PARAM_BLD *bld, const char *key, int val);
int PEM_get_EVP_CIPHER_INFO(char *header, EVP_CIPHER_INFO *cipher);
int PEM_SignInit(EVP_MD_CTX *ctx, EVP_MD *type);
int PEM_SignUpdate(EVP_MD_CTX *ctx, const unsigned char *d, unsigned int cnt);
int PEM_def_callback(char *buf, int num, int rwflag, void *userdata);
void PEM_proc_type(char *buf, int type);
void PEM_dek_info(char *buf, const char *type, int len, const char *str);
int PEM_write_bio_Parameters(BIO *bp, const EVP_PKEY *x);
int i2b_PrivateKey_bio(BIO *out, const EVP_PKEY *pk);
int i2b_PublicKey_bio(BIO *out, const EVP_PKEY *pk);
int PKCS12_mac_present(const PKCS12 *p12);
int PKCS12_SAFEBAG_get_nid(const PKCS12_SAFEBAG *bag);
int PKCS12_SAFEBAG_get_bag_nid(const PKCS12_SAFEBAG *bag);
int PKCS12_pack_authsafes(PKCS12 *p12, STACK_OF(PKCS7) *safes);
int PKCS8_add_keyusage(PKCS8_PRIV_KEY_INFO *p8, int usage);
char *PKCS12_get_friendlyname(PKCS12_SAFEBAG *bag);
void PKCS12_SAFEBAG_set0_attrs(PKCS12_SAFEBAG *bag, STACK_OF(X509_ATTRIBUTE) *attrs);
int PKCS12_verify_mac(PKCS12 *p12, const char *pass, int passlen);
char *OPENSSL_uni2asc(const unsigned char *uni, int unilen);
char *OPENSSL_uni2utf8(const unsigned char *uni, int unilen);
void PKCS12_PBE_add(void);
int i2d_PKCS12_bio(BIO *bp, const PKCS12 *p12);
int i2d_PKCS12_fp(FILE *fp, const PKCS12 *p12);
int PKCS12_newpass(PKCS12 *p12, const char *oldpass, const char *newpass);
int i2d_PKCS7_fp(FILE *fp, const PKCS7 *p7);
int i2d_PKCS7_bio(BIO *bp, const PKCS7 *p7);
int i2d_PKCS7_bio_stream(BIO *out, PKCS7 *p7, BIO *in, int flags);
int PEM_write_bio_PKCS7_stream(BIO *out, PKCS7 *p7, BIO *in, int flags);
long PKCS7_ctrl(PKCS7 *p7, int cmd, long larg, char *parg);
int PKCS7_type_is_other(PKCS7 *p7);
int PKCS7_set_type(PKCS7 *p7, int type);
int PKCS7_set0_type_other(PKCS7 *p7, int type, ASN1_TYPE *other);
int PKCS7_set_content(PKCS7 *p7, PKCS7 *p7_data);
int PKCS7_SIGNER_INFO_sign(PKCS7_SIGNER_INFO *si);
int PKCS7_add_signer(PKCS7 *p7, PKCS7_SIGNER_INFO *p7i);
int PKCS7_add_certificate(PKCS7 *p7, X509 *cert);
int PKCS7_add_crl(PKCS7 *p7, X509_CRL *crl);
int PKCS7_content_new(PKCS7 *p7, int nid);
int PKCS7_dataFinal(PKCS7 *p7, BIO *bio);
int PKCS7_set_digest(PKCS7 *p7, const EVP_MD *md);
void PKCS7_RECIP_INFO_get0_alg(PKCS7_RECIP_INFO *ri, X509_ALGOR **penc);
int PKCS7_add_recipient_info(PKCS7 *p7, PKCS7_RECIP_INFO *ri);
int PKCS7_RECIP_INFO_set(PKCS7_RECIP_INFO *p7i, X509 *x509);
int PKCS7_set_cipher(PKCS7 *p7, const EVP_CIPHER *cipher);
int PKCS7_stream(unsigned char ***boundary, PKCS7 *p7);
int PKCS7_final(PKCS7 *p7, BIO *data, int flags);
int PKCS7_simple_smimecap(STACK_OF(X509_ALGOR) *sk, int nid, int arg);
int PKCS7_add_attrib_content_type(PKCS7_SIGNER_INFO *si, ASN1_OBJECT *coid);
int PKCS7_add0_attrib_signing_time(PKCS7_SIGNER_INFO *si, ASN1_TIME *t);
int SMIME_write_PKCS7(BIO *bio, PKCS7 *p7, BIO *data, int flags);
int OSSL_PROVIDER_set_default_search_path(OSSL_LIB_CTX *, const char *path);
int OSSL_PROVIDER_unload(OSSL_PROVIDER *prov);
int OSSL_PROVIDER_available(OSSL_LIB_CTX *, const char *name);
int OSSL_PROVIDER_get_params(const OSSL_PROVIDER *prov, OSSL_PARAM params[]);
int OSSL_PROVIDER_self_test(const OSSL_PROVIDER *prov);
void *OSSL_PROVIDER_get0_provider_ctx(const OSSL_PROVIDER *prov);
int RAND_bytes(unsigned char *buf, int num);
int RAND_priv_bytes(unsigned char *buf, int num);
int RAND_set0_public(OSSL_LIB_CTX *ctx, EVP_RAND_CTX *rand);
int RAND_set0_private(OSSL_LIB_CTX *ctx, EVP_RAND_CTX *rand);
void RAND_seed(const void *buf, int num);
void RAND_keep_random_devices_open(int keep);
void RAND_add(const void *buf, int num, double randomness);
int RAND_load_file(const char *file, long max_bytes);
int RAND_write_file(const char *file);
int RAND_status(void);
int RAND_query_egd_bytes(const char *path, unsigned char *buf, int bytes);
int RAND_egd(const char *path);
int RAND_egd_bytes(const char *path, int bytes);
int RAND_poll(void);
int EVP_PKEY_CTX_set_rsa_padding(EVP_PKEY_CTX *ctx, int pad_mode);
int EVP_PKEY_CTX_get_rsa_padding(EVP_PKEY_CTX *ctx, int *pad_mode);
int EVP_PKEY_CTX_set_rsa_pss_saltlen(EVP_PKEY_CTX *ctx, int saltlen);
int EVP_PKEY_CTX_get_rsa_pss_saltlen(EVP_PKEY_CTX *ctx, int *saltlen);
int EVP_PKEY_CTX_set_rsa_keygen_bits(EVP_PKEY_CTX *ctx, int bits);
int EVP_PKEY_CTX_set1_rsa_keygen_pubexp(EVP_PKEY_CTX *ctx, BIGNUM *pubexp);
int EVP_PKEY_CTX_set_rsa_keygen_primes(EVP_PKEY_CTX *ctx, int primes);
int EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(EVP_PKEY_CTX *ctx, int saltlen);
int EVP_PKEY_CTX_set_rsa_keygen_pubexp(EVP_PKEY_CTX *ctx, BIGNUM *pubexp);
int EVP_PKEY_CTX_set_rsa_mgf1_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);
int EVP_PKEY_CTX_get_rsa_mgf1_md(EVP_PKEY_CTX *ctx, const EVP_MD **md);
int EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);
int EVP_PKEY_CTX_set_rsa_pss_keygen_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);
int EVP_PKEY_CTX_set_rsa_oaep_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);
int EVP_PKEY_CTX_get_rsa_oaep_md(EVP_PKEY_CTX *ctx, const EVP_MD **md);
int EVP_PKEY_CTX_set0_rsa_oaep_label(EVP_PKEY_CTX *ctx, void *label, int llen);
int EVP_PKEY_CTX_get0_rsa_oaep_label(EVP_PKEY_CTX *ctx, unsigned char **label);
int RSA_pkey_ctx_ctrl(EVP_PKEY_CTX *ctx, int optype, int cmd, int p1, void *p2);
int (*RSA_meth_get_init(const RSA_METHOD *meth)) (RSA *rsa);
int RSA_meth_set_init(RSA_METHOD *rsa, int (*init) (RSA *rsa));
int (*RSA_meth_get_finish(const RSA_METHOD *meth)) (RSA *rsa);
int RSA_meth_set_finish(RSA_METHOD *rsa, int (*finish) (RSA *rsa));
void OSSL_SELF_TEST_free(OSSL_SELF_TEST *st);
int OSSL_SELF_TEST_oncorrupt_byte(OSSL_SELF_TEST *st, unsigned char *bytes);
void OSSL_SELF_TEST_onend(OSSL_SELF_TEST *st, int ret);
unsigned char *SHA1(const unsigned char *d, size_t n, unsigned char *md);
unsigned char *SHA224(const unsigned char *d, size_t n, unsigned char *md);
unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md);
unsigned char *SHA384(const unsigned char *d, size_t n, unsigned char *md);
unsigned char *SHA512(const unsigned char *d, size_t n, unsigned char *md);
void SRP_user_pwd_free(SRP_user_pwd *user_pwd);
int SRP_user_pwd_set0_sv(SRP_user_pwd *user_pwd, BIGNUM *s, BIGNUM *v);
void SRP_VBASE_free(SRP_VBASE *vb);
int SRP_VBASE_init(SRP_VBASE *vb, char *verifier_file);
int SRP_VBASE_add0_user(SRP_VBASE *vb, SRP_user_pwd *user_pwd);
char *SRP_check_known_gN_param(const BIGNUM *g, const BIGNUM *N);
int SRP_Verify_A_mod_N(const BIGNUM *A, const BIGNUM *N);
int SRP_Verify_B_mod_N(const BIGNUM *B, const BIGNUM *N);
void SSL_CTX_set_psk_client_callback(SSL_CTX *ctx, SSL_psk_client_cb_func cb);
void SSL_set_psk_client_callback(SSL *ssl, SSL_psk_client_cb_func cb);
void SSL_CTX_set_psk_server_callback(SSL_CTX *ctx, SSL_psk_server_cb_func cb);
void SSL_set_psk_server_callback(SSL *ssl, SSL_psk_server_cb_func cb);
void SSL_set_psk_find_session_callback(SSL *s, SSL_psk_find_session_cb_func cb);
void SSL_set_psk_use_session_callback(SSL *s, SSL_psk_use_session_cb_func cb);
void SSL_CTX_set_keylog_callback(SSL_CTX *ctx, SSL_CTX_keylog_cb_func cb);
int SSL_CTX_set_max_early_data(SSL_CTX *ctx, uint32_t max_early_data);
int SSL_set_max_early_data(SSL *s, uint32_t max_early_data);
int SSL_CTX_set_recv_max_early_data(SSL_CTX *ctx, uint32_t recv_max_early_data);
int SSL_set_recv_max_early_data(SSL *s, uint32_t recv_max_early_data);
int SSL_in_init(const SSL *s);
int SSL_in_before(const SSL *s);
int SSL_is_init_finished(const SSL *s);
int SSL_set0_tmp_dh_pkey(SSL *s, EVP_PKEY *dhpkey);
int SSL_CTX_set0_tmp_dh_pkey(SSL_CTX *ctx, EVP_PKEY *dhpkey);
void BIO_ssl_shutdown(BIO *ssl_bio);
int SSL_CTX_up_ref(SSL_CTX *ctx);
void SSL_CTX_free(SSL_CTX *);
void SSL_CTX_set_cert_store(SSL_CTX *, X509_STORE *);
void SSL_CTX_set1_cert_store(SSL_CTX *, X509_STORE *);
void SSL_CTX_flush_sessions(SSL_CTX *ctx, long tm);
void SSL_set0_rbio(SSL *s, BIO *rbio);
void SSL_set0_wbio(SSL *s, BIO *wbio);
void SSL_set_bio(SSL *s, BIO *rbio, BIO *wbio);
void SSL_set_read_ahead(SSL *s, int yes);
void SSL_set_verify(SSL *s, int mode, SSL_verify_cb callback);
void SSL_set_verify_depth(SSL *s, int depth);
void SSL_set_cert_cb(SSL *s, int (*cb) (SSL *ssl, void *arg), void *arg);
int SSL_SESSION_print_fp(FILE *fp, const SSL_SESSION *ses);
int SSL_SESSION_print(BIO *fp, const SSL_SESSION *ses);
int SSL_SESSION_print_keylog(BIO *bp, const SSL_SESSION *x);
int SSL_SESSION_up_ref(SSL_SESSION *ses);
void SSL_SESSION_free(SSL_SESSION *ses);
int SSL_CTX_add_session(SSL_CTX *ctx, SSL_SESSION *session);
int SSL_CTX_remove_session(SSL_CTX *ctx, SSL_SESSION *session);
void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, SSL_verify_cb callback);
void SSL_CTX_set_verify_depth(SSL_CTX *ctx, int depth);
void SSL_CTX_set_default_passwd_cb(SSL_CTX *ctx, pem_password_cb *cb);
void SSL_CTX_set_default_passwd_cb_userdata(SSL_CTX *ctx, void *u);
void *SSL_CTX_get_default_passwd_cb_userdata(SSL_CTX *ctx);
void SSL_set_default_passwd_cb(SSL *s, pem_password_cb *cb);
void SSL_set_default_passwd_cb_userdata(SSL *s, void *u);
void *SSL_get_default_passwd_cb_userdata(SSL *s);
int SSL_up_ref(SSL *s);
int SSL_is_dtls(const SSL *s);
int SSL_is_tls(const SSL *s);
int SSL_is_quic(const SSL *s);
void SSL_set_hostflags(SSL *s, unsigned int flags);
unsigned long SSL_CTX_dane_set_flags(SSL_CTX *ctx, unsigned long flags);
unsigned long SSL_CTX_dane_clear_flags(SSL_CTX *ctx, unsigned long flags);
unsigned long SSL_dane_set_flags(SSL *ssl, unsigned long flags);
unsigned long SSL_dane_clear_flags(SSL *ssl, unsigned long flags);
int SSL_client_hello_isv2(SSL *s);
unsigned int SSL_client_hello_get0_legacy_version(SSL *s);
int SSL_client_hello_get1_extensions_present(SSL *s, int **out, size_t *outlen);
void SSL_certs_clear(SSL *s);
void SSL_free(SSL *ssl);
long SSL_ctrl(SSL *ssl, int cmd, long larg, void *parg);
long SSL_callback_ctrl(SSL *, int, void (*)(void));
long SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg);
long SSL_CTX_callback_ctrl(SSL_CTX *, int, void (*)(void));
int SSL_key_update(SSL *s, int updatetype);
int SSL_get_key_update_type(const SSL *s);
int SSL_renegotiate(SSL *s);
int SSL_renegotiate_abbreviated(SSL *s);
int SSL_new_session_ticket(SSL *s);
int SSL_shutdown(SSL *s);
void SSL_CTX_set_post_handshake_auth(SSL_CTX *ctx, int val);
void SSL_set_post_handshake_auth(SSL *s, int val);
void SSL_set0_CA_list(SSL *s, STACK_OF(X509_NAME) *name_list);
void SSL_CTX_set0_CA_list(SSL_CTX *ctx, STACK_OF(X509_NAME) *name_list);
void SSL_set_client_CA_list(SSL *s, STACK_OF(X509_NAME) *name_list);
void SSL_CTX_set_client_CA_list(SSL_CTX *ctx, STACK_OF(X509_NAME) *name_list);
void SSL_set_connect_state(SSL *s);
void SSL_set_accept_state(SSL *s);
void SSL_CTX_set_quiet_shutdown(SSL_CTX *ctx, int mode);
void SSL_set_quiet_shutdown(SSL *ssl, int mode);
void SSL_set_shutdown(SSL *ssl, int mode);
void SSL_set_verify_result(SSL *ssl, long v);
void *SSL_get_ex_data(const SSL *ssl, int idx);
void *SSL_SESSION_get_ex_data(const SSL_SESSION *ss, int idx);
void *SSL_CTX_get_ex_data(const SSL_CTX *ssl, int idx);
void SSL_CTX_set_default_read_buffer_len(SSL_CTX *ctx, size_t len);
void SSL_set_default_read_buffer_len(SSL *s, size_t len);
int SSL_CIPHER_get_cipher_nid(const SSL_CIPHER *c);
int SSL_CIPHER_get_digest_nid(const SSL_CIPHER *c);
void SSL_CTX_set_record_padding_callback_arg(SSL_CTX *ctx, void *arg);
void *SSL_CTX_get_record_padding_callback_arg(const SSL_CTX *ctx);
int SSL_CTX_set_block_padding(SSL_CTX *ctx, size_t block_size);
void SSL_set_record_padding_callback_arg(SSL *ssl, void *arg);
void *SSL_get_record_padding_callback_arg(const SSL *ssl);
int SSL_set_block_padding(SSL *ssl, size_t block_size);
int SSL_set_num_tickets(SSL *s, size_t num_tickets);
int SSL_CTX_set_num_tickets(SSL_CTX *ctx, size_t num_tickets);
int SSL_handle_events(SSL *s);
int SSL_get_value_uint(SSL *s, uint32_t class_, uint32_t id, uint64_t *v);
int SSL_set_value_uint(SSL *s, uint32_t class_, uint32_t id, uint64_t v);
int SSL_CONF_CTX_finish(SSL_CONF_CTX *cctx);
void SSL_CONF_CTX_free(SSL_CONF_CTX *cctx);
unsigned int SSL_CONF_CTX_set_flags(SSL_CONF_CTX *cctx, unsigned int flags);
void SSL_CONF_CTX_set_ssl(SSL_CONF_CTX *cctx, SSL *ssl);
void SSL_CONF_CTX_set_ssl_ctx(SSL_CONF_CTX *cctx, SSL_CTX *ctx);
void SSL_add_ssl_module(void);
int SSL_config(SSL *s, const char *name);
int SSL_CTX_config(SSL_CTX *ctx, const char *name);
int DTLSv1_listen(SSL *s, BIO_ADDR *client);
int SSL_enable_ct(SSL *s, int validation_mode);
int SSL_CTX_enable_ct(SSL_CTX *ctx, int validation_mode);
int SSL_ct_is_enabled(const SSL *s);
int SSL_CTX_ct_is_enabled(const SSL_CTX *ctx);
int SSL_CTX_set_default_ctlog_list_file(SSL_CTX *ctx);
int SSL_CTX_set_ctlog_list_file(SSL_CTX *ctx, const char *path);
void SSL_CTX_set0_ctlog_store(SSL_CTX *ctx, CTLOG_STORE *logs);
void SSL_set_security_level(SSL *s, int level);
void SSL_set0_security_ex_data(SSL *s, void *ex);
void SSL_CTX_set_security_level(SSL_CTX *ctx, int level);
void SSL_CTX_set0_security_ex_data(SSL_CTX *ctx, void *ex);
int OPENSSL_init_ssl(uint64_t opts, const OPENSSL_INIT_SETTINGS *settings);
int SSL_SESSION_set1_ticket_appdata(SSL_SESSION *ss, const void *data, size_t len);
int SSL_SESSION_get0_ticket_appdata(SSL_SESSION *ss, void **data, size_t *len);
void DTLS_set_timer_cb(SSL *s, DTLS_timer_cb cb);
int SSL_CTX_compress_certs(SSL_CTX *ctx, int alg);
int SSL_compress_certs(SSL *ssl, int alg);
int SSL_CTX_set1_cert_comp_preference(SSL_CTX *ctx, int *algs, size_t len);
int SSL_set1_cert_comp_preference(SSL *ssl, int *algs, size_t len);
int OPENSSL_sk_num(const OPENSSL_STACK *);
void *OPENSSL_sk_value(const OPENSSL_STACK *, int);
void *OPENSSL_sk_set(OPENSSL_STACK *st, int i, const void *data);
int OPENSSL_sk_reserve(OPENSSL_STACK *st, int n);
void OPENSSL_sk_free(OPENSSL_STACK *);
void OPENSSL_sk_pop_free(OPENSSL_STACK *st, void (*func) (void *));
int OPENSSL_sk_insert(OPENSSL_STACK *sk, const void *data, int where);
void *OPENSSL_sk_delete(OPENSSL_STACK *st, int loc);
void *OPENSSL_sk_delete_ptr(OPENSSL_STACK *st, const void *p);
int OPENSSL_sk_find(OPENSSL_STACK *st, const void *data);
int OPENSSL_sk_find_ex(OPENSSL_STACK *st, const void *data);
int OPENSSL_sk_find_all(OPENSSL_STACK *st, const void *data, int *pnum);
int OPENSSL_sk_push(OPENSSL_STACK *st, const void *data);
int OPENSSL_sk_unshift(OPENSSL_STACK *st, const void *data);
void *OPENSSL_sk_shift(OPENSSL_STACK *st);
void *OPENSSL_sk_pop(OPENSSL_STACK *st);
void OPENSSL_sk_zero(OPENSSL_STACK *st);
void OPENSSL_sk_sort(OPENSSL_STACK *st);
int OPENSSL_sk_is_sorted(const OPENSSL_STACK *st);
int OSSL_STORE_eof(OSSL_STORE_CTX *ctx);
int OSSL_STORE_error(OSSL_STORE_CTX *ctx);
int OSSL_STORE_close(OSSL_STORE_CTX *ctx);
int OSSL_STORE_INFO_set0_NAME_description(OSSL_STORE_INFO *info, char *desc);
int OSSL_STORE_INFO_get_type(const OSSL_STORE_INFO *info);
void *OSSL_STORE_INFO_get0_data(int type, const OSSL_STORE_INFO *info);
char *OSSL_STORE_INFO_get1_NAME(const OSSL_STORE_INFO *info);
char *OSSL_STORE_INFO_get1_NAME_description(const OSSL_STORE_INFO *info);
void OSSL_STORE_INFO_free(OSSL_STORE_INFO *info);
int OSSL_STORE_supports_search(OSSL_STORE_CTX *ctx, int search_type);
void OSSL_STORE_SEARCH_free(OSSL_STORE_SEARCH *search);
int OSSL_STORE_SEARCH_get_type(const OSSL_STORE_SEARCH *criterion);
int OSSL_STORE_expect(OSSL_STORE_CTX *ctx, int expected_type);
int OSSL_STORE_find(OSSL_STORE_CTX *ctx, const OSSL_STORE_SEARCH *search);
int OSSL_STORE_LOADER_up_ref(OSSL_STORE_LOADER *loader);
void OSSL_STORE_LOADER_free(OSSL_STORE_LOADER *loader);
int OSSL_STORE_register_loader(OSSL_STORE_LOADER *loader);
int OSSL_set_max_threads(OSSL_LIB_CTX *ctx, uint64_t max_threads);
int SSL_CTX_set_tlsext_max_fragment_length(SSL_CTX *ctx, uint8_t mode);
int SSL_set_tlsext_max_fragment_length(SSL *ssl, uint8_t mode);
int SSL_get_peer_signature_type_nid(const SSL *s, int *pnid);
int SSL_get_signature_type_nid(const SSL *s, int *pnid);
int OSSL_trace_get_category_num(const char *name);
int OSSL_trace_set_channel(int category, BIO* channel);
int OSSL_trace_set_prefix(int category, const char *prefix);
int OSSL_trace_set_suffix(int category, const char *suffix);
int OSSL_trace_set_callback(int category, OSSL_trace_cb callback, void *data);
int OSSL_trace_enabled(int category);
void OSSL_trace_end(int category, BIO *channel);
int i2d_TS_REQ_fp(FILE *fp, const TS_REQ *a);
int i2d_TS_REQ_bio(BIO *fp, const TS_REQ *a);
int i2d_TS_MSG_IMPRINT_fp(FILE *fp, const TS_MSG_IMPRINT *a);
int i2d_TS_MSG_IMPRINT_bio(BIO *bio, const TS_MSG_IMPRINT *a);
int i2d_TS_RESP_fp(FILE *fp, const TS_RESP *a);
int i2d_TS_RESP_bio(BIO *bio, const TS_RESP *a);
int i2d_TS_TST_INFO_fp(FILE *fp, const TS_TST_INFO *a);
int i2d_TS_TST_INFO_bio(BIO *bio, const TS_TST_INFO *a);
int TS_REQ_set_version(TS_REQ *a, long version);
long TS_REQ_get_version(const TS_REQ *a);
int TS_STATUS_INFO_set_status(TS_STATUS_INFO *a, int i);
int TS_REQ_set_msg_imprint(TS_REQ *a, TS_MSG_IMPRINT *msg_imprint);
int TS_MSG_IMPRINT_set_algo(TS_MSG_IMPRINT *a, X509_ALGOR *alg);
int TS_MSG_IMPRINT_set_msg(TS_MSG_IMPRINT *a, unsigned char *d, int len);
int TS_REQ_set_policy_id(TS_REQ *a, const ASN1_OBJECT *policy);
int TS_REQ_set_nonce(TS_REQ *a, const ASN1_INTEGER *nonce);
int TS_REQ_set_cert_req(TS_REQ *a, int cert_req);
int TS_REQ_get_cert_req(const TS_REQ *a);
void TS_REQ_ext_free(TS_REQ *a);
int TS_REQ_get_ext_count(TS_REQ *a);
int TS_REQ_get_ext_by_NID(TS_REQ *a, int nid, int lastpos);
int TS_REQ_get_ext_by_OBJ(TS_REQ *a, const ASN1_OBJECT *obj, int lastpos);
int TS_REQ_get_ext_by_critical(TS_REQ *a, int crit, int lastpos);
int TS_REQ_add_ext(TS_REQ *a, X509_EXTENSION *ex, int loc);
void *TS_REQ_get_ext_d2i(TS_REQ *a, int nid, int *crit, int *idx);
int TS_REQ_print_bio(BIO *bio, TS_REQ *a);
int TS_RESP_set_status_info(TS_RESP *a, TS_STATUS_INFO *info);
void TS_RESP_set_tst_info(TS_RESP *a, PKCS7 *p7, TS_TST_INFO *tst_info);
int TS_TST_INFO_set_version(TS_TST_INFO *a, long version);
long TS_TST_INFO_get_version(const TS_TST_INFO *a);
int TS_TST_INFO_set_policy_id(TS_TST_INFO *a, ASN1_OBJECT *policy_id);
int TS_TST_INFO_set_msg_imprint(TS_TST_INFO *a, TS_MSG_IMPRINT *msg_imprint);
int TS_TST_INFO_set_serial(TS_TST_INFO *a, const ASN1_INTEGER *serial);
int TS_TST_INFO_set_time(TS_TST_INFO *a, const ASN1_GENERALIZEDTIME *gtime);
int TS_TST_INFO_set_accuracy(TS_TST_INFO *a, TS_ACCURACY *accuracy);
int TS_ACCURACY_set_seconds(TS_ACCURACY *a, const ASN1_INTEGER *seconds);
int TS_ACCURACY_set_millis(TS_ACCURACY *a, const ASN1_INTEGER *millis);
int TS_ACCURACY_set_micros(TS_ACCURACY *a, const ASN1_INTEGER *micros);
int TS_TST_INFO_set_ordering(TS_TST_INFO *a, int ordering);
int TS_TST_INFO_get_ordering(const TS_TST_INFO *a);
int TS_TST_INFO_set_nonce(TS_TST_INFO *a, const ASN1_INTEGER *nonce);
int TS_TST_INFO_set_tsa(TS_TST_INFO *a, GENERAL_NAME *tsa);
void TS_TST_INFO_ext_free(TS_TST_INFO *a);
int TS_TST_INFO_get_ext_count(TS_TST_INFO *a);
int TS_TST_INFO_get_ext_by_NID(TS_TST_INFO *a, int nid, int lastpos);
int TS_TST_INFO_get_ext_by_critical(TS_TST_INFO *a, int crit, int lastpos);
int TS_TST_INFO_add_ext(TS_TST_INFO *a, X509_EXTENSION *ex, int loc);
void *TS_TST_INFO_get_ext_d2i(TS_TST_INFO *a, int nid, int *crit, int *idx);
void TS_RESP_CTX_free(TS_RESP_CTX *ctx);
int TS_RESP_CTX_set_signer_cert(TS_RESP_CTX *ctx, X509 *signer);
int TS_RESP_CTX_set_signer_key(TS_RESP_CTX *ctx, EVP_PKEY *key);
int TS_RESP_CTX_set_ess_cert_id_digest(TS_RESP_CTX *ctx, const EVP_MD *md);
int TS_RESP_CTX_set_def_policy(TS_RESP_CTX *ctx, const ASN1_OBJECT *def_policy);
int TS_RESP_CTX_set_certs(TS_RESP_CTX *ctx, STACK_OF(X509) *certs);
int TS_RESP_CTX_add_policy(TS_RESP_CTX *ctx, const ASN1_OBJECT *policy);
int TS_RESP_CTX_add_md(TS_RESP_CTX *ctx, const EVP_MD *md);
void TS_RESP_CTX_add_flags(TS_RESP_CTX *ctx, int flags);
void TS_RESP_CTX_set_serial_cb(TS_RESP_CTX *ctx, TS_serial_cb cb, void *data);
void TS_RESP_CTX_set_time_cb(TS_RESP_CTX *ctx, TS_time_cb cb, void *data);
int TS_RESP_CTX_add_failure_info(TS_RESP_CTX *ctx, int failure);
int TS_RESP_verify_response(TS_VERIFY_CTX *ctx, TS_RESP *response);
int TS_RESP_verify_token(TS_VERIFY_CTX *ctx, PKCS7 *token);
void TS_VERIFY_CTX_init(TS_VERIFY_CTX *ctx);
void TS_VERIFY_CTX_free(TS_VERIFY_CTX *ctx);
void TS_VERIFY_CTX_cleanup(TS_VERIFY_CTX *ctx);
int TS_VERIFY_CTX_set_flags(TS_VERIFY_CTX *ctx, int f);
int TS_VERIFY_CTX_add_flags(TS_VERIFY_CTX *ctx, int f);
int TS_RESP_print_bio(BIO *bio, TS_RESP *a);
int TS_STATUS_INFO_print_bio(BIO *bio, TS_STATUS_INFO *a);
int TS_TST_INFO_print_bio(BIO *bio, TS_TST_INFO *a);
int TS_ASN1_INTEGER_print_bio(BIO *bio, const ASN1_INTEGER *num);
int TS_OBJ_print_bio(BIO *bio, const ASN1_OBJECT *obj);
int TS_ext_print_bio(BIO *bio, const STACK_OF(X509_EXTENSION) *extensions);
int TS_X509_ALGOR_print_bio(BIO *bio, const X509_ALGOR *alg);
int TS_MSG_IMPRINT_print_bio(BIO *bio, TS_MSG_IMPRINT *msg);
int TS_CONF_set_default_engine(const char *name);
int TS_CONF_set_policies(CONF *conf, const char *section, TS_RESP_CTX *ctx);
int TS_CONF_set_digests(CONF *conf, const char *section, TS_RESP_CTX *ctx);
int TS_CONF_set_accuracy(CONF *conf, const char *section, TS_RESP_CTX *ctx);
int TS_CONF_set_ordering(CONF *conf, const char *section, TS_RESP_CTX *ctx);
int TS_CONF_set_tsa_name(CONF *conf, const char *section, TS_RESP_CTX *ctx);
long TXT_DB_write(BIO *out, TXT_DB *db);
void TXT_DB_free(TXT_DB *db);
int TXT_DB_insert(TXT_DB *db, OPENSSL_STRING *value);
void UI_free(UI *ui);
int UI_add_info_string(UI *ui, const char *text);
int UI_dup_info_string(UI *ui, const char *text);
int UI_add_error_string(UI *ui, const char *text);
int UI_dup_error_string(UI *ui, const char *text);
void *UI_add_user_data(UI *ui, void *user_data);
int UI_dup_user_data(UI *ui, void *user_data);
void *UI_get0_user_data(UI *ui);
int UI_get_result_length(UI *ui, int i);
int UI_process(UI *ui);
int UI_ctrl(UI *ui, int cmd, long i, void *p, void (*f) (void));
int UI_set_ex_data(UI *r, int idx, void *arg);
void *UI_get_ex_data(const UI *r, int idx);
void UI_set_default_method(const UI_METHOD *meth);
void UI_destroy_method(UI_METHOD *ui_method);
int UI_method_set_opener(UI_METHOD *method, int (*opener) (UI *ui));
int UI_method_set_flusher(UI_METHOD *method, int (*flusher) (UI *ui));
int UI_method_set_closer(UI_METHOD *method, int (*closer) (UI *ui));
int UI_method_set_ex_data(UI_METHOD *method, int idx, void *data);
int (*UI_method_get_opener(const UI_METHOD *method)) (UI *);
int (*UI_method_get_writer(const UI_METHOD *method)) (UI *, UI_STRING *);
int (*UI_method_get_flusher(const UI_METHOD *method)) (UI *);
int (*UI_method_get_reader(const UI_METHOD *method)) (UI *, UI_STRING *);
int (*UI_method_get_closer(const UI_METHOD *method)) (UI *);
void *(*UI_method_get_data_duplicator(const UI_METHOD *method)) (UI *, void *);
void (*UI_method_get_data_destructor(const UI_METHOD *method)) (UI *, void *);
int UI_get_input_flags(UI_STRING *uis);
int UI_get_result_string_length(UI_STRING *uis);
int UI_get_result_minsize(UI_STRING *uis);
int UI_get_result_maxsize(UI_STRING *uis);
int UI_set_result(UI *ui, UI_STRING *uis, const char *result);
int UI_set_result_ex(UI *ui, UI_STRING *uis, const char *result, int len);
void X509_CRL_set_default_method(const X509_CRL_METHOD *meth);
void X509_CRL_METHOD_free(X509_CRL_METHOD *m);
void X509_CRL_set_meth_data(X509_CRL *crl, void *dat);
void *X509_CRL_get_meth_data(X509_CRL *crl);
int X509_verify(X509 *a, EVP_PKEY *r);
int X509_self_signed(X509 *cert, int verify_signature);
int X509_REQ_verify(X509_REQ *a, EVP_PKEY *r);
int X509_CRL_verify(X509_CRL *a, EVP_PKEY *r);
int NETSCAPE_SPKI_verify(NETSCAPE_SPKI *a, EVP_PKEY *r);
char *NETSCAPE_SPKI_b64_encode(NETSCAPE_SPKI *x);
int NETSCAPE_SPKI_set_pubkey(NETSCAPE_SPKI *x, EVP_PKEY *pkey);
int NETSCAPE_SPKI_print(BIO *out, NETSCAPE_SPKI *spki);
int X509_signature_dump(BIO *bp, const ASN1_STRING *sig, int indent);
int X509_sign(X509 *x, EVP_PKEY *pkey, const EVP_MD *md);
int X509_sign_ctx(X509 *x, EVP_MD_CTX *ctx);
int X509_REQ_sign(X509_REQ *x, EVP_PKEY *pkey, const EVP_MD *md);
int X509_REQ_sign_ctx(X509_REQ *x, EVP_MD_CTX *ctx);
int X509_CRL_sign(X509_CRL *x, EVP_PKEY *pkey, const EVP_MD *md);
int X509_CRL_sign_ctx(X509_CRL *x, EVP_MD_CTX *ctx);
int NETSCAPE_SPKI_sign(NETSCAPE_SPKI *x, EVP_PKEY *pkey, const EVP_MD *md);
int i2d_X509_fp(FILE *fp, const X509 *x509);
int i2d_X509_CRL_fp(FILE *fp, const X509_CRL *crl);
int i2d_X509_REQ_fp(FILE *fp, const X509_REQ *req);
int i2d_PKCS8_fp(FILE *fp, const X509_SIG *p8);
int i2d_X509_PUBKEY_fp(FILE *fp, const X509_PUBKEY *xpk);
int i2d_PKCS8_PRIV_KEY_INFO_fp(FILE *fp, const PKCS8_PRIV_KEY_INFO *p8inf);
int i2d_PKCS8PrivateKeyInfo_fp(FILE *fp, const EVP_PKEY *key);
int i2d_PrivateKey_fp(FILE *fp, const EVP_PKEY *pkey);
int i2d_PUBKEY_fp(FILE *fp, const EVP_PKEY *pkey);
int i2d_X509_bio(BIO *bp, const X509 *x509);
int i2d_X509_CRL_bio(BIO *bp, const X509_CRL *crl);
int i2d_X509_REQ_bio(BIO *bp, const X509_REQ *req);
int i2d_PKCS8_bio(BIO *bp, const X509_SIG *p8);
int i2d_X509_PUBKEY_bio(BIO *bp, const X509_PUBKEY *xpk);
int i2d_PKCS8_PRIV_KEY_INFO_bio(BIO *bp, const PKCS8_PRIV_KEY_INFO *p8inf);
int i2d_PKCS8PrivateKeyInfo_bio(BIO *bp, const EVP_PKEY *key);
int i2d_PrivateKey_bio(BIO *bp, const EVP_PKEY *pkey);
int i2d_PUBKEY_bio(BIO *bp, const EVP_PKEY *pkey);
void X509_ALGOR_set_md(X509_ALGOR *alg, const EVP_MD *md);
int X509_ALGOR_cmp(const X509_ALGOR *a, const X509_ALGOR *b);
int X509_ALGOR_copy(X509_ALGOR *dest, const X509_ALGOR *src);
int X509_cmp_time(const ASN1_TIME *s, time_t *t);
int X509_cmp_current_time(const ASN1_TIME *s);
int X509_PUBKEY_set(X509_PUBKEY **x, EVP_PKEY *pkey);
int X509_get_pubkey_parameters(EVP_PKEY *pkey, STACK_OF(X509) *chain);
long X509_get_pathlen(X509 *x);
int X509_NAME_set(X509_NAME **xn, const X509_NAME *name);
int X509_set_ex_data(X509 *r, int idx, void *arg);
void *X509_get_ex_data(const X509 *r, int idx);
int i2d_re_X509_tbs(X509 *x, unsigned char **pp);
int X509_get_signature_nid(const X509 *x);
void X509_set0_distinguishing_id(X509 *x, ASN1_OCTET_STRING *d_id);
void X509_REQ_set0_distinguishing_id(X509_REQ *x, ASN1_OCTET_STRING *d_id);
int X509_alias_set1(X509 *x, const unsigned char *name, int len);
int X509_keyid_set1(X509 *x, const unsigned char *id, int len);
unsigned char *X509_alias_get0(X509 *x, int *len);
unsigned char *X509_keyid_get0(X509 *x, int *len);
int X509_CRL_add0_revoked(X509_CRL *crl, X509_REVOKED *rev);
int X509_CRL_get0_by_cert(X509_CRL *crl, X509_REVOKED **ret, X509 *x);
void X509_PKEY_free(X509_PKEY *a);
void X509_INFO_free(X509_INFO *a);
char *X509_NAME_oneline(const X509_NAME *a, char *buf, int size);
long X509_get_version(const X509 *x);
int X509_set_version(X509 *x, long version);
int X509_set_serialNumber(X509 *x, ASN1_INTEGER *serial);
int X509_set_issuer_name(X509 *x, const X509_NAME *name);
int X509_set_subject_name(X509 *x, const X509_NAME *name);
int X509_set1_notBefore(X509 *x, const ASN1_TIME *tm);
int X509_set1_notAfter(X509 *x, const ASN1_TIME *tm);
int X509_set_pubkey(X509 *x, EVP_PKEY *pkey);
int X509_up_ref(X509 *x);
int X509_get_signature_type(const X509 *x);
long X509_REQ_get_version(const X509_REQ *req);
int X509_REQ_set_version(X509_REQ *x, long version);
int X509_REQ_set_subject_name(X509_REQ *req, const X509_NAME *name);
void X509_REQ_set0_signature(X509_REQ *req, ASN1_BIT_STRING *psig);
int X509_REQ_set1_signature_algo(X509_REQ *req, X509_ALGOR *palg);
int X509_REQ_get_signature_nid(const X509_REQ *req);
int i2d_re_X509_REQ_tbs(X509_REQ *req, unsigned char **pp);
int X509_REQ_set_pubkey(X509_REQ *x, EVP_PKEY *pkey);
int X509_REQ_extension_nid(int nid);
int *X509_REQ_get_extension_nids(void);
void X509_REQ_set_extension_nids(int *nids);
int X509_REQ_add_extensions(X509_REQ *req, const STACK_OF(X509_EXTENSION) *ext);
int X509_REQ_get_attr_count(const X509_REQ *req);
int X509_REQ_get_attr_by_NID(const X509_REQ *req, int nid, int lastpos);
int X509_REQ_add1_attr(X509_REQ *req, X509_ATTRIBUTE *attr);
int X509_CRL_set_version(X509_CRL *x, long version);
int X509_CRL_set_issuer_name(X509_CRL *x, const X509_NAME *name);
int X509_CRL_set1_lastUpdate(X509_CRL *x, const ASN1_TIME *tm);
int X509_CRL_set1_nextUpdate(X509_CRL *x, const ASN1_TIME *tm);
int X509_CRL_sort(X509_CRL *crl);
int X509_CRL_up_ref(X509_CRL *crl);
long X509_CRL_get_version(const X509_CRL *crl);
int X509_CRL_get_signature_nid(const X509_CRL *crl);
int i2d_re_X509_CRL_tbs(X509_CRL *req, unsigned char **pp);
int X509_REVOKED_set_serialNumber(X509_REVOKED *x, ASN1_INTEGER *serial);
int X509_REVOKED_set_revocationDate(X509_REVOKED *r, ASN1_TIME *tm);
int X509_REQ_check_private_key(const X509_REQ *req, EVP_PKEY *pkey);
int X509_check_private_key(const X509 *cert, const EVP_PKEY *pkey);
int X509_CRL_check_suiteb(X509_CRL *crl, EVP_PKEY *pk, unsigned long flags);
void OSSL_STACK_OF_X509_free(STACK_OF(X509) *certs);
int X509_issuer_and_serial_cmp(const X509 *a, const X509 *b);
unsigned long X509_issuer_and_serial_hash(X509 *a);
int X509_issuer_name_cmp(const X509 *a, const X509 *b);
unsigned long X509_issuer_name_hash(X509 *a);
int X509_subject_name_cmp(const X509 *a, const X509 *b);
unsigned long X509_subject_name_hash(X509 *x);
unsigned long X509_issuer_name_hash_old(X509 *a);
unsigned long X509_subject_name_hash_old(X509 *x);
int X509_add_cert(STACK_OF(X509) *sk, X509 *cert, int flags);
int X509_add_certs(STACK_OF(X509) *sk, STACK_OF(X509) *certs, int flags);
int X509_cmp(const X509 *a, const X509 *b);
int X509_NAME_cmp(const X509_NAME *a, const X509_NAME *b);
unsigned long X509_NAME_hash_old(const X509_NAME *x);
int X509_CRL_cmp(const X509_CRL *a, const X509_CRL *b);
int X509_CRL_match(const X509_CRL *a, const X509_CRL *b);
int X509_aux_print(BIO *out, X509 *x, int indent);
int X509_print_fp(FILE *bp, X509 *x);
int X509_CRL_print_fp(FILE *bp, X509_CRL *x);
int X509_REQ_print_fp(FILE *bp, X509_REQ *req);
int X509_NAME_print(BIO *bp, const X509_NAME *name, int obase);
int X509_print(BIO *bp, X509 *x);
int X509_ocspid_print(BIO *bp, X509 *x);
int X509_CRL_print_ex(BIO *out, X509_CRL *x, unsigned long nmflag);
int X509_CRL_print(BIO *bp, X509_CRL *x);
int X509_REQ_print(BIO *bp, X509_REQ *req);
int X509_NAME_entry_count(const X509_NAME *name);
int X509_NAME_get_index_by_NID(const X509_NAME *name, int nid, int lastpos);
int X509_NAME_ENTRY_set_object(X509_NAME_ENTRY *ne, const ASN1_OBJECT *obj);
int X509_NAME_ENTRY_set(const X509_NAME_ENTRY *ne);
int X509v3_get_ext_count(const STACK_OF(X509_EXTENSION) *x);
int X509_get_ext_count(const X509 *x);
int X509_get_ext_by_NID(const X509 *x, int nid, int lastpos);
int X509_get_ext_by_OBJ(const X509 *x, const ASN1_OBJECT *obj, int lastpos);
int X509_get_ext_by_critical(const X509 *x, int crit, int lastpos);
int X509_add_ext(X509 *x, X509_EXTENSION *ex, int loc);
void *X509_get_ext_d2i(const X509 *x, int nid, int *crit, int *idx);
int X509_CRL_get_ext_count(const X509_CRL *x);
int X509_CRL_get_ext_by_NID(const X509_CRL *x, int nid, int lastpos);
int X509_CRL_get_ext_by_critical(const X509_CRL *x, int crit, int lastpos);
int X509_CRL_add_ext(X509_CRL *x, X509_EXTENSION *ex, int loc);
void *X509_CRL_get_ext_d2i(const X509_CRL *x, int nid, int *crit, int *idx);
int X509_REVOKED_get_ext_count(const X509_REVOKED *x);
int X509_REVOKED_get_ext_by_NID(const X509_REVOKED *x, int nid, int lastpos);
int X509_REVOKED_add_ext(X509_REVOKED *x, X509_EXTENSION *ex, int loc);
int X509_EXTENSION_set_object(X509_EXTENSION *ex, const ASN1_OBJECT *obj);
int X509_EXTENSION_set_critical(X509_EXTENSION *ex, int crit);
int X509_EXTENSION_set_data(X509_EXTENSION *ex, ASN1_OCTET_STRING *data);
int X509_EXTENSION_get_critical(const X509_EXTENSION *ex);
int X509at_get_attr_count(const STACK_OF(X509_ATTRIBUTE) *x);
int X509_ATTRIBUTE_set1_object(X509_ATTRIBUTE *attr, const ASN1_OBJECT *obj);
int X509_ATTRIBUTE_count(const X509_ATTRIBUTE *attr);
int EVP_PKEY_get_attr_count(const EVP_PKEY *key);
int EVP_PKEY_get_attr_by_NID(const EVP_PKEY *key, int nid, int lastpos);
int EVP_PKEY_add1_attr(EVP_PKEY *key, X509_ATTRIBUTE *attr);
int PKCS8_pkey_add1_attr(PKCS8_PRIV_KEY_INFO *p8, X509_ATTRIBUTE *attr);
int X509_PUBKEY_eq(const X509_PUBKEY *a, const X509_PUBKEY *b);
int SXNET_add_id_asc(SXNET **psx, const char *zone, const char *user, int userlen);
int GENERAL_NAME_cmp(GENERAL_NAME *a, GENERAL_NAME *b);
char *i2s_ASN1_IA5STRING(X509V3_EXT_METHOD *method, ASN1_IA5STRING *ia5);
char *i2s_ASN1_UTF8STRING(X509V3_EXT_METHOD *method, ASN1_UTF8STRING *utf8);
int GENERAL_NAME_print(BIO *out, GENERAL_NAME *gen);
int OTHERNAME_cmp(OTHERNAME *a, OTHERNAME *b);
void GENERAL_NAME_set0_value(GENERAL_NAME *a, int type, void *value);
void *GENERAL_NAME_get0_value(const GENERAL_NAME *a, int *ptype);
int i2a_ACCESS_DESCRIPTION(BIO *bp, const ACCESS_DESCRIPTION *a);
int DIST_POINT_set_dpname(DIST_POINT_NAME *dpn, const X509_NAME *iname);
int NAME_CONSTRAINTS_check(X509 *x, NAME_CONSTRAINTS *nc);
int NAME_CONSTRAINTS_check_CN(X509 *x, NAME_CONSTRAINTS *nc);
void X509V3_conf_free(CONF_VALUE *val);
int X509V3_get_value_bool(const CONF_VALUE *value, int *asn1_bool);
int X509V3_get_value_int(const CONF_VALUE *value, ASN1_INTEGER **aint);
void X509V3_set_nconf(X509V3_CTX *ctx, CONF *conf);
void X509V3_set_conf_lhash(X509V3_CTX *ctx, LHASH_OF(CONF_VALUE) *lhash);
char *X509V3_get_string(X509V3_CTX *ctx, const char *name, const char *section);
void X509V3_string_free(X509V3_CTX *ctx, char *str);
void X509V3_section_free(X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *section);
int X509V3_set_issuer_pkey(X509V3_CTX *ctx, EVP_PKEY *pkey);
char *i2s_ASN1_INTEGER(X509V3_EXT_METHOD *meth, const ASN1_INTEGER *aint);
char *i2s_ASN1_ENUMERATED(X509V3_EXT_METHOD *meth, const ASN1_ENUMERATED *aint);
int X509V3_EXT_add(X509V3_EXT_METHOD *ext);
int X509V3_EXT_add_list(X509V3_EXT_METHOD *extlist);
int X509V3_EXT_add_alias(int nid_to, int nid_from);
void X509V3_EXT_cleanup(void);
int X509V3_add_standard_extensions(void);
void *X509V3_EXT_d2i(X509_EXTENSION *ext);
int X509V3_EXT_print_fp(FILE *out, X509_EXTENSION *ext, int flag, int indent);
int X509_check_ca(X509 *x);
int X509_check_purpose(X509 *x, int id, int ca);
int X509_supported_extension(X509_EXTENSION *ex);
int X509_PURPOSE_set(int *p, int purpose);
int X509_check_issued(X509 *issuer, X509 *subject);
int X509_check_akid(const X509 *issuer, const AUTHORITY_KEYID *akid);
void X509_set_proxy_flag(X509 *x);
void X509_set_proxy_pathlen(X509 *x, long l);
long X509_get_proxy_pathlen(X509 *x);
int X509_PURPOSE_get_count(void);
int X509_PURPOSE_get_by_sname(const char *sname);
int X509_PURPOSE_get_by_id(int id);
char *X509_PURPOSE_get0_name(const X509_PURPOSE *xp);
char *X509_PURPOSE_get0_sname(const X509_PURPOSE *xp);
int X509_PURPOSE_get_trust(const X509_PURPOSE *xp);
void X509_PURPOSE_cleanup(void);
int X509_PURPOSE_get_id(const X509_PURPOSE *);
void X509_email_free(STACK_OF(OPENSSL_STRING) *sk);
int X509_check_ip_asc(X509 *x, const char *ipasc, unsigned int flags);
void X509_POLICY_NODE_print(BIO *out, X509_POLICY_NODE *node, int indent);
int X509v3_asid_add_inherit(ASIdentifiers *asid, int which);
unsigned X509v3_addr_get_afi(const IPAddressFamily *f);
int X509v3_asid_is_canonical(ASIdentifiers *asid);
int X509v3_addr_is_canonical(IPAddrBlocks *addr);
int X509v3_asid_canonize(ASIdentifiers *asid);
int X509v3_addr_canonize(IPAddrBlocks *addr);
int X509v3_asid_inherits(ASIdentifiers *asid);
int X509v3_addr_inherits(IPAddrBlocks *addr);
int X509v3_asid_subset(ASIdentifiers *a, ASIdentifiers *b);
int X509v3_addr_subset(IPAddrBlocks *a, IPAddrBlocks *b);
int X509v3_asid_validate_path(X509_STORE_CTX *);
int X509v3_addr_validate_path(X509_STORE_CTX *);
void ADMISSIONS_set0_admissionAuthority(ADMISSIONS *a, GENERAL_NAME *aa);
void ADMISSIONS_set0_namingAuthority(ADMISSIONS *a, NAMING_AUTHORITY *na);
void ADMISSIONS_set0_professionInfos(ADMISSIONS *a, PROFESSION_INFOS *pi);
int X509_TRUST_set(int *t, int trust);
int X509_TRUST_get_count(void);
int X509_TRUST_get_by_id(int id);
void X509_TRUST_cleanup(void);
int X509_TRUST_get_flags(const X509_TRUST *xp);
char *X509_TRUST_get0_name(const X509_TRUST *xp);
int X509_TRUST_get_trust(const X509_TRUST *xp);
int X509_trusted(const X509 *x);
int X509_add1_trust_object(X509 *x, const ASN1_OBJECT *obj);
int X509_add1_reject_object(X509 *x, const ASN1_OBJECT *obj);
void X509_trust_clear(X509 *x);
void X509_reject_clear(X509 *x);
int X509_check_trust(X509 *x, int id, int flags);
int X509_verify_cert(X509_STORE_CTX *ctx);
int X509_STORE_CTX_verify(X509_STORE_CTX *ctx);
int X509_STORE_set_depth(X509_STORE *store, int depth);
int X509_STORE_CTX_print_verify_cb(int ok, X509_STORE_CTX *ctx);
void X509_STORE_CTX_set_depth(X509_STORE_CTX *ctx, int depth);
int X509_OBJECT_up_ref_count(X509_OBJECT *a);
void X509_OBJECT_free(X509_OBJECT *a);
int X509_OBJECT_set1_X509(X509_OBJECT *a, X509 *obj);
int X509_OBJECT_set1_X509_CRL(X509_OBJECT *a, X509_CRL *obj);
void X509_STORE_free(X509_STORE *xs);
int X509_STORE_lock(X509_STORE *xs);
int X509_STORE_unlock(X509_STORE *xs);
int X509_STORE_up_ref(X509_STORE *xs);
int X509_STORE_set_flags(X509_STORE *xs, unsigned long flags);
int X509_STORE_set_purpose(X509_STORE *xs, int purpose);
int X509_STORE_set_trust(X509_STORE *xs, int trust);
int X509_STORE_set1_param(X509_STORE *xs, const X509_VERIFY_PARAM *pm);
void X509_STORE_set_verify(X509_STORE *xs, X509_STORE_CTX_verify_fn verify);
int X509_STORE_set_ex_data(X509_STORE *xs, int idx, void *data);
void *X509_STORE_get_ex_data(const X509_STORE *xs, int idx);
int X509_STORE_CTX_get1_issuer(X509 **issuer, X509_STORE_CTX *ctx, X509 *x);
void X509_STORE_CTX_free(X509_STORE_CTX *ctx);
void X509_STORE_CTX_set0_trusted_stack(X509_STORE_CTX *ctx, STACK_OF(X509) *sk);
void X509_STORE_CTX_cleanup(X509_STORE_CTX *ctx);
void X509_STORE_CTX_set0_untrusted(X509_STORE_CTX *ctx, STACK_OF(X509) *sk);
void X509_LOOKUP_meth_free(X509_LOOKUP_METHOD *method);
int X509_STORE_add_cert(X509_STORE *xs, X509 *x);
int X509_STORE_add_crl(X509_STORE *xs, X509_CRL *x);
int X509_load_cert_file(X509_LOOKUP *ctx, const char *file, int type);
int X509_load_crl_file(X509_LOOKUP *ctx, const char *file, int type);
int X509_load_cert_crl_file(X509_LOOKUP *ctx, const char *file, int type);
void X509_LOOKUP_free(X509_LOOKUP *ctx);
int X509_LOOKUP_init(X509_LOOKUP *ctx);
int X509_LOOKUP_set_method_data(X509_LOOKUP *ctx, void *data);
void *X509_LOOKUP_get_method_data(const X509_LOOKUP *ctx);
int X509_LOOKUP_shutdown(X509_LOOKUP *ctx);
int X509_STORE_load_file(X509_STORE *xs, const char *file);
int X509_STORE_load_path(X509_STORE *xs, const char *path);
int X509_STORE_load_store(X509_STORE *xs, const char *store);
int X509_STORE_load_locations(X509_STORE *s, const char *file, const char *dir);
int X509_STORE_set_default_paths(X509_STORE *xs);
int X509_STORE_CTX_set_ex_data(X509_STORE_CTX *ctx, int idx, void *data);
void *X509_STORE_CTX_get_ex_data(const X509_STORE_CTX *ctx, int idx);
int X509_STORE_CTX_get_error(const X509_STORE_CTX *ctx);
void X509_STORE_CTX_set_error(X509_STORE_CTX *ctx, int s);
int X509_STORE_CTX_get_error_depth(const X509_STORE_CTX *ctx);
void X509_STORE_CTX_set_error_depth(X509_STORE_CTX *ctx, int depth);
void X509_STORE_CTX_set_current_cert(X509_STORE_CTX *ctx, X509 *x);
void X509_STORE_CTX_set_cert(X509_STORE_CTX *ctx, X509 *target);
void X509_STORE_CTX_set0_rpk(X509_STORE_CTX *ctx, EVP_PKEY *target);
void X509_STORE_CTX_set0_verified_chain(X509_STORE_CTX *c, STACK_OF(X509) *sk);
void X509_STORE_CTX_set0_crls(X509_STORE_CTX *ctx, STACK_OF(X509_CRL) *sk);
int X509_STORE_CTX_set_purpose(X509_STORE_CTX *ctx, int purpose);
int X509_STORE_CTX_set_trust(X509_STORE_CTX *ctx, int trust);
void X509_STORE_CTX_set_flags(X509_STORE_CTX *ctx, unsigned long flags);
int X509_STORE_CTX_get_explicit_policy(const X509_STORE_CTX *ctx);
int X509_STORE_CTX_get_num_untrusted(const X509_STORE_CTX *ctx);
void X509_STORE_CTX_set0_param(X509_STORE_CTX *ctx, X509_VERIFY_PARAM *param);
int X509_STORE_CTX_set_default(X509_STORE_CTX *ctx, const char *name);
void X509_STORE_CTX_set0_dane(X509_STORE_CTX *ctx, SSL_DANE *dane);
void X509_VERIFY_PARAM_free(X509_VERIFY_PARAM *param);
int X509_VERIFY_PARAM_set1_name(X509_VERIFY_PARAM *param, const char *name);
unsigned long X509_VERIFY_PARAM_get_flags(const X509_VERIFY_PARAM *param);
int X509_VERIFY_PARAM_set_purpose(X509_VERIFY_PARAM *param, int purpose);
int X509_VERIFY_PARAM_set_trust(X509_VERIFY_PARAM *param, int trust);
void X509_VERIFY_PARAM_set_depth(X509_VERIFY_PARAM *param, int depth);
void X509_VERIFY_PARAM_set_auth_level(X509_VERIFY_PARAM *param, int auth_level);
void X509_VERIFY_PARAM_set_time(X509_VERIFY_PARAM *param, time_t t);
char *X509_VERIFY_PARAM_get0_host(X509_VERIFY_PARAM *param, int idx);
unsigned int X509_VERIFY_PARAM_get_hostflags(const X509_VERIFY_PARAM *param);
char *X509_VERIFY_PARAM_get0_peername(const X509_VERIFY_PARAM *param);
void X509_VERIFY_PARAM_move_peername(X509_VERIFY_PARAM *, X509_VERIFY_PARAM *);
char *X509_VERIFY_PARAM_get0_email(X509_VERIFY_PARAM *param);
char *X509_VERIFY_PARAM_get1_ip_asc(X509_VERIFY_PARAM *param);
int X509_VERIFY_PARAM_get_depth(const X509_VERIFY_PARAM *param);
int X509_VERIFY_PARAM_get_auth_level(const X509_VERIFY_PARAM *param);
int X509_VERIFY_PARAM_add0_table(X509_VERIFY_PARAM *param);
int X509_VERIFY_PARAM_get_count(void);
void X509_VERIFY_PARAM_table_cleanup(void);
void X509_policy_tree_free(X509_POLICY_TREE *tree);
int X509_policy_tree_level_count(const X509_POLICY_TREE *tree);
int X509_policy_level_node_count(X509_POLICY_LEVEL *level);
