#include "specfunc.h"
#include "sqlite3-types.h"

#define SQLITE "SQLITE"

#define SQLITE_OK 0
#define SQLITE_NOMEM 7
#define SQLITE_STATIC      ((sqlite3_destructor_type)0)
#define SQLITE_TRANSIENT   ((sqlite3_destructor_type)-1)

typedef __builtin_va_list va_list;

#define SF_DEREF_READ(ptr) { unsigned char tmp = *(unsigned char *)(ptr); tmp++; }
#define SF_CHECKED_DEREF_READ(ptr) if (ptr) SF_DEREF_READ(ptr)

#define SF_DEREF_WRITE(ptr) { *(unsigned char *)(ptr) = (unsigned char)sf_get_some_int(); }
#define SF_CHECKED_DEREF_WRITE(ptr) if (ptr) { *(unsigned char *)(ptr) = (unsigned char)sf_get_some_int(); }

#define SF_DEFINE_GET_SOME_X(NAMESUFFIX,TYPENAME) \
static TYPENAME sf_get_some_## NAMESUFFIX (void) { \
    TYPENAME res; \
    sf_overwrite(&res); \
    return res; \
}

#define SF_DEFINE_GET_SOME(TYPENAME) SF_DEFINE_GET_SOME_X(TYPENAME, TYPENAME)

SF_DEFINE_GET_SOME(unsigned)
SF_DEFINE_GET_SOME(double)
SF_DEFINE_GET_SOME_X(int64, sqlite3_int64)

#define SF_DEFINE_GET_TAINTED_X(NAMESUFFIX,TYPENAME) \
static TYPENAME sf_get_tainted_## NAMESUFFIX (void) { \
    TYPENAME res = sf_get_some_## NAMESUFFIX(); \
    sf_set_tainted_int((TYPENAME)res); \
    return res; \
}

#define SF_DEFINE_GET_TAINTED(TYPENAME) SF_DEFINE_GET_TAINTED_X(TYPENAME, TYPENAME)

SF_DEFINE_GET_TAINTED(int)
SF_DEFINE_GET_TAINTED(double)
SF_DEFINE_GET_TAINTED_X(int64, sqlite3_int64)

#define __SQLITE_DB_R_ACCESS(DB) \
    sf_must_not_be_release(DB); \
    SF_DEREF_READ(DB)

#define __SQLITE_DB_RW_ACCESS(DB) \
    __SQLITE_DB_R_ACCESS(DB); \
    SF_DEREF_WRITE(DB)

#define __SQLITE_ACQUIRE(TYPE,VARIABLE,RETCODE,CATEGORY) \
    int RETCODE = sf_get_some_int_to_check(); \
    { \
        TYPE *result; \
        sf_overwrite(&result); \
        sf_overwrite(result); \
        sf_uncontrolled_value((int)(long long int)result); \
        sf_uncontrolled_ptr(result); \
        if (RETCODE != SQLITE_OK) { \
            sf_set_possible_null(result); \
        } \
        sf_handle_acquire(result, CATEGORY); \
        sf_not_acquire_if_eq(result, (int)(long long int)result, 0); \
        sf_not_acquire_if_less(result, RETCODE, SQLITE_OK); \
        sf_not_acquire_if_greater(result, RETCODE, SQLITE_OK); \
        *(VARIABLE) = result; \
    }

#define __SQLITE_RELEASE_IMPLEMENTATION(VARIABLE,CATEGORY) \
    /*if (! VARIABLE) {*/ \
    /*    return SQLITE_OK;*/ \
    /*}*/ \
    \
    sf_must_not_be_release(VARIABLE); \
    sf_handle_release(VARIABLE, CATEGORY); \
    /*sf_overwrite(VARIABLE); /* ? */ \
    \
    int ret = sf_get_some_int_to_check();\
    sf_func_success_if(ret, SQLITE_OK);\
    return ret;

#define __SQLITE_RETURN_RETCODE_AND_SET_ERROR_MESSAGE_VAR(ERROR_MESSAGE_VAR) \
    int rc = sf_get_some_int(); \
    if (ERROR_MESSAGE_VAR) { \
        if (rc != SQLITE_OK) { \
            *(ERROR_MESSAGE_VAR) = __alloc_some_string(); \
        } else { \
            *(ERROR_MESSAGE_VAR) = 0; \
        } \
    } \
    sf_must_be_checked(rc); \
    return rc;



static int sf_get_values(int min, int max) {
    int res = sf_get_some_int();
    sf_set_values(res, min, max);
    return res;
}

static int sf_get_bool(void) {
    return sf_get_values(0, 1);
}

static int sf_get_values_with_min(int min) {
    //int res = sf_get_values(min, sf_get_some_int()); // will this work?
    int res = sf_get_some_int();
    sf_assert_cond(res, ">=", min);
    return res;
}

static int sf_get_values_with_max(int max) {
    //int res = sf_get_values(sf_get_some_int(), max); // will this work?
    int res = sf_get_some_int();
    sf_assert_cond(res, "<=", max);
    return res;
}

static int sf_get_some_nonnegative_int(void) {
    int res = sf_get_some_int();
    sf_assert_cond(res, ">=", 0);
    return res;
}

static int sf_get_some_int_to_check(void) {
    int res = sf_get_some_int();
    sf_must_be_checked(res);
    return res;
}

static void *sf_get_uncontrolled_ptr(void) {
    void *res;
    sf_overwrite(&res);
    sf_uncontrolled_ptr(res);
    return res;
}

// below is a workaround for NEGATIVE_CODE_ERROR.EX which uses 'sf_set_trusted_sink_int'
static void sf_set_trusted_sink_nonnegative_int(int n) {
    if (n >= 0) {
        sf_set_trusted_sink_int(n);
    }
}

static char *__alloc_some_string(void) {
    char *res = (char *)sf_get_uncontrolled_ptr();
    sf_new(res, SQLITE3_MALLOC_CATEGORY);
    sf_set_alloc_possible_null(res);
    sf_null_terminated(res); // ?
    sf_strdup_res(res); // ?
    return res;
}

static void *__get_nonfreeable(void) {
    void *res = sf_get_uncontrolled_ptr();
    sf_new(res, SQLITE3_NONFREEABLE_CATEGORY);
    sf_escape(res);
    return res;
}

static void *__get_nonfreeable_tainted(void) {
    void *res = __get_nonfreeable();
    sf_set_tainted(res);
    return res;
}

static void *__get_nonfreeable_possible_null(void) {
    void *res = __get_nonfreeable();
    //sf_set_alloc_possible_null(res); // ?
    sf_set_possible_null(res);
    return res;
}

static void *__get_nonfreeable_tainted_possible_null(void) {
    void *res = __get_nonfreeable_tainted();
    //sf_set_alloc_possible_null(res); // ?
    sf_set_possible_null(res);
    return res;
}

static void *__get_nonfreeable_not_null(void) {
    void *res = __get_nonfreeable();
    sf_not_null(res);
    return res;
}

static char *__get_nonfreeable_string(void) {
    char *res = (char *)__get_nonfreeable();
    sf_null_terminated(res); // ?
    sf_strdup_res(res); // ?
    return res;
}

static char *__get_nonfreeable_possible_null_string(void) {
    char *res = (char *)__get_nonfreeable_possible_null();
    sf_null_terminated(res); // ?
    sf_strdup_res(res); // ?
    return res;
}

static char *__get_nonfreeable_not_null_string(void) {
    char *res = (char *)__get_nonfreeable_not_null();
    sf_null_terminated(res); // ?
    sf_strdup_res(res); // ?
    return res;
}

static char *__get_nonfreeable_tainted_possible_null_string(void) {
    char *res = (char *)__get_nonfreeable_tainted_possible_null();
    sf_null_terminated(res); // ?
    sf_strdup_res(res); // ?
    return res;
}

const char *sqlite3_libversion(void) {
    return __get_nonfreeable_not_null_string();
}

const char *sqlite3_sourceid(void) {
    return __get_nonfreeable_not_null_string();
}

int sqlite3_libversion_number(void) {
    int res = sf_get_some_int();
    sf_pure(res);
    //sf_assert_cond(res, ">=", 0); // ?
    return res;
}

int sqlite3_compileoption_used(const char *zOptName) {
    SF_DEREF_READ(zOptName);
    sf_buf_stop_at_null(zOptName);
    return sf_get_bool();
}

const char *sqlite3_compileoption_get(int N) {
    return __get_nonfreeable_possible_null_string();
}

int sqlite3_threadsafe(void) {
    //return SQLITE_THREADSAFE;
    // Quote: "The SQLITE_THREADSAFE macro must be defined as 0, 1, or 2."
    return sf_get_values(0, 2);
}

static int __close(sqlite3 *db) {
    __SQLITE_RELEASE_IMPLEMENTATION(db, SQLITE3_DB_CATEGORY)
}

int sqlite3_close(sqlite3 *db) {
    return __close(db);
}

int sqlite3_close_v2(sqlite3 *db) {
    return __close(db);
}


int sqlite3_exec(
    sqlite3 *db,                                /* An open database */
    const char *zSql,                           /* SQL to be evaluated */
    int (*xCallback)(void*,int,char**,char**),  /* Callback function */
    void *pArg,                                 /* 1st argument to callback */
    char **pzErrMsg                             /* Error msg written here */
)
{
    sf_vulnerable_fun_type("Use parameterized query with sqlite3_prepare, directly use of sqlite3_exec() is not allowed", SQLITE);
    __SQLITE_DB_RW_ACCESS(db);

    sf_set_trusted_sink_ptr(zSql);
    SF_CHECKED_DEREF_READ(zSql);
    sf_buf_stop_at_null(zSql);

    sf_escape(xCallback);

    __SQLITE_RETURN_RETCODE_AND_SET_ERROR_MESSAGE_VAR(pzErrMsg);
}


int sqlite3_initialize(void) {
    return sf_get_some_int_to_check();
}

int sqlite3_shutdown(void) {
    return sf_get_some_int_to_check();
}

int sqlite3_os_init(void) {
    sf_vulnerable_fun_type("The application should never invoke either sqlite3_os_init() or sqlite3_os_end() directly. The application should only invoke sqlite3_initialize() and sqlite3_shutdown()", SQLITE);
    return sf_get_some_int_to_check();
}

int sqlite3_os_end(void) {
    sf_vulnerable_fun_type("The application should never invoke either sqlite3_os_init() or sqlite3_os_end() directly. The application should only invoke sqlite3_initialize() and sqlite3_shutdown()", SQLITE);
    return sf_get_some_int_to_check();
}

int sqlite3_config(int stub, ...) {
    return sf_get_some_int_to_check();
}

int sqlite3_db_config(sqlite3 *db, int op, ...) {
    __SQLITE_DB_RW_ACCESS(db);
    return sf_get_some_int_to_check();
}


int sqlite3_extended_result_codes(sqlite3 *db, int onoff) {
    __SQLITE_DB_RW_ACCESS(db);
    return sf_get_some_int();
}

sqlite3_int64 sqlite3_last_insert_rowid(sqlite3 *db) {
    __SQLITE_DB_R_ACCESS(db);
    return sf_get_some_int64();
}

void sqlite3_set_last_insert_rowid(sqlite3 *db, sqlite3_int64 rowid) {
    __SQLITE_DB_RW_ACCESS(db);
}

int sqlite3_changes(sqlite3 *db) {
    __SQLITE_DB_R_ACCESS(db);
    return sf_get_some_int();
}

int sqlite3_total_changes(sqlite3 *db) {
    __SQLITE_DB_R_ACCESS(db);
    return sf_get_some_int();
}

void sqlite3_interrupt(sqlite3 *db) {
    __SQLITE_DB_RW_ACCESS(db); // ? in fact: w, and then r
}

static int __complete(const char *sql) {
    SF_DEREF_READ(sql);
    sf_buf_stop_at_null(sql);
    return sf_get_bool();
}

int sqlite3_complete(const char *sql) {
    return __complete(sql);
}

int sqlite3_complete16(const void *sql) {
    return __complete(sql);
}

int sqlite3_busy_handler(
    sqlite3 *db,
    int (*xBusy)(void*,int),
    void *pArg
) {
    __SQLITE_DB_RW_ACCESS(db);
    sf_escape(xBusy); // ?
    // sf_escape(pArg); // ?
    return sf_get_some_int();
}

int sqlite3_busy_timeout(sqlite3 *db, int ms) {
    __SQLITE_DB_RW_ACCESS(db);
    return sf_get_some_int();
}


int sqlite3_get_table(
    sqlite3 *db,          /* An open database */
    const char *zSql,     /* SQL to be evaluated */
    char ***pazResult,    /* Results of the query */
    int *pnRow,           /* Number of result rows written here */
    int *pnColumn,        /* Number of result columns written here */
    char **pzErrMsg       /* Error msg written here */
) {
    sf_vulnerable_fun_type("sqlite3_get_table is a legacy interface that is preserved for backwards compatibility, use of this interface is not recommended", SQLITE);

    __SQLITE_DB_RW_ACCESS(db);

    sf_set_trusted_sink_ptr(zSql);
    sf_buf_stop_at_null(zSql);

    int nrow = sf_get_some_int();
    int ncolumn = sf_get_some_int();

    char **res;

    sf_overwrite(&res);
    sf_overwrite(res); // ?
    sf_uncontrolled_ptr(res);

    int err = SQLITE_OK;
    sf_new(res, SQLITE3_TABLE_CATEGORY);
    sf_set_possible_null(res);
    if (res == NULL) {
        err = SQLITE_NOMEM;
    }
    sf_not_acquire_if_eq(res, err, SQLITE_NOMEM);
    //sf_set_alloc_possible_null(res);
    sf_set_buf_size(res, (nrow + 1) * (ncolumn + 1));

    if (pnRow) {
        *pnRow = nrow;
    }

    if (pnColumn) {
        *pnColumn = ncolumn;
    }

    if (err == SQLITE_OK)
        *pazResult = res; // call with NULL pazResult is not correct

    if (pzErrMsg) {
        if (err != SQLITE_OK) {
            *pzErrMsg = __alloc_some_string();
        } else {
            *pzErrMsg = 0;
        }
    }

    sf_must_be_checked(err);
    return err;
}

void sqlite3_free_table(char **result) {
    sf_vulnerable_fun_type("sqlite3_free_table is a legacy interface that is preserved for backwards compatibility, use of this interface is not recommended", SQLITE);
    sf_set_must_be_not_null(result, FREE_OF_NULL); // ?
    sf_overwrite(result); // ?
    sf_delete(result, SQLITE3_TABLE_CATEGORY);
}

static char *__mprintf(const char *zFormat) {
    sf_buf_stop_at_null(zFormat);
    sf_use_format(zFormat); // for tainted
    SF_DEREF_READ(zFormat);

    char *res;
    sf_overwrite(&res);
    sf_overwrite(res);
    sf_uncontrolled_ptr(res);
    sf_set_alloc_possible_null(res);
    sf_new(res, SQLITE3_MALLOC_CATEGORY);
    return res;
}

char *sqlite3_mprintf(const char *zFormat, ...) {
    //sf_fun_printf_like(0); // SQLite extends standard library formats with %q, %Q, %w, and %z
    sf_fun_does_not_update_vargs(1);
    return __mprintf(zFormat);
}

char *sqlite3_vmprintf(const char *zFormat, va_list ap) {
    return __mprintf(zFormat);
}

static char *__snprintf(int n, char *zBuf, const char *zFormat) {
    SF_DEREF_READ(zFormat);
    sf_buf_stop_at_null(zFormat);
    sf_use_format(zFormat); // for tainted

    sf_buf_size_limit(zBuf, n);
    SF_DEREF_WRITE(zBuf);
    sf_bitinit(zBuf);

    return zBuf;
}

char *sqlite3_snprintf(int n, char *zBuf, const char *zFormat, ...) {
    //sf_fun_printf_like(2); // SQLite extends standard library formats with %q, %Q, %w, and %z
    sf_fun_does_not_update_vargs(3);
    return __snprintf(n, zBuf, zFormat);
}

char *sqlite3_vsnprintf(int n, char *zBuf, const char *zFormat, va_list ap) {
    return __snprintf(n, zBuf, zFormat);
}

static void *__malloc(sqlite3_int64 size) {
    sf_set_trusted_sink_int(size);
    sf_malloc_arg(size);

    void *ptr;
    sf_overwrite(&ptr);
    sf_overwrite(ptr); // ?
    sf_uncontrolled_ptr(ptr);
    sf_set_alloc_possible_null(ptr, size);
    sf_new(ptr, SQLITE3_MALLOC_CATEGORY);
    sf_raw_new(ptr);
    sf_set_buf_size(ptr, size);
    return ptr;
}

void *sqlite3_malloc(int size) {
    return __malloc(size);
}

void *sqlite3_malloc64(sqlite3_uint64 size) {
    return __malloc(size);
}

static void *__realloc(void *ptr, sqlite3_uint64 size) {
    sf_escape(ptr);
    sf_set_trusted_sink_int(size);

    void *retptr;
    sf_overwrite(&retptr);
    sf_overwrite(retptr); // ?
    sf_uncontrolled_ptr(retptr);
    sf_set_alloc_possible_null(retptr, size);
    sf_new(retptr, SQLITE3_MALLOC_CATEGORY);
    sf_invalid_pointer(ptr, retptr);
    sf_set_buf_size(retptr, size);
    return retptr;
}


void *sqlite3_realloc(void *ptr, int size) {
    return __realloc(ptr, size);
}

void *sqlite3_realloc64(void *ptr, sqlite3_uint64 size) {
    return __realloc(ptr, size);
}

void sqlite3_free(void *ptr) {
    sf_set_must_be_not_null(ptr, FREE_OF_NULL); // ?
    sf_overwrite(ptr); // ?
    sf_delete(ptr, SQLITE3_MALLOC_CATEGORY);
}

sqlite3_uint64 sqlite3_msize(void *ptr) {
    if (! ptr) {
        return 0;
    }
    int size = sf_get_some_int();
    sf_set_buf_size(ptr, size);
    return size;
}

sqlite3_int64 sqlite3_memory_used(void) {
    return sf_get_some_nonnegative_int();
}

sqlite3_int64 sqlite3_memory_highwater(int resetFlag) {
    return sf_get_some_nonnegative_int();
}

void sqlite3_randomness(int N, void *P) {
    sf_buf_size_limit(P, N);
    sf_overwrite(P);
}

int sqlite3_set_authorizer(
    sqlite3 *db,
    int (*xAuth)(void*,int,const char*,const char*,const char*,const char*),
    void *pUserData
) {
    __SQLITE_DB_RW_ACCESS(db);
    sf_escape(xAuth);
    sf_escape(pUserData);
    return sf_get_some_int_to_check();
}


void *sqlite3_trace(
    sqlite3 *db,
    void (*xTrace)(void*,const char*),
    void *pArg
) {
    sf_vulnerable_fun_type("sqlite3_trace is deprecated, use the sqlite3_trace_v2() interface instead", SQLITE);
    __SQLITE_DB_RW_ACCESS(db);
    sf_escape(xTrace); // ?
    //sf_escape(pArg); // ?
    void *res = sf_get_uncontrolled_ptr();
    sf_set_possible_null(res);
    return res;
}

void *sqlite3_profile(
    sqlite3 *db,
    void (*xProfile)(void*,const char*,sqlite3_uint64),
    void *pArg
) {
    sf_vulnerable_fun_type("sqlite3_profile is deprecated, use the sqlite3_trace_v2() interface instead", SQLITE);
    __SQLITE_DB_RW_ACCESS(db);
    sf_escape(xProfile); // ?
    //sf_escape(pArg); // ?
    void *res = sf_get_uncontrolled_ptr();
    sf_set_possible_null(res);
    return res;
}

int sqlite3_trace_v2(
    sqlite3 *db,
    unsigned uMask,
    int(*xCallback)(unsigned,void*,void*,void*),
    void *pCtx
) {
    __SQLITE_DB_RW_ACCESS(db);
    sf_escape(xCallback);
    sf_escape(pCtx);
    int res = sf_get_some_int();
    return res;
}

void sqlite3_progress_handler(
    sqlite3 *db,
    int nOps,
    int (*xProgress)(void*),
    void *pArg
) {
    __SQLITE_DB_RW_ACCESS(db);
    sf_escape(xProgress); // ?
    //sf_escape(pArg); // ?
}

static int __sqlite3_open(
    const char *filename,
    sqlite3 **ppDb
) {
    sf_tocttou_access(filename);
    sf_set_trusted_sink_ptr(filename);
    sf_buf_stop_at_null(filename);


    SF_DEREF_WRITE(ppDb);

    __SQLITE_ACQUIRE(sqlite3, ppDb, rc, SQLITE3_DB_CATEGORY);

    return rc;
}


int sqlite3_open(
    const char *filename,
    sqlite3 **ppDb
) {
    return __sqlite3_open(filename, ppDb);
}

int sqlite3_open16(
    const void *filename,
    sqlite3 **ppDb
) {
    return __sqlite3_open(filename, ppDb);
}

int sqlite3_open_v2(
    const char *filename,
    sqlite3 **ppDb,
    int flags,
    const char *zVfs
) {
    sf_tocttou_access(zVfs);
    sf_set_trusted_sink_ptr(zVfs);
    sf_buf_stop_at_null(zVfs);
    return __sqlite3_open(filename, ppDb);
}

const char *sqlite3_uri_parameter(const char *zFilename, const char *zParam) {
    sf_buf_stop_at_null(zFilename);
    sf_buf_stop_at_null(zParam);
    return __get_nonfreeable_possible_null_string();
}

int sqlite3_uri_boolean(const char *zFilename, const char *zParam, int bDefault) {
    sf_buf_stop_at_null(zFilename);
    sf_buf_stop_at_null(zParam);
    return sf_get_bool();
}

sqlite3_int64 sqlite3_uri_int64(const char *zFilename, const char *zParam, sqlite3_int64 bDflt) {
    sf_buf_stop_at_null(zFilename);
    sf_buf_stop_at_null(zParam);
    int res = sf_get_some_int();
    sf_set_possible_negative(res);
    sf_uncontrolled_value(res);
    return res;
}

int sqlite3_errcode(sqlite3 *db) {
    SF_CHECKED_DEREF_READ(db); // or to treat as non-checked ?
//    return sf_get_some_int();
    return db->errCode;
}

int sqlite3_extended_errcode(sqlite3 *db) {
    SF_CHECKED_DEREF_READ(db); // or to treat as non-checked ?
//    return sf_get_some_int();
    return db->errCode;
}

const char *sqlite3_errmsg(sqlite3 *db) {
    SF_CHECKED_DEREF_READ(db); // or to treat as non-checked ?
    return __get_nonfreeable_not_null_string();
}

const void *sqlite3_errmsg16(sqlite3 *db) {
    SF_CHECKED_DEREF_READ(db); // or to treat as non-checked ?
    return __get_nonfreeable_not_null_string();
}

const char *sqlite3_errstr(int rc) {
    return __get_nonfreeable_not_null_string();
}


int sqlite3_limit(sqlite3 *db, int id, int newVal) {
    sf_set_trusted_sink_nonnegative_int(id);
    sf_set_trusted_sink_nonnegative_int(newVal);
    __SQLITE_DB_RW_ACCESS(db);
    return sf_get_some_int(); // non-negative
}

static int __prepare(
    sqlite3 *db,
    const char *zSql,
    int nByte,
    sqlite3_stmt **ppStmt,
    const char **pzTail
) {
    __SQLITE_DB_RW_ACCESS(db);

    sf_set_trusted_sink_ptr(zSql);
    if (nByte < 0) {
        sf_buf_stop_at_null(zSql);
    } else {
        sf_buf_size_limit_read(zSql, nByte);
    }
    SF_DEREF_READ(zSql);

    SF_DEREF_WRITE(ppStmt);

    __SQLITE_ACQUIRE(sqlite3_stmt, ppStmt, rc, SQLITE3_STMT_CATEGORY);
    db->errCode = rc;

    if (pzTail) {
//        sf_overwrite(&pzTail);
        sf_bitinit(pzTail);//pointed memory is initialized
    }

    return rc;
}

int sqlite3_prepare(
    sqlite3 *db,
    const char *zSql,
    int nByte,
    sqlite3_stmt **ppStmt,
    const char **pzTail
) {
    return __prepare(db, zSql, nByte, ppStmt, pzTail);
}

int sqlite3_prepare_v2(
    sqlite3 *db,
    const char *zSql,
    int nByte,
    sqlite3_stmt **ppStmt,
    const char **pzTail
) {
    return __prepare(db, zSql, nByte, ppStmt, pzTail);
}

int sqlite3_prepare_v3(
    sqlite3 *db,
    const char *zSql,
    int nByte,
    unsigned int prepFlags,
    sqlite3_stmt **ppStmt,
    const char **pzTail
) {
    return __prepare(db, zSql, nByte, ppStmt, pzTail);
}

int sqlite3_prepare16(
    sqlite3 *db,
    const void *zSql,
    int nByte,
    sqlite3_stmt **ppStmt,
    const void **pzTail
) {
    return __prepare(db, zSql, nByte, ppStmt, (const char **)pzTail);
}

int sqlite3_prepare16_v2(
    sqlite3 *db,
    const void *zSql,
    int nByte,
    sqlite3_stmt **ppStmt,
    const void **pzTail
) {
    return __prepare(db, zSql, nByte, ppStmt, (const char **)pzTail);
}

int sqlite3_prepare16_v3(
    sqlite3 *db,
    const void *zSql,
    int nByte,
    unsigned int prepFlags,
    sqlite3_stmt **ppStmt,
    const void **pzTail
) {
    return __prepare(db, zSql, nByte, ppStmt, (const char **)pzTail);
}

const char *sqlite3_sql(sqlite3_stmt *pStmt) {
    if (! pStmt) {
        return 0;
    }

    sf_must_not_be_release(pStmt);
    SF_DEREF_READ(pStmt);

    return __get_nonfreeable_not_null_string();
}

char *sqlite3_expanded_sql(sqlite3_stmt *pStmt) {
    if (! pStmt) {
        return 0;
    }

    sf_must_not_be_release(pStmt);
    SF_DEREF_READ(pStmt);

    return __alloc_some_string();
}


int sqlite3_stmt_readonly(sqlite3_stmt *pStmt) {
    if (! pStmt)
        return 1; // not a mistake: NULL statement will not modify database
    sf_must_not_be_release(pStmt);
    SF_DEREF_READ(pStmt);
    return sf_get_bool();
}

int sqlite3_stmt_busy(sqlite3_stmt *pStmt) {
    if (! pStmt)
        return 0;
    sf_must_not_be_release(pStmt);
    SF_DEREF_READ(pStmt);
    return sf_get_bool();
}

int sqlite3_bind_blob(
    sqlite3_stmt *pStmt,
    int i,
    const void *zData,
    int nData,
    void (*xDel)(void*)
) {
    sf_must_not_be_release(pStmt);
    SF_DEREF_WRITE(pStmt);
    // sf_set_trusted_sink_int(i); // ?
    // sf_set_trusted_sink_ptr(zData); // ?
    sf_set_must_be_positive(nData);
    sf_escape(xDel);
    if (xDel != SQLITE_STATIC && xDel != SQLITE_TRANSIENT) {
        sf_escape(zData);
    }
    return sf_get_some_int_to_check();
}

int sqlite3_bind_blob64(
    sqlite3_stmt *pStmt,
    int i,
    const void *zData,
    sqlite3_uint64 nData,
    void (*xDel)(void*)
){
    sf_must_not_be_release(pStmt);
    SF_DEREF_WRITE(pStmt);
    // sf_set_trusted_sink_int(i); // ?
    // sf_set_trusted_sink_ptr(zData); // ?
    sf_set_must_be_positive(nData);
    sf_escape(xDel);
    if (xDel != SQLITE_STATIC && xDel != SQLITE_TRANSIENT) {
        sf_escape(zData);
    }
    return sf_get_some_int_to_check();
}

int sqlite3_bind_double(sqlite3_stmt *pStmt, int i, double rValue) {
    sf_must_not_be_release(pStmt);
    SF_DEREF_WRITE(pStmt);
    return sf_get_some_int_to_check();
}

int sqlite3_bind_int(sqlite3_stmt *pStmt, int i, int iValue) {
    sf_must_not_be_release(pStmt);
    SF_DEREF_WRITE(pStmt);
    // sf_set_trusted_sink_int(i); // ?
    // sf_set_trusted_sink_int(iValue); // ?
    return sf_get_some_int_to_check();
}

int sqlite3_bind_int64(sqlite3_stmt *pStmt, int i, sqlite3_int64 iValue) {
    sf_must_not_be_release(pStmt);
    SF_DEREF_WRITE(pStmt);
    // sf_set_trusted_sink_int(i); // ?
    // sf_set_trusted_sink_int(iValue); // ?
    return sf_get_some_int_to_check();
}

int sqlite3_bind_null(sqlite3_stmt *pStmt, int i) {
    sf_must_not_be_release(pStmt);
    SF_DEREF_WRITE(pStmt);
    return sf_get_some_int_to_check();
}

static int __bind_text(
    sqlite3_stmt *pStmt,
    int i,
    const char *zData,
    int nData,
    void (*xDel)(void*)
) {
    sf_must_not_be_release(pStmt);
    SF_DEREF_WRITE(pStmt);

    // sf_set_trusted_sink_int(i); // ?

    // sf_set_trusted_sink_ptr(zData); // ?

    sf_buf_stop_at_null(zData);

    if (nData > 0) {
        sf_buf_size_limit_read(zData, nData);
    }

    sf_escape(xDel);

    if (xDel != SQLITE_STATIC && xDel != SQLITE_TRANSIENT) {
        sf_escape(zData);
    }

    return sf_get_some_int_to_check();
}

int sqlite3_bind_text(
    sqlite3_stmt *pStmt,
    int i,
    const char *zData,
    int nData,
    void (*xDel)(void*)
) {
    return __bind_text(pStmt, i, zData, nData, xDel);
}

int sqlite3_bind_text16(
    sqlite3_stmt *pStmt,
    int i,
    const char *zData,
    int nData,
    void (*xDel)(void*)
) {
    return __bind_text(pStmt, i, zData, nData, xDel);
}

int sqlite3_bind_text64(
    sqlite3_stmt *pStmt,
    int i,
    const char *zData,
    sqlite3_uint64 nData,
    void (*xDel)(void*),
    unsigned char enc
) {
    return __bind_text(pStmt, i, zData, nData, xDel);
}

int sqlite3_bind_value(sqlite3_stmt *pStmt, int i, const sqlite3_value *pValue) {
    sf_must_not_be_release(pStmt);
    SF_DEREF_WRITE(pStmt);
    // sf_set_trusted_sink_int(i); // ?
    SF_DEREF_READ(pValue);
    return sf_get_some_int_to_check();
}

int sqlite3_bind_pointer(
    sqlite3_stmt *pStmt,
    int i,
    void *pPtr,
    const char *zPTtype,
    void (*xDestructor)(void*)
) {
    sf_must_not_be_release(pStmt);
    SF_DEREF_WRITE(pStmt);

    // sf_set_trusted_sink_int(i); // ?

    // sf_set_trusted_sink_ptr(pPtr); // ?

    SF_CHECKED_DEREF_READ(pPtr);

    SF_CHECKED_DEREF_READ(zPTtype);
    sf_buf_stop_at_null(zPTtype);

    sf_escape(xDestructor); // ?

    if (xDestructor) {
        sf_escape(pPtr);
    }

    return sf_get_some_int_to_check();
}

static int __bind_zeroblob(sqlite3_stmt *pStmt, int i, sqlite3_uint64 n) {
    sf_must_not_be_release(pStmt);
    SF_DEREF_WRITE(pStmt);
    // sf_set_trusted_sink_int(i); // ?
    return sf_get_some_int_to_check();
}

int sqlite3_bind_zeroblob(sqlite3_stmt *pStmt, int i, int n) {
    return __bind_zeroblob(pStmt, i, n);
}

int sqlite3_bind_zeroblob64(sqlite3_stmt *pStmt, int i, sqlite3_uint64 n) {
    return __bind_zeroblob(pStmt, i, n);
}

int sqlite3_bind_parameter_count(sqlite3_stmt *pStmt) {
    sf_must_not_be_release(pStmt);
    SF_CHECKED_DEREF_READ(pStmt);

    int res;
    if (! pStmt) {
        res = 0;
    } else {
        res = sf_get_some_nonnegative_int();
    }
    return res;
}

const char *sqlite3_bind_parameter_name(sqlite3_stmt *pStmt, int i) {
    sf_must_not_be_release(pStmt);
    SF_CHECKED_DEREF_READ(pStmt);
    // sf_set_trusted_sink_int(i); // ?
    return __get_nonfreeable_possible_null_string();
}

int sqlite3_bind_parameter_index(sqlite3_stmt *pStmt, const char *zName) {
    sf_must_not_be_release(pStmt);
    SF_CHECKED_DEREF_READ(pStmt);

    int res;
    if (! pStmt || ! zName) {
        res = 0;
    } else {
        res = sf_get_some_nonnegative_int();
    }
    return res;
}

int sqlite3_clear_bindings(sqlite3_stmt *pStmt) {
    sf_must_not_be_release(pStmt);
    SF_DEREF_READ(pStmt);
    return sf_get_some_int(); // SQLITE_OK
}

int sqlite3_column_count(sqlite3_stmt *pStmt) {
    int res;
    if (! pStmt) {
        res = 0;
    } else {
        res = sf_get_some_nonnegative_int();
    }
    return res;
}

static const char *__column_name(sqlite3_stmt *pStmt, int N) {
    sf_must_not_be_release(pStmt);
    SF_DEREF_READ(pStmt);

    return __get_nonfreeable_possible_null_string();
}

const char *sqlite3_column_name(sqlite3_stmt *pStmt, int N) {
    return __column_name(pStmt, N);
}

const void *sqlite3_column_name16(sqlite3_stmt *pStmt, int N) {
    return __column_name(pStmt, N);
}

const char *sqlite3_column_database_name(sqlite3_stmt *pStmt, int N) {
    return __column_name(pStmt, N);
}

const void *sqlite3_column_database_name16(sqlite3_stmt *pStmt, int N) {
    return __column_name(pStmt, N);
}

const char *sqlite3_column_table_name(sqlite3_stmt *pStmt, int N) {
    return __column_name(pStmt, N);
}

const void *sqlite3_column_table_name16(sqlite3_stmt *pStmt, int N) {
    return __column_name(pStmt, N);
}

const char *sqlite3_column_origin_name(sqlite3_stmt *pStmt, int N) {
    return __column_name(pStmt, N);
}

const void *sqlite3_column_origin_name16(sqlite3_stmt *pStmt, int N) {
    return __column_name(pStmt, N);
}

const char *sqlite3_column_decltype(sqlite3_stmt *pStmt, int N) {
    return __column_name(pStmt, N);
}

const void *sqlite3_column_decltype16(sqlite3_stmt *pStmt, int N) {
    return __column_name(pStmt, N);
}

int sqlite3_step(sqlite3_stmt *pStmt) {
    //sf_long_time();

    sf_must_not_be_release(pStmt);
    //SF_DEREF_WRITE(pStmt); ?
    SF_DEREF_READ(pStmt);

    return sf_get_some_int_to_check();
}

int sqlite3_data_count(sqlite3_stmt *pStmt) {
    sf_must_not_be_release(pStmt);
    SF_DEREF_READ(pStmt);

    int res;
    if (! pStmt) {
        res = 0;
    } else {
        res = sf_get_some_nonnegative_int();
    }
    return res;
}

const void *sqlite3_column_blob(sqlite3_stmt *pStmt, int iCol) {
    sf_must_not_be_release(pStmt);
    SF_CHECKED_DEREF_READ(pStmt);

    return __get_nonfreeable_possible_null();
}

double sqlite3_column_double(sqlite3_stmt *pStmt, int iCol) {
    sf_must_not_be_release(pStmt);
    SF_CHECKED_DEREF_READ(pStmt);

    return sf_get_tainted_double();
}

int sqlite3_column_int(sqlite3_stmt *pStmt, int iCol) {
    sf_must_not_be_release(pStmt);
    SF_CHECKED_DEREF_READ(pStmt);

    return sf_get_tainted_int();
}

sqlite3_int64 sqlite3_column_int64(sqlite3_stmt *pStmt, int iCol) {
    sf_must_not_be_release(pStmt);
    SF_CHECKED_DEREF_READ(pStmt);

    return sf_get_tainted_int64();
}

const unsigned char *sqlite3_column_text(sqlite3_stmt *pStmt, int iCol) {
    sf_must_not_be_release(pStmt);
    SF_CHECKED_DEREF_READ(pStmt);

    return (const unsigned char *)__get_nonfreeable_tainted_possible_null_string();
}

const void *sqlite3_column_text16(sqlite3_stmt *pStmt, int iCol) {
    sf_must_not_be_release(pStmt);
    SF_CHECKED_DEREF_READ(pStmt);

    return __get_nonfreeable_tainted_possible_null_string();
}

sqlite3_value *sqlite3_column_value(sqlite3_stmt *pStmt, int iCol) {
    sf_must_not_be_release(pStmt);
    SF_CHECKED_DEREF_READ(pStmt);

    return (sqlite3_value *)__get_nonfreeable_possible_null();
}

int sqlite3_column_bytes(sqlite3_stmt *pStmt, int iCol) {
    sf_must_not_be_release(pStmt);
    SF_CHECKED_DEREF_READ(pStmt);

    return sf_get_some_nonnegative_int();
}

int sqlite3_column_bytes16(sqlite3_stmt *pStmt, int iCol) {
    sf_must_not_be_release(pStmt);
    SF_CHECKED_DEREF_READ(pStmt);

    return sf_get_some_nonnegative_int();
}

int sqlite3_column_type(sqlite3_stmt *pStmt, int iCol) {
    sf_must_not_be_release(pStmt);
    SF_CHECKED_DEREF_READ(pStmt);

    return sf_get_some_int();
}

int sqlite3_finalize(sqlite3_stmt *pStmt) {
    __SQLITE_RELEASE_IMPLEMENTATION(pStmt, SQLITE3_STMT_CATEGORY)
}


int sqlite3_reset(sqlite3_stmt *pStmt) {
    int res;
    if (! pStmt) {
        res = SQLITE_OK;
    } else {
        res = sf_get_some_int();
    }
    //sf_must_be_checked(res); // ?
    return res;
}

int __create_function(
    sqlite3 *db,
    const char *zFunctionName,
    int nArg,
    int eTextRep,
    void *pApp,
    void (*xFunc)(sqlite3_context*,int,sqlite3_value**),
    void (*xStep)(sqlite3_context*,int,sqlite3_value**),
    void (*xFinal)(sqlite3_context*),
    void(*xDestroy)(void*)
) {
    __SQLITE_DB_RW_ACCESS(db);

    sf_set_trusted_sink_ptr(zFunctionName);
    SF_DEREF_READ(zFunctionName); // return SQLITE_MISUSE_BKPT
    sf_buf_stop_at_null(zFunctionName);

    // Quote: "If the third parameter is less than -1 or greater than 127 then the behavior is undefined."
    int buf[129];
    sf_bitinit(buf); // just to avoid gcc "not used" warnings
    buf[nArg + 1] = 0;

    sf_escape(xFunc); // ?
    sf_escape(xStep); // ?
    sf_escape(xFinal); // ?
    sf_escape(xDestroy); // ?

    if (xDestroy) {
        sf_escape(pApp);
    }

    return sf_get_some_int_to_check();
}

int sqlite3_create_function(
    sqlite3 *db,
    const char *zFunctionName,
    int nArg,
    int eTextRep,
    void *pApp,
    void (*xFunc)(sqlite3_context*,int,sqlite3_value**),
    void (*xStep)(sqlite3_context*,int,sqlite3_value**),
    void (*xFinal)(sqlite3_context*)
) {
    return __create_function(db, zFunctionName, nArg, eTextRep, pApp, xFunc, xStep, xFinal, 0);
}

int sqlite3_create_function16(
    sqlite3 *db,
    const void *zFunctionName,
    int nArg,
    int eTextRep,
    void *pApp,
    void (*xFunc)(sqlite3_context*,int,sqlite3_value**),
    void (*xStep)(sqlite3_context*,int,sqlite3_value**),
    void (*xFinal)(sqlite3_context*)
) {
    return __create_function(db, zFunctionName, nArg, eTextRep, pApp, xFunc, xStep, xFinal, 0);
}

int sqlite3_create_function_v2(
    sqlite3 *db,
    const char *zFunctionName,
    int nArg,
    int eTextRep,
    void *pApp,
    void (*xFunc)(sqlite3_context*,int,sqlite3_value**),
    void (*xStep)(sqlite3_context*,int,sqlite3_value**),
    void (*xFinal)(sqlite3_context*),
    void(*xDestroy)(void*)
) {
    return __create_function(db, zFunctionName, nArg, eTextRep, pApp, xFunc, xStep, xFinal, xDestroy);
}

int sqlite3_aggregate_count(sqlite3_context *pCtx) {
    sf_vulnerable_fun_type("This function is deprecated. Do not use it for new code. It is provided only to avoid breaking legacy code. New aggregate function implementations should keep their own counts within their aggregate context.", SQLITE);

    SF_DEREF_READ(pCtx);

    return sf_get_some_int();
}

int sqlite3_expired(sqlite3_stmt *pStmt) {
    sf_must_not_be_release(pStmt);
    SF_CHECKED_DEREF_READ(pStmt);

    int res;
    if (! pStmt) {
        res = 0;
    } else {
        res = sf_get_bool();
    }
    return res;
}

int sqlite3_transfer_bindings(sqlite3_stmt *pFromStmt, sqlite3_stmt *pToStmt) {
    sf_vulnerable_fun_type("Deprecated external interface", SQLITE);

    sf_must_not_be_release(pFromStmt);
    SF_DEREF_READ(pFromStmt);

    sf_must_not_be_release(pToStmt);
    SF_DEREF_WRITE(pToStmt);

    return sf_get_some_int_to_check();
}

int sqlite3_global_recover(void) {
    sf_vulnerable_fun_type("This function is now an anachronism. It used to be used to recover from a malloc() failure, but SQLite now does this automatically.", SQLITE);
    return sf_get_some_int();
}

void sqlite3_thread_cleanup(void) {
    sf_vulnerable_fun_type("SQLite no longer uses thread-specific data so this routine is now a no-op.", SQLITE);
}

int sqlite3_memory_alarm(
    void(*xCallback)(void *pArg, sqlite3_int64 used,int N),
    void *pArg,
    sqlite3_int64 iThreshold
) {
    sf_vulnerable_fun_type("Deprecated external interface. Now it is a no-op.", SQLITE);
    return sf_get_some_int();
}

const void *sqlite3_value_blob(sqlite3_value *pVal) {
    sf_must_not_be_release(pVal);
    SF_DEREF_READ(pVal);
    return __get_nonfreeable_possible_null();
}

double sqlite3_value_double(sqlite3_value *pVal) {
    sf_must_not_be_release(pVal);
    SF_DEREF_READ(pVal);
    return sf_get_tainted_double();
}

int sqlite3_value_int(sqlite3_value *pVal) {
    sf_must_not_be_release(pVal);
    SF_DEREF_READ(pVal);
    return sf_get_tainted_int();
}

sqlite3_int64 sqlite3_value_int64(sqlite3_value *pVal) {
    sf_must_not_be_release(pVal);
    SF_DEREF_READ(pVal);
    return sf_get_tainted_int64();
}

void *sqlite3_value_pointer(sqlite3_value *pVal, const char *zPType) {
    sf_must_not_be_release(pVal);
    SF_DEREF_READ(pVal);
    return __get_nonfreeable_possible_null();
}

const unsigned char *sqlite3_value_text(sqlite3_value *pVal) {
    sf_must_not_be_release(pVal);
    SF_DEREF_READ(pVal);
    return (unsigned char *)__get_nonfreeable_tainted_possible_null_string();
}

const void *sqlite3_value_text16(sqlite3_value *pVal) {
    sf_must_not_be_release(pVal);
    SF_DEREF_READ(pVal);
    return __get_nonfreeable_tainted_possible_null_string();
}

const void *sqlite3_value_text16le(sqlite3_value *pVal) {
    sf_must_not_be_release(pVal);
    SF_DEREF_READ(pVal);
    return __get_nonfreeable_tainted_possible_null_string();
}

const void *sqlite3_value_text16be(sqlite3_value *pVal) {
    sf_must_not_be_release(pVal);
    SF_DEREF_READ(pVal);
    return __get_nonfreeable_tainted_possible_null_string();
}

int sqlite3_value_bytes(sqlite3_value *pVal) {
    sf_must_not_be_release(pVal);
    SF_DEREF_READ(pVal);
    return sf_get_some_nonnegative_int();
}

int sqlite3_value_bytes16(sqlite3_value *pVal) {
    sf_must_not_be_release(pVal);
    SF_DEREF_READ(pVal);
    return sf_get_some_nonnegative_int();
}

int sqlite3_value_type(sqlite3_value *pVal) {
    sf_must_not_be_release(pVal);
    SF_DEREF_READ(pVal);

    return sf_get_values(0, 5);
}

int sqlite3_value_numeric_type(sqlite3_value *pVal) {
    return sqlite3_value_type(pVal);
}

unsigned int sqlite3_value_subtype(sqlite3_value *pVal) {
    sf_must_not_be_release(pVal);
    SF_DEREF_READ(pVal);
    return sf_get_some_unsigned();
}


#define TREAT__value_dup__AS_MALLOC

sqlite3_value *sqlite3_value_dup(const sqlite3_value *pVal) {
    sqlite3_value *res;

    /*if (!pVal) {
        res = 0;
    } else */{
        sf_overwrite(&res);
        sf_uncontrolled_value((int)(long long int)res);
        sf_uncontrolled_ptr(res);
#ifdef TREAT__value_dup__AS_MALLOC
        sf_set_alloc_possible_null(res);
        sf_new(res, SQLITE3_VALUE_CATEGORY);
#else
        sf_handle_acquire(res, SQLITE3_VALUE_CATEGORY);
        sf_not_acquire_if_eq(res, (int)(long long int)res, 0);
#endif
    }
    return res;
}

void sqlite3_value_free(sqlite3_value *pVal) {
    sf_must_not_be_release(pVal);
#ifdef TREAT__value_dup__AS_MALLOC
    sf_delete(pVal, SQLITE3_VALUE_CATEGORY);
#else
    sf_handle_release(pVal, SQLITE3_VALUE_CATEGORY);
#endif
    sf_overwrite(pVal); // ?
}

void *sqlite3_aggregate_context(sqlite3_context *pCtx, int nBytes) {
    SF_DEREF_WRITE(pCtx);

    sf_set_trusted_sink_nonnegative_int(nBytes);
    sf_malloc_arg(nBytes);

    return __get_nonfreeable_possible_null();
}

void *sqlite3_user_data(sqlite3_context *pCtx) {
    SF_DEREF_READ(pCtx);

    return sf_get_uncontrolled_ptr();
}

sqlite3 *sqlite3_context_db_handle(sqlite3_context *pCtx) {
    SF_DEREF_READ(pCtx);

    sqlite3 *res = sf_get_uncontrolled_ptr();
    sf_not_null(res);
    return res;
}

void *sqlite3_get_auxdata(sqlite3_context *pCtx, int N) {
    SF_DEREF_READ(pCtx);

    sqlite3 *res = sf_get_uncontrolled_ptr();
    sf_set_possible_null(res);
    return res;
}

void sqlite3_set_auxdata(
    sqlite3_context *pCtx,
    int iArg,
    void *pAux,
    void (*xDelete)(void*)
) {
    SF_DEREF_WRITE(pCtx);

    sf_escape(xDelete); // ?

    if (xDelete) {
        sf_escape(pAux);
    }
}


void sqlite3_result_blob(
    sqlite3_context *pCtx,
    const void *z,
    int n,
    void (*xDel)(void *)
) {
    SF_DEREF_WRITE(pCtx);

    sf_set_must_be_positive(n+1); // assert(n>=0)

    sf_escape(xDel); // ?

    if (xDel != SQLITE_TRANSIENT) {
        sf_escape(z);
    }
}

void sqlite3_result_blob64(
    sqlite3_context *pCtx,
    const void *z,
    sqlite3_uint64 n,
    void (*xDel)(void *)
) {
    SF_DEREF_WRITE(pCtx);

    sf_escape(xDel); // ?

    if (xDel != SQLITE_TRANSIENT) {
        sf_escape(z);
    }
}

void sqlite3_result_double(sqlite3_context *pCtx, double rVal) {
    SF_DEREF_WRITE(pCtx);
}

static void __result_error(sqlite3_context *pCtx, const void *z, int n) {
    SF_DEREF_WRITE(pCtx);
    sf_buf_stop_at_null(z);
    SF_CHECKED_DEREF_READ(z);

    sf_set_trusted_sink_ptr(z);

    sf_set_trusted_sink_nonnegative_int(n);

    if (n > 0) {
        sf_buf_size_limit_read(z, n);
    }
}

void sqlite3_result_error(sqlite3_context *pCtx, const char *z, int n) {
    __result_error(pCtx, z, n);
}

void sqlite3_result_error16(sqlite3_context *pCtx, const void *z, int n) {
    __result_error(pCtx, z, n);
}

void sqlite3_result_error_toobig(sqlite3_context *pCtx) {
    SF_DEREF_WRITE(pCtx);
}

void sqlite3_result_error_nomem(sqlite3_context *pCtx) {
    SF_DEREF_WRITE(pCtx);
}

void sqlite3_result_error_code(sqlite3_context *pCtx, int errCode) {
    SF_DEREF_WRITE(pCtx);
}

void sqlite3_result_int(sqlite3_context *pCtx, int iVal) {
    SF_DEREF_WRITE(pCtx);
}

void sqlite3_result_int64(sqlite3_context *pCtx, sqlite3_int64 iVal) {
    SF_DEREF_WRITE(pCtx);
}

void sqlite3_result_null(sqlite3_context *pCtx) {
    SF_DEREF_WRITE(pCtx);
}

static void __result_text(
    sqlite3_context *pCtx,
    const char *z,
    int n,
    void (*xDel)(void *)
) {
    SF_DEREF_WRITE(pCtx);

    sf_buf_stop_at_null(z);
    SF_CHECKED_DEREF_READ(z);

    //sf_set_trusted_sink_ptr(z); // ?

    sf_set_trusted_sink_nonnegative_int(n);


    if (n > 0) {
        sf_buf_size_limit_read(z, n);
    }

    sf_escape(xDel); // ?

    if (xDel) {
        sf_escape(z);
    }
}

void sqlite3_result_text(
    sqlite3_context *pCtx,
    const char *z,
    int n,
    void (*xDel)(void *)
) {
    __result_text(pCtx, z, n, xDel);
}

void sqlite3_result_text64(
    sqlite3_context *pCtx,
    const char *z,
    sqlite3_uint64 n,
    void (*xDel)(void *)
) {
    __result_text(pCtx, z, n, xDel);
}

void sqlite3_result_text16(
    sqlite3_context *pCtx,
    const char *z,
    int n,
    void (*xDel)(void *)
) {
    __result_text(pCtx, z, n, xDel);
}

void sqlite3_result_text16le(
    sqlite3_context *pCtx,
    const char *z,
    int n,
    void (*xDel)(void *)
) {
    __result_text(pCtx, z, n, xDel);
}

void sqlite3_result_text16be(
    sqlite3_context *pCtx,
    const char *z,
    int n,
    void (*xDel)(void *)
) {
    __result_text(pCtx, z, n, xDel);
}

void sqlite3_result_value(sqlite3_context *pCtx, sqlite3_value *pValue) {
    SF_DEREF_WRITE(pCtx);
    SF_DEREF_READ(pValue);
}

void sqlite3_result_pointer(
    sqlite3_context *pCtx,
    void *pPtr,
    const char *zPType,
    void (*xDestructor)(void *)
) {
    SF_DEREF_WRITE(pCtx);

    sf_escape(xDestructor); // ?

    if (xDestructor) {
        sf_escape(pPtr);
    }

    sf_buf_stop_at_null(zPType);
    SF_CHECKED_DEREF_READ(zPType);
}


void sqlite3_result_zeroblob(sqlite3_context *pCtx, int n) {
    SF_DEREF_WRITE(pCtx);
}

int sqlite3_result_zeroblob64(sqlite3_context *pCtx, sqlite3_uint64 n) {
    SF_DEREF_WRITE(pCtx);

    return sf_get_some_int_to_check();
}

void sqlite3_result_subtype(sqlite3_context *pCtx, unsigned int eSubtype) {
    SF_DEREF_WRITE(pCtx);
}

static int __create_collation(
    sqlite3 *db,
    const char *zName,
    void *pArg,
    int(*xCompare)(void*,int,const void*,int,const void*),
    void(*xDestroy)(void*)
) {
    __SQLITE_DB_RW_ACCESS(db);

    sf_set_trusted_sink_ptr(zName);
    SF_DEREF_READ(zName); // ?
    sf_buf_stop_at_null(zName);

    // sf_set_must_be_not_null(xCompare, "???"); // ?

    sf_escape(xCompare); // ?
    sf_escape(xDestroy); // ?

    int rc = sf_get_some_int();

    // Quote from docs:
    // The xDestroy callback is not called if the sqlite3_create_collation_v2() function fails.
    // This is different from every other SQLite interface. The inconsistency is unfortunate but cannot be changed without breaking backwards compatibility.
    if (xDestroy) {
        if (rc == SQLITE_OK) {
            sf_escape(pArg);
        }
    }

    sf_must_be_checked(rc);

    return rc;
}

int sqlite3_create_collation(
    sqlite3 *db,
    const char *zName,
    int eTextRep,
    void *pArg,
    int(*xCompare)(void*,int,const void*,int,const void*)
) {
    return __create_collation(db, zName, pArg, xCompare, 0);
}

int sqlite3_create_collation_v2(
    sqlite3 *db,
    const char *zName,
    int eTextRep,
    void *pArg,
    int(*xCompare)(void*,int,const void*,int,const void*),
    void(*xDestroy)(void*)
) {
    return __create_collation(db, zName, pArg, xCompare, xDestroy);
}

int sqlite3_create_collation16(
    sqlite3 *db,
    const void *zName,
    int eTextRep,
    void *pArg,
    int(*xCompare)(void*,int,const void*,int,const void*)
) {
    return __create_collation(db, zName, pArg, xCompare, 0);
}

int sqlite3_collation_needed(
    sqlite3 *db,
    void *pCollNeededArg,
    void(*xCollNeeded)(void*,sqlite3*,int eTextRep,const char*)
) {
    __SQLITE_DB_RW_ACCESS(db);
    return sf_get_some_int();
}

int sqlite3_collation_needed16(
    sqlite3 *db,
    void *pCollNeededArg,
    void(*xCollNeeded16)(void*,sqlite3*,int eTextRep,const void*)
) {
    __SQLITE_DB_RW_ACCESS(db);
    return sf_get_some_int();
}

int sqlite3_sleep(int ms) {
    sf_long_time();
    return sf_get_some_int();
}

int sqlite3_get_autocommit(sqlite3 *db) {
    __SQLITE_DB_R_ACCESS(db);
    return sf_get_bool();
}

sqlite3 *sqlite3_db_handle(sqlite3_stmt *pStmt) {
    sf_must_not_be_release(pStmt);
    SF_CHECKED_DEREF_READ(pStmt);
    sqlite3 *res;
    if (! pStmt) {
        res = 0;
    } else {
        res = sf_get_uncontrolled_ptr();
        sf_not_null(res);
    }
    return res;
}

const char *sqlite3_db_filename(sqlite3 *db, const char *zDbName) {
    __SQLITE_DB_R_ACCESS(db);

    sf_set_trusted_sink_ptr(zDbName);
    sf_buf_stop_at_null(zDbName);
    SF_CHECKED_DEREF_READ(zDbName);

    return __get_nonfreeable_possible_null_string();
}

int sqlite3_db_readonly(sqlite3 *db, const char *zDbName) {
    __SQLITE_DB_R_ACCESS(db);

    sf_buf_stop_at_null(zDbName);
    SF_CHECKED_DEREF_READ(zDbName);

    return sf_get_values(-1, +1);
}

sqlite3_stmt *sqlite3_next_stmt(sqlite3 *db, sqlite3_stmt *pStmt) {
    __SQLITE_DB_R_ACCESS(db);

    SF_CHECKED_DEREF_READ(pStmt);

    sqlite3_stmt *res = sf_get_uncontrolled_ptr();
    sf_set_possible_null(res);
    return res;
}

void *sqlite3_commit_hook(
    sqlite3 *db,              /* Attach the hook to this database */
    int (*xCallback)(void*),  /* Function to invoke on each commit */
    void *pArg                /* Argument to the function */
) {
    __SQLITE_DB_RW_ACCESS(db);

    sf_escape(xCallback); // ?
    //sf_escape(pArg); // ?

    return sf_get_uncontrolled_ptr();
}


void *sqlite3_rollback_hook(
    sqlite3 *db,              /* Attach the hook to this database */
    void (*xCallback)(void*), /* Callback function */
    void *pArg                /* Argument to the function */
) {
    __SQLITE_DB_RW_ACCESS(db);

    sf_escape(xCallback); // ?
    //sf_escape(pArg); // ?

    return sf_get_uncontrolled_ptr();
}

void *sqlite3_update_hook(
    sqlite3 *db,              /* Attach the hook to this database */
    void (*xCallback)(void*,int,char const *,char const *,sqlite_int64),
    void *pArg                /* Argument to the function */
) {
    __SQLITE_DB_RW_ACCESS(db);

    sf_escape(xCallback); // ?
    //sf_escape(pArg); // ?

    return sf_get_uncontrolled_ptr();
}

int sqlite3_enable_shared_cache(int enable) {
    return sf_get_some_int();
}

int sqlite3_release_memory(int n) {
    sf_set_trusted_sink_nonnegative_int(n);
    return sf_get_some_nonnegative_int();
}

int sqlite3_db_release_memory(sqlite3 *db) {
    __SQLITE_DB_RW_ACCESS(db);
    return sf_get_some_int();
}

sqlite3_int64 sqlite3_soft_heap_limit64(sqlite3_int64 n) {
    sf_set_trusted_sink_nonnegative_int(n);
    return sf_get_some_int64();
}

void sqlite3_soft_heap_limit(int n) {
    sf_set_trusted_sink_nonnegative_int(n);
}

int sqlite3_table_column_metadata(
    sqlite3 *db,                /* Connection handle */
    const char *zDbName,        /* Database name or NULL */
    const char *zTableName,     /* Table name */
    const char *zColumnName,    /* Column name */
    char const **pzDataType,    /* OUTPUT: Declared data type */
    char const **pzCollSeq,     /* OUTPUT: Collation sequence name */
    int *pNotNull,              /* OUTPUT: True if NOT NULL constraint exists */
    int *pPrimaryKey,           /* OUTPUT: True if column part of PK */
    int *pAutoinc               /* OUTPUT: True if column is auto-increment */
) {
    __SQLITE_DB_RW_ACCESS(db);

    sf_buf_stop_at_null(zDbName);
    SF_CHECKED_DEREF_READ(zDbName);

    sf_buf_stop_at_null(zTableName);
    SF_DEREF_READ(zTableName);

    sf_buf_stop_at_null(zColumnName);
    SF_CHECKED_DEREF_READ(zColumnName);

    if (pzDataType) *pzDataType = __get_nonfreeable_string(); // can it be null or not???
    if (pzCollSeq) *pzCollSeq = __get_nonfreeable_string(); // can it be null or not???
    if (pNotNull) *pNotNull = sf_get_bool();
    if (pPrimaryKey) *pPrimaryKey = sf_get_bool();
    if (pAutoinc) *pAutoinc = sf_get_bool();

    return sf_get_some_int_to_check();
}

int sqlite3_load_extension(
    sqlite3 *db,          /* Load the extension into this database connection */
    const char *zFile,    /* Name of the shared library containing extension */
    const char *zProc,    /* Entry point.  Use "sqlite3_extension_init" if 0 */
    char **pzErrMsg       /* Put error message here if not 0 */
) {
    __SQLITE_DB_RW_ACCESS(db);

    sf_set_trusted_sink_ptr(zFile);
    sf_buf_stop_at_null(zFile);
    SF_DEREF_READ(zFile);

    sf_set_trusted_sink_ptr(zProc);
    sf_buf_stop_at_null(zProc);
    SF_CHECKED_DEREF_READ(zProc);

    __SQLITE_RETURN_RETCODE_AND_SET_ERROR_MESSAGE_VAR(pzErrMsg);
}


int sqlite3_enable_load_extension(sqlite3 *db, int onoff) {
    __SQLITE_DB_RW_ACCESS(db);
    sf_set_trusted_sink_nonnegative_int(onoff);
    return sf_get_some_int();
}

int sqlite3_auto_extension(void(*xEntryPoint)(void)) {
    // sf_set_must_be_not_null(xEntryPoint, "???"); // ?
    sf_escape(xEntryPoint); // ?
    return sf_get_some_int_to_check();
}

int sqlite3_cancel_auto_extension(void(*xEntryPoint)(void)) {
    // sf_set_must_be_not_null(xEntryPoint, "???"); // ?
    sf_escape(xEntryPoint); // ?
    return sf_get_bool(); // must be checked ???
}


void sqlite3_reset_auto_extension(void); // nothing to specify (?)

static int __create_module(
    sqlite3 *db,
    const char *zName,
    const sqlite3_module *pModule,
    void *pAux,
    void (*xDestroy)(void *)
) {
    __SQLITE_DB_RW_ACCESS(db);

    sf_buf_stop_at_null(zName);
    SF_DEREF_READ(zName);

    // sf_set_must_be_not_null(pModule, "???"); // ?
    SF_DEREF_READ(pModule); // ?

    sf_escape(xDestroy); // ?
    if (xDestroy) {
        sf_escape(pAux);
    }

    return sf_get_some_int_to_check();
}


int sqlite3_create_module(
    sqlite3 *db,                    /* Database in which module is registered */
    const char *zName,              /* Name assigned to this module */
    const sqlite3_module *pModule,  /* The definition of the module */
    void *pAux                      /* Context pointer for xCreate/xConnect */
) {
    return __create_module(db, zName, pModule, pAux, 0);
}


int sqlite3_create_module_v2(
    sqlite3 *db,                    /* Database in which module is registered */
    const char *zName,              /* Name assigned to this module */
    const sqlite3_module *pModule,  /* The definition of the module */
    void *pAux,                     /* Context pointer for xCreate/xConnect */
    void (*xDestroy)(void *)        /* Module destructor function */
) {
    return __create_module(db, zName, pModule, pAux, xDestroy);
}


int sqlite3_declare_vtab(sqlite3 *db, const char *zSQL) {
    __SQLITE_DB_RW_ACCESS(db);

    sf_buf_stop_at_null(zSQL);
    sf_set_trusted_sink_ptr(zSQL);
    SF_DEREF_READ(zSQL);

    return sf_get_some_int_to_check();
}

int sqlite3_overload_function(sqlite3 *db, const char *zFuncName, int nArg) {
    __SQLITE_DB_RW_ACCESS(db);

    sf_buf_stop_at_null(zFuncName);
    sf_set_trusted_sink_ptr(zFuncName);
    SF_DEREF_READ(zFuncName);

    sf_set_must_be_positive(nArg + 2); // misuse if nArg<-2 - from implementation(?)

    return sf_get_some_int_to_check();
}


int sqlite3_blob_open(
    sqlite3 *db,
    const char *zDb,
    const char *zTable,
    const char *zColumn,
    sqlite3_int64 iRow,
    int flags,
    sqlite3_blob **ppBlob
) {
    __SQLITE_DB_RW_ACCESS(db);

    SF_CHECKED_DEREF_READ(zDb);
    sf_buf_stop_at_null(zDb);

    SF_CHECKED_DEREF_READ(zTable);
    sf_buf_stop_at_null(zTable);

    SF_CHECKED_DEREF_READ(zColumn);
    sf_buf_stop_at_null(zColumn);

    __SQLITE_ACQUIRE(sqlite3_blob, ppBlob, rc, SQLITE3_BLOB_CATEGORY);

    return rc;
}

int sqlite3_blob_reopen(sqlite3_blob *pBlob, sqlite3_int64 iRow) {
    sf_must_not_be_release(pBlob);
    SF_CHECKED_DEREF_WRITE(pBlob); // ?

    return sf_get_some_int_to_check();
}

int sqlite3_blob_close(sqlite3_blob *pBlob) {
    __SQLITE_RELEASE_IMPLEMENTATION(pBlob, SQLITE3_BLOB_CATEGORY)
}

int sqlite3_blob_bytes(sqlite3_blob *pBlob) {
    sf_must_not_be_release(pBlob);
    SF_CHECKED_DEREF_WRITE(pBlob);
    return sf_get_some_nonnegative_int();
}

int sqlite3_blob_read(sqlite3_blob *pBlob, void *z, int n, int iOffset) {
    sf_must_not_be_release(pBlob);
    SF_CHECKED_DEREF_WRITE(pBlob); // ?

    // sf_set_trusted_sink_int(n);
    // sf_set_trusted_sink_int(iOffset);

    SF_DEREF_WRITE(z);
    sf_overwrite(z);
    sf_bitinit(z);
    sf_buf_size_limit(z, n);
    sf_set_tainted(z);

    int res = sf_get_some_int_to_check();
    sf_buf_fill(res, z);
    sf_assert_cond(res, "<=", n);
    return res;
}

int sqlite3_blob_write(sqlite3_blob *pBlob, const void *z, int n, int iOffset) {
    sf_must_not_be_release(pBlob);
    SF_CHECKED_DEREF_WRITE(pBlob); // ?

    // sf_set_trusted_sink_int(n);
    // sf_set_trusted_sink_int(iOffset);

    SF_DEREF_READ(z);
    sf_use(z);
    sf_buf_size_limit_read(z, n);

    int res = sf_get_some_int_to_check();
    sf_assert_cond(res, "<=", n);
    return res;
}

sqlite3_vfs *sqlite3_vfs_find(const char *zVfsName) {
    sf_set_trusted_sink_ptr(zVfsName);
    SF_CHECKED_DEREF_READ(zVfsName);
    sf_buf_stop_at_null(zVfsName);
    return __get_nonfreeable_possible_null();
}

int sqlite3_vfs_register(sqlite3_vfs *pVfs, int makeDflt) {
    SF_DEREF_WRITE(pVfs);
    return sf_get_some_int_to_check();
}

int sqlite3_vfs_unregister(sqlite3_vfs *pVfs) {
    SF_DEREF_WRITE(pVfs);
    return sf_get_some_int_to_check();
}

sqlite3_mutex *sqlite3_mutex_alloc(int id) {
    sqlite3_mutex *res = sf_get_uncontrolled_ptr();
    sf_set_possible_null(res);
    //sf_set_alloc_possible_null(res);
    sf_new(res, SQLITE3_MUTEX_CATEGORY);
    return res;
}

void sqlite3_mutex_free(sqlite3_mutex *p) {
    // sf_set_must_be_not_null(ptr, FREE_OF_NULL); // ?
    sf_must_not_be_release(p);
    sf_overwrite(p); // ?
    sf_delete(p, SQLITE3_MUTEX_CATEGORY);
}

void sqlite3_mutex_enter(sqlite3_mutex *p) {
    sf_must_not_be_release(p);
    //if (p) // ?
        sf_lock(p);
}

int sqlite3_mutex_try(sqlite3_mutex *p) {
    sf_must_not_be_release(p);
    //if (p) // ?
        sf_trylock(p);

    int res;
    sf_overwrite(&res);
    sf_success_lock_if_zero(res, p);
    return res;
}

void sqlite3_mutex_leave(sqlite3_mutex *p) {
    sf_must_not_be_release(p);
    //if (p) // ?
        sf_unlock(p);
}

int sqlite3_mutex_held(sqlite3_mutex *p) {
    sf_must_not_be_release(p);
    return !p || sf_get_bool();
}

int sqlite3_mutex_notheld(sqlite3_mutex *p) {
    sf_must_not_be_release(p);
    return !p || sf_get_bool();
}

sqlite3_mutex *sqlite3_db_mutex(sqlite3 *db) {
    __SQLITE_DB_R_ACCESS(db);
    return __get_nonfreeable();
}

int sqlite3_file_control(sqlite3 *db, const char *zDbName, int op, void *pArg) {
    __SQLITE_DB_R_ACCESS(db);

    sf_set_trusted_sink_ptr(zDbName); // ?
    sf_buf_stop_at_null(zDbName);
    SF_CHECKED_DEREF_READ(zDbName);

    SF_DEREF_WRITE(pArg);

    return sf_get_some_int_to_check();
}

int sqlite3_test_control(int op, ...); // nothing to specify (?)

int sqlite3_status64(
    int op,
    sqlite3_int64 *pCurrent,
    sqlite3_int64 *pHighwater,
    int resetFlag
) {
    if (sf_get_some_int()) {
        SF_DEREF_READ(pCurrent);
        sf_overwrite(pCurrent);
    }
    if (sf_get_some_int()) {
        SF_DEREF_READ(pHighwater);
        sf_overwrite(pHighwater);
    }
    return sf_get_some_int_to_check();
}

int sqlite3_status(int op, int *pCurrent, int *pHighwater, int resetFlag) {
    sqlite3_int64 *pCurrent64 = (sqlite3_int64 *)pCurrent;
    sqlite3_int64 *pHighwater64 = (sqlite3_int64 *)pHighwater;
    return sqlite3_status64(op, pCurrent64, pHighwater64, resetFlag);
}

int sqlite3_db_status(
    sqlite3 *db,          /* The database connection whose status is desired */
    int op,               /* Status verb */
    int *pCurrent,        /* Write current value here */
    int *pHighwater,      /* Write high-water mark here */
    int resetFlag         /* Reset high-water mark if true */
) {
    __SQLITE_DB_R_ACCESS(db);

    SF_DEREF_WRITE(pCurrent);
    SF_DEREF_WRITE(pHighwater);

    return sf_get_some_int_to_check();
}


int sqlite3_stmt_status(sqlite3_stmt *pStmt, int op, int resetFlg) {
    SF_DEREF_WRITE(pStmt);
    return sf_get_some_int();
}


sqlite3_backup *sqlite3_backup_init(
    sqlite3 *pDest,
    const char *zDestName,
    sqlite3 *pSource,
    const char *zSourceName
) {
    sf_must_not_be_release(pSource);
    SF_DEREF_READ(pSource);

    sf_must_not_be_release(pDest);
    SF_DEREF_WRITE(pDest);

    sf_set_trusted_sink_ptr(zSourceName);
    sf_buf_stop_at_null(zSourceName);
    SF_DEREF_READ(zSourceName); // or checked deref ?

    sf_set_trusted_sink_ptr(zDestName);
    sf_buf_stop_at_null(zDestName);
    SF_DEREF_READ(zDestName); // or checked deref?

    sqlite3_backup *res = sf_get_uncontrolled_ptr();
    sf_set_possible_null(res);
    //sf_set_alloc_possible_null(res);
    sf_new(res, SQLITE3_BACKUP_CATEGORY);

    return res;
}

int sqlite3_backup_step(sqlite3_backup *p, int nPage) {
    sf_must_not_be_release(p);
    SF_DEREF_WRITE(p);
    return sf_get_some_int_to_check();
}

int sqlite3_backup_finish(sqlite3_backup *p) {
    if (!p) {
        return SQLITE_OK;
    }
    sf_must_not_be_release(p);
    sf_overwrite(p); // ?
    sf_delete(p, SQLITE3_BACKUP_CATEGORY);
    return sf_get_some_int_to_check();
}

int sqlite3_backup_remaining(sqlite3_backup *p) {
    sf_must_not_be_release(p);
    SF_DEREF_READ(p);
    return sf_get_some_nonnegative_int();
}

int sqlite3_backup_pagecount(sqlite3_backup *p) {
    sf_must_not_be_release(p);
    SF_DEREF_READ(p);
    return sf_get_some_nonnegative_int();
}

int sqlite3_unlock_notify(
    sqlite3 *db,                          /* Waiting connection */
    void (*xNotify)(void **apArg, int nArg),    /* Callback function to invoke */
    void *pArg                                  /* Argument to pass to xNotify */
) {
    __SQLITE_DB_RW_ACCESS(db);

    sf_escape(xNotify); // ?
    //sf_escape(pNotifyArg) // ?

    return sf_get_some_int_to_check();
}


static int __xxx_strcmp(const char *z1, const char *z2) {
    sf_sanitize(z1);
    SF_CHECKED_DEREF_READ(z1);

    sf_sanitize(z2);
    SF_CHECKED_DEREF_READ(z2);

    int res;
    if (z1 == 0) {
        if (z2 == 0) {
           res = 0;
        } else {
           res = -1;
        }
    } else if (z2 == 0) {
        res = 1;
    } else if (*z1 == '\0') {
        if (*z2 == '\0') {
           res = 0;
        } else {
            res = sf_get_values_with_max(-1);
        }
    } else if (*z2 == '\0') {
        res = sf_get_values_with_min(1);
    } else {
        res = sf_get_some_int();
    }

    sf_must_be_checked(res); // ?

    return res;
}

int sqlite3_stricmp(const char *z1, const char *z2) {
    sf_buf_stop_at_null(z1);
    sf_buf_stop_at_null(z2);
    return __xxx_strcmp(z1, z2);
}

int sqlite3_strnicmp(const char *z1, const char *z2, int n) {
    return __xxx_strcmp(z1, z2);
}

int sqlite3_strglob(const char *zGlobPattern, const char *zString) {
    sf_set_trusted_sink_ptr(zGlobPattern);
    sf_buf_stop_at_null(zGlobPattern);
    SF_DEREF_READ(zGlobPattern);

    sf_sanitize(zString);
    sf_buf_stop_at_null(zString);
    SF_DEREF_READ(zString);

    return sf_get_some_int_to_check(); // ?
}

int sqlite3_strlike(const char *zPattern, const char *zStr, unsigned int esc) {
    sf_set_trusted_sink_ptr(zPattern);
    sf_buf_stop_at_null(zPattern);
    SF_DEREF_READ(zPattern);

    sf_sanitize(zStr);
    sf_buf_stop_at_null(zStr);
    SF_DEREF_READ(zStr);

    return sf_get_some_int_to_check(); // ?
}

void sqlite3_log(int iErrCode, const char *zFormat, ...) {
    sf_buf_stop_at_null(zFormat);
    sf_use_format(zFormat); // for tainted
    SF_DEREF_READ(zFormat);

    //sf_fun_printf_like(1); // SQLite extends standard library formats with %q, %Q, %w, and %z
    sf_fun_does_not_update_vargs(2);
}

void *sqlite3_wal_hook(
    sqlite3 *db,                    /* Attach the hook to this db handle */
    int(*xCallback)(void *, sqlite3*, const char*, int),
    void *pArg                      /* First argument passed to xCallback() */
) {
    __SQLITE_DB_RW_ACCESS(db);

    // sf_escape(xCallback); // ?
    // sf_escape(pArg); // ?

    void *res = sf_get_uncontrolled_ptr();
    sf_set_possible_null(res);
    return res;
}

int sqlite3_wal_autocheckpoint(sqlite3 *db, int N) {
    __SQLITE_DB_RW_ACCESS(db);
    return sf_get_some_int();
}

int sqlite3_wal_checkpoint(sqlite3 *db, const char *zDb) {
    __SQLITE_DB_RW_ACCESS(db);

    sf_set_trusted_sink_ptr(zDb);
    sf_buf_stop_at_null(zDb);
    SF_CHECKED_DEREF_READ(zDb);

    return sf_get_some_int_to_check();
}

int sqlite3_wal_checkpoint_v2(
    sqlite3 *db,                    /* Database handle */
    const char *zDb,                /* Name of attached database (or NULL) */
    int eMode,                      /* SQLITE_CHECKPOINT_* value */
    int *pnLog,                     /* OUT: Size of WAL log in frames */
    int *pnCkpt                     /* OUT: Total number of frames checkpointed */
) {
    __SQLITE_DB_RW_ACCESS(db);

    sf_set_trusted_sink_ptr(zDb);
    sf_buf_stop_at_null(zDb);
    SF_CHECKED_DEREF_READ(zDb);

    if (pnLog) {
        *pnLog = sf_get_values_with_min(-1);
    }
    if (pnCkpt) {
        *pnCkpt = sf_get_values_with_min(-1);
    }

    return sf_get_some_int_to_check();
}

int sqlite3_vtab_config(sqlite3 *db, int op, ...) {
    __SQLITE_DB_RW_ACCESS(db);
    return sf_get_some_int_to_check();
}

int sqlite3_vtab_on_conflict(sqlite3 *db) {
    __SQLITE_DB_RW_ACCESS(db);
    return sf_get_some_int();
}

const char *sqlite3_vtab_collation(sqlite3_index_info *pIdxInfo, int iCons) {
    SF_DEREF_READ(pIdxInfo);
    return __get_nonfreeable_possible_null();
}

int sqlite3_stmt_scanstatus(
    sqlite3_stmt *pStmt,
    int idx,
    int iScanStatusOp,
    void *pOut
) {
    sf_must_not_be_release(pStmt);
    SF_DEREF_WRITE(pStmt); // actual deref

    SF_DEREF_WRITE(pOut);
    sf_overwrite(pOut);

    return sf_get_some_int_to_check();
}

void sqlite3_stmt_scanstatus_reset(sqlite3_stmt *pStmt) {
    sf_must_not_be_release(pStmt);
    SF_DEREF_WRITE(pStmt); // actual deref
}

int sqlite3_db_cacheflush(sqlite3 *db) {
    __SQLITE_DB_RW_ACCESS(db);
    return sf_get_some_int_to_check();
}

int sqlite3_system_errno(sqlite3 *db) {
    SF_CHECKED_DEREF_READ(db);
    return sf_get_some_int_to_check();
}


int sqlite3_snapshot_get(
    sqlite3 *db,
    const char *zSchema,
    sqlite3_snapshot **ppSnapshot
) {
    sf_vulnerable_fun_type("This interface is experimental and is subject to change without notice.", SQLITE);

    __SQLITE_DB_RW_ACCESS(db);

    sf_set_trusted_sink_ptr(zSchema); // ?
    sf_buf_stop_at_null(zSchema);
    SF_CHECKED_DEREF_READ(zSchema);

    __SQLITE_ACQUIRE(sqlite3_snapshot, ppSnapshot, rc, SQLITE3_SNAPSHOT_CATEGORY);

    return rc;
}

int sqlite3_snapshot_open(
    sqlite3 *db,
    const char *zSchema,
    sqlite3_snapshot *pSnapshot
) {
    sf_vulnerable_fun_type("This interface is experimental and is subject to change without notice.", SQLITE);

    __SQLITE_DB_RW_ACCESS(db);

    sf_set_trusted_sink_ptr(zSchema); // ?
    sf_buf_stop_at_null(zSchema);
    SF_CHECKED_DEREF_READ(zSchema);

    return sf_get_some_int_to_check();
}

void sqlite3_snapshot_free(sqlite3_snapshot *pSnapshot) {
    sf_vulnerable_fun_type("This interface is experimental and is subject to change without notice.", SQLITE);

    sf_must_not_be_release(pSnapshot);
    sf_handle_release(pSnapshot, SQLITE3_SNAPSHOT_CATEGORY);
    sf_overwrite(pSnapshot); // ?
}

int sqlite3_snapshot_cmp(
    sqlite3_snapshot *p1,
    sqlite3_snapshot *p2
) {
    sf_vulnerable_fun_type("This interface is experimental and is subject to change without notice.", SQLITE);

    SF_DEREF_READ(p1);
    SF_DEREF_READ(p2);

    return sf_get_values(-1, +1);
}

int sqlite3_snapshot_recover(sqlite3 *db, const char *zDb) {
    sf_vulnerable_fun_type("This interface is experimental and is subject to change without notice.", SQLITE);

    __SQLITE_DB_RW_ACCESS(db);

    sf_set_trusted_sink_ptr(zDb); // ?
    sf_buf_stop_at_null(zDb);
    SF_CHECKED_DEREF_READ(zDb);

    return sf_get_some_int_to_check();
}


int sqlite3_rtree_geometry_callback(
    sqlite3 *db,                  /* Register SQL function on this connection */
    const char *zGeom,            /* Name of the new SQL function */
    int (*xGeom)(sqlite3_rtree_geometry*,int,RtreeDValue*,int*), /* Callback */
    void *pContext                /* Extra data associated with the callback */
) {
    __SQLITE_DB_RW_ACCESS(db);

    sf_set_trusted_sink_ptr(zGeom);
    SF_DEREF_READ(zGeom); // return SQLITE_MISUSE_BKPT
    sf_buf_stop_at_null(zGeom);

    //sf_escape(pContext); // ?

    return sf_get_some_int_to_check();
}


int sqlite3_rtree_query_callback(
    sqlite3 *db,                 /* Register SQL function on this connection */
    const char *zQueryFunc,      /* Name of new SQL function */
    int (*xQueryFunc)(sqlite3_rtree_query_info*), /* Callback */
    void *pContext,              /* Extra data passed into the callback */
    void (*xDestructor)(void*)   /* Destructor for the extra data */
) {
    __SQLITE_DB_RW_ACCESS(db);

    sf_set_trusted_sink_ptr(zQueryFunc);
    SF_DEREF_READ(zQueryFunc); // return SQLITE_MISUSE_BKPT
    sf_buf_stop_at_null(zQueryFunc);

    if (xDestructor) {
        sf_escape(pContext);
    }

    return sf_get_some_int_to_check();
}

