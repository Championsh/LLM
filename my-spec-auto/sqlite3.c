#include "specfunc.h"
#include "sqlite3-types.h"

#define SQLITE "SQLITE"

#define SQLITE_OK 0
#define SQLITE_NOMEM 7
#define SQLITE_STATIC      ((sqlite3_destructor_type)0)
#define SQLITE_TRANSIENT   ((sqlite3_destructor_type)-1)

typedef __builtin_va_list va_list;

#define SF_DEREF_READ(ptr);
#define SF_CHECKED_DEREF_READ(ptr)if (ptr)SF_DEREF_READ(ptr)

#define SF_DEREF_WRITE(ptr);
#define SF_CHECKED_DEREF_WRITE(ptr)if (ptr);

#define SF_DEFINE_GET_SOME_X(NAMESUFFIX,TYPENAME)\
static TYPENAME sf_get_some_## NAMESUFFIX (void);

#define SF_DEFINE_GET_SOME(TYPENAME)SF_DEFINE_GET_SOME_X(TYPENAME, TYPENAME)

SF_DEFINE_GET_SOME(unsigned)
SF_DEFINE_GET_SOME(double)
SF_DEFINE_GET_SOME_X(int64, sqlite3_int64)

#define SF_DEFINE_GET_TAINTED_X(NAMESUFFIX,TYPENAME)\
static TYPENAME sf_get_tainted_## NAMESUFFIX (void);

#define SF_DEFINE_GET_TAINTED(TYPENAME)SF_DEFINE_GET_TAINTED_X(TYPENAME, TYPENAME)

SF_DEFINE_GET_TAINTED(int)
SF_DEFINE_GET_TAINTED(double)
SF_DEFINE_GET_TAINTED_X(int64, sqlite3_int64)

#define __SQLITE_DB_R_ACCESS(DB)\
    sf_must_not_be_release(DB); \
    SF_DEREF_READ(DB)

#define __SQLITE_DB_RW_ACCESS(DB)\
    __SQLITE_DB_R_ACCESS(DB); \
    SF_DEREF_WRITE(DB)

#define __SQLITE_ACQUIRE(TYPE,VARIABLE,RETCODE,CATEGORY)\
    int RETCODE = sf_get_some_int_to_check(); \
    ;

#define __SQLITE_RELEASE_IMPLEMENTATION(VARIABLE,CATEGORY)\
      \
      \
      \
    \
    sf_must_not_be_release(VARIABLE); \
    sf_handle_release(VARIABLE, CATEGORY); \
      \
    \
    int ret = sf_get_some_int_to_check();\
    sf_func_success_if(ret, SQLITE_OK);\
    return ret;

#define __SQLITE_RETURN_RETCODE_AND_SET_ERROR_MESSAGE_VAR(ERROR_MESSAGE_VAR)\
    int rc = sf_get_some_int(); \
    if (ERROR_MESSAGE_VAR); \
    sf_must_be_checked(rc); \
    return rc;



static int sf_get_values(int min, int max);

static int sf_get_bool(void);

static int sf_get_values_with_min(int min);

static int sf_get_values_with_max(int max);

static int sf_get_some_nonnegative_int(void);

static int sf_get_some_int_to_check(void);

static void *sf_get_uncontrolled_ptr(void);

 
static void sf_set_trusted_sink_nonnegative_int(int n);

static char *__alloc_some_string(void);

static void *__get_nonfreeable(void);

static void *__get_nonfreeable_tainted(void);

static void *__get_nonfreeable_possible_null(void);

static void *__get_nonfreeable_tainted_possible_null(void);

static void *__get_nonfreeable_not_null(void);

static char *__get_nonfreeable_string(void);

static char *__get_nonfreeable_possible_null_string(void);

static char *__get_nonfreeable_not_null_string(void);

static char *__get_nonfreeable_tainted_possible_null_string(void);

const char *sqlite3_libversion(void);

const char *sqlite3_sourceid(void);

int sqlite3_libversion_number(void);

int sqlite3_compileoption_used(const char *zOptName);

const char *sqlite3_compileoption_get(int N);

int sqlite3_threadsafe(void);

static int __close(sqlite3 *db);

int sqlite3_close(sqlite3 *db);

int sqlite3_close_v2(sqlite3 *db);


int sqlite3_exec(
    sqlite3 *db,                                 
    const char *zSql,                            
    int (*xCallback)(void*,int,char**,char**),   
    void *pArg,                                  
    char **pzErrMsg                              
)
;


int sqlite3_initialize(void);

int sqlite3_shutdown(void);

int sqlite3_os_init(void);

int sqlite3_os_end(void);

int sqlite3_config(int stub, ...);

int sqlite3_db_config(sqlite3 *db, int op, ...);


int sqlite3_extended_result_codes(sqlite3 *db, int onoff);

sqlite3_int64 sqlite3_last_insert_rowid(sqlite3 *db);

void sqlite3_set_last_insert_rowid(sqlite3 *db, sqlite3_int64 rowid);

int sqlite3_changes(sqlite3 *db);

int sqlite3_total_changes(sqlite3 *db);

void sqlite3_interrupt(sqlite3 *db);

static int __complete(const char *sql);

int sqlite3_complete(const char *sql);

int sqlite3_complete16(const void *sql);

int sqlite3_busy_handler(
    sqlite3 *db,
    int (*xBusy)(void*,int),
    void *pArg
);

int sqlite3_busy_timeout(sqlite3 *db, int ms);


int sqlite3_get_table(
    sqlite3 *db,           
    const char *zSql,      
    char ***pazResult,     
    int *pnRow,            
    int *pnColumn,         
    char **pzErrMsg        
);

void sqlite3_free_table(char **result);

static char *__mprintf(const char *zFormat);

char *sqlite3_mprintf(const char *zFormat, ...);

char *sqlite3_vmprintf(const char *zFormat, va_list ap);

static char *__snprintf(int n, char *zBuf, const char *zFormat);

char *sqlite3_snprintf(int n, char *zBuf, const char *zFormat, ...);

char *sqlite3_vsnprintf(int n, char *zBuf, const char *zFormat, va_list ap);

static void *__malloc(sqlite3_int64 size);

void *sqlite3_malloc(int size);

void *sqlite3_malloc64(sqlite3_uint64 size);

static void *__realloc(void *ptr, sqlite3_uint64 size);


void *sqlite3_realloc(void *ptr, int size);

void *sqlite3_realloc64(void *ptr, sqlite3_uint64 size);

void sqlite3_free(void *ptr);

sqlite3_uint64 sqlite3_msize(void *ptr);

sqlite3_int64 sqlite3_memory_used(void);

sqlite3_int64 sqlite3_memory_highwater(int resetFlag);

void sqlite3_randomness(int N, void *P);

int sqlite3_set_authorizer(
    sqlite3 *db,
    int (*xAuth)(void*,int,const char*,const char*,const char*,const char*),
    void *pUserData
);


void *sqlite3_trace(
    sqlite3 *db,
    void (*xTrace)(void*,const char*),
    void *pArg
);

void *sqlite3_profile(
    sqlite3 *db,
    void (*xProfile)(void*,const char*,sqlite3_uint64),
    void *pArg
);

int sqlite3_trace_v2(
    sqlite3 *db,
    unsigned uMask,
    int(*xCallback)(unsigned,void*,void*,void*),
    void *pCtx
);

void sqlite3_progress_handler(
    sqlite3 *db,
    int nOps,
    int (*xProgress)(void*),
    void *pArg
);

static int __sqlite3_open(
    const char *filename,
    sqlite3 **ppDb
);


int sqlite3_open(
    const char *filename,
    sqlite3 **ppDb
);

int sqlite3_open16(
    const void *filename,
    sqlite3 **ppDb
);

int sqlite3_open_v2(
    const char *filename,
    sqlite3 **ppDb,
    int flags,
    const char *zVfs
);

const char *sqlite3_uri_parameter(const char *zFilename, const char *zParam);

int sqlite3_uri_boolean(const char *zFilename, const char *zParam, int bDefault);

sqlite3_int64 sqlite3_uri_int64(const char *zFilename, const char *zParam, sqlite3_int64 bDflt);

int sqlite3_errcode(sqlite3 *db);

int sqlite3_extended_errcode(sqlite3 *db);

const char *sqlite3_errmsg(sqlite3 *db);

const void *sqlite3_errmsg16(sqlite3 *db);

const char *sqlite3_errstr(int rc);


int sqlite3_limit(sqlite3 *db, int id, int newVal);

static int __prepare(
    sqlite3 *db,
    const char *zSql,
    int nByte,
    sqlite3_stmt **ppStmt,
    const char **pzTail
);

int sqlite3_prepare(
    sqlite3 *db,
    const char *zSql,
    int nByte,
    sqlite3_stmt **ppStmt,
    const char **pzTail
);

int sqlite3_prepare_v2(
    sqlite3 *db,
    const char *zSql,
    int nByte,
    sqlite3_stmt **ppStmt,
    const char **pzTail
);

int sqlite3_prepare_v3(
    sqlite3 *db,
    const char *zSql,
    int nByte,
    unsigned int prepFlags,
    sqlite3_stmt **ppStmt,
    const char **pzTail
);

int sqlite3_prepare16(
    sqlite3 *db,
    const void *zSql,
    int nByte,
    sqlite3_stmt **ppStmt,
    const void **pzTail
);

int sqlite3_prepare16_v2(
    sqlite3 *db,
    const void *zSql,
    int nByte,
    sqlite3_stmt **ppStmt,
    const void **pzTail
);

int sqlite3_prepare16_v3(
    sqlite3 *db,
    const void *zSql,
    int nByte,
    unsigned int prepFlags,
    sqlite3_stmt **ppStmt,
    const void **pzTail
);

const char *sqlite3_sql(sqlite3_stmt *pStmt);

char *sqlite3_expanded_sql(sqlite3_stmt *pStmt);


int sqlite3_stmt_readonly(sqlite3_stmt *pStmt);

int sqlite3_stmt_busy(sqlite3_stmt *pStmt);

int sqlite3_bind_blob(
    sqlite3_stmt *pStmt,
    int i,
    const void *zData,
    int nData,
    void (*xDel)(void*)
);

int sqlite3_bind_blob64(
    sqlite3_stmt *pStmt,
    int i,
    const void *zData,
    sqlite3_uint64 nData,
    void (*xDel)(void*)
);

int sqlite3_bind_double(sqlite3_stmt *pStmt, int i, double rValue);

int sqlite3_bind_int(sqlite3_stmt *pStmt, int i, int iValue);

int sqlite3_bind_int64(sqlite3_stmt *pStmt, int i, sqlite3_int64 iValue);

int sqlite3_bind_null(sqlite3_stmt *pStmt, int i);

static int __bind_text(
    sqlite3_stmt *pStmt,
    int i,
    const char *zData,
    int nData,
    void (*xDel)(void*)
);

int sqlite3_bind_text(
    sqlite3_stmt *pStmt,
    int i,
    const char *zData,
    int nData,
    void (*xDel)(void*)
);

int sqlite3_bind_text16(
    sqlite3_stmt *pStmt,
    int i,
    const char *zData,
    int nData,
    void (*xDel)(void*)
);

int sqlite3_bind_text64(
    sqlite3_stmt *pStmt,
    int i,
    const char *zData,
    sqlite3_uint64 nData,
    void (*xDel)(void*),
    unsigned char enc
);

int sqlite3_bind_value(sqlite3_stmt *pStmt, int i, const sqlite3_value *pValue);

int sqlite3_bind_pointer(
    sqlite3_stmt *pStmt,
    int i,
    void *pPtr,
    const char *zPTtype,
    void (*xDestructor)(void*)
);

static int __bind_zeroblob(sqlite3_stmt *pStmt, int i, sqlite3_uint64 n);

int sqlite3_bind_zeroblob(sqlite3_stmt *pStmt, int i, int n);

int sqlite3_bind_zeroblob64(sqlite3_stmt *pStmt, int i, sqlite3_uint64 n);

int sqlite3_bind_parameter_count(sqlite3_stmt *pStmt);

const char *sqlite3_bind_parameter_name(sqlite3_stmt *pStmt, int i);

int sqlite3_bind_parameter_index(sqlite3_stmt *pStmt, const char *zName);

int sqlite3_clear_bindings(sqlite3_stmt *pStmt);

int sqlite3_column_count(sqlite3_stmt *pStmt);

static const char *__column_name(sqlite3_stmt *pStmt, int N);

const char *sqlite3_column_name(sqlite3_stmt *pStmt, int N);

const void *sqlite3_column_name16(sqlite3_stmt *pStmt, int N);

const char *sqlite3_column_database_name(sqlite3_stmt *pStmt, int N);

const void *sqlite3_column_database_name16(sqlite3_stmt *pStmt, int N);

const char *sqlite3_column_table_name(sqlite3_stmt *pStmt, int N);

const void *sqlite3_column_table_name16(sqlite3_stmt *pStmt, int N);

const char *sqlite3_column_origin_name(sqlite3_stmt *pStmt, int N);

const void *sqlite3_column_origin_name16(sqlite3_stmt *pStmt, int N);

const char *sqlite3_column_decltype(sqlite3_stmt *pStmt, int N);

const void *sqlite3_column_decltype16(sqlite3_stmt *pStmt, int N);

int sqlite3_step(sqlite3_stmt *pStmt);

int sqlite3_data_count(sqlite3_stmt *pStmt);

const void *sqlite3_column_blob(sqlite3_stmt *pStmt, int iCol);

double sqlite3_column_double(sqlite3_stmt *pStmt, int iCol);

int sqlite3_column_int(sqlite3_stmt *pStmt, int iCol);

sqlite3_int64 sqlite3_column_int64(sqlite3_stmt *pStmt, int iCol);

const unsigned char *sqlite3_column_text(sqlite3_stmt *pStmt, int iCol);

const void *sqlite3_column_text16(sqlite3_stmt *pStmt, int iCol);

sqlite3_value *sqlite3_column_value(sqlite3_stmt *pStmt, int iCol);

int sqlite3_column_bytes(sqlite3_stmt *pStmt, int iCol);

int sqlite3_column_bytes16(sqlite3_stmt *pStmt, int iCol);

int sqlite3_column_type(sqlite3_stmt *pStmt, int iCol);

int sqlite3_finalize(sqlite3_stmt *pStmt);


int sqlite3_reset(sqlite3_stmt *pStmt);

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
);

int sqlite3_create_function(
    sqlite3 *db,
    const char *zFunctionName,
    int nArg,
    int eTextRep,
    void *pApp,
    void (*xFunc)(sqlite3_context*,int,sqlite3_value**),
    void (*xStep)(sqlite3_context*,int,sqlite3_value**),
    void (*xFinal)(sqlite3_context*)
);

int sqlite3_create_function16(
    sqlite3 *db,
    const void *zFunctionName,
    int nArg,
    int eTextRep,
    void *pApp,
    void (*xFunc)(sqlite3_context*,int,sqlite3_value**),
    void (*xStep)(sqlite3_context*,int,sqlite3_value**),
    void (*xFinal)(sqlite3_context*)
);

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
);

int sqlite3_aggregate_count(sqlite3_context *pCtx);

int sqlite3_expired(sqlite3_stmt *pStmt);

int sqlite3_transfer_bindings(sqlite3_stmt *pFromStmt, sqlite3_stmt *pToStmt);

int sqlite3_global_recover(void);

void sqlite3_thread_cleanup(void);

int sqlite3_memory_alarm(
    void(*xCallback)(void *pArg, sqlite3_int64 used,int N),
    void *pArg,
    sqlite3_int64 iThreshold
);

const void *sqlite3_value_blob(sqlite3_value *pVal);

double sqlite3_value_double(sqlite3_value *pVal);

int sqlite3_value_int(sqlite3_value *pVal);

sqlite3_int64 sqlite3_value_int64(sqlite3_value *pVal);

void *sqlite3_value_pointer(sqlite3_value *pVal, const char *zPType);

const unsigned char *sqlite3_value_text(sqlite3_value *pVal);

const void *sqlite3_value_text16(sqlite3_value *pVal);

const void *sqlite3_value_text16le(sqlite3_value *pVal);

const void *sqlite3_value_text16be(sqlite3_value *pVal);

int sqlite3_value_bytes(sqlite3_value *pVal);

int sqlite3_value_bytes16(sqlite3_value *pVal);

int sqlite3_value_type(sqlite3_value *pVal);

int sqlite3_value_numeric_type(sqlite3_value *pVal);

unsigned int sqlite3_value_subtype(sqlite3_value *pVal);


#define TREAT__value_dup__AS_MALLOC

sqlite3_value *sqlite3_value_dup(const sqlite3_value *pVal);

void sqlite3_value_free(sqlite3_value *pVal);

void *sqlite3_aggregate_context(sqlite3_context *pCtx, int nBytes);

void *sqlite3_user_data(sqlite3_context *pCtx);

sqlite3 *sqlite3_context_db_handle(sqlite3_context *pCtx);

void *sqlite3_get_auxdata(sqlite3_context *pCtx, int N);

void sqlite3_set_auxdata(
    sqlite3_context *pCtx,
    int iArg,
    void *pAux,
    void (*xDelete)(void*)
);


void sqlite3_result_blob(
    sqlite3_context *pCtx,
    const void *z,
    int n,
    void (*xDel)(void *)
);

void sqlite3_result_blob64(
    sqlite3_context *pCtx,
    const void *z,
    sqlite3_uint64 n,
    void (*xDel)(void *)
);

void sqlite3_result_double(sqlite3_context *pCtx, double rVal);

static void __result_error(sqlite3_context *pCtx, const void *z, int n);

void sqlite3_result_error(sqlite3_context *pCtx, const char *z, int n);

void sqlite3_result_error16(sqlite3_context *pCtx, const void *z, int n);

void sqlite3_result_error_toobig(sqlite3_context *pCtx);

void sqlite3_result_error_nomem(sqlite3_context *pCtx);

void sqlite3_result_error_code(sqlite3_context *pCtx, int errCode);

void sqlite3_result_int(sqlite3_context *pCtx, int iVal);

void sqlite3_result_int64(sqlite3_context *pCtx, sqlite3_int64 iVal);

void sqlite3_result_null(sqlite3_context *pCtx);

static void __result_text(
    sqlite3_context *pCtx,
    const char *z,
    int n,
    void (*xDel)(void *)
);

void sqlite3_result_text(
    sqlite3_context *pCtx,
    const char *z,
    int n,
    void (*xDel)(void *)
);

void sqlite3_result_text64(
    sqlite3_context *pCtx,
    const char *z,
    sqlite3_uint64 n,
    void (*xDel)(void *)
);

void sqlite3_result_text16(
    sqlite3_context *pCtx,
    const char *z,
    int n,
    void (*xDel)(void *)
);

void sqlite3_result_text16le(
    sqlite3_context *pCtx,
    const char *z,
    int n,
    void (*xDel)(void *)
);

void sqlite3_result_text16be(
    sqlite3_context *pCtx,
    const char *z,
    int n,
    void (*xDel)(void *)
);

void sqlite3_result_value(sqlite3_context *pCtx, sqlite3_value *pValue);

void sqlite3_result_pointer(
    sqlite3_context *pCtx,
    void *pPtr,
    const char *zPType,
    void (*xDestructor)(void *)
);


void sqlite3_result_zeroblob(sqlite3_context *pCtx, int n);

int sqlite3_result_zeroblob64(sqlite3_context *pCtx, sqlite3_uint64 n);

void sqlite3_result_subtype(sqlite3_context *pCtx, unsigned int eSubtype);

static int __create_collation(
    sqlite3 *db,
    const char *zName,
    void *pArg,
    int(*xCompare)(void*,int,const void*,int,const void*),
    void(*xDestroy)(void*)
);

int sqlite3_create_collation(
    sqlite3 *db,
    const char *zName,
    int eTextRep,
    void *pArg,
    int(*xCompare)(void*,int,const void*,int,const void*)
);

int sqlite3_create_collation_v2(
    sqlite3 *db,
    const char *zName,
    int eTextRep,
    void *pArg,
    int(*xCompare)(void*,int,const void*,int,const void*),
    void(*xDestroy)(void*)
);

int sqlite3_create_collation16(
    sqlite3 *db,
    const void *zName,
    int eTextRep,
    void *pArg,
    int(*xCompare)(void*,int,const void*,int,const void*)
);

int sqlite3_collation_needed(
    sqlite3 *db,
    void *pCollNeededArg,
    void(*xCollNeeded)(void*,sqlite3*,int eTextRep,const char*)
);

int sqlite3_collation_needed16(
    sqlite3 *db,
    void *pCollNeededArg,
    void(*xCollNeeded16)(void*,sqlite3*,int eTextRep,const void*)
);

int sqlite3_sleep(int ms);

int sqlite3_get_autocommit(sqlite3 *db);

sqlite3 *sqlite3_db_handle(sqlite3_stmt *pStmt);

const char *sqlite3_db_filename(sqlite3 *db, const char *zDbName);

int sqlite3_db_readonly(sqlite3 *db, const char *zDbName);

sqlite3_stmt *sqlite3_next_stmt(sqlite3 *db, sqlite3_stmt *pStmt);

void *sqlite3_commit_hook(
    sqlite3 *db,               
    int (*xCallback)(void*),   
    void *pArg                 
);


void *sqlite3_rollback_hook(
    sqlite3 *db,               
    void (*xCallback)(void*),  
    void *pArg                 
);

void *sqlite3_update_hook(
    sqlite3 *db,               
    void (*xCallback)(void*,int,char const *,char const *,sqlite_int64),
    void *pArg                 
);

int sqlite3_enable_shared_cache(int enable);

int sqlite3_release_memory(int n);

int sqlite3_db_release_memory(sqlite3 *db);

sqlite3_int64 sqlite3_soft_heap_limit64(sqlite3_int64 n);

void sqlite3_soft_heap_limit(int n);

int sqlite3_table_column_metadata(
    sqlite3 *db,                 
    const char *zDbName,         
    const char *zTableName,      
    const char *zColumnName,     
    char const **pzDataType,     
    char const **pzCollSeq,      
    int *pNotNull,               
    int *pPrimaryKey,            
    int *pAutoinc                
);

int sqlite3_load_extension(
    sqlite3 *db,           
    const char *zFile,     
    const char *zProc,     
    char **pzErrMsg        
);


int sqlite3_enable_load_extension(sqlite3 *db, int onoff);

int sqlite3_auto_extension(void(*xEntryPoint)(void));

int sqlite3_cancel_auto_extension(void(*xEntryPoint)(void));


void sqlite3_reset_auto_extension(void);  

static int __create_module(
    sqlite3 *db,
    const char *zName,
    const sqlite3_module *pModule,
    void *pAux,
    void (*xDestroy)(void *)
);


int sqlite3_create_module(
    sqlite3 *db,                     
    const char *zName,               
    const sqlite3_module *pModule,   
    void *pAux                       
);


int sqlite3_create_module_v2(
    sqlite3 *db,                     
    const char *zName,               
    const sqlite3_module *pModule,   
    void *pAux,                      
    void (*xDestroy)(void *)        
);


int sqlite3_declare_vtab(sqlite3 *db, const char *zSQL);

int sqlite3_overload_function(sqlite3 *db, const char *zFuncName, int nArg);


int sqlite3_blob_open(
    sqlite3 *db,
    const char *zDb,
    const char *zTable,
    const char *zColumn,
    sqlite3_int64 iRow,
    int flags,
    sqlite3_blob **ppBlob
);

int sqlite3_blob_reopen(sqlite3_blob *pBlob, sqlite3_int64 iRow);

int sqlite3_blob_close(sqlite3_blob *pBlob);

int sqlite3_blob_bytes(sqlite3_blob *pBlob);

int sqlite3_blob_read(sqlite3_blob *pBlob, void *z, int n, int iOffset);

int sqlite3_blob_write(sqlite3_blob *pBlob, const void *z, int n, int iOffset);

sqlite3_vfs *sqlite3_vfs_find(const char *zVfsName);

int sqlite3_vfs_register(sqlite3_vfs *pVfs, int makeDflt);

int sqlite3_vfs_unregister(sqlite3_vfs *pVfs);

sqlite3_mutex *sqlite3_mutex_alloc(int id);

void sqlite3_mutex_free(sqlite3_mutex *p);

void sqlite3_mutex_enter(sqlite3_mutex *p);

int sqlite3_mutex_try(sqlite3_mutex *p);

void sqlite3_mutex_leave(sqlite3_mutex *p);

int sqlite3_mutex_held(sqlite3_mutex *p);

int sqlite3_mutex_notheld(sqlite3_mutex *p);

sqlite3_mutex *sqlite3_db_mutex(sqlite3 *db);

int sqlite3_file_control(sqlite3 *db, const char *zDbName, int op, void *pArg);

int sqlite3_test_control(int op, ...);  

int sqlite3_status64(
    int op,
    sqlite3_int64 *pCurrent,
    sqlite3_int64 *pHighwater,
    int resetFlag
);

int sqlite3_status(int op, int *pCurrent, int *pHighwater, int resetFlag);

int sqlite3_db_status(
    sqlite3 *db,           
    int op,                
    int *pCurrent,         
    int *pHighwater,       
    int resetFlag          
);


int sqlite3_stmt_status(sqlite3_stmt *pStmt, int op, int resetFlg);


sqlite3_backup *sqlite3_backup_init(
    sqlite3 *pDest,
    const char *zDestName,
    sqlite3 *pSource,
    const char *zSourceName
);

int sqlite3_backup_step(sqlite3_backup *p, int nPage);

int sqlite3_backup_finish(sqlite3_backup *p);

int sqlite3_backup_remaining(sqlite3_backup *p);

int sqlite3_backup_pagecount(sqlite3_backup *p);

int sqlite3_unlock_notify(
    sqlite3 *db,                           
    void (*xNotify)(void **apArg, int nArg),     
    void *pArg                                   
);


static int __xxx_strcmp(const char *z1, const char *z2);

int sqlite3_stricmp(const char *z1, const char *z2);

int sqlite3_strnicmp(const char *z1, const char *z2, int n);

int sqlite3_strglob(const char *zGlobPattern, const char *zString);

int sqlite3_strlike(const char *zPattern, const char *zStr, unsigned int esc);

void sqlite3_log(int iErrCode, const char *zFormat, ...);

void *sqlite3_wal_hook(
    sqlite3 *db,                     
    int(*xCallback)(void *, sqlite3*, const char*, int),
    void *pArg                       
);

int sqlite3_wal_autocheckpoint(sqlite3 *db, int N);

int sqlite3_wal_checkpoint(sqlite3 *db, const char *zDb);

int sqlite3_wal_checkpoint_v2(
    sqlite3 *db,                     
    const char *zDb,                 
    int eMode,                       
    int *pnLog,                      
    int *pnCkpt                      
);

int sqlite3_vtab_config(sqlite3 *db, int op, ...);

int sqlite3_vtab_on_conflict(sqlite3 *db);

const char *sqlite3_vtab_collation(sqlite3_index_info *pIdxInfo, int iCons);

int sqlite3_stmt_scanstatus(
    sqlite3_stmt *pStmt,
    int idx,
    int iScanStatusOp,
    void *pOut
);

void sqlite3_stmt_scanstatus_reset(sqlite3_stmt *pStmt);

int sqlite3_db_cacheflush(sqlite3 *db);

int sqlite3_system_errno(sqlite3 *db);


int sqlite3_snapshot_get(
    sqlite3 *db,
    const char *zSchema,
    sqlite3_snapshot **ppSnapshot
);

int sqlite3_snapshot_open(
    sqlite3 *db,
    const char *zSchema,
    sqlite3_snapshot *pSnapshot
);

void sqlite3_snapshot_free(sqlite3_snapshot *pSnapshot);

int sqlite3_snapshot_cmp(
    sqlite3_snapshot *p1,
    sqlite3_snapshot *p2
);

int sqlite3_snapshot_recover(sqlite3 *db, const char *zDb);


int sqlite3_rtree_geometry_callback(
    sqlite3 *db,                   
    const char *zGeom,             
    int (*xGeom)(sqlite3_rtree_geometry*,int,RtreeDValue*,int*),  
    void *pContext                 
);


int sqlite3_rtree_query_callback(
    sqlite3 *db,                  
    const char *zQueryFunc,       
    int (*xQueryFunc)(sqlite3_rtree_query_info*),  
    void *pContext,               
    void (*xDestructor)(void*)   
);

