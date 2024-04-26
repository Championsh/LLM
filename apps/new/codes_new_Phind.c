BSTR SysAllocStringLen(const OLECHAR *pch, unsigned int len) {
    sf_set_trusted_sink_ptr(len);    

    BSTR ptr;
    sf_overwrite(&ptr);
    sf_overwrite(ptr);
    sf_uncontrolled_ptr(ptr);
    sf_set_alloc_possible_null(ptr, len);
    sf_new(ptr, BSTR_ALLOC_CATEGORY);
    sf_buf_copy(ptr, pch);
//  sf_buf_size_limit(pch, len+1);
    return ptr; 
}

int SysReAllocString(BSTR *pbstr, const OLECHAR *psz) {
    //sf_not_null(pbstr); - incorrect use of it

    BSTR ptr;
    sf_overwrite(&ptr);
    sf_overwrite(ptr);
    sf_uncontrolled_ptr(ptr);
    sf_set_alloc_possible_null(ptr);
    sf_new(ptr, BSTR_ALLOC_CATEGORY);
    sf_copy_string(ptr, psz);
    
    sf_escape(pbstr);
    int res;
	sf_overwrite(&res);
    //sf_not_acquire_if_eq(ptr, res, 0);
    sf_not_acquire_if_less(ptr, res, 1);
    return res; // Returns True if the string is successfully reallocated, or False if insufficient memory exists.
}

int SysReAllocStringLen(BSTR *pbstr, const OLECHAR *psz, unsigned int len) {
    //sf_not_null(pbstr); - incorrect use

    sf_set_trusted_sink_ptr(len);
    
    BSTR ptr;
    sf_overwrite(&ptr);
    sf_overwrite(ptr);
    sf_uncontrolled_ptr(ptr);
    sf_set_alloc_possible_null(ptr, len);
    sf_new(ptr, BSTR_ALLOC_CATEGORY);
    sf_buf_copy(ptr, psz);
    sf_buf_size_limit(psz, len);

    sf_overwrite(pbstr);
    sf_delete(pbstr, BSTR_ALLOC_CATEGORY);
    
    int res;
	sf_overwrite(&res);
    //sf_not_acquire_if_eq(ptr, res, 0);
    sf_not_acquire_if_less(ptr, res, 1);
    return res; // Returns True if the string is successfully reallocated, or False if insufficient memory exists.
}

void memory_full(void) {
    sf_terminate_path();
}

int isalnum(int c) {
    sf_set_trusted_sink_char(c);//TODO: remove 1 of 2 lines
    int res;
    sf_overwrite(&res);
    sf_pure(res, c);
    return res
    ;
}

int isalpha(int c) {
    sf_set_trusted_sink_char(c);
    int res;
    sf_overwrite(&res);
    sf_pure(res, c);
    return res
    ;
}

int isascii(int c) {
    sf_set_trusted_sink_char(c);
    int res;
    sf_overwrite(&res);
    sf_pure(res, c);
    return res
    ;
}

int isblank(int c) {
    sf_set_trusted_sink_char(c);
    int res;
    sf_overwrite(&res);
    sf_pure(res, c);
    return res
    ;
}

int iscntrl(int c) {
    sf_set_trusted_sink_char(c);
    int res;
    sf_overwrite(&res);
    sf_pure(res, c);
    return res
    ;
}

int isgraph(int c) {
    sf_set_trusted_sink_char(c);
    int res;
    sf_overwrite(&res);
    sf_pure(res, c);
    return res
    ;
}

int islower(int c) {
    sf_set_trusted_sink_char(c);
    int res;
    sf_overwrite(&res);
    sf_pure(res, c);
    return res
    ;
}

int isprint(int c) {
    sf_set_trusted_sink_char(c);
    int res;
    sf_overwrite(&res);
    sf_pure(res, c);
    return res
    ;
}

int ispunct(int c) {
    sf_set_trusted_sink_char(c);
    int res;
    sf_overwrite(&res);
    sf_pure(res, c);
    return res
    ;
}

int isspace(int c) {
    sf_set_trusted_sink_char(c);
    int res;
    sf_overwrite(&res);
    sf_pure(res, c);
    return res
    ;
}

int isupper(int c) {
    sf_set_trusted_sink_char(c);
    int res;
    sf_overwrite(&res);
    sf_pure(res, c);
    return res
    ;
}

int isxdigit(int c) {
    sf_set_trusted_sink_char(c);
    int res;
    sf_overwrite(&res);
    sf_pure(res, c);
    return res
    ;
}

void err(int eval, const char *fmt, ...) {
    sf_use_format(fmt);

    sf_terminate_path();
}

void errx(int eval, const char *fmt, ...) {
    sf_use_format(fmt);

    sf_terminate_path();
}

int creat(const char *name, mode_t mode) {
    char d1 = *name;
    sf_tocttou_access(name);
    int x;
    sf_overwrite(&x);
    sf_overwrite_int_as_ptr(x);
    sf_uncontrolled_value(x);
    sf_set_possible_negative(x);
    sf_handle_acquire_int_as_ptr(x, HANDLE_FILE_CATEGORY);
    sf_not_acquire_if_less_int_as_ptr(x, x, 2);
    sf_lib_arg_type(x, "StdioHandlerCategory");
    return x;
}

int open(const char *name, int flags, ...) {
    char c = *name;//TODO: is it really dereference its argument?
    sf_set_trusted_sink_ptr(name);
    sf_tocttou_access(name);

    sf_setval_O_CREAT(O_CREAT);
    sf_fun_does_not_update_vargs(2);

    int x;
    sf_overwrite(&x);
	sf_overwrite_int_as_ptr(x);
	sf_uncontrolled_value(x);
    sf_set_possible_negative(x);
	sf_handle_acquire_int_as_ptr(x, HANDLE_FILE_CATEGORY);
	sf_not_acquire_if_less_int_as_ptr(x, x, 3);
	sf_lib_arg_type(x, "StdioHandlerCategory");
    return x;
}

int open64(const char *name, int flags, ...) {
    char c = *name;//TODO: is it really dereference its argument?
    sf_set_trusted_sink_ptr(name);
    sf_tocttou_access(name);

    //sf_setval_O_CREAT(O_CREAT);

    int x;
    sf_overwrite(&x);
    sf_overwrite_int_as_ptr(x);
    sf_uncontrolled_value(x);
    sf_set_possible_negative(x);
    sf_handle_acquire_int_as_ptr(x, HANDLE_FILE_CATEGORY);
    sf_not_acquire_if_less_int_as_ptr(x, x, 2);
    sf_lib_arg_type(x, "StdioHandlerCategory");
    return x;
}

gchar * g_strdup (const gchar *str) {
	//note: str may be null
	sf_buf_stop_at_null(str);

	char *res;
	sf_overwrite(&res);
	sf_overwrite(res);
	//like malloc it may return null.
	sf_set_alloc_possible_null(res);
	sf_new(res, GLIB_CATEGORY);
	sf_strdup_res(res);
	return res;
}

gchar * g_strdup_printf (const gchar *format, ...) {
	gchar d1 = *format;
	sf_buf_stop_at_null(format);
	sf_use_format(format);//not sure what it does

	sf_fun_does_not_update_vargs(1);

	char *res;
	sf_overwrite(&res);
	sf_overwrite(res);
	//like malloc it may return null.
	sf_set_alloc_possible_null(res);
	sf_new(res, GLIB_CATEGORY);
	sf_strdup_res(res);
	return res;
}

guint32 g_random_int (void) {
	sf_fun_rand();
}

int munmap(void *addr, size_t len) {
	char deref = *((char *)addr);

	sf_must_not_be_release(addr);
	sf_set_trusted_sink_int(len);

	sf_handle_release(addr, MMAP_CATEGORY);

	int res;
	sf_overwrite(&res);
	sf_must_be_checked(res);
	return res;
}

int SHA256_Init(SHA256_CTX *sha) {
    sf_overwrite(sha);

    int res;
    sf_overwrite(&res);
    return res;
}

int SHA384_Init(SHA512_CTX *sha) {
    sf_overwrite(sha);

    int res;
    sf_overwrite(&res);
    return res;
}

int SHA512_Init(SHA512_CTX *sha) {
    sf_overwrite(sha);

    int res;
    sf_overwrite(&res);
    return res;
}

int pthread_mutex_destroy(pthread_mutex_t *mutex) {
    char deref = *((char *)mutex);
    int ret;
    sf_overwrite(&ret);
    sf_overwrite(mutex);
    return ret;
}

int pthread_mutex_lock(pthread_mutex_t *mutex) {
    sf_lock(mutex);

    int res;
    sf_overwrite(&res);
    sf_success_lock_if_zero(res, mutex);
    return res;
}

int pthread_spin_lock(pthread_spinlock_t *mutex) {
    sf_lock(mutex);

    int res;
    sf_overwrite(&res);
    sf_success_lock_if_zero(res, mutex);
    return res;
}

int setjmp(jmp_buf env) {
    int ret;
    sf_overwrite(&ret);
    sf_overwrite(env);
    return ret;
}

int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  sf_bitinit(addr);
	sf_must_not_be_release(sockfd);
    sf_set_must_be_positive(sockfd);
    sf_lib_arg_type(sockfd, "SocketCategory");

	int res;
    sf_overwrite(&res);
	sf_set_possible_negative(res);
	
    return res;
}

int listen(int sockfd, int backlog) {
	sf_long_time();

	sf_must_not_be_release(sockfd);
    sf_set_must_be_positive(sockfd);
    sf_lib_arg_type(sockfd, "SocketCategory");

	int res;
    sf_overwrite(&res);
	sf_set_possible_negative(res);
    sf_uncontrolled_value(res);
   
    return res;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    // mark setting of the whole buffer
    if(addr) {
        ((char *)addr)[*addrlen - 1] = 0;
    }

	sf_long_time();

    sf_overwrite(addrlen);
    sf_overwrite(addr);

    sf_must_not_be_release(sockfd);
    sf_set_must_be_positive(sockfd);
    sf_lib_arg_type(sockfd, "SocketCategory");

	int res;
    sf_overwrite(&res);
	sf_overwrite_int_as_ptr(res);
    sf_handle_acquire_int_as_ptr(res, SOCKET_CATEGORY);
	sf_set_possible_negative(res);
	sf_uncontrolled_value(res);
	sf_not_acquire_if_less_int_as_ptr(res, res, 1);

    return res;
}

ssize_t recv(int s, void *buf, size_t len, int flags) {
	sf_must_not_be_release(s);
    sf_set_must_be_positive(s);
    sf_lib_arg_type(s, "SocketCategory");

    sf_overwrite(buf);
    sf_set_tainted(buf);
    sf_set_tainted_buf(buf, len, 0);
    sf_set_possible_nnts(buf);
    sf_bitinit(buf);

    ssize_t res;
    sf_overwrite(&res);
    sf_set_possible_negative(res);
    sf_uncontrolled_value(res);
    sf_buf_size_limit(buf, len);
    sf_buf_fill(res, buf);

    sf_assert_cond(res, "<=", len);
    
    return res;
}

ssize_t recvfrom(int s, void *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen) {

    sf_bitinit(from);
    if(from!=0) {
        // sf_bitinit(from); TODO: make sf_bitinit work here for UNINIT.STRUCT
        socklen_t d1 = *fromlen;
    }

    sf_must_not_be_release(s);
    sf_set_must_be_positive(s);
    sf_lib_arg_type(s, "SocketCategory");

    sf_overwrite(buf);
    sf_set_tainted(buf);
    sf_set_tainted_buf(buf, len, 0);
    sf_set_possible_nnts(buf);
    sf_bitinit(buf);

    sf_buf_size_limit(buf, len);

    ssize_t res;
    sf_overwrite(&res);
    sf_set_possible_negative(res);
    sf_uncontrolled_value(res);
    sf_buf_fill(res, buf);
    sf_assert_cond(res, "<=", len);
    
    return res;
}

ssize_t __recvfrom_chk(int s, void *buf, size_t len, size_t buflen, int flags, struct sockaddr *from, socklen_t *fromlen) {
  sf_bitinit(from);
	socklen_t d1 = *fromlen;

	sf_must_not_be_release(s);
    sf_set_must_be_positive(s);
    sf_lib_arg_type(s, "SocketCategory");

    sf_overwrite(buf);
    sf_set_tainted(buf);
    sf_set_tainted_buf(buf, len, 0);
    sf_set_possible_nnts(buf);
    sf_bitinit(buf);

	sf_buf_size_limit(buf, len);

	ssize_t res;
	sf_overwrite(&res);
    sf_buf_fill(res, buf);
	sf_set_possible_negative(res);
	return res;
}

ssize_t recvmsg(int s, struct msghdr *msg, int flags) {
  sf_deepinit(msg);
	sf_must_not_be_release(s);
    sf_set_must_be_positive(s);
    sf_lib_arg_type(s, "SocketCategory");

	ssize_t res;
    sf_overwrite(&res);
    sf_buf_fill(res, msg);
	sf_set_possible_negative(res);
	return res;
}

int sf_get_values(int min, int max) {
    int res = sf_get_some_int();
    sf_set_values(res, min, max);
    return res;
}

int sf_get_values_with_min(int min) {
    //int res = sf_get_values(min, sf_get_some_int()); // will this work?
    int res = sf_get_some_int();
    sf_assert_cond(res, ">=", min);
    return res;
}

int sf_get_values_with_max(int max) {
    //int res = sf_get_values(sf_get_some_int(), max); // will this work?
    int res = sf_get_some_int();
    sf_assert_cond(res, "<=", max);
    return res;
}

char *__mprintf(const char *zFormat) {
    sf_buf_stop_at_null(zFormat);
    sf_use_format(zFormat); // for tainted
    { unsigned char tmp = *(unsigned char *)(zFormat); tmp++; };

    char *res;
    sf_overwrite(&res);
    sf_overwrite(res);
    sf_uncontrolled_ptr(res);
    sf_set_alloc_possible_null(res);
    sf_new(res, SQLITE3_MALLOC_CATEGORY);
    return res;
}

char *sqlite3_uri_parameter(const char *zFilename, const char *zParam) {
    sf_buf_stop_at_null(zFilename);
    sf_buf_stop_at_null(zParam);
    return __get_nonfreeable_possible_null_string();
}

sqlite3_int64 sqlite3_uri_int64(const char *zFilename, const char *zParam, sqlite3_int64 bDflt) {
    sf_buf_stop_at_null(zFilename);
    sf_buf_stop_at_null(zParam);
    int res = sf_get_some_int();
    sf_set_possible_negative(res);
    sf_uncontrolled_value(res);
    return res;
}

int sqlite3_limit(sqlite3 *db, int id, int newVal) {
    sf_set_trusted_sink_nonnegative_int(id);
    sf_set_trusted_sink_nonnegative_int(newVal);
    __SQLITE_db_R_ACCESS(db);
    SF_DEREF_WRITE(db);
    return sf_get_some_int(); // non-negative
}

int sqlite3_bind_parameter_count(sqlite3_stmt *pStmt) {
    sf_must_not_be_release(pStmt);
    if (pStmt) SF_DEREF_READ(pStmt);

    int res;
    if (! pStmt) {
        res = 0;
    } else {
        res = sf_get_some_nonnegative_int();
    }
    return res;
}

int sqlite3_expired(sqlite3_stmt *pStmt) {
    sf_must_not_be_release(pStmt);
    if (pStmt) SF_DEREF_READ(pStmt);

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
    { unsigned char tmp = *(unsigned char *)(pFromStmt); tmp++; };

    sf_must_not_be_release(pToStmt);
    { *(unsigned char *)(pToStmt) = (unsigned char)sf_get_some_int(); };

    return sf_get_some_int_to_check();
}

void sqlite3_result_error(sqlite3_context *pCtx, const char *z, int n) {
    __result_error(pCtx, z, n);
}

void sqlite3_result_text( sqlite3_context *pCtx, const char *z, int n, void (*xDel)(void *)) {
    __result_text(pCtx, z, n, xDel);
}

void sqlite3_result_text64( sqlite3_context *pCtx, const char *z, sqlite3_uint64 n, void (*xDel)(void *)) {
    __result_text(pCtx, z, n, xDel);
}

void sqlite3_result_text16( sqlite3_context *pCtx, const char *z, int n, void (*xDel)(void *)) {
    __result_text(pCtx, z, n, xDel);
}

void sqlite3_result_text16le( sqlite3_context *pCtx, const char *z, int n, void (*xDel)(void *)) {
    __result_text(pCtx, z, n, xDel);
}

void sqlite3_result_text16be( sqlite3_context *pCtx, const char *z, int n, void (*xDel)(void *)) {
    __result_text(pCtx, z, n, xDel);
}

sqlite3 *sqlite3_db_handle(sqlite3_stmt *pStmt) {
    sf_must_not_be_release(pStmt);
    if (pStmt) SF_DEREF_READ(pStmt);
    sqlite3 *res;
    if (! pStmt) {
        res = 0;
    } else {
        res = sf_get_uncontrolled_ptr();
        sf_not_null(res);
    }
    return res;
}

char *sqlite3_db_filename(sqlite3 *db, const char *zDbName) {
    __SQLITE_DB_R_ACCESS(db);

    sf_set_trusted_sink_ptr(zDbName);
    sf_buf_stop_at_null(zDbName);
    if (zDbName) SF_DEREF_READ(zDbName);

    return __get_nonfreeable_possible_null_string();
}

int sqlite3_db_readonly(sqlite3 *db, const char *zDbName) {
    __SQLITE_DB_R_ACCESS(db);

    sf_buf_stop_at_null(zDbName);
    if (zDbName) SF_DEREF_READ(zDbName);

    return sf_get_values(-1, +1);
}

int sqlite3_load_extension( sqlite3 *db, /* Load the extension into this database connection */ const char *zFile, /* Name of the shared library containing extension */ const char *zProc, /* Entry point. Use "sqlite3_extension_init" if 0 */ char **pzErrMsg /* Put error message here if not 0 */) {
    __SQLITE_db_R_ACCESS(db);
    SF_DEREF_WRITE(db);

    sf_set_trusted_sink_ptr(zFile);
    sf_buf_stop_at_null(zFile);
    { unsigned char tmp = *(unsigned char *)(zFile); tmp++; };

    sf_set_trusted_sink_ptr(zProc);
    sf_buf_stop_at_null(zProc);
    if (zProc) SF_DEREF_READ(zProc);

    int rc = sf_get_some_int();
    if (pzErrMsg) {
    if (rc != SQLITE_OK) {
    *(pzErrMsg) = __alloc_some_string();
    } else {
    *(pzErrMsg) = 0;
    }
    }
    sf_must_be_checked(rc);
    return rc;;
}

int sqlite3_enable_load_extension(sqlite3 *db, int onoff) {
    __SQLITE_db_R_ACCESS(db);
    SF_DEREF_WRITE(db);
    sf_set_trusted_sink_nonnegative_int(onoff);
    return sf_get_some_int();
}

int sqlite3_declare_vtab(sqlite3 *db, const char *zSQL) {
    __SQLITE_db_R_ACCESS(db);
    SF_DEREF_WRITE(db);

    sf_buf_stop_at_null(zSQL);
    sf_set_trusted_sink_ptr(zSQL);
    { unsigned char tmp = *(unsigned char *)(zSQL); tmp++; };

    return sf_get_some_int_to_check();
}

int sqlite3_blob_open( sqlite3 *db, const char *zDb, const char *zTable, const char *zColumn, sqlite3_int64 iRow, int flags, sqlite3_blob **ppBlob) {
    __SQLITE_db_R_ACCESS(db);
    SF_DEREF_WRITE(db);

    if (zDb) SF_DEREF_READ(zDb);
    sf_buf_stop_at_null(zDb);

    if (zTable) SF_DEREF_READ(zTable);
    sf_buf_stop_at_null(zTable);

    if (zColumn) SF_DEREF_READ(zColumn);
    sf_buf_stop_at_null(zColumn);

    int rc = sf_get_some_int_to_check();
    {
    sqlite3_blob *result;
    sf_overwrite(&result);
    sf_overwrite(result);
    sf_uncontrolled_value((int)(long long int)result);
    sf_uncontrolled_ptr(result);
    if (rc != SQLITE_OK) {
    sf_set_possible_null(result);
    }
    sf_handle_acquire(result, SQLITE3_BLOB_CATEGORY);
    sf_not_acquire_if_eq(result, (int)(long long int)result, 0);
    sf_not_acquire_if_less(result, rc, SQLITE_OK);
    sf_not_acquire_if_greater(result, rc, SQLITE_OK);
    *(ppBlob) = result;
    };

    return rc;
}

int sqlite3_blob_read(sqlite3_blob *pBlob, void *z, int n, int iOffset) {
    sf_must_not_be_release(pBlob);
    if (pBlob) { *(unsigned char *)(pBlob) = (unsigned char)sf_get_some_int(); }; // ?

    // sf_set_trusted_sink_int(n);
    // sf_set_trusted_sink_int(iOffset);

    { *(unsigned char *)(z) = (unsigned char)sf_get_some_int(); };
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
    if (pBlob) { *(unsigned char *)(pBlob) = (unsigned char)sf_get_some_int(); }; // ?

    // sf_set_trusted_sink_int(n);
    // sf_set_trusted_sink_int(iOffset);

    { unsigned char tmp = *(unsigned char *)(z); tmp++; };
    sf_use(z);
    sf_buf_size_limit_read(z, n);

    int res = sf_get_some_int_to_check();
    sf_assert_cond(res, "<=", n);
    return res;
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

sqlite3_backup *sqlite3_backup_init( sqlite3 *pDest, const char *zDestName, sqlite3 *pSource, const char *zSourceName) {
    sf_must_not_be_release(pSource);
    { unsigned char tmp = *(unsigned char *)(pSource); tmp++; };

    sf_must_not_be_release(pDest);
    { *(unsigned char *)(pDest) = (unsigned char)sf_get_some_int(); };

    sf_set_trusted_sink_ptr(zSourceName);
    sf_buf_stop_at_null(zSourceName);
    { unsigned char tmp = *(unsigned char *)(zSourceName); tmp++; }; // or checked deref ?

    sf_set_trusted_sink_ptr(zDestName);
    sf_buf_stop_at_null(zDestName);
    { unsigned char tmp = *(unsigned char *)(zDestName); tmp++; }; // or checked deref?

    sqlite3_backup *res = sf_get_uncontrolled_ptr();
    sf_set_possible_null(res);
    //sf_set_alloc_possible_null(res);
    sf_new(res, SQLITE3_BACKUP_CATEGORY);

    return res;
}

int __xxx_strcmp(const char *z1, const char *z2) {
    sf_sanitize(z1);
    if (z1) SF_DEREF_READ(z1);

    sf_sanitize(z2);
    if (z2) SF_DEREF_READ(z2);

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

int sqlite3_strglob(const char *zGlobPattern, const char *zString) {
    sf_set_trusted_sink_ptr(zGlobPattern);
    sf_buf_stop_at_null(zGlobPattern);
    { unsigned char tmp = *(unsigned char *)(zGlobPattern); tmp++; };

    sf_sanitize(zString);
    sf_buf_stop_at_null(zString);
    { unsigned char tmp = *(unsigned char *)(zString); tmp++; };

    return sf_get_some_int_to_check(); // ?
}

int sqlite3_vtab_on_conflict(sqlite3 *db) {
    sf_must_not_be_release(db);
    unsigned char tmp = *(unsigned char *)(db); tmp++;
    *(unsigned char *)(db) = (unsigned char)sf_get_some_int();
    return sf_get_some_int();
}

int sqlite3_snapshot_get( sqlite3 *db, const char *zSchema, sqlite3_snapshot **ppSnapshot) {
    sf_vulnerable_fun_type("This interface is experimental and is subject to change without notice.", SQLITE);

    __SQLITE_db_R_ACCESS(db);
    SF_DEREF_WRITE(db);

    sf_set_trusted_sink_ptr(zSchema); // ?
    sf_buf_stop_at_null(zSchema);
    if (zSchema) SF_DEREF_READ(zSchema);

    int rc = sf_get_some_int_to_check();
    {
    sqlite3_snapshot *result;
    sf_overwrite(&result);
    sf_overwrite(result);
    sf_uncontrolled_value((int)(long long int)result);
    sf_uncontrolled_ptr(result);
    if (rc != SQLITE_OK) {
    sf_set_possible_null(result);
    }
    sf_handle_acquire(result, SQLITE3_SNAPSHOT_CATEGORY);
    sf_not_acquire_if_eq(result, (int)(long long int)result, 0);
    sf_not_acquire_if_less(result, rc, SQLITE_OK);
    sf_not_acquire_if_greater(result, rc, SQLITE_OK);
    *(ppSnapshot) = result;
    };

    return rc;
}

int sqlite3_snapshot_recover(sqlite3 *db, const char *zDb) {
    sf_vulnerable_fun_type("This interface is experimental and is subject to change without notice.", SQLITE);

    __SQLITE_db_R_ACCESS(db);
    SF_DEREF_WRITE(db);

    sf_set_trusted_sink_ptr(zDb); // ?
    sf_buf_stop_at_null(zDb);
    if (zDb) SF_DEREF_READ(zDb);

    return sf_get_some_int_to_check();
}

int statfs(const char *path, struct statfs *buf) {
    sf_bitinit(buf);
    sf_tocttou_check(path);
    sf_bitinit(buf);

    sf_password_set(buf->f_type);
    sf_password_set(buf->f_bsize);
    sf_password_set(buf->f_blocks);
    sf_password_set(buf->f_bfree);
    sf_password_set(buf->f_bavail);
    sf_password_set(buf->f_files);
    sf_password_set(buf->f_ffree);
    sf_password_set(&(buf->f_fsid));
    sf_password_set(buf->f_namelen);
    sf_password_set(buf->f_frsize);
    sf_password_set(buf->f_flags);
    sf_password_set(buf->f_spare);
    return ret_any();
}

int statvfs(const char *path, struct statvfs *buf) {
    sf_bitinit(buf);
    sf_tocttou_check(path);
    sf_bitinit(buf);

    sf_password_set(buf->f_bsize);
    sf_password_set(buf->f_frsize);
    sf_password_set(buf->f_blocks);
    sf_password_set(buf->f_bfree);
    sf_password_set(buf->f_bavail);
    sf_password_set(buf->f_files);
    sf_password_set(buf->f_ffree);
    sf_password_set(buf->f_favail);
    sf_password_set(buf->f_fsid);
    sf_password_set(buf->f_flag);
    sf_password_set(buf->f_namemax);
    sf_password_set(buf->__f_spare);
    return ret_any();
}

int abs(int x) {
    int res;
    sf_overwrite(&res);
    sf_pure(res, x);
    return res;
}

int atoi(const char *arg) {
    char d1 = *arg;
    sf_buf_stop_at_null(arg);

    int res;
    sf_overwrite(&res);
    sf_str_to_int(arg, res);
    sf_pure(res, arg); //hack: result depends from content of arg
    return res;
}

long atol(const char *arg) {
    char d1 = *arg;
    sf_buf_stop_at_null(arg);

    long res;
    sf_overwrite(&res);
    sf_str_to_long(arg, res);
    sf_pure(res, arg); //hack: result depends from content of arg
    return res;
}

long long atoll(const char *arg) {
    char d1 = *arg;
    sf_buf_stop_at_null(arg);

    long res;
    sf_overwrite(&res);
    sf_str_to_long(arg, res);//long long?
    sf_pure(res, arg); //hack: result depends from content of arg
    return res;
}

int putenv(char *cmd) {
    char d1 = *cmd;
    sf_set_trusted_sink_ptr(cmd);
    sf_escape(cmd);
}

int rand(void) {
    int res;
    sf_overwrite(&res);
	sf_set_values(res, 0, 32767);//use RAND_MAX?
    sf_fun_rand();
    sf_set_tainted_int(res);
    sf_rand_value(res);
    return res;
}

long random(void) {
    long res;
    sf_overwrite(&res);
    sf_fun_rand();
    sf_set_tainted_long(res);
    sf_rand_value(res);
    return res;
}

double drand48(void) {
    double res;
    sf_fun_rand();
    sf_overwrite(&res);
    sf_set_tainted_double(res);
    sf_rand_value(res);
    return res;
}

long lrand48(void) {
    long res;
    sf_fun_rand();
    sf_overwrite(&res);
    sf_set_tainted_long(res);
    sf_rand_value(res);
    return res;
}

long mrand48(void) {
    long res;
    sf_fun_rand();
    sf_overwrite(&res);
    sf_set_tainted_long(res);
    sf_rand_value(res);
    return res;
}

double erand48(unsigned short xsubi[3]) {
    double res;
    sf_fun_rand();
    sf_overwrite(&res);
    sf_set_tainted_double(res);
    sf_rand_value(res);
    return res;
}

long nrand48(unsigned short xsubi[3]) {
    long res;
    sf_fun_rand();
    sf_overwrite(&res);
    sf_set_tainted_long(res);
    sf_rand_value(res);
    return res;
}

long seed48(unsigned short seed16v[3]) {
    long res;
    sf_fun_rand();
    sf_overwrite(&res);
    sf_set_tainted_long(res);
    sf_rand_value(res);
    return res;
}

int setenv(const char *key, const char *val, int flag) {
    char d1 = *key;
    char d2 = *val;
    sf_set_trusted_sink_ptr(key);
    sf_set_trusted_sink_ptr(val);
}

int system(const char *cmd) {
    char d1 = *cmd;
    sf_set_trusted_sink_ptr(cmd);
}

void Tcl_Panic(const char *format, ...) {
    char c = *format;
    sf_use_format(format);
    sf_terminate_path();
}

void panic(const char *format, ...) {
    char c = *format;
    sf_use_format(format);
    sf_terminate_path();
}

int dup(int oldd) {
    sf_must_not_be_release(oldd);
    sf_set_must_be_positive(oldd);
    sf_lib_arg_type(oldd, "StdioHandlerCategory");

    int res;
    sf_overwrite(&res);
    sf_overwrite_int_as_ptr(res);
    sf_set_possible_negative(res);
    sf_handle_acquire_int_as_ptr(res, HANDLE_FILE_CATEGORY);
    /* Do not check for leaks on standard descriptors 0, 1 and 2 */
    sf_not_acquire_if_less_int_as_ptr(res, res, 3);
    sf_set_errno_if(res, sf_cond_range("==", -1));
    // as I know, file descriptor is a small non-negative integer
    sf_no_errno_if(res, sf_cond_range(">=", 0));
    sf_lib_arg_type(res, "StdioHandlerCategory");
    return res;
}

int dup2(int oldd, int newdd) {
    sf_set_must_be_positive(oldd);
    sf_lib_arg_type(oldd, "StdioHandlerCategory");

    int res;
    sf_overwrite(&res);
    sf_overwrite_int_as_ptr(newdd);
    sf_set_possible_negative(res);
    sf_handle_acquire_int_as_ptr(newdd, HANDLE_FILE_CATEGORY);
    /* Do not check for leaks on standard descriptors 0, 1 and 2 */
    sf_not_acquire_if_less_int_as_ptr(newdd, res, 3);
    sf_set_errno_if(res, sf_cond_range("==", -1));
    // as I know, file descriptor is a small non-negative integer
    sf_no_errno_if(res, sf_cond_range(">=", 0));
    return res;
}

int fchdir(int fd) {
    sf_must_not_be_release(fd);
    sf_set_must_be_positive(fd);
    sf_lib_arg_type(fd, "FileHandlerCategory");
    int x;
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range("==", 0));
    return x;
}

pid_t getpgid(pid_t pid) {
    pid_t x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    sf_set_must_be_positive(pid);
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range(">=", 0));
    return x;
}

char *getwd(char *buf) {
    char *res;
    sf_bitinit(buf);
    sf_overwrite(&res);
    sf_set_possible_null(res);
    sf_set_errno_if(res, sf_cond_range("==", 0));
    return res;
}

ssize_t read(int fd, void *buf, size_t nbytes) {
    sf_bitinit(buf);

	sf_must_not_be_release(fd);
    sf_set_must_be_positive(fd);
    sf_lib_arg_type(fd, "StdioHandlerCategory");

    sf_overwrite(buf);
    sf_set_tainted(buf);
    sf_set_possible_nnts(buf);
    sf_buf_size_limit(buf, nbytes);

    ssize_t x;
    sf_overwrite(&x);
    sf_read_res(x, buf);
    sf_set_possible_negative(x);
    sf_uncontrolled_value(x);
    sf_set_possible_equals(x, nbytes);

    sf_assert_cond(x, "<=", nbytes);
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range(">=", 0));
    sf_buf_fill(x, buf);
    return x;
}

ssize_t __read_chk(int fd, void *buf, size_t nbytes, size_t buflen) {
    sf_must_not_be_release(fd);
    sf_set_must_be_positive(fd);
    sf_lib_arg_type(fd, "StdioHandlerCategory");

    sf_overwrite(buf);
    sf_set_tainted(buf);
    sf_set_possible_nnts(buf);
    sf_buf_size_limit(buf, nbytes);

    ssize_t x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    sf_set_possible_equals(x, nbytes);
    sf_assert_cond(x, "<=", nbytes);
    sf_buf_fill(x, buf);
    return x;
}

int readlink(const char *path, char *buf, int buf_size) {
    sf_use(path);
    sf_bitinit(buf);
    sf_tocttou_check(path);
	sf_set_trusted_sink_ptr(path);

    sf_set_possible_nnts(buf);
    sf_buf_size_limit(buf, buf_size);

    int x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    sf_set_possible_equals(x, buf_size);
    sf_assert_cond(x, "<=", buf_size);
    sf_buf_fill(x, buf);
    return x;
}

int setpgid(pid_t pid, pid_t pgid) {
    int x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    sf_set_must_be_positive(pid);
    sf_set_must_be_positive(pgid);
    return x;
}

int symlink(const char *path1, const char *path2) {
    sf_tocttou_access(path1);
    sf_tocttou_access(path2);
}

struct utmp *pututline(struct utmp *ut) {
    struct utmp *res;
    sf_overwrite(&res);
    sf_use(ut);
    sf_set_possible_null(res);
    return res;
}

struct utmp *getutxline(struct utmp *ut) {
    struct utmp *res;
    sf_overwrite(&res);
    sf_use(ut);
    sf_set_possible_null(res);
    return res;
}

struct utmp *pututxline(struct utmp *ut) {
    struct utmp *res;
    sf_overwrite(&res);
    sf_use(ut);
    sf_set_possible_null(res);
    return res;
}

VOS_INT32 VOS_sprintf(VOS_CHAR * s, const VOS_CHAR * format, ... ) {
    char d1 = *s;
    char d2 = *format;
    sf_bitinit(s);
    sf_use_format(format);

    sf_fun_snprintf_like(1, -1);

    sf_fun_does_not_update_vargs(2);

    sf_vulnerable_fun("This function is unsafe, use VOS_sprintf_Safe instead.");

    int res;
    sf_overwrite(&res);
    return res;
}

VOS_INT32 VOS_sprintf_Safe( VOS_CHAR * s, VOS_UINT32 uiDestLen, const VOS_CHAR * format, ... ) {
    char d1 = *s;
    char d2 = *format;
    sf_bitinit(s);
    sf_use_format(format);

    sf_fun_snprintf_like(2, 1);
    sf_buf_size_limit_strict(s, uiDestLen);

    sf_fun_does_not_update_vargs(3);

    int res;
    sf_overwrite(&res);
    return res;
}

VOS_VOID * VOS_MemCpy_Safe(VOS_VOID * dst, VOS_SIZE_T dstSize, const VOS_VOID *src, VOS_SIZE_T num) {
    if(dstSize>0 && num>0) {
        char d1 = *(char *)dst;
        char d2 = *(char *)src;
    }

    sf_bitinit(dst);
    sf_bitcopy(dst, src);
    sf_set_trusted_sink_int(num);

    sf_buf_copy(dst, src);
    sf_buf_size_limit(dst, dstSize);
    sf_buf_size_limit_strict(dst, dstSize);
    sf_buf_size_limit_read(src, num);
}

VOS_CHAR * VOS_strcpy_Safe(VOS_CHAR *dst, VOS_SIZE_T dstsz, const VOS_CHAR *src) {
    if(dstsz>0) {
        char d1 = *dst;
        char d2 = *src;
    }

    sf_bitinit(dst);
    sf_buf_copy(dst, src);
    sf_copy_string(dst, src);
    sf_buf_size_limit(dst, dstsz);
    sf_buf_size_limit_strict(dst, dstsz);
    sf_buf_size_limit_read(dst, dstsz);
    sf_buf_stop_at_null(src);
}

VOS_CHAR * VOS_StrCpy_Safe(VOS_CHAR *dst, VOS_SIZE_T dstsz, const VOS_CHAR *src) {
    if(dstsz>0) {
        char d1 = *dst;
        char d2 = *src;
    }

    sf_bitinit(dst);
    sf_buf_copy(dst, src);
    sf_copy_string(dst, src);
    sf_buf_size_limit(dst, dstsz);
    sf_buf_size_limit_strict(dst, dstsz);
    sf_buf_size_limit_read(dst, dstsz);
    sf_buf_stop_at_null(src);
}

VOS_CHAR * VOS_StrNCpy_Safe( VOS_CHAR *dst, VOS_SIZE_T dstsz, const VOS_CHAR *src, VOS_SIZE_T count) {
    if (count > 0 && dstsz>0) {
        char d1 = *dst;
        char d2 = *src;
    }
    sf_bitinit(dst);
    sf_buf_copy(dst, src);
    sf_copy_string(dst, src);
    sf_buf_size_limit(src, count);
    sf_buf_size_limit_read(src, count);
    sf_buf_size_limit(dst, dstsz);
    sf_buf_size_limit_read(dst, dstsz);
    sf_buf_size_limit_strict(dst, dstsz);
    sf_buf_stop_at_null(src);
}

VOS_UINT32 VOS_strlen(const VOS_CHAR *s) {
    char d1 = *s;

    sf_sanitize(s);

    size_t res;
    sf_overwrite(&res);
    sf_strlen(res, s);
    sf_buf_stop_at_null(s);

    if(s)
        sf_assert_cond(res, ">=", 0);
    return res;
}

VOS_UINT32 VOS_StrLen(const VOS_CHAR *s) {
    char d1 = *s;

    sf_sanitize(s);

    size_t res;
    sf_overwrite(&res);
    sf_strlen(res, s);
    sf_buf_stop_at_null(s);

    if(s)
        sf_assert_cond(res, ">=", 0);
    return res;
}

