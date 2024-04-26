BSTR SysAllocStringLen(const OLECHAR *pch, unsigned int len);
int SysReAllocString(BSTR *pbstr, const OLECHAR *psz);
int SysReAllocStringLen(BSTR *pbstr, const OLECHAR *psz, unsigned int len);
void memory_full(void);
int isalnum(int c);
int isalpha(int c);
int isascii(int c);
int isblank(int c);
int iscntrl(int c);
int isgraph(int c);
int islower(int c);
int isprint(int c);
int ispunct(int c);
int isspace(int c);
int isupper(int c);
int isxdigit(int c);
void err(int eval, const char *fmt, ...);
void errx(int eval, const char *fmt, ...);
int creat(const char *name, mode_t mode);
int open(const char *name, int flags, ...);
int open64(const char *name, int flags, ...);
gchar * g_strdup (const gchar *str);
gchar * g_strdup_printf (const gchar *format, ...);
guint32 g_random_int (void);
int munmap(void *addr, size_t len);
int SHA256_Init(SHA256_CTX *sha);
int SHA384_Init(SHA512_CTX *sha);
int SHA512_Init(SHA512_CTX *sha);
int pthread_mutex_destroy(pthread_mutex_t *mutex);
int pthread_mutex_lock(pthread_mutex_t *mutex);
int pthread_spin_lock(pthread_spinlock_t *mutex);
int setjmp(jmp_buf env);
int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int listen(int sockfd, int backlog);
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
ssize_t recv(int s, void *buf, size_t len, int flags);
ssize_t recvfrom(int s, void *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen);
ssize_t __recvfrom_chk(int s, void *buf, size_t len, size_t buflen, int flags, struct sockaddr *from, socklen_t *fromlen);
ssize_t recvmsg(int s, struct msghdr *msg, int flags);
int sf_get_values(int min, int max);
int sf_get_values_with_min(int min);
int sf_get_values_with_max(int max);
char *__mprintf(const char *zFormat);
char *sqlite3_uri_parameter(const char *zFilename, const char *zParam);
sqlite3_int64 sqlite3_uri_int64(const char *zFilename, const char *zParam, sqlite3_int64 bDflt);
int sqlite3_limit(sqlite3 *db, int id, int newVal);
int sqlite3_bind_parameter_count(sqlite3_stmt *pStmt);
int sqlite3_expired(sqlite3_stmt *pStmt);
int sqlite3_transfer_bindings(sqlite3_stmt *pFromStmt, sqlite3_stmt *pToStmt);
void sqlite3_result_error(sqlite3_context *pCtx, const char *z, int n);
void sqlite3_result_text( sqlite3_context *pCtx, const char *z, int n, void (*xDel)(void *));
void sqlite3_result_text64( sqlite3_context *pCtx, const char *z, sqlite3_uint64 n, void (*xDel)(void *));
void sqlite3_result_text16( sqlite3_context *pCtx, const char *z, int n, void (*xDel)(void *));
void sqlite3_result_text16le( sqlite3_context *pCtx, const char *z, int n, void (*xDel)(void *));
void sqlite3_result_text16be( sqlite3_context *pCtx, const char *z, int n, void (*xDel)(void *));
sqlite3 *sqlite3_db_handle(sqlite3_stmt *pStmt);
char *sqlite3_db_filename(sqlite3 *db, const char *zDbName);
int sqlite3_db_readonly(sqlite3 *db, const char *zDbName);
int sqlite3_load_extension( sqlite3 *db, /* Load the extension into this database connection */ const char *zFile, /* Name of the shared library containing extension */ const char *zProc, /* Entry point. Use "sqlite3_extension_init" if 0 */ char **pzErrMsg /* Put error message here if not 0 */);
int sqlite3_enable_load_extension(sqlite3 *db, int onoff);
int sqlite3_declare_vtab(sqlite3 *db, const char *zSQL);
int sqlite3_blob_open( sqlite3 *db, const char *zDb, const char *zTable, const char *zColumn, sqlite3_int64 iRow, int flags, sqlite3_blob **ppBlob);
int sqlite3_blob_read(sqlite3_blob *pBlob, void *z, int n, int iOffset);
int sqlite3_blob_write(sqlite3_blob *pBlob, const void *z, int n, int iOffset);
int sqlite3_mutex_try(sqlite3_mutex *p);
sqlite3_backup *sqlite3_backup_init( sqlite3 *pDest, const char *zDestName, sqlite3 *pSource, const char *zSourceName);
int __xxx_strcmp(const char *z1, const char *z2);
int sqlite3_stricmp(const char *z1, const char *z2);
int sqlite3_strglob(const char *zGlobPattern, const char *zString);
int sqlite3_vtab_on_conflict(sqlite3 *db);
int sqlite3_snapshot_get( sqlite3 *db, const char *zSchema, sqlite3_snapshot **ppSnapshot);
int sqlite3_snapshot_recover(sqlite3 *db, const char *zDb);
int statfs(const char *path, struct statfs *buf);
int statvfs(const char *path, struct statvfs *buf);
int abs(int x);
int atoi(const char *arg);
long atol(const char *arg);
long long atoll(const char *arg);
int putenv(char *cmd);
int rand(void);
long random(void);
double drand48(void);
long lrand48(void);
long mrand48(void);
double erand48(unsigned short xsubi[3]);
long nrand48(unsigned short xsubi[3]);
long seed48(unsigned short seed16v[3]);
int setenv(const char *key, const char *val, int flag);
int system(const char *cmd);
void Tcl_Panic(const char *format, ...);
void panic(const char *format, ...);
int dup(int oldd);
int dup2(int oldd, int newdd);
int fchdir(int fd);
pid_t getpgid(pid_t pid);
char *getwd(char *buf);
ssize_t read(int fd, void *buf, size_t nbytes);
ssize_t __read_chk(int fd, void *buf, size_t nbytes, size_t buflen);
int readlink(const char *path, char *buf, int buf_size);
int setpgid(pid_t pid, pid_t pgid);
int symlink(const char *path1, const char *path2);
struct utmp *pututline(struct utmp *ut);
struct utmp *getutxline(struct utmp *ut);
struct utmp *pututxline(struct utmp *ut);
VOS_INT32 VOS_sprintf(VOS_CHAR * s, const VOS_CHAR * format, ... );
VOS_INT32 VOS_sprintf_Safe( VOS_CHAR * s, VOS_UINT32 uiDestLen, const VOS_CHAR * format, ... );
VOS_VOID * VOS_MemCpy_Safe(VOS_VOID * dst, VOS_SIZE_T dstSize, const VOS_VOID *src, VOS_SIZE_T num);
VOS_CHAR * VOS_strcpy_Safe(VOS_CHAR *dst, VOS_SIZE_T dstsz, const VOS_CHAR *src);
VOS_CHAR * VOS_StrCpy_Safe(VOS_CHAR *dst, VOS_SIZE_T dstsz, const VOS_CHAR *src);
VOS_CHAR * VOS_StrNCpy_Safe( VOS_CHAR *dst, VOS_SIZE_T dstsz, const VOS_CHAR *src, VOS_SIZE_T count);
VOS_UINT32 VOS_strlen(const VOS_CHAR *s);
VOS_UINT32 VOS_StrLen(const VOS_CHAR *s);
