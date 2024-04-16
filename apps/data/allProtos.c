Oem_Debug_Assert(int expression, char *f_assertcmd, char* f_file, int line);
checkDevParam(const char *assert, int v1, int v2, int v3, const char *file, int line);
assertfail(DevAssertFailType assertFailType, const char *cond, const char *file, int line);
utilsAssertFail(const char *cond, const char *file, signed short line, unsigned char allowDiag);
archive_read_data(struct archive *archive, void *buff, size_t len);
__assert_fail(const char *assertion, const char *file,
                   unsigned int line, const char *function);
_assert(const char *a, const char *b, int c);
__promise(int exp);
SysAllocString(const OLECHAR *psz);
SysAllocStringByteLen(LPCSTR psz, unsigned int len);
SysAllocStringLen(const OLECHAR *pch, unsigned int len);
SysReAllocString(BSTR *pbstr, const OLECHAR *psz);
SysReAllocStringLen(BSTR *pbstr, const OLECHAR *psz, unsigned int len);
SysFreeString(BSTR bstrString);
SysStringLen(BSTR bstr);
getch(void);
_getch(void);
memory_full(void);
_CrtDbgReport(
   int reportType,
   const char *filename,
   int linenumber,
   const char *moduleName,
   const char *format,
   ...
);
_CrtDbgReportW(
   int reportType,
   const wchar_t *filename,
   int linenumber,
   const wchar_t *moduleName,
   const wchar_t *format,
   ...
);
crypt(const char *key, const char *salt);
crypt_r(const char *key, const char *salt, struct crypt_data *data);
setkey(const char *key);
setkey_r(const char *key, struct crypt_data *data);
ecb_crypt(char *key, char *data, unsigned datalen, unsigned mode);
cbc_crypt(char *key, char *data, unsigned datalen, unsigned mode, char *ivec);
des_setparity(char *key);
passwd2des(char *passwd, char *key);
xencrypt(char *secret, char *passwd);
xdecrypt(char *secret, char *passwd);
isalnum(int c);
isalpha(int c);
isascii(int c);
isblank(int c);
iscntrl(int c);
isdigit(int c);
isgraph(int c);
islower(int c);
isprint(int c);
ispunct(int c);
isspace(int c);
isupper(int c);
isxdigit(int c);
*__ctype_b_loc(void);
closedir(DIR *file);
opendir(const char *file);
readdir(DIR *file);
dlclose(void *handle);
dlopen(const char *file, int mode);
dlsym(void *handle, const char *symbol);
DebugAssertEnabled (
  void
  );
CpuDeadLoop (
  void
  );
AllocatePages (
  uintptr_t  Pages
  );
AllocateRuntimePages (
  uintptr_t  Pages
  );
AllocateReservedPages (
  uintptr_t  Pages
  );
FreePages (
  void       *Buffer,
  uintptr_t  Pages
  );
AllocateAlignedPages (
  uintptr_t  Pages,
  uintptr_t  Alignment
  );
AllocateAlignedRuntimePages (
  uintptr_t  Pages,
  uintptr_t  Alignment
  );
AllocateAlignedReservedPages (
  uintptr_t  Pages,
  uintptr_t  Alignment
  );
FreeAlignedPages (
  void   *Buffer,
  uintptr_t  Pages
  );
AllocatePool (
  uintptr_t  AllocationSize
  );
AllocateRuntimePool (
  uintptr_t  AllocationSize
  );
AllocateReservedPool (
  uintptr_t  AllocationSize
  );
AllocateZeroPool (
  uintptr_t  AllocationSize
  );
AllocateRuntimeZeroPool (
  uintptr_t  AllocationSize
  );
AllocateReservedZeroPool (
  uintptr_t  AllocationSize
  );
AllocateCopyPool (
  uintptr_t       AllocationSize,
  const void      *Buffer
  );
AllocateRuntimeCopyPool (
  uintptr_t       AllocationSize,
  const void      *Buffer
  );
AllocateReservedCopyPool (
  uintptr_t       AllocationSize,
  const void      *Buffer
  );
ReallocatePool (
  uintptr_t  OldSize,
  uintptr_t  NewSize,
  void       *OldBuffer
  );
ReallocateRuntimePool (
  uintptr_t  OldSize,
  uintptr_t  NewSize,
  void       *OldBuffer
  );
ReallocateReservedPool (
  uintptr_t  OldSize,
  uintptr_t  NewSize,
  void       *OldBuffer
  );
FreePool (
  void   *Buffer
  );
err(int eval, const char *fmt, ...);
verr(int eval, const char *fmt, va_list args);
errx(int eval, const char *fmt, ...);
verrx(int eval, const char *fmt, va_list args);
warn(const char *fmt, ...);
vwarn(const char *fmt, va_list args);
warnx(const char *fmt, ...);
vwarnx(const char *fmt, va_list args);
__errno_location(void);
error(int status, int errnum, const char *fmt, ...);
creat(const char *name, mode_t mode);
creat64(const char *name, mode_t mode);
fcntl(int fd, int cmd, ...);
open(const char *name, int flags, ...);
open64(const char *name, int flags, ...);
ftw(const char *path,
        int (*fn)(const char *, const struct stat *ptr, int flag),
        int ndirs);
ftw64(const char *path,
        int (*fn)(const char *, const struct stat *ptr, int flag),
        int ndirs);
nftw(const char *path,
         int (*fn)(const char *, const struct stat *, int, struct FTW *),
         int fd_limit, int flags);
nftw64(const char *path,
         int (*fn)(const char *, const struct stat *, int, struct FTW *),
         int fd_limit, int flags);
gcry_cipher_setkey(gcry_cipher_hd_t h , const void *key , size_t l);
gcry_cipher_setiv (gcry_cipher_hd_t h, const void *key, size_t l);
gcry_cipher_setctr (gcry_cipher_hd_t h, const void *ctr, size_t l);
gcry_cipher_authenticate (gcry_cipher_hd_t h, const void *abuf, size_t abuflen);
gcry_cipher_checktag (gcry_cipher_hd_t h, const void *tag, size_t taglen);
gcry_md_setkey (gcry_md_hd_t h, const void *key, size_t keylen);
g_free (gpointer ptr);
g_strfreev(const gchar **str_array);
g_async_queue_push (GAsyncQueue *queue, gpointer data);
g_queue_push_tail (GQueue *queue, gpointer data);
g_source_set_callback (struct GSource *source, GSourceFunc func, gpointer data, GDestroyNotify notify);
g_thread_pool_push (GThreadPool *pool, gpointer data, GError **error);
g_list_append(GList *list, gpointer data);
g_list_prepend(GList *list, gpointer data);
g_list_insert(GList *list, gpointer data, gint position);
g_list_insert_before(GList *list, gpointer data, gint position);
g_list_insert_sorted(GList *list, gpointer data, GCompareFunc func);
g_slist_append(GSList *list, gpointer data);
g_slist_prepend(GSList *list, gpointer data);
g_slist_insert(GSList *list, gpointer data, gint position);
g_slist_insert_before(GSList *list, gpointer data, gint position);
g_slist_insert_sorted(GSList *list, gpointer data, GCompareFunc func);
g_array_append_vals(GArray *array, gconstpointer data, guint len);
g_array_prepend_vals(GArray *array, gconstpointer data, guint len);
g_array_insert_vals(GArray *array, gconstpointer data, guint len);
g_strdup (const gchar *str);
g_strdup_printf (const gchar *format, ...);
g_malloc0_n (gsize n_blocks, gsize n_block_bytes);
g_malloc (gsize n_bytes);
g_malloc0 (gsize n_bytes);
g_malloc_n (gsize n_blocks, gsize n_block_bytes);
g_try_malloc0_n (gsize n_blocks, gsize n_block_bytes);
g_try_malloc (gsize n_bytes);
g_try_malloc0 (gsize n_bytes);
g_try_malloc_n (gsize n_blocks, gsize n_block_bytes);
g_random_int (void);
g_realloc(gpointer mem, gsize n_bytes);
g_try_realloc(gpointer mem, gsize n_bytes);
g_realloc_n(gpointer mem, gsize n_blocks, gsize n_block_bytes);
g_try_realloc_n(gpointer mem, gsize n_blocks, gsize n_block_bytes);
klogctl(int type, char *bufp, int len);
g_list_length(GList *list);
inet_ntoa(struct in_addr in);
htonl(uint32_t hostlong);
htons(uint16_t hostshort);
ntohl(uint32_t netlong);
ntohs(uint16_t netshort);
ioctl(int d, int request, ...);
GetStringUTFChars(JNIEnv *env, jstring string, jboolean *isCopy);
NewObjectArray(JNIEnv *env, jsize length, jclass elementClass, jobject initialElement);
NewBooleanArray(JNIEnv *env, jsize length);
NewByteArray(JNIEnv *env, jsize length);
NewCharArray(JNIEnv *env, jsize length);
NewShortArray(JNIEnv *env, jsize length);
NewIntArray(JNIEnv *env, jsize length);
NewLongArray(JNIEnv *env, jsize length);
NewFloatArray(JNIEnv *env, jsize length);
NewDoubleArray(JNIEnv *env, jsize length);
json_generator_new();
json_generator_set_root (struct JsonGenerator *generator,
                         struct JsonNode *node);
json_generator_get_root (struct JsonGenerator *generator);
json_generator_set_pretty (struct JsonGenerator *generator,
                           gboolean is_pretty);
json_generator_set_indent (struct JsonGenerator *generator,
                           guint indent_level);
json_generator_get_indent (struct JsonGenerator *generator);
json_generator_get_indent_char (struct JsonGenerator *generator);
json_generator_to_file (struct JsonGenerator *generator,
                        const gchar *filename,
                        struct GError **error);
json_generator_to_data (struct JsonGenerator *generator,
                        gsize *length);
json_generator_to_stream (struct JsonGenerator *generator,
                          struct GOutputStream *stream,
                          struct GCancellable *cancellable,
                          struct GError **error);
basename(char *path);
dirname(char *path);
textdomain(const char *domainname);
bindtextdomain(const char *domainname, const char *dirname);
kcalloc(size_t n, size_t size, gfp_t flags);
kmalloc_array(size_t n, size_t size, gfp_t flags);
kzalloc_node(size_t size, gfp_t flags, int node);
kmalloc(size_t size, gfp_t flags);
kzalloc(size_t size, gfp_t flags);
__kmalloc(size_t size, gfp_t flags);
__kmalloc_node(size_t size, gfp_t flags, int node);
kmemdup(const void *src, size_t len, gfp_t gfp);
memdup_user(const void /*__user*/ *src, size_t len);
kstrdup(const char *s, gfp_t gfp);
kasprintf(gfp_t gfp, const char *fmt, ...);
kfree(const void *x);
kzfree(const void *x);
_raw_spin_lock(raw_spinlock_t *mutex);
_raw_spin_unlock(raw_spinlock_t *mutex);
_raw_spin_trylock(raw_spinlock_t *mutex);
__raw_spin_lock(raw_spinlock_t *mutex);
__raw_spin_unlock(raw_spinlock_t *mutex);
__raw_spin_trylock(raw_spinlock_t *mutex);
vmalloc(unsigned long size);
vfree(const void *addr);
vrealloc(void *ptr, size_t size);
vdup(vchar_t* src);
tty_register_driver(struct tty_driver *driver);
tty_unregister_driver(struct tty_driver *driver);
device_create_file(struct device *dev, struct device_attribute *dev_attr);
device_remove_file(struct device *dev, struct device_attribute *dev_attr);
platform_device_register(struct platform_device *pdev);
platform_device_unregister(struct platform_device *pdev);
platform_driver_register(struct platform_driver *drv);
platform_driver_unregister(struct platform_driver *drv);
misc_register(struct miscdevice *misc);
misc_deregister(struct miscdevice *misc);
input_register_device(struct input_dev *dev);
input_unregister_device(struct input_dev *dev);
input_allocate_device(void);
input_free_device(struct input_dev *dev);
rfkill_register(struct rfkill *rfkill);
rfkill_unregister(struct rfkill *rfkill);
snd_soc_register_codec(struct device *dev,
      const struct snd_soc_codec_driver *codec_drv,
      struct snd_soc_dai_driver *dai_drv,
      int num_dai);
snd_soc_unregister_codec(struct device *dev);
class_create(void *owner, void *name);
__class_create(void *owner, void *name);
class_destroy(struct class *cls);
platform_device_alloc(const char *name, int id);
platform_device_put(struct platform_device *pdev);
rfkill_alloc(struct rfkill *rfkill, bool blocked);
rfkill_destroy(struct rfkill *rfkill);
ioremap(struct phys_addr_t offset, unsigned long size);
iounmap(void *addr);
clk_enable(struct clk *clk);
clk_disable(struct clk *clk);
regulator_get(struct device *dev, const char *id);
regulator_put(struct regulator *regulator);
regulator_enable(struct regulator *regulator);
regulator_disable(struct regulator *regulator);
create_workqueue(void *name);
create_singlethread_workqueue(void *name);
create_freezable_workqueue(void *name);
destroy_workqueue(struct workqueue_struct *wq);
add_timer (struct timer_list *timer);
del_timer(struct timer_list *timer);
kthread_create(int(*threadfn)(void *data), void *data, const char namefmt[]);
put_task_struct(struct task_struct *t);
alloc_tty_driver(int lines);
__alloc_tty_driver(int lines);
put_tty_driver(struct tty_driver *d);
luaL_error(struct lua_State *L, const char *fmt, ...);
mmap(void *addr, size_t len, int prot, int flags,
int fildes, off_t off);
munmap(void *addr, size_t len);
setmntent(const char *filename, const char *type);
mount(const char *source, const char *target, const char *filesystemtype,
          unsigned long mountflags, const void *data);
umount(const char *target);
mutex_lock(struct mutex *lock);
mutex_unlock(struct mutex *lock);
mutex_lock_nested(struct mutex *lock, unsigned int subclass);
getaddrinfo(const char *node,
                const char *service,
                const struct addrinfo *hints,
                struct addrinfo **res);
freeaddrinfo(struct addrinfo *res);
catopen(const char *fname, int flag);
SHA256_Init(SHA256_CTX *sha);
SHA256_Update(SHA256_CTX *sha, const void *data, size_t len);
SHA256_Final(uint8_t out[SHA256_DIGEST_LENGTH], SHA256_CTX *sha);
SHA384_Init(SHA512_CTX *sha);
SHA384_Update(SHA512_CTX *sha, const void *data, size_t len);
SHA384_Final(uint8_t out[SHA384_DIGEST_LENGTH], SHA512_CTX *sha);
SHA512_Init(SHA512_CTX *sha);
SHA512_Update(SHA512_CTX *sha, const void *data, size_t len);
SHA512_Final(uint8_t out[SHA512_DIGEST_LENGTH], SHA512_CTX *sha);
CMS_add0_recipient_key(CMS_ContentInfo *cms, int nid, unsigned char *key, size_t keylen, unsigned char *id, size_t idlen, ASN1_GENERALIZEDTIME *date, ASN1_OBJECT *otherTypeId, ASN1_TYPE *otherType);
EVP_PKEY_new_mac_key(int type, ENGINE *e, const unsigned char *key, int keylen);
EVP_PKEY_new_raw_private_key(int type, ENGINE *e, const unsigned char *key, size_t keylen);
EVP_PKEY_new_raw_public_key(int type, ENGINE *e, const unsigned char *key, size_t keylen);
CMS_RecipientInfo_set0_key(CMS_RecipientInfo *ri, unsigned char *key, size_t keylen);
CTLOG_new_from_base64(CTLOG ** ct_log, const char *pkey_base64, const char *name);
DH_compute_key(unsigned char *key, BIGNUM *pub_key, DH *dh);
compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh);
EVP_BytesToKey(const EVP_CIPHER *type, const EVP_MD *md, const unsigned char *salt, const unsigned char *data, int datal, int count, unsigned char *key, unsigned char *iv);
EVP_CIPHER_CTX_rand_key(EVP_CIPHER_CTX *ctx, unsigned char *key);
EVP_CipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, const unsigned char *key, const unsigned char *iv, int enc);
EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv, int enc);
EVP_DecryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, const unsigned char *key, const unsigned char *iv);
EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv);
EVP_EncryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, const unsigned char *key, const unsigned char *iv);
EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv);
EVP_PKEY_CTX_set1_hkdf_key(EVP_PKEY_CTX *pctx, unsigned char *key, int keylen);
EVP_PKEY_CTX_set_mac_key(EVP_PKEY_CTX *ctx, unsigned char *key, int len);
EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
BIO_set_cipher(BIO *b, const EVP_CIPHER *cipher, unsigned char *key, unsigned char *iv, int enc);
EVP_PKEY_new_CMAC_key(ENGINE *e, const unsigned char *priv, size_t len, const EVP_CIPHER *cipher);
EVP_OpenInit(EVP_CIPHER_CTX *ctx, EVP_CIPHER *type, unsigned char *ek, int ekl, unsigned char *iv, EVP_PKEY *priv);
EVP_PKEY_get_raw_private_key(const EVP_PKEY *pkey, unsigned char *priv, size_t *len);
EVP_SealInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, unsigned char **ek, int *ekl, unsigned char *iv, EVP_PKEY **pubk, int npubk);
BF_cbc_encrypt(const unsigned char *in, unsigned char *out, long length, BF_KEY *schedule, unsigned char *ivec, int enc);
BF_cfb64_encrypt(const unsigned char *in, unsigned char *out, long length, BF_KEY *schedule, unsigned char *ivec, int *num, int enc);
BF_ofb64_encrypt(const unsigned char *in, unsigned char *out, long length, BF_KEY *schedule, unsigned char *ivec, int *num);
get_priv_key(const EVP_PKEY *pk, unsigned char *priv, size_t *len);
set_priv_key(EVP_PKEY *pk, const unsigned char *priv, size_t len);
DES_crypt(const char *buf, const char *salt);
DES_fcrypt(const char *buf, const char *salt, char *ret);
EVP_PKEY_CTX_set1_hkdf_salt(EVP_PKEY_CTX *pctx, unsigned char *salt, int saltlen);
PKCS5_PBKDF2_HMAC(const char *pass, int passlen, const unsigned char *salt, int saltlen, int iter, const EVP_MD *digest, int keylen, unsigned char *out);
PKCS5_PBKDF2_HMAC_SHA1(const char *pass, int passlen, const unsigned char *salt, int saltlen, int iter, int keylen, unsigned char *out);
PKCS12_newpass(PKCS12 *p12, const char *oldpass, const char *newpass);
PKCS12_parse(PKCS12 *p12, const char *pass, EVP_PKEY **pkey, X509 **cert, STACK_OF(X509) **ca);
PKCS12_create(const char *pass, const char *name, EVP_PKEY *pkey, X509 *cert, STACK_OF(X509) *ca, int nid_key, int nid_cert, int iter, int mac_iter, int keytype);
EVP_PKEY_get_raw_public_key(const EVP_PKEY *pkey, unsigned char *pub, size_t *len);
get_pub_key(const EVP_PKEY *pk, unsigned char *pub, size_t *len);
set_pub_key(EVP_PKEY *pk, const unsigned char *pub, size_t len);
poll(struct pollfd *fds, nfds_t nfds, int timeout);
PQconnectdb(const char *conninfo);
PQsetdbLogin(const char *pghost, const char *pgport, const char *pgoptions,
                        const char *pgtty, const char *dbName, const char *login, const char *pwd);
PQconnectStart(const char *conninfo);
PR_fprintf(struct PRFileDesc* stream, const char *format, ...);
PR_snprintf(char *str, size_t size, const char *format, ...);
pthread_exit(void *value_ptr);
pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr);
pthread_mutex_destroy(pthread_mutex_t *mutex);
pthread_mutex_lock(pthread_mutex_t *mutex);
pthread_mutex_unlock(pthread_mutex_t *mutex);
pthread_mutex_trylock(pthread_mutex_t *mutex);
pthread_spin_lock(pthread_spinlock_t *mutex);
pthread_spin_unlock(pthread_spinlock_t *mutex);
pthread_spin_trylock(pthread_spinlock_t *mutex);
pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                          void *(*start_routine) (void *), void *arg);
__pthread_cleanup_routine (struct __pthread_cleanup_frame *__frame);
getpwnam(const char *name);
getpwuid(uid_t uid);
Py_FatalError(const char *message);
OEM_Malloc(uint32 uSize);
aee_malloc(uint32 dwSize);
OEM_Free(void *p);
aee_free(void *p);
OEM_Realloc(void *p, uint32 uSize);
aee_realloc(void *p, uint32 dwSize);
err_fatal_core_dump(unsigned int line, const char *file_name, const char *format);
quotactl(int cmd, char *spec, int id, caddr_t addr);
sem_wait (sem_t *_sem);
sem_post (sem_t *_sem);
longjmp(jmp_buf env, int value);
siglongjmp(sigjmp_buf env, int val);
setjmp(jmp_buf env);
sigsetjmp(sigjmp_buf env, int savesigs);
pal_MemFreeDebug(void** mem, char* file, int line);
pal_MemAllocTrack(int mid, int size, char* file, int line);
pal_MemAllocGuard(int mid, int size);
pal_MemAllocInternal(int mid, int size, char* file, int line);
raise (int sig);
kill(pid_t pid, int sig);
connect(int sockfd, const struct sockaddr *addr, socklen_t len);
getpeername(int sockfd, struct sockaddr *addr, socklen_t
       *addrlen);
getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
getsockopt(int sockfd, int level, int optname,
                      void *optval, socklen_t *optlen);
listen(int sockfd, int backlog);
accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
recv(int s, void *buf, size_t len, int flags);
recvfrom(int s, void *buf, size_t len, int flags,
                 struct sockaddr *from, socklen_t *fromlen);
__recvfrom_chk(int s, void *buf, size_t len, size_t buflen, int flags,
                 struct sockaddr *from, socklen_t *fromlen);
recvmsg(int s, struct msghdr *msg, int flags);
send(int s, const void *buf, size_t len, int flags);
sendto(int s, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
sendmsg(int s, const struct msghdr*msg, int flags);
setsockopt(int socket, int level, int option_name,
       const void *option_value, socklen_t option_len);
shutdown(int socket, int how);
socket(int domain, int type, int protocol);
sf_get_values(int min, int max);
sf_get_bool(void);
sf_get_values_with_min(int min);
sf_get_values_with_max(int max);
sf_get_some_nonnegative_int(void);
sf_get_some_int_to_check(void);
sf_get_uncontrolled_ptr(void);
sf_set_trusted_sink_nonnegative_int(int n);
__alloc_some_string(void);
__get_nonfreeable(void);
__get_nonfreeable_tainted(void);
__get_nonfreeable_possible_null(void);
__get_nonfreeable_tainted_possible_null(void);
__get_nonfreeable_not_null(void);
__get_nonfreeable_string(void);
__get_nonfreeable_possible_null_string(void);
__get_nonfreeable_not_null_string(void);
__get_nonfreeable_tainted_possible_null_string(void);
sqlite3_libversion(void);
sqlite3_sourceid(void);
sqlite3_libversion_number(void);
sqlite3_compileoption_used(const char *zOptName);
sqlite3_compileoption_get(int N);
sqlite3_threadsafe(void);
__close(sqlite3 *db);
sqlite3_close(sqlite3 *db);
sqlite3_close_v2(sqlite3 *db);
sqlite3_exec(
    sqlite3 *db,                                /* An open database */
    const char *zSql,                           /* SQL to be evaluated */
    int (*xCallback)(void*,int,char**,char**),  /* Callback function */
    void *pArg,                                 /* 1st argument to callback */
    char **pzErrMsg                             /* Error msg written here */
);
sqlite3_initialize(void);
sqlite3_shutdown(void);
sqlite3_os_init(void);
sqlite3_os_end(void);
sqlite3_config(int stub, ...);
sqlite3_db_config(sqlite3 *db, int op, ...);
sqlite3_extended_result_codes(sqlite3 *db, int onoff);
sqlite3_last_insert_rowid(sqlite3 *db);
sqlite3_set_last_insert_rowid(sqlite3 *db, sqlite3_int64 rowid);
sqlite3_changes(sqlite3 *db);
sqlite3_total_changes(sqlite3 *db);
sqlite3_interrupt(sqlite3 *db);
__complete(const char *sql);
sqlite3_complete(const char *sql);
sqlite3_complete16(const void *sql);
sqlite3_busy_handler(
    sqlite3 *db,
    int (*xBusy)(void*,int),
    void *pArg
);
sqlite3_busy_timeout(sqlite3 *db, int ms);
sqlite3_get_table(
    sqlite3 *db,          /* An open database */
    const char *zSql,     /* SQL to be evaluated */
    char ***pazResult,    /* Results of the query */
    int *pnRow,           /* Number of result rows written here */
    int *pnColumn,        /* Number of result columns written here */
    char **pzErrMsg       /* Error msg written here */
);
sqlite3_free_table(char **result);
__mprintf(const char *zFormat);
sqlite3_mprintf(const char *zFormat, ...);
sqlite3_vmprintf(const char *zFormat, va_list ap);
__snprintf(int n, char *zBuf, const char *zFormat);
sqlite3_snprintf(int n, char *zBuf, const char *zFormat, ...);
sqlite3_vsnprintf(int n, char *zBuf, const char *zFormat, va_list ap);
__malloc(sqlite3_int64 size);
sqlite3_malloc(int size);
sqlite3_malloc64(sqlite3_uint64 size);
__realloc(void *ptr, sqlite3_uint64 size);
sqlite3_realloc(void *ptr, int size);
sqlite3_realloc64(void *ptr, sqlite3_uint64 size);
sqlite3_free(void *ptr);
sqlite3_msize(void *ptr);
sqlite3_memory_used(void);
sqlite3_memory_highwater(int resetFlag);
sqlite3_randomness(int N, void *P);
sqlite3_set_authorizer(
    sqlite3 *db,
    int (*xAuth)(void*,int,const char*,const char*,const char*,const char*),
    void *pUserData
);
sqlite3_trace(
    sqlite3 *db,
    void (*xTrace)(void*,const char*),
    void *pArg
);
sqlite3_profile(
    sqlite3 *db,
    void (*xProfile)(void*,const char*,sqlite3_uint64),
    void *pArg
);
sqlite3_trace_v2(
    sqlite3 *db,
    unsigned uMask,
    int(*xCallback)(unsigned,void*,void*,void*),
    void *pCtx
);
sqlite3_progress_handler(
    sqlite3 *db,
    int nOps,
    int (*xProgress)(void*),
    void *pArg
);
__sqlite3_open(
    const char *filename,
    sqlite3 **ppDb
);
sqlite3_open(
    const char *filename,
    sqlite3 **ppDb
);
sqlite3_open16(
    const void *filename,
    sqlite3 **ppDb
);
sqlite3_open_v2(
    const char *filename,
    sqlite3 **ppDb,
    int flags,
    const char *zVfs
);
sqlite3_uri_parameter(const char *zFilename, const char *zParam);
sqlite3_uri_boolean(const char *zFilename, const char *zParam, int bDefault);
sqlite3_uri_int64(const char *zFilename, const char *zParam, sqlite3_int64 bDflt);
sqlite3_errcode(sqlite3 *db);
sqlite3_extended_errcode(sqlite3 *db);
sqlite3_errmsg(sqlite3 *db);
sqlite3_errmsg16(sqlite3 *db);
sqlite3_errstr(int rc);
sqlite3_limit(sqlite3 *db, int id, int newVal);
__prepare(
    sqlite3 *db,
    const char *zSql,
    int nByte,
    sqlite3_stmt **ppStmt,
    const char **pzTail
);
sqlite3_prepare(
    sqlite3 *db,
    const char *zSql,
    int nByte,
    sqlite3_stmt **ppStmt,
    const char **pzTail
);
sqlite3_prepare_v2(
    sqlite3 *db,
    const char *zSql,
    int nByte,
    sqlite3_stmt **ppStmt,
    const char **pzTail
);
sqlite3_prepare_v3(
    sqlite3 *db,
    const char *zSql,
    int nByte,
    unsigned int prepFlags,
    sqlite3_stmt **ppStmt,
    const char **pzTail
);
sqlite3_prepare16(
    sqlite3 *db,
    const void *zSql,
    int nByte,
    sqlite3_stmt **ppStmt,
    const void **pzTail
);
sqlite3_prepare16_v2(
    sqlite3 *db,
    const void *zSql,
    int nByte,
    sqlite3_stmt **ppStmt,
    const void **pzTail
);
sqlite3_prepare16_v3(
    sqlite3 *db,
    const void *zSql,
    int nByte,
    unsigned int prepFlags,
    sqlite3_stmt **ppStmt,
    const void **pzTail
);
sqlite3_sql(sqlite3_stmt *pStmt);
sqlite3_expanded_sql(sqlite3_stmt *pStmt);
sqlite3_stmt_readonly(sqlite3_stmt *pStmt);
sqlite3_stmt_busy(sqlite3_stmt *pStmt);
sqlite3_bind_blob(
    sqlite3_stmt *pStmt,
    int i,
    const void *zData,
    int nData,
    void (*xDel)(void*)
);
sqlite3_bind_blob64(
    sqlite3_stmt *pStmt,
    int i,
    const void *zData,
    sqlite3_uint64 nData,
    void (*xDel)(void*)
);
sqlite3_bind_double(sqlite3_stmt *pStmt, int i, double rValue);
sqlite3_bind_int(sqlite3_stmt *pStmt, int i, int iValue);
sqlite3_bind_int64(sqlite3_stmt *pStmt, int i, sqlite3_int64 iValue);
sqlite3_bind_null(sqlite3_stmt *pStmt, int i);
__bind_text(
    sqlite3_stmt *pStmt,
    int i,
    const char *zData,
    int nData,
    void (*xDel)(void*)
);
sqlite3_bind_text(
    sqlite3_stmt *pStmt,
    int i,
    const char *zData,
    int nData,
    void (*xDel)(void*)
);
sqlite3_bind_text16(
    sqlite3_stmt *pStmt,
    int i,
    const char *zData,
    int nData,
    void (*xDel)(void*)
);
sqlite3_bind_text64(
    sqlite3_stmt *pStmt,
    int i,
    const char *zData,
    sqlite3_uint64 nData,
    void (*xDel)(void*),
    unsigned char enc
);
sqlite3_bind_value(sqlite3_stmt *pStmt, int i, const sqlite3_value *pValue);
sqlite3_bind_pointer(
    sqlite3_stmt *pStmt,
    int i,
    void *pPtr,
    const char *zPTtype,
    void (*xDestructor)(void*)
);
__bind_zeroblob(sqlite3_stmt *pStmt, int i, sqlite3_uint64 n);
sqlite3_bind_zeroblob(sqlite3_stmt *pStmt, int i, int n);
sqlite3_bind_zeroblob64(sqlite3_stmt *pStmt, int i, sqlite3_uint64 n);
sqlite3_bind_parameter_count(sqlite3_stmt *pStmt);
sqlite3_bind_parameter_name(sqlite3_stmt *pStmt, int i);
sqlite3_bind_parameter_index(sqlite3_stmt *pStmt, const char *zName);
sqlite3_clear_bindings(sqlite3_stmt *pStmt);
sqlite3_column_count(sqlite3_stmt *pStmt);
__column_name(sqlite3_stmt *pStmt, int N);
sqlite3_column_name(sqlite3_stmt *pStmt, int N);
sqlite3_column_name16(sqlite3_stmt *pStmt, int N);
sqlite3_column_database_name(sqlite3_stmt *pStmt, int N);
sqlite3_column_database_name16(sqlite3_stmt *pStmt, int N);
sqlite3_column_table_name(sqlite3_stmt *pStmt, int N);
sqlite3_column_table_name16(sqlite3_stmt *pStmt, int N);
sqlite3_column_origin_name(sqlite3_stmt *pStmt, int N);
sqlite3_column_origin_name16(sqlite3_stmt *pStmt, int N);
sqlite3_column_decltype(sqlite3_stmt *pStmt, int N);
sqlite3_column_decltype16(sqlite3_stmt *pStmt, int N);
sqlite3_step(sqlite3_stmt *pStmt);
sqlite3_data_count(sqlite3_stmt *pStmt);
sqlite3_column_blob(sqlite3_stmt *pStmt, int iCol);
sqlite3_column_double(sqlite3_stmt *pStmt, int iCol);
sqlite3_column_int(sqlite3_stmt *pStmt, int iCol);
sqlite3_column_int64(sqlite3_stmt *pStmt, int iCol);
sqlite3_column_text(sqlite3_stmt *pStmt, int iCol);
sqlite3_column_text16(sqlite3_stmt *pStmt, int iCol);
sqlite3_column_value(sqlite3_stmt *pStmt, int iCol);
sqlite3_column_bytes(sqlite3_stmt *pStmt, int iCol);
sqlite3_column_bytes16(sqlite3_stmt *pStmt, int iCol);
sqlite3_column_type(sqlite3_stmt *pStmt, int iCol);
sqlite3_finalize(sqlite3_stmt *pStmt);
sqlite3_reset(sqlite3_stmt *pStmt);
__create_function(
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
sqlite3_create_function(
    sqlite3 *db,
    const char *zFunctionName,
    int nArg,
    int eTextRep,
    void *pApp,
    void (*xFunc)(sqlite3_context*,int,sqlite3_value**),
    void (*xStep)(sqlite3_context*,int,sqlite3_value**),
    void (*xFinal)(sqlite3_context*)
);
sqlite3_create_function16(
    sqlite3 *db,
    const void *zFunctionName,
    int nArg,
    int eTextRep,
    void *pApp,
    void (*xFunc)(sqlite3_context*,int,sqlite3_value**),
    void (*xStep)(sqlite3_context*,int,sqlite3_value**),
    void (*xFinal)(sqlite3_context*)
);
sqlite3_create_function_v2(
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
sqlite3_aggregate_count(sqlite3_context *pCtx);
sqlite3_expired(sqlite3_stmt *pStmt);
sqlite3_transfer_bindings(sqlite3_stmt *pFromStmt, sqlite3_stmt *pToStmt);
sqlite3_global_recover(void);
sqlite3_thread_cleanup(void);
sqlite3_memory_alarm(
    void(*xCallback)(void *pArg, sqlite3_int64 used,int N),
    void *pArg,
    sqlite3_int64 iThreshold
);
sqlite3_value_blob(sqlite3_value *pVal);
sqlite3_value_double(sqlite3_value *pVal);
sqlite3_value_int(sqlite3_value *pVal);
sqlite3_value_int64(sqlite3_value *pVal);
sqlite3_value_pointer(sqlite3_value *pVal, const char *zPType);
sqlite3_value_text(sqlite3_value *pVal);
sqlite3_value_text16(sqlite3_value *pVal);
sqlite3_value_text16le(sqlite3_value *pVal);
sqlite3_value_text16be(sqlite3_value *pVal);
sqlite3_value_bytes(sqlite3_value *pVal);
sqlite3_value_bytes16(sqlite3_value *pVal);
sqlite3_value_type(sqlite3_value *pVal);
sqlite3_value_numeric_type(sqlite3_value *pVal);
sqlite3_value_subtype(sqlite3_value *pVal);
sqlite3_value_dup(const sqlite3_value *pVal);
sqlite3_value_free(sqlite3_value *pVal);
sqlite3_aggregate_context(sqlite3_context *pCtx, int nBytes);
sqlite3_user_data(sqlite3_context *pCtx);
sqlite3_context_db_handle(sqlite3_context *pCtx);
sqlite3_get_auxdata(sqlite3_context *pCtx, int N);
sqlite3_set_auxdata(
    sqlite3_context *pCtx,
    int iArg,
    void *pAux,
    void (*xDelete)(void*)
);
sqlite3_result_blob(
    sqlite3_context *pCtx,
    const void *z,
    int n,
    void (*xDel)(void *)
);
sqlite3_result_blob64(
    sqlite3_context *pCtx,
    const void *z,
    sqlite3_uint64 n,
    void (*xDel)(void *)
);
sqlite3_result_double(sqlite3_context *pCtx, double rVal);
__result_error(sqlite3_context *pCtx, const void *z, int n);
sqlite3_result_error(sqlite3_context *pCtx, const char *z, int n);
sqlite3_result_error16(sqlite3_context *pCtx, const void *z, int n);
sqlite3_result_error_toobig(sqlite3_context *pCtx);
sqlite3_result_error_nomem(sqlite3_context *pCtx);
sqlite3_result_error_code(sqlite3_context *pCtx, int errCode);
sqlite3_result_int(sqlite3_context *pCtx, int iVal);
sqlite3_result_int64(sqlite3_context *pCtx, sqlite3_int64 iVal);
sqlite3_result_null(sqlite3_context *pCtx);
__result_text(
    sqlite3_context *pCtx,
    const char *z,
    int n,
    void (*xDel)(void *)
);
sqlite3_result_text(
    sqlite3_context *pCtx,
    const char *z,
    int n,
    void (*xDel)(void *)
);
sqlite3_result_text64(
    sqlite3_context *pCtx,
    const char *z,
    sqlite3_uint64 n,
    void (*xDel)(void *)
);
sqlite3_result_text16(
    sqlite3_context *pCtx,
    const char *z,
    int n,
    void (*xDel)(void *)
);
sqlite3_result_text16le(
    sqlite3_context *pCtx,
    const char *z,
    int n,
    void (*xDel)(void *)
);
sqlite3_result_text16be(
    sqlite3_context *pCtx,
    const char *z,
    int n,
    void (*xDel)(void *)
);
sqlite3_result_value(sqlite3_context *pCtx, sqlite3_value *pValue);
sqlite3_result_pointer(
    sqlite3_context *pCtx,
    void *pPtr,
    const char *zPType,
    void (*xDestructor)(void *)
);
sqlite3_result_zeroblob(sqlite3_context *pCtx, int n);
sqlite3_result_zeroblob64(sqlite3_context *pCtx, sqlite3_uint64 n);
sqlite3_result_subtype(sqlite3_context *pCtx, unsigned int eSubtype);
__create_collation(
    sqlite3 *db,
    const char *zName,
    void *pArg,
    int(*xCompare)(void*,int,const void*,int,const void*),
    void(*xDestroy)(void*)
);
sqlite3_create_collation(
    sqlite3 *db,
    const char *zName,
    int eTextRep,
    void *pArg,
    int(*xCompare)(void*,int,const void*,int,const void*)
);
sqlite3_create_collation_v2(
    sqlite3 *db,
    const char *zName,
    int eTextRep,
    void *pArg,
    int(*xCompare)(void*,int,const void*,int,const void*),
    void(*xDestroy)(void*)
);
sqlite3_create_collation16(
    sqlite3 *db,
    const void *zName,
    int eTextRep,
    void *pArg,
    int(*xCompare)(void*,int,const void*,int,const void*)
);
sqlite3_collation_needed(
    sqlite3 *db,
    void *pCollNeededArg,
    void(*xCollNeeded)(void*,sqlite3*,int eTextRep,const char*)
);
sqlite3_collation_needed16(
    sqlite3 *db,
    void *pCollNeededArg,
    void(*xCollNeeded16)(void*,sqlite3*,int eTextRep,const void*)
);
sqlite3_sleep(int ms);
sqlite3_get_autocommit(sqlite3 *db);
sqlite3_db_handle(sqlite3_stmt *pStmt);
sqlite3_db_filename(sqlite3 *db, const char *zDbName);
sqlite3_db_readonly(sqlite3 *db, const char *zDbName);
sqlite3_next_stmt(sqlite3 *db, sqlite3_stmt *pStmt);
sqlite3_commit_hook(
    sqlite3 *db,              /* Attach the hook to this database */
    int (*xCallback)(void*),  /* Function to invoke on each commit */
    void *pArg                /* Argument to the function */
);
sqlite3_rollback_hook(
    sqlite3 *db,              /* Attach the hook to this database */
    void (*xCallback)(void*), /* Callback function */
    void *pArg                /* Argument to the function */
);
sqlite3_update_hook(
    sqlite3 *db,              /* Attach the hook to this database */
    void (*xCallback)(void*,int,char const *,char const *,sqlite_int64),
    void *pArg                /* Argument to the function */
);
sqlite3_enable_shared_cache(int enable);
sqlite3_release_memory(int n);
sqlite3_db_release_memory(sqlite3 *db);
sqlite3_soft_heap_limit64(sqlite3_int64 n);
sqlite3_soft_heap_limit(int n);
sqlite3_table_column_metadata(
    sqlite3 *db,                /* Connection handle */
    const char *zDbName,        /* Database name or NULL */
    const char *zTableName,     /* Table name */
    const char *zColumnName,    /* Column name */
    char const **pzDataType,    /* OUTPUT: Declared data type */
    char const **pzCollSeq,     /* OUTPUT: Collation sequence name */
    int *pNotNull,              /* OUTPUT: True if NOT NULL constraint exists */
    int *pPrimaryKey,           /* OUTPUT: True if column part of PK */
    int *pAutoinc               /* OUTPUT: True if column is auto-increment */
);
sqlite3_load_extension(
    sqlite3 *db,          /* Load the extension into this database connection */
    const char *zFile,    /* Name of the shared library containing extension */
    const char *zProc,    /* Entry point.  Use "sqlite3_extension_init" if 0 */
    char **pzErrMsg       /* Put error message here if not 0 */
);
sqlite3_enable_load_extension(sqlite3 *db, int onoff);
sqlite3_auto_extension(void(*xEntryPoint)(void));
sqlite3_cancel_auto_extension(void(*xEntryPoint)(void));
__create_module(
    sqlite3 *db,
    const char *zName,
    const sqlite3_module *pModule,
    void *pAux,
    void (*xDestroy)(void *)
);
sqlite3_create_module(
    sqlite3 *db,                    /* Database in which module is registered */
    const char *zName,              /* Name assigned to this module */
    const sqlite3_module *pModule,  /* The definition of the module */
    void *pAux                      /* Context pointer for xCreate/xConnect */
);
sqlite3_create_module_v2(
    sqlite3 *db,                    /* Database in which module is registered */
    const char *zName,              /* Name assigned to this module */
    const sqlite3_module *pModule,  /* The definition of the module */
    void *pAux,                     /* Context pointer for xCreate/xConnect */
    void (*xDestroy)(void *)        /* Module destructor function */
);
sqlite3_declare_vtab(sqlite3 *db, const char *zSQL);
sqlite3_overload_function(sqlite3 *db, const char *zFuncName, int nArg);
sqlite3_blob_open(
    sqlite3 *db,
    const char *zDb,
    const char *zTable,
    const char *zColumn,
    sqlite3_int64 iRow,
    int flags,
    sqlite3_blob **ppBlob
);
sqlite3_blob_reopen(sqlite3_blob *pBlob, sqlite3_int64 iRow);
sqlite3_blob_close(sqlite3_blob *pBlob);
sqlite3_blob_bytes(sqlite3_blob *pBlob);
sqlite3_blob_read(sqlite3_blob *pBlob, void *z, int n, int iOffset);
sqlite3_blob_write(sqlite3_blob *pBlob, const void *z, int n, int iOffset);
sqlite3_vfs_find(const char *zVfsName);
sqlite3_vfs_register(sqlite3_vfs *pVfs, int makeDflt);
sqlite3_vfs_unregister(sqlite3_vfs *pVfs);
sqlite3_mutex_alloc(int id);
sqlite3_mutex_free(sqlite3_mutex *p);
sqlite3_mutex_enter(sqlite3_mutex *p);
sqlite3_mutex_try(sqlite3_mutex *p);
sqlite3_mutex_leave(sqlite3_mutex *p);
sqlite3_mutex_held(sqlite3_mutex *p);
sqlite3_mutex_notheld(sqlite3_mutex *p);
sqlite3_db_mutex(sqlite3 *db);
sqlite3_file_control(sqlite3 *db, const char *zDbName, int op, void *pArg);
sqlite3_status64(
    int op,
    sqlite3_int64 *pCurrent,
    sqlite3_int64 *pHighwater,
    int resetFlag
);
sqlite3_status(int op, int *pCurrent, int *pHighwater, int resetFlag);
sqlite3_db_status(
    sqlite3 *db,          /* The database connection whose status is desired */
    int op,               /* Status verb */
    int *pCurrent,        /* Write current value here */
    int *pHighwater,      /* Write high-water mark here */
    int resetFlag         /* Reset high-water mark if true */
);
sqlite3_stmt_status(sqlite3_stmt *pStmt, int op, int resetFlg);
sqlite3_backup_init(
    sqlite3 *pDest,
    const char *zDestName,
    sqlite3 *pSource,
    const char *zSourceName
);
sqlite3_backup_step(sqlite3_backup *p, int nPage);
sqlite3_backup_finish(sqlite3_backup *p);
sqlite3_backup_remaining(sqlite3_backup *p);
sqlite3_backup_pagecount(sqlite3_backup *p);
sqlite3_unlock_notify(
    sqlite3 *db,                          /* Waiting connection */
    void (*xNotify)(void **apArg, int nArg),    /* Callback function to invoke */
    void *pArg                                  /* Argument to pass to xNotify */
);
__xxx_strcmp(const char *z1, const char *z2);
sqlite3_stricmp(const char *z1, const char *z2);
sqlite3_strnicmp(const char *z1, const char *z2, int n);
sqlite3_strglob(const char *zGlobPattern, const char *zString);
sqlite3_strlike(const char *zPattern, const char *zStr, unsigned int esc);
sqlite3_log(int iErrCode, const char *zFormat, ...);
sqlite3_wal_hook(
    sqlite3 *db,                    /* Attach the hook to this db handle */
    int(*xCallback)(void *, sqlite3*, const char*, int),
    void *pArg                      /* First argument passed to xCallback() */
);
sqlite3_wal_autocheckpoint(sqlite3 *db, int N);
sqlite3_wal_checkpoint(sqlite3 *db, const char *zDb);
sqlite3_wal_checkpoint_v2(
    sqlite3 *db,                    /* Database handle */
    const char *zDb,                /* Name of attached database (or NULL) */
    int eMode,                      /* SQLITE_CHECKPOINT_* value */
    int *pnLog,                     /* OUT: Size of WAL log in frames */
    int *pnCkpt                     /* OUT: Total number of frames checkpointed */
);
sqlite3_vtab_config(sqlite3 *db, int op, ...);
sqlite3_vtab_on_conflict(sqlite3 *db);
sqlite3_vtab_collation(sqlite3_index_info *pIdxInfo, int iCons);
sqlite3_stmt_scanstatus(
    sqlite3_stmt *pStmt,
    int idx,
    int iScanStatusOp,
    void *pOut
);
sqlite3_stmt_scanstatus_reset(sqlite3_stmt *pStmt);
sqlite3_db_cacheflush(sqlite3 *db);
sqlite3_system_errno(sqlite3 *db);
sqlite3_snapshot_get(
    sqlite3 *db,
    const char *zSchema,
    sqlite3_snapshot **ppSnapshot
);
sqlite3_snapshot_open(
    sqlite3 *db,
    const char *zSchema,
    sqlite3_snapshot *pSnapshot
);
sqlite3_snapshot_free(sqlite3_snapshot *pSnapshot);
sqlite3_snapshot_cmp(
    sqlite3_snapshot *p1,
    sqlite3_snapshot *p2
);
sqlite3_snapshot_recover(sqlite3 *db, const char *zDb);
sqlite3_rtree_geometry_callback(
    sqlite3 *db,                  /* Register SQL function on this connection */
    const char *zGeom,            /* Name of the new SQL function */
    int (*xGeom)(sqlite3_rtree_geometry*,int,RtreeDValue*,int*), /* Callback */
    void *pContext                /* Extra data associated with the callback */
);
sqlite3_rtree_query_callback(
    sqlite3 *db,                 /* Register SQL function on this connection */
    const char *zQueryFunc,      /* Name of new SQL function */
    int (*xQueryFunc)(sqlite3_rtree_query_info*), /* Callback */
    void *pContext,              /* Extra data passed into the callback */
    void (*xDestructor)(void*)   /* Destructor for the extra data */
);
chmod(const char *fname, int mode);
fchmod(int fd, mode_t mode);
lstat(const char *restrict fname, struct stat *restrict st);
lstat64(const char *restrict fname, struct stat *restrict st);
fstat(int fd, struct stat *restrict st);
mkdir(const char *fname, int mode);
mkfifo(const char *fname, int mode);
mknod(const char *fname, int mode, int dev);
stat(const char *restrict fname, struct stat *restrict st);
stat64(const char *restrict fname, struct stat *restrict st);
statfs(const char *path, struct statfs *buf);
statfs64(const char *path, struct statfs *buf);
fstatfs(int fd, struct statfs *buf);
fstatfs64(int fd, struct statfs *buf);
statvfs(const char *path, struct statvfs *buf);
statvfs64(const char *path, struct statvfs *buf);
fstatvfs(int fd, struct statvfs *buf);
fstatvfs64(int fd, struct statvfs *buf);
_Exit(int code);
abort(void);
abs(int x);
labs(long x);
llabs(long long x);
atof(const char *arg);
atoi(const char *arg);
atol(const char *arg);
atoll(const char *arg);
calloc(size_t num, size_t size);
exit(int code);
fcvt(double value, int ndigit, int *dec, int sign);
free(void *ptr);
getenv(const char *key);
malloc(size_t size);
aligned_alloc(size_t alignment, size_t size);
mkstemp(char *template);
mkostemp(char *template, int flags);
mkstemps(char *template, int suffixlen);
mkostemps(char *template, int suffixlen, int flags);
ptsname(int fd);
putenv(char *cmd);
qsort(void *base, size_t num, size_t size, int (*comparator)(const void *, const void *));
rand(void);
rand_r(unsigned int *seedp);
srand(unsigned seed);
random(void);
srandom(unsigned seed);
drand48(void);
lrand48(void);
mrand48(void);
erand48(unsigned short xsubi[3]);
nrand48(unsigned short xsubi[3]);
seed48(unsigned short seed16v[3]);
realloc(void *ptr, size_t size);
realpath(const char *restrict path, char *restrict resolved_path);
setenv(const char *key, const char *val, int flag);
strtod(const char *restrict nptr, char **restrict endptr);
strtof(const char *restrict nptr, char **restrict endptr);
strtol(const char *restrict nptr, char **restrict endptr, int base);
strtold(const char *restrict nptr, char **restrict endptr);
strtoll(const char *restrict nptr, char **restrict endptr, int base);
strtoul(const char *restrict nptr, char **restrict endptr, int base);
strtoull(const char *restrict nptr, char **restrict endptr, int base);
system(const char *cmd);
unsetenv(const char *key);
wctomb(char* pmb, wchar_t wc);
setproctitle(const char *fmt, ...);
syslog(int priority, const char *message, ...);
vsyslog(int priority, const char *message, __va_list);
Tcl_Panic(const char *format, ...);
panic(const char *format, ...);
utimes(const char *fname, const struct timeval times[2]);
localtime(const time_t *timer);
localtime_r(const time_t *restrict timer, struct tm *restrict result);
gmtime(const time_t *timer);
gmtime_r(const time_t *restrict timer, struct tm *restrict result);
ctime(const time_t *clock);
ctime_r(const time_t *clock, char *buf);
asctime(const struct tm *timeptr);
asctime_r(const struct tm *restrict tm, char *restrict buf);
strftime(char *s, size_t maxsize, const char *format,
         const struct tm *timeptr);
mktime(struct tm *timeptr);
time(time_t *t);
clock_getres(clockid_t clk_id, struct timespec *res);
clock_gettime(clockid_t clk_id, struct timespec *tp);
clock_settime(clockid_t clk_id, const struct timespec *tp);
nanosleep(const struct timespec *req, struct timespec *rem);
access(const char *fname, int flags);
chdir(const char *fname);
chroot(const char *fname);
seteuid(uid_t euid);
setegid(uid_t egid);
sethostid(long hostid);
chown(const char *fname, int uid, int gid);
dup(int oldd);
dup2(int oldd, int newdd);
close(int fd);
execl(const char *path, const char *arg0, ...);
execle(const char *path, const char *arg0, ...);
execlp(const char *file, const char *arg0, ...);
execv(const char *path, char *const argv[]);
execve(const char *path, char *const argv[], char *const envp[]);
execvp(const char *file, char *const argv[]);
_exit(int rcode);
fchown(int fd, uid_t owner, gid_t group);
fchdir(int fd);
fork(void);
fpathconf(int fd, int name);
fsync(int fd);
ftruncate(int fd, off_t length);
ftruncate64(int fd, off_t length);
getcwd(char *buf, size_t size);
getopt(int argc, char * const argv[], const char *optstring);
getpid(void);
getppid(void);
getsid(pid_t pid);
getuid(void);
geteuid(void);
getgid(void);
getegid(void);
getpgid(pid_t pid);
getpgrp(/*'void' or 'int pid'*/);
getwd(char *buf);
lchown(const char *fname, int uid, int gid);
link(const char *path1, const char *path2);
lseek(int fildes, off_t offset, int whence);
lseek64(int fildes, off_t offset, int whence);
pathconf(const char *path, int name);
pipe(int pipefd[2]);
pipe2(int pipefd[2], int flags);
pread(int fd, void *buf, size_t nbytes, off_t offset);
pwrite(int fd, const void *buf, size_t nbytes, off_t offset);
read(int fd, void *buf, size_t nbytes);
__read_chk(int fd, void *buf, size_t nbytes, size_t buflen);
readlink(const char *path, char *buf, int buf_size);
rmdir(const char *path);
sleep(unsigned int ms);
setgid(gid_t gid);
setpgid(pid_t pid, pid_t pgid);
setpgrp(/*'void' or 'pid_t pid, pid_t pgid'*/);
setsid(void);
setuid(uid_t uid);
setregid(gid_t rgid, gid_t egid);
setreuid(uid_t ruid, uid_t euidt);
symlink(const char *path1, const char *path2);
sysconf(int name);
truncate(const char *fname, off_t off);
truncate64(const char *fname, off_t off);
unlink(const char *path);
unlinkat(int dirfd, const char *path, int flags);
usleep(useconds_t s);
write(int fd, const void *buf, size_t nbytes);
uselib(const char *library);
mktemp(char *template);
utime(const char *path, const struct utimbuf *times);
getutent(void);
getutid(struct utmp *ut);
getutline(struct utmp *ut);
pututline(struct utmp *ut);
utmpname(const char *file);
getutxent(void);
getutxid(struct utmp *ut);
getutxline(struct utmp *ut);
pututxline(struct utmp *ut);
utmpxname(const char *file);
uname (struct utsname *name);
VOS_sprintf(VOS_CHAR * s, const VOS_CHAR * format,  ... );
VOS_sprintf_Safe( VOS_CHAR * s, VOS_UINT32 uiDestLen, const VOS_CHAR *  format,  ... );
VOS_vsnprintf_s(VOS_CHAR * str, VOS_SIZE_T destMax, VOS_SIZE_T count,  const VOS_CHAR * format, va_list  arglist);
VOS_MemCpy_Safe(VOS_VOID * dst, VOS_SIZE_T dstSize,const VOS_VOID *src, VOS_SIZE_T num);
VOS_strcpy_Safe(VOS_CHAR *dst, VOS_SIZE_T dstsz, const VOS_CHAR *src);
VOS_StrCpy_Safe(VOS_CHAR *dst, VOS_SIZE_T dstsz, const VOS_CHAR *src);
VOS_StrNCpy_Safe( VOS_CHAR *dst, VOS_SIZE_T dstsz, const VOS_CHAR *src, VOS_SIZE_T count);
VOS_Que_Read	(VOS_UINT32	ulQueueID, VOS_UINTPTR aulQueMsg[4], VOS_UINT32 ulFlags, VOS_UINT32 ulTimeOut);
VOS_sscanf_s(const VOS_CHAR *buffer,  const VOS_CHAR *  format, ...);
VOS_strlen(const VOS_CHAR *s);
VOS_StrLen(const VOS_CHAR *s);
XAddHost(Display* dpy, XHostAddress* host);
XRemoveHost(Display* dpy, XHostAddress* host);
XChangeProperty(Display *dpy, Window w, Atom property,
                    Atom type, int format, int mode,
                    _Xconst unsigned char * data, int nelements);
XF86VidModeModModeLine(Display *dpy, int screen, XF86VidModeModeLine *modeline);
XtGetValues(Widget w, ArgList args, Cardinal num_args);
XIQueryDevice(Display *display,
                             int deviceid,
                             int *ndevices_return);
XListInstalledColormaps(Display *display, Window w, int *num_return);
