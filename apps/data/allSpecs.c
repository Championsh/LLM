ssize_t archive_read_data(struct archive *archive, void *buff, size_t len) {
    sf_bitinit(buff);

    sf_overwrite(buff);
    sf_set_tainted(buff);
    sf_set_possible_nnts(buff);
    sf_buf_size_limit(buff, len);

    ssize_t x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    sf_uncontrolled_value(x);
    sf_set_possible_equals(x, len);

    sf_assert_cond(x, "<=", len);
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range(">=", 0));
    sf_buf_fill(x, buff);
    return x;
}

void __assert_fail(const char *assertion, const char *file, unsigned int line, const char *function) {
    sf_terminate_path();
}

void _assert(const char *a, const char *b, int c) {
    sf_terminate_path();
}

void __promise(int exp) {
    if(!exp) {
        sf_terminate_path();
    }
}

BSTR SysAllocString(const OLECHAR *psz) {
    BSTR ptr;
    sf_overwrite(&ptr);
    sf_overwrite(ptr);
    sf_uncontrolled_ptr(ptr);
    sf_set_alloc_possible_null(ptr);
    sf_new(ptr, BSTR_ALLOC_CATEGORY);

    sf_copy_string(ptr, psz);
    return ptr; 
}

BSTR SysAllocStringByteLen(LPCSTR psz, unsigned int len) {
    BSTR ptr;
    sf_overwrite(&ptr);
    sf_overwrite(ptr);
    sf_uncontrolled_ptr(ptr);
    sf_set_alloc_possible_null(ptr, len);
    sf_new(ptr, BSTR_ALLOC_CATEGORY);
    sf_buf_copy(ptr, psz);
//  sf_buf_size_limit(psz, len+1);
    sf_buf_stop_at_null(psz);
    return ptr; 
}

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

void SysFreeString(BSTR bstrString) {
    sf_set_possible_null(bstrString); 
    sf_overwrite(bstrString);
    sf_delete(bstrString, BSTR_ALLOC_CATEGORY);    
}

unsigned int SysStringLen(BSTR bstr) {
// empty spec
}

int getch(void) {
    int tainted_res;
    sf_overwrite(&tainted_res);
    sf_set_tainted_int(tainted_res);
    sf_uncontrolled_value(tainted_res);
    return tainted_res;    
}

int _getch(void) {
    int tainted_res;
    sf_overwrite(&tainted_res);
    sf_set_tainted_int(tainted_res);
    sf_uncontrolled_value(tainted_res);
    return tainted_res;
}

void memory_full(void) {
    sf_terminate_path();
}

int _CrtDbgReport( int reportType, const char *filename, int linenumber, const char *moduleName, const char *format, ...) {
    sf_terminate_path();
}

int _CrtDbgReportW( int reportType, const wchar_t *filename, int linenumber, const wchar_t *moduleName, const wchar_t *format, ...) {
    sf_terminate_path();
}

char *crypt(const char *key, const char *salt) {
    sf_password_use(key);
    sf_password_use(salt);
}

char *crypt_r(const char *key, const char *salt, struct crypt_data *data) {
    sf_password_use(key);
    sf_password_use(salt);
}

void setkey(const char *key) {
    sf_password_use(key);
}

void setkey_r(const char *key, struct crypt_data *data) {
    sf_password_use(key);
}

int ecb_crypt(char *key, char *data, unsigned datalen, unsigned mode) {
    sf_password_use(key);
}

int cbc_crypt(char *key, char *data, unsigned datalen, unsigned mode, char *ivec) {
    sf_password_use(key);
    sf_password_use(ivec);
}

void des_setparity(char *key) {
    sf_password_use(key);
}

void passwd2des(char *passwd, char *key) {
    sf_password_use(key);
    sf_password_use(passwd);
}

int xencrypt(char *secret, char *passwd) {
    sf_password_use(secret);
    sf_password_use(passwd);
}

int xdecrypt(char *secret, char *passwd) {
    sf_password_use(secret);
    sf_password_use(passwd);
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

int isdigit(int c) {
    sf_set_trusted_sink_char(c);
    int res = c >= '0' && c <= '9';
    sf_pure(res, c);
    return res;
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

unsigned short **__ctype_b_loc(void) {
    const unsigned short **res;
    sf_overwrite(&res);
    sf_not_null(res);
    return res;
}

int closedir(DIR *file) {
    sf_overwrite(file);
    sf_handle_release(file, DIR_CATEGORY);
}

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

struct dirent *readdir(DIR *file) {
	sf_tocttou_access(file);

    struct dirent *res;
	sf_overwrite(&res);
    sf_set_possible_null(res);
    return res;
}

int dlclose(void *handle) {
    sf_overwrite(handle);
    sf_handle_release(handle, DL_CATEGORY);
}

void *dlopen(const char *file, int mode) {
    sf_tocttou_access(file);
	sf_set_trusted_sink_ptr(file);

    void *res;
    sf_overwrite(&res);
    sf_overwrite(res);
    sf_set_possible_null(res);
    sf_uncontrolled_ptr(res);
    sf_handle_acquire(res, DL_CATEGORY);
	sf_not_acquire_if_eq(res, mode, RTLD_NOLOAD);
    return res;
}

void *dlsym(void *handle, const char *symbol) {
    void *res;
    sf_overwrite(&res);
    sf_set_possible_null(res);
    return res;
}

bool DebugAssertEnabled ( void ) {
  return true;
}

void CpuDeadLoop ( void ) {
  sf_terminate_path();
}

void *AllocatePages ( uintptr_t Pages ) {
  sf_set_trusted_sink_int(Pages);

  void *Res;

  sf_overwrite(&Res); // Res is initialized
  sf_overwrite(Res);  // pointed memory is also initialized
  sf_new (Res, PAGES_MEMORY_CATEGORY);
  sf_set_possible_null(Res);
  sf_not_acquire_if_eq(Res, Res, 0); // resource is not created if it equals to null
  sf_buf_size_limit(Res, Pages * EFI_PAGE_SIZE);

  return Res;
}

void *AllocateRuntimePages ( uintptr_t Pages ) {
  sf_set_trusted_sink_int(Pages);

  void *Res;

  sf_overwrite(&Res);
  sf_overwrite(Res);
  sf_new (Res, PAGES_MEMORY_CATEGORY);
  sf_set_possible_null(Res);
  sf_not_acquire_if_eq(Res, Res, 0);
  sf_buf_size_limit(Res, Pages * EFI_PAGE_SIZE);

  return Res;
}

void *AllocateReservedPages ( uintptr_t Pages ) {
  sf_set_trusted_sink_int(Pages);

  void *Res;

  sf_overwrite(&Res);
  sf_overwrite(Res);
  sf_new (Res, PAGES_MEMORY_CATEGORY);
  sf_set_possible_null(Res);
  sf_not_acquire_if_eq(Res, Res, 0);
  sf_buf_size_limit(Res, Pages * EFI_PAGE_SIZE);

  return Res;
}

void FreePages ( void *Buffer, uintptr_t Pages ) {
  sf_delete (Buffer, PAGES_MEMORY_CATEGORY);
}

void *AllocateAlignedPages ( uintptr_t Pages, uintptr_t Alignment ) {
  sf_set_trusted_sink_int(Pages);

  void *Res;
  uintptr_t Remainder;

  sf_overwrite(&Res);
  sf_overwrite(Res);
  sf_new (Res, ALIGNED_MEMORY_CATEGORY);
  sf_set_possible_null(Res);
  sf_not_acquire_if_eq(Res, Res, 0);

  Remainder = (Pages * EFI_PAGE_SIZE) % Alignment;
  if (Remainder == 0) {
    sf_buf_size_limit(Res, Pages * EFI_PAGE_SIZE);
  } else {
    sf_buf_size_limit(Res, ((Pages * EFI_PAGE_SIZE) / Alignment + 1) * Alignment);
  }

  return Res;
}

void *AllocateAlignedRuntimePages ( uintptr_t Pages, uintptr_t Alignment ) {
  sf_set_trusted_sink_int(Pages);

  void *Res;
  uintptr_t Remainder;

  sf_overwrite(&Res);
  sf_overwrite(Res);
  sf_new (Res, ALIGNED_MEMORY_CATEGORY);
  sf_set_possible_null(Res);
  sf_not_acquire_if_eq(Res, Res, 0);

  Remainder = (Pages * EFI_PAGE_SIZE) % Alignment;
  if (Remainder == 0) {
    sf_buf_size_limit(Res, Pages * EFI_PAGE_SIZE);
  } else {
    sf_buf_size_limit(Res, ((Pages * EFI_PAGE_SIZE) / Alignment + 1) * Alignment);
  }

  return Res;
}

void *AllocateAlignedReservedPages ( uintptr_t Pages, uintptr_t Alignment ) {
  sf_set_trusted_sink_int(Pages);

  void *Res;
  uintptr_t Remainder;

  sf_overwrite(&Res);
  sf_overwrite(Res);
  sf_new (Res, ALIGNED_MEMORY_CATEGORY);
  sf_set_possible_null(Res);
  sf_not_acquire_if_eq(Res, Res, 0);

  Remainder = (Pages * EFI_PAGE_SIZE) % Alignment;
  if (Remainder == 0) {
    sf_buf_size_limit(Res, Pages * EFI_PAGE_SIZE);
  } else {
    sf_buf_size_limit(Res, ((Pages * EFI_PAGE_SIZE) / Alignment + 1) * Alignment);
  }

  return Res;
}

void FreeAlignedPages ( void *Buffer, uintptr_t Pages ) {
  sf_delete (Buffer, ALIGNED_MEMORY_CATEGORY);
}

void *AllocatePool ( uintptr_t AllocationSize ) {
  sf_set_trusted_sink_int(AllocationSize);

  void *Res;

  sf_overwrite(&Res);
  sf_overwrite(Res);
  sf_new (Res, POOL_MEMORY_CATEGORY);
  sf_set_possible_null(Res);
  sf_not_acquire_if_eq(Res, Res, 0);
  sf_buf_size_limit(Res, AllocationSize);

  return Res;
}

void *AllocateRuntimePool ( uintptr_t AllocationSize ) {
  sf_set_trusted_sink_int(AllocationSize);

  void *Res;

  sf_overwrite(&Res);
  sf_overwrite(Res);
  sf_new (Res, POOL_MEMORY_CATEGORY);
  sf_set_possible_null(Res);
  sf_not_acquire_if_eq(Res, Res, 0);
  sf_buf_size_limit(Res, AllocationSize);

  return Res;
}

void *AllocateReservedPool ( uintptr_t AllocationSize ) {
  sf_set_trusted_sink_int(AllocationSize);

  void *Res;

  sf_overwrite(&Res);
  sf_overwrite(Res);
  sf_new (Res, POOL_MEMORY_CATEGORY);
  sf_set_possible_null(Res);
  sf_not_acquire_if_eq(Res, Res, 0);
  sf_buf_size_limit(Res, AllocationSize);

  return Res;
}

void *AllocateZeroPool ( uintptr_t AllocationSize ) {
  sf_set_trusted_sink_int(AllocationSize);

  void *Res;

  sf_overwrite(&Res);
  sf_overwrite(Res);
  sf_new (Res, POOL_MEMORY_CATEGORY);
  sf_set_possible_null(Res);
  sf_not_acquire_if_eq(Res, Res, 0);
  sf_buf_size_limit(Res, AllocationSize);

  return Res;
}

void *AllocateRuntimeZeroPool ( uintptr_t AllocationSize ) {
  sf_set_trusted_sink_int(AllocationSize);

  void *Res;

  sf_overwrite(&Res);
  sf_overwrite(Res);
  sf_new (Res, POOL_MEMORY_CATEGORY);
  sf_set_possible_null(Res);
  sf_not_acquire_if_eq(Res, Res, 0);
  sf_buf_size_limit(Res, AllocationSize);

  return Res;
}

void *AllocateReservedZeroPool ( uintptr_t AllocationSize ) {
  sf_set_trusted_sink_int(AllocationSize);

  void *Res;

  sf_overwrite(&Res);
  sf_overwrite(Res);
  sf_new (Res, POOL_MEMORY_CATEGORY);
  sf_set_possible_null(Res);
  sf_not_acquire_if_eq(Res, Res, 0);
  sf_buf_size_limit(Res, AllocationSize);

  return Res;
}

void *AllocateCopyPool ( uintptr_t AllocationSize, const void *Buffer ) {
  sf_set_trusted_sink_int(AllocationSize);

  void *Res;

  sf_overwrite(&Res);
  sf_overwrite(Res);
  sf_new (Res, POOL_MEMORY_CATEGORY);
  sf_set_possible_null(Res);
  sf_not_acquire_if_eq(Res, Res, 0);
  sf_buf_size_limit(Res, AllocationSize);
  sf_bitcopy(Res, Buffer);

  return Res;
}

void *AllocateRuntimeCopyPool ( uintptr_t AllocationSize, const void *Buffer ) {
  sf_set_trusted_sink_int(AllocationSize);

  void *Res;

  sf_overwrite(&Res);
  sf_overwrite(Res);
  sf_new (Res, POOL_MEMORY_CATEGORY);
  sf_set_possible_null(Res);
  sf_not_acquire_if_eq(Res, Res, 0);
  sf_buf_size_limit(Res, AllocationSize);
  sf_bitcopy(Res, Buffer);

  return Res;
}

void *AllocateReservedCopyPool ( uintptr_t AllocationSize, const void *Buffer ) {
  sf_set_trusted_sink_int(AllocationSize);

  void *Res;

  sf_overwrite(&Res);
  sf_overwrite(Res);
  sf_new (Res, POOL_MEMORY_CATEGORY);
  sf_set_possible_null(Res);
  sf_not_acquire_if_eq(Res, Res, 0);
  sf_buf_size_limit(Res, AllocationSize);
  sf_bitcopy(Res, Buffer);

  return Res;
}

void *ReallocatePool ( uintptr_t OldSize, uintptr_t NewSize, void *OldBuffer ) {
  sf_set_trusted_sink_int(NewSize);

  void *Res;

  sf_overwrite(&Res);
  sf_overwrite(Res);
  sf_new (Res, POOL_MEMORY_CATEGORY);
  sf_set_possible_null(Res);
  sf_not_acquire_if_eq(Res, Res, 0);
  sf_buf_size_limit(Res, NewSize);
  if (OldBuffer != NULL) {
    sf_bitcopy(Res, OldBuffer);
    sf_delete (OldBuffer, POOL_MEMORY_CATEGORY);
  }

  return Res;
}

void *ReallocateRuntimePool ( uintptr_t OldSize, uintptr_t NewSize, void *OldBuffer ) {
  sf_set_trusted_sink_int(NewSize);

  void *Res;

  sf_overwrite(&Res);
  sf_overwrite(Res);
  sf_new (Res, POOL_MEMORY_CATEGORY);
  sf_set_possible_null(Res);
  sf_not_acquire_if_eq(Res, Res, 0);
  sf_buf_size_limit(Res, NewSize);
  if (OldBuffer != NULL) {
    sf_bitcopy(Res, OldBuffer);
    sf_delete (OldBuffer, POOL_MEMORY_CATEGORY);
  }

  return Res;
}

void *ReallocateReservedPool ( uintptr_t OldSize, uintptr_t NewSize, void *OldBuffer ) {
  sf_set_trusted_sink_int(NewSize);

  void *Res;

  sf_overwrite(&Res);
  sf_overwrite(Res);
  sf_new (Res, POOL_MEMORY_CATEGORY);
  sf_set_possible_null(Res);
  sf_not_acquire_if_eq(Res, Res, 0);
  sf_buf_size_limit(Res, NewSize);
  if (OldBuffer != NULL) {
    sf_bitcopy(Res, OldBuffer);
    sf_delete (OldBuffer, POOL_MEMORY_CATEGORY);
  }

  return Res;
}

void FreePool ( void *Buffer ) {
  sf_delete (Buffer, POOL_MEMORY_CATEGORY);
}

void err(int eval, const char *fmt, ...) {
    sf_use_format(fmt);

    sf_terminate_path();
}

void verr(int eval, const char *fmt, va_list args) {
    sf_use_format(fmt);

    sf_terminate_path();
}

void errx(int eval, const char *fmt, ...) {
    sf_use_format(fmt);

    sf_terminate_path();
}

void verrx(int eval, const char *fmt, va_list args) {
    sf_use_format(fmt);

    sf_terminate_path();
}

void warn(const char *fmt, ...) {
    sf_use_format(fmt);
}

void vwarn(const char *fmt, va_list args) {
    sf_use_format(fmt);
}

void warnx(const char *fmt, ...) {
    sf_use_format(fmt);
}

void vwarnx(const char *fmt, va_list args) {
    sf_use_format(fmt);
}

int *__errno_location(void) {
    int *res;
    sf_overwrite(&res);
    sf_pure(res); // but not '*res'
    sf_not_null(res);
    sf_errno_res(res);
    return res;
}

void error(int status, int errnum, const char *fmt, ...) {
    sf_use_format(fmt);

    if(status>0)
        sf_terminate_path();

    //I don't think we find this in real projects.
    //if(status<0)
    //    sf_terminate_path();
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

int creat64(const char *name, mode_t mode) {
    return creat(name, mode);
}

int fcntl(int fd, int cmd, ...) {
    sf_set_must_be_positive(fd);
    sf_lib_arg_type(fd, "StdioHandlerCategory");

    sf_fun_does_not_update_vargs(2);

    int x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    sf_assert_cond(x, ">=", -1);
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

int ftw(const char *path, int (*fn)(const char *, const struct stat *ptr, int flag), int ndirs) {
    sf_tocttou_access(path);
}

int ftw64(const char *path, int (*fn)(const char *, const struct stat *ptr, int flag), int ndirs) {
    sf_tocttou_access(path);
}

int nftw(const char *path, int (*fn)(const char *, const struct stat *, int, struct FTW *), int fd_limit, int flags) {
    sf_tocttou_access(path);
}

int nftw64(const char *path, int (*fn)(const char *, const struct stat *, int, struct FTW *), int fd_limit, int flags) {
    sf_tocttou_access(path);
}

gcry_error_t gcry_cipher_setkey(gcry_cipher_hd_t h, const void *key, size_t l) {
    sf_password_use(key);
}

gcry_error_t gcry_cipher_setiv (gcry_cipher_hd_t h, const void *key, size_t l) {
    sf_password_use(key);
}

gcry_error_t gcry_cipher_setctr (gcry_cipher_hd_t h, const void *ctr, size_t l) {
    sf_password_use(ctr);
}

gcry_error_t gcry_cipher_authenticate (gcry_cipher_hd_t h, const void *abuf, size_t abuflen) {
    sf_password_use(abuf);
}

gcry_error_t gcry_cipher_checktag (gcry_cipher_hd_t h, const void *tag, size_t taglen) {
    sf_password_use(tag);
}

gcry_error_t gcry_md_setkey (gcry_md_hd_t h, const void *key, size_t keylen) {
    sf_password_use(key);
}

void g_free (gpointer ptr) {
	sf_set_must_be_not_null(ptr, FREE_OF_NULL);
	// sf_overwrite(ptr);
	sf_delete(ptr, GLIB_CATEGORY);
}

gchar * g_strfreev(const gchar **str_array) {
	if(!str_array)
		return;

	sf_escape(str_array);//TODO: create some recursive delete function
	sf_delete(*str_array, GLIB_CATEGORY);
	sf_overwrite(str_array);
	sf_delete(str_array, GLIB_CATEGORY);
}

void g_async_queue_push (GAsyncQueue *queue, gpointer data) {
	sf_escape(data);
}

void g_queue_push_tail (GQueue *queue, gpointer data) {
	sf_escape(data);
}

void g_source_set_callback (struct GSource *source, GSourceFunc func, gpointer data, GDestroyNotify notify) {
	sf_escape(data);
}

gboolean g_thread_pool_push (GThreadPool *pool, gpointer data, GError **error) {
	sf_escape(data);
}

GList * g_list_append(GList *list, gpointer data) {
	sf_escape(data);
}

GList * g_list_prepend(GList *list, gpointer data) {
	sf_escape(data);
}

GList * g_list_insert(GList *list, gpointer data, gint position) {
	sf_escape(data);
}

GList * g_list_insert_before(GList *list, gpointer data, gint position) {
	sf_escape(data);
}

GList * g_list_insert_sorted(GList *list, gpointer data, GCompareFunc func) {
	sf_escape(data);
}

GSList * g_slist_append(GSList *list, gpointer data) {
	sf_escape(data);
}

GSList * g_slist_prepend(GSList *list, gpointer data) {
	sf_escape(data);
}

GSList * g_slist_insert(GSList *list, gpointer data, gint position) {
	sf_escape(data);
}

GSList * g_slist_insert_before(GSList *list, gpointer data, gint position) {
	sf_escape(data);
}

GSList * g_slist_insert_sorted(GSList *list, gpointer data, GCompareFunc func) {
	sf_escape(data);
}

GArray * g_array_append_vals(GArray *array, gconstpointer data, guint len) {
	sf_escape(data);
}

GArray * g_array_prepend_vals(GArray *array, gconstpointer data, guint len) {
	sf_escape(data);
}

GArray * g_array_insert_vals(GArray *array, gconstpointer data, guint len) {
	sf_escape(data);
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

gpointer g_malloc0_n (gsize n_blocks, gsize n_block_bytes) {
	sf_set_trusted_sink_int(n_blocks);
	sf_set_trusted_sink_int(n_block_bytes);

	gpointer ptr;
	sf_bitinit(ptr);
	sf_overwrite(&ptr);
	sf_overwrite(ptr);
	sf_uncontrolled_ptr(ptr);
	sf_new(ptr, GLIB_CATEGORY);
	sf_null_terminated((char*)ptr);
	return ptr;
}

gpointer g_malloc (gsize n_bytes) {
	sf_set_trusted_sink_int(n_bytes);
	sf_malloc_arg(n_bytes);

	gpointer ptr;
	sf_bitinit(ptr);
	sf_overwrite(&ptr);
	sf_overwrite(ptr);
	sf_uncontrolled_ptr(ptr);
	sf_new(ptr, GLIB_CATEGORY);
	sf_raw_new(ptr);
	sf_set_buf_size(ptr, n_bytes);
	return ptr;
}

gpointer g_malloc0 (gsize n_bytes) {
	sf_set_trusted_sink_int(n_bytes);
	sf_malloc_arg(n_bytes);

	gpointer ptr;
	sf_bitinit(ptr);
	sf_overwrite(&ptr);
	sf_overwrite(ptr);
	sf_uncontrolled_ptr(ptr);
	sf_new(ptr, GLIB_CATEGORY);
	sf_set_buf_size(ptr, n_bytes);
	sf_null_terminated((char*)ptr);
	return ptr;
}

gpointer g_malloc_n (gsize n_blocks, gsize n_block_bytes) {
	sf_set_trusted_sink_int(n_blocks);
	sf_set_trusted_sink_int(n_block_bytes);

	gpointer ptr;
	sf_overwrite(&ptr);
	sf_overwrite(ptr);
	sf_uncontrolled_ptr(ptr);
	sf_new(ptr, GLIB_CATEGORY);
	sf_raw_new(ptr);
	sf_set_buf_size(ptr, n_blocks*n_block_bytes);
	return ptr;
}

gpointer g_try_malloc0_n (gsize n_blocks, gsize n_block_bytes) {
	sf_set_trusted_sink_int(n_blocks);
	sf_set_trusted_sink_int(n_block_bytes);

	gpointer ptr;
	sf_overwrite(&ptr);
	sf_overwrite(ptr);
	sf_uncontrolled_ptr(ptr);
	sf_new(ptr, GLIB_CATEGORY);
	sf_set_alloc_possible_null(ptr, n_blocks, n_block_bytes);
	sf_null_terminated((char*)ptr);
	return ptr;
}

gpointer g_try_malloc (gsize n_bytes) {
	sf_set_trusted_sink_int(n_bytes);
	sf_malloc_arg(n_bytes);

	gpointer ptr;
	sf_overwrite(&ptr);
	sf_overwrite(ptr);
	sf_uncontrolled_ptr(ptr);
	sf_new(ptr, GLIB_CATEGORY);
	sf_raw_new(ptr);
	sf_set_buf_size(ptr, n_bytes);
	sf_set_alloc_possible_null(ptr, n_bytes);
	return ptr;
}

gpointer g_try_malloc0 (gsize n_bytes) {
	sf_set_trusted_sink_int(n_bytes);
	sf_malloc_arg(n_bytes);

	gpointer ptr;
	sf_overwrite(&ptr);
	sf_overwrite(ptr);
	sf_uncontrolled_ptr(ptr);
	sf_new(ptr, GLIB_CATEGORY);
	sf_set_buf_size(ptr, n_bytes);
	sf_set_alloc_possible_null(ptr, n_bytes);
	return ptr;
}

gpointer g_try_malloc_n (gsize n_blocks, gsize n_block_bytes) {
	sf_set_trusted_sink_int(n_blocks);
	sf_set_trusted_sink_int(n_block_bytes);

	gpointer ptr;
	sf_overwrite(&ptr);
	sf_overwrite(ptr);
	sf_uncontrolled_ptr(ptr);
	sf_new(ptr, GLIB_CATEGORY);
	sf_raw_new(ptr);
	sf_set_alloc_possible_null(ptr, n_blocks, n_block_bytes);
	return ptr;
}

guint32 g_random_int (void) {
	sf_fun_rand();
}

gpointer g_realloc(gpointer mem, gsize n_bytes) {
	sf_escape(mem);
	sf_set_trusted_sink_int(n_bytes);

	gpointer *retptr;
	sf_overwrite(&retptr);
	sf_overwrite(retptr);
	sf_uncontrolled_ptr(retptr);
	sf_new(retptr, GLIB_CATEGORY);
	sf_invalid_pointer(mem, retptr);
	sf_set_buf_size(retptr, n_bytes);
	return retptr;
}

gpointer g_try_realloc(gpointer mem, gsize n_bytes) {
	sf_escape(mem);
	sf_set_trusted_sink_int(n_bytes);

	gpointer *retptr;
	sf_overwrite(&retptr);
	sf_overwrite(retptr);
	sf_uncontrolled_ptr(retptr);
	sf_new(retptr, GLIB_CATEGORY);
	sf_invalid_pointer(mem, retptr);
	sf_set_buf_size(retptr, n_bytes);
	sf_set_alloc_possible_null(retptr, n_bytes);
	return retptr;
}

gpointer g_realloc_n(gpointer mem, gsize n_blocks, gsize n_block_bytes) {
	sf_escape(mem);
	sf_set_trusted_sink_int(n_blocks);
	sf_set_trusted_sink_int(n_block_bytes);

	gpointer *retptr;
	sf_overwrite(&retptr);
	sf_overwrite(retptr);
	sf_uncontrolled_ptr(retptr);
	sf_new(retptr, GLIB_CATEGORY);
	sf_invalid_pointer(mem, retptr);
	sf_set_buf_size(retptr, n_blocks * n_block_bytes);
	return retptr;
}

gpointer g_try_realloc_n(gpointer mem, gsize n_blocks, gsize n_block_bytes) {
	sf_escape(mem);
	sf_set_trusted_sink_int(n_blocks);
	sf_set_trusted_sink_int(n_block_bytes);

	gpointer *retptr;
	sf_overwrite(&retptr);
	sf_overwrite(retptr);
	sf_uncontrolled_ptr(retptr);
	sf_new(retptr, GLIB_CATEGORY);
	sf_invalid_pointer(mem, retptr);
	sf_set_buf_size(retptr, n_blocks * n_block_bytes);
	sf_set_alloc_possible_null(retptr, n_blocks * n_block_bytes);
	return retptr;
}

int klogctl(int type, char *bufp, int len) {
}

guint g_list_length(GList *list) {
    guint res;
    sf_overwrite(&res);
    sf_assert_cond(res, ">=", 0);
    return res;
}

char *inet_ntoa(struct in_addr in) {
    char *res;
    sf_overwrite(&res);
    //"0.0.0.0" - 7
    //"255.255.255.255" - 15
    sf_string_size_limit(res, 7, 15);
    sf_password_set(res);
    return res;
}

uint32_t htonl(uint32_t hostlong) {
    int res;
    sf_overwrite(&res);
    sf_set_tainted_int(res);
    return (uint32_t)res;
}

uint16_t htons(uint16_t hostshort) {
    int res;
    sf_overwrite(&res);
    sf_set_tainted_int(res);
    return (uint16_t)res;
}

uint32_t ntohl(uint32_t netlong) {
    int res;
    sf_overwrite(&res);
    sf_set_tainted_int(res);
    return (uint32_t)res;
}

uint16_t ntohs(uint16_t netshort) {
    int res;
    sf_overwrite(&res);
    sf_set_tainted_int(res);
    sf_password_set(res);
    return (uint16_t)res;
}

int ioctl(int d, int request, ...) {
  sf_fun_updates_vargs(2);
}

char * GetStringUTFChars(JNIEnv *env, jstring string, jboolean *isCopy) {
	jobject *res;
 sf_overwrite(&res);
 sf_set_possible_null(res);
 return res;
}

jobjectArray NewObjectArray(JNIEnv *env, jsize length, jclass elementClass, jobject initialElement) {
	jobject *res;
 sf_overwrite(&res);
 sf_set_possible_null(res);
 return res;
}

jbooleanArray NewBooleanArray(JNIEnv *env, jsize length) {
	jobject *res;
 sf_overwrite(&res);
 sf_set_possible_null(res);
 return res;
}

jbyteArray NewByteArray(JNIEnv *env, jsize length) {
	jobject *res;
 sf_overwrite(&res);
 sf_set_possible_null(res);
 return res;
}

jcharArray NewCharArray(JNIEnv *env, jsize length) {
}

jshortArray NewShortArray(JNIEnv *env, jsize length) {
	jobject *res;
 sf_overwrite(&res);
 sf_set_possible_null(res);
 return res;
}

jintArray NewIntArray(JNIEnv *env, jsize length) {
	jobject *res;
 sf_overwrite(&res);
 sf_set_possible_null(res);
 return res;
}

jlongArray NewLongArray(JNIEnv *env, jsize length) {
	jobject *res;
 sf_overwrite(&res);
 sf_set_possible_null(res);
 return res;
}

jfloatArray NewFloatArray(JNIEnv *env, jsize length) {
	jobject *res;
 sf_overwrite(&res);
 sf_set_possible_null(res);
 return res;
}

jdoubleArray NewDoubleArray(JNIEnv *env, jsize length) {
	jobject *res;
 sf_overwrite(&res);
 sf_set_possible_null(res);
 return res;
}

struct JsonGenerator * json_generator_new() {
}

void json_generator_set_root (struct JsonGenerator *generator, struct JsonNode *node) {
}

struct JsonNode *json_generator_get_root (struct JsonGenerator *generator) {
}

void json_generator_set_pretty (struct JsonGenerator *generator, gboolean is_pretty) {
}

void json_generator_set_indent (struct JsonGenerator *generator, guint indent_level) {
}

guint json_generator_get_indent (struct JsonGenerator *generator) {
}

gunichar json_generator_get_indent_char (struct JsonGenerator *generator) {
}

gboolean json_generator_to_file (struct JsonGenerator *generator, const gchar *filename, struct GError **error) {
}

gchar *json_generator_to_data (struct JsonGenerator *generator, gsize *length) {
    void *ptr;
    sf_overwrite(&ptr);
    sf_overwrite(ptr);
    sf_new(ptr, GLIB_CATEGORY);
    if(length) {
    	sf_overwrite(length);
        sf_set_buf_size(ptr, *length);
        sf_set_alloc_possible_null(ptr, *length);
    }
    return ptr;

}

gboolean json_generator_to_stream (struct JsonGenerator *generator, struct GOutputStream *stream, struct GCancellable *cancellable, struct GError **error) {
    //cancellable, error may be 0
    //return TRUE or FALSE
}

char *basename(char *path) {
    sf_tocttou_access(path);
}

char *dirname(char *path) {
    sf_tocttou_access(path);
}

char *textdomain(const char *domainname) {
    char *res;
    sf_overwrite(&res);
    sf_set_alloc_possible_null(res);//no memory for string allocation
    return res;
}

char *bindtextdomain(const char *domainname, const char *dirname) {
    sf_tocttou_access(dirname);

    char *res;
    sf_overwrite(&res);
    sf_set_alloc_possible_null(res);//no memory for string allocation
    return res;
}

void *kcalloc(size_t n, size_t size, gfp_t flags) {
	//return kmalloc_array(n, size, flags | __GFP_ZERO);
}

void *kmalloc_array(size_t n, size_t size, gfp_t flags) {
	//if (size != 0 && n > SIZE_MAX / size)
	//	return NULL;
	//return __kmalloc(n * size, flags);
}

void *kzalloc_node(size_t size, gfp_t flags, int node) {
	//return kmalloc_node(size, flags | __GFP_ZERO, node);
}

void *kmalloc(size_t size, gfp_t flags) {
	void *ptr;
 sf_overwrite(&ptr);
 sf_overwrite(ptr);
 sf_set_alloc_possible_null(ptr, size);
 sf_new(ptr, KMALLOC_CATEGORY);
 sf_set_buf_size(ptr, size);
 return ptr;;
}

void *kzalloc(size_t size, gfp_t flags) {
}

void *__kmalloc(size_t size, gfp_t flags) {
    //KRAWMALLOC(size);
	void *ptr;
 sf_overwrite(&ptr);
 sf_overwrite(ptr);
 sf_set_alloc_possible_null(ptr, size);
 sf_new(ptr, KMALLOC_CATEGORY);
 sf_set_buf_size(ptr, size);
 return ptr;;//note: about raw initializing: flags may be __GFP_ZERO - init by zero
}

void *__kmalloc_node(size_t size, gfp_t flags, int node) {
	//KMALLOC_CATEGORY ??
	//KRAWMALLOC(size);
	void *ptr;
 sf_overwrite(&ptr);
 sf_overwrite(ptr);
 sf_set_alloc_possible_null(ptr, size);
 sf_new(ptr, KMALLOC_CATEGORY);
 sf_set_buf_size(ptr, size);
 return ptr;;//note: about raw initializing: flags may be __GFP_ZERO - init by zero
}

void *kmemdup(const void *src, size_t len, gfp_t gfp) {
	//KMALLOC_CATEGORY ??
	void *ptr;
 sf_overwrite(&ptr);
 sf_overwrite(ptr);
 sf_set_alloc_possible_null(ptr, len);
 sf_new(ptr, KMALLOC_CATEGORY);
 sf_set_buf_len(ptr, len);
 return ptr;;
}

void *memdup_user(const void /*__user*/ *src, size_t len) {
	//KMALLOC_CATEGORY ??
	void *ptr;
 sf_overwrite(&ptr);
 sf_overwrite(ptr);
 sf_set_alloc_possible_null(ptr, len);
 sf_new(ptr, KMALLOC_CATEGORY);
 sf_set_buf_len(ptr, len);
 return ptr;;
}

char *kstrdup(const char *s, gfp_t gfp) {
	void *ptr;
 sf_overwrite(&ptr);
 sf_overwrite(ptr);
 sf_set_alloc_possible_null(ptr);
 sf_new(ptr, KMALLOC_CATEGORY);
 return ptr;;
}

char *kasprintf(gfp_t gfp, const char *fmt, ...) {
	void *ptr;
 sf_overwrite(&ptr);
 sf_overwrite(ptr);
 sf_set_alloc_possible_null(ptr);
 sf_new(ptr, KMALLOC_CATEGORY);
 return ptr;;
}

void kfree(const void *x) {
    //sf_overwrite(x);
    sf_delete(x, KMALLOC_CATEGORY);
}

void kzfree(const void *x) {
	//sf_overwrite(x);
    sf_delete(x, KMALLOC_CATEGORY);
	//fill with 0
}

void _raw_spin_lock(raw_spinlock_t *mutex) {
    sf_lock(mutex);
}

void _raw_spin_unlock(raw_spinlock_t *mutex) {
    sf_unlock(mutex);
}

int _raw_spin_trylock(raw_spinlock_t *mutex) {
	sf_trylock(mutex);
}

void __raw_spin_lock(raw_spinlock_t *mutex) {
    sf_lock(mutex);
}

void __raw_spin_unlock(raw_spinlock_t *mutex) {
    sf_unlock(mutex);
}

int __raw_spin_trylock(raw_spinlock_t *mutex) {
	sf_trylock(mutex);
}

void *vmalloc(unsigned long size) {
    void *ptr;
    sf_overwrite(&ptr);
    sf_overwrite(ptr);
    sf_set_alloc_possible_null(ptr, size);
    sf_new(ptr, VMALLOC_CATEGORY);
    sf_set_buf_size(ptr, size);
    return ptr;
}

void vfree(const void *addr) {
    //sf_overwrite(addr);
    sf_delete(addr, VMALLOC_CATEGORY);
}

void *vrealloc(void *ptr, size_t size) {
	sf_escape(ptr);

    sf_set_trusted_sink_int(size);

    void *retptr;
    sf_overwrite(&retptr);
    sf_overwrite(retptr);
	sf_uncontrolled_ptr(retptr);
    sf_set_alloc_possible_null(retptr, size);
    sf_new(retptr, VMALLOC_CATEGORY);
    sf_set_buf_size(retptr, size);
    return retptr;
}

vchar_t * vdup(vchar_t* src) {
    vchar_t* res;
    sf_overwrite(&res);
    sf_overwrite(res);

    sf_set_alloc_possible_null(res);
    sf_new(res, VMALLOC_CATEGORY);
    sf_strdup_res(res);
    return res;
}

int tty_register_driver(struct tty_driver *driver) {
    {
    int ret;
    driverf_overwrite(&ret);
    driverf_overwrite((driver)->ptr);
    driverf_handle_acquire((driver)->ptr, (TTY_REGISTER_DRIVER_CATEGORY));
    driverf_not_acquire_if_ledriverdriver((driver)->ptr, ret, 0);
    return ret;
    }
}

int tty_unregister_driver(struct tty_driver *driver) {
    {
    if (driver)
    driverf_handle_releadrivere((driver)->ptr, (TTY_REGISTER_DRIVER_CATEGORY));
    return 0;
    }
}

int device_create_file(struct device *dev, struct device_attribute *dev_attr) {
    {
    int ret;
    dev_attrf_overwrite(&ret);
    dev_attrf_overwrite((dev_attr)->ptr);
    dev_attrf_handle_acquire((dev_attr)->ptr, (DEVICE_CREATE_FILE_CATEGORY));
    dev_attrf_not_acquire_if_ledev_attrdev_attr((dev_attr)->ptr, ret, 0);
    return ret;
    }
}

void device_remove_file(struct device *dev, struct device_attribute *dev_attr) {
    {
    if (dev_attr)
    dev_attrf_handle_releadev_attre((dev_attr)->ptr, (DEVICE_CREATE_FILE_CATEGORY));
    }
}

int platform_device_register(struct platform_device *pdev) {
    {
    int ret;
    pdevf_overwrite(&ret);
    pdevf_overwrite((pdev)->ptr);
    pdevf_handle_acquire((pdev)->ptr, (PLATFORM_DEVICE_REGISTER_CATEGORY));
    pdevf_not_acquire_if_lepdevpdev((pdev)->ptr, ret, 0);
    return ret;
    }
}

void platform_device_unregister(struct platform_device *pdev) {
    {
    if (pdev)
    pdevf_handle_releapdeve((pdev)->ptr, (PLATFORM_DEVICE_REGISTER_CATEGORY));
    }
}

int platform_driver_register(struct platform_driver *drv) {
    {
    int ret;
    drvf_overwrite(&ret);
    drvf_overwrite((drv)->ptr);
    drvf_handle_acquire((drv)->ptr, (PLATFORM_DRIVER_REGISTER_CATEGORY));
    drvf_not_acquire_if_ledrvdrv((drv)->ptr, ret, 0);
    return ret;
    }
}

void platform_driver_unregister(struct platform_driver *drv) {
    {
    if (drv)
    drvf_handle_releadrve((drv)->ptr, (PLATFORM_DRIVER_REGISTER_CATEGORY));
    }
}

int misc_register(struct miscdevice *misc) {
    {
    int ret;
    miscf_overwrite(&ret);
    miscf_overwrite((misc)->ptr);
    miscf_handle_acquire((misc)->ptr, (MISC_REGISTER_CATEGORY));
    miscf_not_acquire_if_lemiscmisc((misc)->ptr, ret, 0);
    return ret;
    }
}

int misc_deregister(struct miscdevice *misc) {
    {
    if (misc)
    miscf_handle_releamisce((misc)->ptr, (MISC_REGISTER_CATEGORY));
    return 0;
    }
}

int input_register_device(struct input_dev *dev) {
    {
    int ret;
    devf_overwrite(&ret);
    devf_overwrite((dev)->ptr);
    devf_handle_acquire((dev)->ptr, (INPUT_REGISTER_DEVICE_CATEGORY));
    devf_not_acquire_if_ledevdev((dev)->ptr, ret, 0);
    return ret;
    }
}

void input_unregister_device(struct input_dev *dev) {
    {
    if (dev)
    devf_handle_releadeve((dev)->ptr, (INPUT_REGISTER_DEVICE_CATEGORY));
    }
}

struct input_dev *input_allocate_device(void) {
    __my_acquire__(INPUT_ALLOCATE_DEVICE_CATEGORY)
}

void input_free_device(struct input_dev *dev) {
    {
    sf_handle_release((dev), (INPUT_ALLOCATE_DEVICE_CATEGORY));
    }
}

int rfkill_register(struct rfkill *rfkill) {
    {
    int ret;
    rfkillf_overwrite(&ret);
    rfkillf_overwrite((rfkill)->ptr);
    rfkillf_handle_acquire((rfkill)->ptr, (RFKILL_REGISTER_CATEGORY));
    rfkillf_not_acquire_if_lerfkillrfkill((rfkill)->ptr, ret, 0);
    return ret;
    }
}

void rfkill_unregister(struct rfkill *rfkill) {
    {
    if (rfkill)
    rfkillf_handle_relearfkille((rfkill)->ptr, (RFKILL_REGISTER_CATEGORY));
    }
}

int snd_soc_register_codec(struct device *dev, const struct snd_soc_codec_driver *codec_drv, struct snd_soc_dai_driver *dai_drv, int num_dai) {
    {
    int ret;
    devf_overwrite(&ret);
    devf_overwrite((dev)->ptr);
    devf_handle_acquire((dev)->ptr, (SND_SOC_REGISTER_CODEC_CATEGORY));
    devf_not_acquire_if_ledevdev((dev)->ptr, ret, 0);
    return ret;
    }
}

void snd_soc_unregister_codec(struct device *dev) {
    {
    if (dev)
    devf_handle_releadeve((dev)->ptr, (SND_SOC_REGISTER_CODEC_CATEGORY));
    }

}

struct class *class_create(void *owner, void *name) {
    __my_acquire__(CLASS_CREATE_CATEGORY)
}

struct class *__class_create(void *owner, void *name) {
    __my_acquire__(CLASS_CREATE_CATEGORY)
}

void class_destroy(struct class *cls) {
    {
    sf_handle_release((cls), (CLASS_CREATE_CATEGORY));
    }
}

struct platform_device *platform_device_alloc(const char *name, int id) {
    __my_acquire__(PLATFORM_DEVICE_ALLOC_CATEGORY)
}

void platform_device_put(struct platform_device *pdev) {
    {
    sf_handle_release((pdev), (PLATFORM_DEVICE_ALLOC_CATEGORY));
    }
}

void rfkill_alloc(struct rfkill *rfkill, bool blocked) {
    {
    if (rfkill)
    rfkillf_handle_acquire((rfkill)->ptr, (RFKILL_ALLOC_CATEGORY));
    };
}

void rfkill_destroy(struct rfkill *rfkill) {
    //__my_ptr_release__(rfkill, RFKILL_ALLOC_CATEGORY)
}

void *ioremap(struct phys_addr_t offset, unsigned long size) {
    __my_acquire__(IOREMAP_CATEGORY)
}

void iounmap(void *addr) {
    {
    sf_handle_release((addr), (IOREMAP_CATEGORY));
    }
}

int clk_enable(struct clk *clk) {
    {
    int ret;
    clkf_overwrite(&ret);
    clkf_overwrite((clk)->ptr);
    clkf_handle_acquire((clk)->ptr, (CLK_ENABLE_CATEGORY));
    clkf_not_acquire_if_leclkclk((clk)->ptr, ret, 0);
    return ret;
    }
}

void clk_disable(struct clk *clk) {
    {
    if (clk)
    clkf_handle_releaclke((clk)->ptr, (CLK_ENABLE_CATEGORY));
    }
}

struct regulator *regulator_get(struct device *dev, const char *id) {
    __my_acquire__(REGULATOR_GET_CATEGORY)
}

void regulator_put(struct regulator *regulator) {
    {
    sf_handle_release((regulator), (REGULATOR_GET_CATEGORY));
    }
}

int regulator_enable(struct regulator *regulator) {
    {
    int ret;
    regulatorf_overwrite(&ret);
    regulatorf_overwrite((regulator)->ptr);
    regulatorf_handle_acquire((regulator)->ptr, (REGULATOR_ENABLE_CATEGORY));
    regulatorf_not_acquire_if_leregulatorregulator((regulator)->ptr, ret, 0);
    return ret;
    }
}

int regulator_disable(struct regulator *regulator) {
    {
    if (regulator)
    regulatorf_handle_relearegulatore((regulator)->ptr, (REGULATOR_ENABLE_CATEGORY));
    return 0;
    }
}

struct workqueue_struct *create_workqueue(void *name) {
    __my_acquire__(CREATE_WORKQUEUE_CATEGORY)
}

struct workqueue_struct *create_singlethread_workqueue(void *name) {
    __my_acquire__(CREATE_WORKQUEUE_CATEGORY)
}

struct workqueue_struct *create_freezable_workqueue(void *name) {
    __my_acquire__(CREATE_WORKQUEUE_CATEGORY)
}

void destroy_workqueue(struct workqueue_struct *wq) {
    {
    sf_handle_release((wq), (CREATE_WORKQUEUE_CATEGORY));
    }
}

void add_timer (struct timer_list *timer) {
    {
    if (timer)
    timerf_handle_acquire((timer)->ptr, (ADD_TIMER_CATEGORY));
    }
}

int del_timer(struct timer_list *timer) {
    {
    if (timer)
    timerf_handle_releatimere((timer)->ptr, (ADD_TIMER_CATEGORY));
    return 0;
    }
}

struct task_struct *kthread_create(int(*threadfn)(void *data), void *data, const char namefmt[]) {
    __my_acquire__(KTHREAD_CREATE_CATEGORY)
}

void put_task_struct(struct task_struct *t) {
    {
    sf_handle_release((t), (KTHREAD_CREATE_CATEGORY));
    }
}

struct tty_driver *alloc_tty_driver(int lines) {
    __my_acquire__(ALLOC_TTY_DRIVER_CATEGORY)
}

struct tty_driver *__alloc_tty_driver(int lines) {
    __my_acquire__(ALLOC_TTY_DRIVER_CATEGORY)
}

void put_tty_driver(struct tty_driver *d) {
    {
    sf_handle_release((d), (ALLOC_TTY_DRIVER_CATEGORY));
    }
}

int luaL_error(struct lua_State *L, const char *fmt, ...) {
    sf_terminate_path();

    int res;
    sf_overwrite(&res);
    return res;    
}

void *mmap(void *addr, size_t len, int prot, int flags, int fildes, off_t off) {
	sf_set_trusted_sink_int(len);

	void *res;
	sf_overwrite(&res);
	sf_overwrite(res);
	sf_uncontrolled_ptr(res);
	sf_handle_acquire(res, MMAP_CATEGORY);
	sf_not_acquire_if_less(res, res, 1);
	return res;
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

FILE *setmntent(const char *filename, const char *type) {
    sf_tocttou_access(filename);
}

int mount(const char *source, const char *target, const char *filesystemtype, unsigned long mountflags, const void *data) {
    sf_tocttou_access(source);
    sf_tocttou_access(target);

	sf_set_trusted_sink_ptr(source);
	sf_set_trusted_sink_ptr(target);
}

int umount(const char *target) {
    sf_tocttou_access(target);
	sf_set_trusted_sink_ptr(target);
}

void mutex_lock(struct mutex *lock) {
    sf_lock(lock);
}

void mutex_unlock(struct mutex *lock) {
    sf_unlock(lock);
}

void mutex_lock_nested(struct mutex *lock, unsigned int subclass) {
    sf_lock(lock);
}

int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
    sf_overwrite(res);
	sf_handle_acquire(*res, GETADDRINFO_CATEGORY);

	int code;
    sf_overwrite(&code);
	sf_overwrite_int_as_ptr(code);
	sf_set_possible_negative(code);
	sf_not_acquire_if_greater(*res, code, 0);
	sf_not_acquire_if_less(*res, code, 0);
    return code;
}

void freeaddrinfo(struct addrinfo *res) {
    sf_overwrite(res);
    sf_handle_release(res, GETADDRINFO_CATEGORY);
}

int catopen(const char *fname, int flag) {
    sf_tocttou_access(fname);
}

int SHA256_Init(SHA256_CTX *sha) {
    sf_overwrite(sha);

    int res;
    sf_overwrite(&res);
    return res;
}

int SHA256_Update(SHA256_CTX *sha, const void *data, size_t len) {
    sf_overwrite(sha);

    int res;
    sf_overwrite(&res);
    return res;
}

int SHA256_Final(uint8_t out[SHA256_DIGEST_LENGTH], SHA256_CTX *sha) {
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

int SHA384_Update(SHA512_CTX *sha, const void *data, size_t len) {
    sf_overwrite(sha);

    int res;
    sf_overwrite(&res);
    return res;
}

int SHA384_Final(uint8_t out[SHA384_DIGEST_LENGTH], SHA512_CTX *sha) {
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

int SHA512_Update(SHA512_CTX *sha, const void *data, size_t len) {
    sf_overwrite(sha);

    int res;
    sf_overwrite(&res);
    return res;
}

int SHA512_Final(uint8_t out[SHA512_DIGEST_LENGTH], SHA512_CTX *sha) {
    sf_overwrite(sha);

    int res;
    sf_overwrite(&res);
    return res;
}

CMS_RecipientInfo *CMS_add0_recipient_key(CMS_ContentInfo *cms, int nid, unsigned char *key, size_t keylen, unsigned char *id, size_t idlen, ASN1_GENERALIZEDTIME *date, ASN1_OBJECT *otherTypeId, ASN1_TYPE *otherType) {
    sf_password_use(key);
}

EVP_PKEY *EVP_PKEY_new_mac_key(int type, ENGINE *e, const unsigned char *key, int keylen) {
    sf_password_use(key);
}

EVP_PKEY *EVP_PKEY_new_raw_private_key(int type, ENGINE *e, const unsigned char *key, size_t keylen) {
    sf_password_use(key);
}

EVP_PKEY *EVP_PKEY_new_raw_public_key(int type, ENGINE *e, const unsigned char *key, size_t keylen) {
    sf_password_use(key);
}

int CMS_RecipientInfo_set0_key(CMS_RecipientInfo *ri, unsigned char *key, size_t keylen) {
    sf_password_use(key);
}

int CTLOG_new_from_base64(CTLOG ** ct_log, const char *pkey_base64, const char *name) {
    sf_password_use(pkey_base64);
}

int DH_compute_key(unsigned char *key, BIGNUM *pub_key, DH *dh) {
    sf_bitinit(key);
    sf_password_set(key);
}

int compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh) {
    sf_bitinit(key);
    sf_password_set(key);
}

int EVP_BytesToKey(const EVP_CIPHER *type, const EVP_MD *md, const unsigned char *salt, const unsigned char *data, int datal, int count, unsigned char *key, unsigned char *iv) {
    sf_password_use(salt);
    sf_bitinit(key);
    sf_password_set(key);
    sf_bitinit(iv);
    sf_password_set(iv);
}

int EVP_CIPHER_CTX_rand_key(EVP_CIPHER_CTX *ctx, unsigned char *key) {
    sf_bitinit(key);
    sf_password_set(key);
}

int EVP_CipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, const unsigned char *key, const unsigned char *iv, int enc) {
    sf_password_use(key);
    sf_password_use(iv);
}

int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv, int enc) {
    sf_password_use(key);
    sf_password_use(iv);
}

int EVP_DecryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, const unsigned char *key, const unsigned char *iv) {
    sf_password_use(key);
    sf_password_use(iv);
}

int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv) {
    sf_password_use(key);
    sf_password_use(iv);
}

int EVP_EncryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, const unsigned char *key, const unsigned char *iv) {
    sf_password_use(key);
    sf_password_use(iv);
}

int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv) {
    sf_password_use(key);
    sf_password_use(iv);
}

int EVP_PKEY_CTX_set1_hkdf_key(EVP_PKEY_CTX *pctx, unsigned char *key, int keylen) {
    sf_password_use(key);
}

int EVP_PKEY_CTX_set_mac_key(EVP_PKEY_CTX *ctx, unsigned char *key, int len) {
    sf_password_use(key);
}

int EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen) {
    sf_bitinit(key);
    sf_password_set(key);
    if (!key)
        sf_overwrite(keylen);
}

void BIO_set_cipher(BIO *b, const EVP_CIPHER *cipher, unsigned char *key, unsigned char *iv, int enc) {
    sf_password_use(key);
    sf_password_use(iv);
}

EVP_PKEY *EVP_PKEY_new_CMAC_key(ENGINE *e, const unsigned char *priv, size_t len, const EVP_CIPHER *cipher) {
    sf_password_use(priv);
}

int EVP_OpenInit(EVP_CIPHER_CTX *ctx, EVP_CIPHER *type, unsigned char *ek, int ekl, unsigned char *iv, EVP_PKEY *priv) {
    sf_password_use(iv);
}

int EVP_PKEY_get_raw_private_key(const EVP_PKEY *pkey, unsigned char *priv, size_t *len) {
    sf_overwrite(len);
    sf_bitinit(priv);
    sf_password_set(priv);
}

int EVP_SealInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, unsigned char **ek, int *ekl, unsigned char *iv, EVP_PKEY **pubk, int npubk) {
    sf_password_use(iv);
}

void BF_cbc_encrypt(const unsigned char *in, unsigned char *out, long length, BF_KEY *schedule, unsigned char *ivec, int enc) {
    sf_bitinit(out);
    sf_password_use(ivec);
}

void BF_cfb64_encrypt(const unsigned char *in, unsigned char *out, long length, BF_KEY *schedule, unsigned char *ivec, int *num, int enc) {
    sf_bitinit(out);
    sf_password_use(ivec);
}

void BF_ofb64_encrypt(const unsigned char *in, unsigned char *out, long length, BF_KEY *schedule, unsigned char *ivec, int *num) {
    sf_bitinit(out);
    sf_password_use(ivec);
}

int get_priv_key(const EVP_PKEY *pk, unsigned char *priv, size_t *len) {
    sf_bitinit(priv);
    sf_password_set(priv);
    sf_overwrite(len);
}

int set_priv_key(EVP_PKEY *pk, const unsigned char *priv, size_t len) {
    sf_password_use(priv);
}

char *DES_crypt(const char *buf, const char *salt) {
    sf_password_use(salt);
}

char *DES_fcrypt(const char *buf, const char *salt, char *ret) {
    sf_bitinit(ret);
    sf_password_use(salt);
}

int EVP_PKEY_CTX_set1_hkdf_salt(EVP_PKEY_CTX *pctx, unsigned char *salt, int saltlen) {
    sf_password_use(salt);
}

int PKCS5_PBKDF2_HMAC(const char *pass, int passlen, const unsigned char *salt, int saltlen, int iter, const EVP_MD *digest, int keylen, unsigned char *out) {
    sf_bitinit(out);
    sf_password_use(salt);
    sf_password_use(pass);
}

int PKCS5_PBKDF2_HMAC_SHA1(const char *pass, int passlen, const unsigned char *salt, int saltlen, int iter, int keylen, unsigned char *out) {
    sf_bitinit(out);
    sf_password_use(salt);
    sf_password_use(pass);
}

int PKCS12_newpass(PKCS12 *p12, const char *oldpass, const char *newpass) {
    sf_password_use(oldpass);
    sf_password_use(newpass);
}

int PKCS12_parse(PKCS12 *p12, const char *pass, EVP_PKEY **pkey, X509 **cert, STACK_OF(X509) **ca) {
    sf_password_use(pass);
}

PKCS12 *PKCS12_create(const char *pass, const char *name, EVP_PKEY *pkey, X509 *cert, STACK_OF(X509) *ca, int nid_key, int nid_cert, int iter, int mac_iter, int keytype) {
    sf_password_use(pass);
}

int EVP_PKEY_get_raw_public_key(const EVP_PKEY *pkey, unsigned char *pub, size_t *len) {
    sf_overwrite(len);
    sf_bitinit(pub);
    sf_password_set(pub);
}

int get_pub_key(const EVP_PKEY *pk, unsigned char *pub, size_t *len) {
    sf_bitinit(len);
    sf_bitinit(pub);
    sf_password_set(pub);
}

int set_pub_key(EVP_PKEY *pk, const unsigned char *pub, size_t len) {
    sf_password_use(pub);
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    int res;
    sf_overwrite(&res);
    sf_set_possible_negative(res);
    sf_must_be_checked(res);
    return res;
}

PGconn *PQconnectdb(const char *conninfo) {
    sf_password_use(conninfo);
}

PGconn *PQsetdbLogin(const char *pghost, const char *pgport, const char *pgoptions, const char *pgtty, const char *dbName, const char *login, const char *pwd) {
    sf_password_use(pwd);
}

PGconn *PQconnectStart(const char *conninfo) {
    sf_password_use(conninfo);
}

int PR_fprintf(struct PRFileDesc* stream, const char *format, ...) {
    struct PRFileDesc derefStream = *stream;
    char d1 = *format;
    sf_use_format(format);

    sf_fun_does_not_update_vargs(2);
}

int PR_snprintf(char *str, size_t size, const char *format, ...) {
    char d1 = *str;
    char d2 = *format;
    sf_use_format(format);

    sf_fun_does_not_update_vargs(3);
}

void pthread_exit(void *value_ptr) {
    sf_terminate_path();

    // easiest way to suppress 'noreturn' warning in gcc-genmif
    pthread_exit(value_ptr);
}

int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr) {
    sf_bitinit(mutex);

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

int pthread_mutex_unlock(pthread_mutex_t *mutex) {
    sf_unlock(mutex);
}

int pthread_mutex_trylock(pthread_mutex_t *mutex) {
    sf_trylock(mutex);
}

int pthread_spin_lock(pthread_spinlock_t *mutex) {
    sf_lock(mutex);

    int res;
    sf_overwrite(&res);
    sf_success_lock_if_zero(res, mutex);
    return res;
}

int pthread_spin_unlock(pthread_spinlock_t *mutex) {
    sf_unlock(mutex);
}

int pthread_spin_trylock(pthread_spinlock_t *mutex) {
    sf_trylock(mutex);
}

int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine) (void *), void *arg) {
    sf_bitinit(thread);
    sf_escape(arg);
    sf_thread_shared(arg);

    int res;
    sf_overwrite(&res);
    return res;
}

void __pthread_cleanup_routine (struct __pthread_cleanup_frame *__frame) {
    // tmp hack: delete when we will be able to devirtualize correctly
    sf_unlock(__frame->__cancel_arg);
    sf_escape(__frame->__cancel_arg);
}

struct passwd *getpwnam(const char *name) {
    struct passwd *res;
    sf_overwrite(&res);
    sf_set_possible_null(res);
    if (res != NULL) {
        sf_password_set(res->pw_name);
        sf_password_set(res->pw_passwd);
    }
    return res;
}

struct passwd *getpwuid(uid_t uid) {
    struct passwd *res;
    sf_overwrite(&res);
    sf_password_set(res->pw_name);
    sf_password_set(res->pw_passwd);
    return res;
}

void Py_FatalError(const char *message) {
    sf_terminate_path();
}

void *OEM_Malloc(uint32 uSize) {
    void *ptr;
    sf_overwrite(&ptr);
    sf_overwrite(ptr);
    sf_set_alloc_possible_null(ptr, uSize);
    sf_new(ptr, MALLOC_CATEGORY);
    /* sf_raw_new(ptr); */
    /* sf_set_buf_size(ptr, uSize); */
    return ptr;
}

void *aee_malloc(uint32 dwSize) {
    void *ptr;
    sf_overwrite(&ptr);
    sf_overwrite(ptr);
    sf_set_alloc_possible_null(ptr, dwSize);
    sf_new(ptr, MALLOC_CATEGORY);
    /* sf_raw_new(ptr); */
    /* sf_set_buf_size(ptr, dwSize); */
    return ptr;
}

void OEM_Free(void *p) {
    sf_overwrite(p);
    sf_delete(p, MALLOC_CATEGORY);
}

void aee_free(void *p) {
    sf_overwrite(p);
    sf_delete(p, MALLOC_CATEGORY);
}

void *OEM_Realloc(void *p, uint32 uSize) {
    void *ptr;
    sf_escape(p);
    sf_overwrite(&ptr);
    sf_overwrite(ptr);
    sf_set_alloc_possible_null(ptr, uSize);
    sf_new(ptr, MALLOC_CATEGORY);
    /* sf_raw_new(ptr); */
    /* sf_set_buf_size(ptr, uSize); */
    return ptr;
}

void *aee_realloc(void *p, uint32 dwSize) {
    void *ptr;
    sf_escape(p);
    sf_overwrite(&ptr);
    sf_overwrite(ptr);
    sf_set_alloc_possible_null(ptr, dwSize);
    sf_new(ptr, MALLOC_CATEGORY);
    /* sf_raw_new(ptr); */
    /* sf_set_buf_size(ptr, dwSize); */
    return ptr;
}

void err_fatal_core_dump(unsigned int line, const char *file_name, const char *format) {
    sf_terminate_path();
}

long quotactl(int cmd, char *spec, int id, caddr_t addr) {
    sf_tocttou_access(spec);
}

int sem_wait (sem_t *_sem) {
    sf_sync(_sem);
    //commented due too useless DOUBLE_LOCK
	//sf_lock(_sem);
}

int sem_post (sem_t *_sem) {
    sf_sync(_sem);
	//sf_unlock(_sem);
}

void longjmp(jmp_buf env, int value) {
    sf_terminate_path();
}

void siglongjmp(sigjmp_buf env, int val) {
    sf_terminate_path();
}

int setjmp(jmp_buf env) {
    int ret;
    sf_overwrite(&ret);
    sf_overwrite(env);
    return ret;
}

int sigsetjmp(sigjmp_buf env, int savesigs) {
    int ret;
    sf_overwrite(&ret);
    sf_overwrite(env);
    return ret;
}

void pal_MemFreeDebug(void** mem, char* file, int line) {
    sf_overwrite(*mem);
    sf_delete(*mem, PAL_MALLOC_CATEGORY);
}

void * pal_MemAllocTrack(int mid, int size, char* file, int line) {
    void *ptr;
    sf_overwrite(&ptr);
    sf_overwrite(ptr);
    sf_set_must_be_positive(size);
    sf_set_possible_null(ptr);
    sf_new(ptr, PAL_MALLOC_CATEGORY);
    /* sf_raw_new(ptr); */
    /* sf_set_buf_size(ptr, size); */
    return ptr;
}

void * pal_MemAllocGuard(int mid, int size) {
    void *ptr;
    sf_overwrite(&ptr);
    sf_overwrite(ptr);
    sf_set_must_be_positive(size);
    sf_set_possible_null(ptr);
    sf_new(ptr, PAL_MALLOC_CATEGORY);
    /* sf_raw_new(ptr); */
    /* sf_set_buf_size(ptr, size); */
    return ptr;
}

void * pal_MemAllocInternal(int mid, int size, char* file, int line) {
    void *ptr;
    sf_overwrite(&ptr);
    sf_overwrite(ptr);
    sf_set_must_be_positive(size);
    sf_set_possible_null(ptr);
    sf_new(ptr, PAL_MALLOC_CATEGORY);
    /* sf_raw_new(ptr); */
    /* sf_set_buf_size(ptr, size); */
    return ptr;
}

int raise (int sig) {
    if(sig == SIGABRT || sig == SIGKILL)
        sf_terminate_path();
}

int kill(pid_t pid, int sig) {
    int ret;
    sf_overwrite(&ret);
    sf_set_possible_negative(ret);
    return ret;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t len) {
	sf_set_must_be_positive(sockfd);
	sf_lib_arg_type(sockfd, "SocketCategory");

	int res;
    sf_overwrite(&res);
    sf_set_possible_negative(res);
    sf_uncontrolled_value(res);
    
    return res;
}

int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
	sf_must_not_be_release(sockfd);
    sf_set_must_be_positive(sockfd);
    sf_lib_arg_type(sockfd, "SocketCategory");

	int res;
    sf_overwrite(&res);
	sf_set_possible_negative(res);
		
    return res;
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

int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen) {
  sf_bitinit(optval);
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

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    char d = *((char*)addr);
    // mark read of the last byte of the structure
    if(addr) {
        char c = ((char *)addr)[addrlen - 1];
    }

    sf_must_not_be_release(sockfd);
    sf_set_must_be_positive(sockfd);
    sf_lib_arg_type(sockfd, "SocketCategory");

	int res;
    sf_overwrite(&res);
    sf_set_possible_negative(res);
    sf_uncontrolled_value(res);

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

ssize_t send(int s, const void *buf, size_t len, int flags) {
	sf_must_not_be_release(s);
    sf_set_must_be_positive(s);
    sf_lib_arg_type(s, "SocketCategory");
    
    sf_buf_size_limit(buf, len);
    sf_buf_size_limit_read(buf, len);
    
	ssize_t res;
	sf_overwrite(&res);
	sf_set_possible_negative(res);
    sf_uncontrolled_value(res);
	return res;
}

ssize_t sendto(int s, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
	sf_must_not_be_release(s);
    sf_set_must_be_positive(s);
    sf_lib_arg_type(s, "SocketCategory");
    
    sf_buf_size_limit(buf, len);
    sf_buf_size_limit_read(buf, len);

	ssize_t res;
	sf_overwrite(&res);
	sf_set_possible_negative(res);
	return res;
}

ssize_t sendmsg(int s, const struct msghdr*msg, int flags) {
	sf_must_not_be_release(s);
    sf_set_must_be_positive(s);
    sf_lib_arg_type(s, "SocketCategory");

	ssize_t res;
	sf_overwrite(&res);
	sf_set_possible_negative(res);
	return res;
}

int setsockopt(int socket, int level, int option_name, const void *option_value, socklen_t option_len) {
	sf_must_not_be_release(socket);
    sf_set_must_be_positive(socket);
    sf_lib_arg_type(socket, "SocketCategory");

	int res;
    sf_use(option_value);
	sf_overwrite(&res);
	sf_set_possible_negative(res);
	return res;
}

int shutdown(int socket, int how) {
	sf_must_not_be_release(socket);
    sf_set_must_be_positive(socket);
    sf_lib_arg_type(socket, "SocketCategory");

	//note: shutdown doesn't release a socked. It only cloase connection but function close still should be called.
	//sf_handle_release(socket, SOCKET_CATEGORY);
	
}

int socket(int domain, int type, int protocol) {
	int res;
    sf_overwrite(&res);
	sf_overwrite_int_as_ptr(res);
    sf_handle_acquire_int_as_ptr(res, SOCKET_CATEGORY);
	sf_not_acquire_if_less_int_as_ptr(res, res, 1);
	sf_set_possible_negative(res);
    sf_uncontrolled_value(res);
    sf_set_errno_if(res, sf_cond_range("==", -1));
    sf_no_errno_if(res, sf_cond_range(">=", 0));
    sf_lib_arg_type(res, "SocketCategory");
    return res;
}

int sf_get_values(int min, int max) {
    int res = sf_get_some_int();
    sf_set_values(res, min, max);
    return res;
}

int sf_get_bool(void) {
    return sf_get_values(0, 1);
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

int sf_get_some_nonnegative_int(void) {
    int res = sf_get_some_int();
    sf_assert_cond(res, ">=", 0);
    return res;
}

int sf_get_some_int_to_check(void) {
    int res = sf_get_some_int();
    sf_must_be_checked(res);
    return res;
}

void *sf_get_uncontrolled_ptr(void) {
    void *res;
    sf_overwrite(&res);
    sf_uncontrolled_ptr(res);
    return res;
}

void sf_set_trusted_sink_nonnegative_int(int n) {
    if (n >= 0) {
        sf_set_trusted_sink_int(n);
    }
}

char *__alloc_some_string(void) {
    char *res = (char *)sf_get_uncontrolled_ptr();
    sf_new(res, SQLITE3_MALLOC_CATEGORY);
    sf_set_alloc_possible_null(res);
    sf_null_terminated(res); // ?
    sf_strdup_res(res); // ?
    return res;
}

void *__get_nonfreeable(void) {
    void *res = sf_get_uncontrolled_ptr();
    sf_new(res, SQLITE3_NONFREEABLE_CATEGORY);
    sf_escape(res);
    return res;
}

void *__get_nonfreeable_tainted(void) {
    void *res = __get_nonfreeable();
    sf_set_tainted(res);
    return res;
}

void *__get_nonfreeable_possible_null(void) {
    void *res = __get_nonfreeable();
    //sf_set_alloc_possible_null(res); // ?
    sf_set_possible_null(res);
    return res;
}

void *__get_nonfreeable_tainted_possible_null(void) {
    void *res = __get_nonfreeable_tainted();
    //sf_set_alloc_possible_null(res); // ?
    sf_set_possible_null(res);
    return res;
}

void *__get_nonfreeable_not_null(void) {
    void *res = __get_nonfreeable();
    sf_not_null(res);
    return res;
}

char *__get_nonfreeable_string(void) {
    char *res = (char *)__get_nonfreeable();
    sf_null_terminated(res); // ?
    sf_strdup_res(res); // ?
    return res;
}

char *__get_nonfreeable_possible_null_string(void) {
    char *res = (char *)__get_nonfreeable_possible_null();
    sf_null_terminated(res); // ?
    sf_strdup_res(res); // ?
    return res;
}

char *__get_nonfreeable_not_null_string(void) {
    char *res = (char *)__get_nonfreeable_not_null();
    sf_null_terminated(res); // ?
    sf_strdup_res(res); // ?
    return res;
}

char *__get_nonfreeable_tainted_possible_null_string(void) {
    char *res = (char *)__get_nonfreeable_tainted_possible_null();
    sf_null_terminated(res); // ?
    sf_strdup_res(res); // ?
    return res;
}

char *sqlite3_libversion(void) {
    return __get_nonfreeable_not_null_string();
}

char *sqlite3_sourceid(void) {
    return __get_nonfreeable_not_null_string();
}

int sqlite3_libversion_number(void) {
    int res = sf_get_some_int();
    sf_pure(res);
    //sf_assert_cond(res, ">=", 0); // ?
    return res;
}

int sqlite3_compileoption_used(const char *zOptName) {
    { unsigned char tmp = *(unsigned char *)(zOptName); tmp++; };
    sf_buf_stop_at_null(zOptName);
    return sf_get_bool();
}

char *sqlite3_compileoption_get(int N) {
    return __get_nonfreeable_possible_null_string();
}

int sqlite3_threadsafe(void) {
    //return SQLITE_THREADSAFE;
    // Quote: "The SQLITE_THREADSAFE macro must be defined as 0, 1, or 2."
    return sf_get_values(0, 2);
}

int __close(sqlite3 *db) {
    sf_must_not_be_release(db);
    sf_handle_release(db, SQLITE3_DB_CATEGORY);
    
}

int sqlite3_close(sqlite3 *db) {
    return __close(db);
}

int sqlite3_close_v2(sqlite3 *db) {
    return __close(db);
}

int sqlite3_exec( sqlite3 *db, /* An open database */ const char *zSql, /* SQL to be evaluated */ int (*xCallback)(void*, int, char**, char**), /* Callback function */ void *pArg, /* 1st argument to callback */ char **pzErrMsg /* Error msg written here */) {
    sf_vulnerable_fun_type("Use parameterized query with sqlite3_prepare, directly use of sqlite3_exec() is not allowed", SQLITE);
    __SQLITE_db_R_ACCESS(db);
    SF_DEREF_WRITE(db);

    sf_set_trusted_sink_ptr(zSql);
    if (zSql) SF_DEREF_READ(zSql);
    sf_buf_stop_at_null(zSql);

    sf_escape(xCallback);

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
    __SQLITE_db_R_ACCESS(db);
    SF_DEREF_WRITE(db);
    return sf_get_some_int_to_check();
}

int sqlite3_extended_result_codes(sqlite3 *db, int onoff) {
    __SQLITE_db_R_ACCESS(db);
    SF_DEREF_WRITE(db);
    return sf_get_some_int();
}

sqlite3_int64 sqlite3_last_insert_rowid(sqlite3 *db) {
    __SQLITE_DB_R_ACCESS(db);
    return sf_get_some_int64();
}

void sqlite3_set_last_insert_rowid(sqlite3 *db, sqlite3_int64 rowid) {
    __SQLITE_db_R_ACCESS(db);
    SF_DEREF_WRITE(db);
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
    __SQLITE_db_R_ACCESS(db);
    SF_DEREF_WRITE(db); // ? in fact: w, and then r
}

int __complete(const char *sql) {
    { unsigned char tmp = *(unsigned char *)(sql); tmp++; };
    sf_buf_stop_at_null(sql);
    return sf_get_bool();
}

int sqlite3_complete(const char *sql) {
    return __complete(sql);
}

int sqlite3_complete16(const void *sql) {
    return __complete(sql);
}

int sqlite3_busy_handler( sqlite3 *db, int (*xBusy)(void*, int), void *pArg) {
    __SQLITE_db_R_ACCESS(db);
    SF_DEREF_WRITE(db);
    sf_escape(xBusy); // ?
    // sf_escape(pArg); // ?
    return sf_get_some_int();
}

int sqlite3_busy_timeout(sqlite3 *db, int ms) {
    __SQLITE_db_R_ACCESS(db);
    SF_DEREF_WRITE(db);
    return sf_get_some_int();
}

int sqlite3_get_table( sqlite3 *db, /* An open database */ const char *zSql, /* SQL to be evaluated */ char ***pazResult, /* Results of the query */ int *pnRow, /* Number of result rows written here */ int *pnColumn, /* Number of result columns written here */ char **pzErrMsg /* Error msg written here */) {
    sf_vulnerable_fun_type("sqlite3_get_table is a legacy interface that is preserved for backwards compatibility, use of this interface is not recommended", SQLITE);

    __SQLITE_db_R_ACCESS(db);
    SF_DEREF_WRITE(db);

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

char *sqlite3_mprintf(const char *zFormat, ...) {
    //sf_fun_printf_like(0); // SQLite extends standard library formats with %q, %Q, %w, and %z
    sf_fun_does_not_update_vargs(1);
    return __mprintf(zFormat);
}

char *sqlite3_vmprintf(const char *zFormat, va_list ap) {
    return __mprintf(zFormat);
}

char *__snprintf(int n, char *zBuf, const char *zFormat) {
    { unsigned char tmp = *(unsigned char *)(zFormat); tmp++; };
    sf_buf_stop_at_null(zFormat);
    sf_use_format(zFormat); // for tainted

    sf_buf_size_limit(zBuf, n);
    { *(unsigned char *)(zBuf) = (unsigned char)sf_get_some_int(); };
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

void *__malloc(sqlite3_int64 size) {
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

void *__realloc(void *ptr, sqlite3_uint64 size) {
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

int sqlite3_set_authorizer( sqlite3 *db, int (*xAuth)(void*, int, const char*, const char*, const char*, const char*), void *pUserData) {
    __SQLITE_db_R_ACCESS(db);
    SF_DEREF_WRITE(db);
    sf_escape(xAuth);
    sf_escape(pUserData);
    return sf_get_some_int_to_check();
}

void *sqlite3_trace( sqlite3 *db, void (*xTrace)(void*, const char*), void *pArg) {
    sf_vulnerable_fun_type("sqlite3_trace is deprecated, use the sqlite3_trace_v2() interface instead", SQLITE);
    __SQLITE_db_R_ACCESS(db);
    SF_DEREF_WRITE(db);
    sf_escape(xTrace); // ?
    //sf_escape(pArg); // ?
    void *res = sf_get_uncontrolled_ptr();
    sf_set_possible_null(res);
    return res;
}

void *sqlite3_profile( sqlite3 *db, void (*xProfile)(void*, const char*, sqlite3_uint64), void *pArg) {
    sf_vulnerable_fun_type("sqlite3_profile is deprecated, use the sqlite3_trace_v2() interface instead", SQLITE);
    __SQLITE_db_R_ACCESS(db);
    SF_DEREF_WRITE(db);
    sf_escape(xProfile); // ?
    //sf_escape(pArg); // ?
    void *res = sf_get_uncontrolled_ptr();
    sf_set_possible_null(res);
    return res;
}

int sqlite3_trace_v2( sqlite3 *db, unsigned uMask, int(*xCallback)(unsigned, void*, void*, void*), void *pCtx) {
    __SQLITE_db_R_ACCESS(db);
    SF_DEREF_WRITE(db);
    sf_escape(xCallback);
    sf_escape(pCtx);
    int res = sf_get_some_int();
    return res;
}

void sqlite3_progress_handler( sqlite3 *db, int nOps, int (*xProgress)(void*), void *pArg) {
    __SQLITE_db_R_ACCESS(db);
    SF_DEREF_WRITE(db);
    sf_escape(xProgress); // ?
    //sf_escape(pArg); // ?
}

int __sqlite3_open( const char *filename, sqlite3 **ppDb) {
    sf_tocttou_access(filename);
    sf_set_trusted_sink_ptr(filename);
    sf_buf_stop_at_null(filename);


    { *(unsigned char *)(ppDb) = (unsigned char)sf_get_some_int(); };

    int rc = sf_get_some_int_to_check();
    {
    sqlite3 *result;
    sf_overwrite(&result);
    sf_overwrite(result);
    sf_uncontrolled_value((int)(long long int)result);
    sf_uncontrolled_ptr(result);
    if (rc != SQLITE_OK) {
    sf_set_possible_null(result);
    }
    sf_handle_acquire(result, SQLITE3_DB_CATEGORY);
    sf_not_acquire_if_eq(result, (int)(long long int)result, 0);
    sf_not_acquire_if_less(result, rc, SQLITE_OK);
    sf_not_acquire_if_greater(result, rc, SQLITE_OK);
    *(ppDb) = result;
    };

    return rc;
}

int sqlite3_open( const char *filename, sqlite3 **ppDb) {
    return __sqlite3_open(filename, ppDb);
}

int sqlite3_open16( const void *filename, sqlite3 **ppDb) {
    return __sqlite3_open(filename, ppDb);
}

int sqlite3_open_v2( const char *filename, sqlite3 **ppDb, int flags, const char *zVfs) {
    sf_tocttou_access(zVfs);
    sf_set_trusted_sink_ptr(zVfs);
    sf_buf_stop_at_null(zVfs);
    return __sqlite3_open(filename, ppDb);
}

char *sqlite3_uri_parameter(const char *zFilename, const char *zParam) {
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
    if (db) SF_DEREF_READ(db); // or to treat as non-checked ?
//    return sf_get_some_int();
    return db->errCode;
}

int sqlite3_extended_errcode(sqlite3 *db) {
    if (db) SF_DEREF_READ(db); // or to treat as non-checked ?
//    return sf_get_some_int();
    return db->errCode;
}

char *sqlite3_errmsg(sqlite3 *db) {
    if (db) SF_DEREF_READ(db); // or to treat as non-checked ?
    return __get_nonfreeable_not_null_string();
}

void *sqlite3_errmsg16(sqlite3 *db) {
    if (db) SF_DEREF_READ(db); // or to treat as non-checked ?
    return __get_nonfreeable_not_null_string();
}

char *sqlite3_errstr(int rc) {
    return __get_nonfreeable_not_null_string();
}

int sqlite3_limit(sqlite3 *db, int id, int newVal) {
    sf_set_trusted_sink_nonnegative_int(id);
    sf_set_trusted_sink_nonnegative_int(newVal);
    __SQLITE_db_R_ACCESS(db);
    SF_DEREF_WRITE(db);
    return sf_get_some_int(); // non-negative
}

int __prepare( sqlite3 *db, const char *zSql, int nByte, sqlite3_stmt **ppStmt, const char **pzTail) {
    __SQLITE_db_R_ACCESS(db);
    SF_DEREF_WRITE(db);

    sf_set_trusted_sink_ptr(zSql);
    if (nByte < 0) {
        sf_buf_stop_at_null(zSql);
    } else {
        sf_buf_size_limit_read(zSql, nByte);
    }
    { unsigned char tmp = *(unsigned char *)(zSql); tmp++; };

    { *(unsigned char *)(ppStmt) = (unsigned char)sf_get_some_int(); };

    int rc = sf_get_some_int_to_check();
    {
    sqlite3_stmt *result;
    sf_overwrite(&result);
    sf_overwrite(result);
    sf_uncontrolled_value((int)(long long int)result);
    sf_uncontrolled_ptr(result);
    if (rc != SQLITE_OK) {
    sf_set_possible_null(result);
    }
    sf_handle_acquire(result, SQLITE3_STMT_CATEGORY);
    sf_not_acquire_if_eq(result, (int)(long long int)result, 0);
    sf_not_acquire_if_less(result, rc, SQLITE_OK);
    sf_not_acquire_if_greater(result, rc, SQLITE_OK);
    *(ppStmt) = result;
    };
    db->errCode = rc;

    if (pzTail) {
//        sf_overwrite(&pzTail);
        sf_bitinit(pzTail);//pointed memory is initialized
    }

    return rc;
}

int sqlite3_prepare( sqlite3 *db, const char *zSql, int nByte, sqlite3_stmt **ppStmt, const char **pzTail) {
    return __prepare(db, zSql, nByte, ppStmt, pzTail);
}

int sqlite3_prepare_v2( sqlite3 *db, const char *zSql, int nByte, sqlite3_stmt **ppStmt, const char **pzTail) {
    return __prepare(db, zSql, nByte, ppStmt, pzTail);
}

int sqlite3_prepare_v3( sqlite3 *db, const char *zSql, int nByte, unsigned int prepFlags, sqlite3_stmt **ppStmt, const char **pzTail) {
    return __prepare(db, zSql, nByte, ppStmt, pzTail);
}

int sqlite3_prepare16( sqlite3 *db, const void *zSql, int nByte, sqlite3_stmt **ppStmt, const void **pzTail) {
    return __prepare(db, zSql, nByte, ppStmt, (const char **)pzTail);
}

int sqlite3_prepare16_v2( sqlite3 *db, const void *zSql, int nByte, sqlite3_stmt **ppStmt, const void **pzTail) {
    return __prepare(db, zSql, nByte, ppStmt, (const char **)pzTail);
}

int sqlite3_prepare16_v3( sqlite3 *db, const void *zSql, int nByte, unsigned int prepFlags, sqlite3_stmt **ppStmt, const void **pzTail) {
    return __prepare(db, zSql, nByte, ppStmt, (const char **)pzTail);
}

char *sqlite3_sql(sqlite3_stmt *pStmt) {
    if (! pStmt) {
        return 0;
    }

    sf_must_not_be_release(pStmt);
    { unsigned char tmp = *(unsigned char *)(pStmt); tmp++; };

    return __get_nonfreeable_not_null_string();
}

char *sqlite3_expanded_sql(sqlite3_stmt *pStmt) {
    if (! pStmt) {
        return 0;
    }

    sf_must_not_be_release(pStmt);
    { unsigned char tmp = *(unsigned char *)(pStmt); tmp++; };

    return __alloc_some_string();
}

int sqlite3_stmt_readonly(sqlite3_stmt *pStmt) {
    if (! pStmt)
        return 1; // not a mistake: NULL statement will not modify database
    sf_must_not_be_release(pStmt);
    { unsigned char tmp = *(unsigned char *)(pStmt); tmp++; };
    return sf_get_bool();
}

int sqlite3_stmt_busy(sqlite3_stmt *pStmt) {
    if (! pStmt)
        return 0;
    sf_must_not_be_release(pStmt);
    { unsigned char tmp = *(unsigned char *)(pStmt); tmp++; };
    return sf_get_bool();
}

int sqlite3_bind_blob( sqlite3_stmt *pStmt, int i, const void *zData, int nData, void (*xDel)(void*)) {
    sf_must_not_be_release(pStmt);
    { *(unsigned char *)(pStmt) = (unsigned char)sf_get_some_int(); };
    // sf_set_trusted_sink_int(i); // ?
    // sf_set_trusted_sink_ptr(zData); // ?
    sf_set_must_be_positive(nData);
    sf_escape(xDel);
    if (xDel != SQLITE_STATIC && xDel != SQLITE_TRANSIENT) {
        sf_escape(zData);
    }
    return sf_get_some_int_to_check();
}

int sqlite3_bind_blob64( sqlite3_stmt *pStmt, int i, const void *zData, sqlite3_uint64 nData, void (*xDel)(void*)) {
    sf_must_not_be_release(pStmt);
    { *(unsigned char *)(pStmt) = (unsigned char)sf_get_some_int(); };
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
    { *(unsigned char *)(pStmt) = (unsigned char)sf_get_some_int(); };
    return sf_get_some_int_to_check();
}

int sqlite3_bind_int(sqlite3_stmt *pStmt, int i, int iValue) {
    sf_must_not_be_release(pStmt);
    { *(unsigned char *)(pStmt) = (unsigned char)sf_get_some_int(); };
    // sf_set_trusted_sink_int(i); // ?
    // sf_set_trusted_sink_int(iValue); // ?
    return sf_get_some_int_to_check();
}

int sqlite3_bind_int64(sqlite3_stmt *pStmt, int i, sqlite3_int64 iValue) {
    sf_must_not_be_release(pStmt);
    { *(unsigned char *)(pStmt) = (unsigned char)sf_get_some_int(); };
    // sf_set_trusted_sink_int(i); // ?
    // sf_set_trusted_sink_int(iValue); // ?
    return sf_get_some_int_to_check();
}

int sqlite3_bind_null(sqlite3_stmt *pStmt, int i) {
    sf_must_not_be_release(pStmt);
    { *(unsigned char *)(pStmt) = (unsigned char)sf_get_some_int(); };
    return sf_get_some_int_to_check();
}

int __bind_text( sqlite3_stmt *pStmt, int i, const char *zData, int nData, void (*xDel)(void*)) {
    sf_must_not_be_release(pStmt);
    { *(unsigned char *)(pStmt) = (unsigned char)sf_get_some_int(); };

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

int sqlite3_bind_text( sqlite3_stmt *pStmt, int i, const char *zData, int nData, void (*xDel)(void*)) {
    return __bind_text(pStmt, i, zData, nData, xDel);
}

int sqlite3_bind_text16( sqlite3_stmt *pStmt, int i, const char *zData, int nData, void (*xDel)(void*)) {
    return __bind_text(pStmt, i, zData, nData, xDel);
}

int sqlite3_bind_text64( sqlite3_stmt *pStmt, int i, const char *zData, sqlite3_uint64 nData, void (*xDel)(void*), unsigned char enc) {
    return __bind_text(pStmt, i, zData, nData, xDel);
}

int sqlite3_bind_value(sqlite3_stmt *pStmt, int i, const sqlite3_value *pValue) {
    sf_must_not_be_release(pStmt);
    { *(unsigned char *)(pStmt) = (unsigned char)sf_get_some_int(); };
    // sf_set_trusted_sink_int(i); // ?
    { unsigned char tmp = *(unsigned char *)(pValue); tmp++; };
    return sf_get_some_int_to_check();
}

int sqlite3_bind_pointer( sqlite3_stmt *pStmt, int i, void *pPtr, const char *zPTtype, void (*xDestructor)(void*)) {
    sf_must_not_be_release(pStmt);
    { *(unsigned char *)(pStmt) = (unsigned char)sf_get_some_int(); };

    // sf_set_trusted_sink_int(i); // ?

    // sf_set_trusted_sink_ptr(pPtr); // ?

    if (pPtr) SF_DEREF_READ(pPtr);

    if (zPTtype) SF_DEREF_READ(zPTtype);
    sf_buf_stop_at_null(zPTtype);

    sf_escape(xDestructor); // ?

    if (xDestructor) {
        sf_escape(pPtr);
    }

    return sf_get_some_int_to_check();
}

int __bind_zeroblob(sqlite3_stmt *pStmt, int i, sqlite3_uint64 n) {
    sf_must_not_be_release(pStmt);
    { *(unsigned char *)(pStmt) = (unsigned char)sf_get_some_int(); };
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
    if (pStmt) SF_DEREF_READ(pStmt);

    int res;
    if (! pStmt) {
        res = 0;
    } else {
        res = sf_get_some_nonnegative_int();
    }
    return res;
}

char *sqlite3_bind_parameter_name(sqlite3_stmt *pStmt, int i) {
    sf_must_not_be_release(pStmt);
    if (pStmt) SF_DEREF_READ(pStmt);
    // sf_set_trusted_sink_int(i); // ?
    return __get_nonfreeable_possible_null_string();
}

int sqlite3_bind_parameter_index(sqlite3_stmt *pStmt, const char *zName) {
    sf_must_not_be_release(pStmt);
    if (pStmt) SF_DEREF_READ(pStmt);

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
    { unsigned char tmp = *(unsigned char *)(pStmt); tmp++; };
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

char *__column_name(sqlite3_stmt *pStmt, int N) {
    sf_must_not_be_release(pStmt);
    { unsigned char tmp = *(unsigned char *)(pStmt); tmp++; };

    return __get_nonfreeable_possible_null_string();
}

char *sqlite3_column_name(sqlite3_stmt *pStmt, int N) {
    return __column_name(pStmt, N);
}

void *sqlite3_column_name16(sqlite3_stmt *pStmt, int N) {
    return __column_name(pStmt, N);
}

char *sqlite3_column_database_name(sqlite3_stmt *pStmt, int N) {
    return __column_name(pStmt, N);
}

void *sqlite3_column_database_name16(sqlite3_stmt *pStmt, int N) {
    return __column_name(pStmt, N);
}

char *sqlite3_column_table_name(sqlite3_stmt *pStmt, int N) {
    return __column_name(pStmt, N);
}

void *sqlite3_column_table_name16(sqlite3_stmt *pStmt, int N) {
    return __column_name(pStmt, N);
}

char *sqlite3_column_origin_name(sqlite3_stmt *pStmt, int N) {
    return __column_name(pStmt, N);
}

void *sqlite3_column_origin_name16(sqlite3_stmt *pStmt, int N) {
    return __column_name(pStmt, N);
}

char *sqlite3_column_decltype(sqlite3_stmt *pStmt, int N) {
    return __column_name(pStmt, N);
}

void *sqlite3_column_decltype16(sqlite3_stmt *pStmt, int N) {
    return __column_name(pStmt, N);
}

int sqlite3_step(sqlite3_stmt *pStmt) {
    //sf_long_time();

    sf_must_not_be_release(pStmt);
    //SF_DEREF_WRITE(pStmt); ?
    { unsigned char tmp = *(unsigned char *)(pStmt); tmp++; };

    return sf_get_some_int_to_check();
}

int sqlite3_data_count(sqlite3_stmt *pStmt) {
    sf_must_not_be_release(pStmt);
    { unsigned char tmp = *(unsigned char *)(pStmt); tmp++; };

    int res;
    if (! pStmt) {
        res = 0;
    } else {
        res = sf_get_some_nonnegative_int();
    }
    return res;
}

void *sqlite3_column_blob(sqlite3_stmt *pStmt, int iCol) {
    sf_must_not_be_release(pStmt);
    if (pStmt) SF_DEREF_READ(pStmt);

    return __get_nonfreeable_possible_null();
}

double sqlite3_column_double(sqlite3_stmt *pStmt, int iCol) {
    sf_must_not_be_release(pStmt);
    if (pStmt) SF_DEREF_READ(pStmt);

    return sf_get_tainted_double();
}

int sqlite3_column_int(sqlite3_stmt *pStmt, int iCol) {
    sf_must_not_be_release(pStmt);
    if (pStmt) SF_DEREF_READ(pStmt);

    return sf_get_tainted_int();
}

sqlite3_int64 sqlite3_column_int64(sqlite3_stmt *pStmt, int iCol) {
    sf_must_not_be_release(pStmt);
    if (pStmt) SF_DEREF_READ(pStmt);

    return sf_get_tainted_int64();
}

unsigned char *sqlite3_column_text(sqlite3_stmt *pStmt, int iCol) {
    sf_must_not_be_release(pStmt);
    if (pStmt) SF_DEREF_READ(pStmt);

    return (const unsigned char *)__get_nonfreeable_tainted_possible_null_string();
}

void *sqlite3_column_text16(sqlite3_stmt *pStmt, int iCol) {
    sf_must_not_be_release(pStmt);
    if (pStmt) SF_DEREF_READ(pStmt);

    return __get_nonfreeable_tainted_possible_null_string();
}

sqlite3_value *sqlite3_column_value(sqlite3_stmt *pStmt, int iCol) {
    sf_must_not_be_release(pStmt);
    if (pStmt) SF_DEREF_READ(pStmt);

    return (sqlite3_value *)__get_nonfreeable_possible_null();
}

int sqlite3_column_bytes(sqlite3_stmt *pStmt, int iCol) {
    sf_must_not_be_release(pStmt);
    if (pStmt) SF_DEREF_READ(pStmt);

    return sf_get_some_nonnegative_int();
}

int sqlite3_column_bytes16(sqlite3_stmt *pStmt, int iCol) {
    sf_must_not_be_release(pStmt);
    if (pStmt) SF_DEREF_READ(pStmt);

    return sf_get_some_nonnegative_int();
}

int sqlite3_column_type(sqlite3_stmt *pStmt, int iCol) {
    sf_must_not_be_release(pStmt);
    if (pStmt) SF_DEREF_READ(pStmt);

    return sf_get_some_int();
}

int sqlite3_finalize(sqlite3_stmt *pStmt) {
    sf_must_not_be_release(pStmt);
    sf_handle_release(pStmt, SQLITE3_STMT_CATEGORY);
    
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

int __create_function( sqlite3 *db, const char *zFunctionName, int nArg, int eTextRep, void *pApp, void (*xFunc)(sqlite3_context*, int, sqlite3_value**), void (*xStep)(sqlite3_context*, int, sqlite3_value**), void (*xFinal)(sqlite3_context*), void(*xDestroy)(void*)) {
    __SQLITE_db_R_ACCESS(db);
    SF_DEREF_WRITE(db);

    sf_set_trusted_sink_ptr(zFunctionName);
    { unsigned char tmp = *(unsigned char *)(zFunctionName); tmp++; }; // return SQLITE_MISUSE_BKPT
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

int sqlite3_create_function( sqlite3 *db, const char *zFunctionName, int nArg, int eTextRep, void *pApp, void (*xFunc)(sqlite3_context*, int, sqlite3_value**), void (*xStep)(sqlite3_context*, int, sqlite3_value**), void (*xFinal)(sqlite3_context*)) {
    return __create_function(db, zFunctionName, nArg, eTextRep, pApp, xFunc, xStep, xFinal, 0);
}

int sqlite3_create_function16( sqlite3 *db, const void *zFunctionName, int nArg, int eTextRep, void *pApp, void (*xFunc)(sqlite3_context*, int, sqlite3_value**), void (*xStep)(sqlite3_context*, int, sqlite3_value**), void (*xFinal)(sqlite3_context*)) {
    return __create_function(db, zFunctionName, nArg, eTextRep, pApp, xFunc, xStep, xFinal, 0);
}

int sqlite3_create_function_v2( sqlite3 *db, const char *zFunctionName, int nArg, int eTextRep, void *pApp, void (*xFunc)(sqlite3_context*, int, sqlite3_value**), void (*xStep)(sqlite3_context*, int, sqlite3_value**), void (*xFinal)(sqlite3_context*), void(*xDestroy)(void*)) {
    return __create_function(db, zFunctionName, nArg, eTextRep, pApp, xFunc, xStep, xFinal, xDestroy);
}

int sqlite3_aggregate_count(sqlite3_context *pCtx) {
    sf_vulnerable_fun_type("This function is deprecated. Do not use it for new code. It is provided only to avoid breaking legacy code. New aggregate function implementations should keep their own counts within their aggregate context.", SQLITE);

    { unsigned char tmp = *(unsigned char *)(pCtx); tmp++; };

    return sf_get_some_int();
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

int sqlite3_global_recover(void) {
    sf_vulnerable_fun_type("This function is now an anachronism. It used to be used to recover from a malloc() failure, but SQLite now does this automatically.", SQLITE);
    return sf_get_some_int();
}

void sqlite3_thread_cleanup(void) {
    sf_vulnerable_fun_type("SQLite no longer uses thread-specific data so this routine is now a no-op.", SQLITE);
}

int sqlite3_memory_alarm( void(*xCallback)(void *pArg, sqlite3_int64 used, int N), void *pArg, sqlite3_int64 iThreshold) {
    sf_vulnerable_fun_type("Deprecated external interface. Now it is a no-op.", SQLITE);
    return sf_get_some_int();
}

void *sqlite3_value_blob(sqlite3_value *pVal) {
    sf_must_not_be_release(pVal);
    { unsigned char tmp = *(unsigned char *)(pVal); tmp++; };
    return __get_nonfreeable_possible_null();
}

double sqlite3_value_double(sqlite3_value *pVal) {
    sf_must_not_be_release(pVal);
    { unsigned char tmp = *(unsigned char *)(pVal); tmp++; };
    return sf_get_tainted_double();
}

int sqlite3_value_int(sqlite3_value *pVal) {
    sf_must_not_be_release(pVal);
    { unsigned char tmp = *(unsigned char *)(pVal); tmp++; };
    return sf_get_tainted_int();
}

sqlite3_int64 sqlite3_value_int64(sqlite3_value *pVal) {
    sf_must_not_be_release(pVal);
    { unsigned char tmp = *(unsigned char *)(pVal); tmp++; };
    return sf_get_tainted_int64();
}

void *sqlite3_value_pointer(sqlite3_value *pVal, const char *zPType) {
    sf_must_not_be_release(pVal);
    { unsigned char tmp = *(unsigned char *)(pVal); tmp++; };
    return __get_nonfreeable_possible_null();
}

unsigned char *sqlite3_value_text(sqlite3_value *pVal) {
    sf_must_not_be_release(pVal);
    { unsigned char tmp = *(unsigned char *)(pVal); tmp++; };
    return (unsigned char *)__get_nonfreeable_tainted_possible_null_string();
}

void *sqlite3_value_text16(sqlite3_value *pVal) {
    sf_must_not_be_release(pVal);
    { unsigned char tmp = *(unsigned char *)(pVal); tmp++; };
    return __get_nonfreeable_tainted_possible_null_string();
}

void *sqlite3_value_text16le(sqlite3_value *pVal) {
    sf_must_not_be_release(pVal);
    { unsigned char tmp = *(unsigned char *)(pVal); tmp++; };
    return __get_nonfreeable_tainted_possible_null_string();
}

void *sqlite3_value_text16be(sqlite3_value *pVal) {
    sf_must_not_be_release(pVal);
    { unsigned char tmp = *(unsigned char *)(pVal); tmp++; };
    return __get_nonfreeable_tainted_possible_null_string();
}

int sqlite3_value_bytes(sqlite3_value *pVal) {
    sf_must_not_be_release(pVal);
    { unsigned char tmp = *(unsigned char *)(pVal); tmp++; };
    return sf_get_some_nonnegative_int();
}

int sqlite3_value_bytes16(sqlite3_value *pVal) {
    sf_must_not_be_release(pVal);
    { unsigned char tmp = *(unsigned char *)(pVal); tmp++; };
    return sf_get_some_nonnegative_int();
}

int sqlite3_value_type(sqlite3_value *pVal) {
    sf_must_not_be_release(pVal);
    { unsigned char tmp = *(unsigned char *)(pVal); tmp++; };

    return sf_get_values(0, 5);
}

int sqlite3_value_numeric_type(sqlite3_value *pVal) {
    return sqlite3_value_type(pVal);
}

unsigned int sqlite3_value_subtype(sqlite3_value *pVal) {
    sf_must_not_be_release(pVal);
    { unsigned char tmp = *(unsigned char *)(pVal); tmp++; };
    return sf_get_some_unsigned();
}

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
    { *(unsigned char *)(pCtx) = (unsigned char)sf_get_some_int(); };

    sf_set_trusted_sink_nonnegative_int(nBytes);
    sf_malloc_arg(nBytes);

    return __get_nonfreeable_possible_null();
}

void *sqlite3_user_data(sqlite3_context *pCtx) {
    { unsigned char tmp = *(unsigned char *)(pCtx); tmp++; };

    return sf_get_uncontrolled_ptr();
}

sqlite3 *sqlite3_context_db_handle(sqlite3_context *pCtx) {
    { unsigned char tmp = *(unsigned char *)(pCtx); tmp++; };

    sqlite3 *res = sf_get_uncontrolled_ptr();
    sf_not_null(res);
    return res;
}

void *sqlite3_get_auxdata(sqlite3_context *pCtx, int N) {
    { unsigned char tmp = *(unsigned char *)(pCtx); tmp++; };

    sqlite3 *res = sf_get_uncontrolled_ptr();
    sf_set_possible_null(res);
    return res;
}

void sqlite3_set_auxdata( sqlite3_context *pCtx, int iArg, void *pAux, void (*xDelete)(void*)) {
    { *(unsigned char *)(pCtx) = (unsigned char)sf_get_some_int(); };

    sf_escape(xDelete); // ?

    if (xDelete) {
        sf_escape(pAux);
    }
}

void sqlite3_result_blob( sqlite3_context *pCtx, const void *z, int n, void (*xDel)(void *)) {
    { *(unsigned char *)(pCtx) = (unsigned char)sf_get_some_int(); };

    sf_set_must_be_positive(n+1); // assert(n>=0)

    sf_escape(xDel); // ?

    if (xDel != SQLITE_TRANSIENT) {
        sf_escape(z);
    }
}

void sqlite3_result_blob64( sqlite3_context *pCtx, const void *z, sqlite3_uint64 n, void (*xDel)(void *)) {
    { *(unsigned char *)(pCtx) = (unsigned char)sf_get_some_int(); };

    sf_escape(xDel); // ?

    if (xDel != SQLITE_TRANSIENT) {
        sf_escape(z);
    }
}

void sqlite3_result_double(sqlite3_context *pCtx, double rVal) {
    { *(unsigned char *)(pCtx) = (unsigned char)sf_get_some_int(); };
}

void __result_error(sqlite3_context *pCtx, const void *z, int n) {
    { *(unsigned char *)(pCtx) = (unsigned char)sf_get_some_int(); };
    sf_buf_stop_at_null(z);
    if (z) SF_DEREF_READ(z);

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
    { *(unsigned char *)(pCtx) = (unsigned char)sf_get_some_int(); };
}

void sqlite3_result_error_nomem(sqlite3_context *pCtx) {
    { *(unsigned char *)(pCtx) = (unsigned char)sf_get_some_int(); };
}

void sqlite3_result_error_code(sqlite3_context *pCtx, int errCode) {
    { *(unsigned char *)(pCtx) = (unsigned char)sf_get_some_int(); };
}

void sqlite3_result_int(sqlite3_context *pCtx, int iVal) {
    { *(unsigned char *)(pCtx) = (unsigned char)sf_get_some_int(); };
}

void sqlite3_result_int64(sqlite3_context *pCtx, sqlite3_int64 iVal) {
    { *(unsigned char *)(pCtx) = (unsigned char)sf_get_some_int(); };
}

void sqlite3_result_null(sqlite3_context *pCtx) {
    { *(unsigned char *)(pCtx) = (unsigned char)sf_get_some_int(); };
}

void __result_text( sqlite3_context *pCtx, const char *z, int n, void (*xDel)(void *)) {
    { *(unsigned char *)(pCtx) = (unsigned char)sf_get_some_int(); };

    sf_buf_stop_at_null(z);
    if (z) SF_DEREF_READ(z);

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

void sqlite3_result_value(sqlite3_context *pCtx, sqlite3_value *pValue) {
    { *(unsigned char *)(pCtx) = (unsigned char)sf_get_some_int(); };
    { unsigned char tmp = *(unsigned char *)(pValue); tmp++; };
}

void sqlite3_result_pointer( sqlite3_context *pCtx, void *pPtr, const char *zPType, void (*xDestructor)(void *)) {
    { *(unsigned char *)(pCtx) = (unsigned char)sf_get_some_int(); };

    sf_escape(xDestructor); // ?

    if (xDestructor) {
        sf_escape(pPtr);
    }

    sf_buf_stop_at_null(zPType);
    if (zPType) SF_DEREF_READ(zPType);
}

void sqlite3_result_zeroblob(sqlite3_context *pCtx, int n) {
    { *(unsigned char *)(pCtx) = (unsigned char)sf_get_some_int(); };
}

int sqlite3_result_zeroblob64(sqlite3_context *pCtx, sqlite3_uint64 n) {
    { *(unsigned char *)(pCtx) = (unsigned char)sf_get_some_int(); };

    return sf_get_some_int_to_check();
}

void sqlite3_result_subtype(sqlite3_context *pCtx, unsigned int eSubtype) {
    { *(unsigned char *)(pCtx) = (unsigned char)sf_get_some_int(); };
}

int __create_collation( sqlite3 *db, const char *zName, void *pArg, int(*xCompare)(void*, int, const void*, int, const void*), void(*xDestroy)(void*)) {
    __SQLITE_db_R_ACCESS(db);
    SF_DEREF_WRITE(db);

    sf_set_trusted_sink_ptr(zName);
    { unsigned char tmp = *(unsigned char *)(zName); tmp++; }; // ?
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

int sqlite3_create_collation( sqlite3 *db, const char *zName, int eTextRep, void *pArg, int(*xCompare)(void*, int, const void*, int, const void*)) {
    return __create_collation(db, zName, pArg, xCompare, 0);
}

int sqlite3_create_collation_v2( sqlite3 *db, const char *zName, int eTextRep, void *pArg, int(*xCompare)(void*, int, const void*, int, const void*), void(*xDestroy)(void*)) {
    return __create_collation(db, zName, pArg, xCompare, xDestroy);
}

int sqlite3_create_collation16( sqlite3 *db, const void *zName, int eTextRep, void *pArg, int(*xCompare)(void*, int, const void*, int, const void*)) {
    return __create_collation(db, zName, pArg, xCompare, 0);
}

int sqlite3_collation_needed( sqlite3 *db, void *pCollNeededArg, void(*xCollNeeded)(void*, sqlite3*, int eTextRep, const char*)) {
    __SQLITE_db_R_ACCESS(db);
    SF_DEREF_WRITE(db);
    return sf_get_some_int();
}

int sqlite3_collation_needed16( sqlite3 *db, void *pCollNeededArg, void(*xCollNeeded16)(void*, sqlite3*, int eTextRep, const void*)) {
    __SQLITE_db_R_ACCESS(db);
    SF_DEREF_WRITE(db);
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

sqlite3_stmt *sqlite3_next_stmt(sqlite3 *db, sqlite3_stmt *pStmt) {
    __SQLITE_DB_R_ACCESS(db);

    if (pStmt) SF_DEREF_READ(pStmt);

    sqlite3_stmt *res = sf_get_uncontrolled_ptr();
    sf_set_possible_null(res);
    return res;
}

void *sqlite3_commit_hook( sqlite3 *db, /* Attach the hook to this database */ int (*xCallback)(void*), /* Function to invoke on each commit */ void *pArg /* Argument to the function */) {
    __SQLITE_db_R_ACCESS(db);
    SF_DEREF_WRITE(db);

    sf_escape(xCallback); // ?
    //sf_escape(pArg); // ?

    return sf_get_uncontrolled_ptr();
}

void *sqlite3_rollback_hook( sqlite3 *db, /* Attach the hook to this database */ void (*xCallback)(void*), /* Callback function */ void *pArg /* Argument to the function */) {
    __SQLITE_db_R_ACCESS(db);
    SF_DEREF_WRITE(db);

    sf_escape(xCallback); // ?
    //sf_escape(pArg); // ?

    return sf_get_uncontrolled_ptr();
}

void *sqlite3_update_hook( sqlite3 *db, /* Attach the hook to this database */ void (*xCallback)(void*, int, char const *, char const *, sqlite_int64), void *pArg /* Argument to the function */) {
    __SQLITE_db_R_ACCESS(db);
    SF_DEREF_WRITE(db);

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
    __SQLITE_db_R_ACCESS(db);
    SF_DEREF_WRITE(db);
    return sf_get_some_int();
}

sqlite3_int64 sqlite3_soft_heap_limit64(sqlite3_int64 n) {
    sf_set_trusted_sink_nonnegative_int(n);
    return sf_get_some_int64();
}

void sqlite3_soft_heap_limit(int n) {
    sf_set_trusted_sink_nonnegative_int(n);
}

int sqlite3_table_column_metadata( sqlite3 *db, /* Connection handle */ const char *zDbName, /* Database name or NULL */ const char *zTableName, /* Table name */ const char *zColumnName, /* Column name */ char const **pzDataType, /* OUTPUT: Declared data type */ char const **pzCollSeq, /* OUTPUT: Collation sequence name */ int *pNotNull, /* OUTPUT: True if NOT NULL constraint exists */ int *pPrimaryKey, /* OUTPUT: True if column part of PK */ int *pAutoinc /* OUTPUT: True if column is auto-increment */) {
    __SQLITE_db_R_ACCESS(db);
    SF_DEREF_WRITE(db);

    sf_buf_stop_at_null(zDbName);
    if (zDbName) SF_DEREF_READ(zDbName);

    sf_buf_stop_at_null(zTableName);
    { unsigned char tmp = *(unsigned char *)(zTableName); tmp++; };

    sf_buf_stop_at_null(zColumnName);
    if (zColumnName) SF_DEREF_READ(zColumnName);

    if (pzDataType) *pzDataType = __get_nonfreeable_string(); // can it be null or not???
    if (pzCollSeq) *pzCollSeq = __get_nonfreeable_string(); // can it be null or not???
    if (pNotNull) *pNotNull = sf_get_bool();
    if (pPrimaryKey) *pPrimaryKey = sf_get_bool();
    if (pAutoinc) *pAutoinc = sf_get_bool();

    return sf_get_some_int_to_check();
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

int __create_module( sqlite3 *db, const char *zName, const sqlite3_module *pModule, void *pAux, void (*xDestroy)(void *)) {
    __SQLITE_db_R_ACCESS(db);
    SF_DEREF_WRITE(db);

    sf_buf_stop_at_null(zName);
    { unsigned char tmp = *(unsigned char *)(zName); tmp++; };

    // sf_set_must_be_not_null(pModule, "???"); // ?
    { unsigned char tmp = *(unsigned char *)(pModule); tmp++; }; // ?

    sf_escape(xDestroy); // ?
    if (xDestroy) {
        sf_escape(pAux);
    }

    return sf_get_some_int_to_check();
}

int sqlite3_create_module( sqlite3 *db, /* Database in which module is registered */ const char *zName, /* Name assigned to this module */ const sqlite3_module *pModule, /* The definition of the module */ void *pAux /* Context pointer for xCreate/xConnect */) {
    return __create_module(db, zName, pModule, pAux, 0);
}

int sqlite3_create_module_v2( sqlite3 *db, /* Database in which module is registered */ const char *zName, /* Name assigned to this module */ const sqlite3_module *pModule, /* The definition of the module */ void *pAux, /* Context pointer for xCreate/xConnect */ void (*xDestroy)(void *) /* Module destructor function */) {
    return __create_module(db, zName, pModule, pAux, xDestroy);
}

int sqlite3_declare_vtab(sqlite3 *db, const char *zSQL) {
    __SQLITE_db_R_ACCESS(db);
    SF_DEREF_WRITE(db);

    sf_buf_stop_at_null(zSQL);
    sf_set_trusted_sink_ptr(zSQL);
    { unsigned char tmp = *(unsigned char *)(zSQL); tmp++; };

    return sf_get_some_int_to_check();
}

int sqlite3_overload_function(sqlite3 *db, const char *zFuncName, int nArg) {
    __SQLITE_db_R_ACCESS(db);
    SF_DEREF_WRITE(db);

    sf_buf_stop_at_null(zFuncName);
    sf_set_trusted_sink_ptr(zFuncName);
    { unsigned char tmp = *(unsigned char *)(zFuncName); tmp++; };

    sf_set_must_be_positive(nArg + 2); // misuse if nArg<-2 - from implementation(?)

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

int sqlite3_blob_reopen(sqlite3_blob *pBlob, sqlite3_int64 iRow) {
    sf_must_not_be_release(pBlob);
    if (pBlob) { *(unsigned char *)(pBlob) = (unsigned char)sf_get_some_int(); }; // ?

    return sf_get_some_int_to_check();
}

int sqlite3_blob_close(sqlite3_blob *pBlob) {
    sf_must_not_be_release(pBlob);
    sf_handle_release(pBlob, SQLITE3_BLOB_CATEGORY);
    
}

int sqlite3_blob_bytes(sqlite3_blob *pBlob) {
    sf_must_not_be_release(pBlob);
    if (pBlob) { *(unsigned char *)(pBlob) = (unsigned char)sf_get_some_int(); };
    return sf_get_some_nonnegative_int();
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

sqlite3_vfs *sqlite3_vfs_find(const char *zVfsName) {
    sf_set_trusted_sink_ptr(zVfsName);
    if (zVfsName) SF_DEREF_READ(zVfsName);
    sf_buf_stop_at_null(zVfsName);
    return __get_nonfreeable_possible_null();
}

int sqlite3_vfs_register(sqlite3_vfs *pVfs, int makeDflt) {
    { *(unsigned char *)(pVfs) = (unsigned char)sf_get_some_int(); };
    return sf_get_some_int_to_check();
}

int sqlite3_vfs_unregister(sqlite3_vfs *pVfs) {
    { *(unsigned char *)(pVfs) = (unsigned char)sf_get_some_int(); };
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
    if (zDbName) SF_DEREF_READ(zDbName);

    { *(unsigned char *)(pArg) = (unsigned char)sf_get_some_int(); };

    return sf_get_some_int_to_check();
}

int sqlite3_status64( int op, sqlite3_int64 *pCurrent, sqlite3_int64 *pHighwater, int resetFlag) {
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

int sqlite3_db_status( sqlite3 *db, /* The database connection whose status is desired */ int op, /* Status verb */ int *pCurrent, /* Write current value here */ int *pHighwater, /* Write high-water mark here */ int resetFlag /* Reset high-water mark if true */) {
    __SQLITE_DB_R_ACCESS(db);

    { *(unsigned char *)(pCurrent) = (unsigned char)sf_get_some_int(); };
    { *(unsigned char *)(pHighwater) = (unsigned char)sf_get_some_int(); };

    return sf_get_some_int_to_check();
}

int sqlite3_stmt_status(sqlite3_stmt *pStmt, int op, int resetFlg) {
    { *(unsigned char *)(pStmt) = (unsigned char)sf_get_some_int(); };
    return sf_get_some_int();
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

int sqlite3_backup_step(sqlite3_backup *p, int nPage) {
    sf_must_not_be_release(p);
    { *(unsigned char *)(p) = (unsigned char)sf_get_some_int(); };
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
    { unsigned char tmp = *(unsigned char *)(p); tmp++; };
    return sf_get_some_nonnegative_int();
}

int sqlite3_backup_pagecount(sqlite3_backup *p) {
    sf_must_not_be_release(p);
    { unsigned char tmp = *(unsigned char *)(p); tmp++; };
    return sf_get_some_nonnegative_int();
}

int sqlite3_unlock_notify( sqlite3 *db, /* Waiting connection */ void (*xNotify)(void **apArg, int nArg), /* Callback function to invoke */ void *pArg /* Argument to pass to xNotify */) {
    __SQLITE_db_R_ACCESS(db);
    SF_DEREF_WRITE(db);

    sf_escape(xNotify); // ?
    //sf_escape(pNotifyArg) // ?

    return sf_get_some_int_to_check();
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

int sqlite3_strnicmp(const char *z1, const char *z2, int n) {
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

int sqlite3_strlike(const char *zPattern, const char *zStr, unsigned int esc) {
    sf_set_trusted_sink_ptr(zPattern);
    sf_buf_stop_at_null(zPattern);
    { unsigned char tmp = *(unsigned char *)(zPattern); tmp++; };

    sf_sanitize(zStr);
    sf_buf_stop_at_null(zStr);
    { unsigned char tmp = *(unsigned char *)(zStr); tmp++; };

    return sf_get_some_int_to_check(); // ?
}

void sqlite3_log(int iErrCode, const char *zFormat, ...) {
    sf_buf_stop_at_null(zFormat);
    sf_use_format(zFormat); // for tainted
    { unsigned char tmp = *(unsigned char *)(zFormat); tmp++; };

    //sf_fun_printf_like(1); // SQLite extends standard library formats with %q, %Q, %w, and %z
    sf_fun_does_not_update_vargs(2);
}

void *sqlite3_wal_hook( sqlite3 *db, /* Attach the hook to this db handle */ int(*xCallback)(void *, sqlite3*, const char*, int), void *pArg /* First argument passed to xCallback() */) {
    __SQLITE_db_R_ACCESS(db);
    SF_DEREF_WRITE(db);

    // sf_escape(xCallback); // ?
    // sf_escape(pArg); // ?

    void *res = sf_get_uncontrolled_ptr();
    sf_set_possible_null(res);
    return res;
}

int sqlite3_wal_autocheckpoint(sqlite3 *db, int N) {
    __SQLITE_db_R_ACCESS(db);
    SF_DEREF_WRITE(db);
    return sf_get_some_int();
}

int sqlite3_wal_checkpoint(sqlite3 *db, const char *zDb) {
    __SQLITE_db_R_ACCESS(db);
    SF_DEREF_WRITE(db);

    sf_set_trusted_sink_ptr(zDb);
    sf_buf_stop_at_null(zDb);
    if (zDb) SF_DEREF_READ(zDb);

    return sf_get_some_int_to_check();
}

int sqlite3_wal_checkpoint_v2( sqlite3 *db, /* Database handle */ const char *zDb, /* Name of attached database (or NULL) */ int eMode, /* SQLITE_CHECKPOINT_* value */ int *pnLog, /* OUT: Size of WAL log in frames */ int *pnCkpt /* OUT: Total number of frames checkpointed */) {
    sf_must_not_be_release(db);
    unsigned char tmp = *(unsigned char *)(db); tmp++;
    *(unsigned char *)(db) = (unsigned char)sf_get_some_int();

    sf_set_trusted_sink_ptr(zDb);
    sf_buf_stop_at_null(zDb);
    if (zDb) unsigned char tmp = *(unsigned char *)(zDb); tmp++;

    if (pnLog) {
        *pnLog = sf_get_values_with_min(-1);
    }
    if (pnCkpt) {
        *pnCkpt = sf_get_values_with_min(-1);
    }

    return sf_get_some_int_to_check();
}

int sqlite3_vtab_config(sqlite3 *db, int op, ...) {
    sf_must_not_be_release(db);
    unsigned char tmp = *(unsigned char *)(db); tmp++;
    *(unsigned char *)(db) = (unsigned char)sf_get_some_int();
    return sf_get_some_int_to_check();
}

int sqlite3_vtab_on_conflict(sqlite3 *db) {
    sf_must_not_be_release(db);
    unsigned char tmp = *(unsigned char *)(db); tmp++;
    *(unsigned char *)(db) = (unsigned char)sf_get_some_int();
    return sf_get_some_int();
}

char *sqlite3_vtab_collation(sqlite3_index_info *pIdxInfo, int iCons) {
    { unsigned char tmp = *(unsigned char *)(pIdxInfo); tmp++; };
    return __get_nonfreeable_possible_null();
}

int sqlite3_stmt_scanstatus( sqlite3_stmt *pStmt, int idx, int iScanStatusOp, void *pOut) {
    sf_must_not_be_release(pStmt);
    *(unsigned char *)(pStmt) = (unsigned char)sf_get_some_int(); // actual deref

    *(unsigned char *)(pOut) = (unsigned char)sf_get_some_int();
    sf_overwrite(pOut);

    return sf_get_some_int_to_check();
}

void sqlite3_stmt_scanstatus_reset(sqlite3_stmt *pStmt) {
    sf_must_not_be_release(pStmt);
    *(unsigned char *)(pStmt) = (unsigned char)sf_get_some_int(); // actual deref
}

int sqlite3_db_cacheflush(sqlite3 *db) {
    __SQLITE_db_R_ACCESS(db);
    SF_DEREF_WRITE(db);
    return sf_get_some_int_to_check();
}

int sqlite3_system_errno(sqlite3 *db) {
    if (db) SF_DEREF_READ(db);
    return sf_get_some_int_to_check();
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

int sqlite3_snapshot_open( sqlite3 *db, const char *zSchema, sqlite3_snapshot *pSnapshot) {
    sf_vulnerable_fun_type("This interface is experimental and is subject to change without notice.", SQLITE);

    __SQLITE_db_R_ACCESS(db);
    SF_DEREF_WRITE(db);

    sf_set_trusted_sink_ptr(zSchema); // ?
    sf_buf_stop_at_null(zSchema);
    if (zSchema) SF_DEREF_READ(zSchema);

    return sf_get_some_int_to_check();
}

void sqlite3_snapshot_free(sqlite3_snapshot *pSnapshot) {
    sf_vulnerable_fun_type("This interface is experimental and is subject to change without notice.", SQLITE);

    sf_must_not_be_release(pSnapshot);
    sf_handle_release(pSnapshot, SQLITE3_SNAPSHOT_CATEGORY);
    sf_overwrite(pSnapshot); // ?
}

int sqlite3_snapshot_cmp( sqlite3_snapshot *p1, sqlite3_snapshot *p2) {
    sf_vulnerable_fun_type("This interface is experimental and is subject to change without notice.", SQLITE);

    { unsigned char tmp = *(unsigned char *)(p1); tmp++; };
    { unsigned char tmp = *(unsigned char *)(p2); tmp++; };

    return sf_get_values(-1, +1);
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

int sqlite3_rtree_geometry_callback( sqlite3 *db, /* Register SQL function on this connection */ const char *zGeom, /* Name of the new SQL function */ int (*xGeom)(sqlite3_rtree_geometry*, int, RtreeDValue*, int*), /* Callback */ void *pContext /* Extra data associated with the callback */) {
    __SQLITE_db_R_ACCESS(db);
    SF_DEREF_WRITE(db);

    sf_set_trusted_sink_ptr(zGeom);
    { unsigned char tmp = *(unsigned char *)(zGeom); tmp++; }; // return SQLITE_MISUSE_BKPT
    sf_buf_stop_at_null(zGeom);

    //sf_escape(pContext); // ?

    return sf_get_some_int_to_check();
}

int sqlite3_rtree_query_callback( sqlite3 *db, /* Register SQL function on this connection */ const char *zQueryFunc, /* Name of new SQL function */ int (*xQueryFunc)(sqlite3_rtree_query_info*), /* Callback */ void *pContext, /* Extra data passed into the callback */ void (*xDestructor)(void*) /* Destructor for the extra data */) {
    __SQLITE_db_R_ACCESS(db);
    SF_DEREF_WRITE(db);

    sf_set_trusted_sink_ptr(zQueryFunc);
    { unsigned char tmp = *(unsigned char *)(zQueryFunc); tmp++; }; // return SQLITE_MISUSE_BKPT
    sf_buf_stop_at_null(zQueryFunc);

    if (xDestructor) {
        sf_escape(pContext);
    }

    return sf_get_some_int_to_check();
}

int chmod(const char *fname, int mode) {
    sf_tocttou_access(fname);

	int res;
        sf_use(fname);
	sf_overwrite(&res);
	sf_set_possible_negative(res);
	return res;
}

int fchmod(int fd, mode_t mode) {
  int res;
  sf_use(fd);
  sf_overwrite(&res);
  sf_set_possible_negative(res);
  return res;
}

int lstat(const char *restrict fname, struct stat *restrict st) {
    sf_use(fname);
    sf_bitinit(st);
    //note: do note forget sf_bitinit
    sf_tocttou_check(fname);

    int res;
    sf_overwrite(&res);
    sf_set_possible_negative(res);
    sf_set_errno_if(res, sf_cond_range("==", -1));
    sf_no_errno_if(res, sf_cond_range("==", 0));
    return res;
}

int lstat64(const char *restrict fname, struct stat *restrict st) {
    return lstat64(fname, st);
}

int fstat(int fd, struct stat *restrict st) {
    sf_bitinit(st);

    int res;
    sf_overwrite(&res);
    sf_set_possible_negative(res);
    sf_set_errno_if(res, sf_cond_range("==", -1));
    sf_no_errno_if(res, sf_cond_range("==", 0));
    return res;
}

int mkdir(const char *fname, int mode) {
    sf_use(fname);
    sf_tocttou_access(fname);

	int res;
	sf_overwrite(&res);
	sf_set_possible_negative(res);
	return res;
}

int mkfifo(const char *fname, int mode) {
    sf_use(fname);
    sf_tocttou_access(fname);

	int res;
	sf_overwrite(&res);
	sf_set_possible_negative(res);
	return res;
}

int mknod(const char *fname, int mode, int dev) {
    sf_use(fname);
    sf_tocttou_access(fname);

	int res;
	sf_overwrite(&res);
	sf_set_possible_negative(res);
	return res;
}

int stat(const char *restrict fname, struct stat *restrict st) {
    sf_use(fname);
    sf_bitinit(st);
    //note: do not forget sf_bitinit
    sf_tocttou_check(fname);

    int res;
    sf_overwrite(&res);
    sf_set_possible_negative(res);
    sf_set_errno_if(res, sf_cond_range("==", -1));
    sf_no_errno_if(res, sf_cond_range("==", 0));
    return res;
}

int stat64(const char *restrict fname, struct stat *restrict st) {
    return stat(fname, st);
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

int statfs64(const char *path, struct statfs *buf) {
    return statfs(path, buf);
}

int fstatfs(int fd, struct statfs *buf) {
    sf_bitinit(buf);
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

int fstatfs64(int fd, struct statfs *buf) {
    return fstatfs(fd, buf);
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

int statvfs64(const char *path, struct statvfs *buf) {
    return statvfs(path, buf);
}

int fstatvfs(int fd, struct statvfs *buf) {
    sf_bitinit(buf);
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

int fstatvfs64(int fd, struct statvfs *buf) {
    return fstatvfs(fd, buf);
}

void _Exit(int code) {
    sf_terminate_path();
    // easiest way to suppress 'noreturn' warning in gcc-genmif
    //_Exit(code);
}

void abort(void) {
    sf_terminate_path();
    // easiest way to suppress 'noreturn' warning in gcc-genmif
    //abort();
}

int abs(int x) {
    int res;
    sf_overwrite(&res);
    sf_pure(res, x);
    return res;
}

long labs(long x) {
    long res;
    sf_overwrite(&res);
    sf_pure((long)res, (long)x);
    return res;
}

long long llabs(long long x) {
    long long res;
    sf_overwrite(&res);
    sf_pure((long long)res, (long)x);
    return res;
}

double atof(const char *arg) {
    char d1 = *arg;
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

void *calloc(size_t num, size_t size) {
    sf_set_trusted_sink_int(num);
    sf_set_trusted_sink_int(size);

    void *ptr;
    sf_overwrite(&ptr);
    sf_overwrite(ptr);
    sf_set_alloc_possible_null(ptr, num ,size);
    sf_uncontrolled_ptr(ptr);
    sf_new(ptr, MALLOC_CATEGORY);
    sf_set_buf_size(ptr, size * num);
    sf_lib_arg_type(ptr, "MallocCategory");
    return ptr;
}

void exit(int code) {
    sf_terminate_path();
    // easiest way to suppress 'noreturn' warning in gcc-genmif
    //exit(code);
}

char *fcvt(double value, int ndigit, int *dec, int sign) { // (LEGACY ) 
    sf_overwrite(*dec);                                                                                      
    sf_set_possible_negative(*dec);                                                                          
}

void free(void *ptr) {
    sf_set_must_be_not_null(ptr, FREE_OF_NULL);
    //sf_overwrite(ptr);
    sf_delete(ptr, MALLOC_CATEGORY);
    sf_lib_arg_type(ptr, "MallocCategory");
}

char *getenv(const char *key) {
    sf_vulnerable_fun_type(
        "System's environment variable can be controlled externally. "
        "Please use tzplatform_getenv() or use secure storage instead of getenv()", GETENV);
    
    char d1 = *key;

    char *str;
    sf_overwrite(&str);
    sf_set_tainted(str);
//    sf_set_tainted_buf(str, 0, 0);
    sf_set_possible_null(str);
    sf_null_terminated(str);
    return str;
}

void *malloc(size_t size) {
    sf_set_trusted_sink_int(size);
    sf_malloc_arg(size);

    void *ptr;
    sf_overwrite(&ptr);
    sf_overwrite(ptr);
    sf_uncontrolled_ptr(ptr);
    sf_set_alloc_possible_null(ptr, size);
    sf_new(ptr, MALLOC_CATEGORY);
    sf_raw_new(ptr);
    sf_set_buf_size(ptr, size);
    sf_lib_arg_type(ptr, "MallocCategory");
    return ptr;
}

void *aligned_alloc(size_t alignment, size_t size) {
    return malloc(size);
}

int mkstemp(char *template) {
    int res;
    sf_overwrite(&res);
    sf_set_possible_negative(res);
    return res;
}

int mkostemp(char *template, int flags) {
    int res;
    sf_overwrite(&res);
    sf_set_possible_negative(res);
    return res;
}

int mkstemps(char *template, int suffixlen) {
    int res;
    sf_overwrite(&res);
    sf_set_possible_negative(res);
    return res;
}

int mkostemps(char *template, int suffixlen, int flags) {
    int res;
    sf_overwrite(&res);
    sf_set_possible_negative(res);
    return res;
}

char *ptsname(int fd) {
    char *res;
    sf_overwrite(&res);
    sf_set_possible_null(res);
    return res;
}

int putenv(char *cmd) {
    char d1 = *cmd;
    sf_set_trusted_sink_ptr(cmd);
    sf_escape(cmd);
}

void qsort(void *base, size_t num, size_t size, int (*comparator)(const void *, const void *)) {
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

int rand_r(unsigned int *seedp) {
    unsigned int d = *seedp;
    int res;
    sf_overwrite(&res);
	sf_set_values(res, 0, 32767);//use RAND_MAX?
    sf_set_tainted_int(res);
    sf_rand_value(res);
    return res;
}

void srand(unsigned seed) {
}

long random(void) {
    long res;
    sf_overwrite(&res);
    sf_fun_rand();
    sf_set_tainted_long(res);
    sf_rand_value(res);
    return res;
}

void srandom(unsigned seed) {
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

void *realloc(void *ptr, size_t size) {
	sf_escape(ptr);
    //TODO:
    //if(ptr!=0) {
    //    sf_overwrite(ptr);
    //    sf_delete(ptr, MALLOC_CATEGORY);
    //}
    //it's totally incorrect
    //if(ptr)
    //    free(ptr);

    sf_set_trusted_sink_int(size);

    void *retptr;
    sf_overwrite(&retptr);
    sf_overwrite(retptr);
    sf_uncontrolled_ptr(retptr);
    sf_set_alloc_possible_null(retptr, size);
    sf_new(retptr, MALLOC_CATEGORY);
    sf_invalid_pointer(ptr, retptr);
    sf_set_buf_size(retptr, size);
    sf_lib_arg_type(retptr, "MallocCategory");
    sf_bitcopy(retptr, ptr);

    return retptr;
}

char *realpath(const char *restrict path, char *restrict resolved_path) {
    sf_use(path);
    sf_tocttou_access(path);

    if (resolved_path == NULL) {
        void *retptr;
        sf_overwrite(&retptr);
        sf_overwrite(retptr);
        sf_uncontrolled_ptr(retptr);
        sf_new(retptr, MALLOC_CATEGORY);
        return retptr;
    }

    sf_bitinit(resolved_path);
    return resolved_path;
}

int setenv(const char *key, const char *val, int flag) {
    char d1 = *key;
    char d2 = *val;
    sf_set_trusted_sink_ptr(key);
    sf_set_trusted_sink_ptr(val);
}

double strtod(const char *restrict nptr, char **restrict endptr) {
    char d1 = *nptr;
    sf_overwrite(endptr);//note: maybe null
}

float strtof(const char *restrict nptr, char **restrict endptr) {
    char d1 = *nptr;
    sf_overwrite(endptr);//note: maybe null
}

long strtol(const char *restrict nptr, char **restrict endptr, int base) {
    char d1 = *nptr;

    long res;
    sf_overwrite(&res);
    sf_str_to_long(nptr, res);

    if(endptr) {
        sf_overwrite(endptr);

        if(*endptr==0) {
            //idea is follow: function return 0 in case of error. 
            sf_assert_cond(res, "==", 0);
        }

    }

    sf_pure(res, nptr, base); //hack: we have to check content of 'nptr', not 'nptr' itself

    return res;
}

long double strtold(const char *restrict nptr, char **restrict endptr) {
    char d1 = *nptr;
    sf_overwrite(endptr);//note: maybe null
}

long long strtoll(const char *restrict nptr, char **restrict endptr, int base) {
    char d1 = *nptr;
    sf_overwrite(endptr);//note: maybe null

    long res;
    sf_overwrite(&res);
    sf_str_to_long(nptr, res);//long long?
    sf_pure(res, nptr, base); //hack: result depends from content of nptr
    return res;
}

unsigned long strtoul(const char *restrict nptr, char **restrict endptr, int base) {
    char d1 = *nptr;
    sf_overwrite(endptr);//note: maybe null

    long res;
    sf_overwrite(&res);
    sf_str_to_long(nptr, res);//unsigned long?
    sf_pure(res, nptr, base); //hack: result depends from content of nptr
    return res;
}

unsigned long long strtoull(const char *restrict nptr, char **restrict endptr, int base) {
    char d1 = *nptr;
    sf_overwrite(endptr);//note: maybe null

    long res;
    sf_overwrite(&res);
    sf_str_to_long(nptr, res);//unsigned long long
    sf_pure(res, nptr, base); //hack: result depends from content of arg
    return res;
}

int system(const char *cmd) {
    char d1 = *cmd;
    sf_set_trusted_sink_ptr(cmd);
}

int unsetenv(const char *key) {
    char d1 = *key;
}

int wctomb(char* pmb, wchar_t wc) {
	int res;
        sf_bitinit(pmb);
	sf_overwrite(&res);
	sf_must_be_checked(res);
	return res;
}

void setproctitle(const char *fmt, ...) {
    sf_use_format(fmt);
}

void syslog(int priority, const char *message, ...) {
	char d1 = *message;
    sf_use_format(message);
    sf_fun_does_not_update_vargs(2);
}

void vsyslog(int priority, const char *message, __va_list) {
		char d1 = *message;
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

int utimes(const char *fname, const struct timeval times[2]) {
    sf_tocttou_access(fname);
}

struct tm *localtime(const time_t *timer) {
    { char _qqq_ = *((char*)timer);};
    
    struct tm *ptr;
    sf_overwrite(&ptr);
    sf_bitinit(ptr);
    sf_set_possible_null(ptr);
    return ptr;
}

int access(const char *fname, int flags) {
    sf_tocttou_check(fname);
    sf_set_trusted_sink_ptr(fname);
    int res;
    sf_set_errno_if(res, sf_cond_range("==", -1));
    sf_no_errno_if(res, sf_cond_range("==", 0));
    return res;
}

int chdir(const char *fname) {
    sf_tocttou_access(fname);
    sf_set_trusted_sink_ptr(fname);
    int res;
    sf_set_errno_if(res, sf_cond_range("==", -1));
    sf_no_errno_if(res, sf_cond_range("==", 0));
    return res;
}

int chroot(const char *fname) {
    sf_tocttou_access(fname);
    sf_set_trusted_sink_ptr(fname);

    int a;
    sf_overwrite(&a);
    sf_chroot_return(a);
    sf_vulnerable_fun("This function is unsafe.");
    sf_set_errno_if(a, sf_cond_range("==", -1));
    sf_no_errno_if(a, sf_cond_range("==", 0));
    return a;
}

int seteuid(uid_t euid) {
    sf_vulnerable_fun("This function is unsafe.");
    int x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range("==", 0));
    return x;
}

int setegid(uid_t egid) {
    sf_vulnerable_fun("This function is unsafe.");
    int x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range("==", 0));
    return x;
}

int sethostid(long hostid) {
    sf_vulnerable_fun("This function is unsafe.");
    int x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range("==", 0));
    return x;
}

int chown(const char *fname, int uid, int gid) {
    sf_tocttou_access(fname);
    sf_set_trusted_sink_ptr(fname);
    int x;
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range("==", 0));
    return x;
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

int close(int fd) {
    sf_must_not_be_release(fd);
    sf_handle_release(fd, SOCKET_CATEGORY);//TODO: ??
    sf_lib_arg_type(fd, "StdioHandlerCategory");

    int x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range("==", 0));
    sf_func_success_if(x, 0);
    return x;
}

int execl(const char *path, const char *arg0, ...) {
    sf_tocttou_access(path);
    sf_set_trusted_sink_ptr(path);
    sf_fun_does_not_update_vargs(2);
    // The exec() functions return only if an error has occurred.
    int res = -1;
    sf_set_errno_if(res, sf_top());
    sf_no_errno_if(res, sf_bottom());
    return res;
}

int execle(const char *path, const char *arg0, ...) {
    sf_tocttou_access(path);
    sf_fun_does_not_update_vargs(2);
    // The exec() functions return only if an error has occurred.
    int res;
    sf_set_errno_if(res, sf_top());
    sf_no_errno_if(res, sf_bottom());
    return res = -1;
}

int execlp(const char *file, const char *arg0, ...) {
    sf_tocttou_access(file);
    sf_fun_does_not_update_vargs(2);
    // The exec() functions return only if an error has occurred.
    int res = -1;
    sf_set_errno_if(res, sf_top());
    sf_no_errno_if(res, sf_bottom());
    return res;
}

int execv(const char *path, char *const argv[]) {
    sf_tocttou_access(path);
    sf_set_trusted_sink_ptr(path);
    // The exec() functions return only if an error has occurred.
    int res = -1;
    sf_set_errno_if(res, sf_top());
    sf_no_errno_if(res, sf_bottom());
    return res;
}

int execve(const char *path, char *const argv[], char *const envp[]) {
    sf_tocttou_access(path);
    sf_set_trusted_sink_ptr(path);
    // The exec() functions return only if an error has occurred.
    int res = -1;
    sf_set_errno_if(res, sf_top());
    sf_no_errno_if(res, sf_bottom());
    return res;
}

int execvp(const char *file, char *const argv[]) {
    sf_tocttou_access(file);
    sf_set_trusted_sink_ptr(file);
    // The exec() functions return only if an error has occurred.
    int res = -1;
    sf_set_errno_if(res, sf_top());
    sf_no_errno_if(res, sf_bottom());
    return res;
}

void _exit(int rcode) {
    sf_terminate_path();
    // easiest way to suppress 'noreturn' warning in gcc-genmif
    _exit(rcode);
}

int fchown(int fd, uid_t owner, gid_t group) {
    sf_set_must_be_positive(fd);
    int x;
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range("==", 0));
    return x;
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

pid_t fork(void) {
    pid_t x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range(">=", 0));
    sf_fork_by(x);
    return x;
}

long int fpathconf(int fd, int name) {
    sf_set_must_be_positive(fd);
    // If the system does not have a limit for the requested
    // resource, -1 is returned, and errno is unchanged.
    // Don't use sf_set_errno_if here!
}

int fsync(int fd) {
    sf_set_must_be_positive(fd);
    sf_lib_arg_type(fd, "FileHandlerCategory");
    int x;
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range("==", 0));
    return x;
}

int ftruncate(int fd, off_t length) {
    sf_set_must_be_positive(fd);
    sf_lib_arg_type(fd, "FileHandlerCategory");
    int x;
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range("==", 0));
    return x;
}

int ftruncate64(int fd, off_t length) {
    return ftruncate(fd, length);
}

char *getcwd(char *buf, size_t size) {
    if (size > 0) {
        char d1 = *buf;
        char d2 = buf[size-1];
    }
    sf_bitinit(buf);
    char *res;
    sf_overwrite(&res);
    sf_set_possible_null(res);
    sf_set_errno_if(res, sf_cond_range("==", 0));
    sf_password_set(buf);
    sf_password_set(res);
    return res;
}

int getopt(int argc, char * const argv[], const char *optstring) {
    if (argc > 0) {
        char *c1 = argv[0];
	char *c2 = argv[argc - 1];
	char c3 = *optstring;
    }
    int ret;
    sf_overwrite(&ret);
    sf_set_possible_negative(ret);
    sf_overwrite(&optarg);
    sf_set_possible_null(optarg);
    // The value of errno after getopt() is unspecified
    return ret;
}

pid_t getpid(void) {
    pid_t x;
    sf_overwrite(&x);
    sf_password_set(x);
    return x;
}

pid_t getppid(void) {
    pid_t x;
    sf_overwrite(&x);
    return x;
}

pid_t getsid(pid_t pid) {
    pid_t x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range(">=", 0));
    return x;
}

uid_t getuid(void) {
    uid_t x;
    sf_overwrite(&x);
    return x;
}

uid_t geteuid(void) {
    uid_t x;
    sf_overwrite(&x);
    return x;
}

gid_t getgid(void) {
    gid_t x;
    sf_overwrite(&x);
    return x;
}

gid_t getegid(void) {
    gid_t x;
    sf_overwrite(&x);
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

pid_t getpgrp(/*'void' or 'int pid'*/) {
    pid_t x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
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

int lchown(const char *fname, int uid, int gid) {
    sf_tocttou_access(fname);
    sf_set_trusted_sink_ptr(fname);
    int x;
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range("==", 0));
    return x;
}

int link(const char *path1, const char *path2) {
    sf_tocttou_access(path1);
    sf_tocttou_access(path2);

    sf_set_trusted_sink_ptr(path1);
    sf_set_trusted_sink_ptr(path2);
    int x;
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range("==", 0));
    return x;
}

off_t lseek(int fildes, off_t offset, int whence) {
    sf_must_not_be_release(fildes);
    sf_set_must_be_positive(fildes);
    sf_lib_arg_type(fildes, "FileHandlerCategory");
    off_t x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range(">=", 0));
    return x;
}

off_t lseek64(int fildes, off_t offset, int whence) {
    return lseek(fildes, offset, whence);
}

long int pathconf(const char *path, int name) {
    sf_tocttou_access(path);
    sf_set_trusted_sink_ptr(path);
    // Don't use sf_set_errno_if here!
}

int pipe(int pipefd[2]) {
    int x, y, z;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    sf_overwrite(&y);
    pipefd[0] = y;
    sf_overwrite(&z);
    pipefd[1] = z;
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range("==", 0));
    return x;
}

int pipe2(int pipefd[2], int flags) {
    int x, y, z;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    sf_overwrite(&y);
    pipefd[0] = y;
    sf_overwrite(&z);
    pipefd[1] = z;
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range("==", 0));
    return x;
}

ssize_t pread(int fd, void *buf, size_t nbytes, off_t offset) {
    sf_bitinit(buf);
	sf_must_not_be_release(fd);
    sf_set_must_be_positive(fd);
    sf_lib_arg_type(fd, "StdioHandlerCategory");

    sf_set_possible_nnts(buf);
    sf_buf_size_limit(buf, nbytes);

    ssize_t x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    sf_uncontrolled_value(x);

    sf_assert_cond(x, "<=", nbytes);
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range(">=", 0));
    sf_buf_fill(x, buf);
    return x;
}

ssize_t pwrite(int fd, const void *buf, size_t nbytes, off_t offset) {
    sf_use(buf);
	sf_must_not_be_release(fd);
    sf_set_must_be_positive(fd);
    sf_lib_arg_type(fd, "StdioHandlerCategory");
    sf_set_trusted_sink_int(nbytes);


    sf_buf_size_limit(buf, nbytes);
    sf_buf_size_limit_read(buf, nbytes);

    ssize_t x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    sf_assert_cond(x, "<=", nbytes);
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range(">=", 0));
    sf_buf_fill(x, buf);
    return x;
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

int rmdir(const char *path) {
    sf_tocttou_access(path);
	sf_set_trusted_sink_ptr(path);
}

unsigned int sleep(unsigned int ms) {
	sf_long_time();
    sf_set_trusted_sink_int(ms);
}

int setgid(gid_t gid) {
    int x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
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

pid_t setpgrp(/*'void' or 'pid_t pid, pid_t pgid'*/) {
    pid_t x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    return x;
}

pid_t setsid(void) {
    pid_t x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    return x;
}

int setuid(uid_t uid) {
    int x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    return x;
}

int setregid(gid_t rgid, gid_t egid) {
    int x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    return x;
}

int setreuid(uid_t ruid, uid_t euidt) {
    int x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    return x;
}

int symlink(const char *path1, const char *path2) {
    sf_tocttou_access(path1);
    sf_tocttou_access(path2);
}

long int sysconf(int name) {
    int x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    return x;    
}

int truncate(const char *fname, off_t off) {
    sf_tocttou_access(fname);
	sf_set_trusted_sink_ptr(fname);
	return ret_any();
}

int truncate64(const char *fname, off_t off) {
    return truncate(fname, off);
}

int unlink(const char *path) {
    sf_tocttou_access(path);
	sf_set_trusted_sink_ptr(path);
}

int unlinkat(int dirfd, const char *path, int flags) {
    sf_tocttou_access(path);
	sf_set_trusted_sink_ptr(path);
}

int usleep(useconds_t s) {
	sf_long_time();
    sf_set_trusted_sink_int(s);
}

ssize_t write(int fd, const void *buf, size_t nbytes) {
    if (nbytes != 0) {
	char ch = (*(const char*)buf);
    }

    sf_must_not_be_release(fd);
    sf_set_must_be_positive(fd);
    sf_lib_arg_type(fd, "StdioHandlerCategory");

    sf_set_trusted_sink_int(nbytes);
    sf_buf_size_limit(buf, nbytes);
    sf_buf_size_limit_read(buf, nbytes);

    ssize_t x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    sf_assert_cond(x, "<=", nbytes);
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range(">=", 0));
    return x;
}

int uselib(const char *library) {
    sf_tocttou_access(library);
	sf_set_trusted_sink_ptr(library);
}

char *mktemp(char *template) {
    sf_vulnerable_fun_temp("This function is susceptible to a race condition occurring between testing for a file's existence (in the function) and access to the file (later in user code), which allows malicious users to potentially access arbitrary files in the system. Use mkstemp(), mkstemps(), or mkdtemp() instead.");
}

int utime(const char *path, const struct utimbuf *times) {
    sf_tocttou_access(path);
}

struct utmp *getutent(void) {
    struct utmp *res;
    sf_overwrite(&res);
    sf_set_possible_null(res);
    return res;
}

struct utmp *getutid(struct utmp *ut) {
    struct utmp *res;
    sf_overwrite(&res);
    sf_use(ut);
    sf_set_possible_null(res);
    return res;
}

struct utmp *getutline(struct utmp *ut) {
    struct utmp *res;
    sf_overwrite(&res);
    sf_use(ut);
    sf_set_possible_null(res);
    return res;
}

struct utmp *pututline(struct utmp *ut) {
    struct utmp *res;
    sf_overwrite(&res);
    sf_use(ut);
    sf_set_possible_null(res);
    return res;
}

void utmpname(const char *file) {
    sf_tocttou_access(file);
}

struct utmp *getutxent(void) {
    struct utmp *res;
    sf_overwrite(&res);
    sf_set_possible_null(res);
    return res;
}

struct utmp *getutxid(struct utmp *ut) {
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

void utmpxname(const char *file) {
    sf_tocttou_access(file);
}

int uname (struct utsname *name) {
    sf_bitinit(name);
    sf_password_set(name->sysname);
    sf_password_set(name->nodename);
    sf_password_set(name->release);
    sf_password_set(name->version);
    sf_password_set(name->machine);

    int ret;
    sf_overwrite(&ret);
    return ret;
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

VOS_INT VOS_vsnprintf_s(VOS_CHAR * str, VOS_SIZE_T destMax, VOS_SIZE_T count, const VOS_CHAR * format, va_list arglist) {
    if (format) {
        char d2 = *format;
    }

    sf_bitinit(str);
    sf_use_format(format);
    sf_buf_size_limit(str, destMax);
    sf_buf_size_limit_strict(str, destMax);
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

VOS_UINT32 VOS_Que_Read (VOS_UINT32 ulQueueID, VOS_UINTPTR aulQueMsg[4], VOS_UINT32 ulFlags, VOS_UINT32 ulTimeOut) {
    sf_overwrite(aulQueMsg);
    sf_set_tainted(aulQueMsg);
    sf_set_possible_nnts(aulQueMsg);
    sf_bitinit(aulQueMsg);
}

VOS_INT VOS_sscanf_s(const VOS_CHAR *buffer, const VOS_CHAR * format, ...) {
    char d1 = *buffer;
    char d2 = *format;
    sf_use_format(format);

    sf_fun_scanf_like(1);
    sf_fun_updates_vargs(2);
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

int XAddHost(Display* dpy, XHostAddress* host) {
  sf_use(host);
}

int XRemoveHost(Display* dpy, XHostAddress* host) {
  sf_use(host);
}

int XChangeProperty(Display *dpy, Window w, Atom property, Atom type, int format, int mode, _Xconst unsigned char * data, int nelements) {
  sf_use(data); 
}

Bool XF86VidModeModModeLine(Display *dpy, int screen, XF86VidModeModeLine *modeline) {
  sf_use(modeline);
}

void XtGetValues(Widget w, ArgList args, Cardinal num_args) {
  sf_bitinit_subelements(args);
}

XIDeviceInfo * XIQueryDevice(Display *display, int deviceid, int *ndevices_return) {
    XIDeviceInfo *res;
    sf_overwrite(&res);
    sf_overwrite(res);
	//sf_uncontrolled_value(res);
    //sf_set_possible_null(res);
    sf_bitinit(ndevices_return);
    sf_handle_acquire(res, X11_DEVICE);
    return res;
}

struct Colormap *XListInstalledColormaps(Display *display, Window w, int *num_return) {
    struct Colormap *res;
    sf_overwrite(&res);
    sf_overwrite(res);
	//sf_uncontrolled_value(res);
    //sf_set_possible_null(res);
    sf_handle_acquire(res, X11_CATEGORY);
    return res;
}

