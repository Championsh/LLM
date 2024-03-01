#include "specfunc.h"

// todo gcc-genmif doesn't seem to recognize it - need to play with
// cmdline parameters
#define restrict

#define GETENV "GETENV"
#define SQLITE "SQLITE"

void _Exit(int code) {
    sf_terminate_path();
    // easiest way to suppress 'noreturn' warning in gcc-genmif
    //_Exit(code);
}

// long a64l(const char *);

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

// int atexit(void (*)(void));

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

// void *bsearch(const void *, const void *, size_t, size_t, int (*)(const void *, const void *));

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


// div_t div(int, int);

// double drand48(void);
// char *ecvt(double, int, int *restrict, int *restrict);
// (LEGACY ) double erand48(unsigned short[3]);

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

// char *gcvt(double, int, char *); (LEGACY )

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

// int getsubopt(char **, char *const *, char **);
// int grantpt(int);
// char *initstate(unsigned, char *, size_t);
// long jrand48(unsigned short[3]);
// char *l64a(long);

// void lcong48(unsigned short[7]);

// ldiv_t ldiv(long, long);
// lldiv_t lldiv(long long, long long);

// long lrand48(void);

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



// int mblen(const char *, size_t);
// size_t mbstowcs(wchar_t *restrict, const char *restrict, size_t);
// int mbtowc(wchar_t *restrict, const char *restrict, size_t);

// char *mktemp(char *);

// (LEGACY ) 
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

// long mrand48(void);
// long nrand48(unsigned short[3]);

// int posix_memalign(void **, size_t, size_t);

// int posix_openpt(int);

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

// unsigned short seed48(unsigned short[3]);

int setenv(const char *key, const char *val, int flag) {
    char d1 = *key;
    char d2 = *val;
    sf_set_trusted_sink_ptr(key);
    sf_set_trusted_sink_ptr(val);
}

// void setkey(const char *);
// char *setstate(const char *);

// void srand48(long);

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

// int unlockpt(int);

int unsetenv(const char *key) {
    char d1 = *key;
}

// size_t wcstombs(char *restrict, const wchar_t *restrict, size_t);

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
