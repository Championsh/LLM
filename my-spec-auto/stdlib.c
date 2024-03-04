#include "specfunc.h"

 
 
#define restrict

#define GETENV "GETENV"
#define SQLITE "SQLITE"

void _Exit(int code);

 

void abort(void);

int abs(int x);

long labs(long x);

long long llabs(long long x);

 

double atof(const char *arg);

int atoi(const char *arg);

long atol(const char *arg);

long long atoll(const char *arg);

 

void *calloc(size_t num, size_t size);


 

 
 
 

void exit(int code);

char *fcvt(double value, int ndigit, int *dec, int sign);

void free(void *ptr);

 

char *getenv(const char *key);

 
 
 
 
 

 

 
 

 

void *malloc(size_t size);

void *aligned_alloc(size_t alignment, size_t size);



 
 
 

 

 
int mkstemp(char *template);

int mkostemp(char *template, int flags);

int mkstemps(char *template, int suffixlen);

int mkostemps(char *template, int suffixlen, int flags);

 
 

 

 

char *ptsname(int fd);

int putenv(char *cmd);

void qsort(void *base, size_t num, size_t size, int (*comparator)(const void *, const void *));

int rand(void);

int rand_r(unsigned int *seedp);

void srand(unsigned seed);

long random(void);

void srandom(unsigned seed);

double drand48(void);

long lrand48(void);

long mrand48(void);

double erand48(unsigned short xsubi[3]);

long nrand48(unsigned short xsubi[3]);

long seed48(unsigned short seed16v[3]);

void *realloc(void *ptr, size_t size);

char *realpath(const char *restrict path, char *restrict resolved_path);

 

int setenv(const char *key, const char *val, int flag);

 
 

 

double strtod(const char *restrict nptr, char **restrict endptr);

float strtof(const char *restrict nptr, char **restrict endptr);

long strtol(const char *restrict nptr, char **restrict endptr, int base);

long double strtold(const char *restrict nptr, char **restrict endptr);

long long strtoll(const char *restrict nptr, char **restrict endptr, int base);

unsigned long strtoul(const char *restrict nptr, char **restrict endptr, int base);

unsigned long long strtoull(const char *restrict nptr, char **restrict endptr, int base);

int system(const char *cmd);

 

int unsetenv(const char *key);

 

int wctomb(char* pmb, wchar_t wc);

void setproctitle(const char *fmt, ...);

