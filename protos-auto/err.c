#include "specfunc.h"

#define va_list void *

 
 

void err(int eval, const char *fmt, ...);

void verr(int eval, const char *fmt, va_list args);

void errx(int eval, const char *fmt, ...);

void verrx(int eval, const char *fmt, va_list args);

void warn(const char *fmt, ...);

void vwarn(const char *fmt, va_list args);

void warnx(const char *fmt, ...);

void vwarnx(const char *fmt, va_list args);
