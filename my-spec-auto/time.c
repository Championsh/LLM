#include "specfunc.h"

 
 
 
 
 
 

struct timeval ;;

struct timespec
;;

struct tm ;;

#define MAY_RETURN_NULL     struct tm *ptr;\
    						sf_overwrite(&ptr);\
                                                sf_bitinit(ptr); \
    						sf_set_possible_null(ptr);\
    						return ptr;

#define DEREF(ptr); 

int utimes(const char *fname, const struct timeval times[2]);

struct tm *localtime(const time_t *timer);

struct tm *localtime_r(const time_t *restrict timer, struct tm *restrict result);

struct tm *gmtime(const time_t *timer);

struct tm *gmtime_r(const time_t *restrict timer, struct tm *restrict result);

char *ctime(const time_t *clock);

char *ctime_r(const time_t *clock, char *buf);

char *asctime(const struct tm *timeptr);

char *asctime_r(const struct tm *restrict tm, char *restrict buf);

size_t
strftime(char *s, size_t maxsize, const char *format,
         const struct tm *timeptr);

time_t mktime(struct tm *timeptr);

time_t time(time_t *t);

int clock_getres(clockid_t clk_id, struct timespec *res);

int clock_gettime(clockid_t clk_id, struct timespec *tp);

int clock_settime(clockid_t clk_id, const struct timespec *tp);

int nanosleep(const struct timespec *req, struct timespec *rem);
