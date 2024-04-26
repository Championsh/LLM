#include "specfunc.h"

// int getitimer(int, struct itimerval *);
// int gettimeofday(struct timeval *restrict, void *restrict);
// int select(int, fd_set *restrict, fd_set *restrict, fd_set *restrict,
//             struct timeval *restrict);
// int setitimer(int, const struct itimerval *restrict,
//               struct itimerval *restrict);

struct timeval {
    time_t          tv_sec;         /* seconds */
    suseconds_t     tv_usec;        /* and microseconds */
};

struct timespec
{
    time_t          tv_sec;         /* seconds.  */
    long int        tv_nsec;        /* manoseconds.  */
};

struct tm {
};

#define MAY_RETURN_NULL     struct tm *ptr;\
    						sf_overwrite(&ptr);\
                                                sf_bitinit(ptr); \
    						sf_set_possible_null(ptr);\
    						return ptr;

#define DEREF(ptr) { char _qqq_ = *((char*)ptr);} 

struct tm *localtime_r(const time_t *restrict timer, struct tm *restrict result) {
    DEREF(timer);
    sf_bitinit(result);
    MAY_RETURN_NULL
}

struct tm *gmtime(const time_t *timer) {
    DEREF(timer);
    MAY_RETURN_NULL
}

struct tm *gmtime_r(const time_t *restrict timer, struct tm *restrict result) {
    DEREF(timer);
    sf_bitinit(result);
    MAY_RETURN_NULL
}

char *ctime(const time_t *clock) {
	MAY_RETURN_NULL
}

char *ctime_r(const time_t *clock, char *buf) {
	MAY_RETURN_NULL
}

char *asctime(const struct tm *timeptr) {
	MAY_RETURN_NULL
}

char *asctime_r(const struct tm *restrict tm, char *restrict buf) {
	MAY_RETURN_NULL
}

size_t
strftime(char *s, size_t maxsize, const char *format,
         const struct tm *timeptr) {
    DEREF(timeptr);
    sf_bitinit(s);
}

time_t mktime(struct tm *timeptr) {
    DEREF(timeptr);
}

time_t time(time_t *t) {
    if(!t) {
/* time(NULL) can fail only on clockless systems,
   so assume it can't. */
        time_t ret;
        sf_overwrite(&ret);
        return ret;
    }

    DEREF(t);

    time_t ret;
    sf_bitinit(t);
    sf_overwrite(t);
    sf_overwrite(&ret);
    sf_set_possible_negative(ret);
    return ret;
}

int clock_getres(clockid_t clk_id, struct timespec *res) {
    int ret;
    if(res != 0) {
        sf_overwrite(res);
    }
    sf_overwrite(&ret);
    sf_set_possible_negative(ret);
    sf_bitinit(res);
    return ret;
}

int clock_gettime(clockid_t clk_id, struct timespec *tp) {
    int ret;
    if(tp != 0) {
        sf_overwrite(tp);
    }
    sf_overwrite(&ret);
    sf_set_possible_negative(ret);
    sf_bitinit(tp);
    return ret;
}

int clock_settime(clockid_t clk_id, const struct timespec *tp) {
    int ret;
    DEREF(tp);
    sf_overwrite(&ret);
    sf_set_possible_negative(ret);
    sf_bitinit(tp);
    return ret;
}

int nanosleep(const struct timespec *req, struct timespec *rem) {
    int ret;
    DEREF(req);
    sf_overwrite(&ret);
    sf_set_possible_negative(ret);
    sf_overwrite(rem);
    return ret;
}
