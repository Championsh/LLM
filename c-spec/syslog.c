#include "specfunc.h"

/*
void closelog(void);
void openlog(const char *, int, int);
int setlogmask(int);
*/

void syslog(int priority, const char *message, ...) {
	char d1 = *message;
    sf_use_format(message);
    sf_fun_does_not_update_vargs(2);
}

void vsyslog(int priority, const char *message, __va_list) {
		char d1 = *message;
}

/*
void closelog_r(struct syslog_data *);
void openlog_r(const char *, int, int, struct syslog_data *);
int setlogmask_r(int, struct syslog_data *);
void syslog_r(int, struct syslog_data *, const char *, ...)
void vsyslog_r(int, struct syslog_data *, const char *, __va_list);
*/
