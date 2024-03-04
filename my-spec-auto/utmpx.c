#include "specfunc.h"

struct utmp *getutxent(void);

struct utmp *getutxid(struct utmp *ut);

struct utmp *getutxline(struct utmp *ut);

struct utmp *pututxline(struct utmp *ut);

 
 

void utmpxname(const char *file);
