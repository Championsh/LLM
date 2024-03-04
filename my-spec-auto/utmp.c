#include "specfunc.h"

struct utmp *getutent(void);

struct utmp *getutid(struct utmp *ut);

struct utmp *getutline(struct utmp *ut);

struct utmp *pututline(struct utmp *ut);

 
 

void utmpname(const char *file);
