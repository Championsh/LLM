#include "specfunc.h"

#define SIGABRT 6
#define SIGKILL 9

typedef void (*sighandler_t)(int);

 

int raise (int sig);

 

int kill(pid_t pid, int sig);
