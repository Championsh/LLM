#include "specfunc.h"

struct sem;
typedef struct sem sem_t;

int sem_wait (sem_t *_sem);

int sem_post (sem_t *_sem);
