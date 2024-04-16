#include "specfunc.h"

struct sem;
typedef struct sem sem_t;

int sem_wait (sem_t *_sem) {
    sf_sync(_sem);
    //commented due too useless DOUBLE_LOCK
	//sf_lock(_sem);
}

int sem_post (sem_t *_sem) {
    sf_sync(_sem);
	//sf_unlock(_sem);
}
