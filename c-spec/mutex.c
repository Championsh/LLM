#include "specfunc.h"

struct mutex;

void mutex_lock(struct mutex *lock) {
    sf_lock(lock);
}

void mutex_unlock(struct mutex *lock) {
    sf_unlock(lock);
}

void mutex_lock_nested(struct mutex *lock, unsigned int subclass)
{
    sf_lock(lock);
}

