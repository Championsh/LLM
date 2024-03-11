#include "specfunc.h"

struct mutex;

void mutex_lock(struct mutex *lock);

void mutex_unlock(struct mutex *lock);

void mutex_lock_nested(struct mutex *lock, unsigned int subclass)
;

