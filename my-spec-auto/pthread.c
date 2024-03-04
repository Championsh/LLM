#include "specfunc.h"

struct pthread;
typedef struct pthread pthread_t;

struct pthread_attr;
typedef struct pthread_attr pthread_attr_t;

struct pthread_mutex;
typedef struct pthread_mutex pthread_mutex_t;

struct pthread_spinlock;
typedef struct pthread_spinlock pthread_spinlock_t;

struct pthread_mutexattr;
typedef struct pthread_mutexattr pthread_mutexattr_t;

void pthread_exit(void *value_ptr);

int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr);

 
int pthread_mutex_destroy(pthread_mutex_t *mutex)
;

int pthread_mutex_lock(pthread_mutex_t *mutex);

int pthread_mutex_unlock(pthread_mutex_t *mutex);

int pthread_mutex_trylock(pthread_mutex_t *mutex);

int pthread_spin_lock(pthread_spinlock_t *mutex);

int pthread_spin_unlock(pthread_spinlock_t *mutex);

int pthread_spin_trylock(pthread_spinlock_t *mutex);

int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                          void *(*start_routine)(void *), void *arg);

struct __pthread_cleanup_frame ;;

void __pthread_cleanup_routine (struct __pthread_cleanup_frame *__frame);
