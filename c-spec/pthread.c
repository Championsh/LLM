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

void pthread_exit(void *value_ptr) {
    sf_terminate_path();

    // easiest way to suppress 'noreturn' warning in gcc-genmif
    pthread_exit(value_ptr);
}

int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr) {
    sf_bitinit(mutex);

    int res;
    sf_overwrite(&res);
    return res;
}

/* TODO */
int pthread_mutex_destroy(pthread_mutex_t *mutex)
{
    char deref = *((char *)mutex);
    int ret;
    sf_overwrite(&ret);
    sf_overwrite(mutex);
    return ret;
}

int pthread_mutex_lock(pthread_mutex_t *mutex) {
    sf_lock(mutex);

    int res;
    sf_overwrite(&res);
    sf_success_lock_if_zero(res, mutex);
    return res;
}

int pthread_mutex_unlock(pthread_mutex_t *mutex) {
    sf_unlock(mutex);
}

int pthread_mutex_trylock(pthread_mutex_t *mutex) {
    sf_trylock(mutex);
}

int pthread_spin_lock(pthread_spinlock_t *mutex) {
    sf_lock(mutex);

    int res;
    sf_overwrite(&res);
    sf_success_lock_if_zero(res, mutex);
    return res;
}

int pthread_spin_unlock(pthread_spinlock_t *mutex) {
    sf_unlock(mutex);
}

int pthread_spin_trylock(pthread_spinlock_t *mutex) {
    sf_trylock(mutex);
}

int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                          void *(*start_routine) (void *), void *arg) {
    sf_bitinit(thread);
    sf_escape(arg);
    sf_thread_shared(arg);

    int res;
    sf_overwrite(&res);
    return res;
}

struct __pthread_cleanup_frame {
    void (*__cancel_routine) (void *);
    void *__cancel_arg;
    int __do_it;
    int __cancel_type;
};

void __pthread_cleanup_routine (struct __pthread_cleanup_frame *__frame) {
    // tmp hack: delete when we will be able to devirtualize correctly
    sf_unlock(__frame->__cancel_arg);
    sf_escape(__frame->__cancel_arg);
}
