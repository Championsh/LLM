#include "specfunc.h"

#if __WORDSIZE == 64
typedef long int __jmp_buf[8];
#else
typedef int __jmp_buf[6];
#endif

#define _SIGSET_NWORDS (1024 / (8 * sizeof (unsigned long int)))
typedef struct {
    unsigned long int __val[_SIGSET_NWORDS];
} __sigset_t;

struct __jmp_buf_tag {
    __jmp_buf __jmpbuf;         /* Calling environment.  */
    int __mask_was_saved;       /* Saved the signal mask?  */
    __sigset_t __saved_mask;    /* Saved signal mask.  */
};

typedef struct __jmp_buf_tag jmp_buf[1];
typedef struct __jmp_buf_tag sigjmp_buf[1];

void longjmp(jmp_buf env, int value) {
    sf_terminate_path();
}

void siglongjmp(sigjmp_buf env, int val) {
    sf_terminate_path();
}

int setjmp(jmp_buf env) {
    int ret;
    sf_overwrite(&ret);
    sf_overwrite(env);
    return ret;
}

int sigsetjmp(sigjmp_buf env, int savesigs) {
    int ret;
    sf_overwrite(&ret);
    sf_overwrite(env);
    return ret;
}
