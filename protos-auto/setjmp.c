#include "specfunc.h"

#if __WORDSIZE == 64
typedef long int __jmp_buf[8];
#else
typedef int __jmp_buf[6];
#endif

#define _SIGSET_NWORDS (1024 / (8 * sizeof (unsigned long int)))
typedef struct ; __sigset_t;

struct __jmp_buf_tag ;;

typedef struct __jmp_buf_tag jmp_buf[1];
typedef struct __jmp_buf_tag sigjmp_buf[1];

void longjmp(jmp_buf env, int value);

void siglongjmp(sigjmp_buf env, int val);

int setjmp(jmp_buf env);

int sigsetjmp(sigjmp_buf env, int savesigs);
