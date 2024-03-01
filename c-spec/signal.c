#include "specfunc.h"

#define SIGABRT 6
#define SIGKILL 9

typedef void (*sighandler_t)(int);

/*
sighandler_t sysv_signal (int sig, sighandler_t handler);
sighandler_t signal (int sig, sighandler_t handler);
sighandler_t bsd_signal (int sig, sighandler_t handler);
int killpg (pid_t pgrp, int sig);*/

int raise (int sig) {
    if(sig == SIGABRT || sig == SIGKILL)
        sf_terminate_path();
}

/*
sighandler_t ssignal (int sig, sighandler_t handler);
int gsignal (int sig);
void psignal (int sig, const char *s);
void psiginfo (const siginfo_t *pinfo, const char *s);
int sigpause (int sig_or_mask, int is_sig);
int sigpause (int mask);
int sigpause (int sig);
int sigblock (int mask);
int sigsetmask (int mask);
int siggetmask (void);
int sigemptyset (sigset_t *set);
int sigfillset (sigset_t *set);
int sigaddset (sigset_t *set, int signo);
int sigdelset (sigset_t *set, int signo);
int sigismember (const sigset_t *set, int signo);
int sigisemptyset (const sigset_t *set);
int sigandset (sigset_t *dest, sigset_t *left, sigset_t *right);
int sigorset (sigset_t *dest, sigset_t *left, sigset_t *right);
int sigprocmask (int how, const sigset_t *set, sigset_t *oldset);
int sigsuspend (const sigset_t *set);
int sigaction (int sig, const struct sigaction *act, struct sigaction *oldact);
int sigpending (sigset_t *set);
int sigwait (const sigset_t *__restrict set, int *sig);
int sigwaitinfo (const sigset_t *set, siginfo_t *info);
int sigtimedwait (const sigset_t *set, siginfo_t *info, const struct timespec *timeout);
int sigqueue (pid_t pid, int sig, const union sigval val);
int sigvec (int sig, struct sigvec *vec, struct sigvec *ovec);
int sigreturn (struct sigcontext *scp);
int siginterrupt (int sig, int interrupt);
int sigstack (const stack_t *ss, stack_t *oss);
int sigaltstack (const stack_t *ss, stack_t *oss);
int sighold (int sig);
int sigrelse (int sig);
int sigignore (int sig);
sighandler_t sigset (int sig, sighandler_t disp);
*/

int kill(pid_t pid, int sig) {
    int ret;
    sf_overwrite(&ret);
    sf_set_possible_negative(ret);
    return ret;
}
