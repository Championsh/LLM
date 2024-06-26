#include "specfunc.h"

static int ret_any() {
    int x;
    sf_overwrite(&x);
    return x;
}

int access(const char *fname, int flags) {
    sf_tocttou_check(fname);
    sf_set_trusted_sink_ptr(fname);
    int res;
    sf_set_errno_if(res, sf_cond_range("==", -1));
    sf_no_errno_if(res, sf_cond_range("==", 0));
    return res;
}

// unsigned int     alarm(unsigned int);
// int          brk(void *);

int chdir(const char *fname) {
    sf_tocttou_access(fname);
    sf_set_trusted_sink_ptr(fname);
    int res;
    sf_set_errno_if(res, sf_cond_range("==", -1));
    sf_no_errno_if(res, sf_cond_range("==", 0));
    return res;
}

int chroot(const char *fname) {
    sf_tocttou_access(fname);
    sf_set_trusted_sink_ptr(fname);

    int a;
    sf_overwrite(&a);
    sf_chroot_return(a);
    sf_vulnerable_fun("This function is unsafe.");
    sf_set_errno_if(a, sf_cond_range("==", -1));
    sf_no_errno_if(a, sf_cond_range("==", 0));
    return a;
}

int seteuid(uid_t euid){
    sf_vulnerable_fun("This function is unsafe.");
    int x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range("==", 0));
    return x;
}

int setegid(uid_t egid){
    sf_vulnerable_fun("This function is unsafe.");
    int x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range("==", 0));
    return x;
}

int sethostid(long hostid){
    sf_vulnerable_fun("This function is unsafe.");
    int x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range("==", 0));
    return x;
}

int chown(const char *fname, int uid, int gid) {
    sf_tocttou_access(fname);
    sf_set_trusted_sink_ptr(fname);
    int x;
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range("==", 0));
    return x;
}

/*
size_t       confstr(int, char *, size_t);
char        *crypt(const char *, const char *);
char        *ctermid(char *);
char        *cuserid(char *s); (LEGACY)
*/

int dup(int oldd) {
    sf_must_not_be_release(oldd);
    sf_set_must_be_positive(oldd);
    sf_lib_arg_type(oldd, "StdioHandlerCategory");

    int res;
    sf_overwrite(&res);
    sf_overwrite_int_as_ptr(res);
    sf_set_possible_negative(res);
    sf_handle_acquire_int_as_ptr(res, HANDLE_FILE_CATEGORY);
    /* Do not check for leaks on standard descriptors 0, 1 and 2 */
    sf_not_acquire_if_less_int_as_ptr(res, res, 3);
    sf_set_errno_if(res, sf_cond_range("==", -1));
    // as I know, file descriptor is a small non-negative integer
    sf_no_errno_if(res, sf_cond_range(">=", 0));
    sf_lib_arg_type(res, "StdioHandlerCategory");
    return res;
}

int dup2(int oldd, int newdd) {
    sf_set_must_be_positive(oldd);
    sf_lib_arg_type(oldd, "StdioHandlerCategory");

    int res;
    sf_overwrite(&res);
    sf_overwrite_int_as_ptr(newdd);
    sf_set_possible_negative(res);
    sf_handle_acquire_int_as_ptr(newdd, HANDLE_FILE_CATEGORY);
    /* Do not check for leaks on standard descriptors 0, 1 and 2 */
    sf_not_acquire_if_less_int_as_ptr(newdd, res, 3);
    sf_set_errno_if(res, sf_cond_range("==", -1));
    // as I know, file descriptor is a small non-negative integer
    sf_no_errno_if(res, sf_cond_range(">=", 0));
    return res;
}

int close(int fd) {
    sf_must_not_be_release(fd);
    sf_handle_release(fd, SOCKET_CATEGORY);//TODO: ??
    sf_lib_arg_type(fd, "StdioHandlerCategory");

    int x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range("==", 0));
    sf_func_success_if(x, 0);
    return x;
}

//void         encrypt(char[64], int);

int execl(const char *path, const char *arg0, ...) {
    sf_tocttou_access(path);
    sf_set_trusted_sink_ptr(path);
    sf_fun_does_not_update_vargs(2);
    // The exec() functions return only if an error has occurred.
    int res = -1;
    sf_set_errno_if(res, sf_top());
    sf_no_errno_if(res, sf_bottom());
    return res;
}

int execle(const char *path, const char *arg0, ...) {
    sf_tocttou_access(path);
    sf_fun_does_not_update_vargs(2);
    // The exec() functions return only if an error has occurred.
    int res;
    sf_set_errno_if(res, sf_top());
    sf_no_errno_if(res, sf_bottom());
    return res = -1;
}

int execlp(const char *file, const char *arg0, ...) {
    sf_tocttou_access(file);
    sf_fun_does_not_update_vargs(2);
    // The exec() functions return only if an error has occurred.
    int res = -1;
    sf_set_errno_if(res, sf_top());
    sf_no_errno_if(res, sf_bottom());
    return res;
}

int execv(const char *path, char *const argv[]) {
    sf_tocttou_access(path);
    sf_set_trusted_sink_ptr(path);
    // The exec() functions return only if an error has occurred.
    int res = -1;
    sf_set_errno_if(res, sf_top());
    sf_no_errno_if(res, sf_bottom());
    return res;
}

int execve(const char *path, char *const argv[], char *const envp[]) {
    sf_tocttou_access(path);
    sf_set_trusted_sink_ptr(path);
    // The exec() functions return only if an error has occurred.
    int res = -1;
    sf_set_errno_if(res, sf_top());
    sf_no_errno_if(res, sf_bottom());
    return res;
}

int execvp(const char *file, char *const argv[]) {
    sf_tocttou_access(file);
    sf_set_trusted_sink_ptr(file);
    // The exec() functions return only if an error has occurred.
    int res = -1;
    sf_set_errno_if(res, sf_top());
    sf_no_errno_if(res, sf_bottom());
    return res;
}

void _exit(int rcode) {
    sf_terminate_path();
    // easiest way to suppress 'noreturn' warning in gcc-genmif
    _exit(rcode);
}

int fchown(int fd, uid_t owner, gid_t group) {
    sf_set_must_be_positive(fd);
    int x;
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range("==", 0));
    return x;
}

int fchdir(int fd) {
    sf_must_not_be_release(fd);
    sf_set_must_be_positive(fd);
    sf_lib_arg_type(fd, "FileHandlerCategory");
    int x;
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range("==", 0));
    return x;
}

//int          fdatasync(int);
pid_t fork(void) {
    pid_t x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range(">=", 0));
    sf_fork_by(x);
    return x;
}

long int fpathconf(int fd, int name) {
    sf_set_must_be_positive(fd);
    // If the system does not have a limit for the requested
    // resource, -1 is returned, and errno is unchanged.
    // Don't use sf_set_errno_if here!
}

int fsync(int fd) {
    sf_set_must_be_positive(fd);
    sf_lib_arg_type(fd, "FileHandlerCategory");
    int x;
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range("==", 0));
    return x;
}

int ftruncate(int fd, off_t length) {
    sf_set_must_be_positive(fd);
    sf_lib_arg_type(fd, "FileHandlerCategory");
    int x;
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range("==", 0));
    return x;
}

int ftruncate64(int fd, off_t length) {
    return ftruncate(fd, length);
}

char *getcwd(char *buf, size_t size) {
    if (size > 0) {
        char d1 = *buf;
        char d2 = buf[size-1];
    }
    sf_bitinit(buf);
    char *res;
    sf_overwrite(&res);
    sf_set_possible_null(res);
    sf_set_errno_if(res, sf_cond_range("==", 0));
    sf_password_set(buf);
    sf_password_set(res);
    return res;
}

/*
int          getdtablesize(void); (LEGACY)
int          getgroups(int, gid_t []);
long         gethostid(void);
char        *getlogin(void);
int          getlogin_r(char *, size_t);
int          getpagesize(void); (LEGACY)
char        *getpass(const char *); (LEGACY)
*/

extern char *optarg;
int getopt(int argc, char * const argv[], const char *optstring) {
    if (argc > 0) {
        char *c1 = argv[0];
	char *c2 = argv[argc - 1];
	char c3 = *optstring;
    }
    int ret;
    sf_overwrite(&ret);
    sf_set_possible_negative(ret);
    sf_overwrite(&optarg);
    sf_set_possible_null(optarg);
    // The value of errno after getopt() is unspecified
    return ret;
}

pid_t getpid(void) {
    pid_t x;
    sf_overwrite(&x);
    sf_password_set(x);
    return x;
}

pid_t getppid(void) {
    pid_t x;
    sf_overwrite(&x);
    return x;
}

pid_t getsid(pid_t pid) {
    pid_t x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range(">=", 0));
    return x;
}

uid_t getuid(void) {
    uid_t x;
    sf_overwrite(&x);
    return x;
}

uid_t geteuid(void) {
    uid_t x;
    sf_overwrite(&x);
    return x;
}

gid_t getgid(void) {
    gid_t x;
    sf_overwrite(&x);
    return x;
}

gid_t getegid(void) {
    gid_t x;
    sf_overwrite(&x);
    return x;
}

pid_t getpgid(pid_t pid) {
    pid_t x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    sf_set_must_be_positive(pid);
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range(">=", 0));
    return x;
}

pid_t getpgrp(/*'void' or 'int pid'*/) {
    pid_t x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    return x;
}

char *getwd(char *buf) {
    char *res;
    sf_bitinit(buf);
    sf_overwrite(&res);
    sf_set_possible_null(res);
    sf_set_errno_if(res, sf_cond_range("==", 0));
    return res;
}

//int          isatty(int);


int lchown(const char *fname, int uid, int gid) {
    sf_tocttou_access(fname);
    sf_set_trusted_sink_ptr(fname);
    int x;
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range("==", 0));
    return x;
}

int link(const char *path1, const char *path2) {
    sf_tocttou_access(path1);
    sf_tocttou_access(path2);

    sf_set_trusted_sink_ptr(path1);
    sf_set_trusted_sink_ptr(path2);
    int x;
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range("==", 0));
    return x;
}

// int          lockf(int, int, off_t);

off_t lseek(int fildes, off_t offset, int whence) {
    sf_must_not_be_release(fildes);
    sf_set_must_be_positive(fildes);
    sf_lib_arg_type(fildes, "FileHandlerCategory");
    off_t x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range(">=", 0));
    return x;
}

off_t lseek64(int fildes, off_t offset, int whence) {
    return lseek(fildes, offset, whence);
}

// int          nice(int);

long int pathconf(const char *path, int name) {
    sf_tocttou_access(path);
    sf_set_trusted_sink_ptr(path);
    // Don't use sf_set_errno_if here!
}

//int          pause(void);
int pipe(int pipefd[2]) {
    int x, y, z;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    sf_overwrite(&y);
    pipefd[0] = y;
    sf_overwrite(&z);
    pipefd[1] = z;
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range("==", 0));
    return x;
}

int pipe2(int pipefd[2], int flags) {
    int x, y, z;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    sf_overwrite(&y);
    pipefd[0] = y;
    sf_overwrite(&z);
    pipefd[1] = z;
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range("==", 0));
    return x;
}

ssize_t pread(int fd, void *buf, size_t nbytes, off_t offset) {
    sf_bitinit(buf);
	sf_must_not_be_release(fd);
    sf_set_must_be_positive(fd);
    sf_lib_arg_type(fd, "StdioHandlerCategory");

    sf_set_possible_nnts(buf);
    sf_buf_size_limit(buf, nbytes);

    ssize_t x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    sf_uncontrolled_value(x);

    sf_assert_cond(x, "<=", nbytes);
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range(">=", 0));
    sf_buf_fill(x, buf);
    return x;
}

//int          pthread_atfork(void (*)(void), void (*)(void), void(*)(void));

ssize_t pwrite(int fd, const void *buf, size_t nbytes, off_t offset) {
    sf_use(buf);
	sf_must_not_be_release(fd);
    sf_set_must_be_positive(fd);
    sf_lib_arg_type(fd, "StdioHandlerCategory");
    sf_set_trusted_sink_int(nbytes);


    sf_buf_size_limit(buf, nbytes);
    sf_buf_size_limit_read(buf, nbytes);

    ssize_t x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    sf_assert_cond(x, "<=", nbytes);
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range(">=", 0));
    sf_buf_fill(x, buf);
    return x;
}

ssize_t read(int fd, void *buf, size_t nbytes) {
    sf_bitinit(buf);

	sf_must_not_be_release(fd);
    sf_set_must_be_positive(fd);
    sf_lib_arg_type(fd, "StdioHandlerCategory");

    sf_overwrite(buf);
    sf_set_tainted(buf);
    sf_set_possible_nnts(buf);
    sf_buf_size_limit(buf, nbytes);

    ssize_t x;
    sf_overwrite(&x);
    sf_read_res(x, buf);
    sf_set_possible_negative(x);
    sf_uncontrolled_value(x);
    sf_set_possible_equals(x, nbytes);

    sf_assert_cond(x, "<=", nbytes);
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range(">=", 0));
    sf_buf_fill(x, buf);
    return x;
}

ssize_t __read_chk(int fd, void *buf, size_t nbytes, size_t buflen) {
    sf_must_not_be_release(fd);
    sf_set_must_be_positive(fd);
    sf_lib_arg_type(fd, "StdioHandlerCategory");

    sf_overwrite(buf);
    sf_set_tainted(buf);
    sf_set_possible_nnts(buf);
    sf_buf_size_limit(buf, nbytes);

    ssize_t x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    sf_set_possible_equals(x, nbytes);
    sf_assert_cond(x, "<=", nbytes);
    sf_buf_fill(x, buf);
    return x;
}

int readlink(const char *path, char *buf, int buf_size) {
    sf_use(path);
    sf_bitinit(buf);
    sf_tocttou_check(path);
	sf_set_trusted_sink_ptr(path);

    sf_set_possible_nnts(buf);
    sf_buf_size_limit(buf, buf_size);

    int x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    sf_set_possible_equals(x, buf_size);
    sf_assert_cond(x, "<=", buf_size);
    sf_buf_fill(x, buf);
    return x;
}

int rmdir(const char *path) {
    sf_tocttou_access(path);
	sf_set_trusted_sink_ptr(path);
}


//void        *sbrk(intptr_t);

unsigned int sleep(unsigned int ms) {
	sf_long_time();
    sf_set_trusted_sink_int(ms);
}

//void         swab(const void *, void *, ssize_t);


int setgid(gid_t gid) {
    int x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    return x;
}

int setpgid(pid_t pid, pid_t pgid) {
    int x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    sf_set_must_be_positive(pid);
    sf_set_must_be_positive(pgid);
    return x;
}

pid_t setpgrp(/*'void' or 'pid_t pid, pid_t pgid'*/) {
    pid_t x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    return x;
}

pid_t setsid(void) {
    pid_t x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    return x;
}

int setuid(uid_t uid) {
    int x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    return x;
}

int setregid(gid_t rgid, gid_t egid) {
    int x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    return x;
}

int setreuid(uid_t ruid, uid_t euidt) {
    int x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    return x;
}

int symlink(const char *path1, const char *path2) {
    sf_tocttou_access(path1);
    sf_tocttou_access(path2);
}

// void         sync(void);
long int     sysconf(int name) {
    int x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    return x;    
}

// pid_t        tcgetpgrp(int fd);
// int          tcsetpgrp(int, pid_t);

int truncate(const char *fname, off_t off) {
    sf_tocttou_access(fname);
	sf_set_trusted_sink_ptr(fname);
	return ret_any();
}

int truncate64(const char *fname, off_t off) {
    return truncate(fname, off);
}

// char        *ttyname(int);
// int          ttyname_r(int, char *, size_t);
// useconds_t   ualarm(useconds_t, useconds_t);

int unlink(const char *path) {
    sf_tocttou_access(path);
	sf_set_trusted_sink_ptr(path);
}

int unlinkat(int dirfd, const char *path, int flags) {
    sf_tocttou_access(path);
	sf_set_trusted_sink_ptr(path);
}

int usleep(useconds_t s) {
	sf_long_time();
    sf_set_trusted_sink_int(s);
}

// pid_t        vfork(void);

ssize_t write(int fd, const void *buf, size_t nbytes) {
    if (nbytes != 0) {
	char ch = (*(const char*)buf);
    }

    sf_must_not_be_release(fd);
    sf_set_must_be_positive(fd);
    sf_lib_arg_type(fd, "StdioHandlerCategory");

    sf_set_trusted_sink_int(nbytes);
    sf_buf_size_limit(buf, nbytes);
    sf_buf_size_limit_read(buf, nbytes);

    ssize_t x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    sf_assert_cond(x, "<=", nbytes);
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range(">=", 0));
    return x;
}

int uselib(const char *library) {
    sf_tocttou_access(library);
	sf_set_trusted_sink_ptr(library);
}

char *mktemp(char *template) {
    sf_vulnerable_fun_temp("This function is susceptible to a race condition occurring between testing for a file's existence (in the function) and access to the file (later in user code), which allows malicious users to potentially access arbitrary files in the system. Use mkstemp(), mkstemps(), or mkdtemp() instead.");
}
