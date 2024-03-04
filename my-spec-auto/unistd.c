#include "specfunc.h"

static int ret_any();

int access(const char *fname, int flags);

 
 

int chdir(const char *fname);

int chroot(const char *fname);

int seteuid(uid_t euid);

int setegid(uid_t egid);

int sethostid(long hostid);

int chown(const char *fname, int uid, int gid);

 

int dup(int oldd);

int dup2(int oldd, int newdd);

int close(int fd);

 

int execl(const char *path, const char *arg0, ...);

int execle(const char *path, const char *arg0, ...);

int execlp(const char *file, const char *arg0, ...);

int execv(const char *path, char *const argv[]);

int execve(const char *path, char *const argv[], char *const envp[]);

int execvp(const char *file, char *const argv[]);

void _exit(int rcode);

int fchown(int fd, uid_t owner, gid_t group);

int fchdir(int fd);

 
pid_t fork(void);

long int fpathconf(int fd, int name);

int fsync(int fd);

int ftruncate(int fd, off_t length);

int ftruncate64(int fd, off_t length);

char *getcwd(char *buf, size_t size);

 

extern char *optarg;
int getopt(int argc, char * const argv[], const char *optstring);

pid_t getpid(void);

pid_t getppid(void);

pid_t getsid(pid_t pid);

uid_t getuid(void);

uid_t geteuid(void);

gid_t getgid(void);

gid_t getegid(void);

pid_t getpgid(pid_t pid);

pid_t getpgrp();

char *getwd(char *buf);

 


int lchown(const char *fname, int uid, int gid);

int link(const char *path1, const char *path2);

 

off_t lseek(int fildes, off_t offset, int whence);

off_t lseek64(int fildes, off_t offset, int whence);

 

long int pathconf(const char *path, int name);

 
int pipe(int pipefd[2]);

int pipe2(int pipefd[2], int flags);

ssize_t pread(int fd, void *buf, size_t nbytes, off_t offset);

 

ssize_t pwrite(int fd, const void *buf, size_t nbytes, off_t offset);

ssize_t read(int fd, void *buf, size_t nbytes);

ssize_t __read_chk(int fd, void *buf, size_t nbytes, size_t buflen);

int readlink(const char *path, char *buf, int buf_size);

int rmdir(const char *path);


 

unsigned int sleep(unsigned int ms);

 


int setgid(gid_t gid);

int setpgid(pid_t pid, pid_t pgid);

pid_t setpgrp();

pid_t setsid(void);

int setuid(uid_t uid);

int setregid(gid_t rgid, gid_t egid);

int setreuid(uid_t ruid, uid_t euidt);

int symlink(const char *path1, const char *path2);

 
long int     sysconf(int name);

 
 

int truncate(const char *fname, off_t off);

int truncate64(const char *fname, off_t off);

 
 
 

int unlink(const char *path);

int unlinkat(int dirfd, const char *path, int flags);

int usleep(useconds_t s);

 

ssize_t write(int fd, const void *buf, size_t nbytes);

int uselib(const char *library);

char *mktemp(char *template);
