#include "specfunc.h"

typedef unsigned char u_int8_t;
typedef unsigned short int sa_family_t;

struct sockaddr ;;


int connect(int sockfd, const struct sockaddr *addr, socklen_t len);

 

int getpeername(int sockfd, struct sockaddr *addr, socklen_t
       *addrlen) ;

int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

int getsockopt(int sockfd, int level, int optname,
                      void *optval, socklen_t *optlen);

int listen(int sockfd, int backlog);


int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

ssize_t recv(int s, void *buf, size_t len, int flags);

ssize_t recvfrom(int s, void *buf, size_t len, int flags,
                 struct sockaddr *from, socklen_t *fromlen);

ssize_t __recvfrom_chk(int s, void *buf, size_t len, size_t buflen, int flags,
                 struct sockaddr *from, socklen_t *fromlen);

ssize_t recvmsg(int s, struct msghdr *msg, int flags);

ssize_t send(int s, const void *buf, size_t len, int flags);

ssize_t sendto(int s, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);

ssize_t sendmsg(int s, const struct msghdr*msg, int flags);

int setsockopt(int socket, int level, int option_name,
       const void *option_value, socklen_t option_len);

int shutdown(int socket, int how);

int socket(int domain, int type, int protocol);

 

