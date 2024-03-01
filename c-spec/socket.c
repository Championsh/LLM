#include "specfunc.h"

typedef unsigned char u_int8_t;
typedef unsigned short int sa_family_t;

struct sockaddr {
    u_int8_t    sa_len;         /* total length */
    sa_family_t sa_family;      /* address family */
    char        sa_data[14];    /* actually longer; address value */
};


int connect(int sockfd, const struct sockaddr *addr, socklen_t len) {
	sf_set_must_be_positive(sockfd);
	sf_lib_arg_type(sockfd, "SocketCategory");

	int res;
    sf_overwrite(&res);
    sf_set_possible_negative(res);
    sf_uncontrolled_value(res);
    
    return res;
}

//int getpeereid(int, uid_t *, gid_t *);

int getpeername(int sockfd, struct sockaddr *addr, socklen_t
       *addrlen)  {
	sf_must_not_be_release(sockfd);
    sf_set_must_be_positive(sockfd);
    sf_lib_arg_type(sockfd, "SocketCategory");

	int res;
    sf_overwrite(&res);
	sf_set_possible_negative(res);
		
    return res;
}

int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  sf_bitinit(addr);
	sf_must_not_be_release(sockfd);
    sf_set_must_be_positive(sockfd);
    sf_lib_arg_type(sockfd, "SocketCategory");

	int res;
    sf_overwrite(&res);
	sf_set_possible_negative(res);
	
    return res;
}

int getsockopt(int sockfd, int level, int optname,
                      void *optval, socklen_t *optlen) {
  sf_bitinit(optval);
	sf_must_not_be_release(sockfd);
    sf_set_must_be_positive(sockfd);
    sf_lib_arg_type(sockfd, "SocketCategory");

	int res;
    sf_overwrite(&res);
	sf_set_possible_negative(res);
	
    return res;
}

int listen(int sockfd, int backlog) {
	sf_long_time();

	sf_must_not_be_release(sockfd);
    sf_set_must_be_positive(sockfd);
    sf_lib_arg_type(sockfd, "SocketCategory");

	int res;
    sf_overwrite(&res);
	sf_set_possible_negative(res);
    sf_uncontrolled_value(res);
   
    return res;
}


int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    // mark setting of the whole buffer
    if(addr) {
        ((char *)addr)[*addrlen - 1] = 0;
    }

	sf_long_time();

    sf_overwrite(addrlen);
    sf_overwrite(addr);

    sf_must_not_be_release(sockfd);
    sf_set_must_be_positive(sockfd);
    sf_lib_arg_type(sockfd, "SocketCategory");

	int res;
    sf_overwrite(&res);
	sf_overwrite_int_as_ptr(res);
    sf_handle_acquire_int_as_ptr(res, SOCKET_CATEGORY);
	sf_set_possible_negative(res);
	sf_uncontrolled_value(res);
	sf_not_acquire_if_less_int_as_ptr(res, res, 1);

    return res;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    char d = *((char*)addr);
    // mark read of the last byte of the structure
    if(addr) {
        char c = ((char *)addr)[addrlen - 1];
    }

    sf_must_not_be_release(sockfd);
    sf_set_must_be_positive(sockfd);
    sf_lib_arg_type(sockfd, "SocketCategory");

	int res;
    sf_overwrite(&res);
    sf_set_possible_negative(res);
    sf_uncontrolled_value(res);

    return res;
}

ssize_t recv(int s, void *buf, size_t len, int flags) {
	sf_must_not_be_release(s);
    sf_set_must_be_positive(s);
    sf_lib_arg_type(s, "SocketCategory");

    sf_overwrite(buf);
    sf_set_tainted(buf);
    sf_set_tainted_buf(buf, len, 0);
    sf_set_possible_nnts(buf);
    sf_bitinit(buf);

    ssize_t res;
    sf_overwrite(&res);
    sf_set_possible_negative(res);
    sf_uncontrolled_value(res);
    sf_buf_size_limit(buf, len);
    sf_buf_fill(res, buf);

    sf_assert_cond(res, "<=", len);
    
    return res;
}

ssize_t recvfrom(int s, void *buf, size_t len, int flags,
                 struct sockaddr *from, socklen_t *fromlen) {

    sf_bitinit(from);
    if(from!=0) {
        // sf_bitinit(from); TODO: make sf_bitinit work here for UNINIT.STRUCT
        socklen_t d1 = *fromlen;
    }

    sf_must_not_be_release(s);
    sf_set_must_be_positive(s);
    sf_lib_arg_type(s, "SocketCategory");

    sf_overwrite(buf);
    sf_set_tainted(buf);
    sf_set_tainted_buf(buf, len, 0);
    sf_set_possible_nnts(buf);
    sf_bitinit(buf);

    sf_buf_size_limit(buf, len);

    ssize_t res;
    sf_overwrite(&res);
    sf_set_possible_negative(res);
    sf_uncontrolled_value(res);
    sf_buf_fill(res, buf);
    sf_assert_cond(res, "<=", len);
    
    return res;
}

ssize_t __recvfrom_chk(int s, void *buf, size_t len, size_t buflen, int flags,
                 struct sockaddr *from, socklen_t *fromlen) {
  sf_bitinit(from);
	socklen_t d1 = *fromlen;

	sf_must_not_be_release(s);
    sf_set_must_be_positive(s);
    sf_lib_arg_type(s, "SocketCategory");

    sf_overwrite(buf);
    sf_set_tainted(buf);
    sf_set_tainted_buf(buf, len, 0);
    sf_set_possible_nnts(buf);
    sf_bitinit(buf);

	sf_buf_size_limit(buf, len);

	ssize_t res;
	sf_overwrite(&res);
    sf_buf_fill(res, buf);
	sf_set_possible_negative(res);
	return res;
}

ssize_t recvmsg(int s, struct msghdr *msg, int flags) {
  sf_deepinit(msg);
	sf_must_not_be_release(s);
    sf_set_must_be_positive(s);
    sf_lib_arg_type(s, "SocketCategory");

	ssize_t res;
    sf_overwrite(&res);
    sf_buf_fill(res, msg);
	sf_set_possible_negative(res);
	return res;
}

ssize_t send(int s, const void *buf, size_t len, int flags) {
	sf_must_not_be_release(s);
    sf_set_must_be_positive(s);
    sf_lib_arg_type(s, "SocketCategory");
    
    sf_buf_size_limit(buf, len);
    sf_buf_size_limit_read(buf, len);
    
	ssize_t res;
	sf_overwrite(&res);
	sf_set_possible_negative(res);
    sf_uncontrolled_value(res);
	return res;
}

ssize_t sendto(int s, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
	sf_must_not_be_release(s);
    sf_set_must_be_positive(s);
    sf_lib_arg_type(s, "SocketCategory");
    
    sf_buf_size_limit(buf, len);
    sf_buf_size_limit_read(buf, len);

	ssize_t res;
	sf_overwrite(&res);
	sf_set_possible_negative(res);
	return res;
}

ssize_t sendmsg(int s, const struct msghdr*msg, int flags) {
	sf_must_not_be_release(s);
    sf_set_must_be_positive(s);
    sf_lib_arg_type(s, "SocketCategory");

	ssize_t res;
	sf_overwrite(&res);
	sf_set_possible_negative(res);
	return res;
}

int setsockopt(int socket, int level, int option_name,
       const void *option_value, socklen_t option_len) {
	sf_must_not_be_release(socket);
    sf_set_must_be_positive(socket);
    sf_lib_arg_type(socket, "SocketCategory");

	int res;
  sf_use(option_value);
	sf_overwrite(&res);
	sf_set_possible_negative(res);
	return res;
}

int shutdown(int socket, int how) {
	sf_must_not_be_release(socket);
    sf_set_must_be_positive(socket);
    sf_lib_arg_type(socket, "SocketCategory");

	//note: shutdown doesn't release a socked. It only cloase connection but function close still should be called.
	//sf_handle_release(socket, SOCKET_CATEGORY);
	
}

int socket(int domain, int type, int protocol) {
	int res;
    sf_overwrite(&res);
	sf_overwrite_int_as_ptr(res);
    sf_handle_acquire_int_as_ptr(res, SOCKET_CATEGORY);
	sf_not_acquire_if_less_int_as_ptr(res, res, 1);
	sf_set_possible_negative(res);
    sf_uncontrolled_value(res);
    sf_set_errno_if(res, sf_cond_range("==", -1));
    sf_no_errno_if(res, sf_cond_range(">=", 0));
    sf_lib_arg_type(res, "SocketCategory");
    return res;
}

//int    socketpair(int, int, int, int *);

