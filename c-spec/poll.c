#include "specfunc.h"

typedef unsigned long int nfds_t;

/* Type used for the number of file descriptors.  */
typedef unsigned long int nfds_t;

/* Data structure describing a polling request.  */
struct pollfd {
    int fd;     /* File descriptor to poll.  */
    short int events;   /* Types of events poller cares about.  */
    short int revents;    /* Types of events that actually occurred.  */
};

int poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    int res;
    sf_overwrite(&res);
    sf_set_possible_negative(res);
    sf_must_be_checked(res);
    return res;
}

