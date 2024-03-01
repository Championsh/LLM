#include "specfunc.h"

typedef unsigned int in_addr_t;

typedef unsigned int uint32_t;
typedef unsigned short uint16_t;

struct in_addr {
    in_addr_t s_addr;
};

//int inet_aton(const char *cp, struct in_addr *inp);

//in_addr_t inet_addr(const char *cp);

//in_addr_t inet_network(const char *cp);

char *inet_ntoa(struct in_addr in) {
    char *res;
    sf_overwrite(&res);
    //"0.0.0.0" - 7
    //"255.255.255.255" - 15
    sf_string_size_limit(res, 7, 15);
    sf_password_set(res);
    return res;
}

//struct in_addr inet_makeaddr(int net, int host);

//in_addr_t inet_lnaof(struct in_addr in);

//in_addr_t inet_netof(struct in_addr in);

uint32_t htonl(uint32_t hostlong) {
    int res;
    sf_overwrite(&res);
    sf_set_tainted_int(res);
    return (uint32_t)res;
}

uint16_t htons(uint16_t hostshort) {
    int res;
    sf_overwrite(&res);
    sf_set_tainted_int(res);
    return (uint16_t)res;
}

uint32_t ntohl(uint32_t netlong) {
    int res;
    sf_overwrite(&res);
    sf_set_tainted_int(res);
    return (uint32_t)res;
}

uint16_t ntohs(uint16_t netshort) {
    int res;
    sf_overwrite(&res);
    sf_set_tainted_int(res);
    sf_password_set(res);
    return (uint16_t)res;
}
