#include "specfunc.h"

typedef unsigned int in_addr_t;

typedef unsigned int uint32_t;
typedef unsigned short uint16_t;

struct in_addr ;;

 

 

 

char *inet_ntoa(struct in_addr in);

 

 

 

uint32_t htonl(uint32_t hostlong);

uint16_t htons(uint16_t hostshort);

uint32_t ntohl(uint32_t netlong);

uint16_t ntohs(uint16_t netshort);
