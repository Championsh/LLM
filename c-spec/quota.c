#include "specfunc.h"

long quotactl(int cmd, char *spec, int id, caddr_t addr) {
    sf_tocttou_access(spec);
}
