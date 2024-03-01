#include "specfunc.h"

char *basename(char *path) {
    sf_tocttou_access(path);
}

char *dirname(char *path) {
    sf_tocttou_access(path);
}
