#include "specfunc.h"

void error(int status, int errnum, const char *fmt, ...) {
    sf_use_format(fmt);

    if(status>0)
        sf_terminate_path();

    //I don't think we find this in real projects.
    //if(status<0)
    //    sf_terminate_path();
}
