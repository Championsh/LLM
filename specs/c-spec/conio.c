#include "specfunc.h"

int getch(void) {
    int tainted_res;
    sf_overwrite(&tainted_res);
    sf_set_tainted_int(tainted_res);
    sf_uncontrolled_value(tainted_res);
    return tainted_res;    
}

int _getch(void) {
    int tainted_res;
    sf_overwrite(&tainted_res);
    sf_set_tainted_int(tainted_res);
    sf_uncontrolled_value(tainted_res);
    return tainted_res;
}
