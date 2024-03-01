#include "specfunc.h"

struct lua_State;

int luaL_error(struct lua_State *L, const char *fmt, ...) {
    sf_terminate_path();

    int res;
    sf_overwrite(&res);
    return res;    
}
