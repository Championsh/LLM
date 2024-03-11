int lua_dump(lua_State *L, lua_Writer writer, void *data, int strip);
int lua_equal(lua_State *L, int index1, int index2);
int lua_error(lua_State *L);
int lua_gc(lua_State *L, int what, int data);
lua_Alloc lua_getallocf(lua_State *L, void **ud);
int lua_getfenv(lua_State *L, int index);
const char *lua_getfield(lua_State *L, int index, const char *k);