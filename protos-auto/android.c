#include "specfunc.h"

 
void Oem_Debug_Assert(int expression, char *f_assertcmd, char* f_file, int line)
;

void checkDevParam(const char *assert, int v1, int v2, int v3, const char *file, int line)
;

typedef enum DevAssertFailTypeTag
; DevAssertFailType;

void assertfail(DevAssertFailType assertFailType, const char *cond, const char *file, int line)
;

void utilsAssertFail(const char *cond, const char *file, signed short line, unsigned char allowDiag)
;

