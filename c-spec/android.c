#include "specfunc.h"

/* TODO */
void Oem_Debug_Assert(int expression, char *f_assertcmd, char* f_file, int line)
{
    if (!expression)
	sf_terminate_path();
}

void checkDevParam(const char *assert, int v1, int v2, int v3, const char *file, int line)
{
    sf_terminate_path();
}

typedef enum DevAssertFailTypeTag
{
    DAF_TYPE_ASSERT_LONG,
    DAF_TYPE_ASSERT_SHORT,
    DAF_TYPE_FAIL_LONG,
    DAF_TYPE_FAIL_SHORT
} DevAssertFailType;

void assertfail(DevAssertFailType assertFailType, const char *cond, const char *file, int line)
{
    sf_terminate_path();
}

void utilsAssertFail(const char *cond, const char *file, signed short line, unsigned char allowDiag)
{
    sf_terminate_path();
}

