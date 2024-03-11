#include "specfunc.h"

typedef wchar_t OLECHAR;
typedef OLECHAR* BSTR;
typedef const char* LPCSTR;

BSTR SysAllocString(const OLECHAR *psz);

BSTR SysAllocStringByteLen(LPCSTR psz, unsigned int len);

BSTR SysAllocStringLen(const OLECHAR *pch, unsigned int len);

int SysReAllocString(BSTR *pbstr, const OLECHAR *psz);

int SysReAllocStringLen(BSTR *pbstr, const OLECHAR *psz, unsigned int len);

void SysFreeString(BSTR bstrString);

unsigned int SysStringLen(BSTR bstr);
