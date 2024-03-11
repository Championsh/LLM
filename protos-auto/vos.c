#include <stdarg.h>
#include "specfunc.h"

typedef unsigned int VOS_UINT32;
typedef int VOS_INT32;
typedef int VOS_INT;

typedef void VOS_VOID;

typedef char VOS_CHAR;

typedef size_t VOS_SIZE_T;

typedef unsigned int* VOS_UINTPTR;

VOS_INT32 VOS_sprintf(VOS_CHAR * s, const VOS_CHAR * format,  ... );

VOS_INT32 VOS_sprintf_Safe(VOS_CHAR * s, VOS_UINT32 uiDestLen, const VOS_CHAR *  format,  ... );

VOS_INT VOS_vsnprintf_s(VOS_CHAR * str, VOS_SIZE_T destMax, VOS_SIZE_T count,  const VOS_CHAR * format, va_list  arglist);

VOS_VOID* VOS_MemCpy_Safe(VOS_VOID * dst, VOS_SIZE_T dstSize,const VOS_VOID *src, VOS_SIZE_T num);

VOS_CHAR* VOS_strcpy_Safe(VOS_CHAR *dst, VOS_SIZE_T dstsz, const VOS_CHAR *src);

 
VOS_CHAR* VOS_StrCpy_Safe(VOS_CHAR *dst, VOS_SIZE_T dstsz, const VOS_CHAR *src);

VOS_CHAR* VOS_StrNCpy_Safe(VOS_CHAR *dst, VOS_SIZE_T dstsz, const VOS_CHAR *src, VOS_SIZE_T count);

VOS_UINT32 VOS_Que_Read	(VOS_UINT32	ulQueueID, VOS_UINTPTR aulQueMsg[4], VOS_UINT32 ulFlags, VOS_UINT32 ulTimeOut);

VOS_INT VOS_sscanf_s(const VOS_CHAR *buffer,  const VOS_CHAR *  format, ...);

 
VOS_UINT32 VOS_strlen(const VOS_CHAR *s);

VOS_UINT32 VOS_StrLen(const VOS_CHAR *s);

