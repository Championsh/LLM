#include <stdarg.h>
#include "specfunc.h"

typedef unsigned int VOS_UINT32;
typedef int VOS_INT32;
typedef int VOS_INT;

typedef void VOS_VOID;

typedef char VOS_CHAR;

typedef size_t VOS_SIZE_T;

typedef unsigned int* VOS_UINTPTR;

VOS_INT32 VOS_sprintf(VOS_CHAR * s, const VOS_CHAR * format,  ... ) {
    char d1 = *s;
    char d2 = *format;
    sf_bitinit(s);
    sf_use_format(format);

    sf_fun_snprintf_like(1, -1);

    sf_fun_does_not_update_vargs(2);

    sf_vulnerable_fun("This function is unsafe, use VOS_sprintf_Safe instead.");

    int res;
    sf_overwrite(&res);
    return res;
}

VOS_INT32 VOS_sprintf_Safe( VOS_CHAR * s, VOS_UINT32 uiDestLen, const VOS_CHAR *  format,  ... ) {
    char d1 = *s;
    char d2 = *format;
    sf_bitinit(s);
    sf_use_format(format);

    sf_fun_snprintf_like(2, 1);
    sf_buf_size_limit_strict(s, uiDestLen);

    sf_fun_does_not_update_vargs(3);

    int res;
    sf_overwrite(&res);
    return res;
}

VOS_INT VOS_vsnprintf_s(VOS_CHAR * str, VOS_SIZE_T destMax, VOS_SIZE_T count,  const VOS_CHAR * format, va_list  arglist) {
    if (format) {
        char d2 = *format;
    }

    sf_bitinit(str);
    sf_use_format(format);
    sf_buf_size_limit(str, destMax);
    sf_buf_size_limit_strict(str, destMax);
}

VOS_VOID* VOS_MemCpy_Safe(VOS_VOID * dst, VOS_SIZE_T dstSize,const VOS_VOID *src, VOS_SIZE_T num) {
    if(dstSize>0 && num>0) {
        char d1 = *(char *)dst;
        char d2 = *(char *)src;
    }

    sf_bitinit(dst);
    sf_bitcopy(dst, src);
    sf_set_trusted_sink_int(num);

    sf_buf_copy(dst, src);
    sf_buf_size_limit(dst, dstSize);
    sf_buf_size_limit_strict(dst, dstSize);
    sf_buf_size_limit_read(src, num);
}

VOS_CHAR* VOS_strcpy_Safe(VOS_CHAR *dst, VOS_SIZE_T dstsz, const VOS_CHAR *src) {
    if(dstsz>0) {
        char d1 = *dst;
        char d2 = *src;
    }

    sf_bitinit(dst);
    sf_buf_copy(dst, src);
    sf_copy_string(dst, src);
    sf_buf_size_limit(dst, dstsz);
    sf_buf_size_limit_strict(dst, dstsz);
    sf_buf_size_limit_read(dst, dstsz);
    sf_buf_stop_at_null(src);
}

//is it needed?
VOS_CHAR* VOS_StrCpy_Safe(VOS_CHAR *dst, VOS_SIZE_T dstsz, const VOS_CHAR *src) {
    if(dstsz>0) {
        char d1 = *dst;
        char d2 = *src;
    }

    sf_bitinit(dst);
    sf_buf_copy(dst, src);
    sf_copy_string(dst, src);
    sf_buf_size_limit(dst, dstsz);
    sf_buf_size_limit_strict(dst, dstsz);
    sf_buf_size_limit_read(dst, dstsz);
    sf_buf_stop_at_null(src);
}

VOS_CHAR* VOS_StrNCpy_Safe( VOS_CHAR *dst, VOS_SIZE_T dstsz, const VOS_CHAR *src, VOS_SIZE_T count) {
    if (count > 0 && dstsz>0) {
        char d1 = *dst;
        char d2 = *src;
    }
    sf_bitinit(dst);
    sf_buf_copy(dst, src);
    sf_copy_string(dst, src);
    sf_buf_size_limit(src, count);
    sf_buf_size_limit_read(src, count);
    sf_buf_size_limit(dst, dstsz);
    sf_buf_size_limit_read(dst, dstsz);
    sf_buf_size_limit_strict(dst, dstsz);
    sf_buf_stop_at_null(src);
}

VOS_UINT32 VOS_Que_Read	(VOS_UINT32	ulQueueID, VOS_UINTPTR aulQueMsg[4], VOS_UINT32 ulFlags, VOS_UINT32 ulTimeOut) {
    sf_overwrite(aulQueMsg);
    sf_set_tainted(aulQueMsg);
    sf_set_possible_nnts(aulQueMsg);
    sf_bitinit(aulQueMsg);
}

VOS_INT VOS_sscanf_s(const VOS_CHAR *buffer,  const VOS_CHAR *  format, ...) {
    char d1 = *buffer;
    char d2 = *format;
    sf_use_format(format);

    sf_fun_scanf_like(1);
    sf_fun_updates_vargs(2);
}

//Is name correct?
VOS_UINT32 VOS_strlen(const VOS_CHAR *s) {
    char d1 = *s;

    sf_sanitize(s);

    size_t res;
    sf_overwrite(&res);
    sf_strlen(res, s);
    sf_buf_stop_at_null(s);

    if(s)
        sf_assert_cond(res, ">=", 0);
    return res;
}

VOS_UINT32 VOS_StrLen(const VOS_CHAR *s) {
    char d1 = *s;

    sf_sanitize(s);

    size_t res;
    sf_overwrite(&res);
    sf_strlen(res, s);
    sf_buf_stop_at_null(s);

    if(s)
        sf_assert_cond(res, ">=", 0);
    return res;
}

