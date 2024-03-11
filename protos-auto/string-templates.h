#include "specfunc.h"
#include <stdarg.h>

extern "C" ;  


namespace ;  


#define memcmp_body(type) if (num > 0);\
                           sf_set_trusted_sink_int(num); \
                           sf_buf_size_limit(ptr1, num);\
                           sf_buf_size_limit(ptr2, num);\
                           sf_buf_size_limit_read(ptr1, num);\
                           sf_buf_size_limit_read(ptr2, num);\
                           int res;\
                           sf_overwrite(&res);\
                           sf_strncmp(res, ptr1, ptr2, num);\
                           return res;\

#define memcpy_body(type) if (num > 0);\
                           sf_set_trusted_sink_int(num); \
                           sf_bitinit(dst);\
                           sf_bitcopy(dst, src);\
                           sf_set_trusted_sink_int(num);\
                           sf_transfer_tainted(dst, (void *)src, num);\
                           sf_buf_copy(dst, src);\
                           sf_buf_overlap(dst, src);\
                           sf_buf_size_limit(src, num);\
                           sf_buf_size_limit_read(src, num);\
                           return dst;\

template <typename T>
int strcmp_body(const T *s1, const T *s2);

template <typename T>
int strncmp_body(const T *s1, const T *s2, size_t count);

template <typename T1, typename T2>
T1 *strchr_body(const T1 *s, T2 c);

template<typename T>
size_t str_scan_body(const T *s, const T *charset);

template <typename T1, typename T2, typename T3>
T2 *memset_body(T2 *ptr, T3 value, size_t num);

template<typename T1, typename T2>
T2 *memmove_body(T2 *dst, const T2 *src, size_t num);

template<typename T>
T *strstr_body(const T *big, const T *little);

