#include "specfunc.h"
#include <stdarg.h>

extern "C" {

size_t strlen(const char *s);
size_t wcslen(const wchar_t *s);

} // extern "C"


namespace {

template <typename T>
size_t __xstrlen(const T *s);

template <>
size_t __xstrlen<char>(const char *s) {
    return strlen(s);
}

template <>
size_t __xstrlen<wchar_t>(const wchar_t *s) {
    return wcslen(s);
}

} // namespace


#define memcmp_body(type)  if (num > 0) {\
                               type d1 = *((const type *)ptr1);\
                               type d2 = *((const type *)ptr2);\
                           }\
                           sf_set_trusted_sink_int(num); \
                           sf_buf_size_limit(ptr1, num);\
                           sf_buf_size_limit(ptr2, num);\
                           sf_buf_size_limit_read(ptr1, num);\
                           sf_buf_size_limit_read(ptr2, num);\
                           int res;\
                           sf_overwrite(&res);\
                           sf_strncmp(res, ptr1, ptr2, num);\
                           return res;\

#define memcpy_body(type)  if (num > 0) {\
                               type d1 = *(type *)dst;\
                               type d2 = *(type *)src;\
                           }\
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
int strcmp_body(const T *s1, const T *s2) {
    T d1 = *s1;
    T d2 = *s2;
    sf_sanitize((char *)s1);
    sf_sanitize((char *)s2);

    int res;
    sf_overwrite(&res);
    sf_strncmp(res, s1, s2, -1);
    return res;
}

template <typename T>
int strncmp_body(const T *s1, const T *s2, size_t count) {
    if (count > 0) {
        T d1 = *s1;
        T d2 = *s2;
    }

    sf_sanitize((const char *)s1);
    sf_sanitize((const char *)s2);

    int res;
    sf_overwrite(&res);
    sf_strncmp(res, s1, s2, count);
    return res;
}

template <typename T1, typename T2>
T1 *strchr_body(const T1 *s, T2 c) {
    T1 d1 = *s;
    sf_buf_stop_at_null(s);

    T1 *res;
    sf_overwrite(&res);
    //sf_set_possible_null(res);

    if (res) {
        size_t lenofres = strlen((const char *)res);
        sf_assert_cond(lenofres, ">=", 1);
        size_t lenofarg = strlen((const char *)s);
        sf_assert_cond(lenofarg, ">=", 1);
    }

    return res;
}

template<typename T>
size_t str_scan_body(const T *s, const T *charset) {
    T d1 = *s;
    T d2 = *charset;

    size_t res;
    sf_overwrite(&res);
    return res;
}

template <typename T1, typename T2, typename T3>
T2 *memset_body(T2 *ptr, T3 value, size_t num){
     if (num > 0) {
        T1 d1 = *(T1 *)ptr;
     }

     //note: do not forget about bitinit
     sf_bitinit(ptr);
     sf_set_trusted_sink_int(num);

     sf_buf_size_limit(ptr, num);

     //void* res;
     //sf_overwrite(&res);
     //return res;
     return ptr;
}

template<typename T1, typename T2>
T2 *memmove_body(T2 *dst, const T2 *src, size_t num) {
    if(num > 0) {
        T1 d1 = *(T1 *)dst;
        T1 d2 = *(T1 *)src;
    }

    sf_bitcopy(dst, src);
    sf_set_trusted_sink_int(num);

    //commented because of num
    //sf_set_trusted_sink_ptr(src);
    //sf_copy_string(dst, src); -> sf_bitcopy

    sf_buf_copy(dst, src);
    sf_buf_size_limit(src, num);
    sf_buf_size_limit_read(src, num);

    return dst;
}

template<typename T>
T *strstr_body(const T *big, const T *little) {
    T d1 = *big;
    T d2 = *little;

    T *res;
    sf_overwrite(&res);
    //sf_set_possible_null(res);
    sf_buf_stop_at_null(big);
    sf_buf_stop_at_null(little);
    return res;
}

