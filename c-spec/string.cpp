#include "specfunc.h"
#include "string-templates.h"

static int ret_any() {
    int x;
    sf_overwrite(&x);
    return x;
}

const char *str_strcpy;
typedef int errno_t;

typedef size_t rsize_t;

extern "C"{

char *strcat(char *s, const char *append) {
    char d1 = *s;
    char d2 = *append;
    sf_set_trusted_sink_ptr(s);
    sf_set_trusted_sink_ptr(append);
    sf_append_string((char *)s, (const char *)append);
    sf_vulnerable_fun("This function is unsafe, use strncat instead.");
    sf_null_terminated((char *)s);
    sf_buf_overlap(s, append);
    return s;
}

char *__strcat_chk(char *s, const char *append, size_t destlen) {
    if (destlen > 0) {
        char d1 = *s;
        char d2 = *append;
    }
    sf_set_trusted_sink_int(destlen);
    sf_set_trusted_sink_ptr(s);
    sf_set_trusted_sink_ptr(append);
    sf_append_string(s, append);
    sf_null_terminated(s);
    //note: it's safe version of strcat.
    return s;
}

char *strncat(char *s, const char *append, size_t count) {
    char d1 = *s;
    if (count > 0) {
        char d2 = *append;
    }

    sf_set_trusted_sink_int(count);
    sf_buf_copy(s, append);
    sf_append_string(s, append);
    sf_buf_size_limit(append, count);
    sf_buf_size_limit_read(append, count);
    sf_buf_stop_at_null(append);
    sf_null_terminated(s);
    sf_buf_overlap(s, append);

    return s;
}

size_t strlcat(char *dst, const char *append, size_t dstsize) {
    int newlen;
    if (dstsize > 0) {
        char d1 = *dst;
        char d2 = *append;
    }
    sf_set_trusted_sink_int(dstsize);
    //newlen = strlen(s) + strlen(append);
    sf_overwrite(&newlen);
    //sf_append_string(dst, append);
    sf_null_terminated(dst);
    sf_buf_overlap(dst, append);
    return newlen;
}

char *strchr(const char *s, int c) {
    return strchr_body<char, int>(s, c);
}

char *strrchr(const char *s, int c) {
    return strchr_body<char, int>(s, c);
}

int strcmp(const char *s1, const char *s2) {
    return strcmp_body<char>(s1, s2);
}

int strncmp(const char *s1, const char *s2, size_t count) {
    return strncmp_body<char>(s1, s2, count);
}

int memcmp(const void *ptr1, const void *ptr2, size_t num) {
    memcmp_body(char);
}

int strcasecmp(const char *s1, const char *s2) {
    char d1 = *s1;
    char d2 = *s2;

    sf_sanitize(s1);
    sf_sanitize(s2);

    int res;
    sf_overwrite(&res);
    sf_strncmp(res, s1, s2, -1);
    return res;
}

int strncasecmp(const char *s1, const char *s2, size_t count) {
    if (count > 0) {
        char d1 = *s1;
        char d2 = *s2;
    }

    sf_set_trusted_sink_int(count);

    sf_sanitize(s1);
    sf_sanitize(s2);

    int res;
    
    sf_overwrite(&res);
    sf_strncmp(res, s1, s2, count);
    return res;
}

char *strcpy(char *dst, const char *src) {
    char d1 = *dst;
    char d2 = *src;
    sf_bitinit(dst);
    sf_buf_copy(dst, src);
    sf_set_trusted_sink_ptr(src);
    sf_copy_string((char *)dst, (char *)src);
    sf_buf_stop_at_null(src);
    sf_vulnerable_fun("This function is unsafe, use strncpy instead.");
//    sf_null_terminated((char *)dst);
    sf_buf_overlap(dst, src);
    return dst;
}

char * __strcpy_chk(char *dst, const char *src, size_t dstlen) {
    if (dstlen > 0) {
        char d1 = *dst;
    }
    sf_set_trusted_sink_int(dstlen);
    char d2 = *src;
    sf_bitinit(dst);
    sf_set_trusted_sink_ptr(src);
    sf_copy_string(dst, src);
    sf_vulnerable_fun("This function is unsafe, use strncpy instead.");
    return dst;    
}

char *strncpy(char *dst, const char *src, size_t count) {
    if (count > 0) {
        char d1 = *dst;
        char d2 = *src;
    }
    sf_set_trusted_sink_int(count);
    sf_bitinit(dst);
    sf_buf_copy(dst, src);
    sf_copy_string(dst, src);
    sf_buf_size_limit(src, count);
    sf_buf_size_limit_read(src, count);
    sf_buf_stop_at_null(src);
    sf_buf_overlap(dst, src);
    return dst;
}

errno_t strcpy_s(char *dst, rsize_t dstsz, const char *src) {
    if(dstsz>0) {
        char d1 = *dst;
        char d2 = *src;
    }

    sf_set_trusted_sink_int(dstsz);
    sf_bitinit(dst);
    sf_buf_copy(dst, src);
    sf_copy_string(dst, src);
    sf_buf_size_limit_strict(dst, dstsz);
    sf_buf_size_limit_read(dst, dstsz);
    sf_buf_stop_at_null(src);
    sf_null_terminated(dst);
    return ret_any();
}

errno_t strncpy_s(char *dst, rsize_t dstsz,
                  const char *src, rsize_t count) {
    if (count > 0 && dstsz>0) {
        char d1 = *dst;
        char d2 = *src;
    }
    sf_set_trusted_sink_int(count);
    sf_set_trusted_sink_int(dstsz);
    sf_bitinit(dst);
    sf_buf_copy(dst, src);
    sf_copy_string(dst, src);
    sf_buf_size_limit(src, count);
    sf_buf_size_limit_read(src, count);
    sf_buf_size_limit_strict(dst, dstsz);
    sf_buf_size_limit_read(dst, dstsz);
    sf_buf_stop_at_null(src);
    sf_null_terminated(dst);
    return ret_any();
}

char * __strncpy_chk(char *dst, const char *src, size_t count, size_t dstlen) {
    if (count > 0) {
        if (dstlen > 0) {
            char d1 = *dst;
        }
        char d2 = *src;
    }
    sf_set_trusted_sink_int(count);
    sf_set_trusted_sink_int(dstlen);
    sf_bitinit(dst);
    sf_buf_copy(dst, src);
    sf_copy_string(dst, src);
    sf_buf_size_limit(src, count);
    sf_buf_size_limit_read(src, count);
    sf_buf_stop_at_null(src);
    return dst;
}

char * __strncpy_chk2(char *dst, const char *src, size_t count, size_t dstlen, size_t srclen) {
    if (count > 0) {
        if (dstlen > 0) {
            char d1 = *dst;
        }
        if (srclen > 0) {
            char d2 = *src;
        }
    }
    sf_set_trusted_sink_int(count);
    sf_set_trusted_sink_int(dstlen);
    sf_set_trusted_sink_int(srclen);
    sf_bitinit(dst);
    sf_buf_copy(dst, src);
    sf_copy_string(dst, src);
    sf_buf_size_limit(src, count);
    sf_buf_size_limit_read(src, count);
    sf_buf_stop_at_null(src);
    return dst;
}

size_t strlcpy(char *dst, const char *src, size_t dstsize) {
    size_t newlen;
    if (dstsize > 0) {
        char d1 = *dst;
        char d2 = *src;
    }
    sf_set_trusted_sink_int(dstsize);
    sf_bitinit(dst);
    //newlen = strlen(s) + strlen(append);
    sf_overwrite(&newlen);

    sf_buf_copy(dst, src);
    sf_copy_string(dst, src);
    sf_buf_size_limit(src, dstsize-1);
    sf_buf_size_limit_read(src, dstsize-1);
    sf_buf_stop_at_null(src);
    sf_null_terminated(dst);
    sf_buf_overlap(dst, src);
    return newlen;
}

//do not confuse with strcpy!!!
char *stpcpy(char *dst, const char *src) {
    char d1 = *dst;
    char d2 = *src;
    sf_bitinit(dst);
    sf_set_trusted_sink_ptr(src);
    sf_copy_string(dst, src);
    sf_null_terminated(dst);
    char* res;
    sf_overwrite(&res);
    sf_buf_overlap(dst, src);
    return res;
}

char *strerror(int errno) {
    sf_set_must_be_positive(errno);
    char *res;
    sf_overwrite(&res);
    return res;
}

size_t strlen(const char *s) {
    char d1 = *s;

    size_t res;
    sf_overwrite(&res);
    sf_strlen(res, (const char *)s);
    sf_buf_stop_at_null(s);

    sf_assert_cond(res, ">=", 0);
    return res;
}

size_t strnlen(const char *s, size_t maxlen) {
    if (maxlen > 0) {
        char d1 = *s;
    }

    sf_set_trusted_sink_int(maxlen);
    //sf_sanitize(s);

    size_t res;
    sf_overwrite(&res);

    sf_assert_cond(res, ">=", 0);
    sf_strlen(res, s);//?
    return res;
}

char *strpbrk(const char *s, const char *charset) {
    return (char *)str_scan_body<char>(s, charset);
}

char *strsep(char **stringp, const char *delim) {
    char d1 = *delim;
    int is_last;
    unsigned int shift;
    sf_overwrite(&is_last);
    sf_overwrite(&shift);
    if(is_last)
        return *stringp = 0;
    else
        return *stringp = *stringp + shift;
}

size_t strspn(const char *s, const char *charset) {
    return str_scan_body<char>(s, charset);
}

size_t strcspn(const char *s, const char *charset) {
    return str_scan_body<char>(s, charset);
}

char *strcasestr(const char *s1, const char *s2) {
    char d1 = *s1;
    char d2 = *s2;

    char* res;
    sf_overwrite(&res);
    return res;
}

char *strnstr(const char *s1, const char *s2, size_t n) {
    if (n > 0) {
        char d1 = *s1;
    }
    char d2 = *s2;

    char* res;
    sf_overwrite(&res);
    return res;
}

char *strstr(const char *big, const char *little) {
    return strstr_body<char>(big, little);
}

char *strtok(char *s, const char *delim) {
    char d2 = *delim;

    sf_buf_stop_at_null(s);

    char* res;
    sf_overwrite(&res);
    sf_null_terminated((char *)res);
    return res;
}

char *index(const char *s, int c) {
    char d1 = *s;

    char* res;
    sf_overwrite(&res);
    return res;
}

char *rindex(const char *s, int c) {
    char d1 = *s;

    char* res;
    sf_overwrite(&res);
    return res;
}

char *strdup(const char *s) {
    char d1 = *s;
    sf_buf_stop_at_null(s);

    char *res;
    sf_overwrite(&res);
    sf_overwrite(res);
    //like malloc it may return null.
    sf_set_alloc_possible_null(res);
    sf_new(res, MALLOC_CATEGORY);
    sf_strdup_res(res);
    sf_null_terminated(res);
    return res;
}

void *memset(void *ptr, int value, size_t num) {
    return memset_body<char, void, int>(ptr, value, num);
}

void *__memset_chk(void *ptr, int value, size_t num, size_t destlen) {
    if (num > 0 && destlen > 0) {
        char d1 = *(char *)ptr;
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

void *memcpy(void *dst, const void *src, size_t num) {
    memcpy_body(char);
}


errno_t memcpy_s(void *dst, size_t dstSize, const void *src, size_t num) {
    if(dstSize>0 && num>0) {
        char d1 = *(char *)dst;
        char d2 = *(char *)src;
    }    

    sf_bitinit(dst);
    sf_bitcopy(dst, src);

    sf_set_trusted_sink_int(num);

    sf_buf_copy(dst, src);
    sf_buf_size_limit_strict(dst, dstSize);
    sf_buf_size_limit(src, num);
    sf_buf_size_limit_read(src, num);

    sf_transfer_tainted(dst, (void *)src, dstSize);

    errno_t res;
    sf_overwrite(&res);
    return res;
}

void *__memcpy_chk(void *dst, const void *src, size_t num, size_t dstlen) {
    if(num > 0) {
        char d2 = *(char *)src;
        if(dstlen > 0) {
            char d1 = *(char *)dst;
        }
    }

    //sf_overwrite(dst); see MemoryModelPlugin.MemcpySpecFunc
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

void *memmove(void *dst, const void *src, size_t num) {
     return memmove_body<char, void>(dst, src, num);
}

}

