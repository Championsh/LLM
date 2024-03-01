#include "specfunc.h"
#include "stdio-templates.h"
#include "string-templates.h"

typedef __builtin_va_list va_list;
typedef unsigned int wint_t;
/*
int iswalpha(wint_t i) {
    sf_set_trusted_sink_ink(i);
}

int iswxdigit(wint_t i) {
    sf_set_trusted_sink_ink(i);
}*/

extern "C"{

wint_t putwchar(wchar_t wc) {
    return putchar_body(wc);
}

int fgetwc(FILE *stream) {
    fgetc_body(char);
}

wchar_t *fgetws(wchar_t *s, int num, FILE *stream) {
    fgets_body(wchar_t);
}

int fputwc(wchar_t c, FILE *stream) {
    fputc_body();
}

int fputws(const wchar_t *s, FILE *stream) {
    fputs_body(wchar_t);
}

int fwscanf(FILE *stream, const wchar_t *format, ...){
    const wchar_t derefStream = *((const wchar_t *)stream);
    const wchar_t d1 = *format;
    sf_use_format(format);
    sf_must_not_be_release(stream);
    sf_fun_scanf_like(1);
    sf_fun_updates_vargs(2);

    int res;
    sf_overwrite(&res);
    sf_must_be_checked(res);
    return res;
}

wint_t getwchar(void){
    return getchar_body();
}

wint_t getwc(FILE *stream) {
	return getc_body(stream);
}

int wprintf(const wchar_t *format, ...) {
    printf_body(wchar_t);
}

wint_t putwc(wchar_t c, FILE *stream){
     return putc_body<wchar_t>(c, stream);
}

int wscanf(const wchar_t *format, ...) {
    scanf_body(wchar_t);
}

int swprintf(wchar_t *s, size_t maxlen, const wchar_t *format, ...){
    wchar_t d1 = *s;
    wchar_t d2 = *format;
    sf_bitinit(s);
    sf_use_format(format);

    sf_fun_snprintf_like(1, -1);

    sf_fun_does_not_update_vargs(2);
    int res;
    sf_overwrite(&res);
    return res;
}

int swscanf(const wchar_t *s, const wchar_t *format, ...) {
    sscanf_body(wchar_t);
}

int vwscanf(const wchar_t *format, va_list ap){
    return vscanf_body<wchar_t>(format, ap);
}

int vswscanf(const wchar_t *str, const wchar_t *format, va_list ap) {
	return vsscanf_body<wchar_t>(str, format, ap);
}

int vfwscanf(FILE *stream, const wchar_t *format, va_list ap) {
	return vfscanf_body<wchar_t>(stream, format, ap);
}

int vfwprintf(FILE *stream, const wchar_t *format, va_list ap) {
	return vfprintf_body<wchar_t>(stream, format, ap);
}

int vwprintf(const wchar_t *format, va_list ap) {
    return vprintf_body<wchar_t>(format, ap);
}

int vswprintf(wchar_t *s, size_t len, const wchar_t *format, va_list ap) {
    wchar_t d1 = *s;

    if (format) {
        wchar_t d2 = *format;
    }

    sf_bitinit(s);
    sf_use_format(format);

    return ret_any();
}

wint_t ungetwc(wint_t c, FILE *stream) {
    return ret_any();
}

wchar_t *wcschr(const wchar_t *s, wchar_t wc) {
    return strchr_body<wchar_t, wchar_t>(s, wc);;
}

int fwprintf(FILE *stream, const wchar_t *format, ...) {
    fprintf_body(wchar_t);
}

wchar_t *wcsrchr(const wchar_t *s, wchar_t wc) {
    return strchr_body<wchar_t, wchar_t>(s, wc);
}

int wcscmp(const wchar_t *s1, const wchar_t *s2) {
    return strcmp_body<wchar_t>(s1, s2);
}

int wmemcmp(const wchar_t *ptr1, const wchar_t *ptr2, size_t num) {
    memcmp_body(wchar_t);
}

wchar_t *wcspbrk(const wchar_t *s, const wchar_t *charset) {
    return str_scan_body<wchar_t>(s, charset);
}

size_t wcsspn(const wchar_t *s, const wchar_t *charset) {
    return str_scan_body<wchar_t>(s, charset);
}

size_t wcscspn(const wchar_t *s, const wchar_t *charset) {
      return str_scan_body<wchar_t>(s, charset);
}

wchar_t *wcsstr(const wchar_t *big, const wchar_t *little) {
    return strstr_body<wchar_t>(big, little);
}

wchar_t *wcstok(wchar_t *s, const wchar_t *delim, wchar_t **p) {
    wchar_t d2 = *delim;

    sf_buf_stop_at_null(s);

    wchar_t* res;
    sf_overwrite(&res);
    sf_null_terminated((char *)res);
    return res;
}

wchar_t *wmemset(wchar_t *ptr, wchar_t value, size_t num) {
    return memset_body<wchar_t, wchar_t, wchar_t>(ptr, value, num);
}

wchar_t *wmemcpy(wchar_t *dst, const wchar_t *src, size_t num) {
    memcpy_body(wchar_t);
}

wchar_t *wmemmove(wchar_t *dst, const wchar_t *src, size_t num) {
    return memmove_body<wchar_t, wchar_t>(dst, src, sizeof(wchar_t) * num);
}

wchar_t *wcscat(wchar_t *s, const wchar_t *append) {
    wchar_t d1 = *s;
    wchar_t d2 = *append;
    sf_set_trusted_sink_ptr(s);
    sf_set_trusted_sink_ptr(append);
    sf_append_wcs((char *)s, (const char *)append);
    sf_vulnerable_fun("This function is unsafe, use wcsncat instead.");
    sf_null_terminated((char *)s);
    return s;
}

wchar_t *wcsncat(wchar_t *s, const wchar_t *append, size_t count) {
     char d1 = *s;
     if (count > 0) {
         char d2 = *append;
     }
 
//     sf_buf_copy(s, append);
     sf_append_wcs((char *)s, (char *)append);
     sf_buf_size_limit(append, count);
     sf_buf_size_limit_read(append, count);
     sf_buf_stop_at_null(append);
 
     return s;
}


int wcsncmp(const wchar_t *s1, const wchar_t *s2, size_t count) {
    return strncmp_body<wchar_t>(s1, s2, count);
}

size_t wcslen(const wchar_t *s) {
    wchar_t d1 = *s;

//    sf_sanitize(s);

    size_t res;
    sf_overwrite(&res);
    sf_wcslen(res, s);
    sf_buf_stop_at_null(s);

    if(s)
        sf_assert_cond(res, ">=", 0);
    return res;
}

wchar_t *wcscpy(wchar_t *dst, const wchar_t *src) {
    wchar_t d1 = *dst;
    wchar_t d2 = *src;
    sf_bitinit(dst);
    sf_set_trusted_sink_ptr(src);
    sf_copy_wcs(dst, src);
    sf_vulnerable_fun("This function is unsafe, use wcsncpy instead.");
    return dst;
}

wchar_t *wcsncpy(wchar_t *dst, const wchar_t *src, size_t count){
     if (count > 0) {
         char d1 = *dst;
         char d2 = *src;
     }
     sf_bitinit(dst);
//     sf_buf_copy(dst, src);
     sf_copy_wcs(dst, src);
     sf_buf_size_limit(src, count);
     sf_buf_size_limit_read(src, count);
     sf_buf_stop_at_null(src);
     return dst;
}
} //extern "C"
