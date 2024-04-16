#include "specfunc.h"
#include "basetypes.h"
#include <stdarg.h>

static int ret_any() {
    int x;
    sf_overwrite(&x);
    return x;
}

#define fgets_body(type)   type derefStream = *((type *)stream);\
                           sf_set_trusted_sink_int(num);\
                           sf_must_not_be_release(stream);\
                           sf_overwrite(s);\
                           type d1 = *s;\
                           type d2 = s[num-1];\
                           sf_set_tainted(s);\
                           sf_set_tainted_buf(s, num, -1); \
                           sf_buf_size_limit(s, num);\
                           sf_null_terminated((char*)s);\
                           sf_string_size_limit((const char *const)s, 2, num);\
                           sf_string_size_limit_2((const char *const)s, num, -1);\
                           type *str = s;\
                           if(sf_unknown_int())\
                           str = 0;\
                           sf_uncontrolled_value((int)(intptr_t)str);\
                           return str;\

#define sscanf_body(type)  type d1 = *s;\
                           type d2 = *format;\
                           sf_use_format(format);\
                           sf_fun_scanf_like(1);\
                           sf_vulnerable_fun_sscanf("This function is unsafe.");\
                           sf_fun_updates_vargs(2);\
							int res;\
							sf_overwrite(&res);\
							return res;\

#define fputs_body(type)  type derefStream = *((type *)stream);\
                          type d1 = *s;\
                          sf_must_not_be_release(stream);\
                          int res;\
                          sf_overwrite(&res);\
                          sf_must_be_checked(res);\
                          return res;\

#define fgetc_body(type)  type derefStream = *((type *)stream);\
                          sf_must_not_be_release(stream);\
                          int res;\
                          sf_overwrite(&res);\
                          sf_must_int(res);\
                          sf_must_be_checked(res);\
                          sf_set_values(res, -1, 255);\
                          sf_set_tainted_interval(res, -1, 255);\
                          return res;\

#define fprintf_body(type)  type derefStream = *((type *)stream);\
                            type d1 = *format;\
                            sf_bitinit(stream);\
                            sf_use_format(format);\
                            sf_must_not_be_release(stream);\
                            sf_fun_printf_like(1);\
                            sf_fun_does_not_update_vargs(2);\
                            sf_fun_does_not_update_vargs(2);\
                            int res;\
							sf_overwrite(&res);\
							return res;\

#define printf_body(type)  int ret;\
                           sf_overwrite(&ret);\
                           type d1 = *format;\
                           sf_use_format(format);\
                           sf_fun_printf_like(0);\
                           sf_fun_does_not_update_vargs(1);\
                           return ret;\

#define scanf_body(type)  type d1 = *format;\
                          sf_use_format(format);\
                          sf_long_time();\
                          sf_fun_scanf_like(0);\
                          sf_fun_updates_vargs(1);\
                          int res;\
                          sf_overwrite(&res);\
                          sf_must_be_checked(res);\
                          return res;\

#define fputc_body()  sf_must_not_be_release(stream);\
                      int res;\
                      sf_overwrite(&res);\
                      sf_must_be_checked(res);\
                      return res;\

template <typename T>
int vscanf_body(const T *format, va_list ap){
	sf_long_time();

	T d1 = *format;
    sf_use_format(format);
    return ret_any();
}

template <typename T>
int vsscanf_body(const T *str, const T *format, va_list ap) {
	T d1 = *str;
	T d2 = *format;
    sf_use_format(format);
    return ret_any();
}

template <typename T>
int vfscanf_body(FILE *stream, const T *format, va_list ap) {
	T d1 = *format;
    sf_use_format(format);
    return ret_any();
}

template<typename T>
int vfprintf_body(FILE *stream, const T *format, va_list ap) {
	sf_must_not_be_release(stream);
    sf_bitinit(stream);
    T derefStream = *((T *)stream);
    if (format) {
        T d1 = *format;
    }
    sf_use_format(format);
    return ret_any();
}

template<typename T>
int putc_body(T c, FILE *stream){
	sf_must_not_be_release(stream);
	int res;
	sf_overwrite(&res);
	return res;
}

static int getc_body(FILE *stream){
    sf_must_not_be_release(stream);

    int res;
    sf_overwrite(&res);
    sf_must_int(res);
    sf_must_be_checked(res);
    sf_set_values(res, -1, 255);
    sf_set_tainted_interval(res, -1, 255);
    return res;
}

static int getchar_body(void){
    sf_long_time();

    int res;
    sf_overwrite(&res);
    sf_must_int(res);
    sf_must_be_checked(res);
    sf_set_values(res, -1, 255);
    sf_set_tainted_interval(res, -1, 255);
    return res;
}

static int putchar_body(int c) {
    int ret;
    sf_overwrite(&ret);
    sf_set_possible_negative(ret);
    return ret;
}

template <typename T>
int vprintf_body(const T *format, va_list ap) {
    if (format) {
        T d1 = *format;
    }

    sf_use_format(format);
    return ret_any();
}

