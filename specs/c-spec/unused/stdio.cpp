#include "stdio-templates.h"
#include "specfunc.h"
#include "basetypes.h"

extern "C" {

// TODO: fpos_t is actually a struct - depends on defines which exactly,
//       see stdio.h
typedef long fpos_t;

void clearerr(FILE *stream) {
    char derefStream = *((char *)stream);
}

// char *ctermid(char *s);

int fclose(FILE *stream) {
    char derefStream = *((char *)stream);

	sf_must_not_be_release(stream);

    sf_overwrite(stream);
    sf_handle_release(stream, FILE_CATEGORY);
    sf_lib_arg_type(stream, "FilePointerCategory");

	int res;
	sf_overwrite(&res);
	sf_must_be_checked(res);//EOF
	return res;
}


FILE *fdopen(int fildes, const char * mode) {
	char d1 = *mode;
	sf_set_must_be_positive(fildes);
	sf_escape((void*)fildes);

    FILE *res;
    sf_overwrite(&res);
    sf_set_possible_null(res);
    sf_lib_arg_type(res, "FilePointerCategory");
    return res;
}

int feof(FILE *stream) {
    char derefStream = *((char *)stream);

	sf_must_not_be_release(stream);
	sf_lib_arg_type(stream, "FilePointerCategory");

    int res;
    sf_overwrite(&res);
    sf_feof_res(res);
    sf_feof((int)(intptr_t)stream);
    return res;
}

int ferror(FILE *stream) {
    char derefStream = *((char *)stream);
    sf_ferror((int)(intptr_t)stream);
    sf_lib_arg_type(stream, "FilePointerCategory");
    return ret_any();
}

// this function can take a NULL pointer
int fflush(FILE *stream) {
	sf_must_not_be_release(stream);
	sf_lib_arg_type(stream, "FilePointerCategory");
    int res;
    sf_overwrite(&res);
    sf_set_possible_negative(res);
    return res;
}

int fgetc(FILE *stream) {
	sf_lib_arg_type(stream, "FilePointerCategory");
    fgetc_body(char);
}

int fgetpos(FILE *stream, fpos_t *pos) {
    char derefStream = *((char *)stream);
	sf_must_not_be_release(stream);
	sf_lib_arg_type(stream, "FilePointerCategory");

	int res;
	sf_overwrite(&res);
	sf_must_be_checked(res);
	return res;
}

char *fgets(char *s, int num, FILE *stream) {
    fgets_body(char);
}

int fileno(FILE *stream) {
    char derefStream = *((char *)stream);
    return ret_any();
}

FILE *fopen(const char *filename, const char *mode){
    char d1 = *filename;
    char d2 = *mode;
    sf_tocttou_access(filename);
    sf_set_trusted_sink_ptr(filename);

    FILE *res;
    sf_overwrite(&res);
    sf_overwrite(res);
    sf_uncontrolled_value((int)(intptr_t)res);
    sf_set_possible_null(res);
    sf_handle_acquire(res, FILE_CATEGORY);
    sf_lib_arg_type(res, "FilePointerCategory");
    sf_not_acquire_if_eq(res, (int)(intptr_t)res, 0);
    sf_set_errno_if((int)(intptr_t)res, 0);
    return res;
}

FILE *fopen64(const char *filename, const char *mode){
    return fopen(filename, mode);
}

int fprintf(FILE *stream, const char *format, ...) {
	sf_lib_arg_type(stream, "FilePointerCategory");
    fprintf_body(char);
}

int fputc(int c, FILE *stream) {
	fputc_body();
}

} //extern "C"

extern "C" {

int fputs(const char *s, FILE *stream) {
    fputs_body(char);
}

size_t fread(void *ptr, size_t size, size_t nitems, FILE *stream) {
    char derefStream = *((char *)stream);
	
	sf_must_not_be_release(stream);
	sf_lib_arg_type(stream, "FilePointerCategory");

    sf_set_trusted_sink_int(size);
    sf_set_trusted_sink_int(nitems);

    sf_overwrite(ptr);
    sf_bitinit(ptr);
	char derefPtr = *((char*)ptr);
    sf_set_tainted(ptr);
    sf_set_possible_nnts(ptr);
    //note: sf_bitinit, sf_set_tainted

	size_t res;
	sf_overwrite(&res);
	sf_must_be_checked(res);
	sf_fread(res, (int)(intptr_t)stream);
    sf_buf_fill(res, ptr);
    sf_fread_buflen(size, nitems, ptr);
    sf_assert_cond(res, "<=", nitems);
	return res;
}

FILE *freopen(const char *filename, const char *mode, FILE *stream) {
    char derefStream = *((char *)stream);
	char d2 = *mode;
    sf_tocttou_access(filename);
    sf_set_trusted_sink_ptr(filename);
	sf_must_not_be_release(stream);
	sf_lib_arg_type(stream, "FilePointerCategory");
	sf_handle_release(stream, FILE_CATEGORY);

    FILE *res = stream;
    sf_set_possible_null(res);
    sf_lib_arg_type(res, "FilePointerCategory");
    return res; return ret_any();
}

FILE *freopen64(const char *filename, const char *mode, FILE *stream) {
    return freopen(filename, mode, stream);
}

} //extern "C"

//TODO: this function is handled directly as a special function, which overrides the use
// of this specification; the two mechanisms should probably be integrated somehow.

extern "C" {

int fscanf(FILE *stream, const char *format, ...){
    const char derefStream = *((const char *)stream);
    const char d1 = *format;
    sf_use_format(format);
    sf_must_not_be_release(stream);
    sf_lib_arg_type(stream, "FilePointerCategory");
    sf_fun_scanf_like(1);
    sf_fun_updates_vargs(2);

    int res;
    sf_overwrite(&res);
    sf_must_be_checked(res);
    return res;
}

int fscanf_s(FILE *stream, const char *format, ...){
    char derefStream = *((char *)stream);
    char d1 = *format;
    sf_use_format(format);
    sf_must_not_be_release(stream);
    sf_lib_arg_type(stream, "FilePointerCategory");
    //sf_fun_scanf_like(1); this function is not like scanf, because each buffer-param requiring buffer-size after himself
    sf_fun_updates_vargs(2);
    int res;
    sf_overwrite(&res);
    sf_must_be_checked(res);
    return res;
}

int fseek(FILE *stream, long int offset, int whence) {
    char derefStream = *((char *)stream);
	sf_must_not_be_release(stream);
	sf_lib_arg_type(stream, "FilePointerCategory");

	int res;
	sf_overwrite(&res);
	sf_must_be_checked(res);
	return res;
}

int fsetpos(FILE *stream, const fpos_t *pos) {
    char derefStream = *((char *)stream);
	sf_must_not_be_release(stream);
	sf_lib_arg_type(stream, "FilePointerCategory");

	int res;
	sf_overwrite(&res);
	sf_must_be_checked(res);
	return res;
}

long int ftell(FILE *stream) {
    char derefStream = *((char *)stream);
	sf_must_not_be_release(stream);
	sf_lib_arg_type(stream, "FilePointerCategory");

    long int res;
    sf_overwrite(&res);
    sf_set_possible_negative(res);
    return res;
}

size_t fwrite(const void *ptr, size_t size, size_t nitems, FILE *stream) {
    char derefStream = *((char *)stream);
	sf_must_not_be_release(stream);
	sf_lib_arg_type(stream, "FilePointerCategory");

    sf_use(ptr);
    sf_set_trusted_sink_int(size);
    sf_set_trusted_sink_int(nitems);
    size_t x;
    size_t nbytes = size * nitems;
    sf_assert_cond(x, "<=", nbytes);
    return x;
}

int getc(FILE *stream) {
    //return getc_body(stream);
    sf_must_not_be_release(stream);
    sf_lib_arg_type(stream, "FilePointerCategory");

    int res;
    sf_overwrite(&res);
    sf_must_int(res);
    sf_must_be_checked(res);
    sf_set_values(res, -1, 255);
    sf_set_tainted_interval(res, -1, 255);
    return res;
}

int getchar(void) {
    return getchar_body();
}

char *gets(char *s) {
    char d1 = *s;

	sf_long_time();
    sf_vulnerable_fun("This function doesn't check input buffer capacity, allowing the possibility of buffer overflow.");

    sf_overwrite(s);
    sf_set_tainted(s);
    char *str;
    sf_overwrite(&str);
    sf_set_tainted(str);
    return str;
}

int getw(FILE *stream) {
	sf_must_not_be_release(stream);
	return ret_any();
}

int pclose(FILE *stream) {
    char derefStream = *((char *)stream);

	sf_must_not_be_release(stream);

    sf_overwrite(stream);
    sf_handle_release(stream, FILE_CATEGORY);//file?
	
    int res;
    sf_overwrite(&res);
    sf_must_be_checked(res);//EOF
    return res;
}

void perror(const char *s) {
}

FILE *popen(const char *command, const char *mode) {
    sf_set_trusted_sink_ptr(command);

    FILE *res;
    sf_overwrite(&res);
    sf_overwrite(res);
	sf_uncontrolled_value((int)(intptr_t)res);
    sf_set_possible_null(res);
    sf_handle_acquire(res, FILE_CATEGORY);//file?
    return res;
}

int printf(const char *format, ...) {
    printf_body(char);
}

} //extern "C"

extern "C" {

int putc(int c, FILE *stream){
     return putc_body<int>(c, stream);
}

int putchar(int c) {
    int ret;
    sf_overwrite(&ret);
    sf_set_possible_negative(ret);
    return ret;
}

int puts(const char *s) {
    char d1 = *s;
    int res;
    sf_overwrite(&res);
    return res;
}

int putw(int w, FILE *stream) {
    return ret_any();
}

int remove(const char *path) {
    char d1 = *path;
    sf_tocttou_access(path);
	sf_set_trusted_sink_ptr(path);

	int res;
	sf_overwrite(&res);
	sf_must_be_checked(res);
	return res;
}

int rename(const char *old, const char *news){
    char d1 = *old;
    char d2 = *news;
    sf_tocttou_access(old);
    sf_tocttou_access(news);

	sf_set_trusted_sink_ptr(old);
	sf_set_trusted_sink_ptr(news);

	int res;
	sf_overwrite(&res);
	sf_must_be_checked(res);
	return res;
}

void rewind(FILE *stream) {
}

int scanf(const char *format, ...) {
    scanf_body(char);
}

int scanf_s(const char *format, ...) {
    char d1 = *format;
    sf_use_format(format);

    sf_long_time();
    //sf_fun_scanf_like(0); this function is not like scanf, because each buffer-param requiring buffer-size after himself
    sf_fun_updates_vargs(1);

    int res;
    sf_overwrite(&res);
    return res;

}

//buf may be null
void setbuf(FILE *stream, char *buf) {
	sf_must_not_be_release(stream);
}

int setvbuf(FILE *stream, char *buf, int type, size_t size) {
	sf_must_not_be_release(stream);
	return ret_any();
}

int sprintf(char *s, const char *format, ...) {
    char d1 = *s;
    char d2 = *format;
    sf_bitinit(s);
    sf_use_format(format);

    sf_fun_snprintf_like(1, -1);

    sf_fun_does_not_update_vargs(2);

    sf_vulnerable_fun("This function is unsafe, use snprintf instead.");

	int res;
	sf_overwrite(&res);
	//commented because it useless in most cases (TODO: create some minor group sf_set_possible_negative(res, minor))
	//sf_set_possible_negative(res);
	return res;
}

int snprintf(char *str, size_t size, const char *format, ...) {
    char d2 = *format;
    sf_bitinit(str);
    sf_use_format(format);

    sf_fun_snprintf_like(2, 1);
    sf_fun_does_not_update_vargs(3);
    sf_buf_size_limit(str, size);

	int res;
	sf_overwrite(&res);
	//commented because it useless in most cases (TODO: create some minor group sf_set_possible_negative(res, minor))
	//sf_set_possible_negative(res);
	sf_must_be_checked(res);
	return res;
}


int snprintf_s(char *str, size_t size, const char *format, ...) {
    char d2 = *format;
    sf_bitinit(str);
    sf_use_format(format);

    sf_fun_snprintf_like(2, 1);
    sf_fun_does_not_update_vargs(3);
    sf_buf_size_limit_strict(str, size);

    int res;
    sf_overwrite(&res);
    //commented because it useless in most cases (TODO: create some minor group sf_set_possible_negative(res, minor))
    //sf_set_possible_negative(res);
    sf_must_be_checked(res);
    return res;
}

int sprintf_s(char *str, size_t size, const char *format, ...) {
    char d2 = *format;
    sf_bitinit(str);
    sf_use_format(format);

    sf_fun_snprintf_like(2, 1);
    sf_fun_does_not_update_vargs(3);
    sf_buf_size_limit_strict(str, size);

	int res;
	sf_overwrite(&res);
	//commented because it useless in most cases (TODO: create some minor group sf_set_possible_negative(res, minor))
	//sf_set_possible_negative(res);
	sf_must_be_checked(res);
	return res;
}

int asprintf(char **ret, const char *format, ...) {
    sf_use_format(format);

    sf_overwrite(ret);
    sf_overwrite(*ret);
    sf_new(*ret, MALLOC_CATEGORY);

    sf_fun_snprintf_like(1, -2); // limit is not specified, however buffer can't overflow
    sf_fun_does_not_update_vargs(2);

    int res;
    sf_overwrite(&res);
    //sf_not_acquire_if_eq(*ret, res, -1);
	sf_not_acquire_if_less(*ret, res, 1);
	sf_set_possible_negative(res);
    return res;
    //sf_fun_does_not_update_vargs(2);
}

int sscanf(const char *s, const char *format, ...) {
    sscanf_body(char);
}

int sscanf_s(const char *buffer, const char *format, ...) {
    char d1 = *buffer;
    char d2 = *format;
    sf_use_format(format);

    //sf_fun_scanf_like(1); this function is not like scanf, because each buffer-param requiring buffer-size after himself 
    sf_fun_updates_vargs(2);
    int res;
    sf_overwrite(&res);
    return res;
}

int vscanf(const char *format, va_list ap){
    return vscanf_body<char>(format, ap);
}

int vsscanf(const char *str, const char *format, va_list ap) {
	return vsscanf_body<char>(str, format, ap);
}

int vfscanf(FILE *stream, const char *format, va_list ap) {
	return vfscanf_body<char>(stream, format, ap);
}

#define UNSAFE_TMP_FUNCTION_DECL() sf_vulnerable_fun_temp("This function is susceptible to a race condition occurring between selection of the file name and creation of the file, which allows malicious users to potentially overwrite arbitrary files in the system. Use mkstemp(), mkstemps(), or mkdtemp() instead.");

char *tempnam(const char *dir, const char *pfx) {
    UNSAFE_TMP_FUNCTION_DECL();
    sf_tocttou_access(dir);
	sf_set_trusted_sink_ptr(dir);

    char *res;
    sf_overwrite(&res);
    sf_set_possible_null(res);
    return res;
}

int ungetc(int c, FILE *stream) {
    return ret_any();
}

int vfprintf(FILE *stream, const char *format, va_list ap) {
	return vfprintf_body<char>(stream, format, ap);
}

int vprintf(const char *format, va_list ap) {
    return vprintf_body<char>(format, ap);
}

int vsprintf(char *s, const char *format, va_list ap) {
    char d1 = *s;
    
    if (format) {
        char d2 = *format;
    }

    sf_bitinit(s);
    sf_use_format(format);

    sf_vulnerable_fun("This function is unsafe, use vsnprintf instead.");
    return ret_any();
}

int vsnprintf(char *str, size_t size, const char *format, va_list ap) {
    if (format) {
        char d2 = *format;
    }

    sf_bitinit(str);
    sf_use_format(format);
    sf_buf_size_limit(str, size);
    return ret_any();
}

int vasprintf(char **ret, const char *format, va_list ap) {
    if (format) {
        char d1 = *format;
    }

    sf_use_format(format);

    sf_overwrite(ret);
    sf_overwrite(*ret);
    sf_new(*ret, MALLOC_CATEGORY);

    int res;
    sf_overwrite(&res);
    sf_set_possible_negative(res);
	sf_not_acquire_if_less(*ret, res, 1);
    return res;
}

ssize_t getline(char **lineptr, size_t *n, FILE *stream) {
    char *d1 = *lineptr;
	sf_escape(*lineptr);

	sf_overwrite(lineptr);
    sf_overwrite(*lineptr);
	char derefStream = *((char *)stream);
	sf_new(*lineptr, MALLOC_CATEGORY);
    sf_set_tainted(*lineptr);

    ssize_t res;
    sf_overwrite(&res);
    sf_set_possible_negative(res);
    //*lineptr should be freed even if getline fails.
	//sf_not_acquire_if_less(*lineptr, res, 1);
    sf_buf_fill(res, *lineptr);
	sf_bitinit(n);
	sf_bitinit(*lineptr);
    return res;
}

// char *cuserid(char *s);
// int getopt(int argc, const char *argv[], const char *optstring);

FILE *tmpfile() {
    UNSAFE_TMP_FUNCTION_DECL();

    FILE *res;
    sf_overwrite(&res);
    sf_set_possible_null(res);
    return res;
}

char *tmpnam(char *s) {
    UNSAFE_TMP_FUNCTION_DECL();

    char *res;
    sf_overwrite(&res);
    sf_set_possible_null(res);
    return res;
}

}
