#include "specfunc.h"

	class PCString {
		private:

		        PCString(void) {}

		public:
		        static void         Copy(char* dest, const char* source);
		        static void         Copy(char* dest, const char* source, unsigned long size);
		        static void         Print(char* str, const char* format, ...);
        		static void         Print(char* str, int len, const char* format, ...);
	}; 

void PCString::Copy(char* dest, const char* source) {
	char d1 = *dest;
    char d2 = *source;
    sf_bitinit(dest);
    sf_set_trusted_sink_ptr(source);
    sf_copy_string(dest, source);
    sf_vulnerable_fun("This function is unsafe, use strncpy instead.");
}


void PCString::Copy(char* dest, const char* source, unsigned long size) {
	char d1 = *dest;
    char d2 = *source;
    sf_bitinit(dest);
    sf_buf_copy(dest, source);
    sf_buf_size_limit(source, size);
    sf_buf_size_limit_read(source, size);
    sf_buf_stop_at_null(const_cast<void *>(static_cast<const void *>(source)));
}


void PCString::Print(char* str, const char* format, ...) {
	char d1 = *str;
    char d2 = *format;
    sf_bitinit(str);
    sf_use_format(format);

    sf_fun_snprintf_like(1, -1);

    sf_fun_does_not_update_vargs(2);

    sf_vulnerable_fun("This function is unsafe, use snprintf instead.");

}


void PCString::Print(char* str, int len, const char* format, ...) {
	char d2 = *format;
    sf_bitinit(str);
    sf_use_format(format);

    sf_fun_printf_like(2);
    sf_fun_does_not_update_vargs(3);
    
    sf_buf_size_limit(str, len);
}
