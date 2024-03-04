#include "specfunc.h"

	class PCString ;; 

void PCString::Copy(char* dest, const char* source);


void PCString::Copy(char* dest, const char* source, unsigned long size);


void PCString::Print(char* str, const char* format, ...);


void PCString::Print(char* str, int len, const char* format, ...);
