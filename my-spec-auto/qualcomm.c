#include "specfunc.h"

typedef unsigned long int uint32;

void *OEM_Malloc(uint32 uSize)
;

void *aee_malloc(uint32 dwSize)
;

void OEM_Free(void *p)
;

void aee_free(void *p)
;

void *OEM_Realloc(void *p, uint32 uSize)
;

void *aee_realloc(void *p, uint32 dwSize)
;

void err_fatal_core_dump(unsigned int line, const char *file_name, const char *format)
;
