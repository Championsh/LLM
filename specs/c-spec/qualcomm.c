#include "specfunc.h"

typedef unsigned long int uint32;

void *OEM_Malloc(uint32 uSize)
{
    void *ptr;
    sf_overwrite(&ptr);
    sf_overwrite(ptr);
    sf_set_alloc_possible_null(ptr, uSize);
    sf_new(ptr, MALLOC_CATEGORY);
    /* sf_raw_new(ptr); */
    /* sf_set_buf_size(ptr, uSize); */
    return ptr;
}

void *aee_malloc(uint32 dwSize)
{
    void *ptr;
    sf_overwrite(&ptr);
    sf_overwrite(ptr);
    sf_set_alloc_possible_null(ptr, dwSize);
    sf_new(ptr, MALLOC_CATEGORY);
    /* sf_raw_new(ptr); */
    /* sf_set_buf_size(ptr, dwSize); */
    return ptr;
}

void OEM_Free(void *p)
{
    sf_overwrite(p);
    sf_delete(p, MALLOC_CATEGORY);
}

void aee_free(void *p)
{
    sf_overwrite(p);
    sf_delete(p, MALLOC_CATEGORY);
}

void *OEM_Realloc(void *p, uint32 uSize)
{
    void *ptr;
    sf_escape(p);
    sf_overwrite(&ptr);
    sf_overwrite(ptr);
    sf_set_alloc_possible_null(ptr, uSize);
    sf_new(ptr, MALLOC_CATEGORY);
    /* sf_raw_new(ptr); */
    /* sf_set_buf_size(ptr, uSize); */
    return ptr;
}

void *aee_realloc(void *p, uint32 dwSize)
{
    void *ptr;
    sf_escape(p);
    sf_overwrite(&ptr);
    sf_overwrite(ptr);
    sf_set_alloc_possible_null(ptr, dwSize);
    sf_new(ptr, MALLOC_CATEGORY);
    /* sf_raw_new(ptr); */
    /* sf_set_buf_size(ptr, dwSize); */
    return ptr;
}

void err_fatal_core_dump(unsigned int line, const char *file_name, const char *format)
{
    sf_terminate_path();
}
