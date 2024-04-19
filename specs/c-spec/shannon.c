#include "specfunc.h"

#define PAL_MALLOC_CATEGORY 101

void pal_MemFreeDebug(void** mem, char* file, int line)
{
    sf_overwrite(*mem);
    sf_delete(*mem, PAL_MALLOC_CATEGORY);
}

void* pal_MemAllocTrack(int mid, int size, char* file, int line)
{
    void *ptr;
    sf_overwrite(&ptr);
    sf_overwrite(ptr);
    sf_set_must_be_positive(size);
    sf_set_possible_null(ptr);
    sf_new(ptr, PAL_MALLOC_CATEGORY);
    /* sf_raw_new(ptr); */
    /* sf_set_buf_size(ptr, size); */
    return ptr;
}

void* pal_MemAllocGuard(int mid, int size)
{
    void *ptr;
    sf_overwrite(&ptr);
    sf_overwrite(ptr);
    sf_set_must_be_positive(size);
    sf_set_possible_null(ptr);
    sf_new(ptr, PAL_MALLOC_CATEGORY);
    /* sf_raw_new(ptr); */
    /* sf_set_buf_size(ptr, size); */
    return ptr;
}

void* pal_MemAllocInternal(int mid, int size, char* file, int line)
{
    void *ptr;
    sf_overwrite(&ptr);
    sf_overwrite(ptr);
    sf_set_must_be_positive(size);
    sf_set_possible_null(ptr);
    sf_new(ptr, PAL_MALLOC_CATEGORY);
    /* sf_raw_new(ptr); */
    /* sf_set_buf_size(ptr, size); */
    return ptr;
}
