#include "specfunc.h"

#define PAL_MALLOC_CATEGORY 101

void pal_MemFreeDebug(void** mem, char* file, int line)
;

void* pal_MemAllocTrack(int mid, int size, char* file, int line)
;

void* pal_MemAllocGuard(int mid, int size)
;

void* pal_MemAllocInternal(int mid, int size, char* file, int line)
;
