#include "specfunc.h"

void * AllocatePages ( uintptr_t Pages )
{
    void *Res;
    sf_set_trusted_sink_int(&Pages);
    sf_overwrite(&Res, sizeof(Res));
    sf_new(&Res, PAGES_MEMORY_CATEGORY);
    sf_set_possible_null(&Res);
    sf_not_acquire_if_eq(&Res, NULL);
    sf_buf_size_limit(&Res, Pages * PAGE_SIZE);
    return Res;
}

void * AllocateRuntimePages ( uintptr_t Pages )
{
    void *Res;
    sf_set_trusted_sink_int(&Pages);
    sf_overwrite(&Res, sizeof(Res));
    sf_new(&Res, RUNTIME_PAGES_MEMORY_CATEGORY);
    sf_set_possible_null(&Res);
    sf_not_acquire_if_eq(&Res, NULL);
    sf_buf_size_limit(&Res, Pages * PAGE_SIZE);
    return Res;
}

void * AllocateReservedPages ( uintptr_t Pages )
{
    void *Res;
    sf_set_trusted_sink_int(&Pages);
    sf_overwrite(&Res, sizeof(Res));
    sf_new(&Res, RESERVED_PAGES_MEMORY_CATEGORY);
    sf_set_possible_null(&Res);
    sf_not_acquire_if_eq(&Res, NULL);
    sf_buf_size_limit(&Res, Pages * PAGE_SIZE);
    return Res;
}

void FreePages ( void *Buffer, uintptr_t Pages )
{
    sf_delete(Buffer, PAGES_MEMORY_CATEGORY);
}

void * AllocateAlignedPages ( uintptr_t Pages, uintptr_t Alignment )
{
    void *Res;
    sf_set_trusted_sink_int(&Pages);
    sf_overwrite(&Res, sizeof(Res));
    sf_new(&Res, ALIGNED_PAGES_MEMORY_CATEGORY);
    sf_set_possible_null(&Res);
    sf_not_acquire_if_eq(&Res, NULL);
    sf_buf_size_limit(&Res, Pages * PAGE_SIZE);
    return Res;
}

void * AllocatePool ( uintptr_t AllocationSize )
{
    void *Res;
    sf_set_trusted_sink_int(&AllocationSize);
    sf_overwrite(&Res, sizeof(Res));
    sf_new(&Res, POOL_MEMORY_CATEGORY);
    sf_set_possible_null(&Res);
    sf_not_acquire_if_eq(&Res, NULL);
    sf_buf_size_limit(&Res, AllocationSize);
    return Res;
}

void * AllocateRuntimePool ( uintptr_t AllocationSize )
{
    void *Res;
    sf_set_trusted_sink_int(&AllocationSize);
    sf_overwrite(&Res, sizeof(Res));
    sf_new(&Res, RUNTIME_POOL_MEMORY_CATEGORY);
    sf_set_possible_null(&Res);
    sf_not_acquire_if_eq(&Res, NULL);
    sf_buf_size_limit(&Res, AllocationSize);
    return Res;
}

void * AllocateReservedPool ( uintptr_t AllocationSize )
{
    void *Res;
    sf_set_trusted_sink_int(&AllocationSize);
    sf_overwrite(&Res, sizeof(Res));
    sf_new(&Res, RESERVED_POOL_MEMORY_CATEGORY);
    sf_set_possible_null(&Res);
    sf_not_acquire_if_eq(&Res, NULL);
    sf_buf_size_limit(&Res, AllocationSize);
    return Res;
}

void FreePool ( void *Buffer )
{
    sf_delete(Buffer, POOL_MEMORY_CATEGORY);
}

void * ReallocatePool ( uintptr_t OldSize, uintptr_t NewSize, void *OldBuffer )
{
    void *Res;
    sf_set_trusted_sink_int(&NewSize);
    sf_overwrite(&Res, sizeof(Res));
    sf_new(&Res, POOL_MEMORY_CATEGORY);
    sf_set_possible_null(&Res);
    sf_not_acquire_if_eq(&Res, NULL);
    sf_buf_size_limit(&Res, NewSize);
    sf_bitcopy(Res, OldBuffer, OldSize);
    sf_delete(OldBuffer, POOL_MEMORY_CATEGORY);
    return Res;
}

void * ReallocateRuntimePool ( uintptr_t OldSize, uintptr_t NewSize, void *OldBuffer )
{
    void *Res;
    sf_set_trusted_sink_int(&NewSize);
    sf_overwrite(&Res, sizeof(Res));
    sf_new(&Res, RUNTIME_POOL_MEMORY_CATEGORY);
    sf_set_possible_null(&Res);
    sf_not_acquire_if_eq(&Res, NULL);
    sf_buf_size_limit(&Res, NewSize);
    sf_bitcopy(Res, OldBuffer, OldSize);
    sf_delete(OldBuffer, RUNTIME_POOL_MEMORY_CATEGORY);
    return Res;
}

void * ReallocateReservedPool ( uintptr_t OldSize, uintptr_t NewSize, void *OldBuffer )
{
    void *Res;
    sf_set_trusted_sink_int(&NewSize);
    sf_overwrite(&Res, sizeof(Res));
    sf_new(&Res, RESERVED_POOL_MEMORY_CATEGORY);
    sf_set_possible_null(&Res);
    sf_not_acquire_if_eq(&Res, NULL);
    sf_buf_size_limit(&Res, NewSize);
    sf_bitcopy(Res, OldBuffer, OldSize);
    sf_delete(OldBuffer, RESERVED_POOL_MEMORY_CATEGORY);
    return Res;
}
