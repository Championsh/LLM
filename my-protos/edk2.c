void * AllocatePages ( uintptr_t Pages )

void * AllocateRuntimePages ( uintptr_t Pages )

void * AllocateReservedPages ( uintptr_t Pages )

void FreePages ( void    *Buffer,  uintptr_t Pages )

void * AllocateAlignedPages ( uintptr_t Pages,  uintptr_t Alignment )

void * AllocatePool ( uintptr_t AllocationSize )

void * AllocateRuntimePool ( uintptr_t AllocationSize )

void * AllocateReservedPool ( uintptr_t AllocationSize )

void * AllocateZeroPool ( uintptr_t AllocationSize )

void * AllocateRuntimeZeroPool ( uintptr_t AllocationSize )

void * AllocateReservedZeroPool ( uintptr_t AllocationSize )

void * AllocateCopyPool ( uintptr_t    AllocationSize,  const void   *Buffer )

void * AllocateRuntimeCopyPool ( uintptr_t    AllocationSize,  const void   *Buffer )

void * AllocateReservedCopyPool ( uintptr_t    AllocationSize,  const void   *Buffer )

void * ReallocatePool ( uintptr_t OldSize,  uintptr_t NewSize,  void    *OldBuffer )

void * ReallocateRuntimePool ( uintptr_t OldSize,  uintptr_t NewSize,  void    *OldBuffer )

void * ReallocateReservedPool ( uintptr_t OldSize,  uintptr_t NewSize,  void    *OldBuffer )

void FreePool ( void  *Buffer )
