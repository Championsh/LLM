#include "specfunc.h"

#include <stdint.h>
#include <stdbool.h>

#define EFI_PAGE_SIZE             0x1000
#define PAGES_MEMORY_CATEGORY     0x10001
#define ALIGNED_MEMORY_CATEGORY   0x10002
#define POOL_MEMORY_CATEGORY      0x10003

bool
DebugAssertEnabled (
  void
  )
{
  return true;
}

void
CpuDeadLoop (
  void
  )
{
  sf_terminate_path();
}

/**
  Allocates one or more 4KB pages of type EfiBootServicesData.

  Allocates the number of 4KB pages of type EfiBootServicesData and returns a pointer to the
  allocated buffer.  The buffer returned is aligned on a 4KB boundary.  If Pages is 0, then NULL
  is returned.  If there is not enough memory remaining to satisfy the request, then NULL is
  returned.

  @param  Pages                 The number of 4 KB pages to allocate.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
void *
AllocatePages (
  uintptr_t  Pages
  )
{
  sf_set_trusted_sink_int(Pages);

  void *Res;

  sf_overwrite(&Res); // Res is initialized
  sf_overwrite(Res);  // pointed memory is also initialized
  sf_new (Res, PAGES_MEMORY_CATEGORY);
  sf_set_possible_null(Res);
  sf_not_acquire_if_eq(Res, Res, 0); // resource is not created if it equals to null
  sf_buf_size_limit(Res, Pages * EFI_PAGE_SIZE);

  return Res;
}

/**
  Allocates one or more 4KB pages of type EfiRuntimeServicesData.

  Allocates the number of 4KB pages of type EfiRuntimeServicesData and returns a pointer to the
  allocated buffer.  The buffer returned is aligned on a 4KB boundary.  If Pages is 0, then NULL
  is returned.  If there is not enough memory remaining to satisfy the request, then NULL is
  returned.

  @param  Pages                 The number of 4 KB pages to allocate.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
void *
AllocateRuntimePages (
  uintptr_t  Pages
  )
{
  sf_set_trusted_sink_int(Pages);

  void *Res;

  sf_overwrite(&Res);
  sf_overwrite(Res);
  sf_new (Res, PAGES_MEMORY_CATEGORY);
  sf_set_possible_null(Res);
  sf_not_acquire_if_eq(Res, Res, 0);
  sf_buf_size_limit(Res, Pages * EFI_PAGE_SIZE);

  return Res;
}

/**
  Allocates one or more 4KB pages of type EfiReservedMemoryType.

  Allocates the number of 4KB pages of type EfiReservedMemoryType and returns a pointer to the
  allocated buffer.  The buffer returned is aligned on a 4KB boundary.  If Pages is 0, then NULL
  is returned.  If there is not enough memory remaining to satisfy the request, then NULL is
  returned.

  @param  Pages                 The number of 4 KB pages to allocate.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
void *
AllocateReservedPages (
  uintptr_t  Pages
  )
{
  sf_set_trusted_sink_int(Pages);

  void *Res;

  sf_overwrite(&Res);
  sf_overwrite(Res);
  sf_new (Res, PAGES_MEMORY_CATEGORY);
  sf_set_possible_null(Res);
  sf_not_acquire_if_eq(Res, Res, 0);
  sf_buf_size_limit(Res, Pages * EFI_PAGE_SIZE);

  return Res;
}

/**
  Frees one or more 4KB pages that were previously allocated with one of the page allocation
  functions in the Memory Allocation Library.

  Frees the number of 4KB pages specified by Pages from the buffer specified by Buffer.  Buffer
  must have been allocated on a previous call to the page allocation services of the Memory
  Allocation Library.  If it is not possible to free allocated pages, then this function will
  perform no actions.

  If Buffer was not allocated with a page allocation function in the Memory Allocation Library,
  then ASSERT().
  If Pages is zero, then ASSERT().

  @param  Buffer                Pointer to the buffer of pages to free.
  @param  Pages                 The number of 4 KB pages to free.

**/
void
FreePages (
  void       *Buffer,
  uintptr_t  Pages
  )
{
  sf_delete (Buffer, PAGES_MEMORY_CATEGORY);
}

/**
  Allocates one or more 4KB pages of type EfiBootServicesData at a specified alignment.

  Allocates the number of 4KB pages specified by Pages of type EfiBootServicesData with an
  alignment specified by Alignment.  The allocated buffer is returned.  If Pages is 0, then NULL is
  returned.  If there is not enough memory at the specified alignment remaining to satisfy the
  request, then NULL is returned.

  If Alignment is not a power of two and Alignment is not zero, then ASSERT().
  If Pages plus EFI_SIZE_TO_PAGES (Alignment) overflows, then ASSERT().

  @param  Pages                 The number of 4 KB pages to allocate.
  @param  Alignment             The requested alignment of the allocation.  Must be a power of two.
                                If Alignment is zero, then byte alignment is used.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
void *
AllocateAlignedPages (
  uintptr_t  Pages,
  uintptr_t  Alignment
  )
{
  sf_set_trusted_sink_int(Pages);

  void *Res;
  uintptr_t Remainder;

  sf_overwrite(&Res);
  sf_overwrite(Res);
  sf_new (Res, ALIGNED_MEMORY_CATEGORY);
  sf_set_possible_null(Res);
  sf_not_acquire_if_eq(Res, Res, 0);

  Remainder = (Pages * EFI_PAGE_SIZE) % Alignment;
  if (Remainder == 0) {
    sf_buf_size_limit(Res, Pages * EFI_PAGE_SIZE);
  } else {
    sf_buf_size_limit(Res, ((Pages * EFI_PAGE_SIZE) / Alignment + 1) * Alignment);
  }

  return Res;
}

/**
  Allocates one or more 4KB pages of type EfiRuntimeServicesData at a specified alignment.

  Allocates the number of 4KB pages specified by Pages of type EfiRuntimeServicesData with an
  alignment specified by Alignment.  The allocated buffer is returned.  If Pages is 0, then NULL is
  returned.  If there is not enough memory at the specified alignment remaining to satisfy the
  request, then NULL is returned.

  If Alignment is not a power of two and Alignment is not zero, then ASSERT().
  If Pages plus EFI_SIZE_TO_PAGES (Alignment) overflows, then ASSERT().

  @param  Pages                 The number of 4 KB pages to allocate.
  @param  Alignment             The requested alignment of the allocation.  Must be a power of two.
                                If Alignment is zero, then byte alignment is used.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
void *
AllocateAlignedRuntimePages (
  uintptr_t  Pages,
  uintptr_t  Alignment
  )
{
  sf_set_trusted_sink_int(Pages);

  void *Res;
  uintptr_t Remainder;

  sf_overwrite(&Res);
  sf_overwrite(Res);
  sf_new (Res, ALIGNED_MEMORY_CATEGORY);
  sf_set_possible_null(Res);
  sf_not_acquire_if_eq(Res, Res, 0);

  Remainder = (Pages * EFI_PAGE_SIZE) % Alignment;
  if (Remainder == 0) {
    sf_buf_size_limit(Res, Pages * EFI_PAGE_SIZE);
  } else {
    sf_buf_size_limit(Res, ((Pages * EFI_PAGE_SIZE) / Alignment + 1) * Alignment);
  }

  return Res;
}

/**
  Allocates one or more 4KB pages of type EfiReservedMemoryType at a specified alignment.

  Allocates the number of 4KB pages specified by Pages of type EfiReservedMemoryType with an
  alignment specified by Alignment.  The allocated buffer is returned.  If Pages is 0, then NULL is
  returned.  If there is not enough memory at the specified alignment remaining to satisfy the
  request, then NULL is returned.

  If Alignment is not a power of two and Alignment is not zero, then ASSERT().
  If Pages plus EFI_SIZE_TO_PAGES (Alignment) overflows, then ASSERT().

  @param  Pages                 The number of 4 KB pages to allocate.
  @param  Alignment             The requested alignment of the allocation.  Must be a power of two.
                                If Alignment is zero, then byte alignment is used.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
void *
AllocateAlignedReservedPages (
  uintptr_t  Pages,
  uintptr_t  Alignment
  )
{
  sf_set_trusted_sink_int(Pages);

  void *Res;
  uintptr_t Remainder;

  sf_overwrite(&Res);
  sf_overwrite(Res);
  sf_new (Res, ALIGNED_MEMORY_CATEGORY);
  sf_set_possible_null(Res);
  sf_not_acquire_if_eq(Res, Res, 0);

  Remainder = (Pages * EFI_PAGE_SIZE) % Alignment;
  if (Remainder == 0) {
    sf_buf_size_limit(Res, Pages * EFI_PAGE_SIZE);
  } else {
    sf_buf_size_limit(Res, ((Pages * EFI_PAGE_SIZE) / Alignment + 1) * Alignment);
  }

  return Res;
}

/**
  Frees one or more 4KB pages that were previously allocated with one of the aligned page
  allocation functions in the Memory Allocation Library.

  Frees the number of 4KB pages specified by Pages from the buffer specified by Buffer.  Buffer
  must have been allocated on a previous call to the aligned page allocation services of the Memory
  Allocation Library.  If it is not possible to free allocated pages, then this function will
  perform no actions.

  If Buffer was not allocated with an aligned page allocation function in the Memory Allocation
  Library, then ASSERT().
  If Pages is zero, then ASSERT().

  @param  Buffer                Pointer to the buffer of pages to free.
  @param  Pages                 The number of 4 KB pages to free.

**/
void
FreeAlignedPages (
  void   *Buffer,
  uintptr_t  Pages
  )
{
  sf_delete (Buffer, ALIGNED_MEMORY_CATEGORY);
}

/**
  Allocates a buffer of type EfiBootServicesData.

  Allocates the number bytes specified by AllocationSize of type EfiBootServicesData and returns a
  pointer to the allocated buffer.  If AllocationSize is 0, then a valid buffer of 0 size is
  returned.  If there is not enough memory remaining to satisfy the request, then NULL is returned.

  @param  AllocationSize        The number of bytes to allocate.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
void *
AllocatePool (
  uintptr_t  AllocationSize
  )
{
  sf_set_trusted_sink_int(AllocationSize);

  void *Res;

  sf_overwrite(&Res);
  sf_overwrite(Res);
  sf_new (Res, POOL_MEMORY_CATEGORY);
  sf_set_possible_null(Res);
  sf_not_acquire_if_eq(Res, Res, 0);
  sf_buf_size_limit(Res, AllocationSize);

  return Res;
}

/**
  Allocates a buffer of type EfiRuntimeServicesData.

  Allocates the number bytes specified by AllocationSize of type EfiRuntimeServicesData and returns
  a pointer to the allocated buffer.  If AllocationSize is 0, then a valid buffer of 0 size is
  returned.  If there is not enough memory remaining to satisfy the request, then NULL is returned.

  @param  AllocationSize        The number of bytes to allocate.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
void *
AllocateRuntimePool (
  uintptr_t  AllocationSize
  )
{
  sf_set_trusted_sink_int(AllocationSize);

  void *Res;

  sf_overwrite(&Res);
  sf_overwrite(Res);
  sf_new (Res, POOL_MEMORY_CATEGORY);
  sf_set_possible_null(Res);
  sf_not_acquire_if_eq(Res, Res, 0);
  sf_buf_size_limit(Res, AllocationSize);

  return Res;
}

/**
  Allocates a buffer of type EfiReservedMemoryType.

  Allocates the number bytes specified by AllocationSize of type EfiReservedMemoryType and returns
  a pointer to the allocated buffer.  If AllocationSize is 0, then a valid buffer of 0 size is
  returned.  If there is not enough memory remaining to satisfy the request, then NULL is returned.

  @param  AllocationSize        The number of bytes to allocate.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
void *
AllocateReservedPool (
  uintptr_t  AllocationSize
  )
{
  sf_set_trusted_sink_int(AllocationSize);

  void *Res;

  sf_overwrite(&Res);
  sf_overwrite(Res);
  sf_new (Res, POOL_MEMORY_CATEGORY);
  sf_set_possible_null(Res);
  sf_not_acquire_if_eq(Res, Res, 0);
  sf_buf_size_limit(Res, AllocationSize);

  return Res;
}

/**
  Allocates and zeros a buffer of type EfiBootServicesData.

  Allocates the number bytes specified by AllocationSize of type EfiBootServicesData, clears the
  buffer with zeros, and returns a pointer to the allocated buffer.  If AllocationSize is 0, then a
  valid buffer of 0 size is returned.  If there is not enough memory remaining to satisfy the
  request, then NULL is returned.

  @param  AllocationSize        The number of bytes to allocate and zero.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
void *
AllocateZeroPool (
  uintptr_t  AllocationSize
  )
{
  sf_set_trusted_sink_int(AllocationSize);

  void *Res;

  sf_overwrite(&Res);
  sf_overwrite(Res);
  sf_new (Res, POOL_MEMORY_CATEGORY);
  sf_set_possible_null(Res);
  sf_not_acquire_if_eq(Res, Res, 0);
  sf_buf_size_limit(Res, AllocationSize);

  return Res;
}

/**
  Allocates and zeros a buffer of type EfiRuntimeServicesData.

  Allocates the number bytes specified by AllocationSize of type EfiRuntimeServicesData, clears the
  buffer with zeros, and returns a pointer to the allocated buffer.  If AllocationSize is 0, then a
  valid buffer of 0 size is returned.  If there is not enough memory remaining to satisfy the
  request, then NULL is returned.

  @param  AllocationSize        The number of bytes to allocate and zero.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
void *
AllocateRuntimeZeroPool (
  uintptr_t  AllocationSize
  )
{
  sf_set_trusted_sink_int(AllocationSize);

  void *Res;

  sf_overwrite(&Res);
  sf_overwrite(Res);
  sf_new (Res, POOL_MEMORY_CATEGORY);
  sf_set_possible_null(Res);
  sf_not_acquire_if_eq(Res, Res, 0);
  sf_buf_size_limit(Res, AllocationSize);

  return Res;
}

/**
  Allocates and zeros a buffer of type EfiReservedMemoryType.

  Allocates the number bytes specified by AllocationSize of type EfiReservedMemoryType, clears the
  buffer with zeros, and returns a pointer to the allocated buffer.  If AllocationSize is 0, then a
  valid buffer of 0 size is returned.  If there is not enough memory remaining to satisfy the
  request, then NULL is returned.

  @param  AllocationSize        The number of bytes to allocate and zero.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
void *
AllocateReservedZeroPool (
  uintptr_t  AllocationSize
  )
{
  sf_set_trusted_sink_int(AllocationSize);

  void *Res;

  sf_overwrite(&Res);
  sf_overwrite(Res);
  sf_new (Res, POOL_MEMORY_CATEGORY);
  sf_set_possible_null(Res);
  sf_not_acquire_if_eq(Res, Res, 0);
  sf_buf_size_limit(Res, AllocationSize);

  return Res;
}

/**
  Copies a buffer to an allocated buffer of type EfiBootServicesData.

  Allocates the number bytes specified by AllocationSize of type EfiBootServicesData, copies
  AllocationSize bytes from Buffer to the newly allocated buffer, and returns a pointer to the
  allocated buffer.  If AllocationSize is 0, then a valid buffer of 0 size is returned.  If there
  is not enough memory remaining to satisfy the request, then NULL is returned.

  If Buffer is NULL, then ASSERT().
  If AllocationSize is greater than (MAX_ADDRESS - Buffer + 1), then ASSERT().

  @param  AllocationSize        The number of bytes to allocate and zero.
  @param  Buffer                The buffer to copy to the allocated buffer.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
void *
AllocateCopyPool (
  uintptr_t       AllocationSize,
  const void      *Buffer
  )
{
  sf_set_trusted_sink_int(AllocationSize);

  void *Res;

  sf_overwrite(&Res);
  sf_overwrite(Res);
  sf_new (Res, POOL_MEMORY_CATEGORY);
  sf_set_possible_null(Res);
  sf_not_acquire_if_eq(Res, Res, 0);
  sf_buf_size_limit(Res, AllocationSize);
  sf_bitcopy(Res, Buffer);

  return Res;
}

/**
  Copies a buffer to an allocated buffer of type EfiRuntimeServicesData.

  Allocates the number bytes specified by AllocationSize of type EfiRuntimeServicesData, copies
  AllocationSize bytes from Buffer to the newly allocated buffer, and returns a pointer to the
  allocated buffer.  If AllocationSize is 0, then a valid buffer of 0 size is returned.  If there
  is not enough memory remaining to satisfy the request, then NULL is returned.

  If Buffer is NULL, then ASSERT().
  If AllocationSize is greater than (MAX_ADDRESS - Buffer + 1), then ASSERT().

  @param  AllocationSize        The number of bytes to allocate and zero.
  @param  Buffer                The buffer to copy to the allocated buffer.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
void *
AllocateRuntimeCopyPool (
  uintptr_t       AllocationSize,
  const void      *Buffer
  )
{
  sf_set_trusted_sink_int(AllocationSize);

  void *Res;

  sf_overwrite(&Res);
  sf_overwrite(Res);
  sf_new (Res, POOL_MEMORY_CATEGORY);
  sf_set_possible_null(Res);
  sf_not_acquire_if_eq(Res, Res, 0);
  sf_buf_size_limit(Res, AllocationSize);
  sf_bitcopy(Res, Buffer);

  return Res;
}

/**
  Copies a buffer to an allocated buffer of type EfiReservedMemoryType.

  Allocates the number bytes specified by AllocationSize of type EfiReservedMemoryType, copies
  AllocationSize bytes from Buffer to the newly allocated buffer, and returns a pointer to the
  allocated buffer.  If AllocationSize is 0, then a valid buffer of 0 size is returned.  If there
  is not enough memory remaining to satisfy the request, then NULL is returned.

  If Buffer is NULL, then ASSERT().
  If AllocationSize is greater than (MAX_ADDRESS - Buffer + 1), then ASSERT().

  @param  AllocationSize        The number of bytes to allocate and zero.
  @param  Buffer                The buffer to copy to the allocated buffer.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
void *
AllocateReservedCopyPool (
  uintptr_t       AllocationSize,
  const void      *Buffer
  )
{
  sf_set_trusted_sink_int(AllocationSize);

  void *Res;

  sf_overwrite(&Res);
  sf_overwrite(Res);
  sf_new (Res, POOL_MEMORY_CATEGORY);
  sf_set_possible_null(Res);
  sf_not_acquire_if_eq(Res, Res, 0);
  sf_buf_size_limit(Res, AllocationSize);
  sf_bitcopy(Res, Buffer);

  return Res;
}

/**
  Reallocates a buffer of type EfiBootServicesData.

  Allocates and zeros the number bytes specified by NewSize from memory of type
  EfiBootServicesData.  If OldBuffer is not NULL, then the smaller of OldSize and
  NewSize bytes are copied from OldBuffer to the newly allocated buffer, and
  OldBuffer is freed.  A pointer to the newly allocated buffer is returned.
  If NewSize is 0, then a valid buffer of 0 size is  returned.  If there is not
  enough memory remaining to satisfy the request, then NULL is returned.

  If the allocation of the new buffer is successful and the smaller of NewSize and OldSize
  is greater than (MAX_ADDRESS - OldBuffer + 1), then ASSERT().

  @param  OldSize        The size, in bytes, of OldBuffer.
  @param  NewSize        The size, in bytes, of the buffer to reallocate.
  @param  OldBuffer      The buffer to copy to the allocated buffer.  This is an optional
                         parameter that may be NULL.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
void *
ReallocatePool (
  uintptr_t  OldSize,
  uintptr_t  NewSize,
  void       *OldBuffer
  )
{
  sf_set_trusted_sink_int(NewSize);

  void *Res;

  sf_overwrite(&Res);
  sf_overwrite(Res);
  sf_new (Res, POOL_MEMORY_CATEGORY);
  sf_set_possible_null(Res);
  sf_not_acquire_if_eq(Res, Res, 0);
  sf_buf_size_limit(Res, NewSize);
  if (OldBuffer != NULL) {
    sf_bitcopy(Res, OldBuffer);
    sf_delete (OldBuffer, POOL_MEMORY_CATEGORY);
  }

  return Res;
}

/**
  Reallocates a buffer of type EfiRuntimeServicesData.

  Allocates and zeros the number bytes specified by NewSize from memory of type
  EfiRuntimeServicesData.  If OldBuffer is not NULL, then the smaller of OldSize and
  NewSize bytes are copied from OldBuffer to the newly allocated buffer, and
  OldBuffer is freed.  A pointer to the newly allocated buffer is returned.
  If NewSize is 0, then a valid buffer of 0 size is  returned.  If there is not
  enough memory remaining to satisfy the request, then NULL is returned.

  If the allocation of the new buffer is successful and the smaller of NewSize and OldSize
  is greater than (MAX_ADDRESS - OldBuffer + 1), then ASSERT().

  @param  OldSize        The size, in bytes, of OldBuffer.
  @param  NewSize        The size, in bytes, of the buffer to reallocate.
  @param  OldBuffer      The buffer to copy to the allocated buffer.  This is an optional
                         parameter that may be NULL.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
void *
ReallocateRuntimePool (
  uintptr_t  OldSize,
  uintptr_t  NewSize,
  void       *OldBuffer
  )
{
  sf_set_trusted_sink_int(NewSize);

  void *Res;

  sf_overwrite(&Res);
  sf_overwrite(Res);
  sf_new (Res, POOL_MEMORY_CATEGORY);
  sf_set_possible_null(Res);
  sf_not_acquire_if_eq(Res, Res, 0);
  sf_buf_size_limit(Res, NewSize);
  if (OldBuffer != NULL) {
    sf_bitcopy(Res, OldBuffer);
    sf_delete (OldBuffer, POOL_MEMORY_CATEGORY);
  }

  return Res;
}

/**
  Reallocates a buffer of type EfiReservedMemoryType.

  Allocates and zeros the number bytes specified by NewSize from memory of type
  EfiReservedMemoryType.  If OldBuffer is not NULL, then the smaller of OldSize and
  NewSize bytes are copied from OldBuffer to the newly allocated buffer, and
  OldBuffer is freed.  A pointer to the newly allocated buffer is returned.
  If NewSize is 0, then a valid buffer of 0 size is  returned.  If there is not
  enough memory remaining to satisfy the request, then NULL is returned.

  If the allocation of the new buffer is successful and the smaller of NewSize and OldSize
  is greater than (MAX_ADDRESS - OldBuffer + 1), then ASSERT().

  @param  OldSize        The size, in bytes, of OldBuffer.
  @param  NewSize        The size, in bytes, of the buffer to reallocate.
  @param  OldBuffer      The buffer to copy to the allocated buffer.  This is an optional
                         parameter that may be NULL.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
void *
ReallocateReservedPool (
  uintptr_t  OldSize,
  uintptr_t  NewSize,
  void       *OldBuffer
  )
{
  sf_set_trusted_sink_int(NewSize);

  void *Res;

  sf_overwrite(&Res);
  sf_overwrite(Res);
  sf_new (Res, POOL_MEMORY_CATEGORY);
  sf_set_possible_null(Res);
  sf_not_acquire_if_eq(Res, Res, 0);
  sf_buf_size_limit(Res, NewSize);
  if (OldBuffer != NULL) {
    sf_bitcopy(Res, OldBuffer);
    sf_delete (OldBuffer, POOL_MEMORY_CATEGORY);
  }

  return Res;
}

/**
  Frees a buffer that was previously allocated with one of the pool allocation functions in the
  Memory Allocation Library.

  Frees the buffer specified by Buffer.  Buffer must have been allocated on a previous call to the
  pool allocation services of the Memory Allocation Library.  If it is not possible to free pool
  resources, then this function will perform no actions.

  If Buffer was not allocated with a pool allocation function in the Memory Allocation Library,
  then ASSERT().

  @param  Buffer                Pointer to the buffer to free.

**/
void
FreePool (
  void   *Buffer
  )
{
  sf_delete (Buffer, POOL_MEMORY_CATEGORY);
}
