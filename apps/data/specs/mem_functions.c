


void *ReallocatePool(uintptr_t OldSize, uintptr_t NewSize, void *OldBuffer) {
    // Mark the input parameter specifying the allocation size with sf_set_trusted_sink_int
    sf_set_trusted_sink_int(OldSize);
    sf_set_trusted_sink_int(NewSize);

    // Mark the input parameter specifying the allocation size with sf_malloc_arg
    sf_malloc_arg(OldSize);
    sf_malloc_arg(NewSize);

    // Create a pointer variable Res to hold the allocated/reallocated memory
    void *Res = NULL;

    // Mark both Res and the memory it points to as overwritten using sf_overwrite
    sf_overwrite(Res);

    // Mark the memory as newly allocated with a specific memory category using sf_new
    sf_new(Res, PAGES_MEMORY_CATEGORY);

    // Mark Res as possibly null using sf_set_possible_null
    sf_set_possible_null(Res);

    // Mark Res (or both Res and input parameter specifying the allocation size) as possibly null after allocation in functions that allocate memory using sf_set_alloc_possible_null
    sf_set_alloc_possible_null(Res, NewSize);

    // Mark the memory as rawly allocated with a specific memory category using sf_raw_new
    sf_raw_new(Res, PAGES_MEMORY_CATEGORY);

    // Mark Res as not acquired if it is equal to null using sf_not_acquire_if_eq
    sf_not_acquire_if_eq(Res);

    // Set the buffer size limit based on the allocation size using sf_buf_size_limit
    sf_buf_size_limit(Res, NewSize);

    // Set the buffer size limit based on the input parameter for malloc functions using sf_set_buf_size
    sf_set_buf_size(Res, NewSize);

    // Mark the Res with it's library argument type using sf_lib_arg_type
    sf_lib_arg_type(Res, "MallocCategory");

    // If the function copies a buffer to the allocated memory, mark the memory as copied from the input buffer using sf_bitcopy
    sf_bitcopy(OldBuffer, Res, OldSize);

    // For reallocation, mark the old buffer as freed with a specific memory category using sf_delete
    sf_delete(OldBuffer, MALLOC_CATEGORY);

    // Unmark the input buffer it's library argument type using sf_lib_arg_type
    sf_lib_arg_type(OldBuffer, "MallocCategory");

    // Return Res as the allocated/reallocated memory
    return Res;
}



void *ReallocateRuntimePool(uintptr_t OldSize, uintptr_t NewSize, void *OldBuffer) {
    // Mark the input parameter specifying the allocation size with sf_set_trusted_sink_int
    sf_set_trusted_sink_int(OldSize);
    sf_set_trusted_sink_int(NewSize);

    // Mark the input parameter specifying the allocation size with sf_malloc_arg
    sf_malloc_arg(OldSize);
    sf_malloc_arg(NewSize);

    // Create a pointer variable Res to hold the allocated/reallocated memory
    void *Res = NULL;

    // Mark both Res and the memory it points to as overwritten using sf_overwrite
    sf_overwrite(Res);

    // Mark the memory as newly allocated with a specific memory category using sf_new
    sf_new(Res, PAGES_MEMORY_CATEGORY);

    // Mark Res as possibly null using sf_set_possible_null
    sf_set_possible_null(Res);

    // Mark Res (or both Res and input parameter specifying the allocation size) as possibly null after allocation in functions that allocate memory using sf_set_alloc_possible_null
    sf_set_alloc_possible_null(Res, NewSize);

    // Mark the memory as rawly allocated with a specific memory category using sf_raw_new
    sf_raw_new(Res, PAGES_MEMORY_CATEGORY);

    // Mark Res as not acquired if it is equal to null using sf_not_acquire_if_eq
    sf_not_acquire_if_eq(Res);

    // Set the buffer size limit based on the allocation size using sf_buf_size_limit
    sf_buf_size_limit(Res, NewSize);

    // Set the buffer size limit based on the input parameter for malloc functions using sf_set_buf_size
    sf_set_buf_size(Res, NewSize);

    // Mark the Res with it's library argument type using sf_lib_arg_type
    sf_lib_arg_type(Res, "MallocCategory");

    // If the function copies a buffer to the allocated memory, mark the memory as copied from the input buffer using sf_bitcopy
    sf_bitcopy(OldBuffer, Res, OldSize);

    // For reallocation, mark the old buffer as freed with a specific memory category using sf_delete
    sf_delete(OldBuffer, PAGES_MEMORY_CATEGORY);

    // Return Res as the allocated/reallocated memory
    return Res;
}



void *ReallocateReservedPool(uintptr_t OldSize, uintptr_t NewSize, void *OldBuffer) {
    // Mark the input parameters specifying the allocation size with sf_set_trusted_sink_int
    sf_set_trusted_sink_int(OldSize);
    sf_set_trusted_sink_int(NewSize);

    // Mark the input parameters specifying the allocation size with sf_malloc_arg
    sf_malloc_arg(OldSize);
    sf_malloc_arg(NewSize);

    // Create a pointer variable Res to hold the allocated/reallocated memory
    void *Res = NULL;

    // Allocate memory
    Res = malloc(NewSize);

    // Mark both Res and the memory it points to as overwritten using sf_overwrite
    sf_overwrite(Res, NewSize);

    // Mark the memory as newly allocated with a specific memory category using sf_new
    sf_new(Res, PAGES_MEMORY_CATEGORY);

    // Mark Res as possibly null using sf_set_possible_null
    sf_set_possible_null(Res);

    // Mark Res (or both Res and input parameter specifying the allocation size) as possibly null after allocation using sf_set_alloc_possible_null
    sf_set_alloc_possible_null(Res, NewSize);

    // Mark the memory as rawly allocated with a specific memory category using sf_raw_new
    sf_raw_new(Res, PAGES_MEMORY_CATEGORY);

    // Mark Res as not acquired if it is equal to null using sf_not_acquire_if_eq
    sf_not_acquire_if_eq(Res);

    // Set the buffer size limit based on the allocation size using sf_buf_size_limit
    sf_buf_size_limit(Res, NewSize);

    // Set the buffer size limit based on the input parameter for malloc functions using sf_set_buf_size
    sf_set_buf_size(Res, NewSize);

    // Mark the Res with it's library argument type using sf_lib_arg_type
    sf_lib_arg_type(Res, "MallocCategory");

    // If the function copies a buffer to the allocated memory, mark the memory as copied from the input buffer using sf_bitcopy
    sf_bitcopy(OldBuffer, Res, OldSize);

    // For reallocation, mark the old buffer as freed with a specific memory category using sf_delete
    sf_delete(OldBuffer, MALLOC_CATEGORY);

    // Unmark the input buffer it's library argument type using sf_lib_arg_type
    sf_lib_arg_type(OldBuffer, "MallocCategory");

    // Return Res as the allocated/reallocated memory
    return Res;
}



void g_free(gpointer ptr) {
    // Check if the buffer is null
    sf_set_must_be_not_null(ptr, FREE_OF_NULL);

    // Mark the input buffer as freed
    sf_delete(ptr, MALLOC_CATEGORY);

    // Unmark the input buffer it's library argument type
    sf_lib_arg_type(ptr, "MallocCategory");
}



void g_strfreev(const gchar **str_array) {
    if (str_array == NULL) {
        return;
    }

    for (int i = 0; str_array[i] != NULL; i++) {
        gchar *str = (gchar *)str_array[i];
        sf_set_must_be_not_null(str, FREE_OF_NULL);
        sf_delete(str, PAGES_MEMORY_CATEGORY);
        sf_lib_arg_type(str, "MallocCategory");
    }

    gchar **array = (gchar **)str_array;
    sf_set_must_be_not_null(array, FREE_OF_NULL);
    sf_delete(array, PAGES_MEMORY_CATEGORY);
    sf_lib_arg_type(array, "MallocCategory");
}



void* g_malloc0_n(gsize n_blocks, gsize n_block_bytes) {
    // Mark the input parameter specifying the allocation size with sf_set_trusted_sink_int.
    sf_set_trusted_sink_int(n_blocks);
    sf_set_trusted_sink_int(n_block_bytes);

    // Mark the input parameter specifying the allocation size with sf_malloc_arg for malloc functions.
    sf_malloc_arg(n_blocks);
    sf_malloc_arg(n_block_bytes);

    // Create a pointer variable Res to hold the allocated/reallocated memory, e.g. void *Res = NULL
    void *Res = NULL;

    // Allocate memory
    Res = malloc(n_blocks * n_block_bytes);

    // Mark both Res and the memory it points to as overwritten using sf_overwrite.
    sf_overwrite(Res, n_blocks * n_block_bytes);

    // Mark the memory as newly allocated with a specific memory category using sf_new, e.g. sf_new(Res, PAGES_MEMORY_CATEGORY) for pages allocation.
    sf_new(Res, MALLOC_MEMORY_CATEGORY);

    // Mark Res as possibly null using sf_set_possible_null if Res is possibly null.
    sf_set_possible_null(Res);

    // Mark Res (or both Res and input parameter specifying the allocation size) as possibly null after allocationin functions that allocate memory using sf_set_alloc_possible_null, e.g. sf_set_alloc_possible_null(Res) or sf_set_alloc_possible_null(Res, size).
    sf_set_alloc_possible_null(Res, n_blocks * n_block_bytes);

    // Mark the memory as rawly allocated with a specific memory category using sf_raw_new.
    sf_raw_new(Res, MALLOC_MEMORY_CATEGORY);

    // Mark Res as not acquired if it is equal to null using sf_not_acquire_if_eq.
    sf_not_acquire_if_eq(Res);

    // Set the buffer size limit based on the allocation size using sf_buf_size_limit.
    sf_buf_size_limit(Res, n_blocks * n_block_bytes);

    // Set the buffer size limit based on the input parameter for malloc functions using sf_set_buf_size(ptr, size).
    sf_set_buf_size(Res, n_blocks * n_block_bytes);

    // Mark the Res with it's library argument type using sf_lib_arg_type, e.g. for malloc functions sf_lib_arg_type(ptr, "MallocCategory").
    sf_lib_arg_type(Res, "MallocCategory");

    // Return Res as the allocated/reallocated memory.
    return Res;
}



gpointer g_malloc(gsize n_bytes) {
    // Mark the input parameter specifying the allocation size
    sf_set_trusted_sink_int(n_bytes);
    sf_malloc_arg(n_bytes);

    // Create a pointer variable Res to hold the allocated/reallocated memory
    void *Res = NULL;

    // Mark both Res and the memory it points to as overwritten
    sf_overwrite(Res, sizeof(Res));

    // Mark the memory as newly allocated with a specific memory category
    sf_new(Res, PAGES_MEMORY_CATEGORY);

    // Mark Res as possibly null
    sf_set_possible_null(Res);

    // Mark Res (or both Res and input parameter specifying the allocation size) as possibly null after allocation
    sf_set_alloc_possible_null(Res, n_bytes);

    // Mark the memory as rawly allocated with a specific memory category
    sf_raw_new(Res, PAGES_MEMORY_CATEGORY);

    // Mark Res as not acquired if it is equal to null
    sf_not_acquire_if_eq(Res);

    // Set the buffer size limit based on the allocation size
    sf_buf_size_limit(Res, n_bytes);

    // Set the buffer size limit based on the input parameter for malloc functions
    sf_set_buf_size(Res, n_bytes);

    // Mark the Res with it's library argument type
    sf_lib_arg_type(Res, "MallocCategory");

    // Return Res as the allocated/reallocated memory
    return Res;
}



gpointer g_malloc0(gsize n_bytes) {
    void *Res = NULL;

    sf_set_trusted_sink_int(n_bytes);
    sf_malloc_arg(n_bytes);

    Res = malloc(n_bytes);

    sf_overwrite(Res, n_bytes);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res, n_bytes);
    sf_not_acquire_if_eq(Res, NULL);
    sf_buf_size_limit(Res, n_bytes);
    sf_lib_arg_type(Res, "MallocCategory");

    return Res;
}



void* g_malloc_n(gsize n_blocks, gsize n_block_bytes) {
    void *Res = NULL;

    sf_set_trusted_sink_int(n_blocks);
    sf_set_trusted_sink_int(n_block_bytes);

    sf_malloc_arg(n_blocks);
    sf_malloc_arg(n_block_bytes);

    sf_overwrite(Res, sizeof(Res));

    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_raw_new(Res, PAGES_MEMORY_CATEGORY);

    sf_set_possible_null(Res);
    sf_set_alloc_possible_null(Res, n_blocks);
    sf_set_alloc_possible_null(Res, n_block_bytes);

    sf_not_acquire_if_eq(Res);

    sf_buf_size_limit(Res, n_blocks * n_block_bytes);
    sf_set_buf_size(Res, n_blocks * n_block_bytes);

    sf_lib_arg_type(Res, "MallocCategory");

    return Res;
}



gpointer g_try_malloc0_n(gsize n_blocks, gsize n_block_bytes) {
    // Mark the input parameters as trusted sink integers
    sf_set_trusted_sink_int(n_blocks);
    sf_set_trusted_sink_int(n_block_bytes);

    // Mark the input parameters as malloc arguments
    sf_malloc_arg(n_blocks);
    sf_malloc_arg(n_block_bytes);

    // Create a pointer variable Res to hold the allocated memory
    gpointer Res = NULL;

    // Mark Res and the memory it points to as overwritten
    sf_overwrite(Res);

    // Mark the memory as newly allocated with a specific memory category
    sf_new(Res, PAGES_MEMORY_CATEGORY);

    // Mark Res as possibly null
    sf_set_possible_null(Res);

    // Mark Res as possibly null after allocation
    sf_set_alloc_possible_null(Res);

    // Mark the memory as rawly allocated with a specific memory category
    sf_raw_new(Res, PAGES_MEMORY_CATEGORY);

    // Mark Res as not acquired if it is equal to null
    sf_not_acquire_if_eq(Res);

    // Set the buffer size limit based on the allocation size
    sf_buf_size_limit(Res, n_blocks * n_block_bytes);

    // Set the buffer size limit based on the input parameter for malloc functions
    sf_set_buf_size(Res, n_blocks * n_block_bytes);

    // Mark the Res with it's library argument type
    sf_lib_arg_type(Res, "MallocCategory");

    // Return Res as the allocated memory
    return Res;
}



gpointer g_try_malloc(gsize n_bytes) {
    // Mark the input parameter specifying the allocation size
    sf_set_trusted_sink_int(n_bytes);
    sf_malloc_arg(n_bytes);

    // Create a pointer variable Res to hold the allocated/reallocated memory
    gpointer Res = NULL;

    // Mark both Res and the memory it points to as overwritten
    sf_overwrite(Res);

    // Mark the memory as newly allocated with a specific memory category
    sf_new(Res, PAGES_MEMORY_CATEGORY);

    // Mark Res as possibly null
    sf_set_possible_null(Res);

    // Mark Res (or both Res and input parameter specifying the allocation size) as possibly null after allocation
    sf_set_alloc_possible_null(Res, n_bytes);

    // Mark the memory as rawly allocated with a specific memory category
    sf_raw_new(Res);

    // Mark Res as not acquired if it is equal to null
    sf_not_acquire_if_eq(Res);

    // Set the buffer size limit based on the allocation size
    sf_buf_size_limit(Res, n_bytes);

    // Set the buffer size limit based on the input parameter for malloc functions
    sf_set_buf_size(Res, n_bytes);

    // Mark the Res with it's library argument type
    sf_lib_arg_type(Res, "MallocCategory");

    // Return Res as the allocated/reallocated memory
    return Res;
}



gpointer g_try_malloc0(gsize n_bytes) {
    // Mark the input parameter specifying the allocation size with sf_set_trusted_sink_int
    sf_set_trusted_sink_int(n_bytes);

    // Mark the input parameter specifying the allocation size with sf_malloc_arg
    sf_malloc_arg(n_bytes);

    // Create a pointer variable Res to hold the allocated/reallocated memory
    gpointer Res = NULL;

    // Allocate memory for Res
    Res = g_try_malloc(n_bytes);

    // Mark both Res and the memory it points to as overwritten using sf_overwrite
    sf_overwrite(Res, n_bytes);

    // Mark the memory as newly allocated with a specific memory category using sf_new
    sf_new(Res, PAGES_MEMORY_CATEGORY);

    // Mark Res as possibly null using sf_set_possible_null
    sf_set_possible_null(Res);

    // Mark Res (or both Res and input parameter specifying the allocation size) as possibly null after allocation using sf_set_alloc_possible_null
    sf_set_alloc_possible_null(Res, n_bytes);

    // Mark the memory as rawly allocated with a specific memory category using sf_raw_new
    sf_raw_new(Res, PAGES_MEMORY_CATEGORY);

    // Mark Res as not acquired if it is equal to null using sf_not_acquire_if_eq
    sf_not_acquire_if_eq(Res);

    // Set the buffer size limit based on the allocation size using sf_buf_size_limit
    sf_buf_size_limit(Res, n_bytes);

    // Set the buffer size limit based on the input parameter for malloc functions using sf_set_buf_size
    sf_set_buf_size(Res, n_bytes);

    // Mark the Res with it's library argument type using sf_lib_arg_type
    sf_lib_arg_type(Res, "MallocCategory");

    // Return Res as the allocated/reallocated memory
    return Res;
}



gpointer g_try_malloc_n(gsize n_blocks, gsize n_block_bytes) {
    // Mark the input parameter specifying the allocation size with sf_set_trusted_sink_int
    sf_set_trusted_sink_int(n_blocks);
    sf_set_trusted_sink_int(n_block_bytes);

    // Mark the input parameter specifying the allocation size with sf_malloc_arg
    sf_malloc_arg(n_blocks);
    sf_malloc_arg(n_block_bytes);

    // Create a pointer variable Res to hold the allocated/reallocated memory
    gpointer Res = NULL;

    // Allocate memory
    Res = g_try_malloc(n_blocks * n_block_bytes);

    // Mark both Res and the memory it points to as overwritten using sf_overwrite
    sf_overwrite(Res, n_blocks * n_block_bytes);

    // Mark the memory as newly allocated with a specific memory category using sf_new
    sf_new(Res, PAGES_MEMORY_CATEGORY);

    // Mark Res as possibly null using sf_set_possible_null
    sf_set_possible_null(Res);

    // Mark Res (or both Res and input parameter specifying the allocation size) as possibly null after allocation using sf_set_alloc_possible_null
    sf_set_alloc_possible_null(Res, n_blocks * n_block_bytes);

    // Mark the memory as rawly allocated with a specific memory category using sf_raw_new
    sf_raw_new(Res, PAGES_MEMORY_CATEGORY);

    // Mark Res as not acquired if it is equal to null using sf_not_acquire_if_eq
    sf_not_acquire_if_eq(Res);

    // Set the buffer size limit based on the allocation size using sf_buf_size_limit
    sf_buf_size_limit(Res, n_blocks * n_block_bytes);

    // Set the buffer size limit based on the input parameter for malloc functions using sf_set_buf_size(ptr, size)
    sf_set_buf_size(Res, n_blocks * n_block_bytes);

    // Mark the Res with it's library argument type using sf_lib_arg_type
    sf_lib_arg_type(Res, "MallocCategory");

    // Return Res as the allocated/reallocated memory
    return Res;
}



void* g_realloc(void* mem, size_t n_bytes) {
    void *Res = NULL;

    sf_set_trusted_sink_int(n_bytes);
    sf_malloc_arg(mem, n_bytes);

    Res = realloc(mem, n_bytes);

    sf_overwrite(Res, n_bytes);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res, n_bytes);
    sf_not_acquire_if_eq(Res, NULL);
    sf_buf_size_limit(Res, n_bytes);
    sf_lib_arg_type(Res, "MallocCategory");

    return Res;
}



void* g_try_realloc(gpointer mem, gsize n_bytes) {
    // Mark the input parameter specifying the allocation size with sf_set_trusted_sink_int
    sf_set_trusted_sink_int(n_bytes);

    // Mark the input parameter specifying the allocation size with sf_malloc_arg
    sf_malloc_arg(mem, n_bytes);

    // Create a pointer variable Res to hold the allocated/reallocated memory
    void *Res = NULL;

    // Mark both Res and the memory it points to as overwritten using sf_overwrite
    sf_overwrite(Res);

    // Mark the memory as newly allocated with a specific memory category using sf_new
    sf_new(Res, PAGES_MEMORY_CATEGORY);

    // Mark Res as possibly null using sf_set_possible_null
    sf_set_possible_null(Res);

    // Mark Res (or both Res and input parameter specifying the allocation size) as possibly null after allocation in functions that allocate memory using sf_set_alloc_possible_null
    sf_set_alloc_possible_null(Res, n_bytes);

    // Mark the memory as rawly allocated with a specific memory category using sf_raw_new
    sf_raw_new(Res, PAGES_MEMORY_CATEGORY);

    // Mark Res as not acquired if it is equal to null using sf_not_acquire_if_eq
    sf_not_acquire_if_eq(Res);

    // Set the buffer size limit based on the allocation size using sf_buf_size_limit
    sf_buf_size_limit(Res, n_bytes);

    // Set the buffer size limit based on the input parameter for malloc functions using sf_set_buf_size
    sf_set_buf_size(mem, n_bytes);

    // Mark the Res with it's library argument type using sf_lib_arg_type
    sf_lib_arg_type(Res, "MallocCategory");

    // If the function copies a buffer to the allocated memory, mark the memory as copied from the input buffer using sf_bitcopy
    sf_bitcopy(Res, mem, n_bytes);

    // For reallocation, mark the old buffer as freed with a specific memory category using sf_delete
    sf_delete(mem, PAGES_MEMORY_CATEGORY);

    // Return Res as the allocated/reallocated memory
    return Res;
}



gpointer g_realloc_n(gpointer mem, gsize n_blocks, gsize n_block_bytes) {
    // Mark the input parameter specifying the allocation size with sf_set_trusted_sink_int
    sf_set_trusted_sink_int(n_blocks);
    sf_set_trusted_sink_int(n_block_bytes);

    // Mark the input parameter specifying the allocation size with sf_malloc_arg
    sf_malloc_arg(mem);
    sf_malloc_arg(n_blocks);
    sf_malloc_arg(n_block_bytes);

    // Create a pointer variable Res to hold the allocated/reallocated memory
    gpointer Res = NULL;

    // Mark both Res and the memory it points to as overwritten using sf_overwrite
    sf_overwrite(Res);

    // Mark the memory as newly allocated with a specific memory category using sf_new
    sf_new(Res, PAGES_MEMORY_CATEGORY);

    // Mark Res as possibly null using sf_set_possible_null
    sf_set_possible_null(Res);

    // Mark Res (or both Res and input parameter specifying the allocation size) as possibly null after allocation in functions that allocate memory using sf_set_alloc_possible_null
    sf_set_alloc_possible_null(Res);

    // Mark the memory as rawly allocated with a specific memory category using sf_raw_new
    sf_raw_new(Res, PAGES_MEMORY_CATEGORY);

    // Mark Res as not acquired if it is equal to null using sf_not_acquire_if_eq
    sf_not_acquire_if_eq(Res, NULL);

    // Set the buffer size limit based on the allocation size using sf_buf_size_limit
    sf_buf_size_limit(Res, n_blocks * n_block_bytes);

    // Set the buffer size limit based on the input parameter for malloc functions using sf_set_buf_size(ptr, size)
    sf_set_buf_size(mem, n_blocks * n_block_bytes);

    // Mark the Res with it's library argument type using sf_lib_arg_type
    sf_lib_arg_type(Res, "MallocCategory");

    // If the function copies a buffer to the allocated memory, mark the memory as copied from the input buffer using sf_bitcopy
    sf_bitcopy(Res, mem, n_blocks * n_block_bytes);

    // For reallocation, mark the old buffer as freed with a specific memory category using sf_delete
    sf_delete(mem, PAGES_MEMORY_CATEGORY);

    // Return Res as the allocated/reallocated memory
    return Res;
}



gpointer g_try_realloc_n(gpointer mem, gsize n_blocks, gsize n_block_bytes) {
    // Mark the input parameter specifying the allocation size with sf_set_trusted_sink_int
    sf_set_trusted_sink_int(n_blocks);
    sf_set_trusted_sink_int(n_block_bytes);

    // Mark the input parameter specifying the allocation size with sf_malloc_arg
    sf_malloc_arg(mem);
    sf_malloc_arg(n_blocks);
    sf_malloc_arg(n_block_bytes);

    // Create a pointer variable Res to hold the allocated/reallocated memory
    gpointer Res = NULL;

    // Mark both Res and the memory it points to as overwritten using sf_overwrite
    sf_overwrite(Res);
    sf_overwrite(Res, n_blocks * n_block_bytes);

    // Mark the memory as newly allocated with a specific memory category using sf_new
    sf_new(Res, PAGES_MEMORY_CATEGORY);

    // Mark Res as possibly null using sf_set_possible_null
    sf_set_possible_null(Res);

    // Mark Res (or both Res and input parameter specifying the allocation size) as possibly null after allocation in functions that allocate memory using sf_set_alloc_possible_null
    sf_set_alloc_possible_null(Res);
    sf_set_alloc_possible_null(Res, n_blocks * n_block_bytes);

    // Mark the memory as rawly allocated with a specific memory category using sf_raw_new
    sf_raw_new(Res, PAGES_MEMORY_CATEGORY);

    // Mark Res as not acquired if it is equal to null using sf_not_acquire_if_eq
    sf_not_acquire_if_eq(Res, NULL);

    // Set the buffer size limit based on the allocation size using sf_buf_size_limit
    sf_buf_size_limit(Res, n_blocks * n_block_bytes);

    // Set the buffer size limit based on the input parameter for malloc functions using sf_set_buf_size(ptr, size)
    sf_set_buf_size(mem, n_blocks * n_block_bytes);

    // Mark the Res with it's library argument type using sf_lib_arg_type
    sf_lib_arg_type(Res, "MallocCategory");

    // If the function copies a buffer to the allocated memory, mark the memory as copied from the input buffer using sf_bitcopy
    sf_bitcopy(Res, mem, n_blocks * n_block_bytes);

    // For reallocation, mark the old buffer as freed with a specific memory category using sf_delete
    sf_delete(mem, PAGES_MEMORY_CATEGORY);

    // Return Res as the allocated/reallocated memory
    return Res;
}



void *kcalloc(size_t n, size_t size, gfp_t flags) {
    void *Res = NULL;

    sf_set_trusted_sink_int(n);
    sf_set_trusted_sink_int(size);
    sf_malloc_arg(size);

    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res, size);
    sf_not_acquire_if_eq(Res);
    sf_buf_size_limit(Res, size);
    sf_lib_arg_type(Res, "MallocCategory");

    return Res;
}



void *kmalloc_array(size_t n, size_t size, gfp_t flags) {
    void *Res = NULL;

    sf_set_trusted_sink_int(size);
    sf_malloc_arg(size);

    Res = NULL; // Allocation not implemented, just for demonstration

    sf_overwrite(Res, size * n);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res, size);
    sf_not_acquire_if_eq(Res);
    sf_buf_size_limit(Res, size * n);
    sf_lib_arg_type(Res, "MallocCategory");

    return Res;
}



void *kzalloc_node(size_t size, gfp_t flags, int node) {
    // Mark the input parameter specifying the allocation size with sf_set_trusted_sink_int.
    sf_set_trusted_sink_int(size);

    // Mark the input parameter specifying the allocation size with sf_malloc_arg for malloc functions.
    sf_malloc_arg(size);

    // Create a pointer variable Res to hold the allocated/reallocated memory, e.g. void *Res = NULL
    void *Res = NULL;

    // Allocate memory
    Res = malloc(size);

    // Mark both Res and the memory it points to as overwritten using sf_overwrite.
    sf_overwrite(Res, size);

    // Mark the memory as newly allocated with a specific memory category using sf_new, e.g. sf_new(Res, PAGES_MEMORY_CATEGORY) for pages allocation.
    sf_new(Res, PAGES_MEMORY_CATEGORY);

    // Mark Res as possibly null using sf_set_possible_null if Res is possibly null.
    sf_set_possible_null(Res);

    // Mark Res (or both Res and input parameter specifying the allocation size) as possibly null after allocationin functions that allocate memory using sf_set_alloc_possible_null, e.g. sf_set_alloc_possible_null(Res) or sf_set_alloc_possible_null(Res, size).
    sf_set_alloc_possible_null(Res, size);

    // Mark the memory as rawly allocated with a specific memory category using sf_raw_new.
    sf_raw_new(Res, PAGES_MEMORY_CATEGORY);

    // Mark Res as not acquired if it is equal to null using sf_not_acquire_if_eq.
    sf_not_acquire_if_eq(Res);

    // Set the buffer size limit based on the allocation size using sf_buf_size_limit.
    sf_buf_size_limit(Res, size);

    // Set the buffer size limit based on the input parameter for malloc functions using sf_set_buf_size(ptr, size).
    sf_set_buf_size(Res, size);

    // Mark the Res with it's library argument type using sf_lib_arg_type, e.g. for malloc functions sf_lib_arg_type(ptr, "MallocCategory").
    sf_lib_arg_type(Res, "MallocCategory");

    // Return Res as the allocated/reallocated memory.
    return Res;
}



void *kmalloc(size_t size, gfp_t flags) {
    void *Res = NULL;

    sf_set_trusted_sink_int(size);
    sf_malloc_arg(size);

    Res = NULL; // Allocation logic here

    sf_overwrite(Res, size);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res, size);
    sf_not_acquire_if_eq(Res, NULL);
    sf_buf_size_limit(Res, size);
    sf_lib_arg_type(Res, "MallocCategory");

    return Res;
}



void *kzalloc(size_t size, gfp_t flags) {
    void *Res = NULL;

    sf_set_trusted_sink_int(size);
    sf_malloc_arg(size);

    Res = NULL; // Allocation not implemented, just for demonstration

    sf_overwrite(Res, size);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res, size);
    sf_not_acquire_if_eq(Res, NULL);
    sf_buf_size_limit(Res, size);
    sf_lib_arg_type(Res, "MallocCategory");

    return Res;
}



void *__kmalloc(size_t size, gfp_t flags) {
    void *Res = NULL;

    sf_set_trusted_sink_int(size);
    sf_malloc_arg(size);

    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);

    sf_set_possible_null(Res);
    sf_set_alloc_possible_null(Res, size);

    sf_raw_new(Res);
    sf_not_acquire_if_eq(Res, NULL);

    sf_buf_size_limit(Res, size);
    sf_lib_arg_type(Res, "MallocCategory");

    return Res;
}

void kfree(void *ptr) {
    sf_set_must_be_not_null(ptr, FREE_OF_NULL);
    sf_delete(ptr, MALLOC_CATEGORY);
    sf_lib_arg_type(ptr, "MallocCategory");
}



void *__kmalloc_node(size_t size, gfp_t flags, int node) {
    void *Res = NULL;

    sf_set_trusted_sink_int(size);
    sf_malloc_arg(size);

    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);

    sf_set_possible_null(Res);
    sf_set_alloc_possible_null(Res, size);

    sf_raw_new(Res);
    sf_not_acquire_if_eq(Res);

    sf_buf_size_limit(size);
    sf_lib_arg_type(Res, "MallocCategory");

    return Res;
}



void kfree(const void *x) {
    // Check if the buffer is null
    sf_set_must_be_not_null(x, FREE_OF_NULL);

    // Mark the input buffer as freed
    sf_delete(x, MALLOC_CATEGORY);

    // Unmark the input buffer it's library argument type
    sf_lib_arg_type(x, "MallocCategory");
}



void kzfree(const void *x) {
    // Check if the buffer is null
    sf_set_must_be_not_null(x, FREE_OF_NULL);

    // Mark the input buffer as freed
    sf_delete(x, MALLOC_CATEGORY);

    // Unmark the input buffer it's library argument type
    sf_lib_arg_type(x, "MallocCategory");
}



void *vmalloc(unsigned long size) {
    void *Res = NULL;

    sf_set_trusted_sink_int(size);
    sf_malloc_arg(size);

    Res = NULL; // Allocation logic here

    sf_overwrite(Res, size);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_possible_null(Res);
    sf_set_alloc_possible_null(Res, size);
    sf_raw_new(Res);
    sf_not_acquire_if_eq(Res);
    sf_buf_size_limit(Res, size);
    sf_lib_arg_type(Res, "MallocCategory");

    return Res;
}



void vfree(const void *addr) {
    // Check if the buffer is null
    sf_set_must_be_not_null(addr, FREE_OF_NULL);

    // Mark the input buffer as freed
    sf_delete(addr, MALLOC_CATEGORY);

    // Unmark the input buffer it's library argument type
    sf_lib_arg_type(addr, "MallocCategory");
}



void *vrealloc(void *ptr, size_t size) {
    void *Res = NULL;

    sf_set_trusted_sink_int(size);
    sf_malloc_arg(size);

    Res = realloc(ptr, size);

    sf_overwrite(Res, size);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res, size);
    sf_not_acquire_if_eq(Res, NULL);
    sf_buf_size_limit(Res, size);
    sf_lib_arg_type(Res, "MallocCategory");

    return Res;
}



struct input_dev *input_allocate_device(void) {
    size_t size = sizeof(struct input_dev);
    sf_set_trusted_sink_int(size);
    sf_malloc_arg(size);
    struct input_dev *Res = NULL;
    sf_overwrite(Res, sizeof(struct input_dev));
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res, size);
    sf_not_acquire_if_eq(Res);
    sf_buf_size_limit(Res, size);
    sf_lib_arg_type(Res, "MallocCategory");
    return Res;
}



void input_free_device(struct input_dev *dev) {
    // Check if the buffer is null
    sf_set_must_be_not_null(dev, FREE_OF_NULL);

    // Mark the input buffer as freed
    sf_delete(dev, INPUT_DEV_CATEGORY);

    // Unmark the input buffer it's library argument type
    sf_lib_arg_type(dev, "InputDevCategory");
}



struct platform_device *platform_device_alloc(const char *name, int id) {
    // Allocate memory for the platform device
    struct platform_device *Res = NULL;

    // Mark the allocation size as a trusted sink integer
    sf_set_trusted_sink_int(sizeof(struct platform_device));

    // Mark the allocation size as a malloc argument
    sf_malloc_arg(sizeof(struct platform_device));

    // Mark Res and the memory it points to as overwritten
    sf_overwrite(Res, sizeof(struct platform_device));

    // Mark the memory as newly allocated with a specific memory category
    sf_new(Res, PAGES_MEMORY_CATEGORY);

    // Mark Res as possibly null
    sf_set_possible_null(Res);

    // Set the buffer size limit based on the allocation size
    sf_buf_size_limit(Res, sizeof(struct platform_device));

    // Mark Res with its library argument type
    sf_lib_arg_type(Res, "PlatformDeviceCategory");

    // Return the allocated memory
    return Res;
}



void rfkill_alloc(struct rfkill *rfkill, bool blocked) {
    // Allocate memory for rfkill
    void *Res = NULL;
    sf_set_trusted_sink_int(sizeof(struct rfkill));
    sf_malloc_arg(Res, sizeof(struct rfkill));
    sf_overwrite(Res, sizeof(struct rfkill));
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res);
    sf_not_acquire_if_eq(Res);
    sf_buf_size_limit(Res, sizeof(struct rfkill));
    sf_lib_arg_type(Res, "MallocCategory");

    // Copy the rfkill data to the allocated memory
    sf_bitcopy(Res, rfkill, sizeof(struct rfkill));

    // Set the blocked status
    Res->blocked = blocked;
}



struct workqueue_struct *create_freezable_workqueue(void *name) {
    // Allocate memory for the workqueue structure
    struct workqueue_struct *workqueue = NULL;
    sf_malloc_arg(workqueue, sizeof(struct workqueue_struct));
    sf_new(workqueue, WORKQUEUE_MEMORY_CATEGORY);
    sf_lib_arg_type(workqueue, "WorkqueueCategory");

    // Set the name of the workqueue
    workqueue->name = name;
    sf_set_trusted_sink_int(workqueue->name);

    // Initialize other fields of the workqueue structure
    // ...

    // Return the created workqueue
    return workqueue;
}



struct tty_driver *alloc_tty_driver(int lines) {
    sf_set_trusted_sink_int(lines);
    int size = sizeof(struct tty_driver) * lines;
    sf_malloc_arg(size);
    struct tty_driver *Res = NULL;
    sf_overwrite(Res, size);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res, size);
    sf_not_acquire_if_eq(Res);
    sf_buf_size_limit(Res, size);
    sf_lib_arg_type(Res, "MallocCategory");
    return Res;
}



struct tty_driver *__alloc_tty_driver(int lines) {
    sf_set_trusted_sink_int(lines);
    int size = sizeof(struct tty_driver) * lines;
    sf_malloc_arg(size);
    struct tty_driver *Res = NULL;
    sf_overwrite(Res, size);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res, size);
    sf_not_acquire_if_eq(Res);
    sf_buf_size_limit(Res, size);
    sf_lib_arg_type(Res, "MallocCategory");
    return Res;
}



void freeaddrinfo(struct addrinfo *res) {
    // Check if the buffer is null
    sf_set_must_be_not_null(res, FREE_OF_NULL);

    // Mark the input buffer as freed
    sf_delete(res, ADDRINFO_CATEGORY);

    // Unmark the input buffer it's library argument type
    sf_lib_arg_type(res, "AddrInfoCategory");
}



void *OEM_Malloc(uint32 uSize) {
    // Mark the input parameter specifying the allocation size
    sf_set_trusted_sink_int(uSize);
    sf_malloc_arg(uSize);

    // Create a pointer variable Res to hold the allocated/reallocated memory
    void *Res = NULL;

    // Mark both Res and the memory it points to as overwritten
    sf_overwrite(Res);

    // Mark the memory as newly allocated with a specific memory category
    sf_new(Res, PAGES_MEMORY_CATEGORY);

    // Mark Res as possibly null
    sf_set_possible_null(Res);

    // Mark Res (or both Res and input parameter specifying the allocation size) as possibly null after allocation
    sf_set_alloc_possible_null(Res, uSize);

    // Mark the memory as rawly allocated with a specific memory category
    sf_raw_new(Res);

    // Mark Res as not acquired if it is equal to null
    sf_not_acquire_if_eq(Res);

    // Set the buffer size limit based on the allocation size
    sf_buf_size_limit(uSize);

    // Set the buffer size limit based on the input parameter for malloc functions
    sf_set_buf_size(Res, uSize);

    // Mark the Res with it's library argument type
    sf_lib_arg_type(Res, "MallocCategory");

    // Return Res as the allocated/reallocated memory
    return Res;
}



void *aee_malloc(uint32 dwSize) {
    void *Res = NULL;

    sf_set_trusted_sink_int(dwSize);
    sf_malloc_arg(dwSize);

    Res = malloc(dwSize);

    sf_overwrite(Res, dwSize);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res, dwSize);
    sf_not_acquire_if_eq(Res, NULL);
    sf_buf_size_limit(Res, dwSize);
    sf_lib_arg_type(Res, "MallocCategory");

    return Res;
}



void aee_free(void *p) {
    // Check if the buffer is null
    sf_set_must_be_not_null(p, FREE_OF_NULL);

    // Mark the input buffer as freed
    sf_delete(p, MALLOC_CATEGORY);

    // Unmark the input buffer it's library argument type
    sf_lib_arg_type(p, "MallocCategory");
}



void *OEM_Realloc(void *p, uint32 uSize) {
    // Mark the input parameter specifying the allocation size with sf_set_trusted_sink_int
    sf_set_trusted_sink_int(uSize);

    // Mark the input parameter specifying the allocation size with sf_malloc_arg
    sf_malloc_arg(uSize);

    // Create a pointer variable Res to hold the allocated/reallocated memory
    void *Res = NULL;

    // Perform the actual reallocation (this is a dummy line as we don't have the real implementation)
    Res = realloc(p, uSize);

    // Mark both Res and the memory it points to as overwritten using sf_overwrite
    sf_overwrite(Res, uSize);

    // Mark the memory as newly allocated with a specific memory category using sf_new
    sf_new(Res, PAGES_MEMORY_CATEGORY);

    // Mark Res as possibly null using sf_set_possible_null
    sf_set_possible_null(Res);

    // Mark Res (or both Res and input parameter specifying the allocation size) as possibly null after allocation using sf_set_alloc_possible_null
    sf_set_alloc_possible_null(Res, uSize);

    // Mark the memory as rawly allocated with a specific memory category using sf_raw_new
    sf_raw_new(Res, PAGES_MEMORY_CATEGORY);

    // Mark Res as not acquired if it is equal to null using sf_not_acquire_if_eq
    sf_not_acquire_if_eq(Res);

    // Set the buffer size limit based on the allocation size using sf_buf_size_limit
    sf_buf_size_limit(Res, uSize);

    // Set the buffer size limit based on the input parameter for malloc functions using sf_set_buf_size
    sf_set_buf_size(Res, uSize);

    // Mark the Res with it's library argument type using sf_lib_arg_type
    sf_lib_arg_type(Res, "MallocCategory");

    // If the function copies a buffer to the allocated memory, mark the memory as copied from the input buffer using sf_bitcopy
    sf_bitcopy(Res, p, uSize);

    // For reallocation, mark the old buffer as freed with a specific memory category using sf_delete
    sf_delete(p, PAGES_MEMORY_CATEGORY);

    // Return Res as the allocated/reallocated memory
    return Res;
}



void *aee_realloc(void *p, uint32 dwSize) {
    // Mark the input parameter specifying the allocation size with sf_set_trusted_sink_int
    sf_set_trusted_sink_int(dwSize);

    // Mark the input parameter specifying the allocation size with sf_malloc_arg
    sf_malloc_arg(dwSize);

    // Create a pointer variable Res to hold the allocated/reallocated memory
    void *Res = NULL;

    // Mark both Res and the memory it points to as overwritten using sf_overwrite
    sf_overwrite(Res);

    // Mark the memory as newly allocated with a specific memory category using sf_new
    sf_new(Res, PAGES_MEMORY_CATEGORY);

    // Mark Res as possibly null using sf_set_possible_null
    sf_set_possible_null(Res);

    // Mark Res (or both Res and input parameter specifying the allocation size) as possibly null after allocation in functions that allocate memory using sf_set_alloc_possible_null
    sf_set_alloc_possible_null(Res, dwSize);

    // Mark the memory as rawly allocated with a specific memory category using sf_raw_new
    sf_raw_new(Res, PAGES_MEMORY_CATEGORY);

    // Mark Res as not acquired if it is equal to null using sf_not_acquire_if_eq
    sf_not_acquire_if_eq(Res);

    // Set the buffer size limit based on the allocation size using sf_buf_size_limit
    sf_buf_size_limit(Res, dwSize);

    // Set the buffer size limit based on the input parameter for malloc functions using sf_set_buf_size
    sf_set_buf_size(Res, dwSize);

    // Mark the Res with it's library argument type using sf_lib_arg_type
    sf_lib_arg_type(Res, "MallocCategory");

    // If the function copies a buffer to the allocated memory, mark the memory as copied from the input buffer using sf_bitcopy
    sf_bitcopy(Res, p, dwSize);

    // For reallocation, mark the old buffer as freed with a specific memory category using sf_delete
    sf_delete(p, PAGES_MEMORY_CATEGORY);

    // Return Res as the allocated/reallocated memory
    return Res;
}



char *__alloc_some_string(void) {
    size_t size = 100; // example size

    sf_set_trusted_sink_int(size);
    sf_malloc_arg(size);

    char *Res = NULL;

    sf_overwrite(Res, size);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res, size);
    sf_not_acquire_if_eq(Res, NULL);
    sf_buf_size_limit(Res, size);
    sf_lib_arg_type(Res, "MallocCategory");

    return Res;
}



void *__get_nonfreeable(void) {
    void *Res = NULL;
    sf_set_trusted_sink_int(Res);
    sf_malloc_arg(Res);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_possible_null(Res);
    sf_set_alloc_possible_null(Res);
    sf_raw_new(Res);
    sf_not_acquire_if_eq(Res);
    sf_buf_size_limit(Res);
    sf_lib_arg_type(Res, "MallocCategory");
    return Res;
}



void *__get_nonfreeable_tainted(void) {
    size_t size = 0;
    sf_set_trusted_sink_int(size);
    sf_malloc_arg(size);
    void *Res = NULL;
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_possible_null(Res);
    sf_set_alloc_possible_null(Res, size);
    sf_raw_new(Res);
    sf_not_acquire_if_eq(Res);
    sf_buf_size_limit(Res, size);
    sf_lib_arg_type(Res, "MallocCategory");
    return Res;
}



void *__get_nonfreeable_possible_null(void) {
    void *Res = NULL;

    sf_set_trusted_sink_int(size);
    sf_malloc_arg(size);

    Res = sf_malloc(size);

    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res, size);
    sf_set_possible_null(Res);
    sf_not_acquire_if_eq(Res, NULL);
    sf_buf_size_limit(Res, size);
    sf_lib_arg_type(Res, "MallocCategory");

    return Res;
}



void *__get_nonfreeable_tainted_possible_null(void) {
    void *Res = NULL;

    sf_set_trusted_sink_int(size);
    sf_malloc_arg(size);

    Res = sf_malloc(size);

    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res, size);
    sf_set_possible_null(Res);
    sf_not_acquire_if_eq(Res, NULL);
    sf_buf_size_limit(Res, size);
    sf_lib_arg_type(Res, "MallocCategory");

    return Res;
}



void *__get_nonfreeable_not_null(void) {
    void *Res = NULL;
    sf_set_trusted_sink_int(Res);
    sf_malloc_arg(Res);
    sf_overwrite(Res);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_possible_null(Res);
    sf_set_alloc_possible_null(Res);
    sf_raw_new(Res);
    sf_not_acquire_if_eq(Res);
    sf_buf_size_limit(Res);
    sf_lib_arg_type(Res, "MallocCategory");
    return Res;
}



char *__get_nonfreeable_string(void) {
    size_t size = 100; // example size
    char *Res = NULL;

    sf_set_trusted_sink_int(size);
    sf_malloc_arg(size);
    Res = (char *)malloc(size * sizeof(char));

    sf_overwrite(Res, size);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_possible_null(Res);
    sf_set_alloc_possible_null(Res, size);
    sf_raw_new(Res);
    sf_not_acquire_if_eq(Res, NULL);
    sf_buf_size_limit(Res, size);
    sf_lib_arg_type(Res, "MallocCategory");

    return Res;
}



char *__get_nonfreeable_possible_null_string(void) {
    size_t size = 100; // example size
    sf_set_trusted_sink_int(size);
    sf_malloc_arg(size);
    void *Res = NULL;
    Res = malloc(size * sizeof(char));
    sf_overwrite(Res, size);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_possible_null(Res);
    sf_set_alloc_possible_null(Res, size);
    sf_raw_new(Res);
    sf_not_acquire_if_eq(Res, NULL);
    sf_buf_size_limit(Res, size);
    sf_lib_arg_type(Res, "MallocCategory");
    return Res;
}

void __free_nonfreeable_string(char *buffer) {
    sf_set_must_be_not_null(buffer, FREE_OF_NULL);
    sf_delete(buffer, MALLOC_CATEGORY);
    sf_lib_arg_type(buffer, "MallocCategory");
}



char *__get_nonfreeable_not_null_string(void) {
    size_t size = 100; // example size
    char *Res = NULL;

    sf_set_trusted_sink_int(size);
    sf_malloc_arg(size);
    Res = (char *)malloc(size * sizeof(char));

    sf_overwrite(Res, size);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res, size);
    sf_not_acquire_if_eq(Res, NULL);
    sf_buf_size_limit(Res, size);
    sf_lib_arg_type(Res, "MallocCategory");

    return Res;
}



char *__get_nonfreeable_tainted_possible_null_string(void) {
    size_t size = 100; // example size
    char *Res = NULL;

    sf_set_trusted_sink_int(size);
    sf_malloc_arg(size);
    Res = (char *)malloc(size * sizeof(char));

    sf_overwrite(Res, size);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_possible_null(Res);
    sf_set_alloc_possible_null(Res, size);
    sf_raw_new(Res);
    sf_not_acquire_if_eq(Res);
    sf_buf_size_limit(Res, size);
    sf_lib_arg_type(Res, "MallocCategory");

    return Res;
}



void sqlite3_free_table(char **result) {
    // Check if the buffer is null
    sf_set_must_be_not_null(result, FREE_OF_NULL);

    // Mark the input buffer as freed
    sf_delete(result, MALLOC_CATEGORY);

    // Unmark the input buffer it's library argument type
    sf_lib_arg_type(result, "MallocCategory");
}



void *__malloc(sqlite3_int64 size) {
    void *Res = NULL;

    sf_set_trusted_sink_int(size);
    sf_malloc_arg(size);

    Res = malloc(size);

    sf_overwrite(Res, size);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res, size);
    sf_not_acquire_if_eq(Res, NULL);
    sf_buf_size_limit(Res, size);
    sf_lib_arg_type(Res, "MallocCategory");

    return Res;
}



void *sqlite3_malloc(int size) {
    // Mark the input parameter specifying the allocation size
    sf_set_trusted_sink_int(size);
    sf_malloc_arg(size);

    // Create a pointer variable Res to hold the allocated/reallocated memory
    void *Res = NULL;

    // Mark both Res and the memory it points to as overwritten
    sf_overwrite(Res);

    // Mark the memory as newly allocated with a specific memory category
    sf_new(Res, PAGES_MEMORY_CATEGORY);

    // Mark Res as possibly null
    sf_set_possible_null(Res);

    // Mark Res (or both Res and input parameter specifying the allocation size) as possibly null after allocation
    sf_set_alloc_possible_null(Res, size);

    // Mark the memory as rawly allocated with a specific memory category
    sf_raw_new(Res);

    // Mark Res as not acquired if it is equal to null
    sf_not_acquire_if_eq(Res);

    // Set the buffer size limit based on the allocation size
    sf_buf_size_limit(size);

    // Set the buffer size limit based on the input parameter for malloc functions
    sf_set_buf_size(Res, size);

    // Mark the Res with it's library argument type
    sf_lib_arg_type(Res, "MallocCategory");

    // Return Res as the allocated/reallocated memory
    return Res;
}



void *sqlite3_malloc64(sqlite3_uint64 size) {
    void *Res = NULL;

    sf_set_trusted_sink_int(size);
    sf_malloc_arg(size);

    Res = malloc(size);

    sf_overwrite(Res, size);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res, size);
    sf_not_acquire_if_eq(Res, NULL);
    sf_buf_size_limit(Res, size);
    sf_lib_arg_type(Res, "MallocCategory");

    return Res;
}



void *__realloc(void *ptr, sqlite3_uint64 size) {
    void *Res = NULL;

    sf_set_trusted_sink_int(size);
    sf_malloc_arg(size);

    Res = realloc(ptr, size);

    sf_overwrite(Res, size);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res, size);
    sf_not_acquire_if_eq(Res, NULL);
    sf_buf_size_limit(Res, size);
    sf_lib_arg_type(Res, "MallocCategory");

    if (ptr != NULL) {
        sf_delete(ptr, MALLOC_CATEGORY);
        sf_lib_arg_type(ptr, "MallocCategory");
    }

    return Res;
}



void *sqlite3_realloc(void *ptr, int size) {
    // Mark the input parameter specifying the allocation size with sf_set_trusted_sink_int
    sf_set_trusted_sink_int(size);

    // Mark the input parameter specifying the allocation size with sf_malloc_arg
    sf_malloc_arg(size);

    // Create a pointer variable Res to hold the allocated/reallocated memory
    void *Res = NULL;

    // Mark both Res and the memory it points to as overwritten using sf_overwrite
    sf_overwrite(Res);

    // Mark the memory as newly allocated with a specific memory category using sf_new
    sf_new(Res, PAGES_MEMORY_CATEGORY);

    // Mark Res as possibly null using sf_set_possible_null
    sf_set_possible_null(Res);

    // Mark Res (or both Res and input parameter specifying the allocation size) as possibly null after allocation in functions that allocate memory using sf_set_alloc_possible_null
    sf_set_alloc_possible_null(Res, size);

    // Mark the memory as rawly allocated with a specific memory category using sf_raw_new
    sf_raw_new(Res);

    // Mark Res as not acquired if it is equal to null using sf_not_acquire_if_eq
    sf_not_acquire_if_eq(Res);

    // Set the buffer size limit based on the allocation size using sf_buf_size_limit
    sf_buf_size_limit(Res, size);

    // Set the buffer size limit based on the input parameter for malloc functions using sf_set_buf_size
    sf_set_buf_size(ptr, size);

    // Mark the Res with it's library argument type using sf_lib_arg_type
    sf_lib_arg_type(Res, "MallocCategory");

    // If the function copies a buffer to the allocated memory, mark the memory as copied from the input buffer using sf_bitcopy
    sf_bitcopy(Res, ptr);

    // For reallocation, mark the old buffer as freed with a specific memory category using sf_delete
    sf_delete(ptr, MALLOC_CATEGORY);

    // Return Res as the allocated/reallocated memory
    return Res;
}



void *sqlite3_realloc64(void *ptr, sqlite3_uint64 size) {
    void *Res = NULL;

    sf_set_trusted_sink_int(size);
    sf_malloc_arg(size);

    Res = sf_realloc(ptr, size);

    sf_overwrite(Res, size);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res, size);
    sf_not_acquire_if_eq(Res);
    sf_buf_size_limit(Res, size);
    sf_lib_arg_type(Res, "MallocCategory");

    return Res;
}



void sqlite3_free(void *ptr) {
    // Check if the buffer is null
    sf_set_must_be_not_null(ptr, FREE_OF_NULL);

    // Mark the input buffer as freed
    sf_delete(ptr, MALLOC_CATEGORY);

    // Unmark the input buffer it's library argument type
    sf_lib_arg_type(ptr, "MallocCategory");
}



void sqlite3_value_free(sqlite3_value *pVal) {
    // Check if the buffer is null
    sf_set_must_be_not_null(pVal, FREE_OF_NULL);

    // Mark the input buffer as freed
    sf_delete(pVal, SQLITE_VALUE_CATEGORY);

    // Unmark the input buffer it's library argument type
    sf_lib_arg_type(pVal, "Sqlite3ValueCategory");
}



sqlite3_mutex *sqlite3_mutex_alloc(int id) {
    // Mark the input parameter specifying the allocation size with sf_set_trusted_sink_int.
    sf_set_trusted_sink_int(id);

    // Mark the input parameter specifying the allocation size with sf_malloc_arg for malloc functions.
    sf_malloc_arg(id);

    // Create a pointer variable Res to hold the allocated/reallocated memory, e.g. void *Res = NULL
    sqlite3_mutex *Res = NULL;

    // Mark both Res and the memory it points to as overwritten using sf_overwrite.
    sf_overwrite(Res);

    // Mark the memory as newly allocated with a specific memory category using sf_new, e.g. sf_new(Res, PAGES_MEMORY_CATEGORY) for pages allocation.
    sf_new(Res, MUTEX_MEMORY_CATEGORY);

    // Mark Res as possibly null using sf_set_possible_null if Res is possibly null.
    sf_set_possible_null(Res);

    // Mark Res (or both Res and input parameter specifying the allocation size) as possibly null after allocationin functions that allocate memory using sf_set_alloc_possible_null, e.g. sf_set_alloc_possible_null(Res) or sf_set_alloc_possible_null(Res, size).
    sf_set_alloc_possible_null(Res, id);

    // Mark the memory as rawly allocated with a specific memory category using sf_raw_new.
    sf_raw_new(Res, MUTEX_MEMORY_CATEGORY);

    // Mark Res as not acquired if it is equal to null using sf_not_acquire_if_eq.
    sf_not_acquire_if_eq(Res);

    // Set the buffer size limit based on the allocation size using sf_buf_size_limit.
    sf_buf_size_limit(Res, id);

    // Set the buffer size limit based on the input parameter for malloc functions using sf_set_buf_size(ptr, size).
    sf_set_buf_size(Res, id);

    // Mark the Res with it's library argument type using sf_lib_arg_type, e.g. for malloc functions sf_lib_arg_type(ptr, "MallocCategory").
    sf_lib_arg_type(Res, "MutexCategory");

    // Return Res as the allocated/reallocated memory.
    return Res;
}



void sqlite3_mutex_free(sqlite3_mutex *p) {
    // Check if the buffer is null
    sf_set_must_be_not_null(p, FREE_OF_NULL);

    // Mark the input buffer as freed
    sf_delete(p, MUTEX_CATEGORY);

    // Unmark the input buffer it's library argument type
    sf_lib_arg_type(p, "MutexCategory");
}



void sqlite3_snapshot_free(sqlite3_snapshot *pSnapshot) {
    // Check if the buffer is null
    sf_set_must_be_not_null(pSnapshot, FREE_OF_NULL);

    // Mark the input buffer as freed
    sf_delete(pSnapshot, SNAPSHOT_CATEGORY);

    // Unmark the input buffer it's library argument type
    sf_lib_arg_type(pSnapshot, "SnapshotCategory");
}



void *calloc(size_t num, size_t size) {
    // Mark the input parameter specifying the allocation size with sf_set_trusted_sink_int
    sf_set_trusted_sink_int(num);
    sf_set_trusted_sink_int(size);

    // Mark the input parameter specifying the allocation size with sf_malloc_arg
    sf_malloc_arg(num);
    sf_malloc_arg(size);

    // Create a pointer variable Res to hold the allocated/reallocated memory
    void *Res = NULL;

    // Mark both Res and the memory it points to as overwritten using sf_overwrite
    sf_overwrite(Res, sizeof(Res));

    // Mark the memory as newly allocated with a specific memory category using sf_new
    sf_new(Res, PAGES_MEMORY_CATEGORY);

    // Mark Res as possibly null using sf_set_possible_null
    sf_set_possible_null(Res);

    // Mark Res (or both Res and input parameter specifying the allocation size) as possibly null after allocation using sf_set_alloc_possible_null
    sf_set_alloc_possible_null(Res, size);

    // Mark the memory as rawly allocated with a specific memory category using sf_raw_new
    sf_raw_new(Res, PAGES_MEMORY_CATEGORY);

    // Mark Res as not acquired if it is equal to null using sf_not_acquire_if_eq
    sf_not_acquire_if_eq(Res);

    // Set the buffer size limit based on the allocation size using sf_buf_size_limit
    sf_buf_size_limit(Res, num * size);

    // Set the buffer size limit based on the input parameter for malloc functions using sf_set_buf_size
    sf_set_buf_size(Res, size);

    // Mark the Res with it's library argument type using sf_lib_arg_type
    sf_lib_arg_type(Res, "MallocCategory");

    // Return Res as the allocated/reallocated memory
    return Res;
}



void free(void *ptr) {
    // Check if the buffer is null
    sf_set_must_be_not_null(ptr, FREE_OF_NULL);

    // Mark the input buffer as freed
    sf_delete(ptr, MALLOC_CATEGORY);

    // Unmark the input buffer it's library argument type
    sf_lib_arg_type(ptr, "MallocCategory");
}



void *malloc(size_t size) {
    // Mark the input parameter specifying the allocation size
    sf_set_trusted_sink_int(size);
    sf_malloc_arg(size);

    // Create a pointer variable Res to hold the allocated memory
    void *Res = NULL;

    // Mark both Res and the memory it points to as overwritten
    sf_overwrite(Res);

    // Mark the memory as newly allocated
    sf_new(Res, PAGES_MEMORY_CATEGORY);

    // Mark Res as possibly null
    sf_set_possible_null(Res);

    // Mark Res as possibly null after allocation
    sf_set_alloc_possible_null(Res, size);

    // Mark the memory as rawly allocated
    sf_raw_new(Res);

    // Mark Res as not acquired if it is equal to null
    sf_not_acquire_if_eq(Res);

    // Set the buffer size limit based on the allocation size
    sf_buf_size_limit(Res, size);

    // Set the buffer size limit based on the input parameter for malloc functions
    sf_set_buf_size(Res, size);

    // Mark the Res with it's library argument type
    sf_lib_arg_type(Res, "MallocCategory");

    // Return Res as the allocated memory
    return Res;
}



void *malloc(size_t size) {
    // Mark the input parameter specifying the allocation size
    sf_set_trusted_sink_int(size);
    sf_malloc_arg(size);

    // Create a pointer variable Res to hold the allocated/reallocated memory
    void *Res = NULL;

    // Mark both Res and the memory it points to as overwritten
    sf_overwrite(Res, sizeof(Res));

    // Mark the memory as newly allocated with a specific memory category
    sf_new(Res, PAGES_MEMORY_CATEGORY);

    // Mark Res as possibly null
    sf_set_possible_null(Res);

    // Mark Res (or both Res and input parameter specifying the allocation size) as possibly null after allocation
    sf_set_alloc_possible_null(Res, size);

    // Mark the memory as rawly allocated with a specific memory category
    sf_raw_new(Res, PAGES_MEMORY_CATEGORY);

    // Mark Res as not acquired if it is equal to null
    sf_not_acquire_if_eq(Res);

    // Set the buffer size limit based on the allocation size
    sf_buf_size_limit(Res, size);

    // Set the buffer size limit based on the input parameter for malloc functions
    sf_set_buf_size(Res, size);

    // Mark the Res with it's library argument type
    sf_lib_arg_type(Res, "MallocCategory");

    // Return Res as the allocated/reallocated memory
    return Res;
}



void *aligned_alloc(size_t alignment, size_t size) {
    void *Res = NULL;

    sf_set_trusted_sink_int(size);
    sf_malloc_arg(size);

    Res = malloc(size);

    sf_overwrite(Res, size);
    sf_new(Res, PAGES_MEMORY_CATEGORY);
    sf_set_alloc_possible_null(Res, size);
    sf_not_acquire_if_eq(Res, NULL);
    sf_buf_size_limit(Res, size);
    sf_lib_arg_type(Res, "MallocCategory");

    return Res;
}



void *realloc(void *ptr, size_t size) {
    // Mark the input parameter specifying the allocation size with sf_set_trusted_sink_int
    sf_set_trusted_sink_int(size);

    // Mark the input parameter specifying the allocation size with sf_malloc_arg
    sf_malloc_arg(size);

    // Create a pointer variable Res to hold the allocated/reallocated memory
    void *Res = NULL;

    // Allocate memory
    Res = malloc(size);

    // Mark both Res and the memory it points to as overwritten using sf_overwrite
    sf_overwrite(Res, size);

    // Mark the memory as newly allocated with a specific memory category using sf_new
    sf_new(Res, PAGES_MEMORY_CATEGORY);

    // Mark Res as possibly null using sf_set_possible_null
    sf_set_possible_null(Res);

    // Mark Res (or both Res and input parameter specifying the allocation size) as possibly null after allocation using sf_set_alloc_possible_null
    sf_set_alloc_possible_null(Res, size);

    // Mark the memory as rawly allocated with a specific memory category using sf_raw_new
    sf_raw_new(Res, PAGES_MEMORY_CATEGORY);

    // Mark Res as not acquired if it is equal to null using sf_not_acquire_if_eq
    sf_not_acquire_if_eq(Res);

    // Set the buffer size limit based on the allocation size using sf_buf_size_limit
    sf_buf_size_limit(Res, size);

    // Set the buffer size limit based on the input parameter for malloc functions using sf_set_buf_size
    sf_set_buf_size(ptr, size);

    // Mark the Res with it's library argument type using sf_lib_arg_type
    sf_lib_arg_type(Res, "MallocCategory");

    // If the function copies a buffer to the allocated memory, mark the memory as copied from the input buffer using sf_bitcopy
    sf_bitcopy(Res, ptr, size);

    // For reallocation, mark the old buffer as freed with a specific memory category using sf_delete
    sf_delete(ptr, MALLOC_CATEGORY);

    // Return Res as the allocated/reallocated memory
    return Res;
}
