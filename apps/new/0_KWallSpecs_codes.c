void *ReallocatePool ( uintptr_t OldSize, uintptr_t NewSize, void *OldBuffer ) {
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

void *ReallocateRuntimePool ( uintptr_t OldSize, uintptr_t NewSize, void *OldBuffer ) {
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

void *ReallocateReservedPool ( uintptr_t OldSize, uintptr_t NewSize, void *OldBuffer ) {
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

void g_free (gpointer ptr) {
	sf_set_must_be_not_null(ptr, FREE_OF_NULL);
	// sf_overwrite(ptr);
	sf_delete(ptr, GLIB_CATEGORY);
}

gchar * g_strfreev(const gchar **str_array) {
	if(!str_array)
		return;

	sf_escape(str_array);//TODO: create some recursive delete function
	sf_delete(*str_array, GLIB_CATEGORY);
	sf_overwrite(str_array);
	sf_delete(str_array, GLIB_CATEGORY);
}

gpointer g_malloc0_n (gsize n_blocks, gsize n_block_bytes) {
	sf_set_trusted_sink_int(n_blocks);
	sf_set_trusted_sink_int(n_block_bytes);

	gpointer ptr;
	sf_bitinit(ptr);
	sf_overwrite(&ptr);
	sf_overwrite(ptr);
	sf_uncontrolled_ptr(ptr);
	sf_new(ptr, GLIB_CATEGORY);
	sf_null_terminated((char*)ptr);
	return ptr;
}

gpointer g_malloc (gsize n_bytes) {
	sf_set_trusted_sink_int(n_bytes);
	sf_malloc_arg(n_bytes);

	gpointer ptr;
	sf_bitinit(ptr);
	sf_overwrite(&ptr);
	sf_overwrite(ptr);
	sf_uncontrolled_ptr(ptr);
	sf_new(ptr, GLIB_CATEGORY);
	sf_raw_new(ptr);
	sf_set_buf_size(ptr, n_bytes);
	return ptr;
}

gpointer g_malloc0 (gsize n_bytes) {
	sf_set_trusted_sink_int(n_bytes);
	sf_malloc_arg(n_bytes);

	gpointer ptr;
	sf_bitinit(ptr);
	sf_overwrite(&ptr);
	sf_overwrite(ptr);
	sf_uncontrolled_ptr(ptr);
	sf_new(ptr, GLIB_CATEGORY);
	sf_set_buf_size(ptr, n_bytes);
	sf_null_terminated((char*)ptr);
	return ptr;
}

gpointer g_malloc_n (gsize n_blocks, gsize n_block_bytes) {
	sf_set_trusted_sink_int(n_blocks);
	sf_set_trusted_sink_int(n_block_bytes);

	gpointer ptr;
	sf_overwrite(&ptr);
	sf_overwrite(ptr);
	sf_uncontrolled_ptr(ptr);
	sf_new(ptr, GLIB_CATEGORY);
	sf_raw_new(ptr);
	sf_set_buf_size(ptr, n_blocks*n_block_bytes);
	return ptr;
}

gpointer g_try_malloc0_n (gsize n_blocks, gsize n_block_bytes) {
	sf_set_trusted_sink_int(n_blocks);
	sf_set_trusted_sink_int(n_block_bytes);

	gpointer ptr;
	sf_overwrite(&ptr);
	sf_overwrite(ptr);
	sf_uncontrolled_ptr(ptr);
	sf_new(ptr, GLIB_CATEGORY);
	sf_set_alloc_possible_null(ptr, n_blocks, n_block_bytes);
	sf_null_terminated((char*)ptr);
	return ptr;
}

gpointer g_try_malloc (gsize n_bytes) {
	sf_set_trusted_sink_int(n_bytes);
	sf_malloc_arg(n_bytes);

	gpointer ptr;
	sf_overwrite(&ptr);
	sf_overwrite(ptr);
	sf_uncontrolled_ptr(ptr);
	sf_new(ptr, GLIB_CATEGORY);
	sf_raw_new(ptr);
	sf_set_buf_size(ptr, n_bytes);
	sf_set_alloc_possible_null(ptr, n_bytes);
	return ptr;
}

gpointer g_try_malloc0 (gsize n_bytes) {
	sf_set_trusted_sink_int(n_bytes);
	sf_malloc_arg(n_bytes);

	gpointer ptr;
	sf_overwrite(&ptr);
	sf_overwrite(ptr);
	sf_uncontrolled_ptr(ptr);
	sf_new(ptr, GLIB_CATEGORY);
	sf_set_buf_size(ptr, n_bytes);
	sf_set_alloc_possible_null(ptr, n_bytes);
	return ptr;
}

gpointer g_try_malloc_n (gsize n_blocks, gsize n_block_bytes) {
	sf_set_trusted_sink_int(n_blocks);
	sf_set_trusted_sink_int(n_block_bytes);

	gpointer ptr;
	sf_overwrite(&ptr);
	sf_overwrite(ptr);
	sf_uncontrolled_ptr(ptr);
	sf_new(ptr, GLIB_CATEGORY);
	sf_raw_new(ptr);
	sf_set_alloc_possible_null(ptr, n_blocks, n_block_bytes);
	return ptr;
}

gpointer g_realloc(gpointer mem, gsize n_bytes) {
	sf_escape(mem);
	sf_set_trusted_sink_int(n_bytes);

	gpointer *retptr;
	sf_overwrite(&retptr);
	sf_overwrite(retptr);
	sf_uncontrolled_ptr(retptr);
	sf_new(retptr, GLIB_CATEGORY);
	sf_invalid_pointer(mem, retptr);
	sf_set_buf_size(retptr, n_bytes);
	return retptr;
}

gpointer g_try_realloc(gpointer mem, gsize n_bytes) {
	sf_escape(mem);
	sf_set_trusted_sink_int(n_bytes);

	gpointer *retptr;
	sf_overwrite(&retptr);
	sf_overwrite(retptr);
	sf_uncontrolled_ptr(retptr);
	sf_new(retptr, GLIB_CATEGORY);
	sf_invalid_pointer(mem, retptr);
	sf_set_buf_size(retptr, n_bytes);
	sf_set_alloc_possible_null(retptr, n_bytes);
	return retptr;
}

gpointer g_realloc_n(gpointer mem, gsize n_blocks, gsize n_block_bytes) {
	sf_escape(mem);
	sf_set_trusted_sink_int(n_blocks);
	sf_set_trusted_sink_int(n_block_bytes);

	gpointer *retptr;
	sf_overwrite(&retptr);
	sf_overwrite(retptr);
	sf_uncontrolled_ptr(retptr);
	sf_new(retptr, GLIB_CATEGORY);
	sf_invalid_pointer(mem, retptr);
	sf_set_buf_size(retptr, n_blocks * n_block_bytes);
	return retptr;
}

gpointer g_try_realloc_n(gpointer mem, gsize n_blocks, gsize n_block_bytes) {
	sf_escape(mem);
	sf_set_trusted_sink_int(n_blocks);
	sf_set_trusted_sink_int(n_block_bytes);

	gpointer *retptr;
	sf_overwrite(&retptr);
	sf_overwrite(retptr);
	sf_uncontrolled_ptr(retptr);
	sf_new(retptr, GLIB_CATEGORY);
	sf_invalid_pointer(mem, retptr);
	sf_set_buf_size(retptr, n_blocks * n_block_bytes);
	sf_set_alloc_possible_null(retptr, n_blocks * n_block_bytes);
	return retptr;
}

void *kcalloc(size_t n, size_t size, gfp_t flags) {
	//return kmalloc_array(n, size, flags | __GFP_ZERO);
}

void *kmalloc_array(size_t n, size_t size, gfp_t flags) {
	//if (size != 0 && n > SIZE_MAX / size)
	//	return NULL;
	//return __kmalloc(n * size, flags);
}

void *kzalloc_node(size_t size, gfp_t flags, int node) {
	//return kmalloc_node(size, flags | __GFP_ZERO, node);
}

void *kmalloc(size_t size, gfp_t flags) {
	void *ptr;
 sf_overwrite(&ptr);
 sf_overwrite(ptr);
 sf_set_alloc_possible_null(ptr, size);
 sf_new(ptr, KMALLOC_CATEGORY);
 sf_set_buf_size(ptr, size);
 return ptr;;
}

void *kzalloc(size_t size, gfp_t flags) {
}

void *__kmalloc(size_t size, gfp_t flags) {
    //KRAWMALLOC(size);
	void *ptr;
 sf_overwrite(&ptr);
 sf_overwrite(ptr);
 sf_set_alloc_possible_null(ptr, size);
 sf_new(ptr, KMALLOC_CATEGORY);
 sf_set_buf_size(ptr, size);
 return ptr;;//note: about raw initializing: flags may be __GFP_ZERO - init by zero
}

void *__kmalloc_node(size_t size, gfp_t flags, int node) {
	//KMALLOC_CATEGORY ??
	//KRAWMALLOC(size);
	void *ptr;
 sf_overwrite(&ptr);
 sf_overwrite(ptr);
 sf_set_alloc_possible_null(ptr, size);
 sf_new(ptr, KMALLOC_CATEGORY);
 sf_set_buf_size(ptr, size);
 return ptr;;//note: about raw initializing: flags may be __GFP_ZERO - init by zero
}

void kfree(const void *x) {
    //sf_overwrite(x);
    sf_delete(x, KMALLOC_CATEGORY);
}

void kzfree(const void *x) {
	//sf_overwrite(x);
    sf_delete(x, KMALLOC_CATEGORY);
	//fill with 0
}

void *vmalloc(unsigned long size) {
    void *ptr;
    sf_overwrite(&ptr);
    sf_overwrite(ptr);
    sf_set_alloc_possible_null(ptr, size);
    sf_new(ptr, VMALLOC_CATEGORY);
    sf_set_buf_size(ptr, size);
    return ptr;
}

void vfree(const void *addr) {
    //sf_overwrite(addr);
    sf_delete(addr, VMALLOC_CATEGORY);
}

void *vrealloc(void *ptr, size_t size) {
	sf_escape(ptr);

    sf_set_trusted_sink_int(size);

    void *retptr;
    sf_overwrite(&retptr);
    sf_overwrite(retptr);
	sf_uncontrolled_ptr(retptr);
    sf_set_alloc_possible_null(retptr, size);
    sf_new(retptr, VMALLOC_CATEGORY);
    sf_set_buf_size(retptr, size);
    return retptr;
}

struct input_dev *input_allocate_device(void) {
    __my_acquire__(INPUT_ALLOCATE_DEVICE_CATEGORY)
}

void input_free_device(struct input_dev *dev) {
    {
    sf_handle_release((dev), (INPUT_ALLOCATE_DEVICE_CATEGORY));
    }
}

struct platform_device *platform_device_alloc(const char *name, int id) {
    __my_acquire__(PLATFORM_DEVICE_ALLOC_CATEGORY)
}

void rfkill_alloc(struct rfkill *rfkill, bool blocked) {
    {
    if (rfkill)
    rfkillf_handle_acquire((rfkill)->ptr, (RFKILL_ALLOC_CATEGORY));
    };
}

struct workqueue_struct *create_freezable_workqueue(void *name) {
    __my_acquire__(CREATE_WORKQUEUE_CATEGORY)
}

struct tty_driver *alloc_tty_driver(int lines) {
    __my_acquire__(ALLOC_TTY_DRIVER_CATEGORY)
}

struct tty_driver *__alloc_tty_driver(int lines) {
    __my_acquire__(ALLOC_TTY_DRIVER_CATEGORY)
}

void freeaddrinfo(struct addrinfo *res) {
    sf_overwrite(res);
    sf_handle_release(res, GETADDRINFO_CATEGORY);
}

void *OEM_Malloc(uint32 uSize) {
    void *ptr;
    sf_overwrite(&ptr);
    sf_overwrite(ptr);
    sf_set_alloc_possible_null(ptr, uSize);
    sf_new(ptr, MALLOC_CATEGORY);
    /* sf_raw_new(ptr); */
    /* sf_set_buf_size(ptr, uSize); */
    return ptr;
}

void *aee_malloc(uint32 dwSize) {
    void *ptr;
    sf_overwrite(&ptr);
    sf_overwrite(ptr);
    sf_set_alloc_possible_null(ptr, dwSize);
    sf_new(ptr, MALLOC_CATEGORY);
    /* sf_raw_new(ptr); */
    /* sf_set_buf_size(ptr, dwSize); */
    return ptr;
}

void aee_free(void *p) {
    sf_overwrite(p);
    sf_delete(p, MALLOC_CATEGORY);
}

void *OEM_Realloc(void *p, uint32 uSize) {
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

void *aee_realloc(void *p, uint32 dwSize) {
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

char *__alloc_some_string(void) {
    char *res = (char *)sf_get_uncontrolled_ptr();
    sf_new(res, SQLITE3_MALLOC_CATEGORY);
    sf_set_alloc_possible_null(res);
    sf_null_terminated(res); // ?
    sf_strdup_res(res); // ?
    return res;
}

void *__get_nonfreeable(void) {
    void *res = sf_get_uncontrolled_ptr();
    sf_new(res, SQLITE3_NONFREEABLE_CATEGORY);
    sf_escape(res);
    return res;
}

void *__get_nonfreeable_tainted(void) {
    void *res = __get_nonfreeable();
    sf_set_tainted(res);
    return res;
}

void *__get_nonfreeable_possible_null(void) {
    void *res = __get_nonfreeable();
    //sf_set_alloc_possible_null(res); // ?
    sf_set_possible_null(res);
    return res;
}

void *__get_nonfreeable_tainted_possible_null(void) {
    void *res = __get_nonfreeable_tainted();
    //sf_set_alloc_possible_null(res); // ?
    sf_set_possible_null(res);
    return res;
}

void *__get_nonfreeable_not_null(void) {
    void *res = __get_nonfreeable();
    sf_not_null(res);
    return res;
}

char *__get_nonfreeable_string(void) {
    char *res = (char *)__get_nonfreeable();
    sf_null_terminated(res); // ?
    sf_strdup_res(res); // ?
    return res;
}

char *__get_nonfreeable_possible_null_string(void) {
    char *res = (char *)__get_nonfreeable_possible_null();
    sf_null_terminated(res); // ?
    sf_strdup_res(res); // ?
    return res;
}

char *__get_nonfreeable_not_null_string(void) {
    char *res = (char *)__get_nonfreeable_not_null();
    sf_null_terminated(res); // ?
    sf_strdup_res(res); // ?
    return res;
}

char *__get_nonfreeable_tainted_possible_null_string(void) {
    char *res = (char *)__get_nonfreeable_tainted_possible_null();
    sf_null_terminated(res); // ?
    sf_strdup_res(res); // ?
    return res;
}

void sqlite3_free_table(char **result) {
    sf_vulnerable_fun_type("sqlite3_free_table is a legacy interface that is preserved for backwards compatibility, use of this interface is not recommended", SQLITE);
    sf_set_must_be_not_null(result, FREE_OF_NULL); // ?
    sf_overwrite(result); // ?
    sf_delete(result, SQLITE3_TABLE_CATEGORY);
}

void *__malloc(sqlite3_int64 size) {
    sf_set_trusted_sink_int(size);
    sf_malloc_arg(size);

    void *ptr;
    sf_overwrite(&ptr);
    sf_overwrite(ptr); // ?
    sf_uncontrolled_ptr(ptr);
    sf_set_alloc_possible_null(ptr, size);
    sf_new(ptr, SQLITE3_MALLOC_CATEGORY);
    sf_raw_new(ptr);
    sf_set_buf_size(ptr, size);
    return ptr;
}

void *sqlite3_malloc(int size) {
    return __malloc(size);
}

void *sqlite3_malloc64(sqlite3_uint64 size) {
    return __malloc(size);
}

void *__realloc(void *ptr, sqlite3_uint64 size) {
    sf_escape(ptr);
    sf_set_trusted_sink_int(size);

    void *retptr;
    sf_overwrite(&retptr);
    sf_overwrite(retptr); // ?
    sf_uncontrolled_ptr(retptr);
    sf_set_alloc_possible_null(retptr, size);
    sf_new(retptr, SQLITE3_MALLOC_CATEGORY);
    sf_invalid_pointer(ptr, retptr);
    sf_set_buf_size(retptr, size);
    return retptr;
}

void *sqlite3_realloc(void *ptr, int size) {
    return __realloc(ptr, size);
}

void *sqlite3_realloc64(void *ptr, sqlite3_uint64 size) {
    return __realloc(ptr, size);
}

void sqlite3_free(void *ptr) {
    sf_set_must_be_not_null(ptr, FREE_OF_NULL); // ?
    sf_overwrite(ptr); // ?
    sf_delete(ptr, SQLITE3_MALLOC_CATEGORY);
}

void sqlite3_value_free(sqlite3_value *pVal) {
    sf_must_not_be_release(pVal);
#ifdef TREAT__value_dup__AS_MALLOC
    sf_delete(pVal, SQLITE3_VALUE_CATEGORY);
#else
    sf_handle_release(pVal, SQLITE3_VALUE_CATEGORY);
#endif
    sf_overwrite(pVal); // ?
}

sqlite3_mutex *sqlite3_mutex_alloc(int id) {
    sqlite3_mutex *res = sf_get_uncontrolled_ptr();
    sf_set_possible_null(res);
    //sf_set_alloc_possible_null(res);
    sf_new(res, SQLITE3_MUTEX_CATEGORY);
    return res;
}

void sqlite3_mutex_free(sqlite3_mutex *p) {
    // sf_set_must_be_not_null(ptr, FREE_OF_NULL); // ?
    sf_must_not_be_release(p);
    sf_overwrite(p); // ?
    sf_delete(p, SQLITE3_MUTEX_CATEGORY);
}

void sqlite3_snapshot_free(sqlite3_snapshot *pSnapshot) {
    sf_vulnerable_fun_type("This interface is experimental and is subject to change without notice.", SQLITE);

    sf_must_not_be_release(pSnapshot);
    sf_handle_release(pSnapshot, SQLITE3_SNAPSHOT_CATEGORY);
    sf_overwrite(pSnapshot); // ?
}

void *calloc(size_t num, size_t size) {
    sf_set_trusted_sink_int(num);
    sf_set_trusted_sink_int(size);

    void *ptr;
    sf_overwrite(&ptr);
    sf_overwrite(ptr);
    sf_set_alloc_possible_null(ptr, num ,size);
    sf_uncontrolled_ptr(ptr);
    sf_new(ptr, MALLOC_CATEGORY);
    sf_set_buf_size(ptr, size * num);
    sf_lib_arg_type(ptr, "MallocCategory");
    return ptr;
}

void free(void *ptr) {
    sf_set_must_be_not_null(ptr, FREE_OF_NULL);
    //sf_overwrite(ptr);
    sf_delete(ptr, MALLOC_CATEGORY);
    sf_lib_arg_type(ptr, "MallocCategory");
}

void *malloc(size_t size) {
    sf_set_trusted_sink_int(size);
    sf_malloc_arg(size);

    void *ptr;
    sf_overwrite(&ptr);
    sf_overwrite(ptr);
    sf_uncontrolled_ptr(ptr);
    sf_set_alloc_possible_null(ptr, size);
    sf_new(ptr, MALLOC_CATEGORY);
    sf_raw_new(ptr);
    sf_set_buf_size(ptr, size);
    sf_lib_arg_type(ptr, "MallocCategory");
    return ptr;
}

void *aligned_alloc(size_t alignment, size_t size) {
    sf_set_trusted_sink_int(size);
    sf_malloc_arg(size);

    void *ptr;
    sf_overwrite(&ptr);
    sf_overwrite(ptr);
    sf_uncontrolled_ptr(ptr);
    sf_set_alloc_possible_null(ptr, size);
    sf_new(ptr, MALLOC_CATEGORY);
    sf_raw_new(ptr);
    sf_set_buf_size(ptr, size);
    sf_lib_arg_type(ptr, "MallocCategory");
    return ptr;
}

void *realloc(void *ptr, size_t size) {
	sf_escape(ptr);
    //TODO:
    //if(ptr!=0) {
    //    sf_overwrite(ptr);
    //    sf_delete(ptr, MALLOC_CATEGORY);
    //}
    //it's totally incorrect
    //if(ptr)
    //    free(ptr);

    sf_set_trusted_sink_int(size);

    void *retptr;
    sf_overwrite(&retptr);
    sf_overwrite(retptr);
    sf_uncontrolled_ptr(retptr);
    sf_set_alloc_possible_null(retptr, size);
    sf_new(retptr, MALLOC_CATEGORY);
    sf_invalid_pointer(ptr, retptr);
    sf_set_buf_size(retptr, size);
    sf_lib_arg_type(retptr, "MallocCategory");
    sf_bitcopy(retptr, ptr);

    return retptr;
}

