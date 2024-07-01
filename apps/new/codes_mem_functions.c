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

