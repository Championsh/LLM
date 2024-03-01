#include "specfunc.h"
#include "glib-types.h"

#define GLIB_CATEGORY MALLOC_CATEGORY

//-----------------------------------------------------
void g_free (gpointer ptr) {
	sf_set_must_be_not_null(ptr, FREE_OF_NULL);
	// sf_overwrite(ptr);
	sf_delete(ptr, GLIB_CATEGORY);
}

gchar* g_strfreev(const gchar **str_array) {
	if(!str_array)
		return;

	sf_escape(str_array);//TODO: create some recursive delete function
	sf_delete(*str_array, GLIB_CATEGORY);
	sf_overwrite(str_array);
	sf_delete(str_array, GLIB_CATEGORY);
}

//-----------------------------------------------------
void g_async_queue_push (GAsyncQueue *queue, gpointer data) {
	sf_escape(data);
}

void g_queue_push_tail (GQueue *queue, gpointer data) {
	sf_escape(data);
}

void g_source_set_callback (struct GSource *source, GSourceFunc func, gpointer data, GDestroyNotify notify) {
	sf_escape(data);
}

gboolean g_thread_pool_push (GThreadPool *pool, gpointer data, GError **error) {
	sf_escape(data);
}

//-----------------------------------------------------
GList* g_list_append(GList *list, gpointer data) {
	sf_escape(data);
}

GList* g_list_prepend(GList *list, gpointer data) {
	sf_escape(data);
}

GList* g_list_insert(GList *list, gpointer data, gint position) {
	sf_escape(data);
}

GList* g_list_insert_before(GList *list, gpointer data, gint position) {
	sf_escape(data);
}

GList* g_list_insert_sorted(GList *list, gpointer data, GCompareFunc func) {
	sf_escape(data);
}

//-----------------------------------------------------
GSList* g_slist_append(GSList *list, gpointer data) {
	sf_escape(data);
}

GSList* g_slist_prepend(GSList *list, gpointer data) {
	sf_escape(data);
}

GSList* g_slist_insert(GSList *list, gpointer data, gint position) {
	sf_escape(data);
}

GSList* g_slist_insert_before(GSList *list, gpointer data, gint position) {
	sf_escape(data);
}

GSList* g_slist_insert_sorted(GSList *list, gpointer data, GCompareFunc func) {
	sf_escape(data);
}

//-----------------------------------------------------
//arrays
GArray* g_array_append_vals(GArray *array, gconstpointer data, guint len) {
	sf_escape(data);
}

GArray* g_array_prepend_vals(GArray *array, gconstpointer data, guint len) {
	sf_escape(data);
}

GArray* g_array_insert_vals(GArray *array, gconstpointer data, guint len) {
	sf_escape(data);
}

//-----------------------------------------------------
gchar* g_strdup (const gchar *str) {
	//note: str may be null
	sf_buf_stop_at_null(str);

	char *res;
	sf_overwrite(&res);
	sf_overwrite(res);
	//like malloc it may return null.
	sf_set_alloc_possible_null(res);
	sf_new(res, GLIB_CATEGORY);
	sf_strdup_res(res);
	return res;
}

gchar* g_strdup_printf (const gchar *format, ...) {
	gchar d1 = *format;
	sf_buf_stop_at_null(format);
	sf_use_format(format);//not sure what it does

	sf_fun_does_not_update_vargs(1);

	char *res;
	sf_overwrite(&res);
	sf_overwrite(res);
	//like malloc it may return null.
	sf_set_alloc_possible_null(res);
	sf_new(res, GLIB_CATEGORY);
	sf_strdup_res(res);
	return res;
}

//----------------------------------------------------------
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

//----------------------------------------------------------
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

guint32 g_random_int (void) {
	sf_fun_rand();
}

//----------------------------------------------------------
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

int klogctl(int type, char *bufp, int len) {
}
