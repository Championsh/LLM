#include "specfunc.h"
#include "glib-types.h"

#define GLIB_CATEGORY MALLOC_CATEGORY

 
void g_free (gpointer ptr);

gchar* g_strfreev(const gchar **str_array);

 
void g_async_queue_push (GAsyncQueue *queue, gpointer data);

void g_queue_push_tail (GQueue *queue, gpointer data);

void g_source_set_callback (struct GSource *source, GSourceFunc func, gpointer data, GDestroyNotify notify);

gboolean g_thread_pool_push (GThreadPool *pool, gpointer data, GError **error);

 
GList* g_list_append(GList *list, gpointer data);

GList* g_list_prepend(GList *list, gpointer data);

GList* g_list_insert(GList *list, gpointer data, gint position);

GList* g_list_insert_before(GList *list, gpointer data, gint position);

GList* g_list_insert_sorted(GList *list, gpointer data, GCompareFunc func);

 
GSList* g_slist_append(GSList *list, gpointer data);

GSList* g_slist_prepend(GSList *list, gpointer data);

GSList* g_slist_insert(GSList *list, gpointer data, gint position);

GSList* g_slist_insert_before(GSList *list, gpointer data, gint position);

GSList* g_slist_insert_sorted(GSList *list, gpointer data, GCompareFunc func);

 
 
GArray* g_array_append_vals(GArray *array, gconstpointer data, guint len);

GArray* g_array_prepend_vals(GArray *array, gconstpointer data, guint len);

GArray* g_array_insert_vals(GArray *array, gconstpointer data, guint len);

 
gchar* g_strdup (const gchar *str);

gchar* g_strdup_printf (const gchar *format, ...);

 
gpointer g_malloc0_n (gsize n_blocks, gsize n_block_bytes);

gpointer g_malloc (gsize n_bytes);

gpointer g_malloc0 (gsize n_bytes);

gpointer g_malloc_n (gsize n_blocks, gsize n_block_bytes);

 
gpointer g_try_malloc0_n (gsize n_blocks, gsize n_block_bytes);

gpointer g_try_malloc (gsize n_bytes);

gpointer g_try_malloc0 (gsize n_bytes);

gpointer g_try_malloc_n (gsize n_blocks, gsize n_block_bytes);

guint32 g_random_int (void);

 
gpointer g_realloc(gpointer mem, gsize n_bytes);

gpointer g_try_realloc(gpointer mem, gsize n_bytes);

gpointer g_realloc_n(gpointer mem, gsize n_blocks, gsize n_block_bytes);

gpointer g_try_realloc_n(gpointer mem, gsize n_blocks, gsize n_block_bytes);

int klogctl(int type, char *bufp, int len);
