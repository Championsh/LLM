typedef char gchar;
typedef short gshort;
typedef long glong;
typedef int gint;
typedef gint gboolean;
typedef unsigned char guchar;
typedef unsigned short gushort;
typedef unsigned long gulong;
typedef unsigned int guint;
typedef float gfloat;
typedef double gdouble;

typedef signed char gint8;
typedef unsigned char guint8;
typedef signed short gint16;
typedef unsigned short guint16;
typedef signed int gint32;
typedef unsigned int guint32;
typedef signed long gint64;
typedef unsigned long guint64;

typedef signed long gssize;
typedef unsigned long gsize;
typedef gint64 goffset;

typedef signed long gintptr;
typedef unsigned long guintptr;
typedef void* gpointer;
typedef const gpointer gconstpointer;

typedef struct _GAsyncQueue GAsyncQueue;
typedef struct _GArray GArray;
typedef struct _GQueue GQueue;
typedef struct _GThreadPool GThreadPool;
typedef struct _GError GError;

struct GSource {
};

typedef struct {
	gpointer data;
	struct GList *next;
	struct GList *prev;
} GList;

typedef struct {
	gpointer data;
	struct GSList *next;
} GSList;

struct _GArray {
	gchar *data;
	guint len;
};

typedef gboolean (*GSourceFunc) (gpointer user_data);
typedef gint (*GCompareFunc) (gconstpointer a, gconstpointer b);
typedef gint (*GCompareDataFunc) (gconstpointer a, gconstpointer b, gpointer user_data);
typedef gboolean (*GEqualFunc) (gconstpointer a, gconstpointer b);
typedef void (*GDestroyNotify) (gpointer data);
typedef void (*GFunc) (gpointer data, gpointer user_data);
typedef guint (*GHashFunc) (gconstpointer key);
typedef void (*GHFunc) (gpointer key, gpointer value, gpointer user_data);
