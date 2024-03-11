typedef struct sqlite3 sqlite3;
struct sqlite3 ;;

typedef long long int sqlite_int64;
typedef unsigned long long int sqlite_uint64;

typedef sqlite_int64 sqlite3_int64;
typedef sqlite_uint64 sqlite3_uint64;

typedef int (*sqlite3_callback)(void*,int,char**, char**);


typedef struct sqlite3_file sqlite3_file;
struct sqlite3_file ;;

typedef struct sqlite3_io_methods sqlite3_io_methods;
struct sqlite3_io_methods ;;

typedef struct sqlite3_mutex sqlite3_mutex;
typedef struct sqlite3_api_routines sqlite3_api_routines;
typedef struct sqlite3_vfs sqlite3_vfs;
typedef void (*sqlite3_syscall_ptr)(void);
struct sqlite3_vfs ;;

typedef struct sqlite3_mem_methods sqlite3_mem_methods;
struct sqlite3_mem_methods ;;

int sqlite3_get_table(
  sqlite3 *db,
  const char *zSql,
  char ***pazResult,
  int *pnRow,
  int *pnColumn,
  char **pzErrmsg
);
typedef struct sqlite3_stmt sqlite3_stmt;
typedef struct sqlite3_value sqlite3_value;
typedef struct sqlite3_context sqlite3_context;
typedef void (*sqlite3_destructor_type)(void*);

typedef struct sqlite3_vtab sqlite3_vtab;
typedef struct sqlite3_index_info sqlite3_index_info;
typedef struct sqlite3_vtab_cursor sqlite3_vtab_cursor;
typedef struct sqlite3_module sqlite3_module;
struct sqlite3_module ;;

struct sqlite3_index_info ;;

struct sqlite3_vtab ;;

struct sqlite3_vtab_cursor ;;

typedef struct sqlite3_blob sqlite3_blob;
typedef struct sqlite3_mutex_methods sqlite3_mutex_methods;
struct sqlite3_mutex_methods ;;

typedef struct sqlite3_pcache sqlite3_pcache;
typedef struct sqlite3_pcache_page sqlite3_pcache_page;
struct sqlite3_pcache_page ;;

typedef struct sqlite3_pcache_methods2 sqlite3_pcache_methods2;
struct sqlite3_pcache_methods2 ;;


typedef struct sqlite3_pcache_methods sqlite3_pcache_methods;
struct sqlite3_pcache_methods ;;

typedef struct sqlite3_backup sqlite3_backup;
typedef struct sqlite3_snapshot ; sqlite3_snapshot;
typedef struct sqlite3_rtree_geometry sqlite3_rtree_geometry;
typedef struct sqlite3_rtree_query_info sqlite3_rtree_query_info;

typedef double sqlite3_rtree_dbl;

struct sqlite3_rtree_geometry ;;



struct sqlite3_rtree_query_info ;;

typedef struct Fts5ExtensionApi Fts5ExtensionApi;
typedef struct Fts5Context Fts5Context;
typedef struct Fts5PhraseIter Fts5PhraseIter;

typedef void (*fts5_extension_function)(
  const Fts5ExtensionApi *pApi,
  Fts5Context *pFts,
  sqlite3_context *pCtx,
  int nVal,
  sqlite3_value **apVal
);

struct Fts5PhraseIter ;;

struct Fts5ExtensionApi ;;

typedef struct Fts5Tokenizer Fts5Tokenizer;
typedef struct fts5_tokenizer fts5_tokenizer;
struct fts5_tokenizer ;;

typedef struct fts5_api fts5_api;
struct fts5_api ;;

typedef double RtreeDValue;
typedef float RtreeValue;

