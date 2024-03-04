#include "specfunc.h"

struct	JsonGenerator;
struct	JsonGeneratorClass;

struct JsonNode;

struct GOutputStream *stream;
struct GCancellable;
struct GError;

typedef unsigned int guint;
typedef int gboolean;
typedef unsigned char gunichar;
typedef char gchar;
typedef size_t gsize;

struct JsonGenerator *	json_generator_new();

void
json_generator_set_root (struct JsonGenerator *generator,
                         struct JsonNode *node);

struct JsonNode *
json_generator_get_root (struct JsonGenerator *generator);

void
json_generator_set_pretty (struct JsonGenerator *generator,
                           gboolean is_pretty);

void
json_generator_set_indent (struct JsonGenerator *generator,
                           guint indent_level);

guint
json_generator_get_indent (struct JsonGenerator *generator);

gunichar
json_generator_get_indent_char (struct JsonGenerator *generator);

gboolean
json_generator_to_file (struct JsonGenerator *generator,
                        const gchar *filename,
                        struct GError **error);

gchar *
json_generator_to_data (struct JsonGenerator *generator,
                        gsize *length);

gboolean
json_generator_to_stream (struct JsonGenerator *generator,
                          struct GOutputStream *stream,
                          struct GCancellable *cancellable,
                          struct GError **error);
