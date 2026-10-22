#ifndef LITE_STORE_H
#define LITE_STORE_H

#include <stddef.h>

// SharedPreferences-shaped key/value store, namespaced by file (e.g. "NPCICLVAULT", "DataUPI").
typedef struct lite_store {
    void *ctx;
    long (*get)(void *ctx, const char *file, const char *key, char *out, size_t cap);
    int (*set)(void *ctx, const char *file, const char *key, const char *val);
    int (*remove)(void *ctx, const char *file, const char *key);
} lite_store;

lite_store *lite_store_mem_new(void);
void lite_store_mem_free(lite_store *s);

#endif
