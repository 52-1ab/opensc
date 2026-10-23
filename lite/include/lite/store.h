#ifndef LITE_STORE_H
#define LITE_STORE_H

#include <stddef.h>

/// @file
/// Pluggable key/value store shaped like Android SharedPreferences.

/// SharedPreferences-shaped store, namespaced by file (e.g. "NPCICLVAULT", "DataUPI").
typedef struct lite_store {
    void *ctx;  ///< Backend-private state.
    /// Reads `file`/`key` into `out` (NUL-terminated); returns length, or -1 if absent/too small. `out` may be NULL to query length.
    long (*get)(void *ctx, const char *file, const char *key, char *out, size_t cap);
    int (*set)(void *ctx, const char *file, const char *key, const char *val);  ///< Writes `file`/`key`=`val`. 0 on success.
    int (*remove)(void *ctx, const char *file, const char *key);                ///< Removes `file`/`key`. 0 on success.
} lite_store;

/// Allocates an in-memory store (for tests). Free with lite_store_mem_free().
lite_store *lite_store_mem_new(void);
/// Frees an in-memory store created by lite_store_mem_new().
void lite_store_mem_free(lite_store *s);

#endif
