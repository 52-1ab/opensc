#include "lite/store.h"

#include <stdlib.h>
#include <string.h>

typedef struct { char *file, *key, *val; } entry;
typedef struct { entry *e; size_t n, cap; } memstore;

static entry *find(memstore *m, const char *file, const char *key) {
    for (size_t i = 0; i < m->n; i++)
        if (strcmp(m->e[i].file, file) == 0 && strcmp(m->e[i].key, key) == 0) return &m->e[i];
    return NULL;
}

static long ms_get(void *ctx, const char *file, const char *key, char *out, size_t cap) {
    entry *e = find(ctx, file, key);
    if (!e) return -1;
    size_t n = strlen(e->val);
    if (out) {
        if (n + 1 > cap) return -1;
        memcpy(out, e->val, n + 1);
    }
    return (long)n;
}

static int ms_set(void *ctx, const char *file, const char *key, const char *val) {
    memstore *m = ctx;
    entry *e = find(m, file, key);
    if (e) { free(e->val); e->val = strdup(val); return 0; }
    if (m->n == m->cap) { m->cap = m->cap ? m->cap * 2 : 8; m->e = realloc(m->e, m->cap * sizeof *m->e); }
    m->e[m->n].file = strdup(file);
    m->e[m->n].key = strdup(key);
    m->e[m->n].val = strdup(val);
    m->n++;
    return 0;
}

static int ms_remove(void *ctx, const char *file, const char *key) {
    memstore *m = ctx;
    for (size_t i = 0; i < m->n; i++) {
        if (strcmp(m->e[i].file, file) == 0 && strcmp(m->e[i].key, key) == 0) {
            free(m->e[i].file); free(m->e[i].key); free(m->e[i].val);
            m->e[i] = m->e[--m->n];
            return 0;
        }
    }
    return -1;
}

lite_store *lite_store_mem_new(void) {
    lite_store *s = calloc(1, sizeof *s);
    s->ctx = calloc(1, sizeof(memstore));
    s->get = ms_get;
    s->set = ms_set;
    s->remove = ms_remove;
    return s;
}

void lite_store_mem_free(lite_store *s) {
    if (!s) return;
    memstore *m = s->ctx;
    for (size_t i = 0; i < m->n; i++) { free(m->e[i].file); free(m->e[i].key); free(m->e[i].val); }
    free(m->e);
    free(m);
    free(s);
}
