#ifndef LITE_JSON_H
#define LITE_JSON_H

#include <stddef.h>

typedef enum { LJ_NULL, LJ_BOOL, LJ_NUM, LJ_STR, LJ_ARR, LJ_OBJ } lj_type;

typedef struct lj_node lj_node;

lj_node *lj_parse(const char *text, size_t len);
lj_node *lj_new_obj(void);
lj_node *lj_new_arr(void);
void lj_free(lj_node *n);

lj_type lj_typeof(const lj_node *n);

// Object access/build. put() updates in place if key exists, matching Android LinkedHashMap.
const lj_node *lj_get(const lj_node *obj, const char *key);
const char *lj_get_str(const lj_node *obj, const char *key, const char *dflt);
void lj_put_str(lj_node *obj, const char *key, const char *val);
void lj_put_node(lj_node *obj, const char *key, lj_node *val);

// Array access/build.
size_t lj_len(const lj_node *arr);
const lj_node *lj_at(const lj_node *arr, size_t i);
void lj_append(lj_node *arr, lj_node *val);

const char *lj_as_str(const lj_node *n);

// Compact serialization matching org.json toString(): no spaces, escaped strings.
char *lj_dump(const lj_node *n);

#endif
