#ifndef LITE_JSON_H
#define LITE_JSON_H

#include <stddef.h>

/// @file
/// Minimal JSON facade (backed by vendored parson), preserving key order like Android's org.json.

/// JSON value kinds.
typedef enum { LJ_NULL, LJ_BOOL, LJ_NUM, LJ_STR, LJ_ARR, LJ_OBJ } lj_type;

/// Opaque JSON value (object, array, or scalar).
typedef struct lj_node lj_node;

/// Parses `len` bytes of JSON text; returns a root node (free with lj_free) or NULL on error.
lj_node *lj_parse(const char *text, size_t len);
/// Creates an empty object node.
lj_node *lj_new_obj(void);
/// Creates an empty array node.
lj_node *lj_new_arr(void);
/// Frees a node and everything it owns (call only on a root).
void lj_free(lj_node *n);

/// Returns the kind of `n`.
lj_type lj_typeof(const lj_node *n);

/// Returns the value at `key`, or NULL if absent / not an object (borrowed).
const lj_node *lj_get(const lj_node *obj, const char *key);
/// Returns the string value at `key`, or `dflt` if absent / not a string.
const char *lj_get_str(const lj_node *obj, const char *key, const char *dflt);
/// Sets `key` to a string; updates in place if present, preserving position (matches org.json).
void lj_put_str(lj_node *obj, const char *key, const char *val);
/// Sets `key` to `val`, taking ownership of `val`; updates in place if present.
void lj_put_node(lj_node *obj, const char *key, lj_node *val);

/// Number of elements in an array (0 if not an array).
size_t lj_len(const lj_node *arr);
/// Element `i` of an array, or NULL if out of range / not an array (borrowed).
const lj_node *lj_at(const lj_node *arr, size_t i);
/// Appends `val` to an array, taking ownership of `val`.
void lj_append(lj_node *arr, lj_node *val);

/// Returns the scalar as text (string verbatim, number formatted, bool "true"/"false"), else NULL.
const char *lj_as_str(const lj_node *n);

/// Serializes `n` compactly (no spaces, escaped strings) like org.json toString(); caller frees.
char *lj_dump(const lj_node *n);

#endif
