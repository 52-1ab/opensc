#include "lite/json.h"
#include "parson.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Thin adapter: the lj_* facade (used across the lib) backed by the vendored parson submodule.
// parson keeps object key order and replaces an existing key in place, matching the CL's org.json.

static JSON_Value *V(const lj_node *n) { return (JSON_Value *)n; }

lj_node *lj_parse(const char *text, size_t len) {
    char *s = malloc(len + 1);
    memcpy(s, text, len);
    s[len] = '\0';
    JSON_Value *v = json_parse_string(s);
    free(s);
    return (lj_node *)v;
}

lj_node *lj_new_obj(void) { return (lj_node *)json_value_init_object(); }
lj_node *lj_new_arr(void) { return (lj_node *)json_value_init_array(); }
void lj_free(lj_node *n) { json_value_free(V(n)); }

lj_type lj_typeof(const lj_node *n) {
    if (!n) return LJ_NULL;
    switch (json_value_get_type(V(n))) {
        case JSONString: return LJ_STR;
        case JSONNumber: return LJ_NUM;
        case JSONObject: return LJ_OBJ;
        case JSONArray: return LJ_ARR;
        case JSONBoolean: return LJ_BOOL;
        default: return LJ_NULL;
    }
}

const lj_node *lj_get(const lj_node *obj, const char *key) {
    if (!obj || json_value_get_type(V(obj)) != JSONObject) return NULL;
    return (const lj_node *)json_object_get_value(json_value_get_object(V(obj)), key);
}

const char *lj_get_str(const lj_node *obj, const char *key, const char *dflt) {
    if (!obj || json_value_get_type(V(obj)) != JSONObject) return dflt;
    const char *s = json_object_get_string(json_value_get_object(V(obj)), key);
    return s ? s : dflt;
}

void lj_put_str(lj_node *obj, const char *key, const char *val) {
    json_object_set_string(json_value_get_object(V(obj)), key, val);
}

void lj_put_node(lj_node *obj, const char *key, lj_node *val) {
    json_object_set_value(json_value_get_object(V(obj)), key, V(val));
}

size_t lj_len(const lj_node *arr) {
    if (!arr || json_value_get_type(V(arr)) != JSONArray) return 0;
    return json_array_get_count(json_value_get_array(V(arr)));
}

const lj_node *lj_at(const lj_node *arr, size_t i) {
    if (!arr || json_value_get_type(V(arr)) != JSONArray) return NULL;
    return (const lj_node *)json_array_get_value(json_value_get_array(V(arr)), i);
}

void lj_append(lj_node *arr, lj_node *val) {
    json_array_append_value(json_value_get_array(V(arr)), V(val));
}

// parson stores numbers as doubles; format into a small rotating buffer for the few numeric reads.
static char *num_slot(void) {
    static char ring[8][32];
    static int i = 0;
    i = (i + 1) & 7;
    return ring[i];
}

const char *lj_as_str(const lj_node *n) {
    if (!n) return NULL;
    switch (json_value_get_type(V(n))) {
        case JSONString:
            return json_value_get_string(V(n));
        case JSONNumber: {
            char *s = num_slot();
            snprintf(s, 32, "%g", json_value_get_number(V(n)));
            return s;
        }
        case JSONBoolean:
            return json_value_get_boolean(V(n)) ? "true" : "false";
        default:
            return NULL;
    }
}

char *lj_dump(const lj_node *n) {
    char *s = json_serialize_to_string(V(n));
    char *r = strdup(s ? s : "null");
    json_free_serialized_string(s);
    return r;
}
