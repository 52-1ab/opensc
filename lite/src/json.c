#include "lite/json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct lj_node {
    lj_type type;
    char *str;              // STR/NUM text, or key when stored as an entry
    int bval;
    lj_node **kids;
    char **keys;            // non-NULL for OBJ entries
    size_t n, cap;
};

static lj_node *node_new(lj_type t) {
    lj_node *n = calloc(1, sizeof *n);
    n->type = t;
    return n;
}

lj_node *lj_new_obj(void) { return node_new(LJ_OBJ); }
lj_node *lj_new_arr(void) { return node_new(LJ_ARR); }

void lj_free(lj_node *n) {
    if (!n) return;
    for (size_t i = 0; i < n->n; i++) {
        lj_free(n->kids[i]);
        if (n->keys) free(n->keys[i]);
    }
    free(n->kids);
    free(n->keys);
    free(n->str);
    free(n);
}

lj_type lj_typeof(const lj_node *n) { return n ? n->type : LJ_NULL; }

static void grow(lj_node *n) {
    if (n->n < n->cap) return;
    n->cap = n->cap ? n->cap * 2 : 4;
    n->kids = realloc(n->kids, n->cap * sizeof *n->kids);
    if (n->type == LJ_OBJ) n->keys = realloc(n->keys, n->cap * sizeof *n->keys);
}

void lj_put_node(lj_node *obj, const char *key, lj_node *val) {
    for (size_t i = 0; i < obj->n; i++) {
        if (strcmp(obj->keys[i], key) == 0) {
            lj_free(obj->kids[i]);
            obj->kids[i] = val;
            return;
        }
    }
    grow(obj);
    obj->keys[obj->n] = strdup(key);
    obj->kids[obj->n] = val;
    obj->n++;
}

void lj_put_str(lj_node *obj, const char *key, const char *val) {
    lj_node *s = node_new(LJ_STR);
    s->str = strdup(val);
    lj_put_node(obj, key, s);
}

const lj_node *lj_get(const lj_node *obj, const char *key) {
    if (!obj || obj->type != LJ_OBJ) return NULL;
    for (size_t i = 0; i < obj->n; i++)
        if (strcmp(obj->keys[i], key) == 0) return obj->kids[i];
    return NULL;
}

const char *lj_as_str(const lj_node *n) {
    if (!n) return NULL;
    if (n->type == LJ_STR || n->type == LJ_NUM) return n->str;
    if (n->type == LJ_BOOL) return n->bval ? "true" : "false";
    return NULL;
}

const char *lj_get_str(const lj_node *obj, const char *key, const char *dflt) {
    const lj_node *v = lj_get(obj, key);
    const char *s = lj_as_str(v);
    return s ? s : dflt;
}

size_t lj_len(const lj_node *arr) { return (arr && arr->type == LJ_ARR) ? arr->n : 0; }
const lj_node *lj_at(const lj_node *arr, size_t i) {
    return (arr && arr->type == LJ_ARR && i < arr->n) ? arr->kids[i] : NULL;
}
void lj_append(lj_node *arr, lj_node *val) {
    grow(arr);
    arr->kids[arr->n++] = val;
}

typedef struct { const char *s; size_t i, n; } parser;

static lj_node *parse_val(parser *p);

static void skip_ws(parser *p) {
    while (p->i < p->n) {
        char c = p->s[p->i];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') p->i++;
        else break;
    }
}

static char *parse_rawstr(parser *p) {
    if (p->i >= p->n || p->s[p->i] != '"') return NULL;
    p->i++;
    size_t cap = 16, len = 0;
    char *out = malloc(cap);
    while (p->i < p->n && p->s[p->i] != '"') {
        char c = p->s[p->i++];
        if (c == '\\' && p->i < p->n) {
            char e = p->s[p->i++];
            switch (e) {
                case 'n': c = '\n'; break;
                case 't': c = '\t'; break;
                case 'r': c = '\r'; break;
                case 'b': c = '\b'; break;
                case 'f': c = '\f'; break;
                case '/': c = '/'; break;
                case '"': c = '"'; break;
                case '\\': c = '\\'; break;
                case 'u': {
                    unsigned v = 0;
                    for (int k = 0; k < 4 && p->i < p->n; k++) {
                        char h = p->s[p->i++];
                        v <<= 4;
                        if (h >= '0' && h <= '9') v |= (unsigned)(h - '0');
                        else if (h >= 'a' && h <= 'f') v |= (unsigned)(h - 'a' + 10);
                        else if (h >= 'A' && h <= 'F') v |= (unsigned)(h - 'A' + 10);
                    }
                    if (len + 3 >= cap) { cap = len + 8; out = realloc(out, cap); }
                    if (v < 0x80) { out[len++] = (char)v; }
                    else if (v < 0x800) {
                        out[len++] = (char)(0xC0 | (v >> 6));
                        out[len++] = (char)(0x80 | (v & 0x3F));
                    } else {
                        out[len++] = (char)(0xE0 | (v >> 12));
                        out[len++] = (char)(0x80 | ((v >> 6) & 0x3F));
                        out[len++] = (char)(0x80 | (v & 0x3F));
                    }
                    continue;
                }
                default: c = e; break;
            }
        }
        if (len + 1 >= cap) { cap *= 2; out = realloc(out, cap); }
        out[len++] = c;
    }
    if (p->i < p->n) p->i++;
    out[len] = '\0';
    return out;
}

static lj_node *parse_obj(parser *p) {
    lj_node *o = lj_new_obj();
    p->i++;
    skip_ws(p);
    if (p->i < p->n && p->s[p->i] == '}') { p->i++; return o; }
    while (p->i < p->n) {
        skip_ws(p);
        char *key = parse_rawstr(p);
        if (!key) { lj_free(o); return NULL; }
        skip_ws(p);
        if (p->i >= p->n || p->s[p->i] != ':') { free(key); lj_free(o); return NULL; }
        p->i++;
        lj_node *v = parse_val(p);
        if (!v) { free(key); lj_free(o); return NULL; }
        lj_put_node(o, key, v);
        free(key);
        skip_ws(p);
        if (p->i < p->n && p->s[p->i] == ',') { p->i++; continue; }
        break;
    }
    skip_ws(p);
    if (p->i < p->n && p->s[p->i] == '}') p->i++;
    return o;
}

static lj_node *parse_arr(parser *p) {
    lj_node *a = lj_new_arr();
    p->i++;
    skip_ws(p);
    if (p->i < p->n && p->s[p->i] == ']') { p->i++; return a; }
    while (p->i < p->n) {
        lj_node *v = parse_val(p);
        if (!v) { lj_free(a); return NULL; }
        lj_append(a, v);
        skip_ws(p);
        if (p->i < p->n && p->s[p->i] == ',') { p->i++; continue; }
        break;
    }
    skip_ws(p);
    if (p->i < p->n && p->s[p->i] == ']') p->i++;
    return a;
}

static lj_node *parse_val(parser *p) {
    skip_ws(p);
    if (p->i >= p->n) return NULL;
    char c = p->s[p->i];
    if (c == '{') return parse_obj(p);
    if (c == '[') return parse_arr(p);
    if (c == '"') {
        lj_node *s = node_new(LJ_STR);
        s->str = parse_rawstr(p);
        return s;
    }
    if (strncmp(p->s + p->i, "true", 4) == 0) { p->i += 4; lj_node *n = node_new(LJ_BOOL); n->bval = 1; return n; }
    if (strncmp(p->s + p->i, "false", 5) == 0) { p->i += 5; lj_node *n = node_new(LJ_BOOL); n->bval = 0; return n; }
    if (strncmp(p->s + p->i, "null", 4) == 0) { p->i += 4; return node_new(LJ_NULL); }
    size_t start = p->i;
    while (p->i < p->n) {
        char d = p->s[p->i];
        if ((d >= '0' && d <= '9') || d == '-' || d == '+' || d == '.' || d == 'e' || d == 'E') p->i++;
        else break;
    }
    if (p->i == start) return NULL;
    lj_node *num = node_new(LJ_NUM);
    num->str = malloc(p->i - start + 1);
    memcpy(num->str, p->s + start, p->i - start);
    num->str[p->i - start] = '\0';
    return num;
}

lj_node *lj_parse(const char *text, size_t len) {
    parser p = {text, 0, len};
    lj_node *v = parse_val(&p);
    return v;
}

typedef struct { char *buf; size_t len, cap; } sb;

static void sb_putc(sb *b, char c) {
    if (b->len + 1 >= b->cap) { b->cap = b->cap ? b->cap * 2 : 64; b->buf = realloc(b->buf, b->cap); }
    b->buf[b->len++] = c;
}
static void sb_puts(sb *b, const char *s) { while (*s) sb_putc(b, *s++); }

static void dump_str(sb *b, const char *s) {
    sb_putc(b, '"');
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
            case '"': sb_puts(b, "\\\""); break;
            case '\\': sb_puts(b, "\\\\"); break;
            case '\n': sb_puts(b, "\\n"); break;
            case '\r': sb_puts(b, "\\r"); break;
            case '\t': sb_puts(b, "\\t"); break;
            case '\b': sb_puts(b, "\\b"); break;
            case '\f': sb_puts(b, "\\f"); break;
            default:
                if (c < 0x20) { char t[8]; snprintf(t, sizeof t, "\\u%04x", c); sb_puts(b, t); }
                else sb_putc(b, (char)c);
        }
    }
    sb_putc(b, '"');
}

static void dump_node(sb *b, const lj_node *n) {
    switch (n->type) {
        case LJ_NULL: sb_puts(b, "null"); break;
        case LJ_BOOL: sb_puts(b, n->bval ? "true" : "false"); break;
        case LJ_NUM: sb_puts(b, n->str ? n->str : "0"); break;
        case LJ_STR: dump_str(b, n->str ? n->str : ""); break;
        case LJ_ARR:
            sb_putc(b, '[');
            for (size_t i = 0; i < n->n; i++) { if (i) sb_putc(b, ','); dump_node(b, n->kids[i]); }
            sb_putc(b, ']');
            break;
        case LJ_OBJ:
            sb_putc(b, '{');
            for (size_t i = 0; i < n->n; i++) {
                if (i) sb_putc(b, ',');
                dump_str(b, n->keys[i]);
                sb_putc(b, ':');
                dump_node(b, n->kids[i]);
            }
            sb_putc(b, '}');
            break;
    }
}

char *lj_dump(const lj_node *n) {
    sb b = {0};
    dump_node(&b, n);
    sb_putc(&b, '\0');
    return b.buf;
}
