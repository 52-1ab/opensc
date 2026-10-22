#include "lite/env.h"

#include <stdlib.h>

typedef struct { int64_t ms; } fixedclock;

static int64_t fc_now(void *ctx) { return ((fixedclock *)ctx)->ms; }

lite_clock *lite_clock_fixed_new(int64_t millis) {
    lite_clock *c = calloc(1, sizeof *c);
    fixedclock *f = calloc(1, sizeof *f);
    f->ms = millis;
    c->ctx = f;
    c->now_millis = fc_now;
    return c;
}

void lite_clock_fixed_set(lite_clock *c, int64_t millis) { ((fixedclock *)c->ctx)->ms = millis; }

void lite_clock_fixed_free(lite_clock *c) {
    if (!c) return;
    free(c->ctx);
    free(c);
}

typedef struct { uint64_t s; } xrng;

// splitmix64: deterministic test RNG so IVs and salts are reproducible across runs.
static int xr_fill(void *ctx, uint8_t *out, size_t len) {
    xrng *r = ctx;
    for (size_t i = 0; i < len; i++) {
        r->s += 0x9E3779B97F4A7C15ULL;
        uint64_t z = r->s;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        z ^= z >> 31;
        out[i] = (uint8_t)z;
    }
    return 0;
}

lite_rng *lite_rng_seeded_new(uint64_t seed) {
    lite_rng *r = calloc(1, sizeof *r);
    xrng *x = calloc(1, sizeof *x);
    x->s = seed;
    r->ctx = x;
    r->fill = xr_fill;
    return r;
}

void lite_rng_seeded_free(lite_rng *r) {
    if (!r) return;
    free(r->ctx);
    free(r);
}
