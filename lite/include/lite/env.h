#ifndef LITE_ENV_H
#define LITE_ENV_H

#include <stdint.h>

#include "lite/crypto.h"
#include "lite/keystore.h"
#include "lite/store.h"

typedef struct lite_clock {
    void *ctx;
    int64_t (*now_millis)(void *ctx);
} lite_clock;

typedef struct lite_rng {
    void *ctx;
    int (*fill)(void *ctx, uint8_t *out, size_t len);
} lite_rng;

// Everything the wallet needs, injected so tests can pin the clock, RNG and keys.
typedef struct lite_env {
    const lite_crypto *crypto;
    lite_keystore *keystore;
    lite_store *store;
    const lite_clock *clock;
    const lite_rng *rng;
    const uint8_t *signer_upi_cert;   // PEM/DER of signer-upi.crt for riskRules verify
    size_t signer_upi_cert_len;
} lite_env;

lite_clock *lite_clock_fixed_new(int64_t millis);
void lite_clock_fixed_set(lite_clock *c, int64_t millis);
void lite_clock_fixed_free(lite_clock *c);

lite_rng *lite_rng_seeded_new(uint64_t seed);
void lite_rng_seeded_free(lite_rng *r);

#endif
