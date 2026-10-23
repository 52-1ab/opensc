#ifndef LITE_ENV_H
#define LITE_ENV_H

#include <stdint.h>

#include "lite/crypto.h"
#include "lite/keystore.h"
#include "lite/store.h"

/// @file
/// The injected runtime environment (crypto, keystore, store, clock, RNG) the wallet runs against.

/// Pluggable clock so tests can pin "now".
typedef struct lite_clock {
    void *ctx;                          ///< Backend-private state.
    int64_t (*now_millis)(void *ctx);   ///< Current time in epoch milliseconds.
} lite_clock;

/// Pluggable RNG so tests can make IVs and salts reproducible.
typedef struct lite_rng {
    void *ctx;                                      ///< Backend-private state.
    int (*fill)(void *ctx, uint8_t *out, size_t len);  ///< Fills `out` with `len` random bytes. 0 on success.
} lite_rng;

/// Everything the wallet needs, injected so tests can pin the clock, RNG and keys.
typedef struct lite_env {
    const lite_crypto *crypto;        ///< Stateless crypto primitives.
    lite_keystore *keystore;          ///< Alias-keyed key storage/signing.
    lite_store *store;                ///< SharedPreferences-shaped persistence.
    const lite_clock *clock;          ///< Time source.
    const lite_rng *rng;              ///< Randomness source.
    const uint8_t *signer_upi_cert;   ///< PEM/DER of signer-upi.crt, used to verify riskRules.
    size_t signer_upi_cert_len;       ///< Length of signer_upi_cert in bytes.
} lite_env;

/// Allocates a fixed clock reading `millis`. Free with lite_clock_fixed_free().
lite_clock *lite_clock_fixed_new(int64_t millis);
/// Sets the time a fixed clock reports.
void lite_clock_fixed_set(lite_clock *c, int64_t millis);
/// Frees a fixed clock created by lite_clock_fixed_new().
void lite_clock_fixed_free(lite_clock *c);

/// Allocates a deterministic (seeded) RNG. Free with lite_rng_seeded_free().
lite_rng *lite_rng_seeded_new(uint64_t seed);
/// Frees a seeded RNG created by lite_rng_seeded_new().
void lite_rng_seeded_free(lite_rng *r);

#endif
