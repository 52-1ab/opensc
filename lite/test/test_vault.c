#include "lite/vault.h"
#include "lite/primitives.h"
#include "testutil.h"

int main(void) {
    lite_env env = {0};
    env.crypto = lite_crypto_openssl();
    env.keystore = lite_keystore_mem_new();
    env.store = lite_store_mem_new();
    env.clock = lite_clock_fixed_new(1767225600000LL);
    env.rng = lite_rng_seeded_new(42);

    char alias[256];
    CHECK(lite_alias(env.crypto, "DEV123", "9663078862", "ACC789", "UPI", alias, sizeof alias) > 0);

    CHECK(lite_vault_open(&env, alias) == LITE_OK);

    CHECK(lite_vault_set(&env, alias, "BAL", "5000.00") == LITE_OK);
    CHECK(lite_vault_set(&env, alias, "ATC", "7") == LITE_OK);

    char out[256];
    CHECK(lite_vault_get(&env, alias, "BAL", out, sizeof out) == 7);
    CHECK_STR(out, "5000.00");
    CHECK(lite_vault_get(&env, alias, "ATC", out, sizeof out) == 1);
    CHECK_STR(out, "7");
    CHECK(lite_vault_get(&env, alias, "MISSING", out, sizeof out) == LITE_ERR_ABSENT);

    char sigk[320];
    snprintf(sigk, sizeof sigk, "%s-SIGNATURE", alias);
    env.store->set(env.store->ctx, "NPCICLVAULT", sigk, "AAAAtampered");
    CHECK(lite_vault_get(&env, alias, "BAL", out, sizeof out) == LITE_ERR_TAMPER);
    CHECK(lite_vault_get(&env, alias, "BAL", out, sizeof out) == LITE_ERR_ABSENT);

    lite_keystore_mem_free(env.keystore);
    lite_store_mem_free(env.store);
    lite_clock_fixed_free((lite_clock *)env.clock);
    lite_rng_seeded_free((lite_rng *)env.rng);
    printf("test_vault");
    DONE();
}
