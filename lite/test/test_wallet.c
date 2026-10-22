#include "lite/wallet.h"
#include "lite/primitives.h"
#include "npci_test_ca.h"
#include "testutil.h"

static char *state(npci_ca *ca, const char *bal, const char *ltl, const char *acs, long long ts) {
    char inner[512];
    snprintf(inner, sizeof inner,
             "{\"BAL\":\"%s\",\"LTL\":\"%s\",\"ACSTATUS\":\"%s\",\"EOT\":\"true\",\"timestamp\":\"%lld\"}",
             bal, ltl, acs, ts);
    return npci_ca_sign_state(ca, inner);
}

int main(void) {
    npci_ca *ca = npci_ca_new();
    size_t clen;
    const uint8_t *cert = npci_ca_cert_pem(ca, &clen);

    lite_env env = {0};
    env.crypto = lite_crypto_openssl();
    env.keystore = lite_keystore_mem_new();
    env.store = lite_store_mem_new();
    env.clock = lite_clock_fixed_new(1767225600000LL);
    env.rng = lite_rng_seeded_new(7);
    env.signer_upi_cert = cert;
    env.signer_upi_cert_len = clen;

    char alias[256];
    CHECK(lite_alias(env.crypto, "DEV123", "9663078862", "ACC789", "UPI", alias, sizeof alias) > 0);

    char *s1 = state(ca, "5000.00", "1000.00", "A", 1000);
    CHECK(lite_onboard(&env, alias, s1) == LITE_SYNC_OK);

    lite_bind_info bi;
    CHECK(lite_is_bound(&env, alias, &bi) == LITE_BIND_YES);
    CHECK_STR(bi.ltl, "1000.00");
    CHECK_STR(bi.bal, "5000.00");
    CHECK_STR(bi.acstatus, "A");
    CHECK(bi.sync_required == 0);

    lite_balance_info bal;
    CHECK(lite_balance(&env, alias, &bal) == LITE_OK);
    CHECK(bal.balance == 5000.0);
    CHECK(bal.pending_count == 0);

    lite_txn txn = {"100.00", "TXN1", "20260101120000", "5001234567", "merchant@upi",
                    "com.phonepe.app", "9663078862", "DEV123"};
    char out[8192];
    CHECK(lite_spend(&env, alias, &txn, 0, out, sizeof out) == LITE_OK);
    CHECK(strstr(out, "\"signature\":") != NULL);
    CHECK(strstr(out, "\"riskParams\":") != NULL);

    CHECK(lite_balance(&env, alias, &bal) == LITE_OK);
    CHECK(bal.balance == 4900.0);
    CHECK(bal.pending_count == 1);

    lite_txn txn2 = {"50.00", "TXN2", "20260101120100", "5001234567", "merchant@upi",
                     "com.phonepe.app", "9663078862", "DEV123"};
    CHECK(lite_spend(&env, alias, &txn2, 0, out, sizeof out) == LITE_SPEND_SYNC_REQUIRED);

    char *s2 = state(ca, "4900.00", "1000.00", "A", 2000);
    CHECK(lite_sync(&env, alias, s2) == LITE_SYNC_OK);
    CHECK(lite_is_bound(&env, alias, &bi) == LITE_BIND_YES);
    CHECK(bi.sync_required == 0);

    CHECK(lite_spend(&env, alias, &txn2, 0, out, sizeof out) == LITE_OK);

    char *s3 = state(ca, "4850.00", "1000.00", "A", 2000);
    CHECK(lite_sync(&env, alias, s3) == LITE_SYNC_STALE);

    lite_txn over = {"2000.00", "TXN3", "20260101120200", "5001234567", "merchant@upi",
                     "com.phonepe.app", "9663078862", "DEV123"};
    char *s4 = state(ca, "4850.00", "1000.00", "A", 3000);
    CHECK(lite_sync(&env, alias, s4) == LITE_SYNC_OK);
    CHECK(lite_spend(&env, alias, &over, 0, out, sizeof out) == LITE_SPEND_DECLINED);

    CHECK(lite_unbind(&env, alias) == LITE_OK);
    CHECK(lite_is_bound(&env, alias, &bi) == LITE_BIND_NO);

    free(s1); free(s2); free(s3); free(s4);
    lite_keystore_mem_free(env.keystore);
    lite_store_mem_free(env.store);
    lite_clock_fixed_free((lite_clock *)env.clock);
    lite_rng_seeded_free((lite_rng *)env.rng);
    npci_ca_free(ca);
    printf("test_wallet");
    DONE();
}
