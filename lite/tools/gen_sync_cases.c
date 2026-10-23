#include "lite/wallet.h"
#include "lite/primitives.h"
#include "lite/codec.h"
#include "npci_test_ca.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Runs lite_sync over a table of scenarios and emits each incoming state + the C decision, so the
// genuine-CL oracle can recompute the CL's accept/reject rule and confirm they agree.

static char *state(npci_ca *ca, const char *acs, long long ts) {
    char inner[256];
    snprintf(inner, sizeof inner,
             "{\"BAL\":\"5000.00\",\"LTL\":\"1000.00\",\"ACSTATUS\":\"%s\",\"timestamp\":\"%lld\"}",
             acs, ts);
    return npci_ca_sign_state(ca, inner);
}

static const char *decision_name(int rc) {
    switch (rc) {
        case LITE_SYNC_OK: return "OK";
        case LITE_SYNC_BAD_SIG: return "BAD_SIG";
        case LITE_SYNC_STALE: return "STALE";
        case LITE_SYNC_DEACTIVATED: return "DEACTIVATED";
        default: return "ERR";
    }
}

// Flips one base64 char of the signature so the genuine CL verify must fail.
static char *tamper(const char *signed_state) {
    char *s = strdup(signed_state);
    char *sig = strstr(s, "\"signature\":\"");
    if (sig) { char *v = sig + 13; if (v[0]) v[0] = (v[0] == 'A') ? 'B' : 'A'; }
    return s;
}

int main(int argc, char **argv) {
    FILE *f = argc > 1 ? fopen(argv[1], "w") : stdout;
    npci_ca *ca = npci_ca_new();
    size_t clen;
    const uint8_t *cert = npci_ca_cert_pem(ca, &clen);
    size_t ccap = lite_b64_encode_len(clen, LITE_B64_NO_WRAP);
    char *cert_b64 = malloc(ccap);
    lite_b64_encode(cert, clen, LITE_B64_NO_WRAP, cert_b64, ccap);
    fprintf(f, "{\"cert\":\"%s\"}\n", cert_b64);

    struct { long long old_ts, new_ts; const char *acs; int tampered; } cases[] = {
        {1000, 2000, "A", 0},   {1000, 1000, "A", 0},   {2000, 1000, "A", 0},
        {1000, 2000, "A", 1},   {1000, 3000, "DA", 0},  {5000, 5001, "A", 0},
        {5000, 4999, "A", 0},   {1000, 2000, "DA", 1},
    };

    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        lite_env env = {0};
        env.crypto = lite_crypto_openssl();
        env.keystore = lite_keystore_mem_new();
        env.store = lite_store_mem_new();
        env.clock = lite_clock_fixed_new(0);
        env.rng = lite_rng_seeded_new(1 + i);
        env.signer_upi_cert = cert;
        env.signer_upi_cert_len = clen;

        char alias[256];
        lite_alias(env.crypto, "DEV", "9000000000", "ACC", "UPI", alias, sizeof alias);
        char *base = state(ca, "A", cases[i].old_ts);
        lite_onboard(&env, alias, base);

        char *inc = state(ca, cases[i].acs, cases[i].new_ts);
        char *use = cases[i].tampered ? tamper(inc) : strdup(inc);
        int rc = lite_sync(&env, alias, use);

        fprintf(f, "{\"old_ts\":%lld,\"new_ts\":%lld,\"acs\":\"%s\",\"tampered\":%d,"
                   "\"state\":%s,\"decision\":\"%s\"}\n",
                cases[i].old_ts, cases[i].new_ts, cases[i].acs, cases[i].tampered,
                use, decision_name(rc));

        free(base); free(inc); free(use);
        lite_keystore_mem_free(env.keystore);
        lite_store_mem_free(env.store);
        lite_clock_fixed_free((lite_clock *)env.clock);
        lite_rng_seeded_free((lite_rng *)env.rng);
    }
    free(cert_b64);
    npci_ca_free(ca);
    if (f != stdout) fclose(f);
    return 0;
}
