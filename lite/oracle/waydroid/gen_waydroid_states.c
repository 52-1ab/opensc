#include "lite/wallet.h"
#include "lite/primitives.h"
#include "lite/codec.h"
#include "npci_test_ca.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Emits the signed states + session key + expected C decision for the waydroid genuine-sync run.
// Writes cert.pem and cases.tsv under the output dir. States are base64'd for safe argv transport.

static char *state(npci_ca *ca, const char *acs, long long ts) {
    char inner[256];
    snprintf(inner, sizeof inner,
             "{\"BAL\":\"5000.00\",\"LTL\":\"1000.00\",\"ACSTATUS\":\"%s\",\"timestamp\":\"%lld\"}",
             acs, ts);
    return npci_ca_sign_state(ca, inner);
}

static char *b64(const char *s) {
    size_t cap = lite_b64_encode_len(strlen(s), LITE_B64_NO_WRAP);
    char *o = malloc(cap);
    lite_b64_encode((const uint8_t *)s, strlen(s), LITE_B64_NO_WRAP, o, cap);
    return o;
}

// The C decision for onboard(old)+sync(new), as the device result should agree with.
static const char *c_decision(const char *cert, size_t clen, const char *old_s, const char *new_s) {
    lite_env env = {0};
    env.crypto = lite_crypto_openssl();
    env.keystore = lite_keystore_mem_new();
    env.store = lite_store_mem_new();
    env.clock = lite_clock_fixed_new(0);
    env.rng = lite_rng_seeded_new(1);
    env.signer_upi_cert = (const uint8_t *)cert;
    env.signer_upi_cert_len = clen;
    char alias[256];
    lite_alias(env.crypto, "DEV", "9000000000", "ACC", "UPI", alias, sizeof alias);
    lite_onboard(&env, alias, old_s);
    int rc = lite_sync(&env, alias, new_s);
    lite_keystore_mem_free(env.keystore);
    lite_store_mem_free(env.store);
    lite_clock_fixed_free((lite_clock *)env.clock);
    lite_rng_seeded_free((lite_rng *)env.rng);
    switch (rc) {
        case LITE_SYNC_OK: return "OK";
        case LITE_SYNC_STALE: return "STALE";
        case LITE_SYNC_DEACTIVATED: return "DEACTIVATED";
        case LITE_SYNC_BAD_SIG: return "BAD_SIG";
        default: return "ERR";
    }
}

int main(int argc, char **argv) {
    const char *dir = argc > 1 ? argv[1] : ".";
    npci_ca *ca = npci_ca_new();
    size_t clen;
    const uint8_t *cert = npci_ca_cert_pem(ca, &clen);

    char path[1024];
    snprintf(path, sizeof path, "%s/cert.pem", dir);
    FILE *cf = fopen(path, "wb");
    fwrite(cert, 1, clen, cf);
    fclose(cf);

    uint8_t k[32];
    lite_rng *rng = lite_rng_seeded_new(123);
    rng->fill(rng->ctx, k, 32);
    char kb[64];
    lite_b64_encode(k, 32, LITE_B64_NO_WRAP, kb, sizeof kb);

    char *old_s = state(ca, "A", 1000);
    struct { const char *label, *acs; long long ts; const char *expect; } cs[] = {
        {"newer", "A", 2000, "true"},
        {"stale", "A", 500, "false"},
        {"equal", "A", 1000, "false"},
        {"deactivate", "DA", 3000, "true"},
    };

    snprintf(path, sizeof path, "%s/cases.tsv", dir);
    FILE *tf = fopen(path, "w");
    for (size_t i = 0; i < sizeof cs / sizeof cs[0]; i++) {
        char *new_s = state(ca, cs[i].acs, cs[i].ts);
        const char *dec = c_decision((const char *)cert, clen, old_s, new_s);
        char *ob = b64(old_s), *nb = b64(new_s);
        fprintf(tf, "%s\t9000000000\tDEV\tACC\t%s\t%s\t%s\t%s\t%s\n",
                cs[i].label, kb, ob, nb, dec, cs[i].expect);
        free(ob); free(nb); free(new_s);
    }
    fclose(tf);
    free(old_s);
    lite_rng_seeded_free(rng);
    npci_ca_free(ca);
    printf("wrote %s/cert.pem and %s/cases.tsv\n", dir, dir);
    return 0;
}
