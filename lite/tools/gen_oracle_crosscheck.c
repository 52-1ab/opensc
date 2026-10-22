#include "lite/codec.h"
#include "lite/crypto.h"
#include "lite/env.h"
#include "lite/primitives.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Emits cross-check material the genuine CL consumes: a C-made vault signature (CL must verify)
// and a C-encrypted vault blob (CL must decrypt). Consumed by the oracle's crosscheck mode.
static void field_b64(FILE *f, const char *name, const uint8_t *b, size_t n) {
    size_t cap = lite_b64_encode_len(n, LITE_B64_NO_WRAP);
    char *s = malloc(cap);
    lite_b64_encode(b, n, LITE_B64_NO_WRAP, s, cap);
    fprintf(f, "\"%s\":\"%s\",", name, s);
    free(s);
}

static void field_str(FILE *f, const char *name, const char *v, int last) {
    fprintf(f, "\"%s\":\"", name);
    for (const char *p = v; *p; p++) {
        if (*p == '\n') fputs("\\n", f);
        else if (*p == '"') fputs("\\\"", f);
        else if (*p == '\\') fputs("\\\\", f);
        else fputc(*p, f);
    }
    fputs(last ? "\"" : "\",", f);
}

int main(int argc, char **argv) {
    const lite_crypto *c = lite_crypto_openssl();
    lite_keystore *ks = lite_keystore_mem_new();
    lite_rng *rng = lite_rng_seeded_new(99);
    FILE *f = argc > 1 ? fopen(argv[1], "w") : stdout;

    uint8_t spki[1024];
    long spn = ks->gen_rsa(ks->ctx, "ORACLE_SIG", 1, spki, sizeof spki);

    char msg[128];
    lite_vault_sig_message(c, "aGVsbG8sIHdvcmxkIQ==", "MTIzNDU2Nzg5MDEy", msg, sizeof msg);
    uint8_t sig[512];
    long sn = ks->sign(ks->ctx, "ORACLE_SIG", 0, (const uint8_t *)msg, strlen(msg), sig, sizeof sig);

    uint8_t key[32], iv[12];
    rng->fill(rng->ctx, key, sizeof key);
    rng->fill(rng->ctx, iv, sizeof iv);
    const char *pt = "{\"BAL\":\"5000.00\",\"ATC\":\"7\"}";
    size_t pl = strlen(pt);
    uint8_t blob[256], tag[16];
    c->aes_gcm_encrypt(c->ctx, key, 32, iv, 12, (const uint8_t *)pt, pl, blob, tag);
    memcpy(blob + pl, tag, 16);

    fputs("{", f);
    field_b64(f, "sig_pubkey", spki, (size_t)spn);
    field_str(f, "sig_msg", msg, 0);
    field_b64(f, "sig", sig, (size_t)sn);
    field_b64(f, "aes_key", key, 32);
    field_b64(f, "aes_ct", blob, pl + 16);
    field_b64(f, "aes_iv", iv, 12);
    field_str(f, "aes_plain", pt, 1);
    fputs("}\n", f);

    if (f != stdout) fclose(f);
    lite_keystore_mem_free(ks);
    lite_rng_seeded_free(rng);
    return 0;
}
