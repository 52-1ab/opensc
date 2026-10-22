#include "lite/litex.h"
#include "lite/codec.h"
#include "lite/primitives.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void litex_pvr_init(litex_pvr *p) { memset(p->b, 0, sizeof p->b); }

void litex_pvr_set(litex_pvr *p, int index, int bit, int on) {
    if (index < 1 || index > 8 || bit < 1 || bit > 8) return;
    uint8_t m = (uint8_t)(1 << (bit - 1));
    if (on) p->b[index - 1] |= m;
    else p->b[index - 1] &= (uint8_t)~m;
}

int lite_pvr_get(const litex_pvr *p, int index, int bit) {
    if (index < 1 || index > 8 || bit < 1 || bit > 8) return 0;
    return (p->b[index - 1] >> (bit - 1)) & 1;
}

// BigInteger(1, b).toString(16) zero-padded to 16 chars, matching the CL's byte->hex formatter.
void litex_pvr_hex(const litex_pvr *p, char out[17]) {
    lite_hex_encode(p->b, 8, out, 17);
}

int litex_pac_applies(uint8_t code, int is_debit) {
    int i = (code >> 6) & 3;
    return (i == 3) || (i == 1 && is_debit) || (i == 2 && !is_debit);
}

double litex_counter_update(uint8_t code, double cur, double amount) {
    int i = (code >> 5) & 1;
    if (i == 0) cur += 1.0;
    return i == 1 ? cur + amount : cur;
}

long litex_txn_id(const lite_crypto *c, const char *payer_id, const char *payer_seq,
                  const char *ac1, const char *payee_id, const char *payee_seq, const char *ac2,
                  char *out, size_t cap) {
    char buf[512];
    int n = snprintf(buf, sizeof buf, "%s.%s.%s.%s.%s.%s",
                     payer_id, payer_seq, ac1, payee_id, payee_seq, ac2);
    if (n < 0 || (size_t)n >= sizeof buf) return -1;
    return lite_sha1_id35(c, buf, out, cap);
}

int litex_enable(lite_env *env, const char *alias) {
    char off[320];
    snprintf(off, sizeof off, "%s-OFFLINE", alias);
    uint8_t spki[256];
    return env->keystore->gen_ec(env->keystore->ctx, off, spki, sizeof spki) < 0 ? -1 : 0;
}

long litex_sign(lite_env *env, const char *alias, const char *data, char *out_b64, size_t cap) {
    char off[320];
    snprintf(off, sizeof off, "%s-OFFLINE", alias);
    uint8_t sig[256];
    long n = env->keystore->sign(env->keystore->ctx, off, 1,
                                 (const uint8_t *)data, strlen(data), sig, sizeof sig);
    if (n < 0) return -1;
    size_t need = lite_b64_encode_len((size_t)n, LITE_B64_NO_WRAP);
    if (need > cap) return -1;
    return (long)lite_b64_encode(sig, (size_t)n, LITE_B64_NO_WRAP, out_b64, cap);
}

int litex_verify(lite_env *env, const char *alias, const char *data, const char *sig_b64) {
    char off[320];
    snprintf(off, sizeof off, "%s-OFFLINE", alias);
    uint8_t spki[256];
    long spn = env->keystore->pubkey(env->keystore->ctx, off, spki, sizeof spki);
    if (spn < 0) return -1;
    uint8_t sig[256];
    long sn = lite_b64_decode(sig_b64, strlen(sig_b64), sig, sizeof sig);
    if (sn < 0) return -1;
    return env->crypto->ecdsa_sha256_verify(env->crypto->ctx, spki, (size_t)spn,
                                            (const uint8_t *)data, strlen(data), sig, (size_t)sn);
}
