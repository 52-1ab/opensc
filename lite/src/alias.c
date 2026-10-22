#include "lite/primitives.h"
#include "lite/codec.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

long lite_sha256_b64(const lite_crypto *c, const char *s, char *out, size_t cap) {
    uint8_t h[32];
    if (c->sha256(c->ctx, (const uint8_t *)s, strlen(s), h) != 0) return -1;
    size_t n = lite_b64_encode(h, 32, LITE_B64_NO_WRAP, out, cap);
    return n ? (long)n : -1;
}

long lite_alias(const lite_crypto *c, const char *device_id, const char *mobile,
                const char *account_ref, const char *service, char *out, size_t cap) {
    char buf[512];
    int n = snprintf(buf, sizeof buf, "%s%s%s%s", device_id, mobile, account_ref, service);
    if (n < 0 || (size_t)n >= sizeof buf) return -1;
    return lite_sha256_b64(c, buf, out, cap);
}

long lite_sha1_id35(const lite_crypto *c, const char *s, char *out, size_t cap) {
    uint8_t h[20];
    if (c->sha1(c->ctx, (const uint8_t *)s, strlen(s), h) != 0) return -1;
    char hex[41];
    lite_hex_encode(h, 20, hex, sizeof hex);
    if (cap < 36) return -1;
    memcpy(out, hex, 35);
    out[35] = '\0';
    return 35;
}

long lite_debit_payload(const char *amount, const char *txn_id, const char *ts,
                        const char *payer_lite_acc, const char *payee_addr, const char *app_id,
                        const char *mobile, const char *device_id, const char *risk_params,
                        char *out, size_t cap) {
    int n = snprintf(out, cap, "1.0|%s|%s|%s|%s|%s|%s|%s|%s|%s", amount, txn_id, ts,
                     payer_lite_acc, payee_addr, app_id, mobile, device_id, risk_params);
    if (n < 0 || (size_t)n >= cap) return -1;
    return n;
}

long lite_vault_sig_message(const lite_crypto *c, const char *ct_b64, const char *iv_b64,
                            char *out, size_t cap) {
    uint8_t iv[64];
    long iv_len = lite_b64_decode(iv_b64, strlen(iv_b64), iv, sizeof iv);
    if (iv_len < 0) return -1;
    size_t ct_len = strlen(ct_b64);
    uint8_t *msg = malloc((size_t)iv_len + ct_len);
    if (!msg) return -1;
    memcpy(msg, iv, (size_t)iv_len);
    memcpy(msg + iv_len, ct_b64, ct_len);
    uint8_t h[32];
    int rc = c->sha256(c->ctx, msg, (size_t)iv_len + ct_len, h);
    free(msg);
    if (rc != 0) return -1;
    size_t n = lite_b64_encode(h, 32, LITE_B64_DEFAULT, out, cap);
    return n ? (long)n : -1;
}
