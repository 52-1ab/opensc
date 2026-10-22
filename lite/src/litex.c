#include "lite/litex.h"
#include "lite/codec.h"
#include "lite/json.h"
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

long litex_offline_pubkey(lite_env *env, const char *alias, char *out_b64, size_t cap) {
    char off[320];
    snprintf(off, sizeof off, "%s-OFFLINE", alias);
    uint8_t spki[256];
    long n = env->keystore->pubkey(env->keystore->ctx, off, spki, sizeof spki);
    if (n < 0) return -1;
    size_t need = lite_b64_encode_len((size_t)n, LITE_B64_NO_WRAP);
    if (need > cap) return -1;
    return (long)lite_b64_encode(spki, (size_t)n, LITE_B64_NO_WRAP, out_b64, cap);
}

int litex_verify_pub(lite_env *env, const char *pub_b64, const char *data, const char *sig_b64) {
    uint8_t spki[256], sig[256];
    long sp = lite_b64_decode(pub_b64, strlen(pub_b64), spki, sizeof spki);
    long sn = lite_b64_decode(sig_b64, strlen(sig_b64), sig, sizeof sig);
    if (sp < 0 || sn < 0) return -1;
    return env->crypto->ecdsa_sha256_verify(env->crypto->ctx, spki, (size_t)sp,
                                            (const uint8_t *)data, strlen(data), sig, (size_t)sn);
}

// generateSignaturePayload (o000OO0O.OooO0Oo): fixed field order, no delimiter.
static void sig_payload(const litex_xfer *x, char *out, size_t cap) {
    snprintf(out, cap, "%s%s%s%s%s%s%s%s%s", x->payer_id, x->payer_seq, x->payer_vpa,
             x->payee_id, x->payee_seq, x->payee_vpa, x->timestamp, x->currency, x->amount);
}

int litex_purse_start(litex_purse *p, lite_env *env, const char *alias, double balance) {
    memset(p, 0, sizeof *p);
    p->env = env;
    snprintf(p->alias, sizeof p->alias, "%s", alias);
    p->state = LX_IDLE;
    p->balance = balance;
    return litex_enable(env, alias);
}

void litex_purse_set_remote(litex_purse *p, const char *remote_pub_b64) {
    snprintf(p->remote_pub, sizeof p->remote_pub, "%s", remote_pub_b64);
}

int litex_start_debit(litex_purse *p, const litex_xfer *x) {
    if (p->state != LX_IDLE) return LX_ERR_STATE;
    double amt = strtod(x->amount, NULL);
    litex_pvr pvr;
    litex_pvr_init(&pvr);
    if (amt > p->balance) litex_pvr_set(&pvr, 7, 8, 1);
    for (int i = 0; i < 8; i++) if (pvr.b[i]) return LX_DECLINED;
    sig_payload(x, p->txndp, sizeof p->txndp);
    litex_txn_id(p->env->crypto, x->payer_id, x->payer_seq, x->payee_vpa,
                 x->payee_id, x->payee_seq, x->payer_vpa, p->txn_id, sizeof p->txn_id);
    p->state = LX_AWAITING_REQ;
    return LX_OK;
}

int litex_start_credit(litex_purse *p, const litex_xfer *x, char *reqs_out, size_t cap) {
    if (p->state != LX_IDLE) return LX_ERR_STATE;
    sig_payload(x, p->txndp, sizeof p->txndp);
    litex_txn_id(p->env->crypto, x->payer_id, x->payer_seq, x->payee_vpa,
                 x->payee_id, x->payee_seq, x->payer_vpa, p->txn_id, sizeof p->txn_id);
    if (litex_sign(p->env, p->alias, p->txndp, reqs_out, cap) < 0) return -1;
    p->state = LX_AWAITING_VAL;
    return LX_OK;
}

int litex_request_value(litex_purse *p, const char *reqs, char *tras_out, size_t cap) {
    if (p->state != LX_AWAITING_REQ) return LX_ERR_STATE;
    if (litex_verify_pub(p->env, p->remote_pub, p->txndp, reqs) != 1) return LX_BAD_SIG;
    char chain[2048];
    snprintf(chain, sizeof chain, "%s%s", p->txndp, reqs);
    if (litex_sign(p->env, p->alias, chain, tras_out, cap) < 0) return -1;
    p->state = LX_AWAITING_ACK;
    return LX_OK;
}

int litex_transfer_value(litex_purse *p, const char *reqs, const char *tras, char *acks_out, size_t cap) {
    if (p->state != LX_AWAITING_VAL) return LX_ERR_STATE;
    char chain[2048];
    snprintf(chain, sizeof chain, "%s%s", p->txndp, reqs);
    if (litex_verify_pub(p->env, p->remote_pub, chain, tras) != 1) return LX_BAD_SIG;
    char chain2[3072];
    snprintf(chain2, sizeof chain2, "%s%s", chain, tras);
    if (litex_sign(p->env, p->alias, chain2, acks_out, cap) < 0) return -1;
    p->state = LX_IDLE;
    return LX_OK;
}

int litex_acknowledge_value(litex_purse *p, const char *reqs, const char *tras, const char *acks) {
    if (p->state != LX_AWAITING_ACK) return LX_ERR_STATE;
    char chain2[3072];
    snprintf(chain2, sizeof chain2, "%s%s%s", p->txndp, reqs, tras);
    if (litex_verify_pub(p->env, p->remote_pub, chain2, acks) != 1) return LX_BAD_SIG;
    p->state = LX_IDLE;
    return LX_OK;
}

long litex_get_purse_info(litex_purse *p, double balance, char *challenge_out, size_t cap) {
    uint8_t rnd[8];
    if (p->env->rng->fill(p->env->rng->ctx, rnd, sizeof rnd) != 0) return -1;
    if (cap < 17) return -1;
    lite_hex_encode(rnd, 8, challenge_out, cap);
    p->balance = balance;
    p->state = LX_IDLE;
    return 16;
}

// Payload order matches o000OO0O assert/verifyIdentity: id+product+currency+country+type+mcc+cert+challenge.
static void identity_payload(const char *id, const char *product, const char *currency,
                             const char *country, const char *type, const char *mcc,
                             const char *cert, const char *challenge, char *out, size_t cap) {
    snprintf(out, cap, "%s%s%s%s%s%s%s%s", id, product, currency, country, type,
             mcc ? mcc : "", cert, challenge);
}

int litex_assert_identity(litex_purse *p, const litex_identity *id, const char *remote_challenge,
                          char *out_json, size_t cap) {
    char cert[512];
    if (litex_offline_pubkey(p->env, p->alias, cert, sizeof cert) < 0) return -1;
    char payload[2048];
    identity_payload(id->id, id->product, id->currency, id->country, id->type, id->mcc, cert,
                     remote_challenge, payload, sizeof payload);
    char ps[512];
    if (litex_sign(p->env, p->alias, payload, ps, sizeof ps) < 0) return -1;
    lj_node *o = lj_new_obj();
    lj_put_str(o, "id", id->id);
    lj_put_str(o, "product", id->product);
    lj_put_str(o, "currency", id->currency);
    lj_put_str(o, "country", id->country);
    lj_put_str(o, "type", id->type);
    if (id->mcc) lj_put_str(o, "mcc", id->mcc);
    lj_put_str(o, "purseCertificate", cert);
    lj_put_str(o, "signature", ps);
    char *s = lj_dump(o);
    lj_free(o);
    int rc = LX_OK;
    if (strlen(s) + 1 > cap) rc = -1; else memcpy(out_json, s, strlen(s) + 1);
    free(s);
    return rc;
}

int litex_verify_identity(litex_purse *p, const char *remote_json, const char *our_challenge) {
    lj_node *o = lj_parse(remote_json, strlen(remote_json));
    if (!o) return -1;
    const char *cert = lj_get_str(o, "purseCertificate", NULL);
    const char *ps = lj_get_str(o, "signature", NULL);
    const char *mcc = lj_get_str(o, "mcc", NULL);
    int rc;
    if (!cert || !ps) {
        rc = -1;
    } else {
        char payload[2048];
        identity_payload(lj_get_str(o, "id", ""), lj_get_str(o, "product", ""),
                         lj_get_str(o, "currency", ""), lj_get_str(o, "country", ""),
                         lj_get_str(o, "type", ""), mcc, cert, our_challenge, payload, sizeof payload);
        if (litex_verify_pub(p->env, cert, payload, ps) == 1) {
            snprintf(p->remote_pub, sizeof p->remote_pub, "%s", cert);
            rc = LX_OK;
        } else {
            rc = LX_BAD_SIG;
        }
    }
    lj_free(o);
    return rc;
}
