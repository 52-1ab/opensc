#include "lite/wallet.h"
#include "lite/codec.h"
#include "lite/json.h"
#include "lite/primitives.h"
#include "lite/riskrules.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SERVICE "UPI"
#define SESSION_KEY_FIELD "AESUPI"
#define CRR_DEFAULT "{\"ATC\":\"0\",\"OSN\":\"0\",\"PISC\":\"0\",\"PC1V\":\"0\",\"PC2V\":\"0\",\"PC3V\":\"0\",\"PC4V\":\"0\"}"

static char *vget(lite_env *env, const char *alias, const char *field) {
    char buf[8192];
    long n = lite_vault_get(env, alias, field, buf, sizeof buf);
    if (n < 0) return NULL;
    char *s = malloc((size_t)n + 1);
    memcpy(s, buf, (size_t)n + 1);
    return s;
}

int lite_is_bound(lite_env *env, const char *alias, lite_bind_info *out) {
    memset(out, 0, sizeof *out);
    if (!env->keystore->contains(env->keystore->ctx, alias)) return LITE_BIND_NO;
    char *srp = vget(env, alias, "ServerRiskParams");
    if (!srp) return LITE_BIND_NO;
    int ok = lite_riskrules_verify(env, srp) == 1;
    if (ok) {
        char *inner = lite_riskrules_decode(srp);
        if (inner) {
            lj_node *r = lj_parse(inner, strlen(inner));
            snprintf(out->ltl, sizeof out->ltl, "%s", lj_get_str(r, "LTL", ""));
            snprintf(out->bal, sizeof out->bal, "%s", lj_get_str(r, "BAL", ""));
            snprintf(out->acstatus, sizeof out->acstatus, "%s", lj_get_str(r, "ACSTATUS", ""));
            lj_free(r);
            free(inner);
        }
        char *pend = vget(env, alias, "PendingTxn");
        out->sync_required = pend && pend[0] && strcmp(pend, "[]") != 0;
        free(pend);
        out->bound = 1;
    }
    free(srp);
    return ok ? LITE_BIND_YES : LITE_BIND_NO;
}

static double sum_pending(const char *pend, int credit, int *count) {
    double s = 0;
    *count = 0;
    if (!pend || !pend[0]) return 0;
    lj_node *a = lj_parse(pend, strlen(pend));
    for (size_t i = 0; i < lj_len(a); i++) {
        const lj_node *o = lj_at(a, i);
        const char *ic = lj_get_str(o, "isCredit", "false");
        const char *amt = lj_get_str(o, "txnAmount", "0");
        int is_c = strcmp(ic, "true") == 0;
        if (is_c == credit) s += strtod(amt, NULL);
        (*count)++;
    }
    lj_free(a);
    return s;
}

int lite_balance(lite_env *env, const char *alias, lite_balance_info *out) {
    memset(out, 0, sizeof *out);
    char *srp = vget(env, alias, "ServerRiskParams");
    if (!srp || lite_riskrules_verify(env, srp) != 1) { free(srp); return LITE_ERR; }
    char *inner = lite_riskrules_decode(srp);
    free(srp);
    if (!inner) return LITE_ERR;
    lj_node *r = lj_parse(inner, strlen(inner));
    double bal = strtod(lj_get_str(r, "BAL", "0"), NULL);
    lj_free(r);
    free(inner);
    char *pend = vget(env, alias, "PendingTxn");
    int total = 0, ignore = 0;
    double debits = sum_pending(pend, 0, &total);
    double credits = sum_pending(pend, 1, &ignore);
    free(pend);
    out->balance = bal - debits > 0 ? bal - debits : 0;
    out->non_spendable = credits;
    out->pending_count = total;
    return LITE_OK;
}

static long long ts_of(const char *inner) {
    lj_node *r = lj_parse(inner, strlen(inner));
    const char *t = lj_get_str(r, "timestamp", "0");
    long long v = strtoll(t, NULL, 10);
    lj_free(r);
    return v;
}

int lite_sync(lite_env *env, const char *alias, const char *signed_state_json) {
    if (lite_riskrules_verify(env, signed_state_json) != 1) return LITE_SYNC_BAD_SIG;
    char *inner = lite_riskrules_decode(signed_state_json);
    if (!inner) return LITE_SYNC_BAD_SIG;
    lj_node *r = lj_parse(inner, strlen(inner));
    const char *acs = lj_get_str(r, "ACSTATUS", "");
    int deactivated = strcmp(acs, "DA") == 0;
    long long new_ts = strtoll(lj_get_str(r, "timestamp", "0"), NULL, 10);
    lj_free(r);
    free(inner);

    if (deactivated) { lite_unbind(env, alias); return LITE_SYNC_DEACTIVATED; }

    char crr[256];
    if (lite_vault_get(env, alias, "ClientRiskRules", crr, sizeof crr) < 0)
        lite_vault_set(env, alias, "ClientRiskRules", CRR_DEFAULT);

    char *existing = vget(env, alias, "ServerRiskParams");
    int accept;
    if (!existing) {
        accept = 1;
    } else if (lite_riskrules_verify(env, existing) == 1) {
        char *ei = lite_riskrules_decode(existing);
        long long old_ts = ei ? ts_of(ei) : 0;
        free(ei);
        accept = new_ts > old_ts;
    } else {
        accept = 1;
    }
    free(existing);
    if (!accept) return LITE_SYNC_STALE;

    lite_vault_set(env, alias, "ServerRiskParams", signed_state_json);
    lite_vault_set(env, alias, "PendingTxn", "");
    return LITE_SYNC_OK;
}

static char *make_risk_params(lite_env *env, const char *alias, const char *srp) {
    char *crr = vget(env, alias, "ClientRiskRules");
    char *k_b64 = vget(env, alias, SESSION_KEY_FIELD);
    if (!crr || !k_b64) { free(crr); free(k_b64); return NULL; }
    uint8_t key[32];
    long kn = lite_b64_decode(k_b64, strlen(k_b64), key, sizeof key);
    free(k_b64);
    lj_node *obj = lj_parse(srp, strlen(srp));
    char crr_cap[512];
    size_t need = lite_b64_encode_len(strlen(crr), LITE_B64_NO_WRAP);
    char *crr_b64 = need <= sizeof crr_cap ? crr_cap : malloc(need);
    lite_b64_encode((const uint8_t *)crr, strlen(crr), LITE_B64_NO_WRAP, crr_b64, need);
    lj_put_str(obj, "clientRiskRules", crr_b64);
    if (crr_b64 != crr_cap) free(crr_b64);
    free(crr);
    char *pt = lj_dump(obj);
    lj_free(obj);
    char *result = NULL;
    if (kn == 32) {
        uint8_t iv[16];
        env->rng->fill(env->rng->ctx, iv, sizeof iv);
        size_t pl = strlen(pt);
        uint8_t *ct = malloc(pl), tag[16];
        if (env->crypto->aes_gcm_encrypt(env->crypto->ctx, key, 32, iv, sizeof iv,
                                         (const uint8_t *)pt, pl, ct, tag) == 0) {
            uint8_t *blob = malloc(pl + 16);
            memcpy(blob, ct, pl);
            memcpy(blob + pl, tag, 16);
            size_t cc = lite_b64_encode_len(pl + 16, LITE_B64_NO_WRAP);
            size_t ic = lite_b64_encode_len(16, LITE_B64_NO_WRAP);
            char *cb = malloc(cc), *ib = malloc(ic);
            lite_b64_encode(blob, pl + 16, LITE_B64_NO_WRAP, cb, cc);
            lite_b64_encode(iv, 16, LITE_B64_NO_WRAP, ib, ic);
            result = malloc(strlen(cb) + strlen(ib) + 2);
            sprintf(result, "%s|%s", cb, ib);
            free(blob); free(cb); free(ib);
        }
        free(ct);
    }
    free(pt);
    return result;
}

static void bump_atc(lite_env *env, const char *alias) {
    char crr[512];
    if (lite_vault_get(env, alias, "ClientRiskRules", crr, sizeof crr) < 0) return;
    lj_node *o = lj_parse(crr, strlen(crr));
    long long atc = strtoll(lj_get_str(o, "ATC", "0"), NULL, 10) + 1;
    char v[32];
    snprintf(v, sizeof v, "%lld", atc);
    lj_put_str(o, "ATC", v);
    char *s = lj_dump(o);
    lj_free(o);
    lite_vault_set(env, alias, "ClientRiskRules", s);
    free(s);
}

static void append_pending(lite_env *env, const char *alias, const lite_txn *txn, int is_credit) {
    char pend[4096];
    long n = lite_vault_get(env, alias, "PendingTxn", pend, sizeof pend);
    lj_node *a = (n > 0 && pend[0]) ? lj_parse(pend, strlen(pend)) : lj_new_arr();
    if (lj_typeof(a) != LJ_ARR) { lj_free(a); a = lj_new_arr(); }
    lj_node *e = lj_new_obj();
    lj_put_str(e, "txnId", txn->txn_id);
    lj_put_str(e, "txnAmount", txn->amount);
    lj_put_str(e, "isCredit", is_credit ? "true" : "false");
    lj_append(a, e);
    char *s = lj_dump(a);
    lj_free(a);
    lite_vault_set(env, alias, "PendingTxn", s);
    free(s);
}

int lite_spend(lite_env *env, const char *alias, const lite_txn *txn, int is_credit,
               char *out, size_t cap) {
    char pend[4096];
    long pn = lite_vault_get(env, alias, "PendingTxn", pend, sizeof pend);
    if (pn > 0 && pend[0] && strcmp(pend, "[]") != 0) return LITE_SPEND_SYNC_REQUIRED;

    char *srp = vget(env, alias, "ServerRiskParams");
    if (!srp || lite_riskrules_verify(env, srp) != 1) { free(srp); return LITE_SPEND_DECLINED; }
    char *inner = lite_riskrules_decode(srp);
    lj_node *r = lj_parse(inner, strlen(inner));
    double ltl = strtod(lj_get_str(r, "LTL", "0"), NULL);
    double bal = strtod(lj_get_str(r, "BAL", "0"), NULL);
    const char *acs = lj_get_str(r, "ACSTATUS", "");
    double amt = strtod(txn->amount, NULL);
    int self = strcmp(txn->payer_lite_acc, txn->payee_addr) == 0;
    int ok = strcmp(acs, "A") == 0;
    if (!is_credit) ok = ok && amt <= bal && (self || amt <= ltl);
    lj_free(r);
    free(inner);
    if (!ok) { free(srp); return LITE_SPEND_DECLINED; }

    char *risk = make_risk_params(env, alias, srp);
    free(srp);
    if (!risk) return LITE_ERR;

    char payload[8192];
    if (lite_debit_payload(txn->amount, txn->txn_id, txn->ts, txn->payer_lite_acc, txn->payee_addr,
                           txn->app_id, txn->mobile, txn->device_id, risk, payload, sizeof payload) < 0) {
        free(risk);
        return LITE_ERR;
    }
    size_t pc = lite_b64_encode_len(strlen(payload), LITE_B64_NO_WRAP);
    char *p_b64 = malloc(pc);
    lite_b64_encode((const uint8_t *)payload, strlen(payload), LITE_B64_NO_WRAP, p_b64, pc);
    uint8_t sig[512];
    long sn = env->keystore->sign(env->keystore->ctx, alias, 0,
                                  (const uint8_t *)p_b64, strlen(p_b64), sig, sizeof sig);
    free(p_b64);
    if (sn < 0) { free(risk); return LITE_ERR; }
    size_t sc = lite_b64_encode_len((size_t)sn, LITE_B64_NO_WRAP);
    char *sig_b64 = malloc(sc);
    lite_b64_encode(sig, (size_t)sn, LITE_B64_NO_WRAP, sig_b64, sc);

    bump_atc(env, alias);
    append_pending(env, alias, txn, is_credit);

    lj_node *res = lj_new_obj();
    lj_put_str(res, "riskParams", risk);
    lj_put_str(res, "signature", sig_b64);
    char *s = lj_dump(res);
    lj_free(res);
    free(risk);
    free(sig_b64);
    int rc = LITE_OK;
    if (strlen(s) + 1 > cap) rc = LITE_ERR;
    else memcpy(out, s, strlen(s) + 1);
    free(s);
    return rc;
}

int lite_onboard(lite_env *env, const char *alias, const char *signed_state_json) {
    if (lite_vault_open(env, alias) != LITE_OK) return LITE_ERR;
    uint8_t spki[1024];
    if (env->keystore->gen_rsa(env->keystore->ctx, alias, 1, spki, sizeof spki) < 0) return LITE_ERR;
    uint8_t k[32];
    if (env->rng->fill(env->rng->ctx, k, sizeof k) != 0) return LITE_ERR;
    char k_b64[64];
    lite_b64_encode(k, 32, LITE_B64_NO_WRAP, k_b64, sizeof k_b64);
    lite_vault_set(env, alias, SESSION_KEY_FIELD, k_b64);
    lite_vault_set(env, alias, "ClientRiskRules", CRR_DEFAULT);
    return lite_sync(env, alias, signed_state_json);
}

int lite_unbind(lite_env *env, const char *alias) {
    char buf[320];
    env->keystore->delete_entry(env->keystore->ctx, alias);
    snprintf(buf, sizeof buf, "%s-OFFLINE", alias);
    env->keystore->delete_entry(env->keystore->ctx, buf);
    snprintf(buf, sizeof buf, "%s-SIGNATURE", alias);
    env->keystore->delete_entry(env->keystore->ctx, buf);
    env->store->remove(env->store->ctx, "NPCICLVAULT", buf);
    snprintf(buf, sizeof buf, "%s-NPCI-Vault", alias);
    env->keystore->delete_entry(env->keystore->ctx, buf);
    env->store->remove(env->store->ctx, "NPCICLVAULT", alias);
    snprintf(buf, sizeof buf, "%sIV", alias);
    env->store->remove(env->store->ctx, "NPCICLVAULT", buf);
    return LITE_OK;
}
