#include "lite/vault.h"
#include "lite/codec.h"
#include "lite/json.h"
#include "lite/primitives.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VAULT_FILE "NPCICLVAULT"
#define SUF_IV "IV"
#define SUF_SIG "-SIGNATURE"
#define SUF_AES "-NPCI-Vault"

static char *store_get_dup(lite_env *env, const char *file, const char *key) {
    long n = env->store->get(env->store->ctx, file, key, NULL, 0);
    if (n < 0) return NULL;
    char *s = malloc((size_t)n + 1);
    if (env->store->get(env->store->ctx, file, key, s, (size_t)n + 1) < 0) { free(s); return NULL; }
    return s;
}

static int key_with(const char *alias, const char *suffix, char *out, size_t cap) {
    int n = snprintf(out, cap, "%s%s", alias, suffix);
    return (n > 0 && (size_t)n < cap) ? 0 : -1;
}

// Encrypt a plaintext doc, returning freshly allocated base64(ct||tag) and base64(iv).
static int encrypt_doc(lite_env *env, const char *alias, const char *pt, char **ct_b64, char **iv_b64) {
    char aes_alias[320];
    if (key_with(alias, SUF_AES, aes_alias, sizeof aes_alias)) return LITE_ERR;
    uint8_t iv[12];
    if (env->rng->fill(env->rng->ctx, iv, sizeof iv) != 0) return LITE_ERR;
    size_t pt_len = strlen(pt);
    uint8_t *ct = malloc(pt_len + 16);
    uint8_t tag[16];
    if (env->keystore->aes_encrypt(env->keystore->ctx, aes_alias, iv, sizeof iv,
                                   (const uint8_t *)pt, pt_len, ct, tag) != 0) {
        free(ct);
        return LITE_ERR;
    }
    memcpy(ct + pt_len, tag, 16);
    size_t blob = pt_len + 16;
    char *cb = malloc(lite_b64_encode_len(blob, LITE_B64_NO_WRAP));
    char *ib = malloc(lite_b64_encode_len(sizeof iv, LITE_B64_NO_WRAP));
    lite_b64_encode(ct, blob, LITE_B64_NO_WRAP, cb, lite_b64_encode_len(blob, LITE_B64_NO_WRAP));
    lite_b64_encode(iv, sizeof iv, LITE_B64_NO_WRAP, ib, lite_b64_encode_len(sizeof iv, LITE_B64_NO_WRAP));
    free(ct);
    *ct_b64 = cb;
    *iv_b64 = ib;
    return LITE_OK;
}

// Decrypt base64(ct||tag)+base64(iv) back to a freshly allocated plaintext string.
static char *decrypt_doc(lite_env *env, const char *alias, const char *ct_b64, const char *iv_b64) {
    char aes_alias[320];
    if (key_with(alias, SUF_AES, aes_alias, sizeof aes_alias)) return NULL;
    size_t cb_len = strlen(ct_b64), ib_len = strlen(iv_b64);
    uint8_t *blob = malloc(lite_b64_decode_len(cb_len));
    uint8_t iv[64];
    long bn = lite_b64_decode(ct_b64, cb_len, blob, lite_b64_decode_len(cb_len));
    long ivn = lite_b64_decode(iv_b64, ib_len, iv, sizeof iv);
    if (bn < 16 || ivn < 0) { free(blob); return NULL; }
    size_t pt_len = (size_t)bn - 16;
    uint8_t *tag = blob + pt_len;
    char *pt = malloc(pt_len + 1);
    if (env->keystore->aes_decrypt(env->keystore->ctx, aes_alias, iv, (size_t)ivn,
                                   blob, pt_len, tag, (uint8_t *)pt) != 0) {
        free(blob); free(pt); return NULL;
    }
    pt[pt_len] = '\0';
    free(blob);
    return pt;
}

static int sign_record(lite_env *env, const char *alias, const char *ct_b64, const char *iv_b64,
                       int regenerate, char **sig_b64) {
    char sig_alias[320];
    if (key_with(alias, SUF_SIG, sig_alias, sizeof sig_alias)) return LITE_ERR;
    if (regenerate) {
        uint8_t spki[1024];
        if (env->keystore->gen_rsa(env->keystore->ctx, sig_alias, 0, spki, sizeof spki) < 0) return LITE_ERR;
    }
    char msg[128];
    if (lite_vault_sig_message(env->crypto, ct_b64, iv_b64, msg, sizeof msg) < 0) return LITE_ERR;
    uint8_t sig[512];
    long sn = env->keystore->sign(env->keystore->ctx, sig_alias, 0,
                                  (const uint8_t *)msg, strlen(msg), sig, sizeof sig);
    if (sn < 0) return LITE_ERR;
    size_t cap = lite_b64_encode_len((size_t)sn, LITE_B64_NO_WRAP);
    char *sb = malloc(cap);
    lite_b64_encode(sig, (size_t)sn, LITE_B64_NO_WRAP, sb, cap);
    *sig_b64 = sb;
    return LITE_OK;
}

static int verify_record(lite_env *env, const char *alias, const char *ct_b64, const char *iv_b64,
                         const char *sig_b64) {
    char sig_alias[320];
    if (key_with(alias, SUF_SIG, sig_alias, sizeof sig_alias)) return 0;
    uint8_t spki[1024];
    long spn = env->keystore->pubkey(env->keystore->ctx, sig_alias, spki, sizeof spki);
    if (spn < 0) return 0;
    char msg[128];
    if (lite_vault_sig_message(env->crypto, ct_b64, iv_b64, msg, sizeof msg) < 0) return 0;
    uint8_t sig[512];
    long sn = lite_b64_decode(sig_b64, strlen(sig_b64), sig, sizeof sig);
    if (sn < 0) return 0;
    return env->crypto->rsa_pss_sha512_verify(env->crypto->ctx, spki, (size_t)spn,
                                              (const uint8_t *)msg, strlen(msg), sig, (size_t)sn) == 1;
}

static int store_record(lite_env *env, const char *alias, const char *ct, const char *iv, const char *sig) {
    char ivk[320], sigk[320];
    if (key_with(alias, SUF_IV, ivk, sizeof ivk) || key_with(alias, SUF_SIG, sigk, sizeof sigk)) return LITE_ERR;
    env->store->set(env->store->ctx, VAULT_FILE, alias, ct);
    env->store->set(env->store->ctx, VAULT_FILE, ivk, iv);
    env->store->set(env->store->ctx, VAULT_FILE, sigk, sig);
    return LITE_OK;
}

static int write_doc(lite_env *env, const char *alias, const char *pt, int regenerate) {
    char *ct = NULL, *iv = NULL, *sig = NULL;
    if (encrypt_doc(env, alias, pt, &ct, &iv) != LITE_OK) return LITE_ERR;
    int rc = sign_record(env, alias, ct, iv, regenerate, &sig);
    if (rc == LITE_OK) rc = store_record(env, alias, ct, iv, sig);
    free(ct); free(iv); free(sig);
    return rc;
}

int lite_vault_reset(lite_env *env, const char *alias) {
    char aes_alias[320];
    if (key_with(alias, SUF_AES, aes_alias, sizeof aes_alias)) return LITE_ERR;
    if (env->keystore->gen_aes(env->keystore->ctx, aes_alias) != 0) return LITE_ERR;
    return write_doc(env, alias, "{}", 1);
}

// Reads ct/iv/sig; verifies; decrypts. On tamper resets and reports it. doc_out may be NULL.
static int read_doc(lite_env *env, const char *alias, char **doc_out) {
    char ivk[320], sigk[320];
    if (key_with(alias, SUF_IV, ivk, sizeof ivk) || key_with(alias, SUF_SIG, sigk, sizeof sigk)) return LITE_ERR;
    char *ct = store_get_dup(env, VAULT_FILE, alias);
    char *iv = store_get_dup(env, VAULT_FILE, ivk);
    char *sig = store_get_dup(env, VAULT_FILE, sigk);
    int rc;
    if (!ct || !iv || !sig) {
        rc = LITE_ERR_ABSENT;
    } else if (!verify_record(env, alias, ct, iv, sig)) {
        lite_vault_reset(env, alias);
        rc = LITE_ERR_TAMPER;
    } else {
        char *pt = decrypt_doc(env, alias, ct, iv);
        if (!pt) rc = LITE_ERR;
        else { if (doc_out) *doc_out = pt; else free(pt); rc = LITE_OK; }
    }
    free(ct); free(iv); free(sig);
    return rc;
}

int lite_vault_open(lite_env *env, const char *alias) {
    int rc = read_doc(env, alias, NULL);
    if (rc == LITE_ERR_ABSENT) return lite_vault_reset(env, alias);
    return rc == LITE_OK ? LITE_OK : rc;
}

long lite_vault_get(lite_env *env, const char *alias, const char *key, char *out, size_t cap) {
    char *pt = NULL;
    int rc = read_doc(env, alias, &pt);
    if (rc != LITE_OK) return rc;
    lj_node *doc = lj_parse(pt, strlen(pt));
    free(pt);
    const char *v = lj_get_str(doc, key, NULL);
    long r;
    if (!v) {
        r = LITE_ERR_ABSENT;
    } else {
        size_t n = strlen(v);
        if (n + 1 > cap) { r = LITE_ERR; }
        else { memcpy(out, v, n + 1); r = (long)n; }
    }
    lj_free(doc);
    return r;
}

int lite_vault_set(lite_env *env, const char *alias, const char *key, const char *val) {
    char *pt = NULL;
    int rc = read_doc(env, alias, &pt);
    lj_node *doc;
    if (rc == LITE_OK) {
        doc = lj_parse(pt, strlen(pt));
        free(pt);
    } else if (rc == LITE_ERR_ABSENT || rc == LITE_ERR_TAMPER) {
        doc = lj_new_obj();
    } else {
        return rc;
    }
    lj_put_str(doc, key, val);
    char *s = lj_dump(doc);
    lj_free(doc);
    int wr = write_doc(env, alias, s, 0);
    free(s);
    return wr;
}
