#include "lite/keystore.h"

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <stdlib.h>
#include <string.h>

typedef struct { char *alias; EVP_PKEY *pk; uint8_t aes[32]; int has_aes; } kentry;
typedef struct { kentry *e; size_t n, cap; } memks;

static kentry *find(memks *m, const char *alias) {
    for (size_t i = 0; i < m->n; i++)
        if (strcmp(m->e[i].alias, alias) == 0) return &m->e[i];
    return NULL;
}

static kentry *add(memks *m, const char *alias) {
    kentry *e = find(m, alias);
    if (e) return e;
    if (m->n == m->cap) { m->cap = m->cap ? m->cap * 2 : 8; m->e = realloc(m->e, m->cap * sizeof *m->e); }
    e = &m->e[m->n++];
    memset(e, 0, sizeof *e);
    e->alias = strdup(alias);
    return e;
}

static int ks_contains(void *ctx, const char *alias) { return find(ctx, alias) != NULL; }

static int ks_delete(void *ctx, const char *alias) {
    memks *m = ctx;
    for (size_t i = 0; i < m->n; i++) {
        if (strcmp(m->e[i].alias, alias) == 0) {
            free(m->e[i].alias);
            EVP_PKEY_free(m->e[i].pk);
            m->e[i] = m->e[--m->n];
            return 0;
        }
    }
    return -1;
}

static long spki_of(EVP_PKEY *pk, uint8_t *out, size_t cap) {
    unsigned char *der = NULL;
    int n = i2d_PUBKEY(pk, &der);
    long r = -1;
    if (n > 0 && (size_t)n <= cap) { memcpy(out, der, (size_t)n); r = n; }
    OPENSSL_free(der);
    return r;
}

static long ks_gen_rsa(void *ctx, const char *alias, int user_auth, uint8_t *spki, size_t cap) {
    (void)user_auth;
    kentry *e = add(ctx, alias);
    EVP_PKEY_free(e->pk);
    e->pk = EVP_RSA_gen(2048);
    return e->pk ? spki_of(e->pk, spki, cap) : -1;
}

static long ks_gen_ec(void *ctx, const char *alias, uint8_t *spki, size_t cap) {
    kentry *e = add(ctx, alias);
    EVP_PKEY_free(e->pk);
    e->pk = EVP_EC_gen("prime256v1");
    return e->pk ? spki_of(e->pk, spki, cap) : -1;
}

static int ks_gen_aes(void *ctx, const char *alias) {
    kentry *e = add(ctx, alias);
    e->has_aes = 1;
    return RAND_bytes(e->aes, 32) == 1 ? 0 : -1;
}

static long ks_sign(void *ctx, const char *alias, int use_ec,
                    const uint8_t *msg, size_t msg_len, uint8_t *sig, size_t cap) {
    (void)use_ec;
    kentry *e = find(ctx, alias);
    if (!e || !e->pk) return -1;
    int is_rsa = EVP_PKEY_base_id(e->pk) == EVP_PKEY_RSA;
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pc = NULL;
    long out = -1;
    const EVP_MD *md = is_rsa ? EVP_sha512() : EVP_sha256();
    if (c && EVP_DigestSignInit(c, &pc, md, NULL, e->pk) == 1) {
        if (is_rsa) {
            EVP_PKEY_CTX_set_rsa_padding(pc, RSA_PKCS1_PSS_PADDING);
            EVP_PKEY_CTX_set_rsa_mgf1_md(pc, EVP_sha512());
            EVP_PKEY_CTX_set_rsa_pss_saltlen(pc, RSA_PSS_SALTLEN_DIGEST);
        }
        size_t n = cap;
        if (EVP_DigestSign(c, sig, &n, msg, msg_len) == 1) out = (long)n;
    }
    EVP_MD_CTX_free(c);
    return out;
}

static long ks_pubkey(void *ctx, const char *alias, uint8_t *spki, size_t cap) {
    kentry *e = find(ctx, alias);
    return (e && e->pk) ? spki_of(e->pk, spki, cap) : -1;
}

static int gcm(const uint8_t *key, const uint8_t *iv, size_t iv_len, int enc,
               const uint8_t *in, size_t in_len, uint8_t *out, uint8_t *tag) {
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c) return -1;
    int len = 0, ok = 0;
    if (enc) {
        if (EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
            EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, NULL) == 1 &&
            EVP_EncryptInit_ex(c, NULL, NULL, key, iv) == 1 &&
            EVP_EncryptUpdate(c, out, &len, in, (int)in_len) == 1) {
            int fin = 0;
            if (EVP_EncryptFinal_ex(c, out + len, &fin) == 1 &&
                EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1) ok = 1;
        }
    } else {
        if (EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
            EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, NULL) == 1 &&
            EVP_DecryptInit_ex(c, NULL, NULL, key, iv) == 1 &&
            EVP_DecryptUpdate(c, out, &len, in, (int)in_len) == 1 &&
            EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) == 1) {
            int fin = 0;
            if (EVP_DecryptFinal_ex(c, out + len, &fin) == 1) ok = 1;
        }
    }
    EVP_CIPHER_CTX_free(c);
    return ok ? 0 : -1;
}

static int ks_aes_enc(void *ctx, const char *alias, const uint8_t *iv, size_t iv_len,
                      const uint8_t *pt, size_t pt_len, uint8_t *ct, uint8_t tag[16]) {
    kentry *e = find(ctx, alias);
    if (!e || !e->has_aes) return -1;
    return gcm(e->aes, iv, iv_len, 1, pt, pt_len, ct, tag);
}

static int ks_aes_dec(void *ctx, const char *alias, const uint8_t *iv, size_t iv_len,
                      const uint8_t *ct, size_t ct_len, const uint8_t tag[16], uint8_t *pt) {
    kentry *e = find(ctx, alias);
    if (!e || !e->has_aes) return -1;
    return gcm(e->aes, iv, iv_len, 0, ct, ct_len, pt, (uint8_t *)tag);
}

lite_keystore *lite_keystore_mem_new(void) {
    lite_keystore *k = calloc(1, sizeof *k);
    k->ctx = calloc(1, sizeof(memks));
    k->contains = ks_contains;
    k->delete_entry = ks_delete;
    k->gen_rsa = ks_gen_rsa;
    k->gen_ec = ks_gen_ec;
    k->gen_aes = ks_gen_aes;
    k->sign = ks_sign;
    k->pubkey = ks_pubkey;
    k->aes_encrypt = ks_aes_enc;
    k->aes_decrypt = ks_aes_dec;
    return k;
}

void lite_keystore_mem_free(lite_keystore *k) {
    if (!k) return;
    memks *m = k->ctx;
    for (size_t i = 0; i < m->n; i++) { free(m->e[i].alias); EVP_PKEY_free(m->e[i].pk); }
    free(m->e);
    free(m);
    free(k);
}
