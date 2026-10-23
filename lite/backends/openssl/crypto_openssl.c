#include "lite/crypto.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <string.h>

static int oe_sha(const EVP_MD *md, const uint8_t *in, size_t len, uint8_t *out) {
    unsigned int n = 0;
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    if (!c) return -1;
    int ok = EVP_DigestInit_ex(c, md, NULL) == 1 &&
             EVP_DigestUpdate(c, in, len) == 1 &&
             EVP_DigestFinal_ex(c, out, &n) == 1;
    EVP_MD_CTX_free(c);
    return ok ? 0 : -1;
}

static int oe_sha256(void *ctx, const uint8_t *in, size_t len, uint8_t out[32]) {
    (void)ctx;
    return oe_sha(EVP_sha256(), in, len, out);
}

static int oe_sha1(void *ctx, const uint8_t *in, size_t len, uint8_t out[20]) {
    (void)ctx;
    return oe_sha(EVP_sha1(), in, len, out);
}

static int oe_gcm_enc(void *ctx, const uint8_t *key, size_t key_len,
                      const uint8_t *iv, size_t iv_len,
                      const uint8_t *pt, size_t pt_len, uint8_t *ct, uint8_t tag[16]) {
    (void)ctx;
    if (key_len != 32) return -1;
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c) return -1;
    int len = 0, ok = 0;
    if (EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, NULL) == 1 &&
        EVP_EncryptInit_ex(c, NULL, NULL, key, iv) == 1 &&
        EVP_EncryptUpdate(c, ct, &len, pt, (int)pt_len) == 1) {
        int fin = 0;
        if (EVP_EncryptFinal_ex(c, ct + len, &fin) == 1 &&
            EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1)
            ok = 1;
    }
    EVP_CIPHER_CTX_free(c);
    return ok ? 0 : -1;
}

static int oe_gcm_dec(void *ctx, const uint8_t *key, size_t key_len,
                      const uint8_t *iv, size_t iv_len,
                      const uint8_t *ct, size_t ct_len, const uint8_t tag[16], uint8_t *pt) {
    (void)ctx;
    if (key_len != 32) return -1;
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c) return -1;
    int len = 0, ok = 0;
    if (EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, NULL) == 1 &&
        EVP_DecryptInit_ex(c, NULL, NULL, key, iv) == 1 &&
        EVP_DecryptUpdate(c, pt, &len, ct, (int)ct_len) == 1 &&
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) == 1) {
        int fin = 0;
        if (EVP_DecryptFinal_ex(c, pt + len, &fin) == 1) ok = 1;
    }
    EVP_CIPHER_CTX_free(c);
    return ok ? 0 : -1;
}

static EVP_PKEY *spki_to_pkey(const uint8_t *spki, size_t spki_len) {
    const unsigned char *p = spki;
    return d2i_PUBKEY(NULL, &p, (long)spki_len);
}

static int oe_pss_verify(void *ctx, const uint8_t *spki, size_t spki_len,
                         const uint8_t *msg, size_t msg_len,
                         const uint8_t *sig, size_t sig_len) {
    (void)ctx;
    EVP_PKEY *k = spki_to_pkey(spki, spki_len);
    if (!k) return -1;
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pc = NULL;
    int rc = -1;
    if (c && EVP_DigestVerifyInit(c, &pc, EVP_sha512(), NULL, k) == 1 &&
        EVP_PKEY_CTX_set_rsa_padding(pc, RSA_PKCS1_PSS_PADDING) > 0 &&
        EVP_PKEY_CTX_set_rsa_mgf1_md(pc, EVP_sha512()) > 0 &&
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pc, RSA_PSS_SALTLEN_DIGEST) > 0) {
        rc = EVP_DigestVerify(c, sig, sig_len, msg, msg_len) == 1 ? 1 : 0;
    }
    EVP_MD_CTX_free(c);
    EVP_PKEY_free(k);
    return rc;
}

static int oe_ecdsa_verify(void *ctx, const uint8_t *spki, size_t spki_len,
                           const uint8_t *msg, size_t msg_len,
                           const uint8_t *sig, size_t sig_len) {
    (void)ctx;
    EVP_PKEY *k = spki_to_pkey(spki, spki_len);
    if (!k) return -1;
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    int rc = -1;
    if (c && EVP_DigestVerifyInit(c, NULL, EVP_sha256(), NULL, k) == 1)
        rc = EVP_DigestVerify(c, sig, sig_len, msg, msg_len) == 1 ? 1 : 0;
    EVP_MD_CTX_free(c);
    EVP_PKEY_free(k);
    return rc;
}

static long oe_oaep_enc(void *ctx, const uint8_t *spki, size_t spki_len, int mgf1_sha1,
                        const uint8_t *pt, size_t pt_len, uint8_t *ct, size_t ct_cap) {
    (void)ctx;
    EVP_PKEY *k = spki_to_pkey(spki, spki_len);
    if (!k) return -1;
    EVP_PKEY_CTX *pc = EVP_PKEY_CTX_new(k, NULL);
    long out = -1;
    size_t n = ct_cap;
    if (pc && EVP_PKEY_encrypt_init(pc) == 1 &&
        EVP_PKEY_CTX_set_rsa_padding(pc, RSA_PKCS1_OAEP_PADDING) > 0 &&
        EVP_PKEY_CTX_set_rsa_oaep_md(pc, EVP_sha256()) > 0 &&
        EVP_PKEY_CTX_set_rsa_mgf1_md(pc, mgf1_sha1 ? EVP_sha1() : EVP_sha256()) > 0 &&
        EVP_PKEY_encrypt(pc, ct, &n, pt, pt_len) == 1) {
        out = (long)n;
    }
    EVP_PKEY_CTX_free(pc);
    EVP_PKEY_free(k);
    return out;
}

static long oe_x509_spki(void *ctx, const uint8_t *cert, size_t cert_len,
                         uint8_t *spki, size_t spki_cap) {
    (void)ctx;
    X509 *x = NULL;
    const unsigned char *p = cert;
    BIO *b = BIO_new_mem_buf(cert, (int)cert_len);
    if (b) {
        x = PEM_read_bio_X509(b, NULL, NULL, NULL);
        BIO_free(b);
    }
    if (!x) x = d2i_X509(NULL, &p, (long)cert_len);
    if (!x) return -1;
    EVP_PKEY *k = X509_get_pubkey(x);
    long out = -1;
    if (k) {
        unsigned char *der = NULL;
        int n = i2d_PUBKEY(k, &der);
        if (n > 0 && (size_t)n <= spki_cap) {
            memcpy(spki, der, (size_t)n);
            out = n;
        }
        OPENSSL_free(der);
        EVP_PKEY_free(k);
    }
    X509_free(x);
    return out;
}

static const lite_crypto OPENSSL_BACKEND = {
    .ctx = NULL,
    .sha256 = oe_sha256,
    .sha1 = oe_sha1,
    .aes_gcm_encrypt = oe_gcm_enc,
    .aes_gcm_decrypt = oe_gcm_dec,
    .rsa_pss_sha512_verify = oe_pss_verify,
    .ecdsa_sha256_verify = oe_ecdsa_verify,
    .rsa_oaep_sha256_encrypt = oe_oaep_enc,
    .x509_spki = oe_x509_spki,
};

const lite_crypto *lite_crypto_openssl(void) { return &OPENSSL_BACKEND; }
