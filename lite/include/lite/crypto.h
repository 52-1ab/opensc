#ifndef LITE_CRYPTO_H
#define LITE_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

// Stateless primitives keyed by explicit material. Alias-keyed signing lives in keystore.h.
typedef struct lite_crypto {
    void *ctx;

    int (*sha256)(void *ctx, const uint8_t *in, size_t len, uint8_t out[32]);
    int (*sha1)(void *ctx, const uint8_t *in, size_t len, uint8_t out[20]);

    int (*aes_gcm_encrypt)(void *ctx, const uint8_t *key, size_t key_len,
                           const uint8_t *iv, size_t iv_len,
                           const uint8_t *pt, size_t pt_len,
                           uint8_t *ct, uint8_t tag[16]);
    int (*aes_gcm_decrypt)(void *ctx, const uint8_t *key, size_t key_len,
                           const uint8_t *iv, size_t iv_len,
                           const uint8_t *ct, size_t ct_len, const uint8_t tag[16],
                           uint8_t *pt);

    int (*rsa_pss_sha512_verify)(void *ctx, const uint8_t *spki, size_t spki_len,
                                 const uint8_t *msg, size_t msg_len,
                                 const uint8_t *sig, size_t sig_len);
    int (*ecdsa_sha256_verify)(void *ctx, const uint8_t *spki, size_t spki_len,
                               const uint8_t *msg, size_t msg_len,
                               const uint8_t *sig, size_t sig_len);

    // OAEP with explicit public key. mgf1_sha1 picks MGF1-SHA1 (DataUPI token wrap) vs SHA256.
    long (*rsa_oaep_sha256_encrypt)(void *ctx, const uint8_t *spki, size_t spki_len,
                                    int mgf1_sha1, const uint8_t *pt, size_t pt_len,
                                    uint8_t *ct, size_t ct_cap);

    long (*x509_spki)(void *ctx, const uint8_t *cert, size_t cert_len,
                      uint8_t *spki, size_t spki_cap);
} lite_crypto;

const lite_crypto *lite_crypto_openssl(void);

#endif
