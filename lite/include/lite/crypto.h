#ifndef LITE_CRYPTO_H
#define LITE_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

/// @file
/// Pluggable crypto backend: stateless primitives keyed by explicit material.
/// Alias-keyed signing lives in keystore.h.

/// Vtable of stateless crypto primitives; obtain a concrete one from lite_crypto_openssl().
typedef struct lite_crypto {
    void *ctx;  ///< Backend-private state, passed back to every callback.

    int (*sha256)(void *ctx, const uint8_t *in, size_t len, uint8_t out[32]);  ///< SHA-256 of `in`; 0 on success.
    int (*sha1)(void *ctx, const uint8_t *in, size_t len, uint8_t out[20]);    ///< SHA-1 of `in`; 0 on success.

    /// AES-256-GCM encrypt; writes ciphertext to `ct` and the 16-byte tag to `tag`. 0 on success.
    int (*aes_gcm_encrypt)(void *ctx, const uint8_t *key, size_t key_len,
                           const uint8_t *iv, size_t iv_len,
                           const uint8_t *pt, size_t pt_len,
                           uint8_t *ct, uint8_t tag[16]);
    /// AES-256-GCM decrypt; verifies `tag`, writes plaintext to `pt`. 0 on success, non-zero on auth failure.
    int (*aes_gcm_decrypt)(void *ctx, const uint8_t *key, size_t key_len,
                           const uint8_t *iv, size_t iv_len,
                           const uint8_t *ct, size_t ct_len, const uint8_t tag[16],
                           uint8_t *pt);

    /// Verifies an RSA-PSS-SHA512 signature over `msg` with the SPKI public key. 1 ok, 0 bad, <0 error.
    int (*rsa_pss_sha512_verify)(void *ctx, const uint8_t *spki, size_t spki_len,
                                 const uint8_t *msg, size_t msg_len,
                                 const uint8_t *sig, size_t sig_len);
    /// Verifies an ECDSA-SHA256 (P-256) signature over `msg` with the SPKI public key. 1 ok, 0 bad, <0 error.
    int (*ecdsa_sha256_verify)(void *ctx, const uint8_t *spki, size_t spki_len,
                               const uint8_t *msg, size_t msg_len,
                               const uint8_t *sig, size_t sig_len);

    /// RSA-OAEP-SHA256 encrypt; `mgf1_sha1` picks MGF1-SHA1 (DataUPI token wrap) vs MGF1-SHA256. Bytes written or -1.
    long (*rsa_oaep_sha256_encrypt)(void *ctx, const uint8_t *spki, size_t spki_len,
                                    int mgf1_sha1, const uint8_t *pt, size_t pt_len,
                                    uint8_t *ct, size_t ct_cap);

    /// Extracts the SubjectPublicKeyInfo DER from a PEM/DER X.509 cert. Bytes written or -1.
    long (*x509_spki)(void *ctx, const uint8_t *cert, size_t cert_len,
                      uint8_t *spki, size_t spki_cap);
} lite_crypto;

/// Returns the OpenSSL-backed crypto vtable (statically allocated; do not free).
const lite_crypto *lite_crypto_openssl(void);

#endif
