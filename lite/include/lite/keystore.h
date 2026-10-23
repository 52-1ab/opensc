#ifndef LITE_KEYSTORE_H
#define LITE_KEYSTORE_H

#include <stddef.h>
#include <stdint.h>

/// @file
/// Pluggable keystore, a software stand-in for AndroidKeyStore.

/// Software AndroidKeyStore stand-in. Keys are in-memory test keys — never real TEE/StrongBox keys —
/// so signatures are valid only within this harness, never for a real account.
typedef struct lite_keystore {
    void *ctx;  ///< Backend-private state.
    int (*contains)(void *ctx, const char *alias);      ///< 1 if `alias` holds a key, else 0.
    int (*delete_entry)(void *ctx, const char *alias);  ///< Removes `alias`. 0 on success.

    long (*gen_rsa)(void *ctx, const char *alias, int user_auth, uint8_t *spki, size_t cap);  ///< Generates an RSA-2048 key; writes SPKI. Length or -1.
    long (*gen_ec)(void *ctx, const char *alias, uint8_t *spki, size_t cap);                  ///< Generates a P-256 key; writes SPKI. Length or -1.
    int (*gen_aes)(void *ctx, const char *alias);                                             ///< Generates an AES-256 key. 0 on success.

    /// Signs `msg` with `alias` (RSA-PSS-SHA512, or ECDSA-SHA256 when `use_ec`); writes signature. Length or -1.
    long (*sign)(void *ctx, const char *alias, int use_ec,
                 const uint8_t *msg, size_t msg_len, uint8_t *sig, size_t cap);
    long (*pubkey)(void *ctx, const char *alias, uint8_t *spki, size_t cap);  ///< Writes `alias`'s SPKI public key. Length or -1.

    /// AES-256-GCM encrypt with the key at `alias`; writes ciphertext and 16-byte tag. 0 on success.
    int (*aes_encrypt)(void *ctx, const char *alias, const uint8_t *iv, size_t iv_len,
                       const uint8_t *pt, size_t pt_len, uint8_t *ct, uint8_t tag[16]);
    /// AES-256-GCM decrypt with the key at `alias`; verifies `tag`, writes plaintext. 0 on success.
    int (*aes_decrypt)(void *ctx, const char *alias, const uint8_t *iv, size_t iv_len,
                       const uint8_t *ct, size_t ct_len, const uint8_t tag[16], uint8_t *pt);
} lite_keystore;

/// Allocates an in-memory software keystore (for tests). Free with lite_keystore_mem_free().
lite_keystore *lite_keystore_mem_new(void);
/// Frees an in-memory keystore created by lite_keystore_mem_new().
void lite_keystore_mem_free(lite_keystore *k);

#endif
