#ifndef LITE_KEYSTORE_H
#define LITE_KEYSTORE_H

#include <stddef.h>
#include <stdint.h>

// Software stand-in for AndroidKeyStore. Keys are test keys held in memory; nothing is a real
// TEE/StrongBox key, so signatures here are valid only for this harness, never for a real account.
typedef struct lite_keystore {
    void *ctx;
    int (*contains)(void *ctx, const char *alias);
    int (*delete_entry)(void *ctx, const char *alias);

    long (*gen_rsa)(void *ctx, const char *alias, int user_auth, uint8_t *spki, size_t cap);
    long (*gen_ec)(void *ctx, const char *alias, uint8_t *spki, size_t cap);
    int (*gen_aes)(void *ctx, const char *alias);

    long (*sign)(void *ctx, const char *alias, int use_ec,
                 const uint8_t *msg, size_t msg_len, uint8_t *sig, size_t cap);
    long (*pubkey)(void *ctx, const char *alias, uint8_t *spki, size_t cap);

    int (*aes_encrypt)(void *ctx, const char *alias, const uint8_t *iv, size_t iv_len,
                       const uint8_t *pt, size_t pt_len, uint8_t *ct, uint8_t tag[16]);
    int (*aes_decrypt)(void *ctx, const char *alias, const uint8_t *iv, size_t iv_len,
                       const uint8_t *ct, size_t ct_len, const uint8_t tag[16], uint8_t *pt);
} lite_keystore;

lite_keystore *lite_keystore_mem_new(void);
void lite_keystore_mem_free(lite_keystore *k);

#endif
