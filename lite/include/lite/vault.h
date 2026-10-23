#ifndef LITE_VAULT_H
#define LITE_VAULT_H

#include <stddef.h>

#include "lite/env.h"

/// @file
/// The NPCICLVAULT codec: an AES-GCM-encrypted JSON doc, separately signed, with tamper-reset.

/// Shared return codes for the vault/wallet layer.
enum {
    LITE_OK = 0,            ///< Success.
    LITE_ERR = -1,          ///< Generic failure.
    LITE_ERR_ABSENT = -2,   ///< Requested field/record not present.
    LITE_ERR_TAMPER = -3,   ///< Signature invalid; the vault was reset as a side effect.
};

/// Ensures the vault's AES and signing keys exist and a valid encrypted record is stored.
int lite_vault_open(lite_env *env, const char *alias);

/// Replaces vault contents with an encrypted "{}" under freshly generated keys.
int lite_vault_reset(lite_env *env, const char *alias);

/// Reads one top-level string field into `out`. Returns length, LITE_ERR_ABSENT, or LITE_ERR_TAMPER.
long lite_vault_get(lite_env *env, const char *alias, const char *key, char *out, size_t cap);

/// Read-modify-write of one field. Verifies the current record first; resets on tamper. 0 on success.
int lite_vault_set(lite_env *env, const char *alias, const char *key, const char *val);

#endif
