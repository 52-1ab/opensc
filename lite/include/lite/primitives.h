#ifndef LITE_PRIMITIVES_H
#define LITE_PRIMITIVES_H

#include <stddef.h>

#include "lite/crypto.h"

/// @file
/// The byte-exact deterministic primitives of the CL (checked against the same vectors as the genuine CL).

/// alias = Base64NoWrap(SHA256(deviceId + mobile + accountRef + service)). Returns length or -1.
long lite_alias(const lite_crypto *c, const char *device_id, const char *mobile,
                const char *account_ref, const char *service, char *out, size_t cap);

/// Base64NoWrap(SHA256(utf8(s))) — the CL's o0OOO0o.OooO0O0 helper used for the alias and K0 hashes. Length or -1.
long lite_sha256_b64(const lite_crypto *c, const char *s, char *out, size_t cap);

/// hex(SHA1(utf8(s)))[0:35] — the CL's txnId builder (o0OOO0o.OooO). Returns 35 or -1.
long lite_sha1_id35(const lite_crypto *c, const char *s, char *out, size_t cap);

/// Builds "1.0|amount|txnId|ts|payerLiteAcc|payeeAddr|appId|mobile|deviceId|riskParams". Length or -1.
long lite_debit_payload(const char *amount, const char *txn_id, const char *ts,
                        const char *payer_lite_acc, const char *payee_addr, const char *app_id,
                        const char *mobile, const char *device_id, const char *risk_params,
                        char *out, size_t cap);

/// Message the vault signature covers: Base64Default(SHA256(ivBytes + utf8(ctB64))), trailing '\n' kept. Length or -1.
long lite_vault_sig_message(const lite_crypto *c, const char *ct_b64, const char *iv_b64,
                            char *out, size_t cap);

#endif
