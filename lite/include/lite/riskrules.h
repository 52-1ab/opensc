#ifndef LITE_RISKRULES_H
#define LITE_RISKRULES_H

#include "lite/env.h"

/// @file
/// Verifying and reading NPCI's signed ServerRiskParams (balance, limits, ACSTATUS, timestamp).

/// Verifies ServerRiskParams: RSA-PSS-SHA512 over utf8(riskRules) against signer-upi.crt. 1 ok, 0 bad, <0 error.
int lite_riskrules_verify(lite_env *env, const char *server_risk_params_json);

/// Decodes the base64 "riskRules" field to its JSON text (caller frees); NULL on error.
char *lite_riskrules_decode(const char *server_risk_params_json);

/// Verifies, decodes, then reads one field from the inner riskRules JSON into `out`. Length or -1.
long lite_riskrules_field(lite_env *env, const char *server_risk_params_json,
                          const char *field, char *out, size_t cap);

#endif
