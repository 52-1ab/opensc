#ifndef LITE_RISKRULES_H
#define LITE_RISKRULES_H

#include "lite/env.h"

// Verifies ServerRiskParams: RSA-PSS-SHA512 over utf8(riskRules) vs signer-upi.crt. 1/0/<0.
int lite_riskrules_verify(lite_env *env, const char *server_risk_params_json);

// Decodes the base64 "riskRules" field to its JSON text (caller frees); NULL on error.
char *lite_riskrules_decode(const char *server_risk_params_json);

// Convenience: verify then decode then read one field from the inner riskRules JSON.
long lite_riskrules_field(lite_env *env, const char *server_risk_params_json,
                          const char *field, char *out, size_t cap);

#endif
