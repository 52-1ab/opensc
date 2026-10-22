#ifndef NPCI_TEST_CA_H
#define NPCI_TEST_CA_H

#include <stddef.h>
#include <stdint.h>

// Test-only stand-in for NPCI's signer key. NOT the real NPCI key; signs test riskRules so the
// verify path can be exercised without the private key, which is not in any APK.
typedef struct npci_ca npci_ca;

npci_ca *npci_ca_new(void);
void npci_ca_free(npci_ca *ca);

// PEM of the self-signed test cert; set as env.signer_upi_cert.
const uint8_t *npci_ca_cert_pem(npci_ca *ca, size_t *len);

// Builds ServerRiskParams {"riskRules":b64(inner),"signature":b64(PSS-SHA512(utf8(b64(inner))))}.
char *npci_ca_sign_state(npci_ca *ca, const char *inner_risk_rules_json);

#endif
