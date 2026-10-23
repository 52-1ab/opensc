#include "npci_test_ca.h"
#include "lite/codec.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <stdlib.h>
#include <string.h>

struct npci_ca {
    EVP_PKEY *key;
    uint8_t *pem;
    size_t pem_len;
};

npci_ca *npci_ca_new(void) {
    npci_ca *ca = calloc(1, sizeof *ca);
    ca->key = EVP_RSA_gen(2048);
    X509 *x = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 3600);
    X509_set_pubkey(x, ca->key);
    X509_NAME *n = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char *)"upinpci-test", -1, -1, 0);
    X509_set_issuer_name(x, n);
    X509_sign(x, ca->key, EVP_sha256());
    BIO *b = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(b, x);
    char *data = NULL;
    long len = BIO_get_mem_data(b, &data);
    ca->pem = malloc((size_t)len);
    memcpy(ca->pem, data, (size_t)len);
    ca->pem_len = (size_t)len;
    BIO_free(b);
    X509_free(x);
    return ca;
}

void npci_ca_free(npci_ca *ca) {
    if (!ca) return;
    EVP_PKEY_free(ca->key);
    free(ca->pem);
    free(ca);
}

const uint8_t *npci_ca_cert_pem(npci_ca *ca, size_t *len) {
    *len = ca->pem_len;
    return ca->pem;
}

char *npci_ca_sign_state(npci_ca *ca, const char *inner) {
    size_t cap = lite_b64_encode_len(strlen(inner), LITE_B64_NO_WRAP);
    char *inner_b64 = malloc(cap);
    lite_b64_encode((const uint8_t *)inner, strlen(inner), LITE_B64_NO_WRAP, inner_b64, cap);

    EVP_MD_CTX *c = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pc = NULL;
    EVP_DigestSignInit(c, &pc, EVP_sha512(), NULL, ca->key);
    EVP_PKEY_CTX_set_rsa_padding(pc, RSA_PKCS1_PSS_PADDING);
    EVP_PKEY_CTX_set_rsa_mgf1_md(pc, EVP_sha512());
    EVP_PKEY_CTX_set_rsa_pss_saltlen(pc, RSA_PSS_SALTLEN_DIGEST);
    size_t sn = 0;
    EVP_DigestSign(c, NULL, &sn, (const uint8_t *)inner_b64, strlen(inner_b64));
    uint8_t *sig = malloc(sn);
    EVP_DigestSign(c, sig, &sn, (const uint8_t *)inner_b64, strlen(inner_b64));
    EVP_MD_CTX_free(c);

    size_t scap = lite_b64_encode_len(sn, LITE_B64_NO_WRAP);
    char *sig_b64 = malloc(scap);
    lite_b64_encode(sig, sn, LITE_B64_NO_WRAP, sig_b64, scap);

    size_t out_cap = strlen(inner_b64) + strlen(sig_b64) + 64;
    char *out = malloc(out_cap);
    snprintf(out, out_cap, "{\"riskRules\":\"%s\",\"signature\":\"%s\"}", inner_b64, sig_b64);
    free(inner_b64);
    free(sig);
    free(sig_b64);
    return out;
}
