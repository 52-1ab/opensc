#include "lite/riskrules.h"
#include "lite/codec.h"
#include "lite/json.h"

#include <stdlib.h>
#include <string.h>

static int get_fields(const char *srp, char **rules, char **sig) {
    lj_node *o = lj_parse(srp, strlen(srp));
    if (!o) return -1;
    const char *r = lj_get_str(o, "riskRules", NULL);
    const char *s = lj_get_str(o, "signature", NULL);
    if (!r || !s) { lj_free(o); return -1; }
    *rules = strdup(r);
    *sig = strdup(s);
    lj_free(o);
    return 0;
}

int lite_riskrules_verify(lite_env *env, const char *srp) {
    if (!env->signer_upi_cert) return -1;
    char *rules = NULL, *sig = NULL;
    if (get_fields(srp, &rules, &sig) != 0) return -1;
    uint8_t spki[1024];
    long spn = env->crypto->x509_spki(env->crypto->ctx, env->signer_upi_cert,
                                      env->signer_upi_cert_len, spki, sizeof spki);
    int rc = -1;
    if (spn > 0) {
        uint8_t raw[1024];
        long sn = lite_b64_decode(sig, strlen(sig), raw, sizeof raw);
        if (sn > 0)
            rc = env->crypto->rsa_pss_sha512_verify(env->crypto->ctx, spki, (size_t)spn,
                                                    (const uint8_t *)rules, strlen(rules),
                                                    raw, (size_t)sn);
    }
    free(rules);
    free(sig);
    return rc;
}

char *lite_riskrules_decode(const char *srp) {
    lj_node *o = lj_parse(srp, strlen(srp));
    if (!o) return NULL;
    const char *r = lj_get_str(o, "riskRules", NULL);
    char *out = NULL;
    if (r) {
        size_t cap = lite_b64_decode_len(strlen(r));
        uint8_t *buf = malloc(cap);
        long n = lite_b64_decode(r, strlen(r), buf, cap);
        if (n >= 0) {
            out = malloc((size_t)n + 1);
            memcpy(out, buf, (size_t)n);
            out[n] = '\0';
        }
        free(buf);
    }
    lj_free(o);
    return out;
}

long lite_riskrules_field(lite_env *env, const char *srp, const char *field, char *out, size_t cap) {
    if (lite_riskrules_verify(env, srp) != 1) return -1;
    char *json = lite_riskrules_decode(srp);
    if (!json) return -1;
    lj_node *o = lj_parse(json, strlen(json));
    free(json);
    const char *v = lj_get_str(o, field, NULL);
    long r = -1;
    if (v) {
        size_t n = strlen(v);
        if (n + 1 <= cap) { memcpy(out, v, n + 1); r = (long)n; }
    }
    lj_free(o);
    return r;
}
