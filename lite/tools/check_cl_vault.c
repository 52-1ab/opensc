#include "lite/codec.h"
#include "lite/crypto.h"
#include "lite/json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Reads a CL-encrypted vault blob ("ct_b64|iv_b64") + key and checks C decrypts it to plain.
int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s crosscheck_cl.json\n", argv[0]); return 2; }
    FILE *f = fopen(argv[1], "r");
    if (!f) { perror("open"); return 2; }
    char buf[8192];
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    buf[n] = '\0';
    fclose(f);

    lj_node *o = lj_parse(buf, strlen(buf));
    const char *key_b64 = lj_get_str(o, "aes_key", "");
    const char *blob = lj_get_str(o, "blob", "");
    const char *plain = lj_get_str(o, "plain", "");

    const char *bar = strchr(blob, '|');
    if (!bar) { fprintf(stderr, "no | in blob\n"); return 1; }
    size_t ct_len_b64 = (size_t)(bar - blob);

    const lite_crypto *c = lite_crypto_openssl();
    uint8_t key[32], iv[32], ctblob[512];
    long kn = lite_b64_decode(key_b64, strlen(key_b64), key, sizeof key);
    long ivn = lite_b64_decode(bar + 1, strlen(bar + 1), iv, sizeof iv);
    long bn = lite_b64_decode(blob, ct_len_b64, ctblob, sizeof ctblob);
    if (kn != 32 || ivn < 0 || bn < 16) { fprintf(stderr, "decode fail\n"); return 1; }

    size_t pt_len = (size_t)bn - 16;
    uint8_t *pt = malloc(pt_len + 1);
    int rc = c->aes_gcm_decrypt(c->ctx, key, 32, iv, (size_t)ivn, ctblob, pt_len,
                                ctblob + pt_len, pt);
    pt[pt_len] = '\0';
    int ok = rc == 0 && strcmp((char *)pt, plain) == 0;
    printf("C decrypts CL vault blob: %s\n", ok ? "true" : "false");
    if (!ok) { printf("  want [%s] got [%s]\n", plain, rc == 0 ? (char *)pt : "<decrypt failed>"); }
    free(pt);
    lj_free(o);
    return ok ? 0 : 1;
}
