#include "lite/codec.h"
#include "lite/litex.h"
#include "lite/primitives.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Line protocol for jqwik parity fuzzing. String args arrive hex-encoded; see README in lite/.
static char *unhex(const char *h) {
    size_t n = strlen(h) / 2;
    char *s = malloc(n + 1);
    lite_hex_decode(h, strlen(h), (uint8_t *)s, n);
    s[n] = '\0';
    return s;
}

static void emit_text(const char *s) { printf("OK %s\n", s); fflush(stdout); }

static void emit_hex(const char *s) {
    size_t n = strlen(s);
    char *h = malloc(n * 2 + 1);
    lite_hex_encode((const uint8_t *)s, n, h, n * 2 + 1);
    printf("OK %s\n", h);
    fflush(stdout);
    free(h);
}

int main(void) {
    const lite_crypto *c = lite_crypto_openssl();
    puts("READY lite alias,sha256b64,sha1id35,vaultsig,pac,counter");
    fflush(stdout);

    char line[1 << 16];
    while (fgets(line, sizeof line, stdin)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strcmp(line, "QUIT") == 0) break;
        if (line[0] == '\0') continue;

        char *tok[8] = {0};
        int nt = 0;
        for (char *p = strtok(line, " "); p && nt < 8; p = strtok(NULL, " ")) tok[nt++] = p;
        char out[4096];

        if (strcmp(tok[0], "alias") == 0 && nt == 5) {
            char *dev = unhex(tok[1]), *mob = unhex(tok[2]), *acc = unhex(tok[3]), *svc = unhex(tok[4]);
            if (lite_alias(c, dev, mob, acc, svc, out, sizeof out) > 0) emit_text(out);
            else emit_text("ERR");
            free(dev); free(mob); free(acc); free(svc);
        } else if (strcmp(tok[0], "sha256b64") == 0 && nt == 2) {
            char *s = unhex(tok[1]);
            lite_sha256_b64(c, s, out, sizeof out);
            emit_text(out);
            free(s);
        } else if (strcmp(tok[0], "sha1id35") == 0 && nt == 2) {
            char *s = unhex(tok[1]);
            lite_sha1_id35(c, s, out, sizeof out);
            emit_text(out);
            free(s);
        } else if (strcmp(tok[0], "vaultsig") == 0 && nt == 3) {
            char *ct = unhex(tok[1]), *iv = unhex(tok[2]);
            if (lite_vault_sig_message(c, ct, iv, out, sizeof out) > 0) emit_hex(out);
            else emit_text("ERR");
            free(ct); free(iv);
        } else if (strcmp(tok[0], "pac") == 0 && nt == 3) {
            snprintf(out, sizeof out, "%d", litex_pac_applies((uint8_t)atoi(tok[1]), atoi(tok[2])));
            emit_text(out);
        } else if (strcmp(tok[0], "counter") == 0 && nt == 4) {
            snprintf(out, sizeof out, "%.2f", litex_counter_update((uint8_t)atoi(tok[1]), atof(tok[2]), atof(tok[3])));
            emit_text(out);
        } else {
            emit_text("ERR");
        }
    }
    return 0;
}
