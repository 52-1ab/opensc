#include "lite/codec.h"
#include "lite/json.h"
#include "lite/litex.h"
#include "lite/primitives.h"
#include "testutil.h"

#include <stdio.h>

static const lite_crypto *C;

static const char *arg(const lj_node *in, size_t i) {
    const char *s = lj_as_str(lj_at(in, i));
    return s ? s : "";
}

static void run(const char *op, const lj_node *in, const char *want) {
    char out[2048];
    if (strcmp(op, "alias") == 0) {
        lite_alias(C, arg(in, 0), arg(in, 1), arg(in, 2), arg(in, 3), out, sizeof out);
    } else if (strcmp(op, "sha256b64") == 0) {
        lite_sha256_b64(C, arg(in, 0), out, sizeof out);
    } else if (strcmp(op, "sha1id35") == 0) {
        lite_sha1_id35(C, arg(in, 0), out, sizeof out);
    } else if (strcmp(op, "vaultsig") == 0) {
        lite_vault_sig_message(C, arg(in, 0), arg(in, 1), out, sizeof out);
    } else if (strcmp(op, "debit_payload") == 0) {
        lite_debit_payload(arg(in, 0), arg(in, 1), arg(in, 2), arg(in, 3), arg(in, 4),
                           arg(in, 5), arg(in, 6), arg(in, 7), arg(in, 8), out, sizeof out);
    } else if (strcmp(op, "pac") == 0) {
        snprintf(out, sizeof out, "%d",
                 litex_pac_applies((uint8_t)atoi(arg(in, 0)), atoi(arg(in, 1))));
    } else if (strcmp(op, "pvr_set") == 0) {
        litex_pvr p;
        litex_pvr_init(&p);
        litex_pvr_set(&p, atoi(arg(in, 0)), atoi(arg(in, 1)), 1);
        litex_pvr_hex(&p, out);
    } else if (strcmp(op, "litex_txn_id") == 0) {
        litex_txn_id(C, arg(in, 0), arg(in, 1), arg(in, 2), arg(in, 3), arg(in, 4), arg(in, 5),
                     out, sizeof out);
    } else {
        fprintf(stderr, "unknown op %s\n", op);
        exit(1);
    }
    CHECK_STR(out, want);
}

int main(int argc, char **argv) {
    C = lite_crypto_openssl();
    const char *path = argc > 1 ? argv[1] : "vectors/vectors.json";
    FILE *f = fopen(path, "r");
    CHECK(f != NULL);
    char line[4096];
    int count = 0;
    while (fgets(line, sizeof line, f)) {
        if (line[0] != '{') continue;
        lj_node *o = lj_parse(line, strlen(line));
        run(lj_get_str(o, "op", ""), lj_get(o, "in"), lj_get_str(o, "out", ""));
        lj_free(o);
        count++;
    }
    fclose(f);
    CHECK(count >= 40);
    printf("test_vectors (%d vectors)", count);
    DONE();
}
