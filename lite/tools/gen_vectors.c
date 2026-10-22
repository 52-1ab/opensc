#include "lite/codec.h"
#include "lite/litex.h"
#include "lite/primitives.h"

#include <stdio.h>
#include <string.h>

// Emits deterministic known-answer vectors as JSON lines: {"op":..,"in":[..],"out":..}.
// Only operations free of OpenSSL-internal randomness appear, so output is byte-stable.

static const lite_crypto *C;

static void emit(FILE *f, const char *op, const char *in_json, const char *out) {
    fprintf(f, "{\"op\":\"%s\",\"in\":%s,\"out\":\"", op, in_json);
    for (const char *p = out; *p; p++) {
        if (*p == '\n') fputs("\\n", f);
        else if (*p == '"') fputs("\\\"", f);
        else if (*p == '\\') fputs("\\\\", f);
        else fputc(*p, f);
    }
    fputs("\"}\n", f);
}

static void gen_alias(FILE *f) {
    const char *tuples[][4] = {
        {"DEV123", "9000000000", "ACC789", "UPI"},
        {"abc", "9999999999", "REF1", "UPI"},
        {"", "", "", "UPI"},
        {"d-e-v", "0000000001", "x/y+z", "UPI"},
        {"长设备", "9112233445", "खाता", "UPI"},
    };
    char out[256], in[512];
    for (size_t i = 0; i < sizeof tuples / sizeof tuples[0]; i++) {
        lite_alias(C, tuples[i][0], tuples[i][1], tuples[i][2], tuples[i][3], out, sizeof out);
        snprintf(in, sizeof in, "[\"%s\",\"%s\",\"%s\",\"%s\"]",
                 tuples[i][0], tuples[i][1], tuples[i][2], tuples[i][3]);
        emit(f, "alias", in, out);
    }
}

static void gen_sha(FILE *f) {
    const char *strs[] = {"hello", "", "a", "100.00|TXN|20260101", "payerId.1.ac", "{\\\"k\\\":1}"};
    const char *raw[] = {"hello", "", "a", "100.00|TXN|20260101", "payerId.1.ac", "{\"k\":1}"};
    char out[256], in[256];
    for (size_t i = 0; i < sizeof raw / sizeof raw[0]; i++) {
        lite_sha256_b64(C, raw[i], out, sizeof out);
        snprintf(in, sizeof in, "[\"%s\"]", strs[i]);
        emit(f, "sha256b64", in, out);
        lite_sha1_id35(C, raw[i], out, sizeof out);
        emit(f, "sha1id35", in, out);
    }
}

static void gen_vaultsig(FILE *f) {
    const char *cts[] = {"Zm9vYmFy", "AAAA", "aGVsbG8sIHdvcmxkIQ=="};
    const char *ivs[] = {"MTIzNDU2Nzg5MDEy", "MDAwMDAwMDAwMDAw", "YWJjZGVmZ2hpamts"};
    char out[256], in[512];
    for (size_t i = 0; i < 3; i++) {
        lite_vault_sig_message(C, cts[i], ivs[i], out, sizeof out);
        snprintf(in, sizeof in, "[\"%s\",\"%s\"]", cts[i], ivs[i]);
        emit(f, "vaultsig", in, out);
    }
}

static void gen_payload(FILE *f) {
    char out[1024];
    lite_debit_payload("100.00", "TXN1", "20260101120000", "5001234567", "merchant@upi",
                       "com.phonepe.app", "9000000000", "DEV123", "CT|IV", out, sizeof out);
    emit(f, "debit_payload",
         "[\"100.00\",\"TXN1\",\"20260101120000\",\"5001234567\",\"merchant@upi\","
         "\"com.phonepe.app\",\"9000000000\",\"DEV123\",\"CT|IV\"]", out);
}

static void gen_litex(FILE *f) {
    char out[64], in[64];
    for (int code = 0; code < 256; code += 32) {
        for (int d = 0; d <= 1; d++) {
            snprintf(out, sizeof out, "%d", litex_pac_applies((uint8_t)code, d));
            snprintf(in, sizeof in, "[%d,%d]", code, d);
            emit(f, "pac", in, out);
        }
    }
    struct { int idx, bit; } sets[] = {{8, 8}, {8, 1}, {7, 8}, {1, 1}, {5, 4}};
    for (size_t i = 0; i < sizeof sets / sizeof sets[0]; i++) {
        litex_pvr p;
        litex_pvr_init(&p);
        litex_pvr_set(&p, sets[i].idx, sets[i].bit, 1);
        char hex[17];
        litex_pvr_hex(&p, hex);
        snprintf(in, sizeof in, "[%d,%d]", sets[i].idx, sets[i].bit);
        emit(f, "pvr_set", in, hex);
    }
    char id[64];
    litex_txn_id(C, "P1", "1", "AC1", "P2", "2", "AC2", id, sizeof id);
    emit(f, "litex_txn_id", "[\"P1\",\"1\",\"AC1\",\"P2\",\"2\",\"AC2\"]", id);
}

int main(int argc, char **argv) {
    C = lite_crypto_openssl();
    FILE *f = argc > 1 ? fopen(argv[1], "w") : stdout;
    gen_alias(f);
    gen_sha(f);
    gen_vaultsig(f);
    gen_payload(f);
    gen_litex(f);
    if (f != stdout) fclose(f);
    return 0;
}
