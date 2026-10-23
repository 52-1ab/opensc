#include "lite/primitives.h"
#include "testutil.h"

int main(void) {
    const lite_crypto *c = lite_crypto_openssl();
    char out[256];

    long n = lite_alias(c, "DEV123", "9663078862", "ACC789", "UPI", out, sizeof out);
    CHECK(n > 0);
    CHECK_STR(out, "ugd+2Us4x7ph09s6zw0FI5cxFdBUoTp5M5nnI73ghiA=");

    lite_sha256_b64(c, "hello", out, sizeof out);
    CHECK_STR(out, "LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=");

    lite_sha1_id35(c, "a.b.c", out, sizeof out);
    CHECK_STR(out, "62322b00c8c084c1c93c431e795e92e1f22");
    CHECK(strlen(out) == 35);

    lite_debit_payload("100.00", "TXN1", "20260101", "5001234", "p@upi", "com.x",
                       "9663078862", "DEV123", "RP==", out, sizeof out);
    CHECK_STR(out, "1.0|100.00|TXN1|20260101|5001234|p@upi|com.x|9663078862|DEV123|RP==");

    lite_vault_sig_message(c, "Zm9vYmFy", "MTIzNDU2Nzg5MDEy", out, sizeof out);
    CHECK_STR(out, "VOdPAQof9AuIW6bJoSiOy2raWQTagaPjIBQ4sgpao0o=\n");

    printf("test_alias");
    DONE();
}
