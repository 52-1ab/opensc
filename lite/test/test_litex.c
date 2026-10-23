#include "lite/litex.h"
#include "lite/primitives.h"
#include "testutil.h"

int main(void) {
    litex_pvr p;
    char hex[17];

    litex_pvr_init(&p);
    litex_pvr_hex(&p, hex);
    CHECK_STR(hex, "0000000000000000");

    litex_pvr_set(&p, 8, 8, 1);
    litex_pvr_hex(&p, hex);
    CHECK_STR(hex, "0000000000000080");
    CHECK(lite_pvr_get(&p, 8, 8) == 1);

    litex_pvr_init(&p);
    litex_pvr_set(&p, 8, 1, 1);
    litex_pvr_hex(&p, hex);
    CHECK_STR(hex, "0000000000000001");

    litex_pvr_init(&p);
    litex_pvr_set(&p, 7, 8, 1);
    litex_pvr_hex(&p, hex);
    CHECK_STR(hex, "0000000000008000");
    litex_pvr_set(&p, 7, 8, 0);
    litex_pvr_hex(&p, hex);
    CHECK_STR(hex, "0000000000000000");

    CHECK(litex_pac_applies(0xC0, 1) == 1);
    CHECK(litex_pac_applies(0xC0, 0) == 1);
    CHECK(litex_pac_applies(0x40, 1) == 1);
    CHECK(litex_pac_applies(0x40, 0) == 0);
    CHECK(litex_pac_applies(0x80, 0) == 1);
    CHECK(litex_pac_applies(0x80, 1) == 0);
    CHECK(litex_pac_applies(0x00, 1) == 0);

    CHECK(litex_counter_update(0x00, 5.0, 10.0) == 6.0);
    CHECK(litex_counter_update(0x20, 5.0, 10.0) == 15.0);

    const lite_crypto *c = lite_crypto_openssl();
    char id[64];
    CHECK(litex_txn_id(c, "P1", "1", "AC1", "P2", "2", "AC2", id, sizeof id) == 35);
    CHECK_STR(id, "bbf4b2529b1d6e176f1525cb1cbd0935a49");

    lite_env env = {0};
    env.crypto = c;
    env.keystore = lite_keystore_mem_new();
    CHECK(litex_enable(&env, "ALIASX") == 0);
    char sig[512];
    CHECK(litex_sign(&env, "ALIASX", "transfer|payload|1", sig, sizeof sig) > 0);
    CHECK(litex_verify(&env, "ALIASX", "transfer|payload|1", sig) == 1);
    CHECK(litex_verify(&env, "ALIASX", "transfer|payload|2", sig) == 0);

    lite_keystore_mem_free(env.keystore);
    printf("test_litex");
    DONE();
}
