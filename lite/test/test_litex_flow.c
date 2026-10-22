#include "lite/litex.h"
#include "testutil.h"

int main(void) {
    lite_env env = {0};
    env.crypto = lite_crypto_openssl();
    env.keystore = lite_keystore_mem_new();

    litex_purse payer, payee;
    CHECK(litex_purse_start(&payer, &env, "PAYER", 500.0) == 0);
    CHECK(litex_purse_start(&payee, &env, "PAYEE", 100.0) == 0);

    char payer_pub[512], payee_pub[512];
    CHECK(litex_offline_pubkey(&env, "PAYER", payer_pub, sizeof payer_pub) > 0);
    CHECK(litex_offline_pubkey(&env, "PAYEE", payee_pub, sizeof payee_pub) > 0);
    litex_purse_set_remote(&payer, payee_pub);
    litex_purse_set_remote(&payee, payer_pub);

    litex_xfer x = {"P", "1", "p@upi", "Q", "1", "q@upi", "1767225600000", "INR", "50.00"};
    char reqs[512], tras[512], acks[512];

    CHECK(litex_start_debit(&payer, &x) == LX_OK);
    CHECK(payer.state == LX_AWAITING_REQ);
    CHECK(litex_start_credit(&payee, &x, reqs, sizeof reqs) == LX_OK);
    CHECK(payee.state == LX_AWAITING_VAL);

    CHECK(strcmp(payer.txn_id, payee.txn_id) == 0);

    CHECK(litex_request_value(&payer, reqs, tras, sizeof tras) == LX_OK);
    CHECK(payer.state == LX_AWAITING_ACK);
    CHECK(litex_transfer_value(&payee, reqs, tras, acks, sizeof acks) == LX_OK);
    CHECK(payee.state == LX_IDLE);
    CHECK(litex_acknowledge_value(&payer, reqs, tras, acks) == LX_OK);
    CHECK(payer.state == LX_IDLE);

    litex_purse over;
    litex_purse_start(&over, &env, "POOR", 10.0);
    CHECK(litex_start_debit(&over, &x) == LX_DECLINED);

    litex_purse p2, q2;
    litex_purse_start(&p2, &env, "PAYER", 500.0);
    litex_purse_start(&q2, &env, "PAYEE", 100.0);
    litex_purse_set_remote(&p2, payee_pub);
    char reqs2[512], tras2[512];
    litex_start_debit(&p2, &x);
    litex_start_credit(&q2, &x, reqs2, sizeof reqs2);
    char tampered[512];
    snprintf(tampered, sizeof tampered, "%s", reqs2);
    tampered[0] = (tampered[0] == 'A') ? 'B' : 'A';
    CHECK(litex_request_value(&p2, tampered, tras2, sizeof tras2) == LX_BAD_SIG);

    litex_purse idle;
    litex_purse_start(&idle, &env, "IDLE", 10.0);
    CHECK(litex_request_value(&idle, reqs, tras, sizeof tras) == LX_ERR_STATE);

    lite_keystore_mem_free(env.keystore);
    printf("test_litex_flow");
    DONE();
}
