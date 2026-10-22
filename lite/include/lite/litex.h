#ifndef LITE_LITEX_H
#define LITE_LITEX_H

#include <stddef.h>
#include <stdint.h>

#include "lite/env.h"

// UPI Lite X: the fully-offline purse. These are its deterministic primitives (o000OO0O).

typedef enum { LX_IDLE, LX_AWAITING_REQ, LX_AWAITING_VAL, LX_AWAITING_ACK } litex_state;

enum { LX_OK = 0, LX_ERR_STATE = -1, LX_DECLINED = -2, LX_BAD_SIG = -3 };

// 8-byte Purse Verification Result bitmap. Index/bit are 1-based, as in the CL's setPVR.
typedef struct { uint8_t b[8]; } litex_pvr;

void litex_pvr_init(litex_pvr *p);
void litex_pvr_set(litex_pvr *p, int index, int bit, int on);
int lite_pvr_get(const litex_pvr *p, int index, int bit);
void litex_pvr_hex(const litex_pvr *p, char out[17]);

// Purse-action-code predicate: top two bits select applicability to debit/credit.
int litex_pac_applies(uint8_t code, int is_debit);

// Counter step: bit5 selects increment-by-one (0) vs add-amount (1).
double litex_counter_update(uint8_t code, double cur, double amount);

// txnId = hex(SHA1(payerId.payerSeq.ac1.payeeId.payeeSeq.ac2))[0:35].
long litex_txn_id(const lite_crypto *c, const char *payer_id, const char *payer_seq,
                  const char *ac1, const char *payee_id, const char *payee_seq, const char *ac2,
                  char *out, size_t cap);

// Generates the offline EC key (alias + "-OFFLINE") used to sign transfer values.
int litex_enable(lite_env *env, const char *alias);

// Signs/verifies a transfer-value payload with ECDSA-SHA256 over the offline key.
long litex_sign(lite_env *env, const char *alias, const char *data, char *out_b64, size_t cap);
int litex_verify(lite_env *env, const char *alias, const char *data, const char *sig_b64);

// Exports the offline EC public key (alias + "-OFFLINE") as base64 SPKI, and verifies with one.
long litex_offline_pubkey(lite_env *env, const char *alias, char *out_b64, size_t cap);
int litex_verify_pub(lite_env *env, const char *pub_b64, const char *data, const char *sig_b64);

// One leg of an offline P2P transfer. Fields order matches the CL's generateSignaturePayload.
typedef struct {
    const char *payer_id, *payer_seq, *payer_vpa;
    const char *payee_id, *payee_seq, *payee_vpa;
    const char *timestamp, *currency, *amount;
} litex_xfer;

// A purse party in the offline transfer handshake.
typedef struct {
    lite_env *env;
    char alias[256];
    char remote_pub[512];
    litex_state state;
    double balance;
    char txndp[1024];   // running signed payload: base + each appended signature
    char txn_id[64];
} litex_purse;

int litex_purse_start(litex_purse *p, lite_env *env, const char *alias, double balance);
void litex_purse_set_remote(litex_purse *p, const char *remote_pub_b64);

// Payer: IDLE -> AWAITING_REQ, declines on insufficient balance (PVR bit 7,8). Fills txn_id.
int litex_start_debit(litex_purse *p, const litex_xfer *x);
// Payee: IDLE -> AWAITING_VAL, signs REQS over the payload. Fills txn_id and reqs_out.
int litex_start_credit(litex_purse *p, const litex_xfer *x, char *reqs_out, size_t cap);
// Payer: AWAITING_REQ -> AWAITING_ACK, verifies REQS, signs TRAS.
int litex_request_value(litex_purse *p, const char *reqs, char *tras_out, size_t cap);
// Payee: AWAITING_VAL -> IDLE, verifies TRAS over payload+REQS, signs ACKS over payload+REQS+TRAS.
int litex_transfer_value(litex_purse *p, const char *reqs, const char *tras, char *acks_out, size_t cap);
// Payer: AWAITING_ACK -> IDLE, verifies ACKS over payload+REQS+TRAS.
int litex_acknowledge_value(litex_purse *p, const char *reqs, const char *tras, const char *acks);

#endif
