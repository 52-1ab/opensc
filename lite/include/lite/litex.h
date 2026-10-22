#ifndef LITE_LITEX_H
#define LITE_LITEX_H

#include <stddef.h>
#include <stdint.h>

#include "lite/env.h"

// UPI Lite X: the fully-offline purse. These are its deterministic primitives (o000OO0O).

typedef enum { LX_IDLE, LX_AWAITING_REQ, LX_AWAITING_VAL, LX_AWAITING_ACK } litex_state;

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

#endif
