#ifndef LITE_LITEX_H
#define LITE_LITEX_H

#include <stddef.h>
#include <stdint.h>

#include "lite/env.h"

/// @file
/// UPI Lite X: the fully-offline purse (o000OO0O) — PVR/pac/counter/txnId primitives, the P2P
/// transfer handshake, and the identity exchange.

/// Offline-purse state-machine states.
typedef enum { LX_IDLE, LX_AWAITING_REQ, LX_AWAITING_VAL, LX_AWAITING_ACK } litex_state;

/// Lite X operation result codes.
enum { LX_OK = 0, LX_ERR_STATE = -1, LX_DECLINED = -2, LX_BAD_SIG = -3 };

/// 8-byte Purse Verification Result bitmap. Index/bit are 1-based, as in the CL's setPVR.
typedef struct {
    uint8_t b[8];  ///< The eight result bytes; byte `index` (1..8) holds bits 1..8.
} litex_pvr;

/// Clears all PVR bits.
void litex_pvr_init(litex_pvr *p);
/// Sets (on!=0) or clears bit `bit` (1..8) of byte `index` (1..8).
void litex_pvr_set(litex_pvr *p, int index, int bit, int on);
/// Returns bit `bit` of byte `index` (0/1).
int lite_pvr_get(const litex_pvr *p, int index, int bit);
/// Writes the 16-char lowercase-hex rendering of the PVR into `out` (17 bytes incl. NUL).
void litex_pvr_hex(const litex_pvr *p, char out[17]);

/// Purse-action-code predicate: the code's top two bits select applicability to debit/credit.
int litex_pac_applies(uint8_t code, int is_debit);

/// Counter step: bit5 of `code` selects increment-by-one (0) vs add-`amount` (1). Returns the new value.
double litex_counter_update(uint8_t code, double cur, double amount);

/// txnId = hex(SHA1(payerId.payerSeq.ac1.payeeId.payeeSeq.ac2))[0:35]. Returns 35 or -1.
long litex_txn_id(const lite_crypto *c, const char *payer_id, const char *payer_seq,
                  const char *ac1, const char *payee_id, const char *payee_seq, const char *ac2,
                  char *out, size_t cap);

/// Generates the offline EC key (alias + "-OFFLINE") used to sign transfer values. 0 on success.
int litex_enable(lite_env *env, const char *alias);

/// Signs `data` with the offline EC key (ECDSA-SHA256); writes base64 signature. Length or -1.
long litex_sign(lite_env *env, const char *alias, const char *data, char *out_b64, size_t cap);
/// Verifies a base64 ECDSA-SHA256 signature over `data` with this purse's own offline key. 1/0/<0.
int litex_verify(lite_env *env, const char *alias, const char *data, const char *sig_b64);

/// Exports the offline EC public key (alias + "-OFFLINE") as base64 SPKI. Length or -1.
long litex_offline_pubkey(lite_env *env, const char *alias, char *out_b64, size_t cap);
/// Verifies a base64 ECDSA-SHA256 signature over `data` with the base64 SPKI `pub_b64`. 1/0/<0.
int litex_verify_pub(lite_env *env, const char *pub_b64, const char *data, const char *sig_b64);

/// One leg of an offline P2P transfer. Field order matches the CL's generateSignaturePayload.
typedef struct {
    const char *payer_id;    ///< Payer purse id.
    const char *payer_seq;   ///< Payer sequence number.
    const char *payer_vpa;   ///< Payer VPA/address.
    const char *payee_id;    ///< Payee purse id.
    const char *payee_seq;   ///< Payee sequence number.
    const char *payee_vpa;   ///< Payee VPA/address.
    const char *timestamp;   ///< Transfer timestamp.
    const char *currency;    ///< Currency code.
    const char *amount;      ///< Transfer amount (decimal string).
} litex_xfer;

/// A purse party in the offline transfer handshake.
typedef struct {
    lite_env *env;          ///< Runtime environment.
    char alias[256];        ///< This purse's key alias.
    char remote_pub[512];   ///< Counterparty's offline public key (base64 SPKI).
    litex_state state;      ///< Current handshake state.
    double balance;         ///< Spendable offline balance.
    char txndp[1024];       ///< Running signed payload: base plus each appended signature.
    char txn_id[64];        ///< Derived transaction id for the in-flight transfer.
} litex_purse;

/// Initializes a purse with its alias and balance, generating its offline key. 0 on success.
int litex_purse_start(litex_purse *p, lite_env *env, const char *alias, double balance);
/// Sets the counterparty's offline public key (base64 SPKI) for verification.
void litex_purse_set_remote(litex_purse *p, const char *remote_pub_b64);

/// Purse identity fields (assert/verifyIdentity). The purse certificate's key is modelled by the
/// offline EC key, since NPCI's real offline purse-CA keys are not in any APK.
typedef struct {
    const char *id;        ///< Purse id (PID).
    const char *product;   ///< Product type (PPT).
    const char *currency;  ///< Currency (PCUR).
    const char *country;   ///< Country (PCOU).
    const char *type;      ///< Purse type (PT).
    const char *mcc;       ///< Merchant category code (PMCC), or NULL.
} litex_identity;

/// Bootstrap: generate the LOCAC challenge, record `balance`, arm the purse. Writes challenge hex; length or -1.
long litex_get_purse_info(litex_purse *p, double balance, char *challenge_out, size_t cap);

/// Asserts this purse's identity, signing the fields + `remote_challenge`; writes an identity doc. LX_OK or <0.
int litex_assert_identity(litex_purse *p, const litex_identity *id, const char *remote_challenge,
                          char *out_json, size_t cap);

/// Verifies a remote identity doc against `our_challenge`; on success adopts its key as remote_pub. LX_OK/LX_BAD_SIG.
int litex_verify_identity(litex_purse *p, const char *remote_json, const char *our_challenge);

/// Payer: IDLE -> AWAITING_REQ; declines on insufficient balance (PVR bit 7,8). Fills txn_id. LX_OK/LX_DECLINED/LX_ERR_STATE.
int litex_start_debit(litex_purse *p, const litex_xfer *x);
/// Payee: IDLE -> AWAITING_VAL; signs REQS over the payload into `reqs_out`. Fills txn_id. LX_OK/LX_ERR_STATE.
int litex_start_credit(litex_purse *p, const litex_xfer *x, char *reqs_out, size_t cap);
/// Payer: AWAITING_REQ -> AWAITING_ACK; verifies REQS, signs TRAS into `tras_out`. LX_OK/LX_BAD_SIG/LX_ERR_STATE.
int litex_request_value(litex_purse *p, const char *reqs, char *tras_out, size_t cap);
/// Payee: AWAITING_VAL -> IDLE; verifies TRAS over payload+REQS, signs ACKS into `acks_out`. LX_OK/LX_BAD_SIG/LX_ERR_STATE.
int litex_transfer_value(litex_purse *p, const char *reqs, const char *tras, char *acks_out, size_t cap);
/// Payer: AWAITING_ACK -> IDLE; verifies ACKS over payload+REQS+TRAS. LX_OK/LX_BAD_SIG/LX_ERR_STATE.
int litex_acknowledge_value(litex_purse *p, const char *reqs, const char *tras, const char *acks);

#endif
