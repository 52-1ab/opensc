#ifndef LITE_WALLET_H
#define LITE_WALLET_H

#include "lite/env.h"
#include "lite/vault.h"

enum {
    LITE_BIND_NO = 0,
    LITE_BIND_YES = 1,
};

enum {
    LITE_SYNC_OK = 0,
    LITE_SYNC_BAD_SIG = -10,
    LITE_SYNC_STALE = -11,       // incoming timestamp not strictly newer: rollback-relevant gate
    LITE_SYNC_DEACTIVATED = -12, // ACSTATUS=DA; device unbound
    LITE_SPEND_SYNC_REQUIRED = -20,
    LITE_SPEND_DECLINED = -21,   // limit/balance/ACSTATUS gate failed
};

typedef struct {
    int bound;
    int sync_required;
    char ltl[32];
    char bal[32];
    char acstatus[8];
} lite_bind_info;

typedef struct {
    double balance;
    double non_spendable;
    int pending_count;
} lite_balance_info;

typedef struct {
    const char *amount;
    const char *txn_id;
    const char *ts;
    const char *payer_lite_acc;
    const char *payee_addr;
    const char *app_id;
    const char *mobile;
    const char *device_id;
} lite_txn;

// Establishes vault + spend key + session key, then applies the first signed state blob.
int lite_onboard(lite_env *env, const char *alias, const char *signed_state_json);

int lite_is_bound(lite_env *env, const char *alias, lite_bind_info *out);
int lite_balance(lite_env *env, const char *alias, lite_balance_info *out);

// Applies a signed state blob: verify, require newer timestamp, replace state, clear PendingTxn.
int lite_sync(lite_env *env, const char *alias, const char *signed_state_json);

// Signs a spend. Writes {"riskParams":..,"signature":..} JSON to out. Enforces the PendingTxn gate.
int lite_spend(lite_env *env, const char *alias, const lite_txn *txn, int is_credit,
               char *out, size_t cap);

int lite_unbind(lite_env *env, const char *alias);

#endif
