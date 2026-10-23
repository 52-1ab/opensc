#ifndef LITE_WALLET_H
#define LITE_WALLET_H

#include "lite/env.h"
#include "lite/vault.h"

/// @file
/// The online UPI Lite wallet: onboard, isBound, balance, sync, spend, unbind.

/// Binding status returned by lite_is_bound().
enum {
    LITE_BIND_NO = 0,   ///< Not bound.
    LITE_BIND_YES = 1,  ///< Bound.
};

/// sync()/spend() result codes.
enum {
    LITE_SYNC_OK = 0,             ///< State applied.
    LITE_SYNC_BAD_SIG = -10,      ///< Incoming state signature invalid.
    LITE_SYNC_STALE = -11,        ///< Incoming timestamp not strictly newer: the rollback-relevant gate.
    LITE_SYNC_DEACTIVATED = -12,  ///< ACSTATUS=DA; device unbound.
    LITE_SPEND_SYNC_REQUIRED = -20, ///< A prior spend is unsynced (PendingTxn non-empty).
    LITE_SPEND_DECLINED = -21,    ///< Limit / balance / ACSTATUS gate failed.
};

/// Result of lite_is_bound().
typedef struct {
    int bound;            ///< 1 if bound.
    int sync_required;    ///< 1 if a spend is pending sync.
    char ltl[32];         ///< Lite transaction limit (decimal string).
    char bal[32];         ///< Balance (decimal string).
    char acstatus[8];     ///< Account status, e.g. "A" or "DA".
} lite_bind_info;

/// Result of lite_balance().
typedef struct {
    double balance;        ///< Spendable balance.
    double non_spendable;  ///< Pending credits not yet spendable.
    int pending_count;     ///< Number of queued PendingTxn entries.
} lite_balance_info;

/// A spend request. All fields are caller-owned strings.
typedef struct {
    const char *amount;          ///< Transaction amount (decimal string).
    const char *txn_id;          ///< Transaction id.
    const char *ts;              ///< Transaction timestamp.
    const char *payer_lite_acc;  ///< Payer's Lite account number.
    const char *payee_addr;      ///< Payee VPA/address.
    const char *app_id;          ///< App package id.
    const char *mobile;          ///< Payer mobile number.
    const char *device_id;       ///< Device id.
} lite_txn;

/// Establishes vault + spend key + session key, then applies the first signed state blob. LITE_SYNC_* code.
int lite_onboard(lite_env *env, const char *alias, const char *signed_state_json);

/// Reports binding status into `out`. Returns LITE_BIND_YES or LITE_BIND_NO.
int lite_is_bound(lite_env *env, const char *alias, lite_bind_info *out);

/// Computes spendable/non-spendable balance and pending count into `out`. LITE_OK or LITE_ERR.
int lite_balance(lite_env *env, const char *alias, lite_balance_info *out);

/// Applies a signed state blob: verify, require a newer timestamp, replace state, clear PendingTxn. LITE_SYNC_* code.
int lite_sync(lite_env *env, const char *alias, const char *signed_state_json);

/// Signs a spend, writing {"riskParams":..,"signature":..} JSON to `out`. Enforces the PendingTxn gate. LITE_OK/LITE_SPEND_*.
int lite_spend(lite_env *env, const char *alias, const lite_txn *txn, int is_credit,
               char *out, size_t cap);

/// Removes the device binding: deletes the alias keys and clears the vault record. LITE_OK.
int lite_unbind(lite_env *env, const char *alias);

#endif
