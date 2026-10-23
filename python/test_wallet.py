"""Mirrors the C test_vault.c + test_wallet.c flows against the Python reference."""

import opensc_lite as o


def _state(sign, bal, ltl, acs, ts):
    inner = '{"BAL":"%s","LTL":"%s","ACSTATUS":"%s","timestamp":"%s"}' % (bal, ltl, acs, ts)
    return sign(inner)


def test_vault():
    env = o.Env()
    al = o.alias("DEV123", "9000000000", "ACC789", "UPI")
    o.vault_open(env, al)
    o.vault_set(env, al, "BAL", "5000.00")
    o.vault_set(env, al, "ATC", "7")
    assert o.vault_get(env, al, "BAL") == "5000.00"
    assert o.vault_get(env, al, "ATC") == "7"
    assert o.vault_get(env, al, "MISSING") is None
    env.set(o.VAULT, al + "-SIGNATURE", "AAAAtampered")   # corrupt the vault signature
    assert o.vault_get(env, al, "BAL") is None            # tamper -> reset -> field gone
    assert o.vault_get(env, al, "ATC") is None


def test_wallet():
    cert, sign = o.make_test_ca()
    env = o.Env(cert)
    al = o.alias("DEV123", "9000000000", "ACC789", "UPI")

    assert o.onboard(env, al, _state(sign, "5000.00", "1000.00", "A", 1000)) == "OK"

    bi = o.is_bound(env, al)
    assert bi["ltl"] == "1000.00" and bi["bal"] == "5000.00" and bi["acstatus"] == "A"
    assert not bi["sync_required"]
    assert o.balance(env, al)["balance"] == 5000.0
    assert o.balance(env, al)["pending_count"] == 0

    txn = {"amount": "100.00", "txn_id": "TXN1", "ts": "20260101120000", "payer_lite_acc": "5001234567",
           "payee_addr": "merchant@upi", "app_id": "com.phonepe.app", "mobile": "9000000000", "device_id": "DEV123"}
    st, res = o.spend(env, al, txn, False)
    assert st == "OK" and "signature" in res and "riskParams" in res
    assert o.balance(env, al)["balance"] == 4900.0
    assert o.balance(env, al)["pending_count"] == 1

    txn2 = {**txn, "amount": "50.00", "txn_id": "TXN2"}
    assert o.spend(env, al, txn2, False)[0] == "SYNC_REQUIRED"

    assert o.sync(env, al, _state(sign, "4900.00", "1000.00", "A", 2000)) == "OK"
    assert not o.is_bound(env, al)["sync_required"]
    assert o.spend(env, al, txn2, False)[0] == "OK"

    assert o.sync(env, al, _state(sign, "4850.00", "1000.00", "A", 2000)) == "STALE"
    assert o.sync(env, al, _state(sign, "4850.00", "1000.00", "A", 3000)) == "OK"

    over = {**txn, "amount": "2000.00", "txn_id": "TXN3"}
    assert o.spend(env, al, over, False)[0] == "DECLINED"

    o.unbind(env, al)
    assert o.is_bound(env, al) is None


def test_sync_bad_sig():
    cert, sign = o.make_test_ca()
    env = o.Env(cert)
    al = o.alias("DEV123", "9000000000", "ACC789", "UPI")
    o.onboard(env, al, _state(sign, "5000.00", "1000.00", "A", 1000))
    good = _state(sign, "4000.00", "1000.00", "A", 2000)
    import json
    bad = json.dumps({**json.loads(good), "signature": "AAAA"})
    assert o.sync(env, al, bad) == "BAD_SIG"
    assert o.sync(env, al, _state(sign, "0.00", "0.00", "DA", 4000)) == "DEACTIVATED"
    assert o.is_bound(env, al) is None


if __name__ == "__main__":
    test_vault(); test_wallet(); test_sync_bad_sig()
    print("OK wallet")
