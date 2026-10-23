"""Mirrors the C test_litex.c + test_litex_flow.c against the Python Lite X reference."""

import opensc_lite as o


def test_primitives():
    assert o.pvr_set(8, 8) == "0000000000000080"
    assert o.pvr_set(8, 1) == "0000000000000001"
    assert o.pvr_set(7, 8) == "0000000000008000"
    assert o.pac_applies(0xC0, 1) == 1 and o.pac_applies(0xC0, 0) == 1
    assert o.pac_applies(0x40, 1) == 1 and o.pac_applies(0x40, 0) == 0
    assert o.pac_applies(0x80, 0) == 1 and o.pac_applies(0x80, 1) == 0
    assert o.pac_applies(0x00, 1) == 0
    assert o.litex_counter_update(0x00, 5.0, 10.0) == 6.0
    assert o.litex_counter_update(0x20, 5.0, 10.0) == 15.0
    assert o.litex_txn_id("P1", "1", "AC1", "P2", "2", "AC2") == "bbf4b2529b1d6e176f1525cb1cbd0935a49"


def _xfer():
    return {"payer_id": "P", "payer_seq": "1", "payer_vpa": "p@upi", "payee_id": "Q", "payee_seq": "1",
            "payee_vpa": "q@upi", "timestamp": "1767225600000", "currency": "INR", "amount": "50.00"}


def test_identity_and_transfer():
    env = o.Env()
    payer = o.LitexPurse(env, "PAYER", 500.0)
    payee = o.LitexPurse(env, "PAYEE", 100.0)

    ch_payer = payer.get_purse_info(500.0)
    ch_payee = payee.get_purse_info(100.0)
    id_p = {"id": "P", "product": "LITE", "currency": "INR", "country": "IN", "type": "PREPAID", "mcc": None}
    id_q = {"id": "Q", "product": "LITE", "currency": "INR", "country": "IN", "type": "PREPAID", "mcc": None}
    doc_p = payer.assert_identity(id_p, ch_payee)
    doc_q = payee.assert_identity(id_q, ch_payer)
    assert payer.verify_identity(doc_q, ch_payer) == "OK"
    assert payee.verify_identity(doc_p, ch_payee) == "OK"

    import json
    tampered = json.dumps({**json.loads(doc_q), "signature": "AAAA"})
    assert payer.verify_identity(tampered, ch_payer) == "BAD_SIG"

    payer.set_remote(payee.offline_pubkey())
    payee.set_remote(payer.offline_pubkey())

    x = _xfer()
    assert payer.start_debit(x) == "OK" and payer.state == o.AWAITING_REQ
    st, reqs = payee.start_credit(x)
    assert st == "OK" and payee.state == o.AWAITING_VAL
    assert payer.txn_id == payee.txn_id

    st, tras = payer.request_value(reqs)
    assert st == "OK" and payer.state == o.AWAITING_ACK
    st, acks = payee.transfer_value(reqs, tras)
    assert st == "OK" and payee.state == o.IDLE
    assert payer.acknowledge_value(reqs, tras, acks) == "OK" and payer.state == o.IDLE


def test_decline_tamper_order():
    env = o.Env()
    poor = o.LitexPurse(env, "POOR", 10.0)
    assert poor.start_debit(_xfer()) == "DECLINED"

    payer = o.LitexPurse(env, "P2", 500.0)
    payee = o.LitexPurse(env, "Q2", 100.0)
    payer.set_remote(payee.offline_pubkey())
    payer.start_debit(_xfer())
    _, reqs = payee.start_credit(_xfer())
    bad = ("B" if reqs[0] == "A" else "A") + reqs[1:]
    assert payer.request_value(bad)[0] == "BAD_SIG"

    idle = o.LitexPurse(env, "IDLE", 10.0)
    assert idle.request_value("x")[0] == "ERR_STATE"


if __name__ == "__main__":
    test_primitives(); test_identity_and_transfer(); test_decline_tamper_order()
    print("OK litex")
