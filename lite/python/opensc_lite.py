"""Reference implementation of the NPCI UPI Lite deterministic primitives (stdlib only)."""

import base64
import hashlib


def _b64_nowrap(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64_default(b: bytes) -> str:
    # android.util.Base64 DEFAULT: wrap every 76 chars with '\n' and append a trailing '\n'.
    s = base64.b64encode(b).decode("ascii")
    return "".join(s[i:i + 76] + "\n" for i in range(0, len(s), 76)) or "\n"


def alias(device_id: str, mobile: str, account_ref: str, service: str) -> str:
    return _b64_nowrap(hashlib.sha256((device_id + mobile + account_ref + service).encode()).digest())


def sha256_b64(s: str) -> str:
    return _b64_nowrap(hashlib.sha256(s.encode()).digest())


def sha1_id35(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest()[:35]


def debit_payload(amount, txn_id, ts, payer_lite_acc, payee_addr, app_id, mobile, device_id, risk_params) -> str:
    return "|".join(["1.0", amount, txn_id, ts, payer_lite_acc, payee_addr, app_id, mobile, device_id, risk_params])


def vault_sig_message(ct_b64: str, iv_b64: str) -> str:
    msg = base64.b64decode(iv_b64) + ct_b64.encode()
    return _b64_default(hashlib.sha256(msg).digest())


def pac_applies(code: int, is_debit: int) -> int:
    i = (code >> 6) & 3
    return int(i == 3 or (i == 1 and is_debit) or (i == 2 and not is_debit))


def pvr_set(index: int, bit: int) -> str:
    b = bytearray(8)
    b[index - 1] |= 1 << (bit - 1)
    return b.hex()


def litex_txn_id(payer_id, payer_seq, ac1, payee_id, payee_seq, ac2) -> str:
    return sha1_id35(".".join([payer_id, payer_seq, ac1, payee_id, payee_seq, ac2]))
