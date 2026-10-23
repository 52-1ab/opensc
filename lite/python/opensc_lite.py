"""Reference implementation of NPCI's UPI Lite / Lite X wallet (Python + pyca/cryptography).

Mirrors the C library in lite/: the deterministic primitives are byte-for-byte (checked by the
same vectors), and the vault/sync/spend/Lite X logic matches the Common Library's behaviour.
"""

import base64
import json
import os
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509 import load_pem_x509_certificate

## Default ClientRiskRules written at onboarding (all counters zero).
CRR_DEFAULT = '{"ATC":"0","OSN":"0","PISC":"0","PC1V":"0","PC2V":"0","PC3V":"0","PC4V":"0"}'
_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA512()), salt_length=padding.PSS.DIGEST_LENGTH)


# --- deterministic primitives (byte-for-byte with the C lib; covered by vectors.json) ----------

def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64_default(b: bytes) -> str:
    s = base64.b64encode(b).decode("ascii")
    return "".join(s[i:i + 76] + "\n" for i in range(0, len(s), 76)) or "\n"


def alias(device_id, mobile, account_ref, service):
    """Lite alias: base64(SHA256(deviceId + mobile + accountRef + service))."""
    return _b64(_sha256((device_id + mobile + account_ref + service).encode()))


def sha256_b64(s):
    """SHA-256 of the UTF-8 string, base64 (no wrap)."""
    return _b64(_sha256(s.encode()))


def sha1_id35(s):
    """First 35 hex chars of SHA-1(s) -- the Lite X txnId truncation."""
    return _hash(hashes.SHA1(), s.encode()).hex()[:35]


def debit_payload(amount, txn_id, ts, payer_lite_acc, payee_addr, app_id, mobile, device_id, risk_params):
    """Pipe-joined spend payload that gets signed; field order matches the CL."""
    return "|".join(["1.0", amount, txn_id, ts, payer_lite_acc, payee_addr, app_id, mobile, device_id, risk_params])


def vault_sig_message(ct_b64, iv_b64):
    """Message signed over a vault record: base64(SHA256(iv || ciphertext)), 76-col wrapped."""
    return _b64_default(_sha256(base64.b64decode(iv_b64) + ct_b64.encode()))


def pac_applies(code, is_debit):
    """Purse-action-code predicate: the top two bits select debit/credit applicability."""
    i = (code >> 6) & 3
    return int(i == 3 or (i == 1 and is_debit) or (i == 2 and not is_debit))


def pvr_set(index, bit):
    """Returns the 16-hex PVR with bit `bit` of byte `index` (both 1-based) set."""
    b = bytearray(8)
    b[index - 1] |= 1 << (bit - 1)
    return b.hex()


def litex_txn_id(payer_id, payer_seq, ac1, payee_id, payee_seq, ac2):
    """Lite X txnId = hex(SHA1(payerId.payerSeq.ac1.payeeId.payeeSeq.ac2))[:35]."""
    return sha1_id35(".".join([payer_id, payer_seq, ac1, payee_id, payee_seq, ac2]))


def _hash(algo, data):
    h = hashes.Hash(algo)
    h.update(data)
    return h.finalize()


def _sha256(data):
    return _hash(hashes.SHA256(), data)


def _spki(pub):
    return pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


# --- pluggable environment: in-memory store + software keystore + crypto ------------------------

class Keystore:
    """Software stand-in for AndroidKeyStore. Keys are test keys, valid only for this harness."""

    def __init__(self):
        self._k = {}

    def contains(self, a):
        """True if a key is stored under alias `a`."""
        return a in self._k

    def delete(self, a):
        """Deletes the key under alias `a` if present."""
        self._k.pop(a, None)

    def gen_rsa(self, a):
        """Generates an RSA-2048 key under alias `a`; returns its DER SPKI."""
        self._k[a] = ("rsa", rsa.generate_private_key(65537, 2048))
        return _spki(self._k[a][1].public_key())

    def gen_ec(self, a):
        """Generates a P-256 EC key under alias `a`; returns its DER SPKI."""
        self._k[a] = ("ec", ec.generate_private_key(ec.SECP256R1()))
        return _spki(self._k[a][1].public_key())

    def gen_aes(self, a):
        """Generates a 256-bit AES key under alias `a`."""
        self._k[a] = ("aes", os.urandom(32))

    def sign(self, a, msg):
        """Signs `msg` with alias `a`: RSA-PSS-SHA512 or ECDSA-SHA256 by key type."""
        kind, key = self._k[a]
        if kind == "rsa":
            return key.sign(msg, _PSS, hashes.SHA512())
        return key.sign(msg, ec.ECDSA(hashes.SHA256()))

    def pubkey(self, a):
        """Returns the public key of alias `a` as DER SPKI."""
        return _spki(self._k[a][1].public_key())

    def aes_encrypt(self, a, iv, pt):
        """AES-GCM encrypt `pt` under alias `a` with the given `iv`."""
        return AESGCM(self._k[a][1]).encrypt(iv, pt, None)

    def aes_decrypt(self, a, iv, blob):
        """AES-GCM decrypt `blob` under alias `a` with the given `iv`."""
        return AESGCM(self._k[a][1]).decrypt(iv, blob, None)


class Env:
    """Runtime environment: in-memory store, software keystore, signer cert, RNG and clock."""

    def __init__(self, signer_cert_pem=None):
        ## Namespaced key/value store (file -> key -> value).
        self.store = {}
        ## Software keystore backing the alias keys.
        self.keystore = Keystore()
        ## NPCI signer certificate (PEM) used to verify riskRules.
        self.signer_cert_pem = signer_cert_pem
        ## Random-byte source (length -> bytes).
        self.rng = os.urandom
        ## Current time in milliseconds.
        self.now_millis = lambda: int(time.time() * 1000)

    def get(self, file, key):
        """Reads a value from the namespaced store, or None."""
        return self.store.get(file, {}).get(key)

    def set(self, file, key, val):
        """Writes a value into the namespaced store."""
        self.store.setdefault(file, {})[key] = val

    def remove(self, file, key):
        """Removes a value from the namespaced store."""
        self.store.get(file, {}).pop(key, None)


def _verify(spki_der, msg, sig, ecdsa=False):
    pub = serialization.load_der_public_key(spki_der)
    try:
        pub.verify(sig, msg, ec.ECDSA(hashes.SHA256())) if ecdsa else pub.verify(sig, msg, _PSS, hashes.SHA512())
        return True
    except InvalidSignature:
        return False


# --- vault codec (mirrors vault.c) --------------------------------------------------------------

## Vault record name in the store.
VAULT = "NPCICLVAULT"
## Internal vault-read status: no record present.
ABSENT = "ABSENT"
## Internal vault-read status: signature invalid (the record was reset).
TAMPER = "TAMPER"


def _encrypt_doc(env, al, pt):
    iv = env.rng(12)
    blob = env.keystore.aes_encrypt(al + "-NPCI-Vault", iv, pt.encode())
    return _b64(blob), _b64(iv)


def _decrypt_doc(env, al, ct_b64, iv_b64):
    return env.keystore.aes_decrypt(al + "-NPCI-Vault", base64.b64decode(iv_b64), base64.b64decode(ct_b64)).decode()


def _sign_record(env, al, ct_b64, iv_b64, regenerate):
    if regenerate:
        env.keystore.gen_rsa(al + "-SIGNATURE")
    return _b64(env.keystore.sign(al + "-SIGNATURE", vault_sig_message(ct_b64, iv_b64).encode()))


def _verify_record(env, al, ct_b64, iv_b64, sig_b64):
    return _verify(env.keystore.pubkey(al + "-SIGNATURE"),
                   vault_sig_message(ct_b64, iv_b64).encode(), base64.b64decode(sig_b64))


def _write_doc(env, al, pt, regenerate):
    ct, iv = _encrypt_doc(env, al, pt)
    env.set(VAULT, al, ct)
    env.set(VAULT, al + "IV", iv)
    env.set(VAULT, al + "-SIGNATURE", _sign_record(env, al, ct, iv, regenerate))


def vault_reset(env, al):
    """Replaces the vault with an encrypted "{}" under freshly generated keys."""
    env.keystore.gen_aes(al + "-NPCI-Vault")
    _write_doc(env, al, "{}", True)


def _read_doc(env, al):
    ct, iv, sig = env.get(VAULT, al), env.get(VAULT, al + "IV"), env.get(VAULT, al + "-SIGNATURE")
    if ct is None or iv is None or sig is None:
        return ABSENT, None
    if not _verify_record(env, al, ct, iv, sig):
        vault_reset(env, al)
        return TAMPER, None
    return "OK", _decrypt_doc(env, al, ct, iv)


def vault_open(env, al):
    """Ensures a valid vault record exists, creating an empty one if absent."""
    status, _ = _read_doc(env, al)
    if status == ABSENT:
        vault_reset(env, al)


def vault_get(env, al, key):
    """Reads one top-level field; None if absent or tampered (tamper also resets the vault)."""
    status, doc = _read_doc(env, al)
    if status != "OK":
        return None
    return json.loads(doc).get(key)


def vault_set(env, al, key, val):
    """Read-modify-write of one field, re-encrypting and re-signing the record."""
    status, doc = _read_doc(env, al)
    obj = json.loads(doc) if status == "OK" else {}
    obj[key] = val
    _write_doc(env, al, json.dumps(obj, separators=(",", ":")), False)


# --- riskRules (mirrors riskrules.c) ------------------------------------------------------------

def riskrules_verify(env, srp):
    """Verifies ServerRiskParams: RSA-PSS-SHA512 over the riskRules text vs the signer cert."""
    o = json.loads(srp)
    spki = load_pem_x509_certificate(env.signer_cert_pem).public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return _verify(spki, o["riskRules"].encode(), base64.b64decode(o["signature"]))


def riskrules_decode(srp):
    """Decodes the base64 "riskRules" field to its JSON text."""
    return base64.b64decode(json.loads(srp)["riskRules"]).decode()


# --- wallet (mirrors wallet.c) ------------------------------------------------------------------

## UPI service tag folded into the alias hash.
SERVICE = "UPI"
## Vault key holding the base64 AES session key.
SESSION_KEY = "AESUPI"


def is_bound(env, al):
    """Binding status (LTL/BAL/ACSTATUS + sync_required), or None if not bound."""
    if not env.keystore.contains(al):
        return None
    srp = vault_get(env, al, "ServerRiskParams")
    if not isinstance(srp, str) or not riskrules_verify(env, srp):
        return None
    r = json.loads(riskrules_decode(srp))
    pend = vault_get(env, al, "PendingTxn")
    return {"ltl": r.get("LTL", ""), "bal": r.get("BAL", ""), "acstatus": r.get("ACSTATUS", ""),
            "sync_required": bool(pend) and pend not in ("", "[]")}


def _sum_pending(pend, credit):
    if not pend:
        return 0.0, 0
    arr = json.loads(pend)
    total = sum(float(e["txnAmount"]) for e in arr if (e.get("isCredit") == "true") == credit)
    return total, len(arr)


def balance(env, al):
    """Spendable / non-spendable balance and pending count, or None if unverifiable."""
    srp = vault_get(env, al, "ServerRiskParams")
    if not isinstance(srp, str) or not riskrules_verify(env, srp):
        return None
    bal = float(json.loads(riskrules_decode(srp)).get("BAL", "0"))
    pend = vault_get(env, al, "PendingTxn")
    debits, n = _sum_pending(pend if isinstance(pend, str) else "", False)
    credits, _ = _sum_pending(pend if isinstance(pend, str) else "", True)
    return {"balance": max(bal - debits, 0.0), "non_spendable": credits, "pending_count": n}


def sync(env, al, signed_state):
    """Applies a signed state: verify, require a newer timestamp, replace state, clear PendingTxn."""
    if not riskrules_verify(env, signed_state):
        return "BAD_SIG"
    r = json.loads(riskrules_decode(signed_state))
    if r.get("ACSTATUS") == "DA":
        unbind(env, al)
        return "DEACTIVATED"
    if not isinstance(vault_get(env, al, "ClientRiskRules"), str):
        vault_set(env, al, "ClientRiskRules", CRR_DEFAULT)
    existing = vault_get(env, al, "ServerRiskParams")
    accept = True
    if isinstance(existing, str) and riskrules_verify(env, existing):
        old = int(json.loads(riskrules_decode(existing)).get("timestamp", "0"))
        accept = int(r.get("timestamp", "0")) > old
    if not accept:
        return "STALE"
    vault_set(env, al, "ServerRiskParams", signed_state)
    vault_set(env, al, "PendingTxn", "")
    return "OK"


def _risk_params(env, al, srp):
    crr = vault_get(env, al, "ClientRiskRules")
    key = base64.b64decode(vault_get(env, al, SESSION_KEY))
    obj = json.loads(srp)
    obj["clientRiskRules"] = _b64(crr.encode())
    pt = json.dumps(obj, separators=(",", ":")).encode()
    iv = env.rng(16)
    blob = AESGCM(key).encrypt(iv, pt, None)
    return _b64(blob) + "|" + _b64(iv)


def spend(env, al, txn, is_credit):
    """Signs a spend, enforcing the PendingTxn gate and limit/balance/ACSTATUS checks."""
    pend = vault_get(env, al, "PendingTxn")
    if isinstance(pend, str) and pend and pend != "[]":
        return "SYNC_REQUIRED", None
    srp = vault_get(env, al, "ServerRiskParams")
    if not isinstance(srp, str) or not riskrules_verify(env, srp):
        return "DECLINED", None
    r = json.loads(riskrules_decode(srp))
    amt = float(txn["amount"])
    self_txn = txn["payer_lite_acc"] == txn["payee_addr"]
    ok = r.get("ACSTATUS") == "A"
    if not is_credit:
        ok = ok and amt <= float(r.get("BAL", "0")) and (self_txn or amt <= float(r.get("LTL", "0")))
    if not ok:
        return "DECLINED", None
    risk = _risk_params(env, al, srp)
    payload = debit_payload(txn["amount"], txn["txn_id"], txn["ts"], txn["payer_lite_acc"],
                            txn["payee_addr"], txn["app_id"], txn["mobile"], txn["device_id"], risk)
    sig = _b64(env.keystore.sign(al, _b64(payload.encode()).encode()))
    crr = json.loads(vault_get(env, al, "ClientRiskRules"))
    crr["ATC"] = str(int(crr["ATC"]) + 1)
    vault_set(env, al, "ClientRiskRules", json.dumps(crr, separators=(",", ":")))
    arr = json.loads(vault_get(env, al, "PendingTxn") or "[]")
    arr.append({"txnId": txn["txn_id"], "txnAmount": txn["amount"], "isCredit": "true" if is_credit else "false"})
    vault_set(env, al, "PendingTxn", json.dumps(arr, separators=(",", ":")))
    return "OK", {"riskParams": risk, "signature": sig}


def onboard(env, al, signed_state):
    """Establishes vault + keys + session key, then applies the first signed state."""
    vault_open(env, al)
    env.keystore.gen_rsa(al)
    vault_set(env, al, SESSION_KEY, _b64(env.rng(32)))
    vault_set(env, al, "ClientRiskRules", CRR_DEFAULT)
    return sync(env, al, signed_state)


def unbind(env, al):
    """Removes the binding: deletes the alias keys and clears the vault record."""
    for suf in ("", "-OFFLINE", "-SIGNATURE", "-NPCI-Vault"):
        env.keystore.delete(al + suf)
    for suf in ("", "IV", "-SIGNATURE"):
        env.remove(VAULT, al + suf)


# --- Lite X offline purse (mirrors litex.c) -----------------------------------------------------

## Offline-purse state: idle, no transfer in flight.
IDLE = 0
## Payer state: waiting for the payee's REQS.
AWAITING_REQ = 1
## Payee state: waiting for the payer's TRAS.
AWAITING_VAL = 2
## Payer state: waiting for the payee's ACKS.
AWAITING_ACK = 3


def litex_counter_update(code, cur, amount):
    """Counter step: bit5 of `code` selects +1 vs +amount; returns the new value."""
    i = (code >> 5) & 1
    cur = cur + 1.0 if i == 0 else cur
    return cur + amount if i == 1 else cur


class LitexPurse:
    """A purse party in the offline Lite X transfer handshake."""

    def __init__(self, env, al, bal):
        ## Runtime environment (store + keystore + crypto).
        self.env = env
        ## This purse's key alias.
        self.alias = al
        ## Spendable offline balance.
        self.balance = bal
        ## Current handshake state (one of IDLE / AWAITING_*).
        self.state = IDLE
        ## Counterparty offline public key (base64 SPKI), set during identity exchange.
        self.remote_pub = None
        ## Running signed transfer payload: base plus each appended signature.
        self.txndp = ""
        ## Derived transaction id for the in-flight transfer.
        self.txn_id = ""
        env.keystore.gen_ec(al + "-OFFLINE")

    def _sign(self, data):
        return _b64(self.env.keystore.sign(self.alias + "-OFFLINE", data.encode()))

    def _verify(self, data, sig_b64):
        return _verify(base64.b64decode(self.remote_pub), data.encode(), base64.b64decode(sig_b64), ecdsa=True)

    def offline_pubkey(self):
        """This purse's offline EC public key as base64 SPKI."""
        return _b64(self.env.keystore.pubkey(self.alias + "-OFFLINE"))

    def set_remote(self, pub_b64):
        """Sets the counterparty's offline public key (base64 SPKI)."""
        self.remote_pub = pub_b64

    @staticmethod
    def _payload(x):
        return "".join([x["payer_id"], x["payer_seq"], x["payer_vpa"], x["payee_id"], x["payee_seq"],
                        x["payee_vpa"], x["timestamp"], x["currency"], x["amount"]])

    def _txnid(self, x):
        return litex_txn_id(x["payer_id"], x["payer_seq"], x["payee_vpa"], x["payee_id"], x["payee_seq"], x["payer_vpa"])

    def get_purse_info(self, bal):
        """Bootstrap: record `bal`, arm the purse, return an 8-byte challenge (hex)."""
        self.balance, self.state = bal, IDLE
        return self.env.rng(8).hex()

    def assert_identity(self, ident, remote_challenge):
        """Signs this purse's identity + the remote challenge; returns the identity doc JSON."""
        cert = self.offline_pubkey()
        payload = "".join([ident["id"], ident["product"], ident["currency"], ident["country"],
                           ident["type"], ident.get("mcc") or "", cert, remote_challenge])
        doc = {"id": ident["id"], "product": ident["product"], "currency": ident["currency"],
               "country": ident["country"], "type": ident["type"]}
        if ident.get("mcc"):
            doc["mcc"] = ident["mcc"]
        doc["purseCertificate"] = cert
        doc["signature"] = self._sign(payload)
        return json.dumps(doc, separators=(",", ":"))

    def verify_identity(self, remote_json, our_challenge):
        """Verifies a remote identity doc vs `our_challenge`; adopts its key on success."""
        o = json.loads(remote_json)
        payload = "".join([o["id"], o["product"], o["currency"], o["country"], o["type"],
                           o.get("mcc", ""), o["purseCertificate"], our_challenge])
        self.remote_pub = o["purseCertificate"]
        return "OK" if self._verify(payload, o["signature"]) else "BAD_SIG"

    def start_debit(self, x):
        """Payer IDLE -> AWAITING_REQ; declines on insufficient balance."""
        if self.state != IDLE:
            return "ERR_STATE"
        if float(x["amount"]) > self.balance:
            return "DECLINED"
        self.txndp, self.txn_id, self.state = self._payload(x), self._txnid(x), AWAITING_REQ
        return "OK"

    def start_credit(self, x):
        """Payee IDLE -> AWAITING_VAL; signs REQS over the payload."""
        if self.state != IDLE:
            return "ERR_STATE", None
        self.txndp, self.txn_id = self._payload(x), self._txnid(x)
        reqs = self._sign(self.txndp)
        self.state = AWAITING_VAL
        return "OK", reqs

    def request_value(self, reqs):
        """Payer AWAITING_REQ -> AWAITING_ACK; verifies REQS, signs TRAS."""
        if self.state != AWAITING_REQ:
            return "ERR_STATE", None
        if not self._verify(self.txndp, reqs):
            return "BAD_SIG", None
        tras = self._sign(self.txndp + reqs)
        self.state = AWAITING_ACK
        return "OK", tras

    def transfer_value(self, reqs, tras):
        """Payee AWAITING_VAL -> IDLE; verifies TRAS, signs ACKS."""
        if self.state != AWAITING_VAL:
            return "ERR_STATE", None
        if not self._verify(self.txndp + reqs, tras):
            return "BAD_SIG", None
        acks = self._sign(self.txndp + reqs + tras)
        self.state = IDLE
        return "OK", acks

    def acknowledge_value(self, reqs, tras, acks):
        """Payer AWAITING_ACK -> IDLE; verifies ACKS."""
        if self.state != AWAITING_ACK:
            return "ERR_STATE"
        if not self._verify(self.txndp + reqs + tras, acks):
            return "BAD_SIG"
        self.state = IDLE
        return "OK"


# --- test-only NPCI CA (mirrors npci_test_ca.c) -------------------------------------------------

def make_test_ca():
    """Builds a throwaway RSA NPCI CA; returns (cert_pem, sign_state) for tests."""
    from datetime import datetime, timedelta, timezone
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(65537, 2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "upinpci-test")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + timedelta(hours=1))
            .sign(key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM)

    def sign_state(inner_json):
        inner_b64 = _b64(inner_json.encode())
        sig = key.sign(inner_b64.encode(), _PSS, hashes.SHA512())
        return json.dumps({"riskRules": inner_b64, "signature": _b64(sig)}, separators=(",", ":"))

    return pem, sign_state
