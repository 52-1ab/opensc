# Using opensc

opensc has three parts:

- `lite/` — the UPI Lite and Lite X wallet, in C.
- `python/` — the same wallet and the signing engine, in Python.
- `secure_component.c` — the native signing engine, in C.

Use the C library in an app. Use the Python code as a reference and for tests.

## Set up the environment (C)

The wallet runs against an environment that you supply. Build one, then pass its
address to every wallet call.

```c
lite_env env = {0};
env.crypto = lite_crypto_openssl();
env.keystore = lite_keystore_mem_new();
env.store = lite_store_mem_new();
env.clock = lite_clock_fixed_new(1767225600000LL);
env.rng = lite_rng_seeded_new(7);
env.signer_upi_cert = cert;          // signer-upi.crt bytes
env.signer_upi_cert_len = cert_len;
```

## Online UPI Lite (C)

Call the functions in this order:

1. Build the alias with `lite_alias()`.
2. Onboard with the first signed state with `lite_onboard()`.
3. Read the binding with `lite_is_bound()`.
4. Read the balance with `lite_balance()`.
5. Sign a payment with `lite_spend()`.
6. Apply a new signed state with `lite_sync()`.
7. Remove the device with `lite_unbind()`.

```c
char alias[256];
lite_alias(env.crypto, "DEV123", "9000000000", "ACC789", "UPI", alias, sizeof alias);

lite_onboard(&env, alias, signed_state);        // returns LITE_SYNC_OK

lite_bind_info bi;
lite_is_bound(&env, alias, &bi);                // LITE_BIND_YES

lite_balance_info bal;
lite_balance(&env, alias, &bal);                // bal.balance, bal.pending_count

lite_txn txn = {"100.00", "TXN1", "20260101120000", "5001234567",
                "merchant@upi", "com.phonepe.app", "9000000000", "DEV123"};
char out[8192];
lite_spend(&env, alias, &txn, 0, out, sizeof out);   // 0 = debit, 1 = credit

lite_sync(&env, alias, next_signed_state);
lite_unbind(&env, alias);
```

Call `lite_sync()` after each payment. Until you do, `lite_spend()` returns
`LITE_SPEND_SYNC_REQUIRED`.

## Offline UPI Lite X (C)

A transfer runs between two devices: the payer (sends money) and the payee (receives
money). Each device runs its own purse. Because the devices are offline, your app
carries these messages between them over any channel (QR code, NFC, Bluetooth):

- the challenge from `litex_get_purse_info()`
- the identity document from `litex_assert_identity()`
- the transfer messages REQS, TRAS, and ACKS

Both devices run the setup and identity steps. Values named `their_*` arrive from the
other device.

Setup and identity (each device):

1. Start your purse with `litex_purse_start()`.
2. Make your challenge with `litex_get_purse_info()`. Send it to the other device.
3. Sign your identity with `litex_assert_identity()`, using the challenge you received.
   Send the result.
4. Verify the identity you received with `litex_verify_identity()`.

```c
litex_purse me;
litex_purse_start(&me, &env, "PAYER", 500.0);

char my_challenge[32];
litex_get_purse_info(&me, 500.0, my_challenge, sizeof my_challenge);   // send to the other device

litex_identity my_id = {"P", "LITE", "INR", "IN", "PREPAID", NULL};
char my_doc[1024];
litex_assert_identity(&me, &my_id, their_challenge, my_doc, sizeof my_doc);   // send my_doc
litex_verify_identity(&me, their_doc, my_challenge);
```

Then run the transfer. Both devices use the same agreed transfer `x` (amount,
parties, timestamp). Each device sends the message it produces to the other.

The payer runs:

5. Call `litex_start_debit(x)`.
6. Call `litex_request_value(their_reqs)`. Send the TRAS it returns.
7. Call `litex_acknowledge_value(their_reqs, tras, their_acks)`.

The payee runs:

5. Call `litex_start_credit(x)`. Send the REQS it returns.
6. Call `litex_transfer_value(my_reqs, their_tras)`. Send the ACKS it returns.

```c
// This device is the payer. their_reqs and their_acks arrive from the payee.
litex_xfer x = {"P","1","p@upi","Q","1","q@upi","1767225600000","INR","50.00"};
char tras[512];
litex_start_debit(&me, &x);
litex_request_value(&me, their_reqs, tras, sizeof tras);   // send tras to the payee
litex_acknowledge_value(&me, their_reqs, tras, their_acks);
```

## Online UPI Lite (Python)

The Python API mirrors the C API.

```python
import opensc_lite as o
pem, sign_state = o.make_test_ca()
env = o.Env(signer_cert_pem=pem)
al = o.alias("DEV123", "9000000000", "ACC789", "UPI")

o.onboard(env, al, sign_state('{"BAL":"5000.00","LTL":"1000.00","ACSTATUS":"A","timestamp":"1000"}'))
o.is_bound(env, al)
o.balance(env, al)
txn = {"amount": "100.00", "txn_id": "TXN1", "ts": "20260101120000",
       "payer_lite_acc": "5001234567", "payee_addr": "merchant@upi",
       "app_id": "com.phonepe.app", "mobile": "9000000000", "device_id": "DEV123"}
o.spend(env, al, txn, False)         # False = debit, True = credit
o.sync(env, al, sign_state('{"BAL":"4900.00","LTL":"1000.00","ACSTATUS":"A","timestamp":"2000"}'))
o.unbind(env, al)
```

## Signing engine (Python)

The signing engine signs and verifies data with per-alias device keys that stay in
the keystore. Use it to:

- sign an offline transaction payload with a device key, named by alias
- verify a signature you received from another device
- export a device's public key so another party can verify its signatures

Call the methods in this order:

1. Create a `SecureComponent`.
2. Sign a payload with `sign(data, alias, use_ec)`. It returns the signature bytes.
3. Export the public key with `public_key_der(alias, "EC")`. Send it to the verifier.
4. Verify a received signature with `verify(data, signature_base64, public_key_der)`.

```python
import base64
from secure_component import SecureComponent

sc = SecureComponent()

# Sign a payload with the device's offline key.
sig = sc.sign("5241234567890123|100.00|20260803", "NPCI_UPI_LITE_X", use_ec=True)

# Share this public key with the other party.
pub = sc.public_key_der("NPCI_UPI_LITE_X", "EC")

# Anyone holding the public key can verify the signature.
sc.verify("5241234567890123|100.00|20260803", base64.b64encode(sig).decode(), pub)  # True
```

Pass `use_ec=True` to sign with ECDSA-SHA256, or `use_ec=False` for RSA-PSS-SHA512.
`sign()` creates the alias key the first time you use it. `verify()` checks
ECDSA-SHA256 signatures only.

### Sign a PIN credential block (OTP or Debit Card)

Setting or changing a UPI PIN produces a credential block that the device signs with
its EC key. The verification method decides which credentials the block carries:

- OTP: an OTP (`type OTP`, `subtype SMS`) and the new PIN (`type PIN`, `subtype NMPIN`).
- Debit Card: the ATM PIN (`type PIN`, `subtype ATMPIN`) and an OTP, plus the new PIN
  (`subtype NMPIN`).

The signing step is identical for both; only the captured credentials differ. Sign the
block with the EC key, then attach the signature and the public key:

1. Build the credential block for the chosen method.
2. Sign it with `sign(block, alias, use_ec=True)`.
3. Put the base64 signature in `signatureValue` and `public_key_der(alias, "EC")` in `keyValue`.

```python
import base64, json, time
from secure_component import SecureComponent

sc = SecureComponent()
ALIAS = "NPCI_CL"

def sign_credential(cred_type, cred_blocks):
    block = json.dumps({"version": "1.0", "credType": cred_type,
                        "credBlocks": cred_blocks}, separators=(",", ":"))
    sig = sc.sign(block, ALIAS, use_ec=True)             # SHA256withECDSA
    pub = sc.public_key_der(ALIAS, "EC")                 # ECwithSPEC256r1
    return {
        "version": "1.0",
        "credType": cred_type,
        "credBlocks": cred_blocks,
        "trust": {
            "owner": "DEVICE-OS",
            "keyType": "ECwithSPEC256r1",
            "keyValue": base64.b64encode(pub).decode(),
            "signatureType": "SHA256withECDSA",
            "signatureValue": base64.b64encode(sig).decode(),
            "timestamp": str(int(time.time() * 1000)),
        },
    }

# OTP flow: an OTP plus the new PIN.
otp_doc = sign_credential("OTP|NMPIN", [
    {"type": "OTP", "subtype": "SMS"},
    {"type": "PIN", "subtype": "NMPIN"},
])

# Debit Card flow: the ATM PIN and an OTP, plus the new PIN.
card_doc = sign_credential("ATMPIN|OTP|NMPIN", [
    {"type": "PIN", "subtype": "ATMPIN"},
    {"type": "OTP", "subtype": "SMS"},
    {"type": "PIN", "subtype": "NMPIN"},
])
```

The captured values go inside `credBlocks` as an encrypted PID block with an HMAC.
Building that block is a separate step; the signing engine produces only the
`signatureValue` and the `keyValue`.
