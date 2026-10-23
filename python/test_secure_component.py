"""Mirrors the secure_component.c self-test (SC_TEST_MAIN) against the Python engine."""

import base64

from secure_component import SecureComponent, _b64_decode

# Same vectors as the C self-test's main().
MSG = "5241234567890123|100.00|20260803"
TAMPERED = "tampered-payload"
B64_KNOWN = "aGVsbG8sIHdvcmxkIQ=="
ALIAS = "NPCI_UPI_LITE_X"


def test_sign_verify_roundtrip():
    sc = SecureComponent()
    pss = sc.sign(MSG, ALIAS, False)
    assert len(pss) == 256  # RSA-2048 PSS signature

    ec_sig = sc.sign(MSG, ALIAS, True)
    pub = sc.public_key_der(ALIAS, "EC")

    genuine = sc.verify(MSG, base64.b64encode(ec_sig).decode(), pub)
    tampered = sc.verify(TAMPERED, base64.b64encode(ec_sig).decode(), pub)
    cross = sc.verify(MSG, base64.b64encode(pss).decode(), pub)
    assert genuine and not tampered and not cross


def test_base64_nowrap():
    assert _b64_decode(B64_KNOWN) == b"hello, world!"
    # Padding is optional (android NO_WRAP), as in the C decoder.
    assert _b64_decode(B64_KNOWN.rstrip("=")) == b"hello, world!"


if __name__ == "__main__":
    test_sign_verify_roundtrip(); test_base64_nowrap()
    print("OK secure_component")
