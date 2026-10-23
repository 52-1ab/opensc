"""Pure-Python mirror of secure_component.c's crypto core (NPCI's native signing engine).

Reproduces the alias keystore and the nOfflineSignWithKey / nOfflineVerifyEcSignature
signing behaviour of libSecureComponent.so, without the JNI or stdio interfaces (the
nEnableUPILITEX JNI registration step has no meaning outside JNI). The signing
algorithms and the android-NO_WRAP base64 decode match the C byte-for-byte.
"""

import base64
import threading

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA512()), salt_length=padding.PSS.DIGEST_LENGTH)
_B64_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")


def _b64_decode(s):
    # android.util.Base64 NO_WRAP: standard alphabet, padding optional, junk skipped (as in C).
    cleaned = "".join(c for c in s.split("=")[0] if c in _B64_ALPHABET)
    full = len(cleaned) // 4 * 4
    out = base64.b64decode(cleaned[:full]) if full else b""
    rem = len(cleaned) - full
    if rem == 3:
        out += base64.b64decode(cleaned[full:] + "=")
    elif rem == 2:
        out += base64.b64decode(cleaned[full:] + "==")
    return out


class SecureComponent:
    """The native signing engine: a per-alias RSA+EC keystore with sign and verify."""

    def __init__(self):
        self._store = {}
        self._lock = threading.Lock()

    def _get_or_create(self, alias):
        with self._lock:
            keys = self._store.get(alias)
            if keys is None:
                keys = (rsa.generate_private_key(65537, 2048), ec.generate_private_key(ec.SECP256R1()))
                self._store[alias] = keys
            return keys

    def sign(self, data, alias, use_ec):
        """nOfflineSignWithKey: sign `data` under `alias`, returning the raw signature bytes.

        RSA-PSS-SHA512 by default, ECDSA-SHA256 (DER) when `use_ec`. `data` is a str (encoded
        UTF-8, as the JNI layer converts the Java String) or bytes. Lazily creates the alias keys.
        """
        rsa_key, ec_key = self._get_or_create(alias)
        msg = data.encode() if isinstance(data, str) else data
        if use_ec:
            return ec_key.sign(msg, ec.ECDSA(hashes.SHA256()))
        return rsa_key.sign(msg, _PSS, hashes.SHA512())

    def verify(self, data, sig_b64, pub_der):
        """nOfflineVerifyEcSignature: verify an ECDSA-SHA256 signature of `data`; returns bool.

        `sig_b64` is the base64 signature (android NO_WRAP); `pub_der` is the public key as
        DER SubjectPublicKeyInfo, i.e. what java.security.PublicKey.getEncoded() returns.
        """
        msg = data.encode() if isinstance(data, str) else data
        sig = _b64_decode(sig_b64)
        try:
            pub = serialization.load_der_public_key(pub_der)
        except ValueError:
            return False
        try:
            pub.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False

    def public_key_der(self, alias, algo):
        """The alias's public key as DER SubjectPublicKeyInfo; `algo` is "EC", else RSA."""
        rsa_key, ec_key = self._get_or_create(alias)
        key = ec_key if algo == "EC" else rsa_key
        return key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
