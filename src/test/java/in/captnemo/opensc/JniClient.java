package in.captnemo.opensc;

import org.npci.upi.security.pinactivitycomponent.OfflineNativeDefenderService;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

// In-process backend: the .so is already loaded into this JVM via System.load,
// so this just forwards to the static natives directly. No coprocess needed --
// it's already as direct as JNI gets, and going through the pipe protocol would
// only add overhead for no benefit.
//
// data is always the UTF-8 bytes of a logical string (see secure_component.c's
// protocol doc), so decoding back to a String here is lossless -- the wire
// protocol's byte contract and the real nOfflineSignWithKey(String, ...)
// contract agree by construction.
class JniClient implements ScClient {

    @Override
    public String name() {
        return "c-jni";
    }

    @Override
    public byte[] sign(String alias, byte[] data, boolean useEc) {
        return OfflineNativeDefenderService.nOfflineSignWithKey(
                new String(data, StandardCharsets.UTF_8), alias, useEc);
    }

    @Override
    public boolean verify(byte[] pubkeyDer, byte[] data, byte[] sig) throws Exception {
        PublicKey pub = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(pubkeyDer));
        String sigB64 = Base64.getEncoder().encodeToString(sig);
        return OfflineNativeDefenderService.nOfflineVerifyEcSignature(
                new String(data, StandardCharsets.UTF_8), sigB64, pub);
    }

    @Override
    public byte[] pubkey(String alias, String algorithm) {
        return OfflineNativeDefenderService.nTestGetPublicKeyDer(alias, algorithm);
    }
}
