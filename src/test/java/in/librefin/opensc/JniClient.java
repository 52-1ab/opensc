package in.librefin.opensc;

import org.npci.upi.security.pinactivitycomponent.OfflineNativeDefenderService;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

// In-process backend: the .so is already System.loaded, so this just forwards to the static natives.
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
