package org.npci.upi.security.pinactivitycomponent;

import java.security.PublicKey;

// Mirrors the real class name/package exactly -- RegisterNatives binds by this descriptor.
public final class OfflineNativeDefenderService {
    private OfflineNativeDefenderService() {
    }

    public static native void nEnableUPILITEX();

    public static native byte[] nOfflineSignWithKey(String data, String alias, boolean useEc);

    public static native boolean nOfflineVerifyEcSignature(String data, String sigB64, PublicKey key);

    public static native byte[] nTestUtf8(String data);

    public static native byte[] nTestGetPublicKeyDer(String alias, String algorithm);
}
