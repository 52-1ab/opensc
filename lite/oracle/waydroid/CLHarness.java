import java.lang.reflect.*;
import java.security.KeyStore;

// Runs the GENUINE NPCI CL sync (Oooo000.registerState) in a real Android runtime (waydroid),
// and prints accept/reject. The CL hard-gates its vault keygen on TEE (isInsideSecureHardware),
// which a software emulator lacks, so the two vault keys are pre-provisioned as software keys and
// the initial vault record is laid down with the CL's OWN encrypt+sign; all sync LOGIC is genuine.
public class CLHarness {
    static final String P = "org.npci.upi.security.pinactivitycomponent.";

    static void installKeystore() {
        for (String c : new String[]{"android.security.keystore2.AndroidKeyStoreProvider",
                                     "android.security.keystore.AndroidKeyStoreProvider"}) {
            try { Class.forName(c).getMethod("install").invoke(null); return; } catch (Throwable ignored) {}
        }
    }

    static Object context() throws Exception {
        Class.forName("android.os.Looper").getMethod("prepareMainLooper").invoke(null);
        Class<?> at = Class.forName("android.app.ActivityThread");
        Object inst = at.getMethod("systemMain").invoke(null);
        installKeystore();
        Object sys = at.getMethod("getSystemContext").invoke(inst);
        return Class.forName("android.content.Context")
                .getMethod("createPackageContext", String.class, int.class)
                .invoke(sys, "com.android.shell", 2);
    }

    // A plain software key under the given alias (no TEE requested); keystore allows this on the emulator.
    static void provisionKey(String alias, String algo, int purposes, String[] blockModes,
                             String[] paddings, String[] digests, String[] sigPad) throws Exception {
        Class<?> bC = Class.forName("android.security.keystore.KeyGenParameterSpec$Builder");
        Object b = bC.getConstructor(String.class, int.class).newInstance(alias, purposes);
        if (blockModes != null) bC.getMethod("setBlockModes", String[].class).invoke(b, (Object) blockModes);
        if (paddings != null) bC.getMethod("setEncryptionPaddings", String[].class).invoke(b, (Object) paddings);
        if (digests != null) bC.getMethod("setDigests", String[].class).invoke(b, (Object) digests);
        if (sigPad != null) bC.getMethod("setSignaturePaddings", String[].class).invoke(b, (Object) sigPad);
        if ("RSA".equals(algo)) bC.getMethod("setKeySize", int.class).invoke(b, 2048);
        Object spec = bC.getMethod("build").invoke(b);
        if ("AES".equals(algo)) {
            javax.crypto.KeyGenerator kg = javax.crypto.KeyGenerator.getInstance("AES", "AndroidKeyStore");
            kg.getClass().getMethod("init", java.security.spec.AlgorithmParameterSpec.class).invoke(kg, spec);
            kg.generateKey();
        } else {
            java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance(algo, "AndroidKeyStore");
            kpg.getClass().getMethod("initialize", java.security.spec.AlgorithmParameterSpec.class).invoke(kpg, spec);
            kpg.generateKeyPair();
        }
    }

    public static void main(String[] a) throws Exception {
        String mob = a[0], dev = a[1], acc = a[2], kB64 = a[3];
        String oldState = new String(java.util.Base64.getDecoder().decode(a[4]));
        String newState = new String(java.util.Base64.getDecoder().decode(a[5]));
        String label = a.length > 6 ? a[6] : "case";
        Object ctx = context();
        Class<?> ctxCls = Class.forName("android.content.Context");

        Class<?> cP = Class.forName(P + "o0OOO0o");
        Object oP = cP.getConstructor(ctxCls).newInstance(ctx);
        String alias = (String) cP.getMethod("OooO0O0", String.class).invoke(oP, dev + mob + acc + "UPI");

        // Substitute the TEE-backed keys the CL would make with software keys of the same shape.
        provisionKey(alias + "-NPCI-Vault", "AES", 3, new String[]{"GCM"}, new String[]{"NoPadding"}, null, null);
        provisionKey(alias + "-SIGNATURE", "RSA", 4, null, null, new String[]{"SHA-512"}, new String[]{"PSS"});

        // Lay down the initial "{}" vault record using the CL's OWN encrypt + sign (bool=false: no keygen).
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        java.security.Key aesKey = ks.getKey(alias + "-NPCI-Vault", null);
        String ctiv = (String) cP.getMethod("OooO00o", String.class, String.class, javax.crypto.SecretKey.class)
                .invoke(oP, "AES/GCM/NoPadding", "{}", aesKey);
        String ct = ctiv.split("\\|")[0], iv = ctiv.split("\\|")[1];
        String sig = (String) cP.getMethod("OooO00o", String.class, String.class, String.class,
                Boolean.class, ctxCls).invoke(oP, alias, ct, iv, Boolean.FALSE, ctx);
        Object sp = ctxCls.getMethod("getSharedPreferences", String.class, int.class).invoke(ctx, "NPCICLVAULT", 0);
        Object ed = sp.getClass().getMethod("edit").invoke(sp);
        Method put = ed.getClass().getMethod("putString", String.class, String.class);
        put.invoke(ed, alias, ct);
        put.invoke(ed, alias + "IV", iv);
        put.invoke(ed, alias + "-SIGNATURE", sig);
        ed.getClass().getMethod("commit").invoke(ed);

        // Seed session key + prior state through the GENUINE vault, then run the GENUINE sync.
        Class<?> cV = Class.forName(P + "o00O00O");
        Object vault = cV.getMethod("OooO00o", String.class, ctxCls, String.class, String.class)
                .invoke(null, alias, ctx, "UPI", acc);
        // bool=FALSE: sign with the existing (software) key, never regenerate (regen is TEE-gated).
        Method setIn = cV.getMethod("OooO00o", String.class, String.class, Boolean.class);
        setIn.invoke(vault, "AESUPI", kB64, Boolean.FALSE);
        setIn.invoke(vault, "ClientRiskRules",
                "{\"ATC\":\"0\",\"OSN\":\"0\",\"PISC\":\"0\",\"PC1V\":\"0\",\"PC2V\":\"0\",\"PC3V\":\"0\",\"PC4V\":\"0\"}",
                Boolean.FALSE);
        setIn.invoke(vault, "ServerRiskParams", oldState, Boolean.FALSE);

        String str4 = (String) cP.getMethod("OooO0Oo", String.class, String.class).invoke(oP, newState, kB64);

        Class<?> cO = Class.forName(P + "Oooo000");
        Object sync = cO.getConstructor(ctxCls, String.class).newInstance(ctx, "UPI");
        Object res = cO.getMethod("OooO00o", String.class, String.class, String.class, String.class)
                .invoke(sync, mob, dev, acc, str4);
        System.out.println("RESULT " + label + " " + res);
        System.out.flush();
        Runtime.getRuntime().halt(0);  // CL starts non-daemon threads; force exit after the result.
    }
}
