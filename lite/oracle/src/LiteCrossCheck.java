import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import javax.crypto.spec.SecretKeySpec;

// Bidirectional cross-check against the genuine CL: it verifies a C signature, decrypts a
// C-encrypted vault blob, and encrypts a blob (written out) for the C side to decrypt.
public final class LiteCrossCheck {
    static final String PKG = "org.npci.upi.security.pinactivitycomponent.";

    public static void main(String[] args) throws Exception {
        // BouncyCastle supplies the Android/Conscrypt "SHA512withRSA/PSS" alias the JDK lacks.
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        String in = args[0], out = args[1];
        @SuppressWarnings("unchecked")
        Map<String, Object> v = (Map<String, Object>) Json.parse(
                Files.readString(Path.of(in), StandardCharsets.UTF_8));

        Class<?> crypto = Class.forName(PKG + "o0OOO0o");
        Object inst = crypto.getDeclaredConstructor(Class.forName("android.content.Context"))
                .newInstance(new Object[]{null});

        var mVerify = crypto.getMethod("OooO00o", String.class, String.class, PublicKey.class);
        var mDec = crypto.getMethod("OooO00o", String.class, String.class,
                javax.crypto.SecretKey.class, String.class);
        var mEnc = crypto.getMethod("OooO0Oo", String.class, String.class);

        int fail = 0;

        byte[] spki = Base64.getDecoder().decode((String) v.get("sig_pubkey"));
        PublicKey pk = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(spki));
        boolean ok = (Boolean) mVerify.invoke(inst, (String) v.get("sig_msg"), (String) v.get("sig"), pk);
        boolean bad = (Boolean) mVerify.invoke(inst, v.get("sig_msg") + "x", (String) v.get("sig"), pk);
        System.out.println("CL verifies C signature: " + ok + " (tampered rejected: " + !bad + ")");
        if (!ok || bad) fail++;

        SecretKeySpec key = new SecretKeySpec(Base64.getDecoder().decode((String) v.get("aes_key")), "AES");
        String dec = (String) mDec.invoke(inst, "AES/GCM/NoPadding", (String) v.get("aes_ct"), key,
                (String) v.get("aes_iv"));
        boolean decOk = v.get("aes_plain").equals(dec);
        System.out.println("CL decrypts C vault blob: " + decOk);
        if (!decOk) fail++;

        String plain = "{\"BAL\":\"1234.56\",\"OSN\":\"3\"}";
        String keyB64 = (String) v.get("aes_key");
        String blob = (String) mEnc.invoke(inst, plain, keyB64);
        StringBuilder sb = new StringBuilder("{");
        sb.append("\"aes_key\":\"").append(keyB64).append("\",");
        sb.append("\"blob\":\"").append(blob).append("\",");
        sb.append("\"plain\":\"").append(plain.replace("\"", "\\\"")).append("\"}");
        Files.writeString(Path.of(out), sb.toString(), StandardCharsets.UTF_8);
        System.out.println("CL-encrypted blob written for C to decrypt: " + out);

        System.out.println("crosscheck: " + (fail == 0 ? "PASS" : "FAIL (" + fail + ")"));
        if (fail > 0) System.exit(1);
    }
}
