import java.io.ByteArrayInputStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Map;

// Confirms the C wallet's sync accept/reject matches the genuine CL's rule: the signature decision
// comes from the genuine CL leaf (o0OOO0o PSS verify); the timestamp/ACSTATUS rule is the CL's own.
public final class LiteSyncOracle {
    static final String PKG = "org.npci.upi.security.pinactivitycomponent.";

    public static void main(String[] args) throws Exception {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        List<String> lines = Files.readAllLines(Path.of(args[0]), StandardCharsets.UTF_8);

        @SuppressWarnings("unchecked")
        Map<String, Object> head = (Map<String, Object>) Json.parse(lines.get(0));
        byte[] certDer = Base64.getDecoder().decode((String) head.get("cert"));
        X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(certDer));
        PublicKey pub = cert.getPublicKey();

        Class<?> crypto = Class.forName(PKG + "o0OOO0o");
        Object inst = crypto.getDeclaredConstructor(Class.forName("android.content.Context"))
                .newInstance(new Object[]{null});
        Method mVerify = crypto.getMethod("OooO00o", String.class, String.class, PublicKey.class);

        int pass = 0, fail = 0;
        for (int i = 1; i < lines.size(); i++) {
            if (lines.get(i).isEmpty()) continue;
            @SuppressWarnings("unchecked")
            Map<String, Object> c = (Map<String, Object>) Json.parse(lines.get(i));
            @SuppressWarnings("unchecked")
            Map<String, Object> st = (Map<String, Object>) c.get("state");
            String riskRules = (String) st.get("riskRules");
            String signature = (String) st.get("signature");
            boolean sigOk = (Boolean) mVerify.invoke(inst, riskRules, signature, pub);

            long oldTs = ((Double) c.get("old_ts")).longValue();
            long newTs = ((Double) c.get("new_ts")).longValue();
            String acs = (String) c.get("acs");
            String expected;
            if (!sigOk) expected = "BAD_SIG";
            else if (acs.equals("DA")) expected = "DEACTIVATED";
            else if (newTs > oldTs) expected = "OK";
            else expected = "STALE";

            String got = (String) c.get("decision");
            if (expected.equals(got)) {
                pass++;
            } else {
                fail++;
                System.out.println("MISMATCH old=" + oldTs + " new=" + newTs + " acs=" + acs +
                                   " tampered=" + c.get("tampered") +
                                   " genuineSig=" + sigOk + " CLrule=" + expected + " C=" + got);
            }
        }
        System.out.println("sync-oracle: pass=" + pass + " fail=" + fail +
                           " (C decisions vs genuine-CL sync rule)");
        if (fail > 0) System.exit(1);
    }
}
