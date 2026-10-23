import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

// Drives the GENUINE NPCI CL leaf methods (dex2jar'd) and checks them against the C vectors.
// Proves the C base64/SHA/alias/vault-signature reproduce NPCI's own bytecode, device-free.
public final class LiteOracle {
    static final String PKG = "org.npci.upi.security.pinactivitycomponent.";

    public static void main(String[] args) throws Exception {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        String vectorsPath = args[0];
        Class<?> crypto = Class.forName(PKG + "o0OOO0o");
        Class<?> b64 = Class.forName(PKG + "OooOO0O");
        Class<?> ctx = Class.forName("android.content.Context");
        Constructor<?> ctor = crypto.getDeclaredConstructor(ctx);
        Object inst = ctor.newInstance(new Object[]{null});

        Method mSha256 = crypto.getMethod("OooO0O0", String.class);
        Method mSha1 = crypto.getMethod("OooO", String.class);
        Method mVaultBytes = crypto.getMethod("OooO00o", String.class, String.class);
        Method mB64enc = b64.getMethod("OooO0OO", byte[].class, int.class);

        int pass = 0, skip = 0, fail = 0;
        for (String line : Files.readAllLines(Path.of(vectorsPath), StandardCharsets.UTF_8)) {
            if (line.isEmpty() || line.charAt(0) != '{') continue;
            @SuppressWarnings("unchecked")
            Map<String, Object> v = (Map<String, Object>) Json.parse(line);
            String op = (String) v.get("op");
            @SuppressWarnings("unchecked")
            List<Object> in = (List<Object>) v.get("in");
            String want = (String) v.get("out");
            String got;
            switch (op) {
                case "alias": {
                    String cat = str(in, 0) + str(in, 1) + str(in, 2) + str(in, 3);
                    got = (String) mSha256.invoke(inst, cat);
                    break;
                }
                case "sha256b64":
                    got = (String) mSha256.invoke(inst, str(in, 0));
                    break;
                case "sha1id35":
                    got = (String) mSha1.invoke(inst, str(in, 0));
                    break;
                case "vaultsig": {
                    byte[] digest = (byte[]) mVaultBytes.invoke(inst, str(in, 0), str(in, 1));
                    got = (String) mB64enc.invoke(null, digest, 0);
                    break;
                }
                default:
                    skip++;
                    continue;
            }
            if (want.equals(got)) {
                pass++;
            } else {
                fail++;
                System.out.println("MISMATCH " + op + " in=" + in);
                System.out.println("  C  : [" + show(want) + "]");
                System.out.println("  CL : [" + show(got) + "]");
            }
        }
        System.out.println("oracle: pass=" + pass + " fail=" + fail + " skip=" + skip +
                           " (genuine NPCI CL vs C vectors)");
        if (fail > 0) System.exit(1);
    }

    static String str(List<Object> in, int i) { return (String) in.get(i); }

    static String show(String s) { return s.replace("\n", "\\n"); }
}
