import java.lang.reflect.*;

// Runs the GENUINE NPCI CL sync (Oooo000.registerState) in a real Android process (waydroid).
// Seeds the vault via genuine o00O00O, then calls the real registerState and prints accept/reject.
public class CLHarness {
    static final String P = "org.npci.upi.security.pinactivitycomponent.";

    static Object context() throws Exception {
        Class<?> at = Class.forName("android.app.ActivityThread");
        try { at.getMethod("systemMain").invoke(null); } catch (Throwable ignored) {}
        Object inst = at.getMethod("currentActivityThread").invoke(null);
        Object ctx = at.getMethod("getSystemContext").invoke(inst);
        return ctx;
    }

    public static void main(String[] a) throws Exception {
        String mob = a[0], dev = a[1], acc = a[2], kB64 = a[3];
        String oldState = new String(java.util.Base64.getDecoder().decode(a[4]));
        String newState = new String(java.util.Base64.getDecoder().decode(a[5]));
        String label = a.length > 6 ? a[6] : "case";
        Object ctx = context();

        Class<?> cP = Class.forName(P + "o0OOO0o");
        Object oP = cP.getConstructor(Class.forName("android.content.Context")).newInstance(ctx);
        String alias = (String) cP.getMethod("OooO0O0", String.class).invoke(oP, dev + mob + acc + "UPI");

        Class<?> cV = Class.forName(P + "o00O00O");
        Object vault = cV.getMethod("OooO00o", String.class, Class.forName("android.content.Context"),
                String.class, String.class).invoke(null, alias, ctx, "UPI", acc);
        Method setIn = cV.getMethod("OooO00o", String.class, String.class, Boolean.class);
        setIn.invoke(vault, "AESUPI", kB64, Boolean.TRUE);
        setIn.invoke(vault, "ClientRiskRules",
                "{\"ATC\":\"0\",\"OSN\":\"0\",\"PISC\":\"0\",\"PC1V\":\"0\",\"PC2V\":\"0\",\"PC3V\":\"0\",\"PC4V\":\"0\"}",
                Boolean.TRUE);
        setIn.invoke(vault, "ServerRiskParams", oldState, Boolean.TRUE);

        // str4 is the new state AES-GCM-encrypted under the session key, as the backend would send.
        String str4 = (String) cP.getMethod("OooO0Oo", String.class, String.class).invoke(oP, newState, kB64);

        Class<?> cO = Class.forName(P + "Oooo000");
        Object sync = cO.getConstructor(Class.forName("android.content.Context"), String.class)
                .newInstance(ctx, "UPI");
        Object res = cO.getMethod("OooO00o", String.class, String.class, String.class, String.class)
                .invoke(sync, mob, dev, acc, str4);
        System.out.println("RESULT " + label + " " + res);
    }
}
