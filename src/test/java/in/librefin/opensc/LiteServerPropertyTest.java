package in.librefin.opensc;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HexFormat;

import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.constraints.IntRange;
import net.jqwik.api.lifecycle.AfterContainer;
import net.jqwik.api.lifecycle.BeforeContainer;

// jqwik parity fuzzing of the lite/ C server against the JDK's own crypto. Aborts (does not fail)
// when the server binary is not built, matching how RealLibraryTest handles a missing artifact.
class LiteServerPropertyTest {

    private static LiteServerClient client;

    @BeforeContainer
    static void setup() {
        client = LiteServerClient.spawnIfBuilt();
    }

    @AfterContainer
    static void teardown() {
        if (client != null) client.close();
    }

    private static void check(boolean cond, String message) {
        if (!cond) throw new AssertionError(message);
    }

    // Lite fields (base64, decimals, VPAs, JSON, hex) never contain NUL; the C-string transport
    // cannot carry an embedded NUL, so the realistic input domain excludes U+0000.
    @Provide
    Arbitrary<String> texts() {
        return Arbitraries.strings().withCharRange('\u0001', '￿').ofMaxLength(80);
    }

    private static String sha256b64(String s) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return Base64.getEncoder().encodeToString(md.digest(s.getBytes(StandardCharsets.UTF_8)));
    }

    private static String sha1id35(String s) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return HexFormat.of().formatHex(md.digest(s.getBytes(StandardCharsets.UTF_8))).substring(0, 35);
    }

    @Property(tries = 300)
    void aliasMatchesJdk(@ForAll("texts") String dev, @ForAll("texts") String mob, @ForAll("texts") String acc) throws Exception {
        if (client == null) return;   // server not built (e.g. test.yml): skip without rejecting tries
        String want = sha256b64(dev + mob + acc + "UPI");
        check(want.equals(client.alias(dev, mob, acc, "UPI")), "alias mismatch");
    }

    @Property(tries = 300)
    void sha256MatchesJdk(@ForAll("texts") String s) throws Exception {
        if (client == null) return;   // server not built (e.g. test.yml): skip without rejecting tries
        String got = client.sha256b64(s);
        check(sha256b64(s).equals(got),
              "sha256b64 mismatch: inHex=" + HexFormat.of().formatHex(s.getBytes(StandardCharsets.UTF_8))
              + " got=[" + got + "] want=[" + sha256b64(s) + "]");
    }

    @Property(tries = 300)
    void sha1id35MatchesJdk(@ForAll("texts") String s) throws Exception {
        if (client == null) return;   // server not built (e.g. test.yml): skip without rejecting tries
        check(sha1id35(s).equals(client.sha1id35(s)), "sha1id35 mismatch for [" + s + "]");
    }

    @Property(tries = 256)
    void pacMatchesRule(@ForAll @IntRange(min = 0, max = 255) int code,
                        @ForAll @IntRange(min = 0, max = 1) int debit) {
        if (client == null) return;   // server not built (e.g. test.yml): skip without rejecting tries
        int i = (code >> 6) & 3;
        boolean expected = (i == 3) || (i == 1 && debit == 1) || (i == 2 && debit == 0);
        check((expected ? "1" : "0").equals(client.pac(code, debit)), "pac mismatch code=" + code);
    }

    @Property(tries = 200)
    void counterMatchesRule(@ForAll @IntRange(min = 0, max = 255) int code,
                            @ForAll @IntRange(min = 0, max = 100000) int curCents,
                            @ForAll @IntRange(min = 0, max = 100000) int amtCents) {
        if (client == null) return;   // server not built (e.g. test.yml): skip without rejecting tries
        double cur = curCents / 100.0, amt = amtCents / 100.0;
        int i = (code >> 5) & 1;
        double base = i == 0 ? cur + 1.0 : cur;
        double expected = i == 1 ? base + amt : base;
        check(String.format(java.util.Locale.US, "%.2f", expected).equals(client.counter(code, cur, amt)),
              "counter mismatch code=" + code);
    }
}
