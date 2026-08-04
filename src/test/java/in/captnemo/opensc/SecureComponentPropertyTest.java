package in.captnemo.opensc;

import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Assume;
import net.jqwik.api.Example;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.lifecycle.BeforeContainer;
import org.npci.upi.security.pinactivitycomponent.OfflineNativeDefenderService;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

// Property tests for secure_component.c. It can't be diffed byte-for-byte
// against the real libSecureComponent.so (that one signs with AndroidKeyStore
// hardware keys we cannot reproduce -- see README.md), so "identical" here means
// spec-conformant: signatures this reimplementation produces must verify under
// the JDK's own, independent SHA512withRSA/PSS and SHA256withECDSA -- and its
// verifier must accept signatures produced entirely outside of it. Compiles the
// C source fresh (with -DSC_TEST_HOOKS) before the first property runs.
class SecureComponentPropertyTest {

    private static final PSSParameterSpec PSS_PARAMS =
            new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1);

    @BeforeContainer
    static void buildAndLoad() throws Exception {
        Path so = NativeBuild.buildJniLib(true);
        System.load(so.toAbsolutePath().toString());
        OfflineNativeDefenderService.nEnableUPILITEX();
    }

    private static void check(boolean cond, String message) {
        if (!cond) throw new AssertionError(message);
    }

    private static PublicKey rsaKeyFor(String alias) throws Exception {
        byte[] der = OfflineNativeDefenderService.nTestGetPublicKeyDer(alias, "RSA");
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
    }

    private static PublicKey ecKeyFor(String alias) throws Exception {
        byte[] der = OfflineNativeDefenderService.nTestGetPublicKeyDer(alias, "EC");
        return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(der));
    }

    private static boolean rsaPssVerify(PublicKey pub, String data, byte[] sig) throws Exception {
        Signature s = Signature.getInstance("RSASSA-PSS");
        s.setParameter(PSS_PARAMS);
        s.initVerify(pub);
        s.update(data.getBytes(StandardCharsets.UTF_8));
        return s.verify(sig);
    }

    private static boolean ecdsaVerifyJca(PublicKey pub, String data, byte[] sig) throws Exception {
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initVerify(pub);
        s.update(data.getBytes(StandardCharsets.UTF_8));
        return s.verify(sig);
    }

    // ---- arbitraries ----

    @Provide
    // A small reusable pool, not a fresh random string per trial: alias content
    // is never crypto-relevant (just a keystore lookup key), and a fresh alias
    // costs an RSA-2048 keygen (tens of ms) the first time it's seen. Reusing
    // ~20 aliases across ~1000 trials turns ~1000 keygens into ~20.
    Arbitrary<String> aliases() {
        return Arbitraries.integers().between(0, 19).map(i -> "alias" + i);
    }

    @Provide
    Arbitrary<String> payloads() {
        Arbitrary<String> ascii = Arbitraries.strings().ascii().ofMinLength(0).ofMaxLength(80);
        Arbitrary<String> bmp = Arbitraries.strings().withCharRange((char) 0x20, (char) 0xD7FF)
                .ofMinLength(0).ofMaxLength(40);
        Arbitrary<String> astral = Arbitraries.integers().between(0x10000, 0x10FFFF)
                .map(cp -> new String(Character.toChars(cp)))
                .list().ofMinSize(0).ofMaxSize(8)
                .map(chars -> String.join("", chars));
        return Arbitraries.oneOf(ascii, bmp, astral);
    }

    @Provide
    Arbitrary<String> garbage() {
        return Arbitraries.strings().withCharRange((char) 0x00, (char) 0x7F).ofMinLength(0).ofMaxLength(120);
    }

    // ---- UTF-8 conversion identity: JNI's modified UTF-8 differs from Java's
    // ---- own String.getBytes(UTF_8); the reimplementation hand-converts to match it.

    @Property
    void utf8ConversionMatchesJavaEncoding(@ForAll("payloads") String s) {
        byte[] native_ = OfflineNativeDefenderService.nTestUtf8(s);
        byte[] java = s.getBytes(StandardCharsets.UTF_8);
        check(Arrays.equals(native_, java),
                "utf8 mismatch for " + escapedCodepoints(s) + ": native=" + Arrays.toString(native_)
                        + " java=" + Arrays.toString(java));
    }

    @Example
    void utf8LoneHighSurrogate() {
        String s = "\uD800";
        check(Arrays.equals(OfflineNativeDefenderService.nTestUtf8(s), s.getBytes(StandardCharsets.UTF_8)),
                "lone high surrogate mismatch");
    }

    @Example
    void utf8LoneLowSurrogate() {
        String s = "\uDC00";
        check(Arrays.equals(OfflineNativeDefenderService.nTestUtf8(s), s.getBytes(StandardCharsets.UTF_8)),
                "lone low surrogate mismatch");
    }

    @Example
    void utf8SupplementaryEmoji() {
        String s = "5241234567890123|100.00|😀"; // valid surrogate pair (an emoji)
        check(Arrays.equals(OfflineNativeDefenderService.nTestUtf8(s), s.getBytes(StandardCharsets.UTF_8)),
                "astral codepoint mismatch");
    }

    private static String escapedCodepoints(String s) {
        StringBuilder sb = new StringBuilder();
        s.codePoints().forEach(cp -> sb.append(String.format("U+%04X ", cp)));
        return sb.toString();
    }

    // ---- RSA/PSS (useEc=false): must be exactly what Java's own SHA512withRSA/PSS
    // ---- resolves to -- SHA-512 digest, MGF1-SHA512, salt length 64, trailer 0xBC.

    @Property
    void rsaPssIsSpecConformantAndCorrectSize(@ForAll("aliases") String alias, @ForAll("payloads") String data) throws Exception {
        byte[] sig = OfflineNativeDefenderService.nOfflineSignWithKey(data, alias, false);
        check(sig.length == 256, "RSA/PSS signature should be 256 bytes (2048-bit key), was " + sig.length);
        check(rsaPssVerify(rsaKeyFor(alias), data, sig), "RSA/PSS signature failed to verify under stock JCA");
    }

    @Property
    void rsaPssRejectsWrongData(@ForAll("aliases") String alias, @ForAll("payloads") String data,
                                 @ForAll("payloads") String other) throws Exception {
        Assume.that(!data.equals(other));
        byte[] sig = OfflineNativeDefenderService.nOfflineSignWithKey(data, alias, false);
        check(!rsaPssVerify(rsaKeyFor(alias), other, sig), "RSA/PSS signature verified against different data");
    }

    // ---- ECDSA (useEc=true): SHA256withECDSA over the alias's P-256 keypair.
    // ---- Checked two ways: against stock JCA, and against the real production
    // ---- nOfflineVerifyEcSignature entry point (both must agree).

    @Property
    void ecdsaIsSpecConformant(@ForAll("aliases") String alias, @ForAll("payloads") String data) throws Exception {
        byte[] sig = OfflineNativeDefenderService.nOfflineSignWithKey(data, alias, true);
        PublicKey pub = ecKeyFor(alias);
        check(ecdsaVerifyJca(pub, data, sig), "ECDSA signature failed to verify under stock JCA");

        String sigB64 = Base64.getEncoder().encodeToString(sig);
        check(OfflineNativeDefenderService.nOfflineVerifyEcSignature(data, sigB64, pub),
                "ECDSA signature failed to verify under the reimplementation's own nOfflineVerifyEcSignature");
    }

    @Property
    void ecdsaRejectsWrongData(@ForAll("aliases") String alias, @ForAll("payloads") String data,
                                @ForAll("payloads") String other) throws Exception {
        Assume.that(!data.equals(other));
        byte[] sig = OfflineNativeDefenderService.nOfflineSignWithKey(data, alias, true);
        PublicKey pub = ecKeyFor(alias);
        check(!ecdsaVerifyJca(pub, other, sig), "ECDSA (JCA) verified against different data");
        String sigB64 = Base64.getEncoder().encodeToString(sig);
        check(!OfflineNativeDefenderService.nOfflineVerifyEcSignature(other, sigB64, pub),
                "ECDSA (native verify) verified against different data");
    }

    @Property
    void ecdsaRejectsFlippedSignatureByte(@ForAll("aliases") String alias, @ForAll("payloads") String data) throws Exception {
        byte[] sig = OfflineNativeDefenderService.nOfflineSignWithKey(data, alias, true);
        Assume.that(sig.length > 0);
        byte[] flipped = sig.clone();
        flipped[flipped.length - 1] ^= (byte) 0xFF;
        PublicKey pub = ecKeyFor(alias);
        String sigB64 = Base64.getEncoder().encodeToString(flipped);
        check(!OfflineNativeDefenderService.nOfflineVerifyEcSignature(data, sigB64, pub),
                "flipped-byte signature verified");
    }

    @Property
    void pssSignatureNeverVerifiesAsEcdsa(@ForAll("aliases") String alias, @ForAll("payloads") String data) throws Exception {
        byte[] pssSig = OfflineNativeDefenderService.nOfflineSignWithKey(data, alias, false);
        PublicKey ecPub = ecKeyFor(alias);
        String sigB64 = Base64.getEncoder().encodeToString(pssSig);
        check(!OfflineNativeDefenderService.nOfflineVerifyEcSignature(data, sigB64, ecPub),
                "a PSS signature verified through the ECDSA verifier");
    }

    // ---- externally-generated keys: nOfflineVerifyEcSignature must accept any
    // ---- JCA PublicKey, not just ones grown from this library's own keystore.

    @Property
    void nativeVerifyAcceptsExternallySignedData(@ForAll("payloads") String data) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = gen.generateKeyPair();
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(kp.getPrivate());
        s.update(data.getBytes(StandardCharsets.UTF_8));
        byte[] sig = s.sign();
        String sigB64 = Base64.getEncoder().encodeToString(sig);

        check(OfflineNativeDefenderService.nOfflineVerifyEcSignature(data, sigB64, kp.getPublic()),
                "failed to verify an externally (stock-JCA) signed EC signature");
        check(!OfflineNativeDefenderService.nOfflineVerifyEcSignature(data + "x", sigB64, kp.getPublic()),
                "verified an externally signed EC signature against tampered data");
    }

    // ---- base64: sigB64 is decoded like android.util.Base64 NO_WRAP -- accept any
    // ---- padding/newline style a real Base64 encoder might reasonably produce.

    @Property
    void base64EncodingVariantsAllVerify(@ForAll("payloads") String data) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = gen.generateKeyPair();
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(kp.getPrivate());
        s.update(data.getBytes(StandardCharsets.UTF_8));
        byte[] sig = s.sign();

        String padded = Base64.getEncoder().encodeToString(sig);
        String unpadded = Base64.getEncoder().withoutPadding().encodeToString(sig);
        String mime = Base64.getMimeEncoder().encodeToString(sig); // wraps with \r\n every 76 chars

        check(OfflineNativeDefenderService.nOfflineVerifyEcSignature(data, padded, kp.getPublic()), "padded base64 rejected");
        check(OfflineNativeDefenderService.nOfflineVerifyEcSignature(data, unpadded, kp.getPublic()), "unpadded base64 rejected");
        check(OfflineNativeDefenderService.nOfflineVerifyEcSignature(data, mime, kp.getPublic()), "MIME-wrapped base64 rejected");
    }

    // ---- alias -> keypair store: lazily generated, then stable and isolated.

    @Property
    void aliasKeysAreDeterministicAcrossCalls(@ForAll("aliases") String alias) throws Exception {
        byte[] rsa1 = OfflineNativeDefenderService.nTestGetPublicKeyDer(alias, "RSA");
        byte[] rsa2 = OfflineNativeDefenderService.nTestGetPublicKeyDer(alias, "RSA");
        byte[] ec1 = OfflineNativeDefenderService.nTestGetPublicKeyDer(alias, "EC");
        byte[] ec2 = OfflineNativeDefenderService.nTestGetPublicKeyDer(alias, "EC");
        check(Arrays.equals(rsa1, rsa2), "RSA public key for alias '" + alias + "' changed across calls");
        check(Arrays.equals(ec1, ec2), "EC public key for alias '" + alias + "' changed across calls");
    }

    @Property
    void differentAliasesGetDifferentKeys(@ForAll("aliases") String a, @ForAll("aliases") String b) {
        Assume.that(!a.equals(b));
        byte[] rsaA = OfflineNativeDefenderService.nTestGetPublicKeyDer(a, "RSA");
        byte[] rsaB = OfflineNativeDefenderService.nTestGetPublicKeyDer(b, "RSA");
        byte[] ecA = OfflineNativeDefenderService.nTestGetPublicKeyDer(a, "EC");
        byte[] ecB = OfflineNativeDefenderService.nTestGetPublicKeyDer(b, "EC");
        check(!Arrays.equals(rsaA, rsaB), "two different aliases produced the same RSA key");
        check(!Arrays.equals(ecA, ecB), "two different aliases produced the same EC key");
    }

    // ---- verify() must never crash on garbage input; a boolean-returning API
    // ---- rejecting malformed input is correct, throwing/crashing is not.

    @Property
    void malformedSignatureBase64NeverVerifies(@ForAll("aliases") String alias, @ForAll("payloads") String data,
                                                @ForAll("garbage") String junk) throws Exception {
        PublicKey pub = ecKeyFor(alias);
        boolean result = OfflineNativeDefenderService.nOfflineVerifyEcSignature(data, junk, pub);
        check(!result, "garbage base64 '" + junk + "' verified as a valid signature");
    }
}
