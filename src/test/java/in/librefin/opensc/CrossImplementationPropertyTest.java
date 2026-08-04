package in.librefin.opensc;

import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.lifecycle.AfterContainer;
import net.jqwik.api.lifecycle.BeforeContainer;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;

// Proves the stdio coprocess protocol interoperates: same crypto core, two transports (JNI vs. pipe), same ScClient.
class CrossImplementationPropertyTest {

    private static JniClient jni;
    private static PipeClient pipe;

    @BeforeContainer
    static void boot() throws Exception {
        // load our own copy rather than assuming another test class already did
        Path so = NativeBuild.buildJniLib(true);
        System.load(so.toAbsolutePath().toString());
        org.npci.upi.security.pinactivitycomponent.OfflineNativeDefenderService.nEnableUPILITEX();
        jni = new JniClient();

        Path server = NativeBuild.buildStdioServer();
        pipe = new PipeClient("c-stdio", List.of(server.toAbsolutePath().toString()));
    }

    @AfterContainer
    static void shutdown() throws Exception {
        if (pipe != null) pipe.close();
    }

    @Provide
    // Small reusable pool -- see SecureComponentPropertyTest.aliases() for why.
    Arbitrary<String> aliases() {
        return Arbitraries.integers().between(0, 19).map(i -> "alias" + i);
    }

    @Provide
    Arbitrary<String> payloads() {
        return Arbitraries.strings().ascii().ofMinLength(0).ofMaxLength(80);
    }

    private static void check(boolean cond, String message) {
        if (!cond) throw new AssertionError(message);
    }

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    @Property
    void jniSignatureVerifiesThroughPipe(@ForAll("aliases") String alias, @ForAll("payloads") String data) throws Exception {
        byte[] sig = jni.sign(alias, utf8(data), true);
        byte[] pub = jni.pubkey(alias, "EC");
        check(jni.verify(pub, utf8(data), sig), "jni signature failed to verify through jni itself");
        check(pipe.verify(pub, utf8(data), sig), "jni signature failed to verify through the stdio coprocess");
    }

    @Property
    void pipeSignatureVerifiesThroughJni(@ForAll("aliases") String alias, @ForAll("payloads") String data) throws Exception {
        byte[] sig = pipe.sign(alias, utf8(data), true);
        byte[] pub = pipe.pubkey(alias, "EC");
        check(pipe.verify(pub, utf8(data), sig), "pipe signature failed to verify through the stdio coprocess itself");
        check(jni.verify(pub, utf8(data), sig), "pipe signature failed to verify through jni");
    }

    @Property
    void tamperedDataRejectedByBothBackends(@ForAll("aliases") String alias, @ForAll("payloads") String data) throws Exception {
        byte[] sig = jni.sign(alias, utf8(data), true);
        byte[] pub = jni.pubkey(alias, "EC");
        byte[] tampered = utf8(data + "!");
        check(!jni.verify(pub, tampered, sig), "jni verify accepted tampered data");
        check(!pipe.verify(pub, tampered, sig), "pipe verify accepted tampered data");
    }

    @Property
    void pssSignatureNeverVerifiesOnEitherBackend(@ForAll("aliases") String alias, @ForAll("payloads") String data) throws Exception {
        byte[] pssSig = jni.sign(alias, utf8(data), false);
        byte[] pub = jni.pubkey(alias, "EC");
        check(!jni.verify(pub, utf8(data), pssSig), "jni verify accepted an RSA/PSS signature");
        check(!pipe.verify(pub, utf8(data), pssSig), "pipe verify accepted an RSA/PSS signature");
    }

    @Property
    void rsaPssSignatureSizeAgreesAcrossBackends(@ForAll("aliases") String alias, @ForAll("payloads") String data) throws Exception {
        byte[] jniSig = jni.sign(alias, utf8(data), false);
        byte[] pipeSig = pipe.sign(alias, utf8(data), false);
        check(jniSig.length == 256, "jni RSA/PSS signature should be 256 bytes, was " + jniSig.length);
        check(pipeSig.length == 256, "pipe RSA/PSS signature should be 256 bytes, was " + pipeSig.length);
    }
}
