package in.librefin.opensc;

import com.github.unidbg.linux.android.dvm.DvmObject;
import net.jqwik.api.Assume;
import net.jqwik.api.Example;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

// End-to-end tests against the REAL libSecureComponent.so copies; see HACKING.md.
class RealLibraryTest {

    private static final Path DIR = Paths.get("").toAbsolutePath().resolve("artifacts/libSecureComponent");
    private static final String DATA = "5241234567890123|100.00|20260803";

    // sha1 -> host app, from static analysis of each binary's pinned package/cert strings.
    private static final Map<String, String> KNOWN_SHA1 = Map.of(
            "b55702f81b9aeb4b90ee357aff99eb6add59b20b", "PhonePe",
            "878306680ccc4cbf4659e0e011fbc059e6ed3eac", "Navi",
            "748f5d8d1c835494079862cf06dc36c8f6aa5c12", "Central Bank",
            "d3e2c253c5bc4f49edd3a6be38544fe9e5a19a70", "BHIM",
            "2a1a19ec45a99eb38cfad982574b599fec12ef46", "KreditBee");

    static List<Path> discoverSoFiles() throws IOException {
        if (!Files.isDirectory(DIR)) {
            return List.of();
        }
        try (var stream = Files.list(DIR)) {
            List<Path> files = new ArrayList<>();
            stream.filter(p -> p.toString().endsWith(".so")).forEach(files::add);
            files.sort(Comparator.comparing(p -> p.getFileName().toString()));
            return files;
        }
    }

    static void failIfAny(List<String> failures) {
        if (!failures.isEmpty()) {
            throw new AssertionError(failures.size() + " file(s) failed:\n  " + String.join("\n  ", failures));
        }
    }

    @Example
    void identityMatchesAKnownHostApp() throws Exception {
        List<Path> files = discoverSoFiles();
        Assume.that(!files.isEmpty());
        List<String> failures = new ArrayList<>();
        for (Path f : files) {
            byte[] digest = MessageDigest.getInstance("SHA-1").digest(Files.readAllBytes(f));
            String sha1 = HexFormat.of().formatHex(digest);
            String app = KNOWN_SHA1.get(sha1);
            System.out.println(f.getFileName() + " identifies as: " + (app == null ? "unknown" : app) + " (sha1=" + sha1 + ")");
            if (app == null) {
                failures.add(f.getFileName() + ": sha1 " + sha1 + " doesn't match any of the 5 documented host apps");
            }
        }
        failIfAny(failures);
    }

    @Example
    void loadsAndRegistersOnlyTheEntryTrampoline() throws Exception {
        List<Path> files = discoverSoFiles();
        Assume.that(!files.isEmpty());
        List<String> failures = new ArrayList<>();
        for (Path f : files) {
            // constructor runs JNI_OnLoad + nEnableUPILITEX; a descriptor mismatch throws
            try (RealLibraryBoot boot = new RealLibraryBoot(f)) {
            } catch (Exception e) {
                failures.add(f.getFileName() + ": " + e);
            }
        }
        failIfAny(failures);
    }

    @Example
    void signAndVerifyRoundTripSucceeds() throws Exception {
        List<Path> files = discoverSoFiles();
        Assume.that(!files.isEmpty());
        List<String> failures = new ArrayList<>();
        for (Path f : files) {
            try (RealLibraryBoot boot = new RealLibraryBoot(f)) {
                String alias = "real-lib-test-alias";

                byte[] sig = boot.sign(DATA, alias, true);
                PublicKey pub = boot.jni.publicKeyFor(alias, "SHA256withECDSA");
                DvmObject<?> pubWrapped = boot.vm.resolveClass("java/security/PublicKey").newObject(pub);
                String sigB64 = Base64.getEncoder().encodeToString(sig);

                if (!boot.verify(DATA, sigB64, pubWrapped)) {
                    failures.add(f.getFileName() + ": genuine signature failed to verify");
                }
                if (boot.verify(DATA + "!", sigB64, pubWrapped)) {
                    failures.add(f.getFileName() + ": tampered data verified as genuine");
                }
            } catch (Exception e) {
                failures.add(f.getFileName() + ": " + e);
            }
        }
        failIfAny(failures);
    }

    @Example
    void rsaPssSignatureHasCorrectSizeAndNeverVerifiesAsEc() throws Exception {
        List<Path> files = discoverSoFiles();
        Assume.that(!files.isEmpty());
        List<String> failures = new ArrayList<>();
        for (Path f : files) {
            try (RealLibraryBoot boot = new RealLibraryBoot(f)) {
                String alias = "real-lib-test-alias";

                byte[] pss = boot.sign(DATA, alias, false);
                if (pss.length != 256) {
                    failures.add(f.getFileName() + ": RSA/PSS signature should be 256 bytes, was " + pss.length);
                }

                PublicKey pub = boot.jni.publicKeyFor(alias, "SHA256withECDSA");
                DvmObject<?> pubWrapped = boot.vm.resolveClass("java/security/PublicKey").newObject(pub);
                if (boot.verify(DATA, Base64.getEncoder().encodeToString(pss), pubWrapped)) {
                    failures.add(f.getFileName() + ": an RSA/PSS signature verified through the EC verifier");
                }
            } catch (Exception e) {
                failures.add(f.getFileName() + ": " + e);
            }
        }
        failIfAny(failures);
    }

    // Full N-by-N: every binary's signature must verify under every OTHER binary too, not just itself.
    @Example
    void crossSourceEcdsaSignVerifyMatrixSucceeds() throws Exception {
        List<Path> files = discoverSoFiles();
        Assume.that(files.size() >= 2);
        String alias = "cross-source-alias";

        List<RealLibraryBoot> boots = new ArrayList<>();
        List<byte[]> sigs = new ArrayList<>();
        List<PublicKey> pubs = new ArrayList<>();
        List<String> failures = new ArrayList<>();
        try {
            for (Path f : files) {
                RealLibraryBoot boot = new RealLibraryBoot(f);
                boots.add(boot);
                sigs.add(boot.sign(DATA, alias, true));
                pubs.add(boot.jni.publicKeyFor(alias, "SHA256withECDSA"));
            }

            for (int signer = 0; signer < boots.size(); signer++) {
                String sigB64 = Base64.getEncoder().encodeToString(sigs.get(signer));
                for (int verifier = 0; verifier < boots.size(); verifier++) {
                    RealLibraryBoot v = boots.get(verifier);
                    DvmObject<?> pubWrapped = v.vm.resolveClass("java/security/PublicKey").newObject(pubs.get(signer));
                    String pair = files.get(signer).getFileName() + " signed -> " + files.get(verifier).getFileName() + " verified";

                    if (!v.verify(DATA, sigB64, pubWrapped)) {
                        failures.add(pair + ": genuine cross-source signature failed to verify");
                    }
                    if (v.verify(DATA + "!", sigB64, pubWrapped)) {
                        failures.add(pair + ": tampered data verified across sources");
                    }
                }
            }
        } finally {
            for (RealLibraryBoot b : boots) {
                try {
                    b.close();
                } catch (Exception ignored) {
                    // best-effort cleanup; a close() failure shouldn't mask a real assertion failure above
                }
            }
        }
        failIfAny(failures);
    }
}
