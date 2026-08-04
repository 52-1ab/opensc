package in.librefin.opensc;

import com.github.unidbg.linux.android.dvm.DvmObject;
import net.jqwik.api.Assume;
import net.jqwik.api.Example;
import net.jqwik.api.lifecycle.BeforeContainer;
import org.npci.upi.security.pinactivitycomponent.OfflineNativeDefenderService;

import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

// Interop between our C reimplementation and the real binaries; see HACKING.md.
class RealVsReimplementationTest {

    private static final String DATA = "5241234567890123|100.00|20260803";

    @BeforeContainer
    static void loadOurReimplementation() throws Exception {
        Path so = NativeBuild.buildJniLib(true);
        System.load(so.toAbsolutePath().toString());
        OfflineNativeDefenderService.nEnableUPILITEX();
    }

    @Example
    void ourSignatureVerifiesUnderEveryRealBinary() throws Exception {
        List<Path> files = RealLibraryTest.discoverSoFiles();
        Assume.that(!files.isEmpty());
        String alias = "our-code-signs";

        byte[] ourSig = OfflineNativeDefenderService.nOfflineSignWithKey(DATA, alias, true);
        byte[] ourPubDer = OfflineNativeDefenderService.nTestGetPublicKeyDer(alias, "EC");
        PublicKey ourPub = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(ourPubDer));
        String sigB64 = Base64.getEncoder().encodeToString(ourSig);

        List<String> failures = new ArrayList<>();
        for (Path f : files) {
            try (RealLibraryBoot boot = new RealLibraryBoot(f)) {
                DvmObject<?> pubWrapped = boot.vm.resolveClass("java/security/PublicKey").newObject(ourPub);
                if (!boot.verify(DATA, sigB64, pubWrapped)) {
                    failures.add(f.getFileName() + ": our signature failed to verify under the real binary");
                }
                if (boot.verify(DATA + "!", sigB64, pubWrapped)) {
                    failures.add(f.getFileName() + ": the real binary verified our signature against tampered data");
                }
            } catch (Exception e) {
                failures.add(f.getFileName() + ": " + e);
            }
        }
        RealLibraryTest.failIfAny(failures);
    }

    @Example
    void everyRealBinarysSignatureVerifiesUnderOurCode() throws Exception {
        List<Path> files = RealLibraryTest.discoverSoFiles();
        Assume.that(!files.isEmpty());
        String alias = "real-binary-signs";

        List<String> failures = new ArrayList<>();
        for (Path f : files) {
            try (RealLibraryBoot boot = new RealLibraryBoot(f)) {
                byte[] realSig = boot.sign(DATA, alias, true);
                PublicKey realPub = boot.jni.publicKeyFor(alias, "SHA256withECDSA");
                String sigB64 = Base64.getEncoder().encodeToString(realSig);

                if (!OfflineNativeDefenderService.nOfflineVerifyEcSignature(DATA, sigB64, realPub)) {
                    failures.add(f.getFileName() + ": the real binary's signature failed to verify under our code");
                }
                if (OfflineNativeDefenderService.nOfflineVerifyEcSignature(DATA + "!", sigB64, realPub)) {
                    failures.add(f.getFileName() + ": our code verified the real binary's signature against tampered data");
                }
            } catch (Exception e) {
                failures.add(f.getFileName() + ": " + e);
            }
        }
        RealLibraryTest.failIfAny(failures);
    }

    // Cross-algorithm rejection has to hold across the boundary too, not just within one side.
    @Example
    void pssSignaturesNeverVerifyAcrossTheBoundaryEither() throws Exception {
        List<Path> files = RealLibraryTest.discoverSoFiles();
        Assume.that(!files.isEmpty());
        String alias = "pss-cross-boundary";

        byte[] ourPss = OfflineNativeDefenderService.nOfflineSignWithKey(DATA, alias, false);
        byte[] ourPubDer = OfflineNativeDefenderService.nTestGetPublicKeyDer(alias, "EC");
        PublicKey ourPub = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(ourPubDer));
        String ourPssB64 = Base64.getEncoder().encodeToString(ourPss);

        List<String> failures = new ArrayList<>();
        for (Path f : files) {
            try (RealLibraryBoot boot = new RealLibraryBoot(f)) {
                DvmObject<?> ourPubWrapped = boot.vm.resolveClass("java/security/PublicKey").newObject(ourPub);
                if (boot.verify(DATA, ourPssB64, ourPubWrapped)) {
                    failures.add(f.getFileName() + ": our RSA/PSS signature verified under the real binary's EC verifier");
                }

                byte[] realPss = boot.sign(DATA, alias, false);
                PublicKey realPub = boot.jni.publicKeyFor(alias, "SHA256withECDSA");
                String realPssB64 = Base64.getEncoder().encodeToString(realPss);
                if (OfflineNativeDefenderService.nOfflineVerifyEcSignature(DATA, realPssB64, realPub)) {
                    failures.add(f.getFileName() + ": the real binary's RSA/PSS signature verified under our EC verifier");
                }
            } catch (Exception e) {
                failures.add(f.getFileName() + ": " + e);
            }
        }
        RealLibraryTest.failIfAny(failures);
    }
}
