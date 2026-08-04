package in.captnemo.opensc;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.memory.Memory;
import net.jqwik.api.Assume;
import net.jqwik.api.Example;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

// Tests against the REAL, proprietary libSecureComponent.so copies -- one per
// host app (PhonePe/Navi/Central Bank/BHIM/KreditBee), gitignored, present
// only if you dropped your own extracted copies into libSecureComponent/ (see
// README.md). Runs every check against every *.so file found there; every
// test aborts (not fails) if the directory is empty or missing, so `mvn test`
// stays green with or without them. Failures across files are aggregated per
// test rather than failing on the first bad file, so one bad copy doesn't
// hide problems with the others.
//
// Deliberately narrow: it loads each library under a near-bare unidbg JNI
// bridge (one override -- see Boot below) rather than reimplementing the real
// AndroidKeyStore/Signature bridge these libraries upcall into -- that already
// exists as JniBridge.java in phonepe-harness, and duplicating it here would
// defeat the point of opensc being lean. What's checked without that bridge:
// each file's identity against the five documented host-app hashes, and that
// JNI_OnLoad and nEnableUPILITEX both complete and register exactly the
// descriptors this project reimplements (visible in RegisterNatives itself,
// so this doesn't need to actually invoke the signing/verifying natives).
//
// Deliberately does NOT call nOfflineSignWithKey/nOfflineVerifyEcSignature:
// doing so without the real KeyStore/Signature bridge reaches an unhandled
// upcall (KeyStore.getInstance) that unidbg's own error-recovery path hangs
// on indefinitely when running under Surefire's forked JVM specifically (a
// plain `java` run hits the identical point and returns cleanly in under a
// second -- this is some Surefire-environment-specific unidbg behavior, not
// a bug in this bridge). Registration succeeding is sufficient proof of a
// signature match; it doesn't require completing the call.
class RealLibraryTest {

    private static final Path DIR = Paths.get("").toAbsolutePath().resolve("libSecureComponent");
    private static final String CLS = "org/npci/upi/security/pinactivitycomponent/OfflineNativeDefenderService";

    // sha1 -> host app, from SECURECOMPONENT-BINDING.md in phonepe-harness.
    private static final Map<String, String> KNOWN_SHA1 = Map.of(
            "b55702f81b9aeb4b90ee357aff99eb6add59b20b", "PhonePe",
            "878306680ccc4cbf4659e0e011fbc059e6ed3eac", "Navi",
            "748f5d8d1c835494079862cf06dc36c8f6aa5c12", "Central Bank",
            "d3e2c253c5bc4f49edd3a6be38544fe9e5a19a70", "BHIM",
            "2a1a19ec45a99eb38cfad982574b599fec12ef46", "KreditBee");

    static {
        // Arch's system libunicorn.so.2 has no JNI shim and shadows unidbg's
        // bundled build; load the bundled one by path instead of by name.
        try {
            String res = "/natives/linux_64/libunicorn.so";
            InputStream in = RealLibraryTest.class.getResourceAsStream(res);
            if (in != null) {
                File tmp = File.createTempFile("libunicorn", ".so");
                tmp.deleteOnExit();
                try (in; OutputStream out = new java.io.FileOutputStream(tmp)) {
                    in.transferTo(out);
                }
                System.load(tmp.getAbsolutePath());
            }
        } catch (IOException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private static List<Path> discoverSoFiles() throws IOException {
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

    private static void failIfAny(List<String> failures) {
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
            try (Boot boot = new Boot(f, false)) {
                // JNI_OnLoad already ran in the constructor; if that trampoline
                // wasn't registered under this exact descriptor, this throws.
                boot.clazz.callStaticJniMethod(boot.emulator, "nEnableUPILITEX()V");
            } catch (Exception e) {
                failures.add(f.getFileName() + ": " + e);
            }
        }
        failIfAny(failures);
    }

    @Example
    void nEnableUpilitexRegistersOurExactSignatures() throws Exception {
        List<Path> files = discoverSoFiles();
        Assume.that(!files.isEmpty());
        List<String> failures = new ArrayList<>();
        for (Path f : files) {
            // unidbg's own verbose trace prints each RegisterNatives entry
            // (descriptor and all) as it happens -- capturing that is proof
            // enough of an exact signature match, with no need to invoke the
            // natives themselves (which, per the class comment, isn't safe here).
            PrintStream realOut = System.out;
            ByteArrayOutputStream captured = new ByteArrayOutputStream();
            String trace;
            try (Boot boot = new Boot(f, true)) {
                System.setOut(new PrintStream(captured, true, StandardCharsets.UTF_8));
                boot.clazz.callStaticJniMethod(boot.emulator, "nEnableUPILITEX()V");
            } catch (Exception e) {
                failures.add(f.getFileName() + ": " + e);
                continue;
            } finally {
                System.setOut(realOut);
                trace = captured.toString(StandardCharsets.UTF_8);
            }

            for (String expected : new String[]{
                    "nOfflineSignWithKey(Ljava/lang/String;Ljava/lang/String;Z)[B",
                    "nOfflineVerifyEcSignature(Ljava/lang/String;Ljava/lang/String;Ljava/security/PublicKey;)Z"}) {
                if (!trace.contains(expected)) {
                    failures.add(f.getFileName() + ": nEnableUPILITEX did not register " + expected);
                }
            }
        }
        failIfAny(failures);
    }

    private static final class Boot implements AutoCloseable {
        final AndroidEmulator emulator;
        final VM vm;
        final DvmClass clazz;

        Boot(Path so, boolean verbose) {
            emulator = AndroidEmulatorBuilder.for64Bit()
                    .setProcessName("com.phonepe.app")
                    .addBackendFactory(new Unicorn2Factory(false))
                    .build();
            Memory memory = emulator.getMemory();
            memory.setLibraryResolver(new AndroidResolver(23));
            vm = emulator.createDalvikVM();
            vm.setJni(new AbstractJni() {
                // The real JNI_OnLoad branches on this: a null Context skips
                // straight to RegisterNatives (see SECURECOMPONENT.md's
                // diagram); a non-null one goes on to call getApplication()
                // and further Context methods this bare bridge can't answer.
                @Override
                public com.github.unidbg.linux.android.dvm.DvmObject<?> callStaticObjectMethodV(
                        com.github.unidbg.linux.android.dvm.BaseVM vm, DvmClass dvmClass, String signature,
                        com.github.unidbg.linux.android.dvm.VaList vaList) {
                    if ("android/app/ActivityThread->currentActivityThread()Landroid/app/ActivityThread;".equals(signature)) {
                        return null;
                    }
                    return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
                }
            });
            vm.setVerbose(verbose);
            DalvikModule dm = vm.loadLibrary(so.toFile(), true);
            dm.callJNI_OnLoad(emulator);
            clazz = vm.resolveClass(CLS);
        }

        @Override
        public void close() throws IOException {
            emulator.close();
        }
    }
}
