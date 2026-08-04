package in.captnemo.opensc;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

// Compiles secure_component.c fresh before tests run, in whichever of its
// mutually-exclusive modes a test needs. Shared by every test class instead
// of each re-implementing its own ProcessBuilder/pkg-config dance.
//
// Every caller that wants the same build mode gets the same fixed output
// path and therefore the same cached artifact -- SecureComponentPropertyTest
// and CrossImplementationPropertyTest both want the SC_TEST_HOOKS JNI build,
// so without this they'd redundantly invoke cc twice for byte-identical
// output. -O0 (not -O2) because these are correctness tests, not benchmarks:
// compiling faster matters here, running faster doesn't.
final class NativeBuild {
    private NativeBuild() {
    }

    static final Path SOURCE = Paths.get("").toAbsolutePath().resolve("secure_component.c");
    private static final Path OUT_DIR = Paths.get("").toAbsolutePath().resolve("target/native-test");
    private static final Map<String, Path> CACHE = new ConcurrentHashMap<>();

    static Path buildJniLib(boolean testHooks) throws Exception {
        String name = testHooks ? "libSecureComponentRe_test" : "libSecureComponentRe";
        List<String> flags = new ArrayList<>(List.of("-shared", "-fPIC",
                "-I" + System.getProperty("java.home") + "/include",
                "-I" + System.getProperty("java.home") + "/include/linux"));
        if (testHooks) flags.add("-DSC_TEST_HOOKS");
        return build(name, OUT_DIR.resolve(name + ".so"), flags);
    }

    static Path buildStdioServer() throws Exception {
        String name = "sc_server";
        return build(name, OUT_DIR.resolve(name), List.of("-DSC_STDIO_SERVER"));
    }

    private static Path build(String name, Path out, List<String> extraFlags) throws Exception {
        Path cached = CACHE.get(name);
        if (cached != null) {
            return cached;
        }
        synchronized (NativeBuild.class) {
            cached = CACHE.get(name);
            if (cached != null) {
                return cached;
            }
            if (Files.isRegularFile(out)) {
                CACHE.put(name, out);
                return out;
            }
            if (!Files.isRegularFile(SOURCE)) {
                throw new IllegalStateException("expected source at " + SOURCE);
            }
            Files.createDirectories(OUT_DIR);

            List<String> cmd = new ArrayList<>(List.of("cc", "-O0", "-Wall"));
            cmd.addAll(extraFlags);
            cmd.add("-o");
            cmd.add(out.toString());
            cmd.add(SOURCE.toString());
            cmd.addAll(pkgConfigOpenssl());
            cmd.add("-lpthread");

            Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
            String output = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            if (p.waitFor() != 0) {
                throw new IllegalStateException("compiling " + name + " failed:\n" + output);
            }
            CACHE.put(name, out);
            return out;
        }
    }

    private static List<String> pkgConfigOpenssl() {
        try {
            Process p = new ProcessBuilder("pkg-config", "--cflags", "--libs", "openssl")
                    .redirectErrorStream(true).start();
            String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
            if (p.waitFor() == 0 && !out.isEmpty()) {
                return new ArrayList<>(List.of(out.split("\\s+")));
            }
        } catch (IOException | InterruptedException ignored) {
            // fall through to the plain -lcrypto guess below
        }
        return new ArrayList<>(List.of("-lcrypto"));
    }
}
