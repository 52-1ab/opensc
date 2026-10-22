package in.librefin.opensc;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.List;

// Drives the lite/ stdio server (built by `make -C lite server`) over a persistent pipe for jqwik.
final class LiteServerClient implements AutoCloseable {

    private final Process process;
    private final OutputStream stdin;
    private final BufferedReader stdout;

    private LiteServerClient(Path bin) throws IOException {
        this.process = new ProcessBuilder(bin.toString()).redirectErrorStream(false).start();
        this.stdin = process.getOutputStream();
        this.stdout = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8));
        String ready = stdout.readLine();
        if (ready == null || !ready.startsWith("READY lite")) {
            throw new IllegalStateException("no READY handshake, got: " + ready);
        }
    }

    static Path binary() {
        return Path.of(System.getProperty("user.dir"), "lite", "build", "lite_server");
    }

    static LiteServerClient spawnIfBuilt() {
        Path bin = binary();
        if (!Files.isExecutable(bin)) {
            return null;
        }
        try {
            return new LiteServerClient(bin);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private String hex(String s) {
        return HexFormat.of().formatHex(s.getBytes(StandardCharsets.UTF_8));
    }

    private synchronized String call(List<String> argv) {
        try {
            stdin.write((String.join(" ", argv) + "\n").getBytes(StandardCharsets.UTF_8));
            stdin.flush();
            String line = stdout.readLine();
            if (line == null || !line.startsWith("OK ")) {
                throw new IllegalStateException("bad response: " + line);
            }
            return line.substring(3);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    String alias(String dev, String mob, String acc, String svc) {
        return call(List.of("alias", hex(dev), hex(mob), hex(acc), hex(svc)));
    }

    String sha256b64(String s) {
        return call(List.of("sha256b64", hex(s)));
    }

    String sha1id35(String s) {
        return call(List.of("sha1id35", hex(s)));
    }

    String pac(int code, int debit) {
        return call(List.of("pac", Integer.toString(code), Integer.toString(debit)));
    }

    String counter(int code, double cur, double amt) {
        return call(List.of("counter", Integer.toString(code), Double.toString(cur), Double.toString(amt)));
    }

    @Override
    public void close() {
        try {
            stdin.write("QUIT\n".getBytes(StandardCharsets.UTF_8));
            stdin.flush();
        } catch (IOException ignored) {
        }
        process.destroy();
    }
}
