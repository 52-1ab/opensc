package in.captnemo.opensc;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

// Drives an external process implementing the sign/verify/pubkey line protocol
// documented in secure_component.c: one request line in, one response line
// out, over a pipe kept open across every call -- not a process forked per
// operation, which is what makes this usable under 1000-trial properties.
class PipeClient implements ScClient {

    private final String name;
    private final Process process;
    private final OutputStream stdin;
    private final BufferedReader stdout;
    private final Set<String> capabilities;

    PipeClient(String name, List<String> command) throws IOException {
        this.name = name;
        this.process = new ProcessBuilder(command).redirectErrorStream(false).start();
        this.stdin = process.getOutputStream();
        this.stdout = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8));

        String ready = readLine();
        if (ready == null || !ready.startsWith("READY ")) {
            throw new IllegalStateException(name + " did not send a READY handshake, got: " + ready);
        }
        String[] parts = ready.split(" ", 3);
        capabilities = parts.length > 2 ? Set.of(parts[2].split(",")) : Set.of();
    }

    @Override
    public String name() {
        return name;
    }

    boolean supports(String op) {
        return capabilities.contains(op);
    }

    @Override
    public byte[] sign(String alias, byte[] data, boolean useEc) throws IOException {
        String resp = call("sign", hex(alias.getBytes(StandardCharsets.UTF_8)), hex(data), useEc ? "01" : "00");
        return unhex(expectOk(resp, "sign"));
    }

    @Override
    public boolean verify(byte[] pubkeyDer, byte[] data, byte[] sig) throws IOException {
        String resp = call("verify", hex(pubkeyDer), hex(data), hex(sig));
        return unhex(expectOk(resp, "verify"))[0] != 0;
    }

    @Override
    public byte[] pubkey(String alias, String algorithm) throws IOException {
        String resp = call("pubkey", hex(alias.getBytes(StandardCharsets.UTF_8)), hex(algorithm.getBytes(StandardCharsets.UTF_8)));
        return unhex(expectOk(resp, "pubkey"));
    }

    private synchronized String call(String op, String... hexArgs) throws IOException {
        StringBuilder line = new StringBuilder(op);
        for (String a : hexArgs) line.append(' ').append(a);
        line.append('\n');
        stdin.write(line.toString().getBytes(StandardCharsets.UTF_8));
        stdin.flush();
        String resp = readLine();
        if (resp == null) {
            throw new IllegalStateException(name + " closed the pipe mid-call (op=" + op + ")");
        }
        return resp;
    }

    private String readLine() throws IOException {
        return stdout.readLine();
    }

    private static String expectOk(String resp, String op) {
        if (resp.equals("OK")) return "";
        if (resp.startsWith("OK ")) return resp.substring(3);
        throw new IllegalStateException(op + " failed: " + resp);
    }

    private static String hex(byte[] b) {
        return HexFormat.of().formatHex(b);
    }

    private static byte[] unhex(String s) {
        return s.isEmpty() ? new byte[0] : HexFormat.of().parseHex(s);
    }

    @Override
    public void close() throws Exception {
        try {
            stdin.write("QUIT\n".getBytes(StandardCharsets.UTF_8));
            stdin.flush();
            stdin.close();
        } catch (IOException ignored) {
            // the process may already be gone; waitFor below is what matters
        }
        if (!process.waitFor(5, TimeUnit.SECONDS)) {
            process.destroyForcibly();
        }
    }
}
