package dev.apigeemap;

import com.sun.net.httpserver.HttpServer;
import dev.apigeemap.protocol.BackendClient;
import dev.apigeemap.protocol.Envelope;
import dev.apigeemap.protocol.Json;
import dev.apigeemap.protocol.Keys;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The fix command against a stand-in for the backend, which answers with a canned proposal. */
class FixCommandTest {

    private final KeyPair keys = Keys.generate();
    private HttpServer server;

    @TempDir
    Path tmp;

    @AfterEach
    void stop() {
        if (server != null) server.stop(0);
    }

    @Test
    void sendsTheContextAndShowsTheProposalAsADiff() throws IOException {
        AtomicReference<Map<?, ?>> sent = new AtomicReference<>();
        Map<String, Object> edit = new LinkedHashMap<>();
        edit.put("bundle", "factorization-api");
        edit.put("path", "resources/jsc/audit-copy.js");
        edit.put("action", "delete");
        edit.put("content", null);
        edit.put("reason", "Same as audit.js");
        start(request -> {
            sent.set(request);
            return Map.of("summary", "JS-Audit-Copy runs audit.js instead of its copy.", "edits", List.of(edit),
                    "warnings", List.of("Check the audit log"), "model", "claude-opus-5-5",
                    "inputTokens", 1200, "outputTokens", 300);
        });

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        String[] args = {"examples/factorization-api", "--rule", "DES-10", "--at", "audit-copy.js",
                "--config", config().toString(), "-o", tmp.resolve("proposal.json").toString()};
        assertEquals(0, FixCommand.run(args, () -> "t", new PrintStream(out),
                new PrintStream(new ByteArrayOutputStream())));

        assertEquals("fix", sent.get().get("type"));
        assertEquals("t", sent.get().get("token"));
        Map<?, ?> body = (Map<?, ?>) sent.get().get("body");
        assertEquals("DES-10", ((Map<?, ?>) body.get("finding")).get("rule"));
        assertTrue(((List<?>) body.get("files")).stream().anyMatch(f -> "resources/jsc/audit-copy.js".equals(((Map<?, ?>) f).get("path"))));

        String shown = out.toString();
        assertTrue(shown.startsWith("DES-10 "), shown);
        assertFalse(shown.contains("claude") || shown.contains("tokens"), shown);
        assertTrue(shown.contains("  - Check the audit log"), shown);
        assertTrue(shown.contains("delete factorization-api/resources/jsc/audit-copy.js: Same as audit.js\n"
                + "--- a/resources/jsc/audit-copy.js\n+++ /dev/null\n@@ -1,"), shown);
        Map<?, ?> written = (Map<?, ?>) Json.parse(Files.readString(tmp.resolve("proposal.json")));
        assertEquals(List.of("summary", "warnings", "edits"), List.copyOf(written.keySet()));
    }

    /** One message whatever the cause, here a backend that fails on every request. */
    @Test
    void showsOneMessageWhenTheBackendFails() throws IOException {
        start(request -> {
            throw new IllegalStateException("down");
        });
        assertUnavailable("t");
    }

    /** Without a token a random one is sent all the same, which the backend refuses: the message is the same. */
    @Test
    void needsAToken() throws IOException {
        AtomicReference<Map<?, ?>> sent = new AtomicReference<>();
        start(request -> {
            sent.set(request);
            if (!"t".equals(request.get("token"))) throw new IllegalStateException("refused");
            return Map.of();
        });
        assertUnavailable("");
        assertEquals(22, ((String) sent.get().get("token")).length(), "looks like a real token");
    }

    private void assertUnavailable(String token) throws IOException {
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        String[] args = {"examples/factorization-api", "--rule", "DES-10", "--at", "audit-copy.js",
                "--config", config().toString()};
        assertEquals(1, FixCommand.run(args, () -> token, new PrintStream(new ByteArrayOutputStream()),
                new PrintStream(err)));
        assertTrue(err.toString().endsWith("error: " + BackendClient.UNAVAILABLE + System.lineSeparator()),
                err.toString());
    }

    private Path config() throws IOException {
        Path file = tmp.resolve("backend.properties");
        Files.writeString(file, "url=http://127.0.0.1:" + server.getAddress().getPort() + "\npublicKey="
                + Keys.encode(keys.getPublic()) + "\n");
        return file;
    }

    /** A backend that answers every request with {@code ok} and the body {@code handler} gives. */
    private void start(java.util.function.Function<Map<?, ?>, Object> handler) throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v1/exchange", exchange -> {
            try (exchange) {
                Envelope.Opened opened = Envelope.open(keys.getPrivate(), Keys.keyId(keys.getPublic()),
                        exchange.getRequestBody().readAllBytes());
                Map<?, ?> request = (Map<?, ?>) Json.parse(new String(opened.plaintext(), StandardCharsets.UTF_8));
                Map<String, Object> reply = new LinkedHashMap<>();
                reply.put("id", request.get("id"));
                reply.put("ok", true);
                reply.put("body", handler.apply(request));
                byte[] body = opened.exchange().sealResponse(Json.write(reply).getBytes(StandardCharsets.UTF_8));
                exchange.sendResponseHeaders(200, body.length);
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(body);
                }
            } catch (Exception e) {
                exchange.sendResponseHeaders(500, -1);
            }
        });
        server.start();
    }
}
