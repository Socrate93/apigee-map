package dev.apigeemap.protocol;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.Authenticator;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The client against a stand-in for the backend, which lives in its own repository (apigee-map-backend). */
class BackendClientTest {

    private final KeyPair keys = Keys.generate();
    private HttpServer server;

    @AfterEach
    void stop() {
        if (server != null) server.stop(0);
    }

    @Test
    void sealsTheRequestAndOpensTheResponse() throws IOException {
        start(request -> reply(request.get("id"), true, Map.of("type", request.get("type"),
                "token", request.get("token"), "body", request.get("body"))));
        Object body = client("secret-token").call("fix", Map.of("from", "test"));
        assertEquals(Map.of("type", "fix", "token", "secret-token", "body", Map.of("from", "test")), body);
    }

    /** While the backend answers that the operation runs, the client asks for its result. */
    @Test
    void asksForTheResultWhileTheOperationRuns() throws IOException {
        java.util.List<String> asked = new java.util.concurrent.CopyOnWriteArrayList<>();
        start(request -> {
            asked.add(request.get("type") + " " + request.get("poll") + " " + request.get("body"));
            if (asked.size() < 3) {
                Map<String, Object> pending = reply(request.get("id"), false, null);
                pending.put("status", 202);
                pending.put("pending", true);
                pending.put("job", "j1");
                return pending;
            }
            return reply(request.get("id"), true, "done");
        });
        assertEquals("done", client("t").call("testPlan", Map.of("proxy", "p")));
        assertEquals(java.util.List.of("testPlan true {proxy=p}", "result true {job=j1}", "result true {job=j1}"),
                asked);
    }

    /** The proxy credentials of the system properties go to the proxy only. */
    @Test
    void answersTheProxyWithTheCredentialsOfTheSystemProperties() {
        assertNull(BackendClient.proxyAuthenticator(), "no user, no authenticator");
        System.setProperty("https.proxyUser", "jdoe");
        System.setProperty("https.proxyPassword", "secret");
        try {
            Authenticator authenticator = BackendClient.proxyAuthenticator();
            PasswordAuthentication proxy = authenticator.requestPasswordAuthenticationInstance("proxy.corp", null,
                    3128, "http", "realm", "Basic", null, Authenticator.RequestorType.PROXY);
            assertEquals("jdoe", proxy.getUserName());
            assertEquals("secret", new String(proxy.getPassword()));
            assertNull(authenticator.requestPasswordAuthenticationInstance("backend", null, 443, "https", "realm",
                    "Basic", null, Authenticator.RequestorType.SERVER), "never sent to the backend");
        } finally {
            System.clearProperty("https.proxyUser");
            System.clearProperty("https.proxyPassword");
        }
    }

    /** The console gets the stack trace of a backend out of reach, and one line for a refusal. */
    @Test
    void reportsTheStackTraceOfConnectivityFailuresOnly() throws IOException {
        start(request -> reply(request.get("id"), true, null));
        BackendClient client = client("t");
        stop();
        IOException unreachable = assertThrows(BackendClient.Unreachable.class, () -> client.call("fix", null));
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        BackendClient.report(unreachable, new PrintStream(err));
        assertTrue(err.toString().startsWith("Backend call failed: Cannot reach the backend at "), err.toString());
        assertTrue(err.toString().contains("ConnectException") && err.toString().contains("\tat "), err.toString());

        err.reset();
        BackendClient.report(new IOException("The backend does not accept this client"), new PrintStream(err));
        assertEquals("Backend call failed: The backend does not accept this client" + System.lineSeparator(),
                err.toString());
    }

    @Test
    void reportsErrorsRejectionsAndForeignResponses() throws IOException {
        start(request -> reply(request.get("id"), false, null));
        assertTrue(assertThrows(IOException.class, () -> client("t").call("fix", null)).getMessage()
                .startsWith("Backend error"));
        stop();

        start(request -> reply("another id", true, null));
        assertEquals("The backend answered another request",
                assertThrows(IOException.class, () -> client("t").call("fix", null)).getMessage());
        stop();

        start(request -> {
            Map<String, Object> refused = reply(request.get("id"), false, null);
            refused.put("status", 401);
            return refused;
        });
        assertTrue(assertThrows(IOException.class, () -> client("t").call("fix", null)).getMessage()
                .contains("check the token"));
        stop();

        start(request -> null);
        assertTrue(assertThrows(IOException.class, () -> client("t").call("fix", null)).getMessage()
                .contains("could not read the request"));
    }

    @Test
    void requiresHttpsOutsideThisMachine() {
        assertThrows(IllegalArgumentException.class,
                () -> new BackendConfig(URI.create("http://backend.example.com"), keys.getPublic(), "t"));
        new BackendConfig(URI.create("https://backend.example.com"), keys.getPublic(), "t");
    }

    private static Map<String, Object> reply(Object id, boolean ok, Object body) {
        Map<String, Object> reply = new LinkedHashMap<>();
        reply.put("id", id);
        reply.put("ok", ok);
        if (ok) reply.put("body", body);
        else reply.put("error", "boom");
        return reply;
    }

    /**
     * Starts a backend that answers with {@code handler}, or, when it returns null, with the noise the backend gives
     * to a request it cannot open.
     */
    private void start(Function<Map<?, ?>, Map<String, Object>> handler) throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v1/exchange", exchange -> {
            try (exchange) {
                Envelope.Opened opened = Envelope.open(keys.getPrivate(), Keys.keyId(keys.getPublic()),
                        exchange.getRequestBody().readAllBytes());
                Map<String, Object> reply = handler.apply((Map<?, ?>) Json.parse(
                        new String(opened.plaintext(), StandardCharsets.UTF_8)));
                byte[] body = new byte[1053];
                new SecureRandom().nextBytes(body);
                body[0] = Envelope.VERSION;
                if (reply != null) body = opened.exchange().sealResponse(Json.write(reply).getBytes(StandardCharsets.UTF_8));
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

    private BackendClient client(String token) {
        return new BackendClient(new BackendConfig(URI.create("http://127.0.0.1:" + server.getAddress().getPort()),
                keys.getPublic(), token));
    }
}
