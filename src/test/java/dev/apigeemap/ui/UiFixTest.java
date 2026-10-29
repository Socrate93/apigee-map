package dev.apigeemap.ui;

import com.sun.net.httpserver.HttpServer;
import dev.apigeemap.protocol.BackendClient;
import dev.apigeemap.protocol.Envelope;
import dev.apigeemap.protocol.Json;
import dev.apigeemap.protocol.Keys;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Fixes and script reviews asked from the UI against a stand-in for the backend, written to a copy of an example
 * bundle.
 */
class UiFixTest {

    private static final Path EXAMPLES = Path.of("examples").toAbsolutePath();
    private static final String COPY = "resources/jsc/audit-copy.js";

    @TempDir
    Path tmp;

    private final KeyPair keys = Keys.generate();
    private final HttpClient http = HttpClient.newHttpClient();
    private final List<String> tokens = new CopyOnWriteArrayList<>();
    private final List<Map<?, ?>> reviews = new CopyOnWriteArrayList<>();
    private HttpServer backend;
    private UiServer server;
    private Path bundle;

    @BeforeEach
    void start() throws Exception {
        copy(EXAMPLES.resolve("factorization-api"), tmp.resolve("proxies/factorization-api"));
        bundle = tmp.resolve("proxies/factorization-api/apiproxy");
        startBackend();
        Path settings = tmp.resolve("settings.json");
        new Settings(tmp.resolve("proxies").toString(), List.of(), tmp.resolve("out").toString(), List.of(), Map.of(),
                Map.of(), List.of()).save(settings);
        Path config = tmp.resolve("backend.properties");
        Files.writeString(config, "url=http://127.0.0.1:" + backend.getAddress().getPort() + "\npublicKey="
                + Keys.encode(keys.getPublic()) + "\n");
        server = UiServer.start(settings, tmp.resolve("history"), config, 0);
        HttpResponse<String> saved = send("/api/token", "PUT", Json.write(Map.of("token", "t")));
        assertEquals(200, saved.statusCode());
        assertEquals("{}", saved.body(), "the token is never sent back");
    }

    @AfterEach
    void stop() {
        if (server != null) server.stop();
        if (backend != null) backend.stop(0);
    }

    @Test
    void proposesAcceptsRecordsAndUndoesAFix() throws Exception {
        String original = Files.readString(bundle.resolve(COPY));
        Map<?, ?> proposal = propose();
        Map<?, ?> edit = (Map<?, ?>) ((List<?>) proposal.get("edits")).get(0);
        assertEquals(original, edit.get("before"));
        assertFalse(proposal.containsKey("model") || proposal.containsKey("inputTokens"), proposal.toString());
        assertEquals(null, edit.get("after"));
        assertTrue(Files.exists(bundle.resolve(COPY)), "nothing is written before accept");
        assertEquals("[]", get("/api/history?id=factorization-api").body());

        HttpResponse<String> accepted = post("/api/fix/accept?proposal=" + proposal.get("proposal"));
        assertEquals(200, accepted.statusCode(), accepted.body());
        assertFalse(Files.exists(bundle.resolve(COPY)));
        String step = (String) ((Map<?, ?>) ((List<?>) Json.parse(accepted.body())).get(0)).get("id");

        Map<?, ?> history = (Map<?, ?>) ((List<?>) Json.parse(get("/api/history?id=factorization-api").body())).get(0);
        List<?> steps = (List<?>) history.get("steps");
        assertEquals(2, steps.size());
        assertEquals("DES-10 Duplicated scripts (proposed fix)", ((Map<?, ?>) steps.get(0)).get("title"));
        assertEquals(true, ((Map<?, ?>) steps.get(1)).get("original"));
        String diff = (String) ((Map<?, ?>) Json.parse(get("/api/history/diff?id=factorization-api&bundle="
                + "factorization-api&step=" + step).body())).get("diff");
        assertTrue(diff.contains("deleted file") && diff.contains(COPY), diff);

        assertEquals(404, post("/api/fix/accept?proposal=" + proposal.get("proposal")).statusCode(), "used once");
        assertEquals(200, post("/api/history/revert?id=factorization-api&bundle=factorization-api&step=" + step)
                .statusCode());
        assertEquals(original, Files.readString(bundle.resolve(COPY)));
    }

    @Test
    void refusesAProposalWhenTheFileChangedSince() throws Exception {
        Map<?, ?> proposal = propose();
        Files.writeString(bundle.resolve(COPY), "// changed by hand\n");
        HttpResponse<String> accepted = post("/api/fix/accept?proposal=" + proposal.get("proposal"));
        assertEquals(409, accepted.statusCode());
        assertTrue(accepted.body().contains("changed since the fix was proposed"), accepted.body());
        assertTrue(Files.exists(bundle.resolve(COPY)));
    }

    @Test
    void rejectingDropsTheProposal() throws Exception {
        Map<?, ?> proposal = propose();
        assertEquals(200, post("/api/fix/reject?proposal=" + proposal.get("proposal")).statusCode());
        assertEquals(404, post("/api/fix/accept?proposal=" + proposal.get("proposal")).statusCode());
        assertTrue(Files.exists(bundle.resolve(COPY)));
    }

    /** One message whatever the cause, here a backend that is gone. */
    @Test
    void showsOneMessageWhenTheBackendFails() throws Exception {
        backend.stop(0);
        backend = null;
        HttpResponse<String> response = askFix();
        assertEquals(200, response.statusCode());
        assertEquals(Map.of("error", BackendClient.UNAVAILABLE), Json.parse(response.body()));
    }

    /** Forgetting the token (a blank one) still calls the backend, with a random token it refuses. */
    @Test
    void needsAToken() throws Exception {
        assertEquals(200, send("/api/token", "PUT", Json.write(Map.of("token", " "))).statusCode());
        assertEquals(Map.of("error", BackendClient.UNAVAILABLE), Json.parse(askFix().body()));
        assertEquals(1, tokens.size(), "the request is sent all the same");
        assertEquals(22, tokens.get(0).length(), "looks like a real token");
    }

    @Test
    void reviewsTheScriptsOnceAndReportsTheRemarksWhileTheScriptIsUnchanged() throws Exception {
        Map<?, ?> scripts = (Map<?, ?>) detail().get("scripts");
        int total = ((Number) scripts.get("total")).intValue();
        assertTrue(total >= 4, scripts.toString());
        assertEquals(0.0, scripts.get("reviewed"));

        HttpResponse<String> reviewed = post("/api/review?id=factorization-api");
        assertEquals(200, reviewed.statusCode(), reviewed.body());
        assertEquals(Map.of("reviewed", (double) total, "remarks", 1.0), Json.parse(reviewed.body()));
        Map<?, ?> request = reviews.get(0);
        String sent = Json.write(request);
        assertTrue(sent.contains("\"file\": \"resources/jsc/broken.js\""), sent);
        assertTrue(((List<?>) request.get("files")).stream().anyMatch(f -> ((Map<?, ?>) f).get("path")
                .equals("resources/jsc/broken.js")), "the scripts are sent");
        assertTrue(sent.contains("\"rule\": \"DES-10\""), "with the findings already reported on them");

        Map<?, ?> detail = detail();
        assertEquals((double) total, ((Map<?, ?>) detail.get("scripts")).get("reviewed"));
        Map<?, ?> finding = findings(detail).stream().filter(f -> f.get("rule").equals("REV-01")).findFirst()
                .orElseThrow();
        assertEquals("resources/jsc/broken.js:2 Secret in the code", finding.get("location"));
        assertEquals("SECURITY", finding.get("category"));
        assertEquals("ERROR", finding.get("severity"));
        assertEquals(1, findings(detail).stream().filter(f -> f.get("rule").equals("REV-01")).count());
        assertTrue(Files.list(tmp.resolve("reviews")).count() >= total - 1, "kept by script");

        assertEquals(Map.of("reviewed", 0.0, "remarks", 0.0),
                Json.parse(post("/api/review?id=factorization-api").body()), "nothing left to review");
        assertEquals(1, reviews.size());

        Files.writeString(bundle.resolve("resources/jsc/broken.js"), "// changed by hand\n");
        detail = detail();
        assertEquals((double) total - 1, ((Map<?, ?>) detail.get("scripts")).get("reviewed"));
        assertFalse(findings(detail).stream().anyMatch(f -> f.get("rule").equals("REV-01")),
                "a remark goes with the script it was made on");

        assertEquals(200, post("/api/review?id=factorization-api&again=true").statusCode());
        assertEquals(total, ((List<?>) reviews.get(1).get("scripts")).size(), "again reviews every script");
    }

    private Map<?, ?> detail() throws Exception {
        return (Map<?, ?>) Json.parse(get("/api/proxy?id=factorization-api").body());
    }

    private static List<Map<?, ?>> findings(Map<?, ?> detail) {
        return ((List<?>) ((Map<?, ?>) detail.get("migration")).get("bundles")).stream()
                .flatMap(b -> ((List<?>) ((Map<?, ?>) b).get("findings")).stream()).<Map<?, ?>>map(f -> (Map<?, ?>) f)
                .toList();
    }

    private Map<?, ?> propose() throws Exception {
        HttpResponse<String> response = askFix();
        assertEquals(200, response.statusCode(), response.body());
        return (Map<?, ?>) Json.parse(response.body());
    }

    /** Asks for the fix of the DES-10 finding at the copy of audit.js. */
    private HttpResponse<String> askFix() throws Exception {
        Map<?, ?> detail = (Map<?, ?>) Json.parse(get("/api/proxy?id=factorization-api").body());
        Map<?, ?> finding = ((List<?>) ((Map<?, ?>) detail.get("migration")).get("bundles")).stream()
                .flatMap(b -> ((List<?>) ((Map<?, ?>) b).get("findings")).stream()).map(f -> (Map<?, ?>) f)
                .filter(f -> f.get("rule").equals("DES-10") && ((String) f.get("location")).contains("audit-copy.js"))
                .findFirst().orElseThrow();
        return send("/api/fix?id=factorization-api", "POST", Json.write(Map.of(
                "bundle", finding.get("bundle"), "rule", "DES-10", "location", finding.get("location"))));
    }

    /** A backend that proposes to delete the copy of audit.js. */
    private void startBackend() throws IOException {
        backend = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        backend.createContext("/v1/exchange", exchange -> {
            try (exchange) {
                Envelope.Opened opened = Envelope.open(keys.getPrivate(), Keys.keyId(keys.getPublic()),
                        exchange.getRequestBody().readAllBytes());
                Map<?, ?> request = (Map<?, ?>) Json.parse(new String(opened.plaintext(), StandardCharsets.UTF_8));
                tokens.add((String) request.get("token"));
                if (!"t".equals(request.get("token"))) throw new IllegalStateException("refused");
                Map<String, Object> reply = new LinkedHashMap<>();
                reply.put("id", request.get("id"));
                reply.put("ok", true);
                if (request.get("type").equals("review")) {
                    reviews.add((Map<?, ?>) request.get("body"));
                    reply.put("body", Map.of("remarks", List.of(
                            Map.of("bundle", "factorization-api", "file", "resources/jsc/broken.js", "line", 2,
                                    "category", "SECURITY", "severity", "ERROR", "title", "Secret in the code",
                                    "message", "A password is written in the script.", "action", "Read it from a KVM."),
                            Map.of("bundle", "factorization-api", "file", "proxies/default.xml", "line", 1,
                                    "category", "DESIGN", "severity", "WARN", "title", "Not a script",
                                    "message", "Ignored.", "action", ""))));
                    seal(exchange, opened, reply);
                    return;
                }
                Map<String, Object> edit = new LinkedHashMap<>();
                edit.put("bundle", "factorization-api");
                edit.put("path", COPY);
                edit.put("action", "delete");
                edit.put("content", null);
                edit.put("reason", "Same as audit.js");
                reply.put("body", Map.of("summary", "Keep one copy.", "edits", List.of(edit), "warnings", List.of(),
                        "model", "claude-test", "inputTokens", 10, "outputTokens", 5));
                seal(exchange, opened, reply);
            } catch (Exception e) {
                exchange.sendResponseHeaders(500, -1);
            }
        });
        backend.start();
    }

    private static void seal(com.sun.net.httpserver.HttpExchange exchange, Envelope.Opened opened,
                             Map<String, Object> reply) throws Exception {
        byte[] body = opened.exchange().sealResponse(Json.write(reply).getBytes(StandardCharsets.UTF_8));
        exchange.sendResponseHeaders(200, body.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(body);
        }
    }

    private static void copy(Path from, Path to) throws IOException {
        try (Stream<Path> paths = Files.walk(from)) {
            for (Path path : paths.sorted(Comparator.naturalOrder()).toList()) {
                Path target = to.resolve(from.relativize(path).toString());
                if (Files.isDirectory(path)) Files.createDirectories(target);
                else Files.copy(path, target);
            }
        }
    }

    private HttpResponse<String> get(String path) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create(server.url() + path.substring(1))).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> post(String path) throws Exception {
        return send(path, "POST", "");
    }

    private HttpResponse<String> send(String path, String method, String body) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create(server.url() + path.substring(1)))
                .method(method, HttpRequest.BodyPublishers.ofString(body)).header(UiServer.CSRF_HEADER, "1").build(),
                HttpResponse.BodyHandlers.ofString());
    }
}
