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
    private final List<Map<?, ?>> groupedFixes = new CopyOnWriteArrayList<>();
    private final List<Map<?, ?>> triages = new CopyOnWriteArrayList<>();
    private final List<Map<?, ?>> documented = new CopyOnWriteArrayList<>();
    private final List<Map<?, ?>> ported = new CopyOnWriteArrayList<>();
    private final List<Map<?, ?>> planned = new CopyOnWriteArrayList<>();
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

    @Test
    void fixesSeveralFindingsTogetherAsOneStep() throws Exception {
        List<Map<?, ?>> manual = findings(detail()).stream().filter(f -> f.get("fix").equals("MANUAL")).toList();
        assertTrue(manual.size() > 2, manual.toString());
        List<Map<String, Object>> picked = manual.stream().limit(UiService.MAX_GROUPED).map(f -> Map.<String, Object>of(
                "bundle", f.get("bundle"), "rule", f.get("rule"), "location", f.get("location"))).toList();

        HttpResponse<String> response = send("/api/fix/all?id=factorization-api", "POST",
                Json.write(Map.of("findings", picked)));
        assertEquals(200, response.statusCode(), response.body());
        Map<?, ?> proposal = (Map<?, ?>) Json.parse(response.body());
        assertEquals(picked.size(), ((List<?>) proposal.get("findings")).size());
        assertEquals(Files.readString(bundle.resolve(COPY)),
                ((Map<?, ?>) ((List<?>) proposal.get("edits")).get(0)).get("before"));

        Map<?, ?> sent = groupedFixes.get(0);
        assertEquals(picked.size(), ((List<?>) sent.get("findings")).size());
        List<String> files = ((List<?>) sent.get("files")).stream()
                .map(f -> ((Map<?, ?>) f).get("bundle") + "/" + ((Map<?, ?>) f).get("path")).toList();
        assertEquals(files.size(), files.stream().distinct().count(), "each file once: " + files);
        assertTrue(files.contains("factorization-api/" + COPY), files.toString());

        HttpResponse<String> accepted = post("/api/fix/accept?proposal=" + proposal.get("proposal"));
        assertEquals(200, accepted.statusCode(), accepted.body());
        assertFalse(Files.exists(bundle.resolve(COPY)));
        Map<?, ?> step = (Map<?, ?>) ((List<?>) ((Map<?, ?>) ((List<?>) Json.parse(
                get("/api/history?id=factorization-api").body())).get(0)).get("steps")).get(0);
        assertEquals("Fixes of " + picked.size() + " finding(s) (proposed fix)", step.get("title"));
        assertTrue(((String) step.get("message")).contains("Findings:\n- " + picked.get(0).get("rule") + " "),
                (String) step.get("message"));

        assertEquals(400, send("/api/fix/all?id=factorization-api", "POST",
                Json.write(Map.of("findings", List.of()))).statusCode());
        assertEquals(400, send("/api/fix/all?id=factorization-api", "POST", Json.write(Map.of("findings",
                java.util.Collections.nCopies(UiService.MAX_GROUPED + 1, picked.get(0))))).statusCode());
    }

    @Test
    void triagesFindingsWithoutMarkingAnything() throws Exception {
        List<Map<?, ?>> all = findings(detail());
        List<Map<String, Object>> picked = all.stream().limit(UiService.MAX_TRIAGE)
                .map(f -> Map.<String, Object>of("bundle", f.get("bundle"), "rule", f.get("rule"),
                        "location", f.get("location"))).toList();

        HttpResponse<String> response = send("/api/triage?id=factorization-api", "POST",
                Json.write(Map.of("findings", picked)));
        assertEquals(200, response.statusCode(), response.body());
        Map<String, Object> expected = new LinkedHashMap<>(picked.get(0));
        expected.put("reason", "Set by an earlier step.");
        assertEquals(Map.of("falsePositives", List.of(expected)), Json.parse(response.body()),
                "only the findings sent, and nothing about how the triage is made");

        Map<?, ?> sent = triages.get(0);
        assertEquals(picked.size(), ((List<?>) sent.get("findings")).size());
        assertTrue(sent.get("files") instanceof List<?> files && !files.isEmpty(), sent.toString());
        assertEquals(all, findings(detail()), "nothing is marked until confirmed");

        assertEquals(400, send("/api/triage?id=factorization-api", "POST",
                Json.write(Map.of("findings", List.of()))).statusCode());
        backend.stop(0);
        assertEquals(Map.of("error", BackendClient.UNAVAILABLE), Json.parse(send("/api/triage?id=factorization-api",
                "POST", Json.write(Map.of("findings", picked))).body()));
    }

    @Test
    void writesKeepsAndReportsTheDocumentation() throws Exception {
        assertEquals("{}", get("/api/document?id=factorization-api").body(), "never written");
        assertEquals(409, get("/api/document/export?id=factorization-api").statusCode());
        assertFalse(get("/api/report?id=factorization-api").body().contains("What the proxy does"));

        HttpResponse<String> response = post("/api/document?id=factorization-api");
        assertEquals(200, response.statusCode(), response.body());
        Map<?, ?> written = (Map<?, ?>) Json.parse(response.body());
        assertEquals(List.of("doc", "written", "current"), List.copyOf(written.keySet()));
        assertEquals(true, written.get("current"));
        Map<?, ?> doc = (Map<?, ?>) written.get("doc");
        assertEquals("Factors numbers.", doc.get("summary"));
        assertEquals(1, ((List<?>) doc.get("operations")).size(), "an operation without description is left out");
        assertEquals(List.of("`VerifyAPIKey` on every request"), doc.get("security"));

        Map<?, ?> sent = documented.get(0);
        assertEquals("factorization-api", sent.get("proxy"));
        List<?> files = (List<?>) sent.get("files");
        assertTrue(files.stream().anyMatch(f -> ((Map<?, ?>) f).get("path").equals("resources/jsc/audit.js")),
                files.toString());
        assertTrue(files.stream().allMatch(f -> ((Map<?, ?>) f).get("bundle") instanceof String), files.toString());

        assertEquals(written, Json.parse(get("/api/document?id=factorization-api").body()), "kept");
        HttpResponse<String> markdown = get("/api/document/export?id=factorization-api");
        assertEquals(200, markdown.statusCode());
        assertEquals("attachment; filename=\"factorization-api.md\"",
                markdown.headers().firstValue("Content-Disposition").orElse(""));
        assertTrue(markdown.body().startsWith("# factorization-api\n") && markdown.body().contains(
                "| `GET` | `/factors/{n}` | Factors | Returns the prime factors of `n`. |"), markdown.body());
        String report = get("/api/report?id=factorization-api").body();
        assertTrue(report.contains("What the proxy does") && report.contains("Returns the prime factors of <code>n</code>.")
                && !report.contains("may be out of date"), report);

        Files.writeString(bundle.resolve(COPY), "// changed\n", java.nio.file.StandardOpenOption.APPEND);
        assertEquals(false, ((Map<?, ?>) Json.parse(get("/api/document?id=factorization-api").body())).get("current"));
        assertTrue(get("/api/report?id=factorization-api").body().contains("may be out of date"));

        backend.stop(0);
        assertEquals(Map.of("error", BackendClient.UNAVAILABLE),
                Json.parse(post("/api/document?id=factorization-api").body()));
        assertEquals("Factors numbers.", ((Map<?, ?>) ((Map<?, ?>) Json.parse(get("/api/document?id=factorization-api")
                .body())).get("doc")).get("summary"), "a failure keeps what was written");
    }

    @Test
    void preparesKeepsAndRunsTheTestPlan() throws Exception {
        Map<?, ?> never = (Map<?, ?>) Json.parse(get("/api/tests?id=factorization-api").body());
        assertEquals(List.of("profile"), List.copyOf(never.keySet()), "never prepared");
        assertEquals(Map.of("kind", "standard", "grants", List.of(), "operations", List.of()), never.get("profile"));
        HttpResponse<String> refused = send("/api/tests/run?id=factorization-api", "POST",
                Json.write(Map.of("edge", "http://127.0.0.1:1", "hybrid", "http://127.0.0.1:1")));
        assertEquals(409, refused.statusCode(), refused.body());

        HttpResponse<String> response = post("/api/tests?id=factorization-api");
        assertEquals(200, response.statusCode(), response.body());
        Map<?, ?> prepared = (Map<?, ?>) Json.parse(response.body());
        assertEquals(List.of("plan", "written", "current", "targets", "uncovered"), List.copyOf(prepared.keySet()));
        List<?> targets = (List<?>) prepared.get("targets");
        assertTrue(!targets.isEmpty() && targets.equals(planned.get(0).get("targets")), "sent to be covered");
        assertEquals(targets.stream().map(t -> ((Map<?, ?>) t).get("id")).toList(), prepared.get("uncovered"),
                "no case says what it covers");
        Map<?, ?> plan = (Map<?, ?>) prepared.get("plan");
        assertEquals("Covers the factors flow.", plan.get("summary"));
        assertEquals(1, ((List<?>) plan.get("cases")).size(), "a case with an unknown method is left out");
        assertEquals("factorization-api", planned.get(0).get("proxy"));
        assertEquals(Map.of("kind", "standard", "grants", List.of(), "operations", List.of()),
                planned.get(0).get("profile"));
        Map<?, ?> kept = new java.util.LinkedHashMap<>((Map<?, ?>) Json.parse(get("/api/tests?id=factorization-api")
                .body()));
        kept.remove("profile");
        assertEquals(prepared, kept, "kept");

        HttpResponse<String> forced = send("/api/tests?id=factorization-api", "POST", Json.write(Map.of(
                "profile", "authorizationServer", "loginForm", Map.of("user", "username", "password", "pass\nword"))));
        assertEquals(200, forced.statusCode(), forced.body());
        assertEquals(Map.of("kind", "authorizationServer", "grants", List.of(), "operations", List.of(),
                "loginForm", Map.of("user", "username", "password", "password")), planned.get(1).get("profile"),
                "chosen, with only field names passed on");
        prepared = (Map<?, ?>) Json.parse(forced.body());

        HttpResponse<String> badUrl = send("/api/tests/run?id=factorization-api", "POST",
                Json.write(Map.of("edge", "ftp://edge", "hybrid", "http://127.0.0.1:1")));
        assertEquals(400, badUrl.statusCode(), badUrl.body());
        assertTrue(badUrl.body().contains("Edge URL"), badUrl.body());

        HttpServer environment = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        List<String> keys = new CopyOnWriteArrayList<>();
        environment.createContext("/", exchange -> {
            keys.add(exchange.getRequestURI().getPath() + " " + exchange.getRequestHeaders().getFirst("x-apikey"));
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
        });
        environment.start();
        try {
            String url = "http://127.0.0.1:" + environment.getAddress().getPort();
            Map<?, ?> run = (Map<?, ?>) Json.parse(send("/api/tests/run?id=factorization-api", "POST",
                    Json.write(Map.of("edge", url + "/", "hybrid", url, "values", Map.of("apikey", "k1")))).body());
            assertEquals(url, run.get("edge"), "the trailing slash is dropped");
            Map<?, ?> result = (Map<?, ?>) ((List<?>) run.get("results")).get(0);
            assertEquals("SAME", result.get("outcome"), result.toString());
            assertEquals(List.of("/factorization/factors/12 k1", "/factorization/factors/12 k1"), keys);
        } finally {
            environment.stop(0);
        }

        backend.stop(0);
        assertEquals(Map.of("error", BackendClient.UNAVAILABLE),
                Json.parse(post("/api/tests?id=factorization-api").body()));
        Map<?, ?> still = new java.util.LinkedHashMap<>((Map<?, ?>) Json.parse(get("/api/tests?id=factorization-api")
                .body()));
        still.remove("profile");
        assertEquals(prepared, still, "a failure keeps what was prepared");
    }

    @Test
    void portsANodeTargetToAServiceOfItsOwn() throws Exception {
        String node = "<TargetEndpoint name=\"node\">\n    <ScriptTarget>\n        <ResourceURL>node://server.js</ResourceURL>\n"
                + "    </ScriptTarget>\n</TargetEndpoint>\n";
        Files.writeString(bundle.resolve("targets/node.xml"), node);
        Files.createDirectories(bundle.resolve("resources/node/node_modules/left-pad"));
        Files.writeString(bundle.resolve("resources/node/server.js"), "require('http').createServer();\n");
        Files.writeString(bundle.resolve("resources/node/node_modules/left-pad/index.js"), "module.exports = 1;\n");
        Map<?, ?> finding = findings(detail()).stream().filter(f -> f.get("rule").equals("HYB-04")).findFirst()
                .orElseThrow();
        assertEquals("TargetEndpoint node", finding.get("location"));
        String picked = Json.write(Map.of("bundle", finding.get("bundle"), "rule", "HYB-04", "location", "TargetEndpoint node"));

        HttpResponse<String> response = send("/api/port?id=factorization-api", "POST", picked);
        assertEquals(200, response.statusCode(), response.body());
        Map<?, ?> proposal = (Map<?, ?>) Json.parse(response.body());
        assertEquals("SERVICE", proposal.get("approach"));
        Map<?, ?> service = (Map<?, ?>) proposal.get("service");
        Path folder = tmp.resolve("services/factorization-api/factorization-node").toAbsolutePath();
        assertEquals(folder.toString(), service.get("folder"));
        assertEquals(List.of("Deploy it"), service.get("steps"));
        List<?> sent = (List<?>) ported.get(0).get("files");
        List<String> paths = sent.stream().map(f -> String.valueOf(((Map<?, ?>) f).get("path"))).toList();
        assertTrue(paths.containsAll(List.of("targets/node.xml", "resources/node/server.js", "proxies/default.xml")),
                paths.toString());
        assertFalse(paths.stream().anyMatch(p -> p.toString().contains("node_modules")), paths.toString());
        assertFalse(Files.exists(folder), "nothing is written before accept");

        Files.createDirectories(folder);
        Files.writeString(folder.resolve("old.txt"), "x");
        HttpResponse<String> taken = post("/api/fix/accept?proposal=" + proposal.get("proposal"));
        assertEquals(409, taken.statusCode(), taken.body());
        assertEquals(node, Files.readString(bundle.resolve("targets/node.xml")), "nothing written when the folder is taken");
        Files.delete(folder.resolve("old.txt"));

        HttpResponse<String> accepted = post("/api/fix/accept?proposal=" + proposal.get("proposal"));
        assertEquals(200, accepted.statusCode(), accepted.body());
        assertTrue(Files.readString(bundle.resolve("targets/node.xml")).contains("factorization-node"));
        assertFalse(Files.exists(bundle.resolve("resources/node/server.js")));
        assertEquals("FROM node:22\n", Files.readString(folder.resolve("Dockerfile")));
        assertEquals("require('http');\n", Files.readString(folder.resolve("src/server.js")));
        Map<?, ?> step = (Map<?, ?>) ((List<?>) ((Map<?, ?>) ((List<?>) Json.parse(get("/api/history?id=factorization-api")
                .body())).get(0)).get("steps")).get(0);
        assertEquals("Port of TargetEndpoint node (proposed port)", step.get("title"));
        assertTrue(step.get("message").toString().contains("TargetServer factorization-node: factorization-node.example.run.app:443"),
                step.get("message").toString());

        Map<?, ?> other = findings(detail()).stream().filter(f -> !f.get("rule").equals("HYB-04")).findFirst().orElseThrow();
        assertEquals(400, send("/api/port?id=factorization-api", "POST", Json.write(Map.of("bundle", other.get("bundle"),
                "rule", other.get("rule"), "location", other.get("location")))).statusCode());
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
                if (request.get("type").equals("triage")) {
                    Map<?, ?> body = (Map<?, ?>) request.get("body");
                    triages.add(body);
                    Map<?, ?> first = (Map<?, ?>) ((List<?>) body.get("findings")).get(0);
                    reply.put("body", Map.of("falsePositives", List.of(
                            Map.of("bundle", first.get("bundle"), "rule", first.get("rule"),
                                    "location", first.get("location"), "reason", " Set by an earlier step. "),
                            Map.of("bundle", "other-api", "rule", "DES-10", "location", "x", "reason", "Not sent"))));
                    seal(exchange, opened, reply);
                    return;
                }
                if (request.get("type").equals("document")) {
                    documented.add((Map<?, ?>) request.get("body"));
                    reply.put("body", Map.of("summary", " Factors numbers. ",
                            "operations", List.of(Map.of("method", "GET", "path", "/factors/{n}", "flow", "Factors",
                                    "description", "Returns the prime factors of `n`."), Map.of("method", "GET")),
                            "security", List.of("`VerifyAPIKey` on every request", " "),
                            "dependencies", List.of(Map.of("name", "math-backend", "kind", "TARGET",
                                    "description", "Computes the factors")),
                            "errors", List.of(), "notes", List.of("Nothing else.")));
                    seal(exchange, opened, reply);
                    return;
                }
                if (request.get("type").equals("testPlan")) {
                    planned.add((Map<?, ?>) request.get("body"));
                    reply.put("body", Map.of("summary", " Covers the factors flow. ",
                            "variables", List.of(Map.of("name", "apikey", "description", "A consumer key")),
                            "cases", List.of(
                                    Map.of("name", "Factors of 12", "flow", "Factors", "method", "GET",
                                            "path", "/factorization/factors/12",
                                            "headers", List.of(Map.of("name", "x-apikey", "value", "{{apikey}}")),
                                            "body", "", "expectedStatus", 200, "compareHeaders", List.of("content-type"),
                                            "safe", true, "purpose", "Returns the factors."),
                                    Map.of("name", "Unknown method", "method", "TRACE", "path", "/factorization")),
                            "warnings", List.of("Create an app on both environments")));
                    seal(exchange, opened, reply);
                    return;
                }
                if (request.get("type").equals("port")) {
                    ported.add((Map<?, ?>) request.get("body"));
                    Map<String, Object> deleted = new LinkedHashMap<>();
                    deleted.put("bundle", "factorization-api");
                    deleted.put("path", "resources/node/server.js");
                    deleted.put("action", "delete");
                    deleted.put("content", null);
                    deleted.put("reason", "Moved to the service");
                    Map<String, Object> body = new LinkedHashMap<>();
                    body.put("summary", "Moves the application to Cloud Run.");
                    body.put("approach", "SERVICE");
                    body.put("edits", List.of(Map.of("bundle", "factorization-api", "path", "targets/node.xml",
                            "action", "replace", "reason", "Targets the service", "content",
                            "<TargetEndpoint name=\"node\"><HTTPTargetConnection><LoadBalancer><Server name=\"factorization-node\"/>"
                                    + "</LoadBalancer></HTTPTargetConnection></TargetEndpoint>\n"), deleted));
                    body.put("warnings", List.of());
                    body.put("service", Map.of("name", "factorization-node", "runtime", "Node.js 22 on Cloud Run",
                            "files", List.of(Map.of("path", "src/server.js", "content", "require('http');\n"),
                                    Map.of("path", "Dockerfile", "content", "FROM node:22\n")),
                            "targetServer", Map.of("name", "factorization-node",
                                    "host", "factorization-node.example.run.app", "port", 443, "sslEnabled", true),
                            "steps", List.of("Deploy it")));
                    reply.put("body", body);
                    seal(exchange, opened, reply);
                    return;
                }
                if (request.get("type").equals("fixAll")) groupedFixes.add((Map<?, ?>) request.get("body"));
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
