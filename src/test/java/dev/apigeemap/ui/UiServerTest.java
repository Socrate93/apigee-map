package dev.apigeemap.ui;

import dev.apigeemap.protocol.Json;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UiServerTest {

    private static final Path EXAMPLES = Path.of("examples").toAbsolutePath();

    @TempDir
    Path tmp;

    private UiServer server;
    private final HttpClient http = HttpClient.newHttpClient();

    @BeforeEach
    void start() throws IOException {
        Path settings = tmp.resolve("settings.json");
        new Settings(EXAMPLES.toString(), List.of(EXAMPLES.resolve("sharedflows").toString()),
                tmp.resolve("out").toString(), List.of(), Map.of(), Map.of(), List.of()).save(settings);
        restart();
    }

    private void restart() throws IOException {
        if (server != null) server.stop();
        server = UiServer.start(tmp.resolve("settings.json"), tmp.resolve("history"), tmp.resolve("backend.properties"), 0);
    }

    @AfterEach
    void stop() {
        server.stop();
    }

    @Test
    void servesThePageAndAssets() throws Exception {
        assertTrue(get("/").body().contains("<script src=\"/assets/app.js\">"));
        assertEquals(200, get("/assets/app.js").statusCode());
        assertEquals(200, get("/assets/app.css").statusCode());
    }

    @Test
    void listsProxiesWithoutAnalyzingThem() throws Exception {
        List<?> proxies = listed();
        assertEquals(4, proxies.size());
        Map<?, ?> orders = listed("orders-api");
        assertEquals(0.0, orders.get("sharedFlows"));
        assertNull(orders.get("analyzed"));
        assertFalse(Files.exists(tmp.resolve("stats.json")));
    }

    @Test
    void listsTheFiguresOfTheLastAnalysisAfterARestart() throws Exception {
        Map<?, ?> analyzed = (Map<?, ?>) Json.parse(post("/api/proxies/analyze").body());
        assertEquals(4.0, analyzed.get("analyzed"));
        assertEquals(0.0, analyzed.get("failed"));

        restart();
        Map<?, ?> orders = listed("orders-api");
        assertEquals(2.0, orders.get("sharedFlows"));
        assertEquals(false, orders.get("migrated"));
        assertEquals(false, orders.get("outdated"));
        assertTrue(((Double) orders.get("errors")) + ((Double) orders.get("warnings")) > 0);
        assertNotNull(orders.get("analyzed"));
    }

    @Test
    void analyzingAProxyUpdatesTheList() throws Exception {
        post("/api/proxy/analyze?id=orders-api");
        assertEquals(2.0, listed("orders-api").get("sharedFlows"));
        assertNull(listed("factorization-api").get("analyzed"), "only that proxy was analyzed");

        get("/api/overview");
        assertNotNull(listed("factorization-api").get("analyzed"));
    }

    @Test
    void anUnreadableStatsFileOnlyMeansAnalyzingAgain() throws Exception {
        post("/api/proxies/analyze");
        Files.writeString(tmp.resolve("stats.json"), "{\"broken");
        restart();
        assertNull(listed("orders-api").get("analyzed"));
    }

    @Test
    void flagsWhatChangedSinceTheAnalysisAndAnalyzesOnlyThat() throws Exception {
        Path root = tmp.resolve("proxies");
        copy(EXAMPLES.resolve("orders-api"), root.resolve("orders-api"));
        copy(EXAMPLES.resolve("orders-api"), root.resolve("other-api"));
        Path shared = tmp.resolve("shared");
        copy(EXAMPLES.resolve("sharedflows"), shared);
        new Settings(root.toString(), List.of(shared.toString()), tmp.resolve("out").toString(), List.of(), Map.of(),
                Map.of(), List.of()).save(tmp.resolve("settings.json"));
        restart();
        assertEquals(2.0, ((Map<?, ?>) Json.parse(post("/api/proxies/analyze").body())).get("analyzed"));
        assertEquals(0.0, ((Map<?, ?>) Json.parse(post("/api/proxies/analyze").body())).get("analyzed"));

        // a file of the proxy
        Path manifest;
        try (Stream<Path> files = Files.list(root.resolve("orders-api/apiproxy"))) {
            manifest = files.filter(Files::isRegularFile).findFirst().orElseThrow();
        }
        Files.writeString(manifest, Files.readString(manifest) + "\n");
        assertEquals(true, listed("orders-api").get("outdated"));
        assertEquals(false, listed("other-api").get("outdated"));
        assertEquals(1.0, ((Map<?, ?>) Json.parse(post("/api/proxies/analyze").body())).get("analyzed"));
        assertEquals(false, listed("orders-api").get("outdated"));

        // a shared flow they do not call, then one they do
        Path unused = shared.resolve("sf-cors/sharedflowbundle/sf-cors.xml");
        Files.writeString(unused, Files.readString(unused) + "\n");
        assertEquals(false, listed("other-api").get("outdated"));
        Path flow = shared.resolve("sf-security/sharedflowbundle/policies/LC-Token.xml");
        Files.writeString(flow, Files.readString(flow) + "\n");
        assertEquals(true, listed("other-api").get("outdated"));
        assertEquals(2.0, ((Map<?, ?>) Json.parse(post("/api/proxies/analyze").body())).get("analyzed"));

        // a false positive only outdates the proxy it belongs to
        assertEquals(200, send("POST", "/api/false-positive", "{\"rule\": \"DES-01\", \"bundle\": \"nobody\", "
                + "\"location\": \"x\", \"reason\": \"y\"}", true).statusCode());
        assertEquals(false, listed("other-api").get("outdated"));
        String finding = "{\"rule\": \"DES-01\", \"bundle\": \"orders-api\", \"location\": \"x\", \"reason\": \"y\"}";
        assertEquals(200, send("POST", "/api/false-positive", finding, true).statusCode());
        assertEquals(true, listed("other-api").get("outdated"));
        assertEquals(200, send("POST", "/api/false-positive/remove", finding, true).statusCode());
        assertEquals(false, listed("other-api").get("outdated"));

        // the rules
        assertEquals(200, send("PUT", "/api/settings", Json.write(Map.of("proxiesRoot", root.toString(),
                "sharedFlowDirs", List.of(shared.toString()), "outputDir", tmp.resolve("out").toString(),
                "disabledRules", List.of("DES-01"))), true).statusCode());
        assertEquals(true, listed("other-api").get("outdated"));
        assertEquals(0.0, ((Map<?, ?>) Json.parse(post("/api/proxies/analyze?all=true").body())).get("failed"));
        assertEquals(false, listed("other-api").get("outdated"));
    }

    @Test
    void listsAFailedAnalysis() throws Exception {
        Path root = tmp.resolve("proxies");
        copy(EXAMPLES.resolve("orders-api"), root.resolve("broken-api"));
        Path manifest;
        try (Stream<Path> files = Files.list(root.resolve("broken-api/apiproxy"))) {
            manifest = files.filter(Files::isRegularFile).findFirst().orElseThrow();
        }
        Files.writeString(manifest, "<not xml");
        new Settings(root.toString(), List.of(), tmp.resolve("out").toString(), List.of(), Map.of(), Map.of(),
                List.of()).save(tmp.resolve("settings.json"));
        restart();
        assertEquals(1.0, ((Map<?, ?>) Json.parse(post("/api/proxies/analyze").body())).get("failed"));
        Map<?, ?> broken = listed("broken-api");
        assertNotNull(broken.get("error"));
        assertNotNull(broken.get("analyzed"));
    }

    @Test
    void opensAProxyWithoutAnalyzingIt() throws Exception {
        Map<?, ?> never = (Map<?, ?>) Json.parse(get("/api/proxy?id=orders-api").body());
        assertFalse(never.containsKey("migration"));
        assertNull(((Map<?, ?>) never.get("summary")).get("analyzed"));
        assertFalse(Files.exists(tmp.resolve("stats.json")));

        Path root = tmp.resolve("proxies");
        copy(EXAMPLES.resolve("orders-api"), root.resolve("orders-api"));
        new Settings(root.toString(), List.of(EXAMPLES.resolve("sharedflows").toString()), tmp.resolve("out").toString(),
                List.of(), Map.of(), Map.of(), List.of()).save(tmp.resolve("settings.json"));
        restart();
        String analyzed = Json.write(((Map<?, ?>) Json.parse(post("/api/proxy/analyze?id=orders-api").body()))
                .get("migration"));

        // what the page shows stays that of the analysis until the next one, even after a restart
        restart();
        Path policy;
        try (Stream<Path> files = Files.list(root.resolve("orders-api/apiproxy/policies"))) {
            policy = files.findFirst().orElseThrow();
        }
        Files.delete(policy);
        Map<?, ?> opened = (Map<?, ?>) Json.parse(get("/api/proxy?id=orders-api").body());
        assertEquals(analyzed, Json.write(opened.get("migration")));
        assertEquals(true, ((Map<?, ?>) opened.get("summary")).get("outdated"));
        assertNull(opened.get("running"));

        Map<?, ?> again = (Map<?, ?>) Json.parse(post("/api/proxy/analyze?id=orders-api").body());
        assertNotEquals(analyzed, Json.write(again.get("migration")));
        assertEquals(false, ((Map<?, ?>) again.get("summary")).get("outdated"));
    }

    @Test
    void opensAMigratedProxyAsADryRun() throws Exception {
        post("/api/proxy/analyze?id=orders-api");
        assertEquals(200, post("/api/apply?id=orders-api").statusCode());
        Map<?, ?> opened = (Map<?, ?>) Json.parse(get("/api/proxy?id=orders-api").body());
        assertEquals(true, ((Map<?, ?>) opened.get("summary")).get("migrated"));
        assertEquals(false, ((Map<?, ?>) opened.get("migration")).get("applied"));
        assertEquals(tmp.resolve("out/orders-api").toString(), opened.get("outputDir"));
    }

    @Test
    void opensAProxyWhoseAnalysisFailed() throws Exception {
        Path root = tmp.resolve("proxies");
        copy(EXAMPLES.resolve("orders-api"), root.resolve("broken-api"));
        new Settings(root.toString(), List.of(), tmp.resolve("out").toString(), List.of(), Map.of(), Map.of(),
                List.of()).save(tmp.resolve("settings.json"));
        restart();
        post("/api/proxy/analyze?id=broken-api");
        Files.writeString(root.resolve("broken-api/apiproxy/orders-api.xml"), "<not xml");
        assertTrue(post("/api/proxy/analyze?id=broken-api").statusCode() >= 400);
        Map<?, ?> opened = (Map<?, ?>) Json.parse(get("/api/proxy?id=broken-api").body());
        assertNotNull(((Map<?, ?>) opened.get("summary")).get("error"));
        assertFalse(opened.containsKey("migration"), "the findings of an earlier analysis are not shown as current");
    }

    private List<?> listed() throws Exception {
        return (List<?>) ((Map<?, ?>) Json.parse(get("/api/proxies").body())).get("proxies");
    }

    private Map<?, ?> listed(String id) throws Exception {
        return listed().stream().map(p -> (Map<?, ?>) p).filter(p -> p.get("id").equals(id)).findFirst().orElseThrow();
    }

    private static void copy(Path from, Path to) throws IOException {
        try (Stream<Path> paths = Files.walk(from)) {
            for (Path path : paths.toList()) {
                Path target = to.resolve(from.relativize(path).toString());
                if (Files.isDirectory(path)) Files.createDirectories(target);
                else Files.copy(path, target);
            }
        }
    }

    @Test
    void previewsFileChangesWithoutWriting() throws Exception {
        Map<?, ?> detail = (Map<?, ?>) Json.parse(post("/api/proxy/analyze?id=orders-api").body());
        String json = Json.write(detail);
        assertTrue(json.contains("\"path\": \"targets/legacy.xml\""));
        assertTrue(json.contains("ts-legacy-orders-internal-8080"));
        assertFalse(Files.exists(tmp.resolve("out")));
    }

    @Test
    void marksAFindingAsAFalsePositiveAndReportsItAgain() throws Exception {
        String finding = "{\"rule\": \"DES-01\", \"bundle\": \"orders-api\", \"location\": \"TargetEndpoint legacy\"";
        assertEquals(400, send("POST", "/api/false-positive", finding + ", \"reason\": \" \"}", true).statusCode(),
                "a reason is required");
        assertEquals(200, send("POST", "/api/false-positive", finding + ", \"reason\": \"same host\"}", true)
                .statusCode());

        String detail = Json.write(Json.parse(post("/api/proxy/analyze?id=orders-api").body()));
        assertFalse(detail.contains("\"path\": \"targets/legacy.xml\""), "the auto-fix is not applied");
        assertTrue(detail.contains("\"reason\": \"same host\""));
        assertTrue(Files.readString(tmp.resolve("settings.json")).contains("same host"));
        // saving the Settings screen keeps them
        assertTrue(Json.write(Json.parse(get("/api/settings").body())).contains("\"falsePositives\""));

        assertEquals(200, send("POST", "/api/false-positive/remove", finding + "}", true).statusCode());
        assertTrue(Json.write(Json.parse(post("/api/proxy/analyze?id=orders-api").body()))
                .contains("\"path\": \"targets/legacy.xml\""));
    }

    @Test
    void listsTheVariablesOfEachStep() throws Exception {
        Map<?, ?> flow = (Map<?, ?>) Json.parse(get("/api/variables?id=orders-api").body());
        Map<?, ?> auth = ((List<?>) flow.get("steps")).stream().map(s -> (Map<?, ?>) s)
                .filter(s -> s.get("policy").equals("AM-Backend-Auth")).findFirst().orElseThrow();
        Map<?, ?> password = ((List<?>) auth.get("reads")).stream().map(r -> (Map<?, ?>) r)
                .filter(r -> r.get("name").equals("private.backend.password")).findFirst().orElseThrow();
        assertEquals("SET", password.get("source"));
        Map<?, ?> producer = ((List<?>) flow.get("steps")).stream().map(s -> (Map<?, ?>) s)
                .filter(s -> s.get("index").equals(((List<?>) password.get("producerSteps")).get(0)))
                .findFirst().orElseThrow();
        assertEquals("KVM-Get-Config", producer.get("policy"));
    }

    @Test
    void appliesTheMigrationOnceUnlessOverwriting() throws Exception {
        assertEquals(200, post("/api/apply?id=orders-api").statusCode());
        assertTrue(Files.isDirectory(tmp.resolve("out/orders-api/orders-api/apiproxy")));
        assertTrue(Files.isDirectory(tmp.resolve("out/orders-api/sharedflows/sf-security/sharedflowbundle")));

        assertEquals(true, listed("orders-api").get("migrated"));

        assertEquals(409, post("/api/apply?id=orders-api").statusCode());
        assertEquals(200, post("/api/apply?id=orders-api&overwrite=true").statusCode());
    }

    @Test
    void savesSettingsThatChangeTheMigration() throws Exception {
        Map<?, ?> payload = (Map<?, ?>) Json.parse(get("/api/settings").body());
        assertEquals(40, ((List<?>) payload.get("rules")).size());
        assertTrue(((Map<?, ?>) payload.get("defaultNamingPrefixes")).containsKey("AssignMessage"));

        String body = Json.write(Map.of(
                "proxiesRoot", EXAMPLES.toString(),
                "sharedFlowDirs", List.of(EXAMPLES.resolve("sharedflows").toString()),
                "outputDir", tmp.resolve("out").toString(),
                "disabledRules", List.of("DES-04"),
                "severities", Map.of("SEC-02", "ERROR"),
                "namingPrefixes", Map.of("VerifyAPIKey", List.of("Verify"))));
        assertEquals(200, send("PUT", "/api/settings", body, true).statusCode());

        String detail = post("/api/proxy/analyze?id=orders-api").body();
        assertFalse(detail.contains("\"rule\": \"DES-04\""));
        assertFalse(detail.contains("\"rule\": \"DES-06\""), "Verify-API-Key now matches the configured prefix");
        assertTrue(detail.contains("\"rule\": \"SEC-02\",\n") && detail.contains("\"severity\": \"ERROR\""));
        assertTrue(Files.readString(tmp.resolve("settings.json")).contains("\"DES-04\""));
    }

    @Test
    void rejectsInvalidSettings() throws Exception {
        String body = "{\"severities\": {\"SEC-01\": \"FATAL\"}}";
        HttpResponse<String> response = send("PUT", "/api/settings", body, true);
        assertEquals(400, response.statusCode());
        assertTrue(response.body().contains("Unknown severity FATAL"));
    }

    @Test
    void refusesForeignHostsWritesWithoutHeaderAndPathsOutsideTheRoot() throws Exception {
        // HttpClient does not let the Host header be changed: send the request by hand
        URI url = URI.create(server.url());
        try (Socket socket = new Socket(url.getHost(), url.getPort())) {
            socket.getOutputStream().write(("GET /api/settings HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n")
                    .getBytes(StandardCharsets.US_ASCII));
            String status = new String(socket.getInputStream().readAllBytes(), StandardCharsets.US_ASCII).lines()
                    .findFirst().orElse("");
            assertTrue(status.contains(" 403 "), status);
        }
        assertEquals(403, send("POST", "/api/apply?id=orders-api", "", false).statusCode());
        assertEquals(404, get("/api/proxy?id=../../etc").statusCode());
    }

    @Test
    void jsonRoundTrips() {
        Map<?, ?> parsed = (Map<?, ?>) Json.parse("{\"a\": [1, 2.5, \"x\\n\\u0041\"], \"b\": {\"c\": null, \"d\": true}}");
        assertEquals(List.of(1.0, 2.5, "x\nA"), parsed.get("a"));
        Map<?, ?> nested = (Map<?, ?>) parsed.get("b");
        assertTrue(nested.containsKey("c") && nested.get("c") == null);
        assertEquals(true, nested.get("d"));
        assertEquals(parsed, Json.parse(Json.write(parsed)));
        assertTrue(Json.write("</script>").contains("\\u003c/script>"));
    }

    private HttpResponse<String> get(String path) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create(server.url() + path.substring(1))).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> post(String path) throws Exception {
        return send("POST", path, "", true);
    }

    private HttpResponse<String> send(String method, String path, String body, boolean header) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(server.url() + path.substring(1)))
                .method(method, HttpRequest.BodyPublishers.ofString(body));
        if (header) request.header(UiServer.CSRF_HEADER, "1");
        return http.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }
}
