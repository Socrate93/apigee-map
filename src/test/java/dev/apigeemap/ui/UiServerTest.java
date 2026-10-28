package dev.apigeemap.ui;

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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
                tmp.resolve("out").toString(), List.of(), Map.of(), Map.of()).save(settings);
        server = UiServer.start(settings, 0);
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
    void listsProxiesWithTheirFindings() throws Exception {
        List<?> proxies = (List<?>) Json.parse(get("/api/proxies").body());
        assertEquals(4, proxies.size());
        Map<?, ?> orders = proxies.stream().map(p -> (Map<?, ?>) p)
                .filter(p -> p.get("id").equals("orders-api")).findFirst().orElseThrow();
        assertEquals(2.0, orders.get("sharedFlows"));
        assertEquals(false, orders.get("migrated"));
    }

    @Test
    void previewsFileChangesWithoutWriting() throws Exception {
        Map<?, ?> detail = (Map<?, ?>) Json.parse(get("/api/proxy?id=orders-api").body());
        String json = Json.write(detail);
        assertTrue(json.contains("\"path\": \"targets/legacy.xml\""));
        assertTrue(json.contains("ts-legacy-orders-internal-8080"));
        assertFalse(Files.exists(tmp.resolve("out")));
    }

    @Test
    void appliesTheMigrationOnceUnlessOverwriting() throws Exception {
        assertEquals(200, post("/api/apply?id=orders-api").statusCode());
        assertTrue(Files.isDirectory(tmp.resolve("out/orders-api/orders-api/apiproxy")));
        assertTrue(Files.isDirectory(tmp.resolve("out/orders-api/sharedflows/sf-security/sharedflowbundle")));

        Map<?, ?> listed = ((List<?>) Json.parse(get("/api/proxies").body())).stream().map(p -> (Map<?, ?>) p)
                .filter(p -> p.get("id").equals("orders-api")).findFirst().orElseThrow();
        assertEquals(true, listed.get("migrated"));

        assertEquals(409, post("/api/apply?id=orders-api").statusCode());
        assertEquals(200, post("/api/apply?id=orders-api&overwrite=true").statusCode());
    }

    @Test
    void savesSettingsThatChangeTheMigration() throws Exception {
        Map<?, ?> payload = (Map<?, ?>) Json.parse(get("/api/settings").body());
        assertEquals(38, ((List<?>) payload.get("rules")).size());
        assertTrue(((Map<?, ?>) payload.get("defaultNamingPrefixes")).containsKey("AssignMessage"));

        String body = Json.write(Map.of(
                "proxiesRoot", EXAMPLES.toString(),
                "sharedFlowDirs", List.of(EXAMPLES.resolve("sharedflows").toString()),
                "outputDir", tmp.resolve("out").toString(),
                "disabledRules", List.of("DES-04"),
                "severities", Map.of("SEC-02", "ERROR"),
                "namingPrefixes", Map.of("VerifyAPIKey", List.of("Verify"))));
        assertEquals(200, send("PUT", "/api/settings", body, true).statusCode());

        String detail = get("/api/proxy?id=orders-api").body();
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
