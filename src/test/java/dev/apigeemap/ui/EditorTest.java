package dev.apigeemap.ui;

import dev.apigeemap.protocol.Json;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
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
import static org.junit.jupiter.api.Assertions.assertTrue;

class EditorTest {

    private static final Path EXAMPLES = Path.of("examples").toAbsolutePath();
    private static final String ID = "orders-api";

    @TempDir
    Path tmp;

    private Path proxies;
    private UiServer server;
    private final HttpClient http = HttpClient.newHttpClient();

    @BeforeEach
    void start() throws IOException {
        proxies = tmp.resolve("proxies");
        copy(EXAMPLES.resolve("orders-api"), proxies.resolve("orders-api"));
        copy(EXAMPLES.resolve("sharedflows"), tmp.resolve("sharedflows"));
        Path settings = tmp.resolve("settings.json");
        new Settings(proxies.toString(), List.of(tmp.resolve("sharedflows").toString()),
                tmp.resolve("out").toString(), List.of(), Map.of(), Map.of(), List.of()).save(settings);
        server = UiServer.start(settings, tmp.resolve("history"), tmp.resolve("backend.properties"), 0);
    }

    @AfterEach
    void stop() {
        server.stop();
    }

    @Test
    void servesTheCodeEditorFromTheJar() throws Exception {
        assertEquals(200, get("/assets/monaco/vs/loader.js").statusCode());
        assertEquals(200, get("/assets/monaco/vs/editor/editor.main.js").statusCode());
        assertEquals(404, get("/assets/monaco/vs/../../../app.js").statusCode());
        assertEquals(404, get("/assets/monaco/vs/missing.js").statusCode());
    }

    @Test
    void listsTheFilesOfTheProxyAndItsSharedFlowsAsReadOnly() throws Exception {
        Map<?, ?> workspace = (Map<?, ?>) Json.parse(get("/api/editor?id=" + ID).body());
        List<?> bundles = (List<?>) workspace.get("bundles");

        Map<?, ?> proxy = (Map<?, ?>) bundles.get(0);
        assertEquals("orders-api", proxy.get("name"));
        assertEquals(true, proxy.get("editable"));
        assertTrue(((List<?>) proxy.get("files")).stream().map(f -> ((Map<?, ?>) f).get("path"))
                .anyMatch("proxies/default.xml"::equals));
        assertTrue(bundles.size() > 1);
        assertEquals(false, ((Map<?, ?>) bundles.get(1)).get("editable"));
    }

    @Test
    void checksFindingsAtTheirPlace() throws Exception {
        List<?> problems = problems(check(List.of()));
        Map<?, ?> virtualHost = problems.stream().map(p -> (Map<?, ?>) p)
                .filter(p -> p.get("rule").equals("HYB-02")).findFirst().orElseThrow();

        Path file = proxies.resolve("orders-api/apiproxy/proxies/default.xml");
        int line = lineOf(Files.readString(file), "<VirtualHost>");
        assertEquals("proxies/default.xml", virtualHost.get("file"));
        assertEquals(line, ((Number) ((Map<?, ?>) virtualHost.get("span")).get("line")).intValue());
    }

    @Test
    void checksTextThatIsNotSavedWithoutWritingIt() throws Exception {
        Path file = proxies.resolve("orders-api/apiproxy/proxies/default.xml");
        String saved = Files.readString(file);
        String edited = saved.replaceAll("<VirtualHost>[^<]*</VirtualHost>", "");

        List<?> problems = problems(check(List.of(Map.of("path", "proxies/default.xml", "content", edited))));

        assertTrue(problems.stream().noneMatch(p -> "HYB-02".equals(((Map<?, ?>) p).get("rule"))));
        assertEquals(saved, Files.readString(file));
    }

    @Test
    void pointsToMalformedXmlInsteadOfFailing() throws Exception {
        Map<?, ?> check = check(List.of(Map.of("path", "policies/broken.xml", "content", "<Root>\n<One>\n</Root>")));

        assertEquals(false, check.get("analyzed"));
        Map<?, ?> problem = (Map<?, ?>) problems(check).get(0);
        assertEquals("policies/broken.xml", problem.get("file"));
        assertEquals(3, ((Number) ((Map<?, ?>) problem.get("span")).get("line")).intValue());
    }

    @Test
    void refusesFilesOutsideTheBundle() throws Exception {
        String body = Json.write(Map.of("buffers", List.of(Map.of("path", "../../outside.xml", "content", "x"))));
        assertEquals(400, post("/api/editor/check?id=" + ID, body).statusCode());
        assertFalse(Files.exists(proxies.resolve("outside.xml")));
        assertEquals(400, get("/api/editor/file?id=" + ID + "&bundle=orders-api&path="
                + URLEncoder.encode("../../../settings.json", StandardCharsets.UTF_8)).statusCode());
    }

    @Test
    void savesAndRecordsAStepOfHistory() throws Exception {
        Path file = proxies.resolve("orders-api/apiproxy/proxies/default.xml");
        String base = Files.readString(file);
        String content = base + "<!-- edited -->\n";

        assertEquals(200, save(content, base).statusCode());

        assertEquals(content, Files.readString(file));
        List<?> steps = (List<?>) ((Map<?, ?>) ((List<?>) Json.parse(get("/api/history?id=" + ID).body())).get(0)).get("steps");
        assertEquals("Edit proxies/default.xml", ((Map<?, ?>) steps.get(0)).get("title"));
    }

    @Test
    void refusesToSaveOverAFileThatChanged() throws Exception {
        Path file = proxies.resolve("orders-api/apiproxy/proxies/default.xml");
        String base = Files.readString(file);
        Files.writeString(file, base + "<!-- changed elsewhere -->\n");

        assertEquals(409, save(base + "<!-- edited -->\n", base).statusCode());
        assertTrue(Files.readString(file).contains("changed elsewhere"));
    }

    @Test
    void opensAProxySavedWithBrokenXmlSoThatItCanBeRepaired() throws Exception {
        Path file = proxies.resolve("orders-api/apiproxy/proxies/default.xml");
        String base = Files.readString(file);
        String broken = base.replace("</ProxyEndpoint>", "");
        assertEquals(200, save(broken, base).statusCode());

        assertEquals(200, get("/api/editor?id=" + ID).statusCode());
        assertEquals(200, get("/api/editor/file?id=" + ID + "&bundle=" + ID + "&path=proxies/default.xml").statusCode());
        assertEquals(false, check(List.of()).get("analyzed"));
        assertEquals(true, check(List.of(Map.of("path", "proxies/default.xml", "content", base))).get("analyzed"));
    }

    private HttpResponse<String> save(String content, String base) throws Exception {
        return post("/api/editor/save?id=" + ID, Json.write(Map.of("files",
                List.of(Map.of("path", "proxies/default.xml", "content", content, "base", base)))));
    }

    private Map<?, ?> check(List<?> buffers) throws Exception {
        HttpResponse<String> response = post("/api/editor/check?id=" + ID, Json.write(Map.of("buffers", buffers)));
        assertEquals(200, response.statusCode(), response.body());
        return (Map<?, ?>) Json.parse(response.body());
    }

    private static List<?> problems(Map<?, ?> check) {
        return (List<?>) check.get("problems");
    }

    private static int lineOf(String text, String needle) {
        return text.substring(0, text.indexOf(needle)).split("\n", -1).length;
    }

    private HttpResponse<String> get(String path) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create(server.url() + path.substring(1))).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> post(String path, String body) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create(server.url() + path.substring(1)))
                .header(UiServer.CSRF_HEADER, "1")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
    }

    private static void copy(Path source, Path target) throws IOException {
        try (Stream<Path> paths = Files.walk(source)) {
            for (Path path : paths.toList()) {
                Path copy = target.resolve(source.relativize(path).toString());
                if (Files.isDirectory(path)) {
                    Files.createDirectories(copy);
                } else {
                    Files.copy(path, copy);
                }
            }
        }
    }
}
