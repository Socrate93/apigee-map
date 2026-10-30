package dev.apigeemap.migration;

import com.sun.net.httpserver.HttpServer;
import dev.apigeemap.protocol.Json;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TestExportsTest {

    /** Same, CORS only on Edge, a POST that changes data, and quotes and variables everywhere. */
    static final TestPlans.Plan PLAN = new TestPlans.Plan("Covers the orders.\nAnd the fallback.",
            List.of(new TestPlans.Variable("apikey", "A consumer key"), new TestPlans.Variable("orderId", "")),
            List.of(
                    new TestPlans.Case("Get Bob's order", "GetOrder", "GET", "/v1/orders/{{orderId}}?q='x'",
                            List.of(new TestPlans.Header("x-apikey", "{{apikey}}")), "", 200,
                            List.of("content-type"), true, "Returns the order."),
                    new TestPlans.Case("CORS", "", "GET", "/cors", List.of(), "", 200,
                            List.of("access-control-allow-origin"), true, ""),
                    new TestPlans.Case("Create", "CreateOrder", "POST", "/v1/orders",
                            List.of(new TestPlans.Header("Content-Type", "application/json")),
                            "{\"note\": \"it's {{apikey}}\"}", 201, List.of(), false, "")),
            List.of("Create an app on both environments"));

    @TempDir
    Path tmp;
    private HttpServer edge;
    private HttpServer hybrid;
    private final List<String> received = new CopyOnWriteArrayList<>();

    @BeforeEach
    void start() throws IOException {
        edge = environment("edge", true);
        hybrid = environment("hybrid", false);
    }

    @AfterEach
    void stop() {
        edge.stop(0);
        hybrid.stop(0);
    }

    private HttpServer environment(String name, boolean cors) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            try (exchange) {
                String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                received.add(name + " " + exchange.getRequestMethod() + " " + exchange.getRequestURI() + " "
                        + exchange.getRequestHeaders().getFirst("x-apikey") + " " + body);
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                if (cors && exchange.getRequestURI().getPath().equals("/cors")) {
                    exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
                }
                byte[] bytes = "{}".getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(200, bytes.length);
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(bytes);
                }
            }
        });
        server.start();
        return server;
    }

    @Test
    void theCurlScriptComparesBothEnvironmentsAndFailsOnADifference() throws Exception {
        Path script = tmp.resolve(TestExports.fileName(TestExports.Format.CURL, "orders api"));
        assertEquals("orders_api-regression.sh", script.getFileName().toString());
        Files.writeString(script, TestExports.write(TestExports.Format.CURL, "orders api", PLAN));

        Result safe = bash(script, Map.of());
        assertEquals(1, safe.code(), safe.output());
        assertTrue(safe.output().contains("SAME       Get Bob's order (200)"), safe.output());
        assertTrue(safe.output().contains("DIFFERENT  CORS\n"
                + "           access-control-allow-origin: '*' on Edge, 'absent' on hybrid"), safe.output());
        assertTrue(safe.output().contains("SKIPPED    Create"), safe.output());
        assertTrue(safe.output().contains("1 same, 1 different, 0 error(s), 1 skipped"), safe.output());
        assertTrue(received.contains("edge GET /v1/orders/42?q='x' k'1 "), received.toString());
        assertTrue(received.contains("hybrid GET /v1/orders/42?q='x' k'1 "), received.toString());
        assertFalse(received.stream().anyMatch(r -> r.contains("POST")), "it changes data");

        received.clear();
        Result unsafe = bash(script, Map.of("INCLUDE_UNSAFE", "1"));
        assertTrue(unsafe.output().contains("SAME       Create (200)\n"
                + "           Edge answered 200, the plan expects 201"), unsafe.output());
        assertTrue(received.contains("hybrid POST /v1/orders null {\"note\": \"it's k'1\"}"), received.toString());

        Result missing = bash(script, Map.of("orderId", ""));
        assertTrue(missing.code() != 0 && missing.output().contains("orderId"), missing.output());
    }

    private record Result(int code, String output) {
    }

    private Result bash(Path script, Map<String, String> env) throws Exception {
        ProcessBuilder builder = new ProcessBuilder("bash", script.toString()).redirectErrorStream(true);
        builder.environment().put("EDGE", "http://127.0.0.1:" + edge.getAddress().getPort() + "/");
        builder.environment().put("HYBRID", "http://127.0.0.1:" + hybrid.getAddress().getPort());
        builder.environment().put("apikey", "k'1");
        builder.environment().put("orderId", "42");
        builder.environment().putAll(env);
        Process process = builder.start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(process.waitFor(30, TimeUnit.SECONDS));
        return new Result(process.exitValue(), output);
    }

    @Test
    void thePostmanCollectionSendsToEdgeAndComparesWithHybrid() {
        Map<?, ?> collection = (Map<?, ?>) Json.parse(TestExports.write(TestExports.Format.POSTMAN, "orders-api", PLAN));
        Map<?, ?> info = (Map<?, ?>) collection.get("info");
        assertEquals("orders-api regression tests", info.get("name"));
        assertEquals("https://schema.getpostman.com/json/collection/v2.1.0/collection.json", info.get("schema"));
        assertEquals(List.of("edgeUrl", "hybridUrl", "includeUnsafe", "apikey", "orderId"),
                ((List<?>) collection.get("variable")).stream().map(v -> ((Map<?, ?>) v).get("key")).toList());

        List<?> items = (List<?>) collection.get("item");
        Map<?, ?> get = (Map<?, ?>) items.get(0);
        Map<?, ?> request = (Map<?, ?>) get.get("request");
        assertEquals("{{edgeUrl}}/v1/orders/{{orderId}}?q='x'", ((Map<?, ?>) request.get("url")).get("raw"));
        assertEquals(List.of(Map.of("key", "x-apikey", "value", "{{apikey}}")), request.get("header"));
        assertEquals(Map.of("followRedirects", false), get.get("protocolProfileBehavior"));
        String test = script(get, "test");
        assertTrue(test.contains("url: pm.variables.replaceIn('{{hybridUrl}}' + '/v1/orders/{{orderId}}?q=\\'x\\''),"),
                test);
        assertTrue(test.contains("hybrid.headers.get('content-type')).to.equal(edge.headers.get('content-type'))"),
                test);
        assertTrue(test.contains("pm.expect(edge.code).to.equal(200)"), test);
        assertNull(script(get, "prerequest"), "safe");

        Map<?, ?> create = (Map<?, ?>) items.get(2);
        assertEquals(Map.of("mode", "raw", "raw", "{\"note\": \"it's {{apikey}}\"}"),
                ((Map<?, ?>) create.get("request")).get("body"));
        assertTrue(script(create, "prerequest").contains("pm.execution.skipRequest()"));
        assertTrue(script(create, "test").contains("raw: pm.variables.replaceIn('{\"note\": \"it\\'s {{apikey}}\"}')"));
    }

    private static String script(Map<?, ?> item, String listen) {
        for (Object e : (List<?>) item.get("event")) {
            Map<?, ?> event = (Map<?, ?>) e;
            if (event.get("listen").equals(listen)) {
                return String.join("\n", ((List<?>) ((Map<?, ?>) event.get("script")).get("exec")).stream()
                        .map(String::valueOf).toList());
            }
        }
        return null;
    }

    @Test
    void theKarateFeatureMatchesBothEnvironments() {
        String feature = TestExports.write(TestExports.Format.KARATE, "orders-api", PLAN);
        assertTrue(feature.startsWith("Feature: orders-api regression tests, on Edge then on hybrid\n\n"
                + "  Covers the orders.\n  And the fallback.\n"), feature);
        assertTrue(feature.contains("    * vars['apikey'] = karate.properties['apikey']\n"), feature);
        assertTrue(feature.contains("  Scenario: Get Bob's order\n"
                + "    # Returns the order.\n"
                + "    * def path = '/v1/orders/' + vars['orderId'] + '?q=\\'x\\''\n"
                + "    Given url edgeUrl + path\n"
                + "    And header x-apikey = vars['apikey']\n"
                + "    When method get\n"), feature);
        assertTrue(feature.contains("    * match karate.response.header('content-type') == edgeHeaders['content-type']\n"
                + "    * match edgeStatus == 200\n"), feature);
        assertTrue(feature.contains("  @unsafe\n  Scenario: Create\n"), feature);
        assertTrue(feature.contains("    And request '{\"note\": \"it\\'s ' + vars['apikey'] + '\"}'\n"), feature);
    }
}
