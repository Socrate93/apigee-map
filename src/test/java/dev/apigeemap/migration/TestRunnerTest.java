package dev.apigeemap.migration;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TestRunnerTest {

    private HttpServer edge;
    private HttpServer hybrid;
    private final List<String> received = new CopyOnWriteArrayList<>();

    @BeforeEach
    void start() throws IOException {
        edge = environment("edge", "*");
        hybrid = environment("hybrid", null);
    }

    @AfterEach
    void stop() {
        edge.stop(0);
        hybrid.stop(0);
    }

    /** Answers 200 with the name of the environment, except /missing (404) and /moved (302); CORS only on Edge. */
    private HttpServer environment(String name, String cors) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            try (exchange) {
                String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                received.add(name + " " + exchange.getRequestMethod() + " " + exchange.getRequestURI() + " "
                        + exchange.getRequestHeaders().getFirst("x-apikey") + " " + body);
                String path = exchange.getRequestURI().getPath();
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                if (cors != null) exchange.getResponseHeaders().add("Access-Control-Allow-Origin", cors);
                if (path.equals("/moved")) exchange.getResponseHeaders().add("Location", "/elsewhere");
                byte[] bytes = ("{\"from\":\"" + (path.equals("/same") ? "both" : name) + "\"}")
                        .getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(path.equals("/missing") ? 404 : path.equals("/moved") ? 302 : 200,
                        bytes.length);
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(bytes);
                }
            }
        });
        server.start();
        return server;
    }

    private static TestPlans.Case get(String name, String path, int expected, List<String> compare) {
        return new TestPlans.Case(name, "", "GET", path, List.of(), "", expected, compare, true, "");
    }

    @Test
    void comparesStatusesAndTheNamedHeaders() {
        TestPlans.Plan plan = new TestPlans.Plan("Plan", List.of(new TestPlans.Variable("apikey", "")), List.of(
                get("Same", "/same", 200, List.of("content-type")),
                get("CORS", "/v1/orders", 200, List.of("access-control-allow-origin")),
                get("Redirect", "/moved", 302, List.of("location")),
                new TestPlans.Case("Create", "CreateOrder", "POST", "/v1/orders",
                        List.of(new TestPlans.Header("x-apikey", "{{apikey}}")), "{\"key\":\"{{apikey}}\"}", 201,
                        List.of(), false, ""),
                new TestPlans.Case("Token", "", "GET", "/v1/me?token={{token}}", List.of(), "", 0, List.of(), true,
                        "")),
                List.of());
        TestRunner runner = new TestRunner(Duration.ofSeconds(5));
        String edgeUrl = TestRunner.baseUrl("Edge", "http://127.0.0.1:" + edge.getAddress().getPort() + "/");
        String hybridUrl = TestRunner.baseUrl("hybrid", "http://127.0.0.1:" + hybrid.getAddress().getPort());

        TestRunner.Run run = runner.run(plan, edgeUrl, hybridUrl, Map.of("apikey", "k1"), false, null);
        List<TestRunner.Result> results = run.results();
        assertEquals(5, results.size());

        assertEquals(TestRunner.Outcome.SAME, results.get(0).outcome(), results.get(0).toString());
        assertEquals(List.of(), results.get(0).notes());

        TestRunner.Result cors = results.get(1);
        assertEquals(TestRunner.Outcome.DIFFERENT, cors.outcome());
        assertEquals(List.of("access-control-allow-origin: \"*\" on Edge, absent on hybrid"), cors.differences());
        assertTrue(cors.notes().get(0).startsWith("The bodies differ"), cors.notes().toString());
        assertNull(cors.hybrid().headers().get("access-control-allow-origin"));

        TestRunner.Result redirect = results.get(2);
        assertEquals(302, redirect.edge().status(), "redirects are not followed");
        assertEquals("{base}/elsewhere", redirect.hybrid().headers().get("location"),
                "on its own host, so that the same redirect reads the same on both");

        assertEquals(TestRunner.Outcome.SKIPPED, results.get(3).outcome(), "it changes data");
        assertEquals(TestRunner.Outcome.ERROR, results.get(4).outcome());
        assertEquals(List.of("No value for {{token}}"), results.get(4).notes());
        assertTrue(received.stream().noneMatch(r -> r.contains("POST") || r.contains("/v1/me")), received.toString());

        TestRunner.Run unsafe = runner.run(plan, edgeUrl, hybridUrl, Map.of("apikey", "k1"), true, Set.of(3));
        TestRunner.Result created = unsafe.results().get(0);
        assertEquals(3, created.index());
        assertEquals(List.of("Edge answered 200, the plan expects 201", "Hybrid answered 200, the plan expects 201"),
                created.notes().subList(0, 2));
        assertTrue(received.contains("edge POST /v1/orders k1 {\"key\":\"k1\"}"), received.toString());
        assertTrue(received.contains("hybrid POST /v1/orders k1 {\"key\":\"k1\"}"), received.toString());
    }

    @Test
    void chainsTheAuthorizationCodeFlowOnEachEnvironment() throws IOException {
        try (FakeAuthorizationServer onEdge = new FakeAuthorizationServer(false);
             FakeAuthorizationServer onHybrid = new FakeAuthorizationServer(true)) {
            TestPlans.Plan plan = FakeAuthorizationServer.plan();
            TestRunner runner = new TestRunner(Duration.ofSeconds(5));
            List<TestRunner.Result> results = runner.run(plan, onEdge.base, onHybrid.base,
                    FakeAuthorizationServer.VALUES, false, null).results();

            assertEquals(List.of("SAME", "SAME", "SAME", "SAME", "SAME", "DIFFERENT", "SAME"),
                    results.stream().map(r -> r.outcome().name()).toList(), results.toString());
            results.forEach(r -> assertEquals(List.of(), r.notes(), r.toString()));
            assertEquals("{base}/idp/login?client&redirect_uri&state", results.get(1).edge().headers().get("location"),
                    "the shape, without the state");
            assertEquals("https://app.example.com/cb?code&state", results.get(4).hybrid().headers().get("location"));
            assertEquals(List.of("JSON keys [access_token, expires_in, token_type] on Edge, "
                    + "[access_token, expires_in, scope, token_type] on hybrid"), results.get(5).differences());
            assertTrue(onEdge.received.contains("POST /idp/login/submit"), onEdge.received.toString());

            Map<String, String> wrong = new java.util.HashMap<>(FakeAuthorizationServer.VALUES);
            wrong.put("idpPassword", "not-alice");
            List<TestRunner.Result> refused = runner.run(plan, onEdge.base, onHybrid.base, wrong, false, null)
                    .results();
            assertEquals(List.of("Nothing to capture as {{callback}} on Edge",
                    "Nothing to capture as {{callback}} on hybrid", "Edge answered 200, the plan expects 302",
                    "Hybrid answered 200, the plan expects 302"), refused.get(3).notes());
            assertEquals(TestRunner.Outcome.ERROR, refused.get(4).outcome());
            assertEquals(List.of("{{callback}} was not captured on Edge", "{{callback}} was not captured on hybrid"),
                    refused.get(4).notes());

            List<TestRunner.Result> userinfo = runner.run(plan, onEdge.base, onHybrid.base,
                    FakeAuthorizationServer.VALUES, false, Set.of(6)).results();
            assertEquals(List.of(1, 2, 3, 4, 5, 6), userinfo.stream().map(TestRunner.Result::index).toList(),
                    "with the cases that capture what it uses");
            assertEquals(TestRunner.Outcome.SAME, userinfo.get(5).outcome(), userinfo.get(5).toString());
        }
    }

    @Test
    void readsTheValuesOfAResponse() {
        Responses.Form form = Responses.form("""
                <form id=login METHOD='post' action="/idp/do?x=1&amp;y=2">
                  <input type=hidden name=state value="a&quot;b"><input name="user">
                  <input type="checkbox" name="remember"><input type="checkbox" name="keep" value="yes" checked>
                  <button>Go</button><input type="submit" name="go" value="Go">
                </form><form action="/other"><input name="other"></form>
                """, java.net.URI.create("https://idp.example.com/login/page?s=1"));
        assertEquals("https://idp.example.com/idp/do?x=1&y=2", form.action());
        assertEquals("POST", form.method());
        assertEquals(Map.of("state", "a\"b", "user", "", "keep", "yes"), form.fields());
        assertNull(Responses.form("<p>No form</p>", java.net.URI.create("https://idp.example.com/")));

        String location = "https://hybrid.example.com/cb?state=s%201&code=c#access_token=t&token_type=Bearer";
        assertEquals("s 1", Responses.param(location, "state"));
        assertEquals("t", Responses.param(location, "access_token"));
        assertNull(Responses.param(location, "missing"));
        assertEquals("{base}/cb?code&state#access_token&token_type",
                Responses.shape(location, "https://hybrid.example.com"));
        assertEquals("b", Responses.json("{\"a\": {\"list\": [\"x\", \"b\"]}}", "a.list.1"));
        assertEquals("3599", Responses.json("{\"expires_in\": 3599}", "expires_in"));
        assertNull(Responses.json("<html/>", "a"));
        assertEquals(List.of("a", "b"), Responses.keys("{\"b\": 1, \"a\": 2}"));
    }

    @Test
    void reportsAnEnvironmentThatDoesNotAnswer() throws IOException {
        int closed;
        try (java.net.ServerSocket socket = new java.net.ServerSocket(0)) {
            closed = socket.getLocalPort();
        }
        TestPlans.Plan plan = new TestPlans.Plan("Plan", List.of(), List.of(get("Missing", "/missing", 404, List.of())),
                List.of());
        TestRunner.Result result = new TestRunner(Duration.ofSeconds(5)).run(plan,
                "http://127.0.0.1:" + edge.getAddress().getPort(), "http://127.0.0.1:" + closed, Map.of(), false,
                null).results().get(0);
        assertEquals(TestRunner.Outcome.ERROR, result.outcome());
        assertEquals(404, result.edge().status());
        assertNotNull(result.hybrid().error());
    }

    @Test
    void takesOnlyASchemeAndAHost() {
        assertEquals("https://api.example.com:8443", TestRunner.baseUrl("Edge", " https://api.example.com:8443/ "));
        for (String bad : List.of("", "api.example.com", "ftp://api.example.com", "https://api.example.com/v1",
                "https://user@api.example.com", "https://api.example.com?x=1", "https://")) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> TestRunner.baseUrl("hybrid", bad), bad);
            assertEquals("Give the hybrid URL as https://host[:port], without a path", e.getMessage());
        }
    }
}
