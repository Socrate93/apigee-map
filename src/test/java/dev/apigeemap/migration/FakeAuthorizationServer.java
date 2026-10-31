package dev.apigeemap.migration;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * An OAuth authorization server and the mock identity provider it sends users to, on one port: /authorize redirects
 * to the login page of the provider, whose form accepts a login equal to the password and redirects to /idp-callback
 * with a code, which redirects to the app with a code of its own, to exchange at /token for a token that /userinfo
 * takes. States, codes and tokens change on every call and only work on the server that issued them.
 */
final class FakeAuthorizationServer implements AutoCloseable {

    final HttpServer server;
    final String base;
    final List<String> received = new CopyOnWriteArrayList<>();
    private final boolean extraTokenField;
    private final Map<String, String> states = new ConcurrentHashMap<>();
    private final Map<String, String> sessions = new ConcurrentHashMap<>();
    private final Map<String, Boolean> codes = new ConcurrentHashMap<>();
    private final Map<String, Boolean> tokens = new ConcurrentHashMap<>();

    /** @param extraTokenField whether the token response has one more field, as a migration could add */
    FakeAuthorizationServer(boolean extraTokenField) throws IOException {
        this.extraTokenField = extraTokenField;
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        base = "http://127.0.0.1:" + server.getAddress().getPort();
        server.createContext("/", exchange -> {
            try (exchange) {
                handle(exchange);
            }
        });
        server.start();
    }

    private void handle(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        String query = exchange.getRequestURI().getRawQuery();
        Map<String, String> params = Responses.params(query == null ? "" : query);
        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        received.add(exchange.getRequestMethod() + " " + path);
        switch (exchange.getRequestMethod() + " " + path) {
            case "GET /oauth2/v1/authorize" -> {
                if (!"app-1".equals(params.get("client_id"))) {
                    send(exchange, 401, "application/json", "{\"error\":\"invalid_client\"}");
                    return;
                }
                String state = UUID.randomUUID().toString();
                states.put(state, params.get("redirect_uri") + "|" + params.get("state"));
                redirect(exchange, "/idp/login?client=apigee&state=" + state + "&redirect_uri="
                        + URLEncoder.encode(base + "/oauth2/v1/idp-callback", StandardCharsets.UTF_8));
            }
            case "GET /idp/login" -> {
                String session = UUID.randomUUID().toString();
                sessions.put(session, params.get("state"));
                exchange.getResponseHeaders().add("Set-Cookie", "sid=" + session + "; Path=/idp");
                send(exchange, 200, "text/html", """
                        <html><body><h1>Sign in</h1>
                        <form method="post" action="login/submit">
                          <input type="hidden" name="state" value="%s">
                          <input type='hidden' name='redirect_uri' value='%s'>
                          <input type="text" name="login"> <input type="password" name="password">
                          <input type="submit" name="go" value="Sign in">
                        </form></body></html>
                        """.formatted(params.get("state"), base + "/oauth2/v1/idp-callback?from=idp&amp;v=1"));
            }
            case "POST /idp/login/submit" -> {
                String cookie = String.valueOf(exchange.getRequestHeaders().getFirst("Cookie"));
                String session = cookie.startsWith("sid=") ? cookie.substring(4) : "";
                Map<String, String> form = Responses.params(body);
                if (!sessions.containsKey(session) || !sessions.get(session).equals(form.get("state"))) {
                    send(exchange, 400, "text/plain", "No session");
                } else if (form.get("login") == null || !form.get("login").equals(form.get("password"))) {
                    send(exchange, 200, "text/html", "<p>Wrong login or password</p>");
                } else {
                    String code = UUID.randomUUID().toString();
                    codes.put("idp:" + code, true);
                    redirect(exchange, form.get("redirect_uri").replace("?from=idp&v=1", "") + "?code=" + code
                            + "&state=" + form.get("state"));
                }
            }
            case "GET /oauth2/v1/idp-callback" -> {
                String client = states.remove(String.valueOf(params.get("state")));
                if (client == null || codes.remove("idp:" + params.get("code")) == null) {
                    send(exchange, 400, "application/json", "{\"error\":\"invalid_request\"}");
                    return;
                }
                String code = UUID.randomUUID().toString();
                codes.put(code, true);
                String[] parts = client.split("\\|");
                redirect(exchange, parts[0] + "?code=" + code + "&state=" + parts[1]);
            }
            case "POST /oauth2/v1/token" -> {
                Map<String, String> form = Responses.params(body);
                if (!"authorization_code".equals(form.get("grant_type")) || codes.remove(form.get("code")) == null) {
                    send(exchange, 400, "application/json", "{\"error\":\"invalid_grant\"}");
                    return;
                }
                String token = UUID.randomUUID().toString();
                tokens.put(token, true);
                send(exchange, 200, "application/json", "{\"access_token\":\"" + token
                        + "\",\"token_type\":\"Bearer\",\"expires_in\":3599"
                        + (extraTokenField ? ",\"scope\":\"openid\"" : "") + "}");
            }
            case "GET /oauth2/v1/userinfo" -> {
                String authorization = String.valueOf(exchange.getRequestHeaders().getFirst("Authorization"));
                if (!tokens.containsKey(authorization.replace("Bearer ", ""))) {
                    send(exchange, 401, "application/json", "{\"error\":\"invalid_token\"}");
                    return;
                }
                send(exchange, 200, "application/json", "{\"sub\":\"alice\"}");
            }
            case "OPTIONS /oauth2/v1/token" -> {
                exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
                exchange.sendResponseHeaders(204, -1);
            }
            default -> send(exchange, 404, "text/plain", "Not found");
        }
    }

    private static void redirect(HttpExchange exchange, String location) throws IOException {
        exchange.getResponseHeaders().add("Location", location);
        exchange.sendResponseHeaders(302, -1);
    }

    private static void send(HttpExchange exchange, int status, String type, String text) throws IOException {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", type);
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    @Override
    public void close() {
        server.stop(0);
    }

    /** The plan of the authorization code flow, as the backend would prepare it, with a case outside the chain. */
    static TestPlans.Plan plan() {
        List<TestPlans.Header> form = List.of(new TestPlans.Header("Content-Type", "application/x-www-form-urlencoded"));
        return new TestPlans.Plan("Covers the authorization code flow.", List.of(
                new TestPlans.Variable("clientId", "Client id of a test app"),
                new TestPlans.Variable("appRedirect", "A redirect URI of the app"),
                new TestPlans.Variable("idpUser", "A user the identity provider accepts"),
                new TestPlans.Variable("idpPassword", "Its password")), List.of(
                new TestPlans.Case("CORS preflight", "CORS", "OPTIONS", "/oauth2/v1/token", List.of(), "", 204,
                        List.of("access-control-allow-origin"), true, ""),
                new TestPlans.Case("Authorize", "Authorize Flow", "GET",
                        "/oauth2/v1/authorize?response_type=code&client_id={{clientId}}&redirect_uri={{appRedirect}}&state=xyz",
                        List.of(), "", 302, List.of(), true, "Redirects to the identity provider.",
                        List.of(new TestPlans.Capture("loginPage", "location", "")), "", true),
                new TestPlans.Case("Login page", "", "GET", "{{loginPage}}", List.of(), "", 200, List.of(), true, "",
                        List.of(new TestPlans.Capture("loginForm", "form", "")), "", true),
                new TestPlans.Case("Log in", "", "POST", "{{loginForm}}", List.of(),
                        "login={{idpUser}}&password={{idpPassword}}", 302, List.of(), true, "",
                        List.of(new TestPlans.Capture("callback", "location", "")), "loginForm", true),
                new TestPlans.Case("IdP callback", "IDP Callback Flow", "GET", "{{callback}}", List.of(), "", 302,
                        List.of(), true, "",
                        List.of(new TestPlans.Capture("code", "query", "code")), "", true),
                new TestPlans.Case("Token", "Token Flow", "POST", "/oauth2/v1/token", form,
                        "grant_type=authorization_code&code={{code}}&redirect_uri={{appRedirect}}", 200, List.of(),
                        true, "", List.of(new TestPlans.Capture("accessToken", "json", "access_token")), "", true),
                new TestPlans.Case("Userinfo", "", "GET", "/oauth2/v1/userinfo",
                        List.of(new TestPlans.Header("Authorization", "Bearer {{accessToken}}")), "", 200, List.of(),
                        true, "", List.of(), "", true)),
                List.of());
    }

    static final Map<String, String> VALUES = Map.of("clientId", "app-1", "appRedirect", "https://app.example.com/cb",
            "idpUser", "alice", "idpPassword", "alice");
}
