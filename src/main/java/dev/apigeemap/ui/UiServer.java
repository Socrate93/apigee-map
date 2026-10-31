package dev.apigeemap.ui;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import dev.apigeemap.history.SourceHistory;
import dev.apigeemap.protocol.BackendConfig;
import dev.apigeemap.protocol.Json;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.BindException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.regex.Pattern;

/**
 * Local web UI: static pages from the jar plus a JSON API over {@link UiService}.
 * Listens on the loopback interface only. Requests must carry a loopback Host header (no DNS rebinding) and
 * state-changing requests the {@value #CSRF_HEADER} header, which another web site cannot send.
 */
public final class UiServer {

    static final String CSRF_HEADER = "X-Apigee-Map";
    private static final Map<String, String> ASSETS = Map.of(
            "/", "index.html",
            "/assets/app.js", "app.js",
            "/assets/app.css", "app.css");
    private static final Set<String> LOOPBACK_HOSTS = Set.of("127.0.0.1", "localhost");
    /** The code editor, from its webjar: this version is the one of monaco.version in the pom. */
    private static final String MONACO_PREFIX = "/assets/monaco/";
    private static final String MONACO_RESOURCES = "/META-INF/resources/webjars/monaco-editor/0.52.2/min/";
    private static final Pattern MONACO_PATH = Pattern.compile("[A-Za-z0-9_-]+(?:[./][A-Za-z0-9_-]+)*");
    private static final Map<String, String> MONACO_TYPES = Map.of("js", "text/javascript", "css", "text/css",
            "ttf", "font/ttf");

    private final UiService service;
    private final EditorService editor;
    private final HttpServer server;

    private UiServer(UiService service, EditorService editor, HttpServer server) {
        this.service = service;
        this.editor = editor;
        this.server = server;
    }

    /** Starts on the given port, or on a free one when it is taken; port 0 always picks a free port. */
    public static UiServer start(Path settingsFile, int port) throws IOException {
        return start(settingsFile, SourceHistory.defaultRoot(), BackendConfig.defaultFile(), port);
    }

    /**
     * @param historyRoot   where the histories of bundles changed in place are kept
     * @param backendConfig the backend settings fixes are asked with
     */
    public static UiServer start(Path settingsFile, Path historyRoot, Path backendConfig, int port) throws IOException {
        InetAddress loopback = InetAddress.getLoopbackAddress();
        HttpServer http;
        try {
            http = HttpServer.create(new InetSocketAddress(loopback, port), 0);
        } catch (BindException e) {
            http = HttpServer.create(new InetSocketAddress(loopback, 0), 0);
        }
        UiService service = new UiService(settingsFile, historyRoot, backendConfig);
        UiServer ui = new UiServer(service, new EditorService(service, historyRoot), http);
        http.createContext("/", ui::handle);
        http.setExecutor(Executors.newFixedThreadPool(4));
        http.start();
        return ui;
    }

    public String url() {
        return "http://127.0.0.1:" + server.getAddress().getPort() + "/";
    }

    public void stop() {
        server.stop(0);
    }

    private void handle(HttpExchange exchange) throws IOException {
        try (exchange) {
            if (!loopbackHost(exchange)) {
                send(exchange, 403, "text/plain", "Forbidden host");
                return;
            }
            String method = exchange.getRequestMethod();
            String path = exchange.getRequestURI().getPath();
            if (!method.equals("GET") && !"1".equals(exchange.getRequestHeaders().getFirst(CSRF_HEADER))) {
                send(exchange, 403, "text/plain", "Missing " + CSRF_HEADER + " header");
                return;
            }
            try {
                route(exchange, method, path, query(exchange));
            } catch (UiService.UiException e) {
                json(exchange, e.status, Map.of("error", e.getMessage()));
            } catch (IllegalArgumentException e) {
                json(exchange, 400, Map.of("error", e.getMessage()));
            } catch (IOException | RuntimeException e) {
                json(exchange, 500, Map.of("error", String.valueOf(e.getMessage())));
            }
        }
    }

    private void route(HttpExchange exchange, String method, String path, Map<String, String> query)
            throws IOException {
        String asset = ASSETS.get(path);
        if (asset != null && method.equals("GET")) {
            sendAsset(exchange, asset);
            return;
        }
        if (path.startsWith(MONACO_PREFIX) && method.equals("GET")) {
            sendMonaco(exchange, path.substring(MONACO_PREFIX.length()));
            return;
        }
        switch (method + " " + path) {
            case "GET /api/settings" -> json(exchange, 200, settingsPayload());
            case "PUT /api/settings" -> {
                service.save(Settings.fromJson(Json.parse(body(exchange))));
                json(exchange, 200, settingsPayload());
            }
            case "POST /api/false-positive" -> {
                service.markFalsePositive((Map<?, ?>) Json.parse(body(exchange)));
                json(exchange, 200, Map.of());
            }
            case "POST /api/false-positive/remove" -> {
                service.unmarkFalsePositive((Map<?, ?>) Json.parse(body(exchange)));
                json(exchange, 200, Map.of());
            }
            case "PUT /api/token" -> {
                Object typed = Json.parse(body(exchange)) instanceof Map<?, ?> map ? map.get("token") : null;
                service.setToken(typed instanceof String text ? text : null);
                json(exchange, 200, Map.of());
            }
            case "GET /api/proxies" -> json(exchange, 200, service.proxies());
            case "GET /api/proxy" -> json(exchange, 200, service.proxy(query.get("id")));
            case "GET /api/variables" -> json(exchange, 200, service.variables(query.get("id")));
            case "GET /api/map" -> send(exchange, 200, "text/html", service.mapHtml(query.get("id")));
            case "GET /api/report" -> {
                exchange.getResponseHeaders().add("Content-Disposition", "attachment; filename=\"migration-"
                        + query.getOrDefault("id", "proxy").replaceAll("[^A-Za-z0-9._-]", "_") + ".html\"");
                send(exchange, 200, "text/html", service.migrationHtml(query.get("id")));
            }
            case "POST /api/apply" -> json(exchange, 200,
                    service.apply(query.get("id"), "true".equals(query.get("overwrite"))));
            case "GET /api/overview" -> json(exchange, 200, service.overview());
            case "POST /api/fix" -> json(exchange, 200,
                    service.proposeFix(query.get("id"), (Map<?, ?>) Json.parse(body(exchange))));
            case "POST /api/fix/all" -> json(exchange, 200,
                    service.proposeFixes(query.get("id"), (Map<?, ?>) Json.parse(body(exchange))));
            case "POST /api/port" -> json(exchange, 200,
                    service.proposePort(query.get("id"), (Map<?, ?>) Json.parse(body(exchange))));
            case "POST /api/triage" -> json(exchange, 200,
                    service.triage(query.get("id"), (Map<?, ?>) Json.parse(body(exchange))));
            case "GET /api/document" -> json(exchange, 200, service.documentation(query.get("id")));
            case "POST /api/document" -> json(exchange, 200, service.document(query.get("id")));
            case "GET /api/tests" -> json(exchange, 200, service.testPlan(query.get("id")));
            case "POST /api/tests" -> {
                String body = body(exchange);
                json(exchange, 200, service.planTests(query.get("id"),
                        body.isBlank() ? Map.of() : (Map<?, ?>) Json.parse(body)));
            }
            case "GET /api/tests/export" -> download(exchange,
                    service.exportTests(query.get("id"), query.get("format")));
            case "GET /api/document/export" -> download(exchange, service.exportDocumentation(query.get("id")));
            case "POST /api/tests/run" -> json(exchange, 200,
                    service.runTests(query.get("id"), (Map<?, ?>) Json.parse(body(exchange))));
            case "POST /api/review" -> json(exchange, 200,
                    service.reviewScripts(query.get("id"), "true".equals(query.get("again"))));
            case "POST /api/fix/accept" -> json(exchange, 200, service.acceptFix(query.get("proposal")));
            case "POST /api/fix/reject" -> {
                service.rejectFix(query.get("proposal"));
                json(exchange, 200, Map.of());
            }
            case "GET /api/history" -> json(exchange, 200, service.history(query.get("id")));
            case "GET /api/history/diff" -> json(exchange, 200,
                    Map.of("diff", service.historyDiff(query.get("id"), query.get("bundle"), query.get("step"))));
            case "POST /api/history/revert" -> json(exchange, 200,
                    service.revertStep(query.get("id"), query.get("bundle"), query.get("step")));
            case "GET /api/editor" -> json(exchange, 200, editor.workspace(query.get("id")));
            case "GET /api/editor/file" -> json(exchange, 200,
                    editor.read(query.get("id"), query.get("bundle"), query.get("path")));
            case "POST /api/editor/check" -> json(exchange, 200,
                    editor.check(query.get("id"), (Map<?, ?>) Json.parse(body(exchange))));
            case "POST /api/editor/rename" -> json(exchange, 200,
                    editor.rename(query.get("id"), (Map<?, ?>) Json.parse(body(exchange))));
            case "POST /api/editor/save" -> json(exchange, 200,
                    Map.of("step", Optional.ofNullable(editor.save(query.get("id"),
                            (Map<?, ?>) Json.parse(body(exchange)))).map(s -> (Object) s.id()).orElse("")));
            default -> json(exchange, 404, Map.of("error", "Not found: " + method + " " + path));
        }
    }

    private Map<String, Object> settingsPayload() {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("settings", service.settings());
        payload.put("file", service.settingsFile().toAbsolutePath().toString());
        payload.put("checks", service.checks());
        payload.put("rules", service.rules());
        payload.put("defaultNamingPrefixes", service.defaultNamingPrefixes());
        return payload;
    }

    private static boolean loopbackHost(HttpExchange exchange) {
        String host = exchange.getRequestHeaders().getFirst("Host");
        if (host == null) return false;
        int colon = host.lastIndexOf(':');
        return LOOPBACK_HOSTS.contains(colon > 0 ? host.substring(0, colon) : host);
    }

    private static Map<String, String> query(HttpExchange exchange) {
        Map<String, String> params = new LinkedHashMap<>();
        String raw = exchange.getRequestURI().getRawQuery();
        if (raw == null) return params;
        for (String pair : raw.split("&")) {
            int eq = pair.indexOf('=');
            String key = URLDecoder.decode(eq < 0 ? pair : pair.substring(0, eq), StandardCharsets.UTF_8);
            String value = eq < 0 ? "" : URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
            params.put(key, value);
        }
        return params;
    }

    private static String body(HttpExchange exchange) throws IOException {
        try (InputStream in = exchange.getRequestBody()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static void sendAsset(HttpExchange exchange, String name) throws IOException {
        try (InputStream in = UiServer.class.getResourceAsStream("/ui/" + name)) {
            if (in == null) {
                send(exchange, 404, "text/plain", "Missing asset " + name);
                return;
            }
            String type = name.endsWith(".js") ? "text/javascript" : name.endsWith(".css") ? "text/css" : "text/html";
            send(exchange, 200, type, new String(in.readAllBytes(), StandardCharsets.UTF_8));
        }
    }

    /** A file of the code editor, which the page loads from here rather than from a CDN. */
    private static void sendMonaco(HttpExchange exchange, String path) throws IOException {
        String type = MONACO_TYPES.get(path.substring(path.lastIndexOf('.') + 1));
        InputStream in = type == null || !MONACO_PATH.matcher(path).matches() ? null
                : UiServer.class.getResourceAsStream(MONACO_RESOURCES + path);
        if (in == null) {
            send(exchange, 404, "text/plain", "Missing asset " + path);
            return;
        }
        try (in) {
            send(exchange, 200, type, in.readAllBytes());
        }
    }

    private static void download(HttpExchange exchange, UiService.Download download) throws IOException {
        exchange.getResponseHeaders().add("Content-Disposition", "attachment; filename=\"" + download.fileName() + "\"");
        send(exchange, 200, download.contentType(), download.content());
    }

    private static void json(HttpExchange exchange, int status, Object value) throws IOException {
        send(exchange, status, "application/json", Json.write(value));
    }

    private static void send(HttpExchange exchange, int status, String type, String body) throws IOException {
        send(exchange, status, type + "; charset=utf-8", body.getBytes(StandardCharsets.UTF_8));
    }

    private static void send(HttpExchange exchange, int status, String type, byte[] bytes) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", type);
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }
}
