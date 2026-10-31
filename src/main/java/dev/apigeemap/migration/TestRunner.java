package dev.apigeemap.migration;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Replays the cases of a {@link TestPlans.Plan} on Edge then on hybrid, one case after the other, and compares the
 * statuses and the headers the plan names. Redirects are not followed, so that they are compared too; bodies are only
 * compared by their hash, as they often hold timestamps or ids. A case can read values from its responses for the next
 * ones, such as the state of an OAuth redirect, each environment its own, and the cases whose answers change on every
 * call compare their shapes only.
 */
public final class TestRunner {

    /** How a case went. */
    public enum Outcome { SAME, DIFFERENT, ERROR, SKIPPED }

    /**
     * What one environment answered; {@code status} is 0 and {@code error} set when it answered nothing.
     *
     * @param headers the compared headers, null when absent
     */
    public record Response(int status, Map<String, String> headers, long bodyLength, String bodyHash, String error) {
    }

    /**
     * @param differences what differs between Edge and hybrid
     * @param notes       what else is worth seeing: a status the plan did not expect, bodies that differ
     */
    public record Result(int index, String name, Outcome outcome, Response edge, Response hybrid,
                         List<String> differences, List<String> notes) {
    }

    public record Run(String edge, String hybrid, List<Result> results) {
    }

    private static final Pattern VARIABLE = Pattern.compile("\\{\\{([A-Za-z][A-Za-z0-9_]{0,39})}}");
    /** Bodies are hashed up to this many bytes. */
    private static final int MAX_BODY = 10_000_000;
    /** What captures and shapes read of a body: its first bytes. */
    private static final int MAX_READ = 1_000_000;

    private final Duration timeout;

    public TestRunner(Duration timeout) {
        this.timeout = timeout;
    }

    /**
     * The scheme, host and port of an environment, without a trailing slash.
     *
     * @throws IllegalArgumentException when it is not an http or https URL with a host and nothing after it
     */
    public static String baseUrl(String label, String raw) {
        String url = raw == null ? "" : raw.strip();
        while (url.endsWith("/")) url = url.substring(0, url.length() - 1);
        try {
            URI uri = new URI(url);
            if (url.isEmpty() || !Set.of("http", "https").contains(String.valueOf(uri.getScheme()).toLowerCase())
                    || uri.getHost() == null || uri.getRawUserInfo() != null
                    || !(uri.getRawPath() == null || uri.getRawPath().isEmpty())
                    || uri.getRawQuery() != null || uri.getRawFragment() != null) {
                throw new IllegalArgumentException("Give the " + label + " URL as https://host[:port], without a path");
            }
            return url;
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Give the " + label + " URL as https://host[:port], without a path");
        }
    }

    /**
     * Runs the cases whose index is in {@code only}, with the earlier cases that capture what they use, or all of
     * them when it is null; unsafe cases only with {@code unsafe}. Each environment keeps its own captured values
     * and, when the plan captures any, its own cookies.
     *
     * @param edge   from {@link #baseUrl}
     * @param hybrid from {@link #baseUrl}
     * @param values the values of the variables, by name
     */
    public Run run(TestPlans.Plan plan, String edge, String hybrid, Map<String, String> values, boolean unsafe,
                   Set<Integer> only) {
        Set<Integer> chosen = only == null ? null : withEarlierCaptures(plan, only);
        boolean chained = !plan.captured().isEmpty();
        Environment onEdge = new Environment("Edge", edge, client(chained));
        Environment onHybrid = new Environment("hybrid", hybrid, client(chained));
        List<Result> results = new ArrayList<>();
        for (int i = 0; i < plan.cases().size(); i++) {
            if (chosen != null && !chosen.contains(i)) continue;
            results.add(run(i, plan.cases().get(i), onEdge, onHybrid, values, plan.captured(), unsafe));
        }
        return new Run(edge, hybrid, results);
    }

    /** The cases, and the earlier ones that capture what they use, the nearest one for each value. */
    static Set<Integer> withEarlierCaptures(TestPlans.Plan plan, Set<Integer> only) {
        Set<Integer> chosen = new TreeSet<>();
        Deque<Integer> pending = new ArrayDeque<>(only);
        while (!pending.isEmpty()) {
            int index = pending.pop();
            if (index < 0 || index >= plan.cases().size() || !chosen.add(index)) continue;
            for (String name : uses(plan.cases().get(index))) {
                for (int i = index - 1; i >= 0; i--) {
                    if (plan.cases().get(i).captures().stream().anyMatch(c -> c.name().equals(name))) {
                        pending.push(i);
                        break;
                    }
                }
            }
        }
        return chosen;
    }

    /** The names of the variables and captured values a case uses. */
    static Set<String> uses(TestPlans.Case c) {
        Set<String> names = new LinkedHashSet<>();
        StringBuilder text = new StringBuilder(c.path()).append(' ').append(c.body());
        c.headers().forEach(h -> text.append(' ').append(h.value()));
        Matcher matcher = VARIABLE.matcher(text);
        while (matcher.find()) names.add(matcher.group(1));
        if (!c.form().isEmpty()) names.add(c.form());
        return names;
    }

    private HttpClient client(boolean cookies) {
        HttpClient.Builder builder = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER)
                .version(HttpClient.Version.HTTP_1_1).connectTimeout(timeout);
        // a login page keeps its session in a cookie between showing the form and receiving it
        if (cookies) builder.cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL));
        return builder.build();
    }

    /** One environment during a run: what its responses gave the next cases. */
    private record Environment(String label, String base, HttpClient client, Map<String, String> captured,
                               Map<String, Responses.Form> forms) {

        Environment(String label, String base, HttpClient client) {
            this(label, base, client, new HashMap<>(), new HashMap<>());
        }
    }

    /** A request ready to send, or why it cannot be. */
    private record Prepared(URI uri, String method, Map<String, String> headers, String body, String problem) {
    }

    /** What an environment answered, with what the captures and shapes read. */
    private record Answer(Response response, HttpHeaders headers, String text, URI uri) {
    }

    private Result run(int index, TestPlans.Case c, Environment edge, Environment hybrid, Map<String, String> values,
                       Set<String> capturable, boolean unsafe) {
        if (!c.safe() && !unsafe) {
            return new Result(index, c.name(), Outcome.SKIPPED, null, null, List.of(),
                    List.of("It changes data: it runs only when unsafe cases are included"));
        }
        List<String> missing = new ArrayList<>();
        Prepared toEdge = prepare(c, edge, values, capturable, missing);
        Prepared toHybrid = prepare(c, hybrid, values, capturable, missing);
        List<String> notes = new ArrayList<>();
        if (!missing.isEmpty()) {
            notes.add("No value for " + String.join(", ", missing.stream().distinct().map(n -> "{{" + n + "}}").toList()));
        }
        Stream.of(toEdge, toHybrid).map(Prepared::problem).filter(Objects::nonNull).distinct().forEach(notes::add);
        if (!notes.isEmpty()) return new Result(index, c.name(), Outcome.ERROR, null, null, List.of(), notes);

        Answer onEdge = send(toEdge, c, edge);
        Answer onHybrid = send(toHybrid, c, hybrid);
        if (onEdge.response().error() != null || onHybrid.response().error() != null) {
            return new Result(index, c.name(), Outcome.ERROR, onEdge.response(), onHybrid.response(), List.of(),
                    notes);
        }
        capture(c, edge, onEdge, notes);
        capture(c, hybrid, onHybrid, notes);
        Response a = onEdge.response();
        Response b = onHybrid.response();
        List<String> differences = new ArrayList<>();
        if (a.status() != b.status()) differences.add("Status " + a.status() + " on Edge, " + b.status() + " on hybrid");
        for (String header : compared(c)) {
            String x = a.headers().get(header);
            String y = b.headers().get(header);
            if (c.shapeOnly() && !header.equals("location")) {
                if ((x == null) != (y == null)) {
                    differences.add(header + ": " + (x == null ? "absent" : "present") + " on Edge, "
                            + (y == null ? "absent" : "present") + " on hybrid");
                }
            } else if (x == null ? y != null : !x.equals(y)) {
                differences.add(header + ": " + shown(x) + " on Edge, " + shown(y) + " on hybrid");
            }
        }
        if (c.shapeOnly()) {
            List<String> x = Responses.keys(onEdge.text());
            List<String> y = Responses.keys(onHybrid.text());
            if (x != null && y != null && !x.equals(y)) {
                differences.add("JSON keys " + x + " on Edge, " + y + " on hybrid");
            } else if ((x == null) != (y == null)) {
                differences.add("A JSON object on " + (x == null ? "hybrid" : "Edge") + " only");
            }
        }
        if (c.expectedStatus() != 0) {
            if (a.status() != c.expectedStatus()) {
                notes.add("Edge answered " + a.status() + ", the plan expects " + c.expectedStatus());
            }
            if (b.status() != c.expectedStatus()) {
                notes.add("Hybrid answered " + b.status() + ", the plan expects " + c.expectedStatus());
            }
        }
        if (!c.shapeOnly() && !a.bodyHash().equals(b.bodyHash())) {
            notes.add("The bodies differ: " + a.bodyLength() + " bytes on Edge, " + b.bodyLength() + " on hybrid");
        }
        return new Result(index, c.name(), differences.isEmpty() ? Outcome.SAME : Outcome.DIFFERENT, a, b,
                differences, notes);
    }

    /** The compared headers; with the Location too when the shapes are compared, as it tells where the flow goes. */
    private static List<String> compared(TestPlans.Case c) {
        if (!c.shapeOnly() || c.compareHeaders().contains("location")) return c.compareHeaders();
        List<String> headers = new ArrayList<>(c.compareHeaders());
        headers.add("location");
        return headers;
    }

    /** @param capturable the names the plan captures, which are not variables to give */
    private Prepared prepare(TestPlans.Case c, Environment env, Map<String, String> values, Set<String> capturable,
                             List<String> missing) {
        Map<String, String> known = new HashMap<>(values);
        known.putAll(env.captured());
        List<String> absent = new ArrayList<>();
        Map<String, String> headers = new LinkedHashMap<>();
        c.headers().forEach(h -> headers.put(h.name(), substitute(h.value(), known, absent)));
        String problem = null;
        URI uri = null;
        String method = c.method();
        String body;
        if (!c.form().isEmpty()) {
            Responses.Form form = env.forms().get(c.form());
            Map<String, String> fields = new LinkedHashMap<>(form == null ? Map.of() : form.fields());
            Responses.fields(c.body()).forEach((k, v) -> fields.put(k, substitute(v, known, absent)));
            body = Responses.encode(fields);
            if (form == null) {
                problem = "The form {{" + c.form() + "}} was not captured on " + env.label();
            } else if (form.method().equals("GET")) {
                uri = URI.create(form.action().replaceAll("[?#].*$", "") + (body.isEmpty() ? "" : "?" + body));
                method = "GET";
                body = "";
            } else {
                uri = URI.create(form.action());
                method = "POST";
                if (headers.keySet().stream().noneMatch(h -> h.equalsIgnoreCase("content-type"))) {
                    headers.put("Content-Type", "application/x-www-form-urlencoded");
                }
            }
        } else {
            body = substitute(c.body(), known, absent);
            String path = substitute(c.path(), known, absent);
            try {
                if (path.startsWith("/")) uri = new URI(env.base() + path);
                else if (path.matches("(?i)https?://.+")) uri = new URI(path);
                else problem = c.path() + " is not a path nor a URL on " + env.label();
            } catch (URISyntaxException e) {
                problem = "The request is not valid: " + e.getMessage();
            }
        }
        for (String name : absent) {
            // a value an earlier case did not capture is not one to give
            if (capturable.contains(name)) {
                problem = "{{" + name + "}} was not captured on " + env.label();
            } else {
                missing.add(name);
            }
        }
        return new Prepared(uri, method, headers, body, problem);
    }

    private Answer send(Prepared prepared, TestPlans.Case c, Environment env) {
        HttpRequest.Builder request;
        try {
            request = HttpRequest.newBuilder(prepared.uri()).timeout(timeout)
                    .method(prepared.method(), prepared.body().isEmpty() ? HttpRequest.BodyPublishers.noBody()
                            : HttpRequest.BodyPublishers.ofString(prepared.body()));
            prepared.headers().forEach(request::header);
        } catch (IllegalArgumentException e) {
            return new Answer(failed("The request is not valid: " + e.getMessage()), null, "", prepared.uri());
        }
        try {
            HttpResponse<InputStream> response = env.client().send(request.build(),
                    HttpResponse.BodyHandlers.ofInputStream());
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            ByteArrayOutputStream kept = new ByteArrayOutputStream();
            long length = 0;
            try (InputStream in = response.body()) {
                byte[] buffer = new byte[8192];
                for (int n; length < MAX_BODY && (n = in.read(buffer)) > 0; length += n) {
                    digest.update(buffer, 0, n);
                    if (kept.size() < MAX_READ) kept.write(buffer, 0, Math.min(n, MAX_READ - kept.size()));
                }
            }
            Map<String, String> compared = new LinkedHashMap<>();
            for (String header : compared(c)) {
                List<String> found = response.headers().allValues(header);
                String value = found.isEmpty() ? null : String.join(", ", found);
                if (value != null && header.equals("location")) {
                    String absolute = prepared.uri().resolve(value).toString();
                    value = c.shapeOnly() ? Responses.shape(absolute, env.base()) : Responses.relative(absolute,
                            env.base());
                } else if (value != null && c.shapeOnly()) {
                    // codes and tokens are not shown
                    value = "present";
                }
                compared.put(header, value);
            }
            return new Answer(new Response(response.statusCode(), compared, length,
                    HexFormat.of().formatHex(digest.digest()), null), response.headers(),
                    kept.toString(StandardCharsets.UTF_8), prepared.uri());
        } catch (IOException e) {
            return new Answer(failed(e.getClass().getSimpleName() + (e.getMessage() == null ? "" : ": "
                    + e.getMessage())), null, "", prepared.uri());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new Answer(failed("Interrupted"), null, "", prepared.uri());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Keeps what the case captures from the answer of the environment; what is not found is noted and forgotten. */
    private static void capture(TestPlans.Case c, Environment env, Answer answer, List<String> notes) {
        String location = answer.headers().firstValue("location").map(l -> answer.uri().resolve(l).toString())
                .orElse(null);
        for (TestPlans.Capture capture : c.captures()) {
            String value = switch (capture.from()) {
                case "location" -> location;
                case "query" -> location == null ? null : Responses.param(location, capture.key());
                case "header" -> answer.headers().firstValue(capture.key()).orElse(null);
                case "json" -> Responses.json(answer.text(), capture.key());
                case "form" -> {
                    Responses.Form form = Responses.form(answer.text(), answer.uri());
                    if (form == null) env.forms().remove(capture.name());
                    else env.forms().put(capture.name(), form);
                    yield form == null ? null : form.action();
                }
                default -> null;
            };
            if (value == null || value.isEmpty()) {
                env.captured().remove(capture.name());
                notes.add("Nothing to capture as {{" + capture.name() + "}} on " + env.label());
            } else {
                env.captured().put(capture.name(), value);
            }
        }
    }

    private static Response failed(String error) {
        return new Response(0, Map.of(), 0, "", error);
    }

    /** The text with its variables replaced; the names without a value are added to {@code missing}. */
    private static String substitute(String text, Map<String, String> values, List<String> missing) {
        Matcher matcher = VARIABLE.matcher(text);
        StringBuilder out = new StringBuilder();
        while (matcher.find()) {
            String value = values.get(matcher.group(1));
            if (value == null || value.isEmpty()) missing.add(matcher.group(1));
            matcher.appendReplacement(out, Matcher.quoteReplacement(value == null ? "" : value));
        }
        return matcher.appendTail(out).toString();
    }

    private static String shown(String value) {
        return value == null ? "absent" : "\"" + value + "\"";
    }
}
