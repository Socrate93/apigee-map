package dev.apigeemap.migration;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Replays the cases of a {@link TestPlans.Plan} on Edge then on hybrid, one case after the other, and compares the
 * statuses and the headers the plan names. Redirects are not followed, so that they are compared too; bodies are only
 * compared by their hash, as they often hold timestamps or ids.
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

    private final HttpClient client;
    private final Duration timeout;

    public TestRunner(Duration timeout) {
        this.timeout = timeout;
        this.client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER)
                .version(HttpClient.Version.HTTP_1_1).connectTimeout(timeout).build();
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
     * Runs the cases whose index is in {@code only}, or all of them when it is null; unsafe cases only with {@code
     * unsafe}.
     *
     * @param edge   from {@link #baseUrl}
     * @param hybrid from {@link #baseUrl}
     * @param values the values of the variables, by name
     */
    public Run run(TestPlans.Plan plan, String edge, String hybrid, Map<String, String> values, boolean unsafe,
                   Set<Integer> only) {
        List<Result> results = new ArrayList<>();
        for (int i = 0; i < plan.cases().size(); i++) {
            if (only != null && !only.contains(i)) continue;
            results.add(run(i, plan.cases().get(i), edge, hybrid, values, unsafe));
        }
        return new Run(edge, hybrid, results);
    }

    private Result run(int index, TestPlans.Case c, String edge, String hybrid, Map<String, String> values,
                       boolean unsafe) {
        if (!c.safe() && !unsafe) {
            return new Result(index, c.name(), Outcome.SKIPPED, null, null, List.of(),
                    List.of("It changes data: it runs only when unsafe cases are included"));
        }
        List<String> missing = new ArrayList<>();
        String path = substitute(c.path(), values, missing);
        Map<String, String> headers = new LinkedHashMap<>();
        c.headers().forEach(h -> headers.put(h.name(), substitute(h.value(), values, missing)));
        String body = substitute(c.body(), values, missing);
        if (!missing.isEmpty()) {
            return new Result(index, c.name(), Outcome.ERROR, null, null, List.of(),
                    List.of("No value for " + String.join(", ", missing.stream().distinct()
                            .map(n -> "{{" + n + "}}").toList())));
        }
        Response onEdge = send(edge, c, path, headers, body);
        Response onHybrid = send(hybrid, c, path, headers, body);
        List<String> differences = new ArrayList<>();
        List<String> notes = new ArrayList<>();
        if (onEdge.error() != null || onHybrid.error() != null) {
            return new Result(index, c.name(), Outcome.ERROR, onEdge, onHybrid, differences, notes);
        }
        if (onEdge.status() != onHybrid.status()) {
            differences.add("Status " + onEdge.status() + " on Edge, " + onHybrid.status() + " on hybrid");
        }
        for (String header : c.compareHeaders()) {
            String a = onEdge.headers().get(header);
            String b = onHybrid.headers().get(header);
            if (a == null ? b != null : !a.equals(b)) {
                differences.add(header + ": " + shown(a) + " on Edge, " + shown(b) + " on hybrid");
            }
        }
        if (c.expectedStatus() != 0) {
            if (onEdge.status() != c.expectedStatus()) {
                notes.add("Edge answered " + onEdge.status() + ", the plan expects " + c.expectedStatus());
            }
            if (onHybrid.status() != c.expectedStatus()) {
                notes.add("Hybrid answered " + onHybrid.status() + ", the plan expects " + c.expectedStatus());
            }
        }
        if (!onEdge.bodyHash().equals(onHybrid.bodyHash())) {
            notes.add("The bodies differ: " + onEdge.bodyLength() + " bytes on Edge, " + onHybrid.bodyLength()
                    + " on hybrid");
        }
        return new Result(index, c.name(), differences.isEmpty() ? Outcome.SAME : Outcome.DIFFERENT, onEdge, onHybrid,
                differences, notes);
    }

    private Response send(String base, TestPlans.Case c, String path, Map<String, String> headers, String body) {
        HttpRequest.Builder request;
        try {
            request = HttpRequest.newBuilder(new URI(base + path)).timeout(timeout)
                    .method(c.method(), body.isEmpty() ? HttpRequest.BodyPublishers.noBody()
                            : HttpRequest.BodyPublishers.ofString(body));
            headers.forEach(request::header);
        } catch (URISyntaxException | IllegalArgumentException e) {
            return failed("The request is not valid: " + e.getMessage());
        }
        try {
            HttpResponse<InputStream> response = client.send(request.build(), HttpResponse.BodyHandlers.ofInputStream());
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            long length = 0;
            try (InputStream in = response.body()) {
                byte[] buffer = new byte[8192];
                for (int n; length < MAX_BODY && (n = in.read(buffer)) > 0; length += n) digest.update(buffer, 0, n);
            }
            Map<String, String> compared = new LinkedHashMap<>();
            for (String header : c.compareHeaders()) {
                List<String> found = response.headers().allValues(header);
                compared.put(header, found.isEmpty() ? null : String.join(", ", found));
            }
            return new Response(response.statusCode(), compared, length, HexFormat.of().formatHex(digest.digest()),
                    null);
        } catch (IOException e) {
            return failed(e.getClass().getSimpleName() + (e.getMessage() == null ? "" : ": " + e.getMessage()));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return failed("Interrupted");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
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
