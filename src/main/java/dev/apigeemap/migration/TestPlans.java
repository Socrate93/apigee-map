package dev.apigeemap.migration;

import dev.apigeemap.protocol.Json;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Regression test plans of the proxies: the requests to replay on Edge then on hybrid, one JSON file per proxy in a
 * folder, with the fingerprint of the files the plan was prepared from, as for {@link ProxyDocs}.
 */
public final class TestPlans {

    /** A value the person running the plan gives, referenced as {@code {{name}}}. */
    public record Variable(String name, String description) {
    }

    public record Header(String name, String value) {
    }

    /**
     * @param path           from the root of the host, base path and query string included
     * @param expectedStatus what the proxy should answer; 0 when it depends on the backend
     * @param compareHeaders response headers, lower case, whose values must be the same on Edge and hybrid
     * @param safe           false when replaying the request changes something
     */
    public record Case(String name, String flow, String method, String path, List<Header> headers, String body,
                       int expectedStatus, List<String> compareHeaders, boolean safe, String purpose) {
    }

    public record Plan(String summary, List<Variable> variables, List<Case> cases, List<String> warnings) {
    }

    /** @param fingerprint of the files the plan was prepared from, see {@link ProxyDocs#fingerprint} */
    public record Stored(Plan plan, String fingerprint, Instant written) {
    }

    static final Set<String> METHODS = Set.of("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS");

    private final Path dir;

    private TestPlans(Path dir) {
        this.dir = dir;
    }

    public static TestPlans at(Path dir) {
        return new TestPlans(dir);
    }

    public Optional<Stored> get(String proxy) {
        Path file = file(proxy);
        if (!Files.isRegularFile(file)) return Optional.empty();
        try {
            if (!(Json.parse(Files.readString(file)) instanceof Map<?, ?> stored)
                    || !(stored.get("fingerprint") instanceof String fingerprint)
                    || !(stored.get("written") instanceof String written)
                    || !(stored.get("plan") instanceof Map<?, ?> map)) {
                return Optional.empty();
            }
            Plan plan = plan(map);
            return plan == null ? Optional.empty() : Optional.of(new Stored(plan, fingerprint, Instant.parse(written)));
        } catch (IOException | RuntimeException e) {
            // an unreadable plan is one to prepare again
            return Optional.empty();
        }
    }

    public Stored put(String proxy, String fingerprint, Plan plan) throws IOException {
        Files.createDirectories(dir);
        Stored stored = new Stored(plan, fingerprint, Instant.now());
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("proxy", proxy);
        m.put("fingerprint", fingerprint);
        m.put("written", stored.written().toString());
        m.put("plan", plan);
        Path temp = Files.createTempFile(dir, "plan", ".tmp");
        Files.writeString(temp, Json.write(m) + "\n");
        Files.move(temp, file(proxy), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        return stored;
    }

    /**
     * The plan from its JSON form, as stored or as the backend sends it; cases without a name, a known method or a
     * path from the root of the host are left out. Null without a summary or a case.
     */
    public static Plan plan(Map<?, ?> map) {
        if (!(map.get("summary") instanceof String summary) || summary.isBlank()) return null;
        List<Case> cases = new ArrayList<>();
        for (Map<?, ?> c : maps(map.get("cases"))) {
            String name = text(c.get("name"));
            String method = text(c.get("method")).toUpperCase();
            String path = text(c.get("path"));
            if (name.isEmpty() || !METHODS.contains(method) || !path.startsWith("/")) continue;
            List<Header> headers = new ArrayList<>();
            for (Map<?, ?> h : maps(c.get("headers"))) {
                String header = text(h.get("name"));
                if (!header.isEmpty()) headers.add(new Header(header, text(h.get("value"))));
            }
            int expected = c.get("expectedStatus") instanceof Number n ? n.intValue() : 0;
            cases.add(new Case(name, text(c.get("flow")), method, path, List.copyOf(headers),
                    c.get("body") instanceof String body ? body : "", expected >= 100 && expected <= 599 ? expected : 0,
                    points(c.get("compareHeaders")).stream().map(String::toLowerCase).toList(),
                    !Boolean.FALSE.equals(c.get("safe")), text(c.get("purpose"))));
        }
        if (cases.isEmpty()) return null;
        List<Variable> variables = new ArrayList<>();
        for (Map<?, ?> v : maps(map.get("variables"))) {
            String name = text(v.get("name"));
            if (!name.isEmpty()) variables.add(new Variable(name, text(v.get("description"))));
        }
        return new Plan(summary.strip(), List.copyOf(variables), List.copyOf(cases), points(map.get("warnings")));
    }

    private Path file(String proxy) {
        // the name of the proxy may hold anything: the file is named by its hash
        return dir.resolve(ScriptReviews.fingerprint(proxy).substring(0, 32) + ".json");
    }

    private static List<Map<?, ?>> maps(Object list) {
        if (!(list instanceof List<?> items)) return List.of();
        return items.stream().filter(i -> i instanceof Map<?, ?>).<Map<?, ?>>map(i -> (Map<?, ?>) i).toList();
    }

    private static List<String> points(Object list) {
        if (!(list instanceof List<?> items)) return List.of();
        return items.stream().map(TestPlans::text).filter(t -> !t.isEmpty()).toList();
    }

    private static String text(Object value) {
        return value instanceof String s ? s.strip() : "";
    }
}
