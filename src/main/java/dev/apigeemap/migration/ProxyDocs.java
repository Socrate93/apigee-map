package dev.apigeemap.migration;

import dev.apigeemap.model.BundleReport;
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
import java.util.stream.Stream;

/**
 * Functional documentation of the proxies, one JSON file per proxy in a folder, with the fingerprint of the files it
 * was written from: it tells whether the proxy changed since.
 */
public final class ProxyDocs {

    /** @param kind TARGET, CALLOUT, SHARED_FLOW, KVM, CACHE or OTHER */
    public record Dependency(String name, String kind, String description) {
    }

    /** @param path under the base path; empty for the base path itself */
    public record Operation(String method, String path, String flow, String description) {
    }

    /** Texts may name policies, flows or variables in backticks. */
    public record Doc(String summary, List<Operation> operations, List<String> security,
                      List<Dependency> dependencies, List<String> errors, List<String> notes) {
    }

    /** @param fingerprint of the files the documentation was written from, see {@link #fingerprint} */
    public record Stored(Doc doc, String fingerprint, Instant written) {
    }

    /** A source file of the proxy or of a shared flow it calls, as sent to be documented. */
    public record SourceFile(String bundle, String path, String content) {
    }

    /** Files sent to be documented: the text sources of the bundles, not the JARs nor files this large. */
    private static final Set<String> TEXT = Set.of("xml", "js", "py", "json", "xsl", "xslt", "xsd", "wsdl",
            "properties", "yaml", "yml", "graphql", "txt");
    private static final long MAX_FILE = 200_000;

    private final Path dir;

    private ProxyDocs(Path dir) {
        this.dir = dir;
    }

    public static ProxyDocs at(Path dir) {
        return new ProxyDocs(dir);
    }

    /** The text files of the proxy and of the shared flows it calls, bundle by bundle, sorted by path. */
    public static List<SourceFile> files(BundleReport root) throws IOException {
        List<SourceFile> files = new ArrayList<>();
        for (BundleReport bundle : FixContext.bundles(root).values()) {
            Path base = Path.of(bundle.path());
            List<Path> paths;
            try (Stream<Path> walk = Files.walk(base)) {
                paths = walk.filter(Files::isRegularFile).filter(ProxyDocs::text).sorted().toList();
            }
            for (Path file : paths) {
                if (Files.size(file) > MAX_FILE) continue;
                files.add(new SourceFile(bundle.name(), base.relativize(file).toString().replace('\\', '/'),
                        Files.readString(file)));
            }
        }
        return files;
    }

    /** SHA-256 of the files, their bundles and paths, in hex. */
    public static String fingerprint(List<SourceFile> files) {
        StringBuilder all = new StringBuilder();
        for (SourceFile file : files) {
            all.append(file.bundle()).append('\0').append(file.path()).append('\0').append(file.content()).append('\0');
        }
        return ScriptReviews.fingerprint(all.toString());
    }

    public Optional<Stored> get(String proxy) {
        Path file = file(proxy);
        if (!Files.isRegularFile(file)) return Optional.empty();
        try {
            if (!(Json.parse(Files.readString(file)) instanceof Map<?, ?> stored)
                    || !(stored.get("fingerprint") instanceof String fingerprint)
                    || !(stored.get("written") instanceof String written)
                    || !(stored.get("doc") instanceof Map<?, ?> map)) {
                return Optional.empty();
            }
            Doc doc = doc(map);
            return doc == null ? Optional.empty() : Optional.of(new Stored(doc, fingerprint, Instant.parse(written)));
        } catch (IOException | RuntimeException e) {
            // an unreadable documentation is one to write again
            return Optional.empty();
        }
    }

    public Stored put(String proxy, String fingerprint, Doc doc) throws IOException {
        Files.createDirectories(dir);
        Stored stored = new Stored(doc, fingerprint, Instant.now());
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("proxy", proxy);
        m.put("fingerprint", fingerprint);
        m.put("written", stored.written().toString());
        m.put("doc", doc);
        Path temp = Files.createTempFile(dir, "doc", ".tmp");
        Files.writeString(temp, Json.write(m) + "\n");
        Files.move(temp, file(proxy), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        return stored;
    }

    /** The documentation from its JSON form, as stored or as the backend sends it; null without a summary. */
    public static Doc doc(Map<?, ?> map) {
        if (!(map.get("summary") instanceof String summary) || summary.isBlank()) return null;
        List<Operation> operations = new ArrayList<>();
        for (Map<?, ?> o : maps(map.get("operations"))) {
            String description = text(o.get("description"));
            if (description.isEmpty()) continue;
            String method = text(o.get("method"));
            operations.add(new Operation(method.isEmpty() ? "ANY" : method, text(o.get("path")), text(o.get("flow")),
                    description));
        }
        List<Dependency> dependencies = new ArrayList<>();
        for (Map<?, ?> d : maps(map.get("dependencies"))) {
            String name = text(d.get("name"));
            String kind = text(d.get("kind"));
            if (!name.isEmpty()) dependencies.add(new Dependency(name, kind.isEmpty() ? "OTHER" : kind,
                    text(d.get("description"))));
        }
        return new Doc(summary.strip(), List.copyOf(operations), points(map.get("security")),
                List.copyOf(dependencies), points(map.get("errors")), points(map.get("notes")));
    }

    private Path file(String proxy) {
        // the name of the proxy may hold anything: the file is named by its hash
        return dir.resolve(ScriptReviews.fingerprint(proxy).substring(0, 32) + ".json");
    }

    private static boolean text(Path file) {
        String name = file.getFileName().toString();
        int dot = name.lastIndexOf('.');
        return dot > 0 && TEXT.contains(name.substring(dot + 1).toLowerCase());
    }

    private static List<Map<?, ?>> maps(Object list) {
        if (!(list instanceof List<?> items)) return List.of();
        return items.stream().filter(i -> i instanceof Map<?, ?>).<Map<?, ?>>map(i -> (Map<?, ?>) i).toList();
    }

    private static List<String> points(Object list) {
        if (!(list instanceof List<?> items)) return List.of();
        return items.stream().map(ProxyDocs::text).filter(t -> !t.isEmpty()).toList();
    }

    private static String text(Object value) {
        return value instanceof String s ? s.strip() : "";
    }
}
