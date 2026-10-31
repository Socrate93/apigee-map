package dev.apigeemap.ui;

import dev.apigeemap.migration.ProxyDocs;
import dev.apigeemap.protocol.Json;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.stream.Stream;

/**
 * What the last analysis of each proxy found, so that the list and the page of a proxy open without analyzing anything:
 * the figures of the list in one JSON file, updated by each analysis, and what the page shows in {@code analyses/} next
 * to it, one file per proxy. With the figures is a stamp of what they were computed from: it tells cheaply, without
 * reading the files, whether a proxy changed since. These files only save time: when they cannot be read or written,
 * proxies are analyzed again.
 */
final class ProxyStats {

    /**
     * @param bundles the folder of the proxy and of each shared flow it calls, by bundle name
     * @param stamp   see {@link #stamp}
     */
    record Entry(UiService.ProxySummary summary, Map<String, String> bundles, String stamp, Instant analyzed) {
    }

    private final Path file;
    private final Map<String, Entry> entries = new LinkedHashMap<>();

    private ProxyStats(Path file) {
        this.file = file;
    }

    static ProxyStats at(Path file) {
        ProxyStats stats = new ProxyStats(file);
        try {
            if (Files.isRegularFile(file) && Json.parse(Files.readString(file)) instanceof Map<?, ?> map) {
                map.forEach((dir, entry) -> {
                    if (dir instanceof String key && entry instanceof Map<?, ?> m) stats.entries.put(key, entry(m));
                });
            }
        } catch (IOException | RuntimeException e) {
            System.err.println("Ignoring " + file + ": " + e.getMessage());
            stats.entries.clear();
        }
        return stats;
    }

    /** What was found the last time the proxy in this folder was analyzed. */
    synchronized Optional<Entry> get(Path dir) {
        return Optional.ofNullable(entries.get(dir.toString()));
    }

    synchronized void put(Path dir, Entry entry) {
        entries.put(dir.toString(), entry);
        write(file, Json.write(entries.entrySet().stream().collect(LinkedHashMap::new,
                (m, e) -> m.put(e.getKey(), view(e.getValue())), Map::putAll)) + "\n");
    }

    /** What the page of the proxy in this folder showed after its last analysis, as JSON. */
    Optional<Map<?, ?>> detail(Path dir) {
        Path path = detailFile(dir);
        try {
            return Files.isRegularFile(path) && Json.parse(Files.readString(path)) instanceof Map<?, ?> map
                    ? Optional.of(map) : Optional.empty();
        } catch (IOException | RuntimeException e) {
            System.err.println("Ignoring " + path + ": " + e.getMessage());
            return Optional.empty();
        }
    }

    void putDetail(Path dir, Object detail) {
        write(detailFile(dir), Json.write(detail) + "\n");
    }

    private Path detailFile(Path dir) {
        return file.toAbsolutePath().resolveSibling("analyses")
                .resolve(ProxyDocs.fingerprint(List.of(new ProxyDocs.SourceFile("", dir.toString(), ""))) + ".json");
    }

    private static void write(Path path, String content) {
        try {
            Files.createDirectories(path.toAbsolutePath().getParent());
            Path temp = Files.createTempFile(path.toAbsolutePath().getParent(), "stats", ".tmp");
            Files.writeString(temp, content);
            Files.move(temp, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            System.err.println("Cannot write " + path + ": " + e.getMessage());
        }
    }

    /**
     * What the figures of a proxy depend on: the name, size and date of the files of its bundles, the settings of the
     * rules, and the false positives of these bundles. A change that keeps the text the same counts as a change.
     *
     * @param folders the files of the folders already looked at, kept between proxies that call the same shared flows
     */
    static String stamp(Settings s, Map<String, String> bundles, Map<String, List<ProxyDocs.SourceFile>> folders) {
        List<ProxyDocs.SourceFile> parts = new ArrayList<>();
        parts.add(new ProxyDocs.SourceFile("", "settings", List.of(new TreeSet<>(s.disabledRules()),
                new TreeMap<>(s.severities()), new TreeMap<>(s.namingPrefixes()), new TreeSet<>(s.sharedFlowDirs()),
                s.falsePositives().stream().filter(f -> bundles.containsKey(f.bundle())).map(Object::toString)
                        .sorted().toList()).toString()));
        new TreeMap<>(bundles).forEach((name, dir) ->
                folders.computeIfAbsent(dir, d -> files(Path.of(d))).forEach(f ->
                        parts.add(new ProxyDocs.SourceFile(name, f.path(), f.content()))));
        return ProxyDocs.fingerprint(parts);
    }

    /** The files of a folder with their size and date for content; none when it cannot be read. */
    private static List<ProxyDocs.SourceFile> files(Path dir) {
        try (Stream<Path> walk = Files.walk(dir)) {
            List<ProxyDocs.SourceFile> files = new ArrayList<>();
            for (Path path : walk.sorted().toList()) {
                BasicFileAttributes attributes = Files.readAttributes(path, BasicFileAttributes.class);
                if (!attributes.isRegularFile()) continue;
                files.add(new ProxyDocs.SourceFile("", dir.relativize(path).toString().replace('\\', '/'),
                        attributes.size() + " " + attributes.lastModifiedTime().toMillis()));
            }
            return files;
        } catch (IOException | UncheckedIOException e) {
            return List.of();
        }
    }

    private static Map<String, Object> view(Entry entry) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("analyzed", entry.analyzed().toString());
        m.put("stamp", entry.stamp());
        m.put("bundles", entry.bundles());
        m.put("summary", entry.summary());
        return m;
    }

    private static Entry entry(Map<?, ?> map) {
        Map<?, ?> s = (Map<?, ?>) map.get("summary");
        Map<String, String> bundles = new LinkedHashMap<>();
        ((Map<?, ?>) map.get("bundles")).forEach((name, dir) -> bundles.put((String) name, (String) dir));
        return new Entry(new UiService.ProxySummary((String) s.get("id"), (String) s.get("name"),
                (String) s.get("revision"), (String) s.get("description"), (int) number(s.get("sharedFlows")),
                number(s.get("errors")), number(s.get("warnings")), number(s.get("infos")), number(s.get("autoFixes")),
                number(s.get("manual")), false, (String) s.get("error"), null, false),
                bundles, (String) map.get("stamp"), Instant.parse((String) map.get("analyzed")));
    }

    private static long number(Object value) {
        return value instanceof Number n ? n.longValue() : 0;
    }
}
