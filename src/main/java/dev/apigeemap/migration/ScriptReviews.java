package dev.apigeemap.migration;

import dev.apigeemap.model.Issue;
import dev.apigeemap.protocol.Json;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Remarks of the script reviews, kept by the fingerprint of each script (one JSON file per script in a folder): they
 * hold while the script is unchanged, and a script found in several bundles is reviewed once. Rule REV-01 reports
 * them as findings.
 */
public final class ScriptReviews {

    /** @param line in the script file, or in the policy file for an inline script; 0 for the whole script */
    public record Remark(int line, Finding.Category category, Issue.Severity severity, String title, String message,
                         String action) {
    }

    /** No review: REV-01 reports nothing. */
    public static final ScriptReviews NONE = new ScriptReviews(null);

    private final Path dir;

    private ScriptReviews(Path dir) {
        this.dir = dir;
    }

    public static ScriptReviews at(Path dir) {
        return new ScriptReviews(dir);
    }

    public static Path defaultRoot() {
        return Path.of(System.getProperty("user.home"), ".apigee-map", "reviews");
    }

    /** SHA-256 of the script source, in hex. */
    public static String fingerprint(String source) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(source.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The remarks of the script, empty when it has none; nothing when it was never reviewed as it is now. */
    public Optional<List<Remark>> get(String fingerprint) {
        if (dir == null) return Optional.empty();
        Path file = dir.resolve(fingerprint + ".json");
        if (!Files.isRegularFile(file)) return Optional.empty();
        try {
            if (!(Json.parse(Files.readString(file)) instanceof Map<?, ?> stored)
                    || !(stored.get("remarks") instanceof List<?> list)) {
                return Optional.empty();
            }
            List<Remark> remarks = new ArrayList<>();
            for (Object item : list) {
                Remark remark = item instanceof Map<?, ?> map ? remark(map) : null;
                if (remark != null) remarks.add(remark);
            }
            return Optional.of(List.copyOf(remarks));
        } catch (IOException | IllegalArgumentException e) {
            // an unreadable review is one to make again
            return Optional.empty();
        }
    }

    public boolean has(String fingerprint) {
        return get(fingerprint).isPresent();
    }

    public void put(String fingerprint, List<Remark> remarks) throws IOException {
        if (dir == null) throw new IllegalStateException("No folder to keep the reviews in");
        Files.createDirectories(dir);
        List<Map<String, Object>> list = remarks.stream().map(r -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("line", r.line());
            m.put("category", r.category().name());
            m.put("severity", r.severity().name());
            m.put("title", r.title());
            m.put("message", r.message());
            m.put("action", r.action());
            return m;
        }).toList();
        Path temp = Files.createTempFile(dir, fingerprint, ".tmp");
        Files.writeString(temp, Json.write(Map.of("remarks", list)) + "\n");
        Files.move(temp, dir.resolve(fingerprint + ".json"), StandardCopyOption.REPLACE_EXISTING,
                StandardCopyOption.ATOMIC_MOVE);
    }

    /** A remark from its JSON form, as stored or as the backend sends it; null when it is not one. */
    public static Remark remark(Map<?, ?> map) {
        try {
            Finding.Category category = Finding.Category.valueOf(String.valueOf(map.get("category")));
            Issue.Severity severity = Issue.Severity.valueOf(String.valueOf(map.get("severity")));
            if (!(map.get("title") instanceof String title) || title.isBlank()
                    || !(map.get("message") instanceof String message) || message.isBlank()) {
                return null;
            }
            int line = map.get("line") instanceof Number n ? Math.max(0, n.intValue()) : 0;
            return new Remark(line, category, severity, title.strip(), message.strip(),
                    map.get("action") instanceof String action ? action.strip() : "");
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
