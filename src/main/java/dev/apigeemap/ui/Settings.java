package dev.apigeemap.ui;

import dev.apigeemap.migration.FalsePositive;
import dev.apigeemap.migration.MigrationOptions;
import dev.apigeemap.model.Issue;
import dev.apigeemap.protocol.Json;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

/**
 * UI settings, stored as JSON (by default in {@code ~/.apigee-map/settings.json}).
 *
 * @param proxiesRoot       folder searched (recursively) for apiproxy/ bundles
 * @param sharedFlowDirs    folders searched for sharedflowbundle/ bundles
 * @param outputDir         where migrated bundles are written, one sub-folder per proxy
 * @param disabledRules     migration rule ids not to run
 * @param severities        severity overrides by rule id
 * @param namingPrefixes    accepted policy name prefixes by policy type, replacing the defaults of that type
 * @param falsePositives    findings marked as false positives, one per rule, bundle and location
 */
public record Settings(String proxiesRoot, List<String> sharedFlowDirs, String outputDir, List<String> disabledRules,
                       Map<String, String> severities, Map<String, List<String>> namingPrefixes,
                       List<FalsePositive> falsePositives) {

    public static final Settings EMPTY = new Settings("", List.of(), "", List.of(), Map.of(), Map.of(), List.of());

    public Settings {
        proxiesRoot = proxiesRoot == null ? "" : proxiesRoot.trim();
        outputDir = outputDir == null ? "" : outputDir.trim();
        sharedFlowDirs = sharedFlowDirs == null ? List.of()
                : sharedFlowDirs.stream().map(String::trim).filter(s -> !s.isEmpty()).distinct().toList();
        disabledRules = disabledRules == null ? List.of() : List.copyOf(new LinkedHashSet<>(disabledRules));
        severities = severities == null ? Map.of() : Map.copyOf(severities);
        namingPrefixes = namingPrefixes == null ? Map.of() : Map.copyOf(namingPrefixes);
        List<FalsePositive> unique = new ArrayList<>();
        // the last one of a rule, bundle and location wins
        if (falsePositives != null) {
            for (FalsePositive falsePositive : falsePositives) {
                unique.removeIf(falsePositive::sameFinding);
                unique.add(falsePositive);
            }
        }
        falsePositives = List.copyOf(unique);
    }

    public static Path defaultFile() {
        return Path.of(System.getProperty("user.home"), ".apigee-map", "settings.json");
    }

    static Settings load(Path file) throws IOException {
        if (!Files.isRegularFile(file)) return EMPTY;
        try {
            return fromJson(Json.parse(Files.readString(file)));
        } catch (IllegalArgumentException e) {
            throw new IOException("Invalid settings file " + file + ": " + e.getMessage(), e);
        }
    }

    void save(Path file) throws IOException {
        Files.createDirectories(file.toAbsolutePath().getParent());
        Files.writeString(file, Json.write(this) + "\n");
    }

    /** Builds settings from parsed JSON; unknown fields are ignored, invalid values rejected. */
    static Settings fromJson(Object json) {
        if (!(json instanceof Map<?, ?> map)) throw new IllegalArgumentException("Settings must be a JSON object");
        Map<String, String> severities = new LinkedHashMap<>();
        stringMap(map.get("severities")).forEach((rule, severity) -> {
            try {
                Issue.Severity.valueOf(severity);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("Unknown severity " + severity + " for rule " + rule);
            }
            severities.put(rule, severity);
        });
        Map<String, List<String>> prefixes = new LinkedHashMap<>();
        if (map.get("namingPrefixes") instanceof Map<?, ?> raw) {
            raw.forEach((type, value) -> prefixes.put(String.valueOf(type), strings(value)));
        }
        return new Settings(string(map.get("proxiesRoot")), strings(map.get("sharedFlowDirs")),
                string(map.get("outputDir")), strings(map.get("disabledRules")), severities, prefixes,
                falsePositives(map.get("falsePositives")));
    }

    MigrationOptions migrationOptions() {
        Map<String, Issue.Severity> overrides = new LinkedHashMap<>();
        severities.forEach((rule, severity) -> overrides.put(rule, Issue.Severity.valueOf(severity)));
        return new MigrationOptions(new LinkedHashSet<>(disabledRules), overrides, namingPrefixes, falsePositives);
    }

    /** These settings with {@code falsePositive} added, replacing the one of the same finding. */
    Settings withFalsePositive(FalsePositive falsePositive) {
        List<FalsePositive> updated = new ArrayList<>(falsePositives);
        updated.add(falsePositive);
        return withFalsePositives(updated);
    }

    /** These settings without the false positive of that rule, bundle and location. */
    Settings withoutFalsePositive(String rule, String bundle, String location) {
        List<FalsePositive> updated = new ArrayList<>(falsePositives);
        updated.removeIf(f -> f.matches(rule, bundle, location));
        return withFalsePositives(updated);
    }

    private Settings withFalsePositives(List<FalsePositive> updated) {
        return new Settings(proxiesRoot, sharedFlowDirs, outputDir, disabledRules, severities, namingPrefixes, updated);
    }

    List<Path> sharedFlowPaths() {
        return sharedFlowDirs.stream().map(Path::of).toList();
    }

    private static String string(Object value) {
        return value == null ? "" : String.valueOf(value);
    }

    private static List<String> strings(Object value) {
        List<String> result = new ArrayList<>();
        if (value instanceof List<?> list) list.forEach(item -> result.add(String.valueOf(item).trim()));
        result.removeIf(String::isEmpty);
        return result;
    }

    private static List<FalsePositive> falsePositives(Object value) {
        List<FalsePositive> result = new ArrayList<>();
        if (!(value instanceof List<?> list)) return result;
        for (Object item : list) {
            if (!(item instanceof Map<?, ?> map)) throw new IllegalArgumentException("A false positive must be an object");
            result.add(falsePositive(map));
        }
        return result;
    }

    /** A false positive from {@code {rule, bundle, location, reason}}; each one is required. */
    static FalsePositive falsePositive(Map<?, ?> map) {
        return new FalsePositive(text(map.get("rule")), text(map.get("bundle")), text(map.get("location")),
                text(map.get("reason")));
    }

    private static String text(Object value) {
        return value instanceof String s ? s : null;
    }

    private static Map<String, String> stringMap(Object value) {
        Map<String, String> result = new LinkedHashMap<>();
        if (value instanceof Map<?, ?> map) map.forEach((k, v) -> result.put(String.valueOf(k), String.valueOf(v)));
        return result;
    }
}
