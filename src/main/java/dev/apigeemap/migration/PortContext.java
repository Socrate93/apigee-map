package dev.apigeemap.migration;

import dev.apigeemap.analysis.Xml;
import dev.apigeemap.model.BundleReport;

import java.io.IOException;
import java.nio.charset.CharacterCodingException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

/**
 * What it takes to port a Node.js or hosted target, which Apigee hybrid does not run: the {@link FixContext} of its
 * HYB-04 finding, plus the application under {@code resources/node} and {@code resources/hosted} and the endpoints of
 * the bundle. Installed modules ({@code node_modules}), binary files and files over {@value #MAX_FILE} bytes are left
 * out: {@code package.json} says which modules the application needs.
 */
public final class PortContext {

    public static final String RULE = "HYB-04";
    private static final long MAX_FILE = 200_000;

    private PortContext() {
    }

    /** Whether the finding is about a target to port, rather than about resources no target uses. */
    public static boolean portable(Finding finding) {
        return finding.rule().equals(RULE) && finding.location().startsWith("TargetEndpoint ");
    }

    public static FixContext of(Finding finding, Map<String, BundleReport> bundles) throws IOException {
        if (!portable(finding)) throw new IllegalArgumentException("Not a Node.js or hosted target: " + finding.location());
        FixContext context = FixContext.of(finding, bundles);
        BundleReport bundle = bundles.get(finding.bundle());
        Path dir = Path.of(bundle.path()).toAbsolutePath().normalize();
        Map<String, FixContext.SourceFile> files = new LinkedHashMap<>();
        context.files().forEach(f -> files.put(f.bundle() + "/" + f.path(), f));
        List<Path> found = new ArrayList<>();
        for (String folder : List.of("proxies", "targets")) found.addAll(Xml.xmlFiles(dir.resolve(folder)));
        for (String type : List.of("node", "hosted")) {
            Path resources = dir.resolve("resources").resolve(type);
            if (!Files.isDirectory(resources)) continue;
            try (Stream<Path> walk = Files.walk(resources)) {
                walk.filter(Files::isRegularFile)
                        .filter(p -> !dir.relativize(p).toString().replace('\\', '/').contains("node_modules/"))
                        .sorted().forEach(found::add);
            }
        }
        for (Path file : found) {
            String path = dir.relativize(file).toString().replace('\\', '/');
            String key = bundle.name() + "/" + path;
            if (files.containsKey(key) || Files.size(file) > MAX_FILE) continue;
            String content;
            try {
                content = Files.readString(file);
            } catch (CharacterCodingException e) {
                continue;
            }
            if (content.indexOf('\0') >= 0) continue;
            files.put(key, new FixContext.SourceFile(bundle.name(), path, content));
        }
        return new FixContext(context.finding(), context.ruleTitle(), context.policies(), List.copyOf(files.values()));
    }
}
