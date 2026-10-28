package dev.apigeemap.ui;

import dev.apigeemap.analysis.BundleAnalyzer;
import dev.apigeemap.analysis.BundleLocator;
import dev.apigeemap.analysis.SharedFlowRepository;
import dev.apigeemap.migration.EnvResource;
import dev.apigeemap.migration.Finding;
import dev.apigeemap.migration.MigrationReport;
import dev.apigeemap.migration.Migrator;
import dev.apigeemap.migration.RuleInfo;
import dev.apigeemap.model.BundleReport;
import dev.apigeemap.model.Issue;
import dev.apigeemap.render.HtmlRenderer;
import dev.apigeemap.render.MigrationHtmlRenderer;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Stream;

/** What the UI does: settings, proxy discovery, analysis, migration preview and application, overview. */
final class UiService {

    /** Folders below the proxies root searched for apiproxy/ bundles. */
    private static final int SCAN_DEPTH = 6;

    /** A proxy found under the proxies root; {@code id} is its folder relative to the root. */
    record ProxySummary(String id, String name, String revision, String description, int sharedFlows,
                        long errors, long warnings, long infos, long autoFixes, long manual, boolean migrated,
                        String error) {
    }

    record ProxyDetail(ProxySummary summary, String path, int policies, int dependencies, String outputDir,
                       MigrationReport migration) {
    }

    record RuleStat(String id, String category, String title, long findings, long proxies,
                    Map<String, Long> bySeverity) {
    }

    record ResourceNeed(String kind, String name, String details, List<String> proxies) {
    }

    record Overview(int proxies, int failed, long errors, long warnings, long infos, long autoFixes, long manual,
                    long migrated, List<RuleStat> rules, List<ResourceNeed> resources) {
    }

    /** State of one configured folder, shown next to the field in the Settings screen. */
    record PathCheck(String path, boolean exists, String message) {
    }

    private final Path settingsFile;
    private Settings settings;

    UiService(Path settingsFile) throws IOException {
        this.settingsFile = settingsFile;
        this.settings = Settings.load(settingsFile);
    }

    synchronized Settings settings() {
        return settings;
    }

    Path settingsFile() {
        return settingsFile;
    }

    synchronized void save(Settings updated) throws IOException {
        updated.save(settingsFile);
        settings = updated;
    }

    List<RuleInfo> rules() {
        return Migrator.rules();
    }

    Map<String, List<String>> defaultNamingPrefixes() {
        return Migrator.defaultNamingPrefixes();
    }

    Map<String, Object> checks() {
        Settings s = settings();
        Map<String, Object> checks = new LinkedHashMap<>();
        PathCheck root = folder(s.proxiesRoot(), "Not set: the proxy list stays empty");
        if (root.exists()) {
            try {
                int count = proxyDirs(s).size();
                root = new PathCheck(root.path(), true, count + " proxy bundle(s) found");
            } catch (IOException e) {
                root = new PathCheck(root.path(), false, e.getMessage());
            }
        }
        checks.put("proxiesRoot", root);
        List<PathCheck> sharedFlows = new ArrayList<>();
        for (String dir : s.sharedFlowDirs()) {
            PathCheck check = folder(dir, "");
            if (check.exists()) {
                try (Stream<Path> paths = Files.walk(Path.of(dir), 5)) {
                    long count = paths.filter(p -> p.getFileName().toString().equals("sharedflowbundle")).count();
                    check = new PathCheck(dir, true, count + " shared flow(s) found");
                } catch (IOException | UncheckedIOException e) {
                    check = new PathCheck(dir, false, e.getMessage());
                }
            }
            sharedFlows.add(check);
        }
        checks.put("sharedFlowDirs", sharedFlows);
        PathCheck output = s.outputDir().isEmpty()
                ? new PathCheck("", false, "Not set: migrations cannot be applied")
                : Files.isDirectory(Path.of(s.outputDir()))
                ? new PathCheck(s.outputDir(), true, "Migrated proxies are written here")
                : new PathCheck(s.outputDir(), false, "Does not exist yet: it is created on the first migration");
        checks.put("outputDir", output);
        return checks;
    }

    private static PathCheck folder(String path, String whenEmpty) {
        if (path.isEmpty()) return new PathCheck("", false, whenEmpty);
        if (!Files.isDirectory(Path.of(path))) return new PathCheck(path, false, "Folder not found");
        return new PathCheck(path, true, "");
    }

    List<ProxySummary> proxies() throws IOException {
        Settings s = settings();
        SharedFlowRepository repository = repository(s);
        Migrator migrator = new Migrator(s.migrationOptions());
        List<ProxySummary> result = new ArrayList<>();
        for (Path dir : proxyDirs(s)) {
            String id = id(s, dir);
            try {
                BundleReport analysis = new BundleAnalyzer(repository).analyze(BundleLocator.locate(dir));
                result.add(summary(s, id, analysis, migrator.migrate(analysis, null)));
            } catch (IOException | RuntimeException e) {
                result.add(new ProxySummary(id, dir.getFileName().toString(), null, null, 0, 0, 0, 0, 0, 0, false,
                        e.getMessage()));
            }
        }
        return result;
    }

    ProxyDetail proxy(String id) throws IOException {
        Settings s = settings();
        BundleReport analysis = analyze(s, id);
        MigrationReport migration = new Migrator(s.migrationOptions()).migrate(analysis, null);
        return new ProxyDetail(summary(s, id, analysis, migration), analysis.path(), analysis.policies().size(),
                analysis.dependencies().size(), output(s, analysis.name()).map(Path::toString).orElse(null),
                migration);
    }

    String mapHtml(String id) throws IOException {
        return new HtmlRenderer().render(analyze(settings(), id));
    }

    String migrationHtml(String id) throws IOException {
        Settings s = settings();
        return new MigrationHtmlRenderer().render(new Migrator(s.migrationOptions()).migrate(analyze(s, id), null));
    }

    /**
     * Writes the migrated proxy and its shared flows to {@code <outputDir>/<proxy name>}. An existing result is
     * replaced only when {@code overwrite} is set.
     */
    MigrationReport apply(String id, boolean overwrite) throws IOException {
        Settings s = settings();
        BundleReport analysis = analyze(s, id);
        Path target = output(s, analysis.name())
                .orElseThrow(() -> new UiException(409, "Set the output folder in Settings first"));
        if (Files.exists(target) && !isEmpty(target)) {
            if (!overwrite) {
                throw new UiException(409, "A migration of " + analysis.name() + " already exists in " + target);
            }
            deleteTree(target);
        }
        return new Migrator(s.migrationOptions()).migrate(analysis, target);
    }

    Overview overview() throws IOException {
        List<ProxySummary> proxies = new ArrayList<>();
        Map<String, List<Finding>> findingsByRule = new LinkedHashMap<>();
        Map<String, Set<String>> proxiesByRule = new LinkedHashMap<>();
        Map<String, ResourceNeed> resources = new TreeMap<>();
        Settings s = settings();
        SharedFlowRepository repository = repository(s);
        Migrator migrator = new Migrator(s.migrationOptions());
        int failed = 0;
        for (Path dir : proxyDirs(s)) {
            String id = id(s, dir);
            try {
                BundleReport analysis = new BundleAnalyzer(repository).analyze(BundleLocator.locate(dir));
                MigrationReport migration = migrator.migrate(analysis, null);
                proxies.add(summary(s, id, analysis, migration));
                for (Finding finding : migration.findings()) {
                    findingsByRule.computeIfAbsent(finding.rule(), r -> new ArrayList<>()).add(finding);
                    proxiesByRule.computeIfAbsent(finding.rule(), r -> new LinkedHashSet<>()).add(analysis.name());
                }
                for (EnvResource resource : migration.resources()) {
                    resources.computeIfAbsent(resource.kind() + "\u0000" + resource.name(),
                                    k -> new ResourceNeed(resource.kind(), resource.name(), resource.details(),
                                            new ArrayList<>()))
                            .proxies().add(analysis.name());
                }
            } catch (IOException | RuntimeException e) {
                failed++;
            }
        }
        List<RuleStat> rules = new ArrayList<>();
        for (RuleInfo rule : Migrator.rules()) {
            List<Finding> findings = findingsByRule.getOrDefault(rule.id(), List.of());
            if (findings.isEmpty()) continue;
            Map<String, Long> bySeverity = new LinkedHashMap<>();
            for (Issue.Severity severity : Issue.Severity.values()) {
                long n = findings.stream().filter(f -> f.severity() == severity).count();
                if (n > 0) bySeverity.put(severity.name(), n);
            }
            rules.add(new RuleStat(rule.id(), rule.category().label(), rule.title(), findings.size(),
                    proxiesByRule.get(rule.id()).size(), bySeverity));
        }
        rules.sort(Comparator.comparingLong(RuleStat::proxies).reversed());
        return new Overview(proxies.size(), failed,
                proxies.stream().mapToLong(ProxySummary::errors).sum(),
                proxies.stream().mapToLong(ProxySummary::warnings).sum(),
                proxies.stream().mapToLong(ProxySummary::infos).sum(),
                proxies.stream().mapToLong(ProxySummary::autoFixes).sum(),
                proxies.stream().mapToLong(ProxySummary::manual).sum(),
                proxies.stream().filter(ProxySummary::migrated).count(),
                rules, List.copyOf(resources.values()));
    }

    private ProxySummary summary(Settings s, String id, BundleReport analysis, MigrationReport migration) {
        List<Finding> findings = migration.findings();
        // the Migrator writes <output>/<name>/apiproxy plus sharedflows/ next to it
        boolean migrated = output(s, analysis.name())
                .map(p -> Files.isDirectory(p.resolve(analysis.name()).resolve("apiproxy"))).orElse(false);
        return new ProxySummary(id, analysis.name(), analysis.revision(), analysis.description(),
                migration.bundles().size() - 1,
                count(findings, Issue.Severity.ERROR), count(findings, Issue.Severity.WARN),
                count(findings, Issue.Severity.INFO),
                findings.stream().filter(f -> f.fix() == Finding.Fix.AUTO).count(),
                findings.stream().filter(f -> f.fix() == Finding.Fix.MANUAL).count(),
                migrated, null);
    }

    private static long count(List<Finding> findings, Issue.Severity severity) {
        return findings.stream().filter(f -> f.severity() == severity).count();
    }

    private BundleReport analyze(Settings s, String id) throws IOException {
        return new BundleAnalyzer(repository(s)).analyze(BundleLocator.locate(resolve(s, id)));
    }

    /** The proxy folder for an id, refusing anything outside the proxies root. */
    private static Path resolve(Settings s, String id) {
        if (s.proxiesRoot().isEmpty()) throw new UiException(409, "Set the proxies folder in Settings first");
        if (id == null || id.isBlank()) throw new UiException(400, "Missing proxy id");
        Path root = Path.of(s.proxiesRoot()).toAbsolutePath().normalize();
        Path dir = root.resolve(id).normalize();
        if (!dir.startsWith(root) || !Files.isDirectory(dir)) throw new UiException(404, "Unknown proxy " + id);
        return dir;
    }

    /** Folders holding an apiproxy/ bundle under the proxies root, outside the output folder. */
    private static List<Path> proxyDirs(Settings s) throws IOException {
        if (s.proxiesRoot().isEmpty()) return List.of();
        Path root = Path.of(s.proxiesRoot()).toAbsolutePath().normalize();
        if (!Files.isDirectory(root)) throw new UiException(409, "Proxies folder not found: " + root);
        Path output = s.outputDir().isEmpty() ? null : Path.of(s.outputDir()).toAbsolutePath().normalize();
        try (Stream<Path> paths = Files.walk(root, SCAN_DEPTH)) {
            return paths.filter(p -> Files.isDirectory(p) && p.getFileName().toString().equals("apiproxy"))
                    .map(Path::getParent)
                    .filter(p -> output == null || !p.startsWith(output))
                    .sorted()
                    .toList();
        } catch (UncheckedIOException e) {
            throw e.getCause();
        }
    }

    private static String id(Settings s, Path dir) {
        Path root = Path.of(s.proxiesRoot()).toAbsolutePath().normalize();
        String id = root.relativize(dir).toString().replace('\\', '/');
        return id.isEmpty() ? "." : id;
    }

    private static SharedFlowRepository repository(Settings s) throws IOException {
        List<Path> dirs = s.sharedFlowPaths().stream().filter(Files::isDirectory).toList();
        return dirs.isEmpty() ? SharedFlowRepository.empty() : SharedFlowRepository.scan(dirs);
    }

    private static Optional<Path> output(Settings s, String proxyName) {
        if (s.outputDir().isEmpty()) return Optional.empty();
        return Optional.of(Path.of(s.outputDir()).toAbsolutePath().normalize().resolve(proxyName));
    }

    private static boolean isEmpty(Path dir) throws IOException {
        try (Stream<Path> entries = Files.list(dir)) {
            return entries.findAny().isEmpty();
        }
    }

    private static void deleteTree(Path dir) throws IOException {
        try (Stream<Path> paths = Files.walk(dir)) {
            for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path);
        }
    }

    /** An error the API returns with a given HTTP status and a message meant for the user. */
    static final class UiException extends RuntimeException {
        final int status;

        UiException(int status, String message) {
            super(message);
            this.status = status;
        }
    }
}
