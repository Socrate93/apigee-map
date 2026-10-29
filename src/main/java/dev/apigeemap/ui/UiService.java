package dev.apigeemap.ui;

import dev.apigeemap.analysis.BundleAnalyzer;
import dev.apigeemap.analysis.BundleLocator;
import dev.apigeemap.analysis.SharedFlowRepository;
import dev.apigeemap.analysis.VariableFlow;
import dev.apigeemap.analysis.Xml;
import dev.apigeemap.history.SourceHistory;
import dev.apigeemap.migration.EnvResource;
import dev.apigeemap.migration.Finding;
import dev.apigeemap.migration.FixContext;
import dev.apigeemap.migration.MigrationReport;
import dev.apigeemap.migration.Migrator;
import dev.apigeemap.migration.RuleInfo;
import dev.apigeemap.model.BundleReport;
import dev.apigeemap.model.Issue;
import dev.apigeemap.protocol.BackendClient;
import dev.apigeemap.protocol.BackendConfig;
import dev.apigeemap.render.FixContextRenderer;
import dev.apigeemap.render.HtmlRenderer;
import dev.apigeemap.render.MigrationHtmlRenderer;
import dev.apigeemap.render.VariableFlowRenderer;

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
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;
import java.util.stream.Stream;

/**
 * What the UI does: settings, proxy discovery, analysis, migration preview and application, overview, fixes asked
 * from the backend and the history of the bundles they change.
 */
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

    /** A fix the backend proposed, kept until it is accepted or rejected; {@code before} null for a new file. */
    private record Proposal(String proxyId, Finding finding, String ruleTitle, String summary,
                            List<ProposedEdit> edits) {
    }

    private record ProposedEdit(String bundle, String path, String action, String reason, String before,
                                String after) {
    }

    /** Proposals not accepted nor rejected yet; the oldest are dropped. */
    private static final int MAX_PROPOSALS = 20;

    private final Path settingsFile;
    private final Path historyRoot;
    private final Path backendConfig;
    private final TokenStore token = new TokenStore();
    private final Map<String, Proposal> proposals = new LinkedHashMap<>();
    private Settings settings;

    UiService(Path settingsFile, Path historyRoot, Path backendConfig) throws IOException {
        this.settingsFile = settingsFile;
        this.historyRoot = historyRoot;
        this.backendConfig = backendConfig;
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

    /** Keeps the client token in memory, never in a file; a blank one forgets it. */
    void setToken(String value) {
        token.set(value);
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
        Migrator migrator = new Migrator(s.migrationOptions(), repository);
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
        MigrationReport migration = migrator(s).migrate(analysis, null);
        return new ProxyDetail(summary(s, id, analysis, migration), analysis.path(), analysis.policies().size(),
                analysis.dependencies().size(), output(s, analysis.name()).map(Path::toString).orElse(null),
                migration);
    }

    String mapHtml(String id) throws IOException {
        return new HtmlRenderer().render(analyze(settings(), id));
    }

    /** The flow variables of the proxy, step by step; see {@link VariableFlowRenderer#model}. */
    Map<String, Object> variables(String id) throws IOException {
        return new VariableFlowRenderer().model(VariableFlow.of(analyze(settings(), id)), null);
    }

    String migrationHtml(String id) throws IOException {
        Settings s = settings();
        return new MigrationHtmlRenderer().render(migrator(s).migrate(analyze(s, id), null));
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
        return migrator(s).migrate(analysis, target);
    }

    /**
     * Asks the backend for the fix of one finding of the proxy, picked by its bundle, rule and location. Nothing is
     * written: the proposal is kept under the returned {@code proposal} id until {@link #acceptFix} or
     * {@link #rejectFix}.
     */
    Map<String, Object> proposeFix(String id, Map<?, ?> picked) throws IOException {
        Settings s = settings();
        BundleReport analysis = analyze(s, id);
        Finding finding = migrator(s).migrate(analysis, null).findings().stream()
                .filter(f -> f.bundle().equals(picked.get("bundle")) && f.rule().equals(picked.get("rule"))
                        && f.location().equals(picked.get("location")))
                .findFirst().orElseThrow(() -> new UiException(404, "This finding is gone: reload the proxy"));
        FixContext context = FixContext.of(finding, FixContext.bundles(analysis));
        Object answer;
        try {
            answer = new BackendClient(BackendConfig.load(backendConfig, token.get().orElse(null)))
                    .call("fix", new FixContextRenderer().model(context));
        } catch (IOException | RuntimeException e) {
            answer = null;
        }
        // a failure answers 200 like a fix, with the same message whatever the cause
        if (!(answer instanceof Map<?, ?> reply)) return Map.of("error", BackendClient.UNAVAILABLE);

        List<ProposedEdit> edits = new ArrayList<>();
        if (reply.get("edits") instanceof List<?> list) {
            for (Object item : list) {
                if (!(item instanceof Map<?, ?> edit)) continue;
                String bundle = String.valueOf(edit.get("bundle"));
                String path = String.valueOf(edit.get("path"));
                String before = context.files().stream()
                        .filter(f -> f.bundle().equals(bundle) && f.path().equals(path))
                        .map(FixContext.SourceFile::content).findFirst().orElse(null);
                edits.add(new ProposedEdit(bundle, path, String.valueOf(edit.get("action")),
                        String.valueOf(edit.get("reason")), before,
                        edit.get("content") instanceof String content ? content : null));
            }
        }
        String summary = String.valueOf(reply.get("summary"));
        String key = UUID.randomUUID().toString();
        synchronized (proposals) {
            proposals.put(key, new Proposal(id, finding, context.ruleTitle(), summary, List.copyOf(edits)));
            while (proposals.size() > MAX_PROPOSALS) proposals.remove(proposals.keySet().iterator().next());
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("proposal", key);
        result.put("finding", finding);
        result.put("ruleTitle", context.ruleTitle());
        result.put("summary", summary);
        result.put("warnings", reply.get("warnings") instanceof List<?> warnings ? warnings : List.of());
        result.put("edits", edits);
        return result;
    }

    void rejectFix(String key) {
        synchronized (proposals) {
            proposals.remove(key);
        }
    }

    /**
     * Writes a proposal to the source bundles and records it as one step of their history. Changes made by hand
     * before are recorded first, as their own step. Nothing is written when a file the proposal changes is no
     * longer as it was when the fix was proposed.
     */
    synchronized List<SourceHistory.Step> acceptFix(String key) throws IOException {
        Proposal proposal;
        synchronized (proposals) {
            proposal = proposals.get(key);
        }
        if (proposal == null) throw new UiException(404, "This proposal is gone: ask for a fix again");
        Map<String, BundleReport> bundles = FixContext.bundles(analyze(settings(), proposal.proxyId()));

        Map<ProposedEdit, Path> targets = new LinkedHashMap<>();
        for (ProposedEdit edit : proposal.edits()) {
            BundleReport bundle = bundles.get(edit.bundle());
            if (bundle == null) throw new UiException(409, "Unknown bundle " + edit.bundle());
            Path dir = Path.of(bundle.path()).toAbsolutePath().normalize();
            Path file = dir.resolve(edit.path()).normalize();
            if (!file.startsWith(dir) || file.equals(dir)) {
                throw new UiException(409, "Not a file of " + edit.bundle() + ": " + edit.path());
            }
            String current = Files.isRegularFile(file) ? Files.readString(file) : null;
            if (!Objects.equals(current, edit.before())) {
                throw new UiException(409, edit.bundle() + "/" + edit.path()
                        + " changed since the fix was proposed: ask for a fix again");
            }
            targets.put(edit, file);
        }

        Map<String, SourceHistory> histories = new LinkedHashMap<>();
        try {
            for (ProposedEdit edit : targets.keySet()) {
                if (histories.containsKey(edit.bundle())) continue;
                SourceHistory history = SourceHistory.open(Path.of(bundles.get(edit.bundle()).path()), historyRoot);
                histories.put(edit.bundle(), history);
                history.record("Manual changes");
            }
            for (Map.Entry<ProposedEdit, Path> target : targets.entrySet()) {
                ProposedEdit edit = target.getKey();
                if (edit.after() == null) {
                    Files.deleteIfExists(target.getValue());
                } else {
                    Files.createDirectories(target.getValue().getParent());
                    Files.writeString(target.getValue(), edit.after());
                }
            }
            List<SourceHistory.Step> steps = new ArrayList<>();
            for (Map.Entry<String, SourceHistory> entry : histories.entrySet()) {
                StringBuilder message = new StringBuilder(proposal.finding().rule())
                        .append(proposal.ruleTitle() == null ? "" : " " + proposal.ruleTitle())
                        .append(" (proposed fix)\n\n")
                        .append(proposal.summary()).append("\n\n");
                for (ProposedEdit edit : targets.keySet()) {
                    if (edit.bundle().equals(entry.getKey())) {
                        message.append(edit.action()).append(' ').append(edit.path()).append(": ")
                                .append(edit.reason()).append('\n');
                    }
                }
                SourceHistory.Step step = entry.getValue().record(message.toString());
                if (step != null) steps.add(step);
            }
            rejectFix(key);
            return steps;
        } finally {
            histories.values().forEach(SourceHistory::close);
        }
    }

    /** The steps of each bundle of the proxy changed in place, newest first; bundles without history are left out. */
    List<Map<String, Object>> history(String id) throws IOException {
        List<Map<String, Object>> result = new ArrayList<>();
        for (BundleReport bundle : FixContext.bundles(analyze(settings(), id)).values()) {
            Path dir = Path.of(bundle.path());
            if (!SourceHistory.exists(dir, historyRoot)) continue;
            try (SourceHistory history = SourceHistory.open(dir, historyRoot)) {
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("bundle", bundle.name());
                entry.put("type", bundle.type());
                entry.put("steps", history.steps().stream().map(step -> {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("id", step.id());
                    m.put("title", step.title());
                    m.put("message", step.message());
                    m.put("time", step.time().toString());
                    m.put("files", step.files());
                    m.put("original", step.title().equals(SourceHistory.ORIGINAL));
                    return m;
                }).toList());
                entry.put("pending", history.pendingChanges());
                result.add(entry);
            }
        }
        return result;
    }

    String historyDiff(String id, String bundle, String step) throws IOException {
        try (SourceHistory history = openHistory(id, bundle)) {
            return history.diff(step);
        }
    }

    synchronized SourceHistory.Step revertStep(String id, String bundle, String step) throws IOException {
        try (SourceHistory history = openHistory(id, bundle)) {
            return history.revert(step);
        } catch (IOException e) {
            // conflicts and changes not recorded yet are for the user to sort out
            throw new UiException(409, e.getMessage());
        }
    }

    private SourceHistory openHistory(String id, String bundle) throws IOException {
        BundleReport report = FixContext.bundles(analyze(settings(), id)).get(bundle);
        if (report == null || !SourceHistory.exists(Path.of(report.path()), historyRoot)) {
            throw new UiException(404, "No history for " + bundle);
        }
        return SourceHistory.open(Path.of(report.path()), historyRoot);
    }

    Overview overview() throws IOException {
        List<ProxySummary> proxies = new ArrayList<>();
        Map<String, List<Finding>> findingsByRule = new LinkedHashMap<>();
        Map<String, Set<String>> proxiesByRule = new LinkedHashMap<>();
        Map<String, ResourceNeed> resources = new TreeMap<>();
        Settings s = settings();
        SharedFlowRepository repository = repository(s);
        Migrator migrator = new Migrator(s.migrationOptions(), repository);
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
        String id = Xml.relativePath(root, dir);
        return id.isEmpty() ? "." : id;
    }

    private static Migrator migrator(Settings s) throws IOException {
        return new Migrator(s.migrationOptions(), repository(s));
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
