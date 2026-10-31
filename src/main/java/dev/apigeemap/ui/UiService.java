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
import dev.apigeemap.migration.PortContext;
import dev.apigeemap.migration.ProxyDocs;
import dev.apigeemap.migration.ProxyProfile;
import dev.apigeemap.migration.TestExports;
import dev.apigeemap.migration.TestPlans;
import dev.apigeemap.migration.TestTargets;
import dev.apigeemap.migration.TestRunner;
import dev.apigeemap.migration.RuleInfo;
import dev.apigeemap.migration.ScriptReviewRequest;
import dev.apigeemap.migration.ScriptReviews;
import dev.apigeemap.model.BundleReport;
import dev.apigeemap.model.Issue;
import dev.apigeemap.protocol.BackendClient;
import dev.apigeemap.protocol.BackendConfig;
import dev.apigeemap.render.DocMarkdownRenderer;
import dev.apigeemap.render.FixContextRenderer;
import dev.apigeemap.render.HtmlRenderer;
import dev.apigeemap.render.MigrationHtmlRenderer;
import dev.apigeemap.render.VariableFlowRenderer;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
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

    /** @param scripts how many of its scripts were reviewed as they are now, and since when a review runs */
    record ProxyDetail(ProxySummary summary, String path, int policies, int dependencies, String outputDir,
                       MigrationReport migration, ReviewStatus scripts) {
    }

    record ReviewStatus(int total, int reviewed, String running) {
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

    /**
     * A fix the backend proposed for one finding or several, kept until it is accepted or rejected.
     *
     * @param title what the step of history is called once the fix is accepted
     */
    private record Proposal(String proxyId, String title, List<Finding> findings, String summary,
                            List<ProposedEdit> edits, Service service) {
    }

    /**
     * The service a port moves a Node.js or hosted target to, written to {@code folder} once accepted.
     *
     * @param targetServer {@code {name, host, port, sslEnabled}}, or null
     */
    private record Service(String name, String runtime, Path folder, List<ServiceFile> files,
                           Map<?, ?> targetServer, List<String> steps) {
    }

    private record ServiceFile(String path, String content) {
    }

    record ProposedEdit(String bundle, String path, String action, String reason, String before,
                                String after) {
    }

    /** Proposals not accepted nor rejected yet; the oldest are dropped. */
    private static final int MAX_PROPOSALS = 20;
    /** At most this many findings are fixed together, so that the proposal stays reviewable. */
    static final int MAX_GROUPED = 30;
    /** At most this many findings are triaged together, as the backend allows. */
    static final int MAX_TRIAGE = 100;
    /** A proxy is documented when its files hold at most this many characters, as one request can take them. */
    static final int MAX_DOCUMENTED = 600_000;
    /** A test plan is prepared when the files of the proxy hold at most this many characters. */
    static final int MAX_PLANNED = 600_000;
    /** How long each environment has to answer a test request. */
    private static final Duration TEST_TIMEOUT = Duration.ofSeconds(30);
    /** A target is ported when its application and endpoints hold at most this many characters. */
    static final int MAX_PORTED = 600_000;
    private static final java.util.regex.Pattern SERVICE_NAME = java.util.regex.Pattern.compile("[a-z][a-z0-9-]{0,62}");

    private final Path settingsFile;
    private final Path historyRoot;
    private final Path backendConfig;
    private final ScriptReviews reviews;
    private final ProxyDocs docs;
    private final TestPlans plans;
    private final Path services;
    private final TokenStore token = new TokenStore();
    private final Map<String, Proposal> proposals = new LinkedHashMap<>();
    private final Running running = new Running();
    private Settings settings;

    /**
     * The script reviews are kept in {@code reviews/}, the documentation in {@code docs/}, the test plans in {@code
     * tests/}, and the services ports move targets to are written to {@code services/<proxy>/<service>}, next to
     * {@code historyRoot}.
     */
    UiService(Path settingsFile, Path historyRoot, Path backendConfig) throws IOException {
        this.settingsFile = settingsFile;
        this.historyRoot = historyRoot;
        this.backendConfig = backendConfig;
        this.reviews = ScriptReviews.at(historyRoot.toAbsolutePath().resolveSibling("reviews"));
        this.docs = ProxyDocs.at(historyRoot.toAbsolutePath().resolveSibling("docs"));
        this.plans = TestPlans.at(historyRoot.toAbsolutePath().resolveSibling("tests"));
        this.services = historyRoot.toAbsolutePath().resolveSibling("services");
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

    /** Marks a finding as a false positive, from {@code {rule, bundle, location, reason}}, and saves the settings. */
    synchronized void markFalsePositive(Map<?, ?> map) throws IOException {
        save(settings.withFalsePositive(Settings.falsePositive(map)));
    }

    /** Reports the finding of {@code {rule, bundle, location}} again, and saves the settings. */
    synchronized void unmarkFalsePositive(Map<?, ?> map) throws IOException {
        save(settings.withoutFalsePositive(String.valueOf(map.get("rule")), String.valueOf(map.get("bundle")),
                String.valueOf(map.get("location"))));
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
        Migrator migrator = new Migrator(s.migrationOptions(), repository, reviews);
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
        List<ScriptReviewRequest.Target> scripts = ScriptReviewRequest.scripts(analysis);
        return new ProxyDetail(summary(s, id, analysis, migration), analysis.path(), analysis.policies().size(),
                analysis.dependencies().size(), output(s, analysis.name()).map(Path::toString).orElse(null),
                migration, new ReviewStatus(scripts.size(),
                (int) scripts.stream().filter(t -> reviews.has(t.fingerprint())).count(),
                running.since("review", id).map(Instant::toString).orElse(null)));
    }

    String mapHtml(String id) throws IOException {
        return new HtmlRenderer().render(analyze(settings(), id));
    }

    /** The flow variables of the proxy, step by step; see {@link VariableFlowRenderer#model}. */
    Map<String, Object> variables(String id) throws IOException {
        return new VariableFlowRenderer().model(VariableFlow.of(analyze(settings(), id)), null);
    }

    /** The migration report, with the documentation of the proxy when it was written. */
    String migrationHtml(String id) throws IOException {
        Settings s = settings();
        BundleReport analysis = analyze(s, id);
        Optional<ProxyDocs.Stored> doc = docs.get(analysis.name());
        return new MigrationHtmlRenderer().render(migrator(s).migrate(analysis, null), doc.orElse(null),
                doc.isEmpty() || current(doc.get(), analysis));
    }

    /**
     * The documentation of the proxy as {@code {doc, written, current}}, {@code current} false when the proxy changed
     * since it was written; without them when it never was. {@code running} tells since when it is being written.
     */
    Map<String, Object> documentation(String id) throws IOException {
        BundleReport analysis = analyze(settings(), id);
        Optional<ProxyDocs.Stored> doc = docs.get(analysis.name());
        return withRunning("document", id,
                doc.isEmpty() ? Map.of() : documentation(doc.get(), current(doc.get(), analysis)));
    }

    /** The answer, with since when an operation of this kind runs for the proxy. */
    private Map<String, Object> withRunning(String kind, String id, Map<String, Object> answer) {
        Map<String, Object> m = new LinkedHashMap<>(answer);
        running.since(kind, id).ifPresent(since -> m.put("running", since.toString()));
        return m;
    }

    /**
     * Has the backend write the functional documentation of the proxy from its files and those of the shared flows it
     * calls, and keeps it. Answers as {@link #documentation}, or {@code {error}} with the same message whatever the
     * cause. While it runs, asking again waits for it.
     */
    Map<String, Object> document(String id) throws IOException {
        return running.run("document", id, () -> writeDocumentation(id));
    }

    private Map<String, Object> writeDocumentation(String id) throws IOException {
        BundleReport analysis = analyze(settings(), id);
        List<ProxyDocs.SourceFile> files = ProxyDocs.files(analysis);
        if (files.stream().mapToLong(f -> f.content().length()).sum() > MAX_DOCUMENTED) {
            throw new UiException(413, "This proxy is too large to be documented at once");
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("proxy", analysis.name());
        body.put("bundles", FixContext.bundles(analysis).values().stream()
                .map(b -> Map.of("name", b.name(), "type", b.type().label())).toList());
        body.put("files", files);

        Object answer;
        try {
            answer = new BackendClient(BackendConfig.load(backendConfig, token.get().orElse(null)))
                    .call("document", body);
        } catch (IOException | RuntimeException e) {
            BackendClient.report(e, System.err);
            answer = null;
        }
        ProxyDocs.Doc doc = answer instanceof Map<?, ?> reply ? ProxyDocs.doc(reply) : null;
        if (doc == null) return Map.of("error", BackendClient.UNAVAILABLE);
        return documentation(docs.put(analysis.name(), ProxyDocs.fingerprint(files), doc), true);
    }

    /** The documentation of the proxy as Markdown, see {@link DocMarkdownRenderer}. */
    Download exportDocumentation(String id) throws IOException {
        BundleReport analysis = analyze(settings(), id);
        ProxyDocs.Stored doc = docs.get(analysis.name())
                .orElseThrow(() -> new UiException(409, "Write the documentation first"));
        return new Download(analysis.name().replaceAll("[^A-Za-z0-9._-]", "_") + ".md", "text/markdown",
                new DocMarkdownRenderer().render(analysis.name(), doc, current(doc, analysis)));
    }

    private static boolean current(ProxyDocs.Stored doc, BundleReport analysis) throws IOException {
        return current(doc.fingerprint(), analysis);
    }

    private static Map<String, Object> documentation(ProxyDocs.Stored doc, boolean current) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("doc", doc.doc());
        m.put("written", doc.written().toString());
        m.put("current", current);
        return m;
    }

    /**
     * The regression test plan of the proxy as {@code {plan, written, current, targets, uncovered}}, {@code current}
     * false when the proxy changed since it was prepared, {@code targets} what the plan must cover and {@code
     * uncovered} those of them no case covers; without them when it never was. {@code running} tells since when it
     * is being prepared.
     */
    Map<String, Object> testPlan(String id) throws IOException {
        Settings s = settings();
        BundleReport analysis = analyze(s, id);
        Optional<TestPlans.Stored> plan = plans.get(analysis.name());
        Map<String, Object> m = new LinkedHashMap<>(plan.isEmpty() ? Map.of() : testPlan(plan.get(),
                current(plan.get().fingerprint(), analysis), targets(s, analysis)));
        m.put("profile", ProxyProfile.of(analysis));
        return withRunning("testPlan", id, m);
    }

    /**
     * Has the backend prepare the regression test plan of the proxy from its files and those of the shared flows it
     * calls, and keeps it. Answers as {@link #testPlan}, or {@code {error}} with the same message whatever the cause.
     * While it runs, asking again waits for it.
     */
    Map<String, Object> planTests(String id) throws IOException {
        return planTests(id, Map.of());
    }

    /**
     * Same, from {@code {profile, loginForm: {user, password}}}: {@code profile} replaces the detected kind of proxy
     * when it is {@code standard} or {@code authorizationServer}, and the names of the fields of the identity
     * provider's login form are those an authorization server's plan fills.
     */
    Map<String, Object> planTests(String id, Map<?, ?> request) throws IOException {
        return running.run("testPlan", id, () -> prepareTests(id, request));
    }

    private Map<String, Object> prepareTests(String id, Map<?, ?> request) throws IOException {
        Settings s = settings();
        BundleReport analysis = analyze(s, id);
        List<ProxyDocs.SourceFile> files = ProxyDocs.files(analysis);
        if (files.stream().mapToLong(f -> f.content().length()).sum() > MAX_PLANNED) {
            throw new UiException(413, "This proxy is too large to plan its tests at once");
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("proxy", analysis.name());
        body.put("bundles", FixContext.bundles(analysis).values().stream()
                .map(b -> Map.of("name", b.name(), "type", b.type().label())).toList());
        body.put("files", files);
        List<TestTargets.Target> targets = targets(s, analysis);
        body.put("targets", targets);
        ProxyProfile profile = ProxyProfile.of(analysis).as(request.get("profile") instanceof String chosen ? chosen : null);
        Map<String, Object> sent = new LinkedHashMap<>();
        sent.put("kind", profile.kind());
        sent.put("grants", profile.grants());
        sent.put("operations", profile.operations());
        if (profile.authorizationServer()) {
            Map<?, ?> form = request.get("loginForm") instanceof Map<?, ?> m ? m : Map.of();
            sent.put("loginForm", Map.of("user", field(form.get("user"), "login"),
                    "password", field(form.get("password"), "password")));
        }
        body.put("profile", sent);

        Object answer;
        try {
            answer = new BackendClient(BackendConfig.load(backendConfig, token.get().orElse(null)))
                    .call("testPlan", body);
        } catch (IOException | RuntimeException e) {
            BackendClient.report(e, System.err);
            answer = null;
        }
        TestPlans.Plan plan = answer instanceof Map<?, ?> reply ? TestPlans.plan(reply) : null;
        if (plan == null) return Map.of("error", BackendClient.UNAVAILABLE);
        return testPlan(plans.put(analysis.name(), ProxyDocs.fingerprint(files), plan), true, targets);
    }

    /** What a test plan of the proxy must cover, with what its migration changes. */
    private List<TestTargets.Target> targets(Settings s, BundleReport analysis) throws IOException {
        return TestTargets.of(analysis, migrator(s).migrate(analysis, null).findings());
    }

    /** The name of a form field as typed, or the default when it is not one. */
    private static String field(Object typed, String otherwise) {
        return typed instanceof String s && s.strip().matches("[A-Za-z0-9_.:\\[\\]-]{1,64}") ? s.strip() : otherwise;
    }

    /**
     * Replays the test plan of the proxy on Edge then on hybrid, from {@code {edge, hybrid, values, unsafe, cases}}:
     * the scheme and host of each environment, the values of the variables, whether to run the cases that change
     * data, and the indexes of the cases to run, all when absent. The values are used for this run only.
     */
    TestRunner.Run runTests(String id, Map<?, ?> request) throws IOException {
        BundleReport analysis = analyze(settings(), id);
        TestPlans.Plan plan = plans.get(analysis.name()).map(TestPlans.Stored::plan)
                .orElseThrow(() -> new UiException(409, "Prepare the test plan first"));
        String edge;
        String hybrid;
        try {
            edge = TestRunner.baseUrl("Edge", request.get("edge") instanceof String s ? s : "");
            hybrid = TestRunner.baseUrl("hybrid", request.get("hybrid") instanceof String s ? s : "");
        } catch (IllegalArgumentException e) {
            throw new UiException(400, e.getMessage());
        }
        Map<String, String> values = new LinkedHashMap<>();
        if (request.get("values") instanceof Map<?, ?> map) {
            map.forEach((k, v) -> {
                if (k instanceof String name && v instanceof String value) values.put(name, value);
            });
        }
        Set<Integer> only = null;
        if (request.get("cases") instanceof List<?> list) {
            only = new HashSet<>();
            for (Object item : list) if (item instanceof Number n) only.add(n.intValue());
        }
        return new TestRunner(TEST_TIMEOUT).run(plan, edge, hybrid, values,
                Boolean.TRUE.equals(request.get("unsafe")), only);
    }

    /** A file to download. */
    record Download(String fileName, String contentType, String content) {
    }

    /** The test plan of the proxy written for Postman, curl or Karate, see {@link TestExports}. */
    Download exportTests(String id, String format) throws IOException {
        TestExports.Format chosen = TestExports.Format.of(format);
        if (chosen == null) throw new UiException(400, "Export as postman, curl or karate");
        BundleReport analysis = analyze(settings(), id);
        TestPlans.Plan plan = plans.get(analysis.name()).map(TestPlans.Stored::plan)
                .orElseThrow(() -> new UiException(409, "Prepare the test plan first"));
        return new Download(TestExports.fileName(chosen, analysis.name()), chosen.contentType,
                TestExports.write(chosen, analysis.name(), plan));
    }

    private static boolean current(String fingerprint, BundleReport analysis) throws IOException {
        return fingerprint.equals(ProxyDocs.fingerprint(ProxyDocs.files(analysis)));
    }

    private static Map<String, Object> testPlan(TestPlans.Stored plan, boolean current,
                                                List<TestTargets.Target> targets) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("plan", plan.plan());
        m.put("written", plan.written().toString());
        m.put("current", current);
        m.put("targets", targets);
        m.put("uncovered", TestTargets.uncovered(targets, plan.plan()).stream().map(TestTargets.Target::id).toList());
        return m;
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
        Finding finding = find(migrator(s).migrate(analysis, null).findings(), picked);
        FixContext context = FixContext.of(finding, FixContext.bundles(analysis));
        Map<String, Object> result = propose(id, "fix", new FixContextRenderer().model(context), context.files(),
                finding.rule() + (context.ruleTitle() == null ? "" : " " + context.ruleTitle()), List.of(finding));
        if (result.containsKey("proposal")) {
            result.put("finding", finding);
            result.put("ruleTitle", context.ruleTitle());
        }
        return result;
    }

    /**
     * Asks the backend for one set of changes that fixes several findings of the proxy together, picked as for
     * {@link #proposeFix} from {@code {findings: [{bundle, rule, location}]}}: a file several of them touch is changed
     * once. Their contexts are sent together, each policy and file once. Kept like a single fix until accepted.
     */
    Map<String, Object> proposeFixes(String id, Map<?, ?> picked) throws IOException {
        Grouped grouped = grouped(id, picked, MAX_GROUPED, "fixed together");
        Map<String, Object> result = propose(id, "fixAll", grouped.body(), grouped.files(),
                "Fixes of " + grouped.findings().size() + " finding(s)", grouped.findings());
        if (result.containsKey("proposal")) result.put("findings", grouped.findings());
        return result;
    }

    /**
     * Asks the backend how to port the Node.js or hosted target of an HYB-04 finding, picked as for
     * {@link #proposeFix}: with policies of the proxy, or with a service of its own the target reaches through a
     * TargetServer. Kept like a fix until accepted; accepting it also writes the service, when there is one.
     */
    Map<String, Object> proposePort(String id, Map<?, ?> picked) throws IOException {
        Settings s = settings();
        BundleReport analysis = analyze(s, id);
        Finding finding = find(migrator(s).migrate(analysis, null).findings(), picked);
        if (!PortContext.portable(finding)) throw new UiException(400, "Only a Node.js or hosted target can be ported");
        FixContext context = PortContext.of(finding, FixContext.bundles(analysis));
        if (context.files().stream().mapToLong(f -> f.content().length()).sum() > MAX_PORTED) {
            throw new UiException(413, "This application is too large to be ported at once");
        }
        Map<String, Object> result = propose(id, "port", new FixContextRenderer().model(context), context.files(),
                "Port of " + finding.location(), List.of(finding));
        if (result.containsKey("proposal")) result.put("finding", finding);
        return result;
    }

    /**
     * Asks the backend which findings of the proxy look like false positives, picked as for {@link #proposeFixes}.
     * Nothing is marked: answers {@code {falsePositives: [{bundle, rule, location, reason}]}} for the user to confirm,
     * or {@code {error}} with the same message whatever the cause.
     */
    Map<String, Object> triage(String id, Map<?, ?> picked) throws IOException {
        Grouped grouped = grouped(id, picked, MAX_TRIAGE, "triaged together");
        Object answer;
        try {
            answer = new BackendClient(BackendConfig.load(backendConfig, token.get().orElse(null)))
                    .call("triage", grouped.body());
        } catch (IOException | RuntimeException e) {
            BackendClient.report(e, System.err);
            answer = null;
        }
        if (!(answer instanceof Map<?, ?> reply) || !(reply.get("falsePositives") instanceof List<?> list)) {
            return Map.of("error", BackendClient.UNAVAILABLE);
        }
        List<Map<String, Object>> falsePositives = new ArrayList<>();
        for (Object item : list) {
            if (!(item instanceof Map<?, ?> map) || !(map.get("reason") instanceof String reason) || reason.isBlank()
                    || grouped.findings().stream().noneMatch(f -> f.bundle().equals(map.get("bundle"))
                    && f.rule().equals(map.get("rule")) && f.location().equals(map.get("location")))) {
                continue;
            }
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("bundle", map.get("bundle"));
            m.put("rule", map.get("rule"));
            m.put("location", map.get("location"));
            m.put("reason", reason.strip());
            falsePositives.add(m);
        }
        return Map.of("falsePositives", falsePositives);
    }

    /** Findings sent together, with the body of the request and the files in it. */
    private record Grouped(List<Finding> findings, Map<String, Object> body, List<FixContext.SourceFile> files) {
    }

    /**
     * The findings of the proxy picked from {@code {findings: [{bundle, rule, location}]}}, at most {@code max}, and
     * their contexts sent together as {@code {findings, policies, files}}, each policy and file once.
     */
    private Grouped grouped(String id, Map<?, ?> picked, int max, String together) throws IOException {
        if (!(picked.get("findings") instanceof List<?> list) || list.isEmpty()) {
            throw new UiException(400, "No finding picked");
        }
        if (list.size() > max) {
            throw new UiException(400, "At most " + max + " findings can be " + together + ": filter them first");
        }
        Settings s = settings();
        BundleReport analysis = analyze(s, id);
        List<Finding> all = migrator(s).migrate(analysis, null).findings();
        Map<String, BundleReport> bundles = FixContext.bundles(analysis);
        FixContextRenderer renderer = new FixContextRenderer();
        List<Finding> findings = new ArrayList<>();
        List<Object> findingModels = new ArrayList<>();
        Map<String, Object> policies = new LinkedHashMap<>();
        Map<String, FixContext.SourceFile> files = new LinkedHashMap<>();
        for (Object item : list) {
            Finding finding = find(all, item instanceof Map<?, ?> map ? map : Map.of());
            if (findings.contains(finding)) continue;
            findings.add(finding);
            FixContext context = FixContext.of(finding, bundles);
            Map<String, Object> model = renderer.model(context);
            findingModels.add(model.get("finding"));
            for (Object policy : (List<?>) model.get("policies")) {
                Map<?, ?> p = (Map<?, ?>) policy;
                policies.putIfAbsent(p.get("bundle") + "/" + p.get("file"), policy);
            }
            context.files().forEach(f -> files.putIfAbsent(f.bundle() + "/" + f.path(), f));
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("findings", findingModels);
        body.put("policies", List.copyOf(policies.values()));
        body.put("files", files.values().stream().map(f -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("bundle", f.bundle());
            m.put("path", f.path());
            m.put("content", f.content());
            return m;
        }).toList());
        return new Grouped(List.copyOf(findings), body, List.copyOf(files.values()));
    }

    /** The finding of the proxy picked by its bundle, rule and location. */
    private static Finding find(List<Finding> findings, Map<?, ?> picked) {
        return findings.stream()
                .filter(f -> f.bundle().equals(picked.get("bundle")) && f.rule().equals(picked.get("rule"))
                        && f.location().equals(picked.get("location")))
                .findFirst().orElseThrow(() -> new UiException(404, "This finding is gone: reload the proxy"));
    }

    /**
     * Sends a fix request to the backend and keeps what it proposes. Answers {@code {proposal, summary, warnings,
     * edits}}, with {@code approach} and {@code service} for a port, or {@code {error}} with the same message
     * whatever the cause.
     *
     * @param files the files sent, to show each edit against what it replaces
     */
    private Map<String, Object> propose(String id, String operation, Map<String, Object> body,
                                        List<FixContext.SourceFile> files, String title, List<Finding> findings) {
        Object answer;
        try {
            answer = new BackendClient(BackendConfig.load(backendConfig, token.get().orElse(null)))
                    .call(operation, body);
        } catch (IOException | RuntimeException e) {
            BackendClient.report(e, System.err);
            answer = null;
        }
        // a failure answers 200 like a fix, with the same message whatever the cause
        if (!(answer instanceof Map<?, ?> reply)) return new LinkedHashMap<>(Map.of("error", BackendClient.UNAVAILABLE));

        List<ProposedEdit> edits = edits(reply, files);
        String summary = String.valueOf(reply.get("summary"));
        Service service = null;
        if (operation.equals("port") && reply.get("service") instanceof Map<?, ?> proposed) {
            service = service(findings.get(0), proposed);
            if (service == null) return new LinkedHashMap<>(Map.of("error", BackendClient.UNAVAILABLE));
        }
        String key = UUID.randomUUID().toString();
        synchronized (proposals) {
            proposals.put(key, new Proposal(id, title, findings, summary, List.copyOf(edits), service));
            while (proposals.size() > MAX_PROPOSALS) proposals.remove(proposals.keySet().iterator().next());
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("proposal", key);
        result.put("summary", summary);
        result.put("warnings", reply.get("warnings") instanceof List<?> warnings ? warnings : List.of());
        result.put("edits", edits);
        if (operation.equals("port")) {
            result.put("approach", reply.get("approach"));
            result.put("service", service == null ? null : serviceView(service));
        }
        return result;
    }

    private static List<ProposedEdit> edits(Map<?, ?> reply, List<FixContext.SourceFile> files) {
        List<ProposedEdit> edits = new ArrayList<>();
        if (reply.get("edits") instanceof List<?> list) {
            for (Object item : list) {
                if (!(item instanceof Map<?, ?> edit)) continue;
                String bundle = String.valueOf(edit.get("bundle"));
                String path = String.valueOf(edit.get("path"));
                String before = files.stream()
                        .filter(f -> f.bundle().equals(bundle) && f.path().equals(path))
                        .map(FixContext.SourceFile::content).findFirst().orElse(null);
                edits.add(new ProposedEdit(bundle, path, String.valueOf(edit.get("action")),
                        String.valueOf(edit.get("reason")), before,
                        edit.get("content") instanceof String content ? content : null));
            }
        }
        return edits;
    }

    /**
     * What the backend answers an editor request, kept nowhere: the page applies the edits to its buffers. Answers
     * {@code {summary, warnings, edits}}, or {@code {error}} with the same message whatever the cause.
     *
     * @param files the files sent, to show each edit against what it replaces
     */
    Map<String, Object> ask(String operation, Map<String, Object> body, List<FixContext.SourceFile> files) {
        Object answer;
        try {
            answer = new BackendClient(BackendConfig.load(backendConfig, token.get().orElse(null)))
                    .call(operation, body);
        } catch (IOException | RuntimeException e) {
            BackendClient.report(e, System.err);
            answer = null;
        }
        if (!(answer instanceof Map<?, ?> reply)) return new LinkedHashMap<>(Map.of("error", BackendClient.UNAVAILABLE));
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("summary", String.valueOf(reply.get("summary")));
        result.put("warnings", reply.get("warnings") instanceof List<?> warnings ? warnings : List.of());
        result.put("edits", edits(reply, files));
        return result;
    }

    /** The service of a port as the backend proposes it, or null when it has a bad name or a file outside it. */
    private Service service(Finding finding, Map<?, ?> proposed) {
        if (!(proposed.get("name") instanceof String name) || !SERVICE_NAME.matcher(name).matches()
                || !(proposed.get("files") instanceof List<?> list) || list.isEmpty()) {
            return null;
        }
        Path folder = services.resolve(finding.bundle().replaceAll("[^A-Za-z0-9._-]", "_")).resolve(name);
        List<ServiceFile> files = new ArrayList<>();
        for (Object item : list) {
            if (!(item instanceof Map<?, ?> file) || !(file.get("path") instanceof String path)
                    || !(file.get("content") instanceof String content)) {
                return null;
            }
            Path target = folder.resolve(path).normalize();
            if (path.isBlank() || Path.of(path).isAbsolute() || !target.startsWith(folder) || target.equals(folder)) {
                return null;
            }
            files.add(new ServiceFile(path, content));
        }
        List<String> steps = proposed.get("steps") instanceof List<?> items
                ? items.stream().filter(i -> i instanceof String).map(String::valueOf).toList() : List.of();
        return new Service(name, proposed.get("runtime") instanceof String runtime ? runtime : "", folder,
                List.copyOf(files), proposed.get("targetServer") instanceof Map<?, ?> server ? server : null, steps);
    }

    private static Map<String, Object> serviceView(Service service) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("name", service.name());
        m.put("runtime", service.runtime());
        m.put("folder", service.folder().toString());
        m.put("files", service.files());
        m.put("targetServer", service.targetServer());
        m.put("steps", service.steps());
        return m;
    }

    /**
     * Has the backend review the scripts of the proxy not reviewed as they are now, or all of them when {@code again}
     * is set, and keeps the remarks, which REV-01 then reports. Answers {@code {reviewed, remarks}}, or
     * {@code {error}} with the same message whatever the cause. While a review runs, asking again waits for it.
     */
    Map<String, Object> reviewScripts(String id, boolean again) throws IOException {
        return running.run("review", id, () -> review(id, again));
    }

    private Map<String, Object> review(String id, boolean again) throws IOException {
        Settings s = settings();
        BundleReport analysis = analyze(s, id);
        List<ScriptReviewRequest.Target> targets = ScriptReviewRequest.scripts(analysis).stream()
                .filter(t -> again || !reviews.has(t.fingerprint())).toList();
        if (targets.isEmpty()) return Map.of("reviewed", 0, "remarks", 0);
        FixContext context = ScriptReviewRequest.context(analysis, targets);
        // the findings without the remarks of earlier reviews, which are about to be replaced
        List<Finding> known = ScriptReviewRequest.known(migrator(s).migrate(analysis, null).findings(), context);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("scripts", targets.stream().map(t -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("bundle", t.bundle());
            m.put("policy", t.policy());
            m.put("file", t.file());
            m.put("inline", t.inline());
            return m;
        }).toList());
        body.put("findings", known.stream().map(f -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("rule", f.rule());
            m.put("bundle", f.bundle());
            m.put("location", f.location());
            m.put("message", f.message());
            return m;
        }).toList());
        Map<String, Object> model = new FixContextRenderer().model(context);
        body.put("policies", model.get("policies"));
        body.put("files", model.get("files"));

        Object answer;
        try {
            answer = new BackendClient(BackendConfig.load(backendConfig, token.get().orElse(null)))
                    .call("review", body);
        } catch (IOException | RuntimeException e) {
            BackendClient.report(e, System.err);
            answer = null;
        }
        if (!(answer instanceof Map<?, ?> reply) || !(reply.get("remarks") instanceof List<?> list)) {
            return Map.of("error", BackendClient.UNAVAILABLE);
        }
        Map<String, List<ScriptReviews.Remark>> remarks = new LinkedHashMap<>();
        targets.forEach(t -> remarks.put(t.bundle() + "/" + t.file(), new ArrayList<>()));
        int count = 0;
        for (Object item : list) {
            if (!(item instanceof Map<?, ?> map)) continue;
            List<ScriptReviews.Remark> of = remarks.get(map.get("bundle") + "/" + map.get("file"));
            ScriptReviews.Remark remark = ScriptReviews.remark(map);
            if (of == null || remark == null) continue;
            of.add(remark);
            count++;
        }
        for (ScriptReviewRequest.Target target : targets) {
            reviews.put(target.fingerprint(), remarks.get(target.bundle() + "/" + target.file()));
        }
        return Map.of("reviewed", targets.size(), "remarks", count);
    }

    void rejectFix(String key) {
        synchronized (proposals) {
            proposals.remove(key);
        }
    }

    /**
     * Writes a proposal to the source bundles and records it as one step of their history. Changes made by hand
     * before are recorded first, as their own step. Nothing is written when a file the proposal changes is no
     * longer as it was when the fix was proposed. The service of a port is written to its own folder, which must
     * not hold anything yet.
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
        Service service = proposal.service();
        if (service != null && Files.exists(service.folder())
                && (!Files.isDirectory(service.folder()) || !isEmpty(service.folder()))) {
            throw new UiException(409, service.folder() + " already exists: move it away, then accept again");
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
            if (service != null) {
                for (ServiceFile file : service.files()) {
                    Path path = service.folder().resolve(file.path()).normalize();
                    Files.createDirectories(path.getParent());
                    Files.writeString(path, file.content());
                }
            }
            List<SourceHistory.Step> steps = new ArrayList<>();
            for (Map.Entry<String, SourceHistory> entry : histories.entrySet()) {
                StringBuilder message = new StringBuilder(proposal.title())
                        .append(proposal.title().startsWith("Port of") ? " (proposed port)\n\n" : " (proposed fix)\n\n")
                        .append(proposal.summary()).append("\n\n");
                if (service != null) {
                    message.append("Service ").append(service.name()).append(" written to ").append(service.folder())
                            .append('\n');
                    if (service.targetServer() != null) {
                        message.append("TargetServer ").append(service.targetServer().get("name")).append(": ")
                                .append(service.targetServer().get("host")).append(':')
                                .append(service.targetServer().get("port")).append('\n');
                    }
                    message.append('\n');
                }
                if (proposal.findings().size() > 1) {
                    message.append("Findings:\n");
                    for (Finding finding : proposal.findings()) {
                        message.append("- ").append(finding.rule()).append(' ').append(finding.bundle()).append(" · ")
                                .append(finding.location()).append('\n');
                    }
                    message.append('\n');
                }
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
        Migrator migrator = new Migrator(s.migrationOptions(), repository, reviews);
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

    /** The folder of the bundle of the proxy, absolute. */
    Path bundleDir(String id) throws IOException {
        return BundleLocator.locate(resolve(settings(), id)).toAbsolutePath().normalize();
    }

    /** The proxy as saved. */
    BundleReport analyzed(String id) throws IOException {
        return analyze(settings(), id);
    }

    /** An analyzer that resolves shared flows from the folders of the settings. */
    BundleAnalyzer analyzer() throws IOException {
        return new BundleAnalyzer(repository(settings()));
    }

    /** The findings of a bundle, with the rules and the false positives of the settings; nothing is written. */
    MigrationReport migrate(BundleReport analysis) throws IOException {
        return migrator(settings()).migrate(analysis, null);
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

    private Migrator migrator(Settings s) throws IOException {
        return new Migrator(s.migrationOptions(), repository(s), reviews);
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
