package dev.apigeemap.migration;

import dev.apigeemap.analysis.SharedFlowRepository;
import dev.apigeemap.model.BundleReport;
import dev.apigeemap.model.BundleType;
import dev.apigeemap.model.Dependency;
import dev.apigeemap.model.Usage;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Migrates an analyzed Edge for Private Cloud bundle, and the shared flows it calls, to Apigee hybrid.
 * Runs every rule on every bundle, lists the resources hybrid needs, and — unless it is a dry run — writes
 * the rewritten bundles to an output folder ({@code <name>/apiproxy}, {@code sharedflows/<name>/sharedflowbundle}),
 * or applies the auto-fixes to the bundles themselves, rule after rule ({@link #migrateInPlace}).
 */
public final class Migrator {

    static final List<Rule> RULES = Stream.of(HybridRules.all(), SecurityRules.all(), PerformanceRules.all(),
            DesignRules.all(), ReviewRules.all()).flatMap(List::stream).toList();

    private final MigrationOptions options;
    private final SharedFlowRepository catalog;
    private final ScriptReviews reviews;

    public Migrator() {
        this(MigrationOptions.DEFAULT);
    }

    public Migrator(MigrationOptions options) {
        this(options, SharedFlowRepository.empty());
    }

    /** @param catalog shared flows available locally, to spot proxies that repeat what one of them does */
    public Migrator(MigrationOptions options, SharedFlowRepository catalog) {
        this(options, catalog, ScriptReviews.NONE);
    }

    /** @param reviews remarks of the script reviews, reported by REV-01 for the scripts reviewed as they are now */
    public Migrator(MigrationOptions options, SharedFlowRepository catalog, ScriptReviews reviews) {
        this.options = options;
        this.catalog = catalog;
        this.reviews = reviews;
    }

    public static List<RuleInfo> rules() {
        return RULES.stream().map(Rule::info).toList();
    }

    /** Accepted policy name prefixes by policy type, before {@link MigrationOptions#namingPrefixes()}. */
    public static Map<String, List<String>> defaultNamingPrefixes() {
        return new TreeMap<>(DesignRules.defaultPrefixes());
    }

    /** Told of each rule whose auto-fixes changed a bundle, once they are written to it. */
    @FunctionalInterface
    public interface AppliedRule {
        void applied(BundleReport bundle, RuleInfo rule, List<String> changes) throws IOException;
    }

    /** @param outputDir where to write the migrated bundles; null for a dry run (report only) */
    public MigrationReport migrate(BundleReport root, Path outputDir) throws IOException {
        if (outputDir != null) checkEmpty(outputDir);
        return run(root, outputDir, null);
    }

    /**
     * Applies the auto-fixes to the source folders of the bundle and of the shared flows it calls, writing the
     * changes of each rule before the next one runs, so that each rule can be recorded as a step of its own.
     */
    public MigrationReport migrateInPlace(BundleReport root, AppliedRule listener) throws IOException {
        return run(root, null, listener);
    }

    private MigrationReport run(BundleReport root, Path outputDir, AppliedRule listener) throws IOException {

        Map<String, BundleReport> sharedFlows = new LinkedHashMap<>();
        MigrationContext.collect(root, sharedFlows);
        sharedFlows.remove(root.name());
        List<BundleReport> bundles = new ArrayList<>(List.of(root));
        bundles.addAll(sharedFlows.values());

        Map<String, EnvResource> resources = new LinkedHashMap<>();
        Map<String, MigrationContext.NewTargetServer> targetServers = new LinkedHashMap<>();
        List<BundleMigration> results = new ArrayList<>();
        for (BundleReport bundle : bundles) {
            BundleWorkspace workspace = new BundleWorkspace(Path.of(bundle.path()));
            MigrationContext ctx = new MigrationContext(bundle, workspace, sharedFlows, catalog.bundles(), options,
                    reviews, resources, targetServers);
            Map<String, FileChange> applied = new LinkedHashMap<>();
            for (Rule rule : RULES) {
                if (options.disabledRules().contains(rule.id())) continue;
                int before = workspace.changes().size();
                ctx.run(rule);
                if (listener != null && workspace.hasPendingChanges()) {
                    for (FileChange change : workspace.applyInPlace()) {
                        FileChange first = applied.get(change.path());
                        applied.put(change.path(), first == null ? change
                                : new FileChange(change.path(), first.before(), change.after()));
                    }
                    List<String> changes = workspace.changes();
                    listener.applied(bundle, rule.info(), changes.subList(before, changes.size()));
                }
            }
            inventory(ctx);

            String output = listener != null ? bundle.path() : null;
            if (outputDir != null) {
                Path target = bundle.type() == BundleType.API_PROXY
                        ? outputDir.resolve(bundle.name()).resolve("apiproxy")
                        : outputDir.resolve("sharedflows").resolve(bundle.name()).resolve("sharedflowbundle");
                workspace.writeTo(target);
                output = target.toString();
            }
            results.add(new BundleMigration(bundle.name(), bundle.type(), bundle.path(), output, ctx.findings(),
                    workspace.changes(), listener != null ? List.copyOf(applied.values()) : workspace.preview(),
                    ctx.hidden(), ctx.unmatched()));
        }
        if (outputDir != null && !targetServers.isEmpty()) {
            Files.writeString(outputDir.resolve("targetservers.json"), targetServersJson(targetServers.values()));
        }
        return new MigrationReport(root.name(), outputDir != null || listener != null,
                outputDir == null ? null : outputDir.toAbsolutePath().toString(), List.copyOf(results),
                List.copyOf(resources.values()));
    }

    private static void checkEmpty(Path outputDir) throws IOException {
        if (!Files.exists(outputDir)) return;
        try (Stream<Path> entries = Files.list(outputDir)) {
            if (entries.findAny().isPresent()) {
                throw new IOException("Output folder is not empty: " + outputDir);
            }
        }
    }

    /** Environment and organization resources the bundle depends on (active dependencies only). */
    private static void inventory(MigrationContext ctx) {
        for (Dependency dependency : ctx.report.dependencies()) {
            if (!dependency.active()) continue;
            String name = dependency.name();
            String dynamic = dependency.dynamic() ? "name resolved at runtime: create every possible value; " : "";
            Usage first = dependency.usages().get(0);
            switch (dependency.kind()) {
                case SHARED_FLOW -> ctx.resource("Shared flow", name, "deploy before the bundles that call it");
                case TARGET_SERVER -> ctx.resource("Target server", name, dynamic + "host and TLS per environment");
                case LOCAL_PROXY -> ctx.resource("API proxy (chained)", name, "deploy in the same environment");
                case KVM -> ctx.resource("KVM", name, dynamic + "scope " + first.details().get("scope")
                        + keys(dependency) + "; re-import the values (hybrid KVMs are always encrypted)");
                // "(default shared cache)" and similar placeholders need nothing
                case CACHE -> {
                    if (!name.startsWith("(")) ctx.resource("Cache", name, dynamic + "environment cache");
                }
                case KEYSTORE, TRUSTSTORE -> {
                    boolean reference = "reference".equals(first.details().get("via"));
                    List<String> details = new ArrayList<>();
                    if (reference) details.add("points to a " + dependency.kind().label().toLowerCase());
                    if (first.details().get("keyAlias") != null) details.add("alias " + first.details().get("keyAlias"));
                    ctx.resource(reference ? "Reference" : dependency.kind().label(), name, String.join(", ", details));
                }
                case SYSLOG -> ctx.resource("Outbound connection", name,
                        "the runtime pods must reach this syslog endpoint (firewall, network policies)");
                default -> {
                    // virtual hosts and resources are inventoried by their rules; URLs need nothing
                }
            }
        }
    }

    private static String keys(Dependency dependency) {
        String keys = dependency.usages().stream()
                .map(u -> u.details().get("keys"))
                .filter(k -> k != null)
                .distinct()
                .collect(Collectors.joining(", "));
        return keys.isEmpty() ? "" : ", keys " + keys;
    }

    /** Target servers in the management API format, ready for {@code apigeecli targetservers import}. */
    private static String targetServersJson(Iterable<MigrationContext.NewTargetServer> servers) {
        List<String> entries = new ArrayList<>();
        for (MigrationContext.NewTargetServer server : servers) {
            entries.add("  {\n    \"name\": \"" + server.name() + "\",\n    \"host\": \"" + server.host()
                    + "\",\n    \"port\": " + server.port() + ",\n    \"isEnabled\": true"
                    + (server.ssl() ? ",\n    \"sSLInfo\": {\"enabled\": true}" : "") + "\n  }");
        }
        return "[\n" + String.join(",\n", entries) + "\n]\n";
    }
}
