package dev.apigeemap.migration;

import dev.apigeemap.analysis.Xml;
import dev.apigeemap.migration.Finding.Subject;
import dev.apigeemap.model.BundleReport;
import dev.apigeemap.model.BundleType;
import dev.apigeemap.model.Dependency;
import dev.apigeemap.model.Issue;
import dev.apigeemap.model.Policy;
import dev.apigeemap.model.SharedFlowLink;
import dev.apigeemap.model.Usage;
import org.w3c.dom.Element;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

/** What a rule sees for one bundle: its analysis report, its workspace, and the shared flows of the migration. */
final class MigrationContext {

    /** A target server created by an auto-fix; exported to targetservers.json. */
    record NewTargetServer(String name, String host, int port, boolean ssl) {
    }

    final BundleReport report;
    final BundleWorkspace workspace;
    /** Every resolved shared flow reachable from the migrated root bundle, by name. */
    final Map<String, BundleReport> sharedFlows;
    /** Every shared flow available locally (called or not): sharedflowbundle/ folder → name. */
    final Map<Path, String> catalog;
    final MigrationOptions options;

    private final Map<String, EnvResource> resources;
    private final Map<String, NewTargetServer> targetServers;
    private final List<Finding> findings = new ArrayList<>();
    private Rule rule;

    MigrationContext(BundleReport report, BundleWorkspace workspace, Map<String, BundleReport> sharedFlows,
                     Map<Path, String> catalog, MigrationOptions options, Map<String, EnvResource> resources,
                     Map<String, NewTargetServer> targetServers) {
        this.report = report;
        this.workspace = workspace;
        this.sharedFlows = sharedFlows;
        this.catalog = catalog;
        this.options = options;
        this.resources = resources;
        this.targetServers = targetServers;
    }

    void run(Rule rule) throws IOException {
        this.rule = rule;
        rule.check().run(this);
    }

    /** The root bundle of the migration (rules comparing it with its shared flows run there only). */
    boolean isRoot() {
        return !sharedFlows.containsKey(report.name());
    }

    /** This bundle, then every shared flow it reaches. */
    List<BundleReport> withSharedFlows() {
        List<BundleReport> bundles = new ArrayList<>(List.of(report));
        bundles.addAll(reachable(report));
        return bundles;
    }

    boolean isProxy() {
        return report.type() == BundleType.API_PROXY;
    }

    /** Policies of the bundle that no earlier rule deleted. */
    List<Policy> policies() {
        return report.policies().stream().filter(p -> !workspace.isDeleted(p.file())).toList();
    }

    List<Policy> policies(String type) {
        return policies().stream().filter(p -> p.type().equals(type)).toList();
    }

    Element xml(Policy policy) throws IOException {
        return workspace.root(policy.file());
    }

    /** ProxyEndpoint, TargetEndpoint and SharedFlow files of the bundle. */
    List<String> endpointFiles() throws IOException {
        List<String> files = new ArrayList<>(workspace.xmlFiles("proxies"));
        files.addAll(workspace.xmlFiles("targets"));
        files.addAll(workspace.xmlFiles("sharedflows"));
        return files;
    }

    /** @param subjects what the finding is about, from {@link #on} and {@link #wholeBundle} */
    void manual(Issue.Severity severity, String location, String message, String action, List<Subject> subjects) {
        add(severity, location, message, action, Finding.Fix.MANUAL, subjects);
    }

    void fixed(Issue.Severity severity, String location, String message, String action, List<Subject> subjects) {
        add(severity, location, message, action, Finding.Fix.AUTO, subjects);
    }

    private void add(Issue.Severity severity, String location, String message, String action, Finding.Fix fix,
                     List<Subject> subjects) {
        Issue.Severity effective = options.severities().getOrDefault(rule.id(), severity);
        findings.add(new Finding(rule.id(), rule.category(), effective, report.name(), location, message, action, fix,
                List.copyOf(new LinkedHashSet<>(subjects))));
    }

    @SafeVarargs
    static List<Subject> and(List<Subject>... lists) {
        return Arrays.stream(lists).flatMap(List::stream).toList();
    }

    /** A finding about the bundle as a whole. */
    static List<Subject> wholeBundle() {
        return List.of();
    }

    /** Policies of this bundle. */
    List<Subject> on(Policy... policies) {
        return Arrays.stream(policies).map(p -> new Subject(report.name(), p.file())).toList();
    }

    /** Files of this bundle (endpoints, resources), bundle-relative. */
    List<Subject> onFiles(Collection<String> files) {
        return files.stream().map(f -> new Subject(report.name(), f)).toList();
    }

    List<Subject> onFile(String file) {
        return onFiles(List.of(file));
    }

    /** Policies by name, of this bundle or of the shared flow named {@code bundle}; unknown names are left out. */
    List<Subject> onPolicies(String bundle, Collection<String> names) {
        BundleReport owner = bundle.equals(report.name()) ? report : sharedFlows.get(bundle);
        if (owner == null) return List.of();
        return owner.policies().stream().filter(p -> names.contains(p.name()))
                .map(p -> new Subject(owner.name(), p.file())).toList();
    }

    /** A script and the policy that runs it. */
    List<Subject> on(Scripts.Script script) {
        List<Subject> subjects = new ArrayList<>(onPolicies(script.bundle(), List.of(script.policy())));
        if (!script.file().equals("inline")) subjects.add(new Subject(script.bundle(), script.file()));
        return subjects;
    }

    /** The policies and endpoints of this bundle that declare the dependency. */
    List<Subject> on(Dependency dependency) throws IOException {
        List<Subject> subjects = new ArrayList<>();
        for (Usage usage : dependency.usages()) {
            if (usage.originType().equals("policy")) {
                subjects.addAll(onPolicies(report.name(), List.of(usage.origin())));
            } else {
                String file = endpointFile(usage.originType(), usage.origin());
                if (file != null) subjects.add(new Subject(report.name(), file));
            }
        }
        return subjects;
    }

    /** File of the ProxyEndpoint, TargetEndpoint or SharedFlow with that name, or null. */
    String endpointFile(String type, String name) throws IOException {
        for (String file : endpointFiles()) {
            Element root = workspace.root(file);
            if (root.getTagName().equals(type) && Xml.nameOf(root).equals(name)) return file;
        }
        return null;
    }

    /** Registers a resource to provision; the first bundle that needs it is kept as {@code requiredBy}. */
    void resource(String kind, String name, String details) {
        resources.putIfAbsent(kind + "\u0000" + name, new EnvResource(kind, name, details, report.name()));
    }

    void targetServer(NewTargetServer server) {
        targetServers.putIfAbsent(server.name(), server);
        resource("Target server (new)", server.name(),
                server.host() + ":" + server.port() + (server.ssl() ? " (TLS)" : ""));
    }

    List<Finding> findings() {
        return List.copyOf(findings);
    }

    /** Resolved shared flows called by the bundle, directly or not, each once. */
    List<BundleReport> reachable(BundleReport bundle) {
        Map<String, BundleReport> found = new LinkedHashMap<>();
        collect(bundle, found);
        found.remove(bundle.name());
        return List.copyOf(found.values());
    }

    static void collect(BundleReport bundle, Map<String, BundleReport> found) {
        for (SharedFlowLink link : bundle.sharedFlows()) {
            if (link.report() != null && found.putIfAbsent(link.name(), link.report()) == null) {
                collect(link.report(), found);
            }
        }
    }

    static String names(Collection<String> names) {
        return String.join(", ", names);
    }
}
