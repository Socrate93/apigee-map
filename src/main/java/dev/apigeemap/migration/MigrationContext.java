package dev.apigeemap.migration;

import dev.apigeemap.model.BundleReport;
import dev.apigeemap.model.BundleType;
import dev.apigeemap.model.Issue;
import dev.apigeemap.model.Policy;
import dev.apigeemap.model.SharedFlowLink;
import org.w3c.dom.Element;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
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
    final MigrationOptions options;

    private final Map<String, EnvResource> resources;
    private final Map<String, NewTargetServer> targetServers;
    private final List<Finding> findings = new ArrayList<>();
    private Rule rule;

    MigrationContext(BundleReport report, BundleWorkspace workspace, Map<String, BundleReport> sharedFlows,
                     MigrationOptions options, Map<String, EnvResource> resources,
                     Map<String, NewTargetServer> targetServers) {
        this.report = report;
        this.workspace = workspace;
        this.sharedFlows = sharedFlows;
        this.options = options;
        this.resources = resources;
        this.targetServers = targetServers;
    }

    void run(Rule rule) throws IOException {
        this.rule = rule;
        rule.check().run(this);
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

    void manual(Issue.Severity severity, String location, String message, String action) {
        add(severity, location, message, action, Finding.Fix.MANUAL);
    }

    void fixed(Issue.Severity severity, String location, String message, String action) {
        add(severity, location, message, action, Finding.Fix.AUTO);
    }

    private void add(Issue.Severity severity, String location, String message, String action, Finding.Fix fix) {
        Issue.Severity effective = options.severities().getOrDefault(rule.id(), severity);
        findings.add(new Finding(rule.id(), rule.category(), effective, report.name(), location, message, action, fix));
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
