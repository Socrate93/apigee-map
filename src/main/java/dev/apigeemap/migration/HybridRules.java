package dev.apigeemap.migration;

import dev.apigeemap.analysis.Xml;
import dev.apigeemap.model.Dependency;
import dev.apigeemap.model.DependencyKind;
import dev.apigeemap.model.Policy;
import dev.apigeemap.model.Usage;
import org.w3c.dom.Element;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static dev.apigeemap.migration.Dom.escape;
import static dev.apigeemap.migration.Finding.Category.HYBRID;
import static dev.apigeemap.migration.MigrationContext.names;
import static dev.apigeemap.model.Issue.Severity.ERROR;
import static dev.apigeemap.model.Issue.Severity.INFO;
import static dev.apigeemap.model.Issue.Severity.WARN;

/** Edge for Private Cloud features that Apigee hybrid does not support or handles differently. */
final class HybridRules {

    /** Policy types without a hybrid equivalent, with the replacement to put in place. */
    private static final Map<String, String> UNSUPPORTED_POLICIES = Map.of(
            "ConcurrentRatelimit", "Replace with SpikeArrest (smooths bursts) and/or Quota;"
                    + " hybrid has no concurrent connection limit.",
            "Ldap", "Authenticate against an identity provider (OAuthV2, VerifyJWT) or call an LDAP-backed"
                    + " service through a ServiceCallout.",
            "OAuthV1", "Move the clients to OAuthV2, VerifyAPIKey or VerifyJWT.");

    private HybridRules() {
    }

    static List<Rule> all() {
        return List.of(
                new Rule("HYB-01", HYBRID, "StatisticsCollector rewritten as DataCapture", true,
                        HybridRules::statisticsCollector),
                new Rule("HYB-02", HYBRID, "VirtualHost is ignored by hybrid", true, HybridRules::virtualHosts),
                new Rule("HYB-03", HYBRID, "Policies not supported by hybrid", HybridRules::unsupportedPolicies),
                new Rule("HYB-04", HYBRID, "Node.js hosted targets", HybridRules::scriptTargets),
                new Rule("HYB-05", HYBRID, "MessageLogging to a local file", HybridRules::fileLogging),
                new Rule("HYB-06", HYBRID, "Resources outside the bundle", HybridRules::externalResources),
                new Rule("HYB-07", HYBRID, "Keystores and truststores without a reference",
                        HybridRules::directKeystores));
    }

    /** StatisticsCollector → DataCapture, one data collector per statistic. */
    private static void statisticsCollector(MigrationContext ctx) throws IOException {
        for (Policy policy : ctx.policies("StatisticsCollector")) {
            Element root = ctx.xml(policy);
            StringBuilder xml = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n")
                    .append("<DataCapture name=\"").append(escape(policy.name())).append('"');
            for (String attribute : List.of("continueOnError", "enabled")) {
                String value = Xml.attr(root, attribute);
                if (value != null) xml.append(' ').append(attribute).append("=\"").append(escape(value)).append('"');
            }
            xml.append(">\n");
            List<String> collectors = new ArrayList<>();
            for (Element statistic : Xml.descendants(root, "Statistic")) {
                String name = Xml.attr(statistic, "name");
                String ref = Xml.attr(statistic, "ref");
                if (name == null || ref == null) continue;
                String collector = "dc_" + name.replaceAll("[^A-Za-z0-9_]", "_");
                collectors.add(collector);
                xml.append("    <Capture>\n        <DataCollector>").append(escape(collector))
                        .append("</DataCollector>\n        <Collect ref=\"").append(escape(ref)).append('"');
                String fallback = Xml.text(statistic);
                if (fallback != null) xml.append(" default=\"").append(escape(fallback)).append('"');
                xml.append("/>\n    </Capture>\n");
                ctx.resource("Data collector", collector,
                        dataType(Xml.attr(statistic, "type")) + ", replaces statistic " + name);
            }
            xml.append("</DataCapture>\n");
            ctx.workspace.replace(policy.file(), xml.toString(), "StatisticsCollector rewritten as DataCapture");
            ctx.fixed(ERROR, policy.name(), "StatisticsCollector is not supported by Apigee hybrid",
                    "Rewritten as a DataCapture policy. Create the data collectors " + names(collectors)
                            + " before deploying, and point custom analytics reports at them.");
        }
    }

    private static String dataType(String statisticType) {
        if (statisticType == null) return "STRING";
        return switch (statisticType.toLowerCase()) {
            case "integer", "long" -> "INTEGER";
            case "float", "double" -> "FLOAT";
            case "boolean" -> "BOOLEAN";
            default -> "STRING";
        };
    }

    /** Hybrid ignores VirtualHost: hostnames come from the environment group the environment belongs to. */
    private static void virtualHosts(MigrationContext ctx) throws IOException {
        for (String file : ctx.workspace.xmlFiles("proxies")) {
            Element root = ctx.workspace.root(file);
            Element connection = Xml.path(root, "HTTPProxyConnection");
            List<Element> virtualHosts = Xml.children(connection, "VirtualHost");
            if (virtualHosts.isEmpty()) continue;
            List<String> names = virtualHosts.stream().map(Xml::text).toList();
            virtualHosts.forEach(Dom::remove);
            ctx.workspace.modified(file, "removed VirtualHost " + names(names));
            names.forEach(vh -> ctx.resource("Environment group hostnames", vh,
                    "hostnames served by Edge virtual host " + vh));
            ctx.fixed(WARN, "ProxyEndpoint " + Xml.nameOf(root),
                    "VirtualHost " + names(names) + " is ignored by Apigee hybrid",
                    "VirtualHost elements removed. Add the hostnames these virtual hosts served to the environment"
                            + " group of the target environment: the proxy answers on every hostname of the group.");
        }
    }

    private static void unsupportedPolicies(MigrationContext ctx) {
        for (Policy policy : ctx.policies()) {
            String replacement = UNSUPPORTED_POLICIES.get(policy.type());
            if (replacement == null || !policy.attached()) continue;
            ctx.manual(ERROR, policy.name(), policy.type() + " is not supported by Apigee hybrid", replacement);
        }
    }

    private static void scriptTargets(MigrationContext ctx) throws IOException {
        for (String file : ctx.workspace.xmlFiles("targets")) {
            Element root = ctx.workspace.root(file);
            if (Xml.path(root, "ScriptTarget") == null) continue;
            ctx.manual(ERROR, "TargetEndpoint " + Xml.nameOf(root),
                    "Node.js hosted targets (ScriptTarget) are not supported by Apigee hybrid",
                    "Deploy the Node.js application as its own service (Cloud Run, GKE...) and target it through a"
                            + " TargetServer.");
        }
    }

    private static void fileLogging(MigrationContext ctx) throws IOException {
        for (Policy policy : ctx.policies("MessageLogging")) {
            if (Xml.path(ctx.xml(policy), "File") == null) continue;
            ctx.manual(ERROR, policy.name(), "MessageLogging to a local file only exists on Edge for Private Cloud",
                    "Log through Syslog or CloudLogging instead of File.");
        }
    }

    /** Resources referenced by URL but absent from the bundle: hybrid has no organization-level resource files. */
    private static void externalResources(MigrationContext ctx) {
        for (Dependency dependency : ctx.report.dependencies()) {
            if (dependency.kind() != DependencyKind.RESOURCE || !dependency.active()) continue;
            boolean external = dependency.usages().stream()
                    .anyMatch(u -> !"bundle".equals(u.details().get("location")));
            if (!external) continue;
            ctx.resource("Resource file (environment)", dependency.name(), "must exist in every target environment");
            ctx.manual(WARN, users(dependency), "Resource " + dependency.name() + " is not in the bundle",
                    "Copy it into the bundle's resources/ folder (preferred), or create it as an environment"
                            + " resource: Apigee hybrid has no organization-level resource files.");
        }
    }

    /** Keystores/truststores named directly: a reference lets certificates rotate without redeploying. */
    private static void directKeystores(MigrationContext ctx) {
        for (Dependency dependency : ctx.report.dependencies()) {
            boolean store = dependency.kind() == DependencyKind.KEYSTORE || dependency.kind() == DependencyKind.TRUSTSTORE;
            if (!store || !dependency.active()) continue;
            if (dependency.usages().stream().allMatch(u -> "reference".equals(u.details().get("via")))) continue;
            ctx.manual(INFO, users(dependency), dependency.kind().label() + " " + dependency.name()
                            + " is named directly",
                    "Create a reference (e.g. " + dependency.name() + "-ref) in each environment and use ref://"
                            + dependency.name() + "-ref, so certificates rotate without redeploying the proxy.");
        }
    }

    static String users(Dependency dependency) {
        return dependency.usages().stream().map(Usage::label).distinct().reduce((a, b) -> a + ", " + b).orElse("");
    }
}
