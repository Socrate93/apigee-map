package dev.apigeemap.migration;

import dev.apigeemap.analysis.ScriptAnalyzer;
import dev.apigeemap.analysis.Xml;
import dev.apigeemap.model.Dependency;
import dev.apigeemap.model.DependencyKind;
import dev.apigeemap.model.Policy;
import dev.apigeemap.model.Usage;
import org.w3c.dom.Element;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
            "OAuthV1", "Move the clients to OAuthV2, VerifyAPIKey or VerifyJWT.",
            "GetOAuthV1Info", "Move the clients to OAuthV2 and read token attributes with GetOAuthV2Info.",
            "DeleteOAuthV1Info", "Move the clients to OAuthV2 and revoke tokens with DeleteOAuthV2Info.",
            "ConnectorCallout", "Edge extensions do not exist in hybrid: call the Google service directly from a"
                    + " ServiceCallout or TargetEndpoint, authenticated with a Google access token.");

    /** virtualhost.name, virtualhost.aliases... outside of words, so {@code <VirtualHost>} never matches. */
    private static final Pattern VIRTUALHOST_VARIABLE = Pattern.compile("(?<![\\w.])virtualhost\\.[A-Za-z_][\\w.]*");

    /** Edge management API paths: /v1/o/{org}/... or /v1/organizations/{org}/... */
    private static final Pattern MANAGEMENT_PATH = Pattern.compile("(?i)/v1/(o|organizations)(/|$|\\{)");
    /** Edge management servers: Edge cloud, or an OPDK management server on its default port. */
    private static final Pattern MANAGEMENT_HOST = Pattern.compile(
            "(?i)^https?://(api\\.enterprise\\.apigee\\.com|[^/]+:8080/v1/)");

    /** Apigee X and hybrid limit, also used by Google's migration assessment tool. */
    static final int MAX_PROXY_ENDPOINTS = 10;

    /** Host of an http(s) URL, also when the rest of the URL holds {variables}. */
    private static final Pattern URL_HOST = Pattern.compile("^https?://(\\[[^\\]]+\\]|[^/:?#{}]+)",
            Pattern.CASE_INSENSITIVE);

    private HybridRules() {
    }

    static List<Rule> all() {
        return List.of(
                new Rule("HYB-01", HYBRID, "StatisticsCollector rewritten as DataCapture", true,
                        HybridRules::statisticsCollector),
                new Rule("HYB-02", HYBRID, "VirtualHost is ignored by hybrid", true, HybridRules::virtualHosts),
                new Rule("HYB-03", HYBRID, "Policies not supported by hybrid", HybridRules::unsupportedPolicies),
                new Rule("HYB-04", HYBRID, "Node.js and hosted targets", HybridRules::scriptTargets),
                new Rule("HYB-05", HYBRID, "MessageLogging to a local file", HybridRules::fileLogging),
                new Rule("HYB-06", HYBRID, "Resources outside the bundle", HybridRules::externalResources),
                new Rule("HYB-07", HYBRID, "Keystores and truststores without a reference",
                        HybridRules::directKeystores),
                new Rule("HYB-08", HYBRID, "Backend on localhost", HybridRules::localhostBackends),
                new Rule("HYB-09", HYBRID, "JSONPath expressions to retest", HybridRules::jsonPath),
                new Rule("HYB-10", HYBRID, "Several ProxyEndpoints", HybridRules::proxyEndpoints),
                new Rule("HYB-11", HYBRID, "virtualhost.* flow variables", HybridRules::virtualHostVariables),
                new Rule("HYB-12", HYBRID, "JavaScript that does not parse", HybridRules::unparsableScripts),
                new Rule("HYB-13", HYBRID, "Calls to the Edge management API", HybridRules::managementApiCalls),
                new Rule("HYB-14", HYBRID, "URLs built at runtime", HybridRules::runtimeUrls));
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
                            + " before deploying, and point custom analytics reports at them.", ctx.on(policy));
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
                            + " group of the target environment: the proxy answers on every hostname of the group.",
                    ctx.onFile(file));
        }
    }

    private static void unsupportedPolicies(MigrationContext ctx) {
        for (Policy policy : ctx.policies()) {
            String replacement = UNSUPPORTED_POLICIES.get(policy.type());
            if (replacement == null || !policy.attached()) continue;
            ctx.manual(ERROR, policy.name(), policy.type() + " is not supported by Apigee hybrid", replacement,
                    ctx.on(policy));
        }
    }

    /** Node.js (ScriptTarget) and hosted targets, and node/hosted resources no target uses any more. */
    private static void scriptTargets(MigrationContext ctx) throws IOException {
        boolean targets = false;
        for (String file : ctx.workspace.xmlFiles("targets")) {
            Element root = ctx.workspace.root(file);
            String kind = Xml.path(root, "ScriptTarget") != null ? "Node.js hosted targets (ScriptTarget)"
                    : Xml.path(root, "HostedTarget") != null ? "Hosted targets (HostedTarget)" : null;
            if (kind == null) continue;
            targets = true;
            ctx.manual(ERROR, "TargetEndpoint " + Xml.nameOf(root), kind + " are not supported by Apigee hybrid",
                    "Deploy the Node.js application as its own service (Cloud Run, GKE...) and target it through a"
                            + " TargetServer.", ctx.onFile(file));
        }
        if (targets) return;
        for (String type : List.of("node", "hosted")) {
            List<String> files = ctx.workspace.resources(type);
            if (files.isEmpty()) continue;
            ctx.manual(WARN, "resources/" + type, files.size() + " " + type
                            + " resource file(s) that Apigee hybrid does not support",
                    "No TargetEndpoint uses them: remove them from the bundle, or move the application they hold to"
                            + " its own service.", ctx.onFiles(files));
        }
    }

    private static void fileLogging(MigrationContext ctx) throws IOException {
        for (Policy policy : ctx.policies("MessageLogging")) {
            if (Xml.path(ctx.xml(policy), "File") == null) continue;
            ctx.manual(ERROR, policy.name(), "MessageLogging to a local file only exists on Edge for Private Cloud",
                    "Log through Syslog or CloudLogging instead of File.", ctx.on(policy));
        }
    }

    /** Resources referenced by URL but absent from the bundle: hybrid has no organization-level resource files. */
    private static void externalResources(MigrationContext ctx) throws IOException {
        for (Dependency dependency : ctx.report.dependencies()) {
            if (dependency.kind() != DependencyKind.RESOURCE || !dependency.active()) continue;
            boolean external = dependency.usages().stream()
                    .anyMatch(u -> !"bundle".equals(u.details().get("location")));
            if (!external) continue;
            ctx.resource("Resource file (environment)", dependency.name(), "must exist in every target environment");
            ctx.manual(WARN, users(dependency), "Resource " + dependency.name() + " is not in the bundle",
                    "Copy it into the bundle's resources/ folder (preferred), or create it as an environment"
                            + " resource: Apigee hybrid has no organization-level resource files.",
                    ctx.on(dependency));
        }
    }

    /** Keystores/truststores named directly: a reference lets certificates rotate without redeploying. */
    private static void directKeystores(MigrationContext ctx) throws IOException {
        for (Dependency dependency : ctx.report.dependencies()) {
            boolean store = dependency.kind() == DependencyKind.KEYSTORE || dependency.kind() == DependencyKind.TRUSTSTORE;
            if (!store || !dependency.active()) continue;
            if (dependency.usages().stream().allMatch(u -> "reference".equals(u.details().get("via")))) continue;
            ctx.manual(INFO, users(dependency), dependency.kind().label() + " " + dependency.name()
                            + " is named directly",
                    "Create a reference (e.g. " + dependency.name() + "-ref) in each environment and use ref://"
                            + dependency.name() + "-ref, so certificates rotate without redeploying the proxy.",
                    ctx.on(dependency));
        }
    }

    /**
     * Backends on localhost: on Edge the message processor host may run them, in hybrid localhost is the runtime
     * pod. TargetEndpoints and ServiceCallouts, checked before DES-01 moves the URLs to target servers.
     */
    private static void localhostBackends(MigrationContext ctx) throws IOException {
        String action = "Point it to the backend's real hostname (through a TargetServer per environment):"
                + " in Apigee hybrid localhost is the runtime pod itself.";
        for (String file : ctx.workspace.xmlFiles("targets")) {
            Element root = ctx.workspace.root(file);
            String url = Xml.text(root, "HTTPTargetConnection", "URL");
            if (isLocal(url)) ctx.manual(ERROR, "TargetEndpoint " + Xml.nameOf(root),
                    "Backend URL " + url + " points to the local host", action, ctx.onFile(file));
        }
        for (Policy policy : ctx.policies("ServiceCallout")) {
            String url = Xml.text(ctx.xml(policy), "HTTPTargetConnection", "URL");
            if (policy.attached() && isLocal(url)) ctx.manual(ERROR, policy.name(),
                    "Callout URL " + url + " points to the local host", action, ctx.on(policy));
        }
        for (Scripts.Script script : Scripts.of(ctx.report)) {
            for (String url : script.facts().urls()) {
                if (isLocal(url)) ctx.manual(ERROR, script.policy(),
                        "JavaScript " + script.file() + " calls " + url + ", which points to the local host", action,
                        ctx.on(script));
            }
        }
    }

    static boolean isLocal(String url) {
        if (url == null) return false;
        Matcher matcher = URL_HOST.matcher(url.trim());
        if (!matcher.find()) return false;
        String host = matcher.group(1).toLowerCase(Locale.ROOT);
        return host.equals("localhost") || host.endsWith(".localhost") || host.startsWith("127.")
                || host.equals("0.0.0.0") || host.equals("[::1]");
    }

    /** Edge evaluates JSONPath with an old engine (0.8); hybrid uses Jayway JsonPath 2.x, whose results can differ. */
    private static void jsonPath(MigrationContext ctx) throws IOException {
        for (Policy policy : ctx.policies("ExtractVariables")) {
            if (!policy.attached()) continue;
            List<String> paths = Xml.descendants(Xml.path(ctx.xml(policy), "JSONPayload"), "JSONPath").stream()
                    .map(Xml::text).filter(p -> p != null).toList();
            if (paths.isEmpty()) continue;
            ctx.manual(WARN, policy.name(), "JSONPath " + names(paths) + " may return different results in hybrid",
                    "Apigee hybrid uses a newer JSONPath engine than Edge (filters, wildcards and single-item arrays"
                            + " behave differently). Test each expression against sample payloads after deploying.",
                    ctx.on(policy));
        }
    }

    /** Above the limit the proxy cannot be deployed; below it, one base path per proxy is the usual design. */
    private static void proxyEndpoints(MigrationContext ctx) throws IOException {
        if (!ctx.isProxy()) return;
        List<String> basePaths = new ArrayList<>();
        for (String file : ctx.workspace.xmlFiles("proxies")) {
            Element root = ctx.workspace.root(file);
            String basePath = Xml.text(root, "HTTPProxyConnection", "BasePath");
            basePaths.add(Xml.nameOf(root) + (basePath != null ? " (" + basePath + ")" : ""));
        }
        if (basePaths.size() > MAX_PROXY_ENDPOINTS) {
            ctx.manual(ERROR, ctx.report.name(), basePaths.size() + " ProxyEndpoints, above the limit of "
                            + MAX_PROXY_ENDPOINTS + " in Apigee hybrid",
                    "Split the proxy into several proxies, grouping the ProxyEndpoints by base path.",
                    ctx.onFiles(ctx.workspace.xmlFiles("proxies")));
        } else if (basePaths.size() > 1) {
            ctx.manual(INFO, ctx.report.name(), basePaths.size() + " ProxyEndpoints: " + names(basePaths),
                    "Consider one proxy per base path: proxies deploy, version and scale independently.",
                    ctx.onFiles(ctx.workspace.xmlFiles("proxies")));
        }
    }

    /**
     * virtualhost.* variables describe the Edge virtual host that received the request; hybrid has environment
     * groups instead, so these variables are empty or different there.
     */
    private static void virtualHostVariables(MigrationContext ctx) throws IOException {
        String action = "Use request.header.host, environment.name or a value from a KVM instead: Apigee hybrid"
                + " has environment groups, not virtual hosts.";
        for (Policy policy : ctx.policies()) {
            Set<String> variables = virtualHostVariables(ctx.workspace.read(policy.file()));
            if (policy.attached() && !variables.isEmpty()) {
                ctx.manual(WARN, policy.name(), "Uses " + names(variables), action, ctx.on(policy));
            }
        }
        for (String file : ctx.endpointFiles()) {
            Set<String> variables = virtualHostVariables(ctx.workspace.read(file));
            Element root = ctx.workspace.root(file);
            if (!variables.isEmpty()) {
                ctx.manual(WARN, root.getTagName() + " " + Xml.nameOf(root), "Uses " + names(variables), action,
                        ctx.onFile(file));
            }
        }
        for (Scripts.Script script : Scripts.of(ctx.report)) {
            List<String> variables = script.facts().reads().stream().filter(v -> v.startsWith("virtualhost.")).toList();
            if (!variables.isEmpty()) {
                ctx.manual(WARN, script.policy(), script.file() + " reads " + names(variables), action,
                        ctx.on(script));
            }
        }
    }

    private static Set<String> virtualHostVariables(String text) {
        Set<String> variables = new LinkedHashSet<>();
        Matcher matcher = VIRTUALHOST_VARIABLE.matcher(text);
        while (matcher.find()) variables.add(matcher.group());
        return variables;
    }

    /** Scripts Rhino rejects: Apigee runs JavaScript on Rhino, and the other script checks cannot read them. */
    private static void unparsableScripts(MigrationContext ctx) throws IOException {
        for (Scripts.Script script : Scripts.of(ctx.report)) {
            if (script.python()) continue;
            ScriptAnalyzer.Facts facts = script.facts();
            if (facts.error() == null) continue;
            ctx.manual(WARN, script.policy(), "JavaScript " + script.file() + " does not parse (" + facts.error() + ")",
                    "Fix the syntax: Apigee runs JavaScript on Rhino too, so the policy can fail at deployment or at"
                            + " runtime. The other script checks skipped this file.", ctx.on(script));
        }
    }

    /**
     * Calls to the Edge management API from the runtime: in hybrid the API moves to apigee.googleapis.com with
     * Google authentication, and reading entities at runtime is usually better done with a policy. Checked on
     * TargetEndpoints and ServiceCallouts (URL, or Path behind a TargetServer), target.url overrides and
     * JavaScript calls; URLs built entirely at runtime cannot be seen.
     */
    private static void managementApiCalls(MigrationContext ctx) throws IOException {
        for (String file : ctx.workspace.xmlFiles("targets")) {
            Element root = ctx.workspace.root(file);
            managementCall(ctx, "TargetEndpoint " + Xml.nameOf(root), Xml.path(root, "HTTPTargetConnection"),
                    ctx.onFile(file));
        }
        for (Policy policy : ctx.policies()) {
            if (!policy.attached()) continue;
            Element root = ctx.xml(policy);
            if (policy.type().equals("ServiceCallout")) {
                managementCall(ctx, policy.name(), Xml.path(root, "HTTPTargetConnection"), ctx.on(policy));
            } else if (policy.type().equals("AssignMessage")) {
                for (Element variable : Xml.children(root, "AssignVariable")) {
                    if (!"target.url".equals(Xml.text(variable, "Name"))) continue;
                    String url = Xml.text(variable, "Value");
                    if (url == null) url = Xml.text(variable, "Template");
                    if (isManagementApi(url)) {
                        reportManagementCall(ctx, policy.name(), "sets target.url to " + url, url, ctx.on(policy));
                    }
                }
            }
        }
        for (Scripts.Script script : Scripts.of(ctx.report)) {
            for (String url : script.facts().urls()) {
                if (isManagementApi(url)) {
                    reportManagementCall(ctx, script.policy(), script.file() + " calls " + url, url, ctx.on(script));
                }
            }
        }
    }

    private static void managementCall(MigrationContext ctx, String location, Element connection,
                                       List<Finding.Subject> subjects) {
        if (connection == null) return;
        String url = Xml.text(connection, "URL");
        if (isManagementApi(url)) {
            reportManagementCall(ctx, location, "calls " + url, url, subjects);
            return;
        }
        String path = Xml.text(connection, "Path");
        if (Xml.path(connection, "LoadBalancer") != null && path != null && MANAGEMENT_PATH.matcher(path).find()) {
            List<String> servers = Xml.children(Xml.path(connection, "LoadBalancer"), "Server").stream()
                    .map(s -> Xml.attr(s, "name")).toList();
            reportManagementCall(ctx, location, "calls " + path + " through target server " + names(servers), path,
                    subjects);
        }
    }

    static boolean isManagementApi(String url) {
        if (url == null) return false;
        String value = url.trim();
        if (MANAGEMENT_HOST.matcher(value).find()) return true;
        Matcher host = URL_HOST.matcher(value);
        return host.find() && !host.group(1).equalsIgnoreCase("apigee.googleapis.com")
                && MANAGEMENT_PATH.matcher(value.substring(host.end())).find();
    }

    private static void reportManagementCall(MigrationContext ctx, String location, String call, String url,
                                             List<Finding.Subject> subjects) {
        String lower = url.toLowerCase(Locale.ROOT);
        String instead = lower.contains("/keyvaluemaps") ? " Read KVM entries with KeyValueMapOperations instead."
                : lower.matches(".*/(developers|apps|apiproducts|companies)\\b.*")
                ? " Read developers, apps and products with AccessEntity (or the variables VerifyAPIKey and OAuthV2"
                        + " set) instead."
                : "";
        ctx.manual(ERROR, location, "Edge management API: " + call,
                "In Apigee hybrid the management API is https://apigee.googleapis.com/v1/organizations/{org}/...,"
                        + " authenticated with a Google OAuth token of a service account, and some paths differ."
                        + instead, subjects);
    }

    /**
     * Backends whose host is only known at runtime: the localhost (HYB-08), management API (HYB-13) and TLS (SEC-05)
     * checks cannot tell where they go, so someone has to.
     */
    private static void runtimeUrls(MigrationContext ctx) throws IOException {
        String action = "Check where it can point to in each environment: the localhost, management API and TLS"
                + " checks cannot see a host computed at runtime. Prefer a TargetServer per environment.";
        for (String file : ctx.workspace.xmlFiles("targets")) {
            Element root = ctx.workspace.root(file);
            String url = Xml.text(root, "HTTPTargetConnection", "URL");
            if (computedHost(url)) ctx.manual(WARN, "TargetEndpoint " + Xml.nameOf(root),
                    "Backend URL " + url + " is built at runtime", action, ctx.onFile(file));
        }
        for (Policy policy : ctx.policies()) {
            if (!policy.attached()) continue;
            Element root = ctx.xml(policy);
            if (policy.type().equals("ServiceCallout")) {
                String url = Xml.text(root, "HTTPTargetConnection", "URL");
                if (computedHost(url)) ctx.manual(WARN, policy.name(), "Callout URL " + url + " is built at runtime",
                        action, ctx.on(policy));
            } else if (policy.type().equals("AssignMessage")) {
                for (Element variable : Xml.children(root, "AssignVariable")) {
                    if (!"target.url".equals(Xml.text(variable, "Name"))) continue;
                    String ref = Xml.text(variable, "Ref");
                    String url = ref != null ? "{" + ref + "}" : Xml.text(variable, "Template");
                    if (url == null) url = Xml.text(variable, "Value");
                    if (computedHost(url)) ctx.manual(WARN, policy.name(), "Sets target.url to " + url
                            + ", built at runtime", action, ctx.on(policy));
                }
            }
        }
        for (Scripts.Script script : Scripts.of(ctx.report)) {
            if (script.python()) continue;
            ScriptAnalyzer.Facts facts = script.facts();
            List<String> urls = new ArrayList<>(facts.computedUrls());
            facts.urls().stream().filter(HybridRules::computedHost).forEach(urls::add);
            if (!urls.isEmpty()) ctx.manual(WARN, script.policy(), "JavaScript " + script.file()
                    + " calls URLs built at runtime: " + names(urls), action, ctx.on(script));
        }
    }

    /** True when the host of the URL holds a {variable}, or the whole URL does. */
    static boolean computedHost(String url) {
        if (url == null || !url.contains("{")) return false;
        Matcher matcher = URL_HOST.matcher(url.trim());
        return !matcher.find() || url.trim().startsWith("{", matcher.end());
    }

    static String users(Dependency dependency) {
        return dependency.usages().stream().map(Usage::label).distinct().reduce((a, b) -> a + ", " + b).orElse("");
    }
}
