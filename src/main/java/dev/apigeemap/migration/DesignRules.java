package dev.apigeemap.migration;

import dev.apigeemap.analysis.Xml;
import dev.apigeemap.model.BundleReport;
import dev.apigeemap.model.Policy;
import org.w3c.dom.Element;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;

import static dev.apigeemap.migration.Finding.Category.DESIGN;
import static dev.apigeemap.migration.MigrationContext.names;
import static dev.apigeemap.model.Issue.Severity.INFO;
import static dev.apigeemap.model.Issue.Severity.WARN;

final class DesignRules {

    /** Usual name prefixes by policy type; a name passes when it starts with one of them followed by - or _. */
    private static final Map<String, List<String>> PREFIXES = Map.ofEntries(
            Map.entry("AssignMessage", List.of("AM")),
            Map.entry("ExtractVariables", List.of("EV")),
            Map.entry("Javascript", List.of("JS")),
            Map.entry("JavaCallout", List.of("JC", "Java")),
            Map.entry("KeyValueMapOperations", List.of("KVM")),
            Map.entry("ServiceCallout", List.of("SC")),
            Map.entry("FlowCallout", List.of("FC")),
            Map.entry("VerifyAPIKey", List.of("VA", "VAK")),
            Map.entry("OAuthV2", List.of("OA", "OAuth", "OAuthV2")),
            Map.entry("Quota", List.of("Q", "Quota")),
            Map.entry("SpikeArrest", List.of("SA")),
            Map.entry("RaiseFault", List.of("RF")),
            Map.entry("MessageLogging", List.of("ML")),
            Map.entry("LookupCache", List.of("LC")),
            Map.entry("PopulateCache", List.of("PC")),
            Map.entry("InvalidateCache", List.of("IC")),
            Map.entry("ResponseCache", List.of("RC")),
            Map.entry("JSONThreatProtection", List.of("JTP", "JSON")),
            Map.entry("XMLThreatProtection", List.of("XTP", "XML")),
            Map.entry("RegularExpressionProtection", List.of("REP", "RE")),
            Map.entry("DataCapture", List.of("DC")),
            Map.entry("StatisticsCollector", List.of("DC")), // rewritten as DataCapture by HYB-01
            Map.entry("BasicAuthentication", List.of("BA")),
            Map.entry("AccessControl", List.of("AC")),
            Map.entry("JSONToXML", List.of("J2X", "JTX")),
            Map.entry("XMLToJSON", List.of("X2J", "XTJ")),
            Map.entry("VerifyJWT", List.of("JWT", "VJWT")),
            Map.entry("GenerateJWT", List.of("JWT", "GJWT")),
            Map.entry("DecodeJWT", List.of("JWT", "DJWT")),
            Map.entry("XSL", List.of("XSL")),
            Map.entry("CORS", List.of("CORS")));

    private DesignRules() {
    }

    /** Unused policies are removed last, after the other rules have looked at them. */
    static List<Rule> all() {
        return List.of(
                new Rule("DES-01", DESIGN, "Hardcoded target URLs moved to target servers", true,
                        DesignRules::hardcodedTargetUrls),
                new Rule("DES-02", DESIGN, "Disabled policies still attached", DesignRules::disabledPolicies),
                new Rule("DES-03", DESIGN, "Condition repeated on several steps", DesignRules::repeatedConditions),
                new Rule("DES-04", DESIGN, "No DefaultFaultRule", DesignRules::defaultFaultRule),
                new Rule("DES-05", DESIGN, "Duplicate policies", DesignRules::duplicatePolicies),
                new Rule("DES-06", DESIGN, "Policy naming convention", DesignRules::naming),
                new Rule("DES-07", DESIGN, "Policies attached to no flow are removed", true,
                        DesignRules::unattachedPolicies));
    }

    /** TargetEndpoint URL → LoadBalancer with a TargetServer per host:port, plus Path. */
    private static void hardcodedTargetUrls(MigrationContext ctx) throws IOException {
        for (String file : ctx.workspace.xmlFiles("targets")) {
            Element root = ctx.workspace.root(file);
            Element connection = Xml.path(root, "HTTPTargetConnection");
            Element urlElement = Xml.path(connection, "URL");
            String url = Xml.text(urlElement);
            if (url == null) continue;
            String location = "TargetEndpoint " + Xml.nameOf(root);
            URI uri = staticUri(url);
            if (uri == null) {
                ctx.manual(INFO, location, "Backend URL " + url + " cannot be moved to a TargetServer automatically",
                        "Move the host and port to a TargetServer and keep the variable part in <Path>.");
                continue;
            }
            boolean https = uri.getScheme().equalsIgnoreCase("https");
            int port = uri.getPort() != -1 ? uri.getPort() : https ? 443 : 80;
            String host = uri.getHost();
            String name = "ts-" + host.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "-")
                    + (uri.getPort() != -1 ? "-" + port : "");

            String indent = Dom.indentOf(urlElement);
            Element loadBalancer = Dom.element(urlElement, "LoadBalancer", null);
            Element server = Dom.element(urlElement, "Server", null);
            server.setAttribute("name", name);
            loadBalancer.appendChild(root.getOwnerDocument().createTextNode(indent + "    "));
            loadBalancer.appendChild(server);
            loadBalancer.appendChild(root.getOwnerDocument().createTextNode(indent));
            Dom.insertBefore(urlElement, loadBalancer);
            String path = uri.getRawPath();
            if (path == null || path.isEmpty()) {
                Dom.remove(urlElement);
            } else {
                connection.replaceChild(Dom.element(urlElement, "Path", path), urlElement);
            }

            ctx.workspace.modified(file, "URL " + url + " replaced by TargetServer " + name);
            ctx.targetServer(new MigrationContext.NewTargetServer(name, host, port, https));
            String ssl = Xml.path(connection, "SSLInfo") != null
                    ? " Move the SSLInfo settings to the target server definition." : "";
            ctx.fixed(WARN, location, "Hardcoded backend URL " + url,
                    "Replaced by TargetServer " + name + ": create it in each environment with that environment's"
                            + " backend host (targetservers.json)." + ssl);
        }
    }

    /** Absolute http(s) URL without variables nor query string, or null. */
    private static URI staticUri(String url) {
        if (url.contains("{")) return null;
        try {
            URI uri = new URI(url);
            boolean http = "http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme());
            return http && uri.getHost() != null && uri.getRawQuery() == null && uri.getUserInfo() == null ? uri : null;
        } catch (URISyntaxException e) {
            return null;
        }
    }

    private static void disabledPolicies(MigrationContext ctx) {
        for (Policy policy : ctx.policies()) {
            if (policy.enabled() || !policy.attached()) continue;
            ctx.manual(INFO, policy.name(), "Disabled " + policy.type() + " still attached to "
                            + policy.attachments().size() + " step(s)",
                    "Remove the policy and its steps, or enable it if it is still needed.");
        }
    }

    /** Three or more steps of a flow phase sharing the same condition belong in a conditional Flow. */
    private static void repeatedConditions(MigrationContext ctx) throws IOException {
        for (String file : ctx.endpointFiles()) {
            Element root = ctx.workspace.root(file);
            List<Element> phases = new ArrayList<>(Xml.descendants(root, "Request"));
            phases.addAll(Xml.descendants(root, "Response"));
            if (root.getTagName().equals("SharedFlow")) phases.add(root);
            for (Element phase : phases) {
                Map<String, List<String>> byCondition = new LinkedHashMap<>();
                for (Element step : Xml.children(phase, "Step")) {
                    String condition = Xml.text(step, "Condition");
                    if (condition != null) {
                        byCondition.computeIfAbsent(condition, c -> new ArrayList<>()).add(Xml.text(step, "Name"));
                    }
                }
                byCondition.forEach((condition, steps) -> {
                    if (steps.size() < 3) return;
                    ctx.manual(INFO, root.getTagName() + " " + Xml.nameOf(root),
                            "Steps " + names(steps) + " repeat the condition " + condition,
                            "Group them in a conditional Flow (or a shared flow) with that condition.");
                });
            }
        }
    }

    private static void defaultFaultRule(MigrationContext ctx) throws IOException {
        if (!ctx.isProxy()) return;
        for (String file : ctx.workspace.xmlFiles("proxies")) {
            Element root = ctx.workspace.root(file);
            if (Xml.path(root, "DefaultFaultRule") != null) continue;
            ctx.manual(INFO, "ProxyEndpoint " + Xml.nameOf(root), "No DefaultFaultRule",
                    "Add a DefaultFaultRule (AlwaysEnforce true) returning your standard error format, so"
                            + " unexpected and backend errors do not reach clients as-is.");
        }
    }

    /** Same policy type and content in several places of the migration (root bundle only, to report once). */
    private static void duplicatePolicies(MigrationContext ctx) throws IOException {
        if (ctx.sharedFlows.containsKey(ctx.report.name())) return;
        List<BundleReport> bundles = new ArrayList<>(List.of(ctx.report));
        bundles.addAll(ctx.sharedFlows.values());
        Map<String, List<String>> byContent = new LinkedHashMap<>();
        for (BundleReport bundle : bundles) {
            for (Policy policy : bundle.policies()) {
                if (!policy.active() || policy.type().equals("FlowCallout")) continue;
                String content = Files.readString(Path.of(bundle.path(), policy.file()))
                        .replaceFirst("\\sname=\"[^\"]*\"", "")
                        .replaceAll("<\\?xml[^>]*\\?>", "")
                        .replaceAll("\\s+", "");
                byContent.computeIfAbsent(policy.type() + content, k -> new ArrayList<>())
                        .add(bundle.name() + "/" + policy.name());
            }
        }
        for (List<String> copies : byContent.values()) {
            if (copies.size() < 2) continue;
            ctx.manual(INFO, names(copies), "Identical policies in " + copies.size() + " places",
                    "Keep a single copy (in a shared flow if several bundles need it) so they cannot drift apart.");
        }
    }

    static Map<String, List<String>> defaultPrefixes() {
        return PREFIXES;
    }

    private static void naming(MigrationContext ctx) {
        Map<String, List<String>> prefixes = new LinkedHashMap<>(PREFIXES);
        prefixes.putAll(ctx.options.namingPrefixes());
        prefixes.values().removeIf(List::isEmpty);
        List<String> offenders = ctx.policies().stream()
                .filter(p -> prefixes.containsKey(p.type()))
                .filter(p -> prefixes.get(p.type()).stream().noneMatch(prefix -> hasPrefix(p.name(), prefix)))
                .map(p -> p.name() + " (" + p.type() + " → " + prefixes.get(p.type()).get(0) + "-)")
                .collect(Collectors.toList());
        if (offenders.isEmpty()) return;
        ctx.manual(INFO, ctx.report.name(), "Policy names without the usual type prefix: " + names(offenders),
                "Rename them (policy file, name attribute and Step names) so the type reads from the flow.");
    }

    private static boolean hasPrefix(String name, String prefix) {
        return name.length() > prefix.length() && name.regionMatches(true, 0, prefix, 0, prefix.length())
                && (name.charAt(prefix.length()) == '-' || name.charAt(prefix.length()) == '_');
    }

    private static void unattachedPolicies(MigrationContext ctx) throws IOException {
        for (Policy policy : ctx.policies()) {
            if (policy.attached()) continue;
            ctx.workspace.delete(policy.file(), "removed (not attached to any flow)");
            removeFromDescriptor(ctx, policy.name());
            ctx.fixed(INFO, policy.name(), policy.type() + " is not attached to any flow", "Removed from the bundle.");
        }
    }

    /** Drops {@code <Policies><Policy>name</Policy></Policies>} entries of exported descriptors. */
    private static void removeFromDescriptor(MigrationContext ctx, String policy) throws IOException {
        for (String file : ctx.workspace.xmlFiles("")) {
            Element root = ctx.workspace.root(file);
            for (Element entry : Xml.children(Xml.path(root, "Policies"), "Policy")) {
                if (!policy.equals(Xml.text(entry))) continue;
                Dom.remove(entry);
                ctx.workspace.modified(file, "removed policy " + policy + " from the descriptor");
            }
        }
    }
}
