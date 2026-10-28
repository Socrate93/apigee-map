package dev.apigeemap.analysis;

import org.w3c.dom.Element;

import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import static dev.apigeemap.analysis.Details.put;
import static dev.apigeemap.model.DependencyKind.CACHE;
import static dev.apigeemap.model.DependencyKind.KVM;
import static dev.apigeemap.model.DependencyKind.RESOURCE;
import static dev.apigeemap.model.DependencyKind.SHARED_FLOW;
import static dev.apigeemap.model.DependencyKind.SYSLOG;
import static dev.apigeemap.model.DependencyKind.TARGET_URL;
import static dev.apigeemap.model.Issue.Severity.ERROR;
import static dev.apigeemap.model.Issue.Severity.INFO;
import static dev.apigeemap.model.Issue.Severity.WARN;

/** Extracts the dependencies declared by a single policy, based on its root element (the policy type). */
final class PolicyAnalyzer {

    /** OPDK defaults: KVM without mapIdentifier is "kvmap", KVM scope defaults to environment. */
    static final String DEFAULT_KVM = "kvmap";
    static final String DEFAULT_KVM_SCOPE = "environment";
    /** Cache policies without CacheResource use the environment's included shared cache. */
    static final String DEFAULT_CACHE = "(default shared cache)";

    private PolicyAnalyzer() {
    }

    static void analyze(Element policy, Origin origin, BundleContext ctx) {
        switch (policy.getTagName()) {
            case "FlowCallout" -> flowCallout(policy, origin, ctx);
            case "KeyValueMapOperations" -> kvm(policy, origin, ctx);
            case "LookupCache", "PopulateCache", "InvalidateCache", "ResponseCache" -> cache(policy, origin, ctx);
            case "ServiceCallout" -> serviceCallout(policy, origin, ctx);
            case "Javascript" -> {
                resources(policy, origin, ctx);
                javascript(policy, origin, ctx);
            }
            case "JavaCallout", "XSL", "Script" -> resources(policy, origin, ctx);
            case "MessageLogging" -> messageLogging(policy, origin, ctx);
            case "AssignMessage" -> assignMessage(policy, origin, ctx);
            default -> {
            }
        }
    }

    private static void flowCallout(Element policy, Origin origin, BundleContext ctx) {
        String sharedFlow = Xml.text(policy, "SharedFlowBundle");
        if (sharedFlow == null) {
            ctx.issue(ERROR, "FlowCallout " + origin.name() + " declares no SharedFlowBundle");
            return;
        }
        ctx.deps.add(SHARED_FLOW, sharedFlow, origin.usage(Map.of()));
        ctx.sharedFlowRefs.add(sharedFlow);
    }

    private static void kvm(Element policy, Origin origin, BundleContext ctx) {
        String map = Objects.requireNonNullElse(Xml.attr(policy, "mapIdentifier"), DEFAULT_KVM);
        Set<String> operations = new LinkedHashSet<>();
        Set<String> keys = new LinkedHashSet<>();
        boolean encrypted = false;
        for (String operation : List.of("Get", "Put", "Delete")) {
            for (Element element : Xml.children(policy, operation)) {
                operations.add(operation.toLowerCase());
                String assignTo = Xml.attr(element, "assignTo");
                if (assignTo != null && assignTo.startsWith("private.")) encrypted = true;
                for (Element key : Xml.children(element, "Key")) {
                    String value = Xml.children(key, "Parameter").stream()
                            .map(Xml::valueOrRef)
                            .filter(Objects::nonNull)
                            .collect(Collectors.joining("."));
                    if (!value.isEmpty()) keys.add(value);
                }
            }
        }
        if (Xml.path(policy, "InitialEntries") != null) operations.add("initialEntries");

        Map<String, String> details = new LinkedHashMap<>();
        details.put("scope", Objects.requireNonNullElse(Xml.text(policy, "Scope"), DEFAULT_KVM_SCOPE));
        if (!operations.isEmpty()) details.put("operations", String.join(", ", operations));
        if (!keys.isEmpty()) details.put("keys", String.join(", ", keys));
        if (encrypted) details.put("encrypted", "true");
        put(details, "ttl", Xml.text(policy, "ExpiryTimeInSecs"));
        ctx.deps.add(KVM, map, origin.usage(details));
    }

    private static void cache(Element policy, Origin origin, BundleContext ctx) {
        String type = policy.getTagName();
        Map<String, String> details = new LinkedHashMap<>();
        details.put("operation", switch (type) {
            case "LookupCache" -> "lookup";
            case "PopulateCache" -> "populate";
            case "InvalidateCache" -> "invalidate";
            default -> "response cache";
        });
        put(details, "scope", Xml.text(policy, "Scope"));
        Element cacheKey = Xml.path(policy, "CacheKey");
        put(details, "prefix", Xml.text(cacheKey, "Prefix"));
        String fragments = Xml.children(cacheKey, "KeyFragment").stream()
                .map(Xml::valueOrRef)
                .filter(Objects::nonNull)
                .collect(Collectors.joining(" + "));
        put(details, "key", fragments);
        Element timeout = Xml.path(policy, "ExpirySettings", "TimeoutInSec");
        if (timeout != null) put(details, "ttl", Xml.valueOrRef(timeout));
        String resource = Objects.requireNonNullElse(Xml.text(policy, "CacheResource"), DEFAULT_CACHE);
        ctx.deps.add(CACHE, resource, origin.usage(details));
    }

    private static void serviceCallout(Element policy, Origin origin, BundleContext ctx) {
        Element http = Xml.path(policy, "HTTPTargetConnection");
        Element local = Xml.path(policy, "LocalTargetConnection");
        if (http != null) Connections.http(http, origin, ctx);
        if (local != null) Connections.local(local, origin, ctx);
        if (http == null && local == null) {
            ctx.issue(WARN, "ServiceCallout " + origin.name() + " declares no target connection");
        }
    }

    private static void resources(Element policy, Origin origin, BundleContext ctx) {
        List<Element> urls = new ArrayList<>(Xml.children(policy, "ResourceURL"));
        urls.addAll(Xml.children(policy, "IncludeURL"));
        for (Element url : urls) {
            String value = Xml.text(url);
            if (value != null) resource(value, origin, ctx);
        }
    }

    /** URLs the scripts call through httpClient; scripts Rhino cannot parse are reported. */
    private static void javascript(Element policy, Origin origin, BundleContext ctx) {
        Map<String, String> scripts;
        try {
            scripts = ScriptAnalyzer.scripts(ctx.dir, policy);
        } catch (IOException e) {
            ctx.issue(WARN, "Cannot read the scripts of " + origin.name() + ": " + e.getMessage());
            return;
        }
        scripts.forEach((file, source) -> {
            ScriptAnalyzer.Facts facts = ScriptAnalyzer.analyze(source, file);
            if (facts.error() != null) {
                ctx.issue(WARN, "JavaScript " + file + " (used by " + origin.name() + ") cannot be parsed: "
                        + facts.error());
            }
            for (String url : facts.urls()) ctx.deps.add(TARGET_URL, url, origin.usage(Map.of("via", "httpClient")));
        });
    }

    /** {@code jsc://file.js}: looked up in resources/jsc/, otherwise expected at environment/organization level. */
    static void resource(String url, Origin origin, BundleContext ctx) {
        Map<String, String> details = new LinkedHashMap<>();
        int separator = url.indexOf("://");
        if (separator > 0) {
            String type = url.substring(0, separator);
            String file = url.substring(separator + 3);
            boolean inBundle = Files.isRegularFile(ctx.dir.resolve("resources").resolve(type).resolve(file));
            details.put("type", type);
            details.put("location", inBundle ? "bundle" : "environment/organization");
            if (!inBundle) {
                ctx.issue(WARN, "Resource " + url + " (used by " + origin.name() + ") is not in the bundle:"
                        + " it must exist as an environment or organization resource");
            }
        }
        ctx.deps.add(RESOURCE, url, origin.usage(details));
    }

    private static void messageLogging(Element policy, Origin origin, BundleContext ctx) {
        Element syslog = Xml.path(policy, "Syslog");
        String host = Xml.text(syslog, "Host");
        if (host == null) return;
        String port = Xml.text(syslog, "Port");
        Map<String, String> details = new LinkedHashMap<>();
        put(details, "protocol", Xml.text(syslog, "Protocol"));
        put(details, "ssl", Xml.text(syslog, "SSLInfo", "Enabled"));
        ctx.deps.add(SYSLOG, port == null ? host : host + ":" + port, origin.usage(details));
    }

    private static void assignMessage(Element policy, Origin origin, BundleContext ctx) {
        for (Element variable : Xml.children(policy, "AssignVariable")) {
            if ("target.url".equals(Xml.text(variable, "Name"))) {
                ctx.issue(INFO, origin.name() + " overrides target.url at runtime:"
                        + " the effective backend may differ from the TargetEndpoint configuration");
            }
        }
    }
}
