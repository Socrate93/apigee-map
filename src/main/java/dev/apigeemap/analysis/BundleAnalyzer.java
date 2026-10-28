package dev.apigeemap.analysis;

import dev.apigeemap.model.Attachment;
import dev.apigeemap.model.BundleReport;
import dev.apigeemap.model.BundleType;
import dev.apigeemap.model.Dependency;
import dev.apigeemap.model.Endpoint;
import dev.apigeemap.model.Policy;
import dev.apigeemap.model.SharedFlowLink;
import dev.apigeemap.model.Usage;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static dev.apigeemap.analysis.Details.put;
import static dev.apigeemap.model.DependencyKind.TARGET_URL;
import static dev.apigeemap.model.DependencyKind.VIRTUAL_HOST;
import static dev.apigeemap.model.Issue.Severity.ERROR;
import static dev.apigeemap.model.Issue.Severity.INFO;
import static dev.apigeemap.model.Issue.Severity.WARN;

/**
 * Builds the dependency report of an apiproxy/ or sharedflowbundle/ folder, following FlowCallouts
 * recursively into the shared flows found in the {@link SharedFlowRepository}.
 */
public final class BundleAnalyzer {

    private final SharedFlowRepository sharedFlows;
    private final Map<Path, BundleReport> cache = new HashMap<>();

    public BundleAnalyzer(SharedFlowRepository sharedFlows) {
        this.sharedFlows = sharedFlows;
    }

    public BundleReport analyze(Path bundleDir) throws IOException {
        return analyze(bundleDir.toAbsolutePath().normalize(), new ArrayDeque<>());
    }

    private BundleReport analyze(Path dir, Deque<String> stack) throws IOException {
        BundleReport cached = cache.get(dir);
        if (cached != null) return cached;

        BundleContext ctx = new BundleContext(dir);
        Element descriptor = descriptor(dir);
        BundleType type = detectType(dir, descriptor);
        String name = Objects.requireNonNullElseGet(Xml.attr(descriptor, "name"), () -> fallbackName(dir));

        List<Element> proxyEndpoints = parseAll(dir.resolve("proxies"));
        List<Element> targetEndpoints = parseAll(dir.resolve("targets"));
        List<Element> flows = parseAll(dir.resolve("sharedflows"));

        Map<String, List<Attachment>> attachments = new LinkedHashMap<>();
        Stream.of(proxyEndpoints, targetEndpoints, flows)
                .flatMap(List::stream)
                .forEach(root -> collectSteps(root, attachments));

        List<Policy> policies = analyzePolicies(dir, attachments, ctx);
        Set<String> policyNames = policies.stream().map(Policy::name).collect(Collectors.toSet());
        attachments.keySet().stream()
                .filter(step -> !policyNames.contains(step))
                .forEach(step -> ctx.issue(ERROR, "Step " + step + " references a policy missing from policies/"));

        List<Endpoint> endpoints = new ArrayList<>();
        Set<String> routedTargets = proxyEndpoints.stream()
                .flatMap(p -> Xml.descendants(p, "RouteRule").stream())
                .map(rule -> Xml.text(rule, "TargetEndpoint"))
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());
        Set<String> targetNames = new LinkedHashSet<>();
        for (Element target : targetEndpoints) {
            endpoints.add(targetEndpoint(target, type, routedTargets, ctx));
            targetNames.add(Xml.nameOf(target));
        }
        for (Element proxy : proxyEndpoints) endpoints.add(proxyEndpoint(proxy, targetNames, ctx));
        for (Element flow : flows) {
            int steps = Xml.descendants(flow, "Step").size();
            endpoints.add(new Endpoint("SharedFlow", Xml.nameOf(flow), Map.of("steps", String.valueOf(steps))));
        }

        List<Dependency> dependencies = ctx.deps.build();
        for (Dependency dependency : dependencies) {
            if (dependency.dynamic()) {
                ctx.issue(INFO, dependency.kind().label() + " " + dependency.name()
                        + " is resolved at runtime from a variable");
            } else if (dependency.kind() == TARGET_URL) {
                ctx.issue(WARN, "Hardcoded URL " + dependency.name() + " (" + origins(dependency)
                        + "): a TargetServer keeps the bundle portable across environments");
            }
        }

        stack.push(name);
        List<SharedFlowLink> links = resolveSharedFlows(ctx, stack);
        stack.pop();

        BundleReport report = new BundleReport(type, name, Xml.attr(descriptor, "revision"),
                Xml.text(descriptor, "Description"), dir.toString(), List.copyOf(endpoints), policies,
                dependencies, links, List.copyOf(ctx.issues));
        cache.put(dir, report);
        return report;
    }

    static Element descriptor(Path dir) throws IOException {
        for (Path file : Xml.xmlFiles(dir)) {
            Element root = Xml.parse(file);
            if (root.getTagName().equals("APIProxy") || root.getTagName().equals("SharedFlowBundle")) return root;
        }
        return null;
    }

    private static BundleType detectType(Path dir, Element descriptor) {
        boolean sharedFlow = dir.getFileName().toString().equals("sharedflowbundle")
                || (descriptor != null && descriptor.getTagName().equals("SharedFlowBundle"))
                || Files.isDirectory(dir.resolve("sharedflows"));
        return sharedFlow ? BundleType.SHARED_FLOW : BundleType.API_PROXY;
    }

    private static String fallbackName(Path dir) {
        String folder = dir.getFileName().toString();
        boolean generic = folder.equals("apiproxy") || folder.equals("sharedflowbundle");
        return generic && dir.getParent() != null ? dir.getParent().getFileName().toString() : folder;
    }

    private static List<Element> parseAll(Path dir) throws IOException {
        List<Element> roots = new ArrayList<>();
        for (Path file : Xml.xmlFiles(dir)) roots.add(Xml.parse(file));
        return roots;
    }

    /** Records, for every Step, the endpoint/flow/phase it runs in and its effective condition. */
    private static void collectSteps(Element root, Map<String, List<Attachment>> attachments) {
        String endpointType = root.getTagName();
        String endpoint = Xml.nameOf(root);
        for (Element step : Xml.descendants(root, "Step")) {
            String policy = Xml.text(step, "Name");
            if (policy == null) continue;
            String phase = null;
            String flow = null;
            String flowCondition = null;
            Node node = step.getParentNode();
            while (node instanceof Element element && element != root) {
                switch (element.getTagName()) {
                    case "Request", "Response" -> {
                        if (phase == null) phase = element.getTagName();
                    }
                    case "PreFlow", "PostFlow", "PostClientFlow" -> flow = element.getTagName();
                    case "Flow" -> {
                        flow = "Flow " + Xml.nameOf(element);
                        flowCondition = Xml.text(element, "Condition");
                    }
                    case "FaultRule" -> {
                        flow = "FaultRule " + Xml.nameOf(element);
                        flowCondition = Xml.text(element, "Condition");
                        if (phase == null) phase = "Fault";
                    }
                    case "DefaultFaultRule" -> {
                        flow = "DefaultFaultRule";
                        if (phase == null) phase = "Fault";
                    }
                    default -> {
                    }
                }
                node = element.getParentNode();
            }
            if (flow == null) flow = endpointType;
            String condition = Stream.of(flowCondition, Xml.text(step, "Condition"))
                    .filter(Objects::nonNull)
                    .collect(Collectors.collectingAndThen(Collectors.joining(" AND "), c -> c.isEmpty() ? null : c));
            attachments.computeIfAbsent(policy, k -> new ArrayList<>())
                    .add(new Attachment(endpointType, endpoint, flow, phase, condition));
        }
    }

    private static List<Policy> analyzePolicies(Path dir, Map<String, List<Attachment>> attachments,
                                                BundleContext ctx) throws IOException {
        List<Policy> policies = new ArrayList<>();
        for (Path file : Xml.xmlFiles(dir.resolve("policies"))) {
            Element root = Xml.parse(file);
            String fileName = file.getFileName().toString();
            String name = Objects.requireNonNullElse(Xml.attr(root, "name"),
                    fileName.substring(0, fileName.length() - ".xml".length()));
            boolean enabled = !"false".equalsIgnoreCase(Xml.attr(root, "enabled"));
            List<Attachment> attached = List.copyOf(attachments.getOrDefault(name, List.of()));
            policies.add(new Policy(name, root.getTagName(), Xml.relativePath(dir, file), enabled, attached));
            if (!enabled) {
                ctx.issue(INFO, "Policy " + name + " is disabled: its dependencies are marked inactive");
            }
            if (attached.isEmpty()) {
                ctx.issue(INFO, "Policy " + name + " is not attached to any flow: its dependencies are marked inactive");
            }
            PolicyAnalyzer.analyze(root, new Origin("policy", name, enabled && !attached.isEmpty(), attached), ctx);
        }
        return List.copyOf(policies);
    }

    private static Endpoint targetEndpoint(Element target, BundleType type, Set<String> routedTargets,
                                           BundleContext ctx) {
        String name = Xml.nameOf(target);
        boolean routed = routedTargets.contains(name);
        if (!routed && type == BundleType.API_PROXY) {
            ctx.issue(INFO, "TargetEndpoint " + name + " is not referenced by any RouteRule");
        }
        Origin origin = new Origin("TargetEndpoint", name, routed, List.of());
        Map<String, String> properties = new LinkedHashMap<>();
        Element http = Xml.path(target, "HTTPTargetConnection");
        Element local = Xml.path(target, "LocalTargetConnection");
        Element script = Xml.path(target, "ScriptTarget");
        if (http != null) properties.putAll(Connections.http(http, origin, ctx));
        if (local != null) properties.putAll(Connections.local(local, origin, ctx));
        if (script != null) {
            String resource = Xml.text(script, "ResourceURL");
            put(properties, "script", resource);
            if (resource != null) PolicyAnalyzer.resource(resource, origin, ctx);
        }
        return new Endpoint("TargetEndpoint", name, Collections.unmodifiableMap(properties));
    }

    private static Endpoint proxyEndpoint(Element proxy, Set<String> targetNames, BundleContext ctx) {
        String name = Xml.nameOf(proxy);
        Origin origin = new Origin("ProxyEndpoint", name, true, List.of());
        Map<String, String> properties = new LinkedHashMap<>();

        Element connection = Xml.path(proxy, "HTTPProxyConnection");
        put(properties, "basePath", Xml.text(connection, "BasePath"));
        List<String> virtualHosts = Xml.children(connection, "VirtualHost").stream()
                .map(Xml::text)
                .filter(Objects::nonNull)
                .toList();
        virtualHosts.forEach(vh -> ctx.deps.add(VIRTUAL_HOST, vh, origin.usage(Map.of())));
        if (virtualHosts.isEmpty()) {
            ctx.issue(INFO, "ProxyEndpoint " + name + " declares no VirtualHost:"
                    + " it is exposed on every virtual host of the environment");
            properties.put("virtualHosts", "(all virtual hosts of the environment)");
        } else {
            properties.put("virtualHosts", String.join(", ", virtualHosts));
        }

        List<String> routes = new ArrayList<>();
        for (Element rule : Xml.children(proxy, "RouteRule")) {
            String ruleName = Xml.nameOf(rule);
            String condition = Xml.text(rule, "Condition");
            String target = Xml.text(rule, "TargetEndpoint");
            String url = Xml.text(rule, "URL");
            if (target != null && !targetNames.contains(target)) {
                ctx.issue(ERROR, "RouteRule " + ruleName + " of ProxyEndpoint " + name
                        + " targets unknown TargetEndpoint " + target);
            }
            if (url != null) {
                ctx.deps.add(TARGET_URL, url, new Origin("RouteRule", ruleName, true, List.of()).usage(Map.of()));
            }
            String destination = target != null ? target : url != null ? url : "(no target)";
            routes.add(ruleName + " → " + destination + (condition != null ? "  [" + condition + "]" : ""));
        }
        if (!routes.isEmpty()) properties.put("routeRules", String.join("; ", routes));
        return new Endpoint("ProxyEndpoint", name, Collections.unmodifiableMap(properties));
    }

    private List<SharedFlowLink> resolveSharedFlows(BundleContext ctx, Deque<String> stack) {
        List<SharedFlowLink> links = new ArrayList<>();
        if (!ctx.sharedFlowRefs.isEmpty() && sharedFlows.isEmpty()) {
            ctx.issue(INFO, "Shared flows are not resolved: pass --sharedflows <dir> to analyze them recursively");
        }
        for (String name : ctx.sharedFlowRefs) {
            if (stack.contains(name)) {
                List<String> chain = new ArrayList<>(stack);
                Collections.reverse(chain);
                chain.add(name);
                ctx.issue(WARN, "Circular shared flow call: " + String.join(" → ", chain));
                links.add(new SharedFlowLink(name, SharedFlowLink.Status.CYCLE, null));
                continue;
            }
            if (sharedFlows.isEmpty()) {
                links.add(new SharedFlowLink(name, SharedFlowLink.Status.NOT_SEARCHED, null));
                continue;
            }
            Optional<Path> location = sharedFlows.find(name);
            if (location.isEmpty()) {
                ctx.issue(WARN, "Shared flow " + name + " not found in the --sharedflows directories");
                links.add(new SharedFlowLink(name, SharedFlowLink.Status.NOT_FOUND, null));
                continue;
            }
            try {
                links.add(new SharedFlowLink(name, SharedFlowLink.Status.RESOLVED, analyze(location.get(), stack)));
            } catch (IOException e) {
                ctx.issue(ERROR, "Cannot analyze shared flow " + name + ": " + e.getMessage());
                links.add(new SharedFlowLink(name, SharedFlowLink.Status.ERROR, null));
            }
        }
        return List.copyOf(links);
    }

    private static String origins(Dependency dependency) {
        return dependency.usages().stream()
                .map(Usage::label)
                .distinct()
                .collect(Collectors.joining(", "));
    }
}
