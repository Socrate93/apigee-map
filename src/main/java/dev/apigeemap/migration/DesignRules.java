package dev.apigeemap.migration;

import dev.apigeemap.analysis.PolicyVariables;
import dev.apigeemap.analysis.ScriptAnalyzer;
import dev.apigeemap.analysis.VariableFlow;
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
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
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

    /** A sequence of steps: a Request/Response phase of an endpoint flow, or the body of a shared flow. */
    private record Phase(String label, String file, List<String> steps) {
    }

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
                new Rule("DES-08", DESIGN, "Policies that differ by one or two values",
                        DesignRules::nearDuplicatePolicies),
                new Rule("DES-09", DESIGN, "Step sequences repeated in several flows", DesignRules::repeatedSequences),
                new Rule("DES-10", DESIGN, "Duplicated scripts", DesignRules::duplicatedScripts),
                new Rule("DES-11", DESIGN, "Steps that repeat an available shared flow",
                        DesignRules::reimplementedSharedFlows),
                new Rule("DES-12", DESIGN, "Variables read by scripts but set nowhere", DesignRules::unsetVariables),
                new Rule("DES-13", DESIGN, "Variables read before the step that sets them",
                        DesignRules::variablesSetLater),
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
                        "Move the host and port to a TargetServer and keep the variable part in <Path>.",
                        ctx.onFile(file));
                continue;
            }
            boolean https = uri.getScheme().equalsIgnoreCase("https");
            int port = uri.getPort() != -1 ? uri.getPort() : https ? 443 : 80;
            String host = uri.getHost();
            String name = "ts-" + host.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "-")
                    + (uri.getPort() != -1 ? "-" + port : "");

            if (!ctx.isFalsePositive(location)) {
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
            }
            String ssl = Xml.path(connection, "SSLInfo") != null
                    ? " Move the SSLInfo settings to the target server definition." : "";
            ctx.fixed(WARN, location, "Hardcoded backend URL " + url,
                    "Replaced by TargetServer " + name + ": create it in each environment with that environment's"
                            + " backend host (targetservers.json)." + ssl, ctx.onFile(file));
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
                    "Remove the policy and its steps, or enable it if it is still needed.", ctx.on(policy));
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
                            "Group them in a conditional Flow (or a shared flow) with that condition.",
                            MigrationContext.and(ctx.onFile(file), ctx.onPolicies(ctx.report.name(), steps)));
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
                            + " unexpected and backend errors do not reach clients as-is.", ctx.onFile(file));
        }
    }

    /**
     * Same policy type and content in several places of the migration (root bundle only, to report once).
     * Names and DisplayNames are ignored.
     */
    private static void duplicatePolicies(MigrationContext ctx) throws IOException {
        if (!ctx.isRoot()) return;
        Map<PolicyShape, List<String>> byShape = new LinkedHashMap<>();
        shapes(ctx).forEach((label, shape) -> byShape.computeIfAbsent(shape, k -> new ArrayList<>()).add(label));
        for (List<String> copies : byShape.values()) {
            if (copies.size() < 2) continue;
            ctx.manual(INFO, names(copies), "Identical policies in " + copies.size() + " places",
                    "Keep a single copy (in a shared flow if several bundles need it) so they cannot drift apart.",
                    policies(ctx, copies));
        }
    }

    /** Policies by "bundle/policy" label, as {@link #shapes} names them. */
    private static List<Finding.Subject> policies(MigrationContext ctx, List<String> labels) {
        List<Finding.Subject> subjects = new ArrayList<>();
        for (String label : labels) {
            int slash = label.indexOf('/');
            subjects.addAll(ctx.onPolicies(label.substring(0, slash), List.of(label.substring(slash + 1))));
        }
        return subjects;
    }

    /** Active policies of the bundle and its shared flows (FlowCallouts aside), as "bundle/policy" → shape. */
    private static Map<String, PolicyShape> shapes(MigrationContext ctx) throws IOException {
        Map<String, PolicyShape> shapes = new LinkedHashMap<>();
        for (BundleReport bundle : ctx.withSharedFlows()) {
            for (Policy policy : bundle.policies()) {
                if (!policy.active() || policy.type().equals("FlowCallout")) continue;
                shapes.put(bundle.name() + "/" + policy.name(),
                        PolicyShape.of(Xml.parse(Path.of(bundle.path()).resolve(policy.file()))));
            }
        }
        return shapes;
    }

    /**
     * Policies with the same structure that differ in one or two values (at most a quarter of them), e.g. the
     * same AssignMessage with another header value: one policy reading the value from a variable is enough.
     */
    private static void nearDuplicatePolicies(MigrationContext ctx) throws IOException {
        if (!ctx.isRoot()) return;
        List<Map.Entry<String, PolicyShape>> shapes = new ArrayList<>(shapes(ctx).entrySet());
        int[] group = new int[shapes.size()];
        for (int i = 0; i < group.length; i++) group[i] = i;
        for (int i = 0; i < shapes.size(); i++) {
            PolicyShape a = shapes.get(i).getValue();
            for (int j = i + 1; j < shapes.size(); j++) {
                List<String> differences = a.differences(shapes.get(j).getValue());
                if (differences == null || differences.isEmpty() || differences.size() > 2) continue;
                if (a.values().size() < 4 || differences.size() * 4 > a.values().size()) continue;
                group[find(group, j)] = find(group, i);
            }
        }
        Map<Integer, List<Map.Entry<String, PolicyShape>>> groups = new LinkedHashMap<>();
        for (int i = 0; i < shapes.size(); i++) {
            groups.computeIfAbsent(find(group, i), k -> new ArrayList<>()).add(shapes.get(i));
        }
        for (List<Map.Entry<String, PolicyShape>> members : groups.values()) {
            if (members.size() < 2) continue;
            PolicyShape first = members.get(0).getValue();
            List<String> differences = new ArrayList<>();
            for (String path : first.values().keySet()) {
                Set<String> values = members.stream().map(m -> m.getValue().values().get(path))
                        .collect(Collectors.toCollection(LinkedHashSet::new));
                if (values.size() < 2) continue;
                differences.add(path.substring(first.type().length()).replaceFirst("^/", "") + " ("
                        + String.join(" / ", values) + ")");
            }
            List<String> labels = members.stream().map(Map.Entry::getKey).toList();
            ctx.manual(INFO, names(labels), first.type() + " policies that differ only in " + names(differences),
                    "Merge them into one policy that reads the differing value from a flow variable (set earlier in"
                            + " the flow, or read from a KVM).", policies(ctx, labels));
        }
    }

    private static int find(int[] group, int i) {
        while (group[i] != i) i = group[i] = group[group[i]];
        return i;
    }

    /** Request/Response phases of the endpoints and the body of shared flows, with their step names. */
    private static List<Phase> phases(String file, Element root) {
        String owner = root.getTagName() + " " + Xml.nameOf(root);
        List<Element> elements = new ArrayList<>(Xml.descendants(root, "Request"));
        elements.addAll(Xml.descendants(root, "Response"));
        if (root.getTagName().equals("SharedFlow")) elements.add(root);
        List<Phase> phases = new ArrayList<>();
        for (Element element : elements) {
            List<String> steps = Xml.children(element, "Step").stream()
                    .map(step -> Xml.text(step, "Name")).filter(name -> name != null).toList();
            if (steps.isEmpty()) continue;
            String label = owner;
            if (element != root && element.getParentNode() instanceof Element flow) {
                label += " › " + (flow.getTagName().equals("Flow") ? Xml.nameOf(flow) : flow.getTagName())
                        + " › " + element.getTagName();
            }
            phases.add(new Phase(label, file, steps));
        }
        return phases;
    }

    private static List<Phase> phases(MigrationContext ctx) throws IOException {
        List<Phase> phases = new ArrayList<>();
        for (String file : ctx.endpointFiles()) phases.addAll(phases(file, ctx.workspace.root(file)));
        return phases;
    }

    /**
     * The same run of two or more steps in several phases of the bundle. Only the longest runs are reported:
     * a run inside a longer one found in the same places adds nothing.
     */
    private static void repeatedSequences(MigrationContext ctx) throws IOException {
        Map<List<String>, Set<String>> places = new LinkedHashMap<>();
        Map<String, String> files = new LinkedHashMap<>();
        for (Phase phase : phases(ctx)) {
            files.put(phase.label(), phase.file());
            List<String> steps = phase.steps();
            for (int length = 2; length <= steps.size(); length++) {
                for (int i = 0; i + length <= steps.size(); i++) {
                    places.computeIfAbsent(List.copyOf(steps.subList(i, i + length)), k -> new LinkedHashSet<>())
                            .add(phase.label());
                }
            }
        }
        places.values().removeIf(where -> where.size() < 2);
        for (Map.Entry<List<String>, Set<String>> run : places.entrySet()) {
            List<String> steps = run.getKey();
            boolean covered = places.entrySet().stream().anyMatch(longer -> longer.getKey().size() > steps.size()
                    && Collections.indexOfSubList(longer.getKey(), steps) >= 0
                    && longer.getValue().equals(run.getValue()));
            if (covered) continue;
            ctx.manual(INFO, ctx.report.name(), "Steps " + String.join(" › ", steps) + " repeated in "
                            + run.getValue().size() + " places: " + String.join("; ", run.getValue()),
                    "Put them once in a shared flow called with a FlowCallout, or in the PreFlow/PostFlow if they"
                            + " run on every request.",
                    MigrationContext.and(ctx.onPolicies(ctx.report.name(), steps),
                            ctx.onFiles(run.getValue().stream().map(files::get).toList())));
        }
    }

    /**
     * Scripts of the proxy and its shared flows that are copies (same code once comments and whitespace are
     * removed) or near copies (80% of their code in common). Scripts under 20 tokens are left out.
     */
    private static void duplicatedScripts(MigrationContext ctx) throws IOException {
        if (!ctx.isRoot()) return;
        Map<String, List<String>> tokens = new LinkedHashMap<>();
        Map<String, Scripts.Script> scripts = new LinkedHashMap<>();
        for (BundleReport bundle : ctx.withSharedFlows()) {
            for (Scripts.Script script : Scripts.of(bundle)) {
                List<String> code = Scripts.tokens(script.source(), script.python());
                if (code.size() >= 20 && tokens.putIfAbsent(script.label(), code) == null) {
                    scripts.put(script.label(), script);
                }
            }
        }
        Map<List<String>, List<String>> copies = new LinkedHashMap<>();
        tokens.forEach((label, code) -> copies.computeIfAbsent(code, k -> new ArrayList<>()).add(label));
        for (List<String> labels : copies.values()) {
            if (labels.size() < 2) continue;
            ctx.manual(INFO, names(labels), "Identical scripts in " + labels.size() + " places",
                    "Keep one copy: one policy (in a shared flow if several bundles need it) or one resource.",
                    scripts(ctx, labels.stream().map(scripts::get).toList()));
        }
        List<List<String>> distinct = new ArrayList<>(copies.keySet());
        for (int i = 0; i < distinct.size(); i++) {
            for (int j = i + 1; j < distinct.size(); j++) {
                double similarity = Scripts.similarity(distinct.get(i), distinct.get(j));
                if (similarity < 0.8) continue;
                String a = copies.get(distinct.get(i)).get(0);
                String b = copies.get(distinct.get(j)).get(0);
                ctx.manual(INFO, a + ", " + b,
                        "Scripts with " + Math.round(similarity * 100) + "% of their code in common",
                        "Move the common code to one script (an IncludeURL library), and pass what differs through"
                                + " flow variables.", scripts(ctx, List.of(scripts.get(a), scripts.get(b))));
            }
        }
    }

    private static List<Finding.Subject> scripts(MigrationContext ctx, List<Scripts.Script> scripts) {
        List<Finding.Subject> subjects = new ArrayList<>();
        for (Scripts.Script script : scripts) subjects.addAll(ctx.on(script));
        return subjects;
    }

    /**
     * Runs of steps doing exactly what an available shared flow does (same policies, names aside), whether the
     * bundle calls that shared flow elsewhere or not.
     */
    private static void reimplementedSharedFlows(MigrationContext ctx) throws IOException {
        if (ctx.catalog.isEmpty()) return;
        Map<String, PolicyShape> mine = new LinkedHashMap<>();
        for (Policy policy : ctx.policies()) mine.put(policy.name(), PolicyShape.of(ctx.xml(policy)));
        List<Phase> phases = phases(ctx);
        Path self = Path.of(ctx.report.path()).toAbsolutePath().normalize();
        for (Map.Entry<Path, String> sharedFlow : ctx.catalog.entrySet()) {
            if (sharedFlow.getKey().equals(self)) continue;
            for (List<PolicyShape> body : sharedFlowBodies(sharedFlow.getKey())) {
                if (body.size() < 2) continue;
                for (Phase phase : phases) {
                    List<PolicyShape> steps = phase.steps().stream().map(mine::get).toList();
                    int start = Collections.indexOfSubList(steps, body);
                    if (start < 0) continue;
                    List<String> names = phase.steps().subList(start, start + body.size());
                    ctx.manual(INFO, phase.label(), "Steps " + String.join(" › ", names)
                                    + " do what shared flow " + sharedFlow.getValue() + " does",
                            "Replace them with a FlowCallout to " + sharedFlow.getValue()
                                    + ", so fixes to the shared flow apply here too.",
                            MigrationContext.and(ctx.onFile(phase.file()), ctx.onPolicies(ctx.report.name(), names)));
                }
            }
        }
    }

    /** Policies run by each flow of a sharedflowbundle/ folder; flows calling a missing policy are left out. */
    private static List<List<PolicyShape>> sharedFlowBodies(Path dir) throws IOException {
        Map<String, PolicyShape> policies = new LinkedHashMap<>();
        for (Path file : Xml.xmlFiles(dir.resolve("policies"))) {
            Element root = Xml.parse(file);
            policies.put(Xml.attr(root, "name"), PolicyShape.of(root));
        }
        List<List<PolicyShape>> bodies = new ArrayList<>();
        for (Path file : Xml.xmlFiles(dir.resolve("sharedflows"))) {
            List<PolicyShape> body = new ArrayList<>();
            for (Element step : Xml.children(Xml.parse(file), "Step")) body.add(policies.get(Xml.text(step, "Name")));
            if (!body.contains(null)) bodies.add(body);
        }
        return bodies;
    }

    /**
     * Variables scripts read (context.getVariable, flow.getVariable) that no policy or script of the proxy and its
     * shared flows sets, and that are not Apigee or policy variables: often a typo or a removed policy.
     */
    private static void unsetVariables(MigrationContext ctx) throws IOException {
        if (!ctx.isRoot()) return;
        Set<String> written = new HashSet<>();
        boolean dynamic = false;
        boolean java = false;
        Map<Scripts.Script, List<String>> reads = new LinkedHashMap<>();
        for (BundleReport bundle : ctx.withSharedFlows()) {
            for (Scripts.Script script : Scripts.of(bundle)) {
                ScriptAnalyzer.Facts facts = script.facts();
                if (facts.error() != null) continue;
                written.addAll(facts.writes());
                dynamic |= facts.dynamicWrites();
                reads.put(script, facts.reads());
            }
            for (Policy policy : bundle.policies()) {
                if (!policy.active()) continue;
                java |= policy.type().equals("JavaCallout");
                Path dir = Path.of(bundle.path());
                PolicyVariables.of(dir, Xml.parse(dir.resolve(policy.file())), name -> null).writes()
                        .forEach(w -> written.add(w.name()));
            }
        }
        String caveat = (dynamic ? " Some scripts set variables with computed names, which this check cannot"
                + " follow." : "") + (java ? " Java callouts are not inspected." : "");
        for (Map.Entry<Scripts.Script, List<String>> entry : reads.entrySet()) {
            Set<String> unset = new TreeSet<>();
            for (String variable : entry.getValue()) {
                boolean set = written.stream().anyMatch(w -> VariableFlow.sets(w, variable));
                if (!set && !VariableFlow.builtIn(variable)) unset.add(variable);
            }
            if (unset.isEmpty()) continue;
            Scripts.Script script = entry.getKey();
            ctx.manual(INFO, script.policy() + " (" + script.label() + ")", "Reads " + names(unset)
                            + ", which no policy of the proxy or its shared flows sets",
                    "Check the names (a typo reads as null) and which policy should set them." + caveat,
                    ctx.on(script));
        }
    }

    /**
     * Variables a step reads that only steps running after it set, in the order Apigee runs the bundle: the step
     * reads null (or the value of the previous request when the variable is cached elsewhere).
     */
    private static void variablesSetLater(MigrationContext ctx) throws IOException {
        VariableFlow flow = VariableFlow.of(ctx.report);
        Map<VariableFlow.Step, List<VariableFlow.Read>> byStep = new LinkedHashMap<>();
        for (VariableFlow.Read read : flow.reads(VariableFlow.Source.SET_LATER)) {
            byStep.computeIfAbsent(read.step(), s -> new ArrayList<>()).add(read);
        }
        for (Map.Entry<VariableFlow.Step, List<VariableFlow.Read>> entry : byStep.entrySet()) {
            VariableFlow.Step step = entry.getKey();
            String details = entry.getValue().stream()
                    .map(r -> r.variable().name() + " (set by " + r.producers().stream()
                            .map(VariableFlow.Step::label).distinct().collect(Collectors.joining(", ")) + ")")
                    .collect(Collectors.joining(", "));
            ctx.manual(WARN, step.label() + " (" + step.location() + ")", "Reads " + details
                            + " before the step that sets it runs",
                    "Move the step that sets the variable before this one, or this step after it: until then the"
                            + " variable reads as null.", subjects(ctx, step));
        }
    }

    /** The policy of a step, or for a RouteRule the endpoint it belongs to. */
    private static List<Finding.Subject> subjects(MigrationContext ctx, VariableFlow.Step step) throws IOException {
        if (!step.type().equals("RouteRule")) return ctx.onPolicies(step.bundle(), List.of(step.policy()));
        String[] endpoint = step.location().split(" › ")[0].split(" ", 2);
        String file = endpoint.length == 2 ? ctx.endpointFile(endpoint[0], endpoint[1]) : null;
        return file == null ? MigrationContext.wholeBundle() : ctx.onFile(file);
    }

    static Map<String, List<String>> defaultPrefixes() {
        return PREFIXES;
    }

    private static void naming(MigrationContext ctx) {
        Map<String, List<String>> prefixes = new LinkedHashMap<>(PREFIXES);
        prefixes.putAll(ctx.options.namingPrefixes());
        prefixes.values().removeIf(List::isEmpty);
        List<Policy> offenders = ctx.policies().stream()
                .filter(p -> prefixes.containsKey(p.type()))
                .filter(p -> prefixes.get(p.type()).stream().noneMatch(prefix -> hasPrefix(p.name(), prefix)))
                .toList();
        if (offenders.isEmpty()) return;
        List<String> labels = offenders.stream()
                .map(p -> p.name() + " (" + p.type() + " → " + prefixes.get(p.type()).get(0) + "-)")
                .collect(Collectors.toList());
        ctx.manual(INFO, ctx.report.name(), "Policy names without the usual type prefix: " + names(labels),
                "Rename them (policy file, name attribute and Step names) so the type reads from the flow.",
                ctx.on(offenders.toArray(Policy[]::new)));
    }

    private static boolean hasPrefix(String name, String prefix) {
        return name.length() > prefix.length() && name.regionMatches(true, 0, prefix, 0, prefix.length())
                && (name.charAt(prefix.length()) == '-' || name.charAt(prefix.length()) == '_');
    }

    private static void unattachedPolicies(MigrationContext ctx) throws IOException {
        for (Policy policy : ctx.policies()) {
            if (policy.attached()) continue;
            if (!ctx.isFalsePositive(policy.name())) {
                ctx.workspace.delete(policy.file(), "removed (not attached to any flow)");
                removeFromDescriptor(ctx, policy.name());
            }
            ctx.fixed(INFO, policy.name(), policy.type() + " is not attached to any flow", "Removed from the bundle.",
                    ctx.on(policy));
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
