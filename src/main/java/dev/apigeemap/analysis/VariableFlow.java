package dev.apigeemap.analysis;

import dev.apigeemap.analysis.PolicyVariables.Access;
import dev.apigeemap.model.BundleReport;
import dev.apigeemap.model.BundleType;
import dev.apigeemap.model.Policy;
import dev.apigeemap.model.SharedFlowLink;
import org.w3c.dom.Element;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Which step sets each flow variable a step reads, in the order Apigee runs the steps of a bundle.
 *
 * <p>An API proxy runs, for each ProxyEndpoint and each TargetEndpoint its RouteRules reach: the proxy request
 * (PreFlow, conditional Flows, PostFlow), the RouteRules, the target request, the target response, the proxy
 * response and the PostClientFlow. A shared flow runs the steps of its {@code default} flow. Conditional flows and
 * steps are taken as possibly run: a variable is set before a step when some step that may run earlier sets it.
 * Fault rules may run after any step, so they see every variable the other steps set.
 *
 * <p>FlowCallouts bring the variables their shared flow reads and writes, when the shared flow is resolved.
 */
public final class VariableFlow {

    /**
     * First segments of the flow variables Apigee or its policies set ({@code request.header.x},
     * {@code fault.name}...): a step may read them without any step of the bundle setting them.
     */
    private static final Set<String> BUILT_IN = Set.of("request", "response", "message", "proxy",
            "target", "client", "system", "environment", "organization", "apiproxy", "apiproduct", "application",
            "app", "developer", "error", "fault", "is", "servicecallout", "oauthv2", "oauthv1", "apigee", "current",
            "route", "router", "virtualhost", "messageid", "flow", "sharedflow", "loadbalancing", "upstream", "tls",
            "keyvaluemap", "quota", "spikearrest", "javascript", "javacallout", "raisefault", "jsonattack",
            "xmlattack", "regularexpressionprotection", "accesstoken", "messagelogging", "analytics", "mint",
            "sharedflowbundle", "x509", "ssl", "datacapture", "client_id");

    /**
     * First segments of the variables a policy sets under its own name, e.g. {@code verifyapikey.VA-Key.client_id}
     * or {@code lookupcache.LC-Orders.cachehit}: set only once that policy has run.
     */
    private static final Set<String> POLICY_SCOPED = Set.of("verifyapikey", "lookupcache", "populatecache",
            "invalidatecache", "responsecache", "ratelimit", "jwt", "jws", "oauthv2accesstoken", "oauthv2authcode",
            "oauthv2refreshtoken", "oauthv2client", "accessentity", "servicecallout");

    private static final Set<String> MESSAGE_FIELDS = Set.of("content", "header", "headers", "queryparam",
            "queryparams", "querystring", "formparam", "formparams", "formstring", "verb", "uri", "url", "path",
            "version", "transport", "transportid", "grpc", "status", "reason", "event");

    /** Second segments Apigee sets under these first segments; any other one is a variable Apigee never sets. */
    private static final Map<String, Set<String>> FIELDS = Map.ofEntries(
            Map.entry("request", Set.of("content", "header", "headers", "queryparam", "queryparams",
                    "querystring", "formparam", "formparams", "formstring", "verb", "uri", "url", "path", "version",
                    "transport", "transportid", "grpc", "event")),
            Map.entry("response", Set.of("content", "header", "headers", "status", "reason", "transport",
                    "version", "event", "grpc")),
            Map.entry("message", MESSAGE_FIELDS),
            Map.entry("proxy", Set.of("basepath", "pathsuffix", "url", "name", "client")),
            Map.entry("client", Set.of("cn", "country", "email", "host", "ip", "locality", "organization", "port",
                    "received", "scheme", "sent", "ssl", "state")),
            Map.entry("target", Set.of("basepath", "cn", "copy", "country", "email", "expectedcn", "host", "ip",
                    "locality", "name", "organization", "port", "received", "scheme", "sent", "ssl", "state",
                    "url")),
            Map.entry("system", Set.of("time", "timestamp", "uuid", "pod", "region", "interface")),
            Map.entry("environment", Set.of("name", "qualifiedname")),
            Map.entry("organization", Set.of("name")),
            Map.entry("apiproxy", Set.of("name", "revision", "basepath")),
            Map.entry("virtualhost", Set.of("name", "aliases", "ssl_enabled")),
            Map.entry("current", Set.of("flow")),
            Map.entry("messageid", Set.of()));

    private static final Pattern HEADER = Pattern.compile("^(\\w+\\.header\\.)(.+)$");

    /**
     * A policy as attached at one place, or a RouteRule ({@code type} "RouteRule", {@code policy} its name).
     *
     * @param location where it runs, e.g. {@code ProxyEndpoint default › Flow getOrder › Request}
     * @param phase    Request, Response or Fault; null in a shared flow
     * @param reads    variables it reads, its condition included
     * @param opaque   it may use variables this analysis cannot name (see {@link PolicyVariables.Result})
     */
    public record Step(String bundle, String policy, String type, String location, String phase, String condition,
                       List<Access> reads, List<Access> writes, boolean opaque) {

        public boolean fault() {
            return "Fault".equals(phase);
        }

        public String label() {
            return type.equals("RouteRule") ? "RouteRule " + policy : policy;
        }
    }

    public enum Source {
        /** A step that may run earlier sets it. */
        SET,
        /** Apigee or the policy that owns the name sets it. */
        BUILT_IN,
        /** Only steps that run later set it: the step reads null. */
        SET_LATER,
        /** No step names it, but an earlier step may set variables this analysis cannot name. */
        UNKNOWN,
        /** No step sets it. */
        UNSET
    }

    /**
     * @param producers the earlier steps that set it (SET), or the later ones (SET_LATER)
     * @param note      why nothing sets it, when the name looks like an Apigee or policy variable; else null
     */
    public record Read(Step step, Access variable, Source source, List<Step> producers, String note) {
    }

    private final BundleReport bundle;
    private final List<Step> steps;
    private final List<Read> reads;

    private VariableFlow(BundleReport bundle, List<Step> steps, List<Read> reads) {
        this.bundle = bundle;
        this.steps = steps;
        this.reads = reads;
    }

    public static VariableFlow of(BundleReport bundle) throws IOException {
        return of(bundle, new HashMap<>());
    }

    private static VariableFlow of(BundleReport bundle, Map<String, PolicyVariables.Result> summaries)
            throws IOException {
        Map<String, BundleReport> called = new HashMap<>();
        for (SharedFlowLink link : bundle.sharedFlows()) {
            if (link.report() != null) called.put(link.name(), link.report());
        }
        Builder builder = new Builder(bundle, name -> {
            if (summaries.containsKey(name)) return summaries.get(name);
            BundleReport report = called.get(name);
            summaries.put(name, null); // a cycle reads as unresolved
            if (report == null) return null;
            try {
                PolicyVariables.Result summary = of(report, summaries).summary();
                summaries.put(name, summary);
                return summary;
            } catch (IOException e) {
                return null;
            }
        });
        List<List<Step>> pipelines = builder.pipelines();
        return new VariableFlow(bundle, List.copyOf(builder.steps), resolve(pipelines));
    }

    public BundleReport bundle() {
        return bundle;
    }

    /** Every step, in the order they run (a ProxyEndpoint's request, then the targets, then the responses). */
    public List<Step> steps() {
        return steps;
    }

    public List<Read> reads() {
        return reads;
    }

    /** What the policy reads, and which steps set it. */
    public List<Read> readsOf(String policy) {
        return reads.stream().filter(r -> isPolicy(r.step(), policy)).toList();
    }

    /** The reads of other steps that the policy sets. */
    public List<Read> consumersOf(String policy) {
        return reads.stream()
                .filter(r -> r.source() == Source.SET && r.producers().stream().anyMatch(p -> isPolicy(p, policy)))
                .toList();
    }

    public List<Read> reads(Source source) {
        return reads.stream().filter(r -> r.source() == source).toList();
    }

    /**
     * True when Apigee sets the variable whatever the steps of the bundle: its first segment is Apigee's and, where
     * the fields Apigee sets there are known, so is its second ({@code request} alone is the message). A policy's
     * own variable ({@code verifyapikey.VA-Key.client_id}) is not built-in: the step of that policy sets it.
     */
    public static boolean builtIn(String variable) {
        String[] parts = variable.toLowerCase(Locale.ROOT).split("\\.");
        if (policyScoped(variable)) return false;
        Set<String> fields = FIELDS.get(parts[0]);
        if (fields != null) return parts.length == 1 || fields.contains(parts[1]);
        return BUILT_IN.contains(parts[0]);
    }

    /** {@code <policy type>.<policy name>.<field>}: a variable the named policy sets when it runs. */
    private static boolean policyScoped(String variable) {
        String[] parts = variable.split("\\.");
        return parts.length >= 3 && POLICY_SCOPED.contains(parts[0].toLowerCase(Locale.ROOT))
                && !(parts[0].equalsIgnoreCase("servicecallout") && parts[1].equals("requesturl"));
    }

    /** Why nothing sets a variable whose name looks like Apigee's or a policy's; null when it does not. */
    private static String note(String variable, Set<String> policies) {
        String[] parts = variable.split("\\.");
        if (policyScoped(variable)) {
            return policies.contains(parts[1]) ? null : "no policy named " + parts[1] + " runs in this bundle";
        }
        String first = parts[0].toLowerCase(Locale.ROOT);
        Set<String> fields = FIELDS.get(first);
        if (fields == null || builtIn(variable)) return null;
        String field = parts[1].toLowerCase(Locale.ROOT);
        String closest = fields.stream().filter(f -> distance(f, field) <= 2)
                .min((a, b) -> distance(a, field) - distance(b, field)).orElse(null);
        return "Apigee sets no " + first + "." + field + ".* variable"
                + (closest == null ? "" : ": " + first + "." + closest + "?");
    }

    /** Levenshtein distance, to suggest the field a misspelt name meant. */
    private static int distance(String a, String b) {
        int[] row = new int[b.length() + 1];
        for (int j = 0; j <= b.length(); j++) row[j] = j;
        for (int i = 1; i <= a.length(); i++) {
            int diagonal = row[0];
            row[0] = i;
            for (int j = 1; j <= b.length(); j++) {
                int above = row[j];
                row[j] = Math.min(Math.min(row[j] + 1, row[j - 1] + 1),
                        diagonal + (a.charAt(i - 1) == b.charAt(j - 1) ? 0 : 1));
                diagonal = above;
            }
        }
        return row[b.length()];
    }

    /** True when writing {@code write} sets {@code read}: same name, a part of it, or a family ({@code x.*}). */
    public static boolean sets(String write, String read) {
        String w = normalize(write);
        String r = normalize(read);
        if (w.endsWith(".*")) {
            String prefix = w.substring(0, w.length() - 2);
            return r.equals(prefix) || r.startsWith(prefix + ".");
        }
        return r.equals(w) || r.startsWith(w + ".");
    }

    /** Header names are case-insensitive. */
    private static String normalize(String name) {
        Matcher header = HEADER.matcher(name);
        return header.matches() ? header.group(1) + header.group(2).toLowerCase(Locale.ROOT) : name;
    }

    private static boolean isPolicy(Step step, String policy) {
        return !step.type().equals("RouteRule") && step.policy().equals(policy);
    }

    /** What the bundle, as a shared flow, reads from its caller and writes for it. */
    private PolicyVariables.Result summary() {
        Map<String, Access> in = new LinkedHashMap<>();
        for (Read read : reads) {
            if (read.source() != Source.SET) {
                in.putIfAbsent(read.variable().name(), new Access(read.variable().name(),
                        read.step().label() + " (" + read.variable().via() + ")", read.variable().optional()));
            }
        }
        Map<String, Access> out = new LinkedHashMap<>();
        for (Step step : steps) {
            for (Access write : step.writes()) {
                out.putIfAbsent(write.name(), new Access(write.name(), step.label() + " (" + write.via() + ")"));
            }
        }
        boolean opaque = steps.stream().anyMatch(Step::opaque);
        return new PolicyVariables.Result(List.copyOf(in.values()), List.copyOf(out.values()), opaque);
    }

    /** For each read of each step, the steps that set the variable before it, in any pipeline it is part of. */
    private static List<Read> resolve(List<List<Step>> pipelines) {
        record Key(Step step, Access variable) {
        }
        Map<Key, Set<Step>> before = new LinkedHashMap<>();
        Map<Key, Set<Step>> after = new HashMap<>();
        Map<Key, Boolean> opaque = new HashMap<>();
        Set<String> policies = pipelines.stream().flatMap(List::stream).filter(s -> !s.type().equals("RouteRule"))
                .map(Step::policy).collect(Collectors.toSet());
        for (List<Step> pipeline : pipelines) {
            for (int i = 0; i < pipeline.size(); i++) {
                Step step = pipeline.get(i);
                for (Access read : step.reads()) {
                    Key key = new Key(step, read);
                    Set<Step> earlier = before.computeIfAbsent(key, k -> new LinkedHashSet<>());
                    Set<Step> later = after.computeIfAbsent(key, k -> new LinkedHashSet<>());
                    for (int j = 0; j < pipeline.size(); j++) {
                        Step other = pipeline.get(j);
                        if (other == step || (other.fault() && !step.fault())) continue;
                        boolean runsBefore = j < i || step.fault();
                        if (runsBefore && other.opaque()) opaque.put(key, true);
                        if (other.writes().stream().noneMatch(w -> sets(w.name(), read.name()))) continue;
                        (runsBefore ? earlier : later).add(other);
                    }
                }
            }
        }
        List<Read> reads = new ArrayList<>();
        for (Map.Entry<Key, Set<Step>> entry : before.entrySet()) {
            Key key = entry.getKey();
            Set<Step> later = after.get(key);
            Source source;
            List<Step> producers = List.of();
            String note = null;
            if (!entry.getValue().isEmpty()) {
                source = Source.SET;
                producers = List.copyOf(entry.getValue());
            } else if (builtIn(key.variable().name())) {
                source = Source.BUILT_IN;
            } else if (!later.isEmpty()) {
                source = Source.SET_LATER;
                producers = List.copyOf(later);
            } else if (key.variable().optional()) {
                continue; // nothing sets it, and the step does without it
            } else {
                source = opaque.getOrDefault(key, false) ? Source.UNKNOWN : Source.UNSET;
                note = note(key.variable().name(), policies);
            }
            reads.add(new Read(key.step(), key.variable(), source, producers, note));
        }
        return List.copyOf(reads);
    }

    /** Reads the endpoints of the bundle and builds its steps, in the order they run. */
    private static final class Builder {

        private final BundleReport bundle;
        private final Path dir;
        private final Function<String, PolicyVariables.Result> sharedFlows;
        private final Map<String, Element> policies = new HashMap<>();
        private final List<Step> steps = new ArrayList<>();

        Builder(BundleReport bundle, Function<String, PolicyVariables.Result> sharedFlows)
                throws IOException {
            this.bundle = bundle;
            this.dir = Path.of(bundle.path());
            this.sharedFlows = sharedFlows;
            for (Policy policy : bundle.policies()) {
                if (policy.enabled()) policies.put(policy.name(), Xml.parse(dir.resolve(policy.file())));
            }
        }

        List<List<Step>> pipelines() throws IOException {
            if (bundle.type() == BundleType.SHARED_FLOW) {
                List<Path> files = Xml.xmlFiles(dir.resolve("sharedflows"));
                List<Path> entry = files.stream().filter(f -> f.getFileName().toString().equals("default.xml")).toList();
                List<List<Step>> pipelines = new ArrayList<>();
                for (Path file : entry.isEmpty() ? files : entry) {
                    Element flow = Xml.parse(file);
                    pipelines.add(steps(Xml.children(flow, "Step"), "SharedFlow " + Xml.nameOf(flow), null, null));
                }
                return pipelines;
            }

            Map<String, Element> targets = new LinkedHashMap<>();
            for (Path file : Xml.xmlFiles(dir.resolve("targets"))) {
                Element target = Xml.parse(file);
                targets.put(Xml.nameOf(target), target);
            }
            List<Element> proxies = new ArrayList<>();
            for (Path file : Xml.xmlFiles(dir.resolve("proxies"))) proxies.add(Xml.parse(file));

            // Steps are built in the order they run, so that steps() reads top to bottom
            Map<Element, List<Step>> proxyRequests = new LinkedHashMap<>();
            for (Element proxy : proxies) {
                List<Step> request = new ArrayList<>(phase(proxy, "Request"));
                for (Element rule : Xml.children(proxy, "RouteRule")) {
                    String condition = Xml.text(rule, "Condition");
                    if (condition == null) continue;
                    request.add(add(new Step(bundle.name(), Xml.nameOf(rule), "RouteRule",
                            endpoint(proxy) + " › RouteRule " + Xml.nameOf(rule), "Request", condition,
                            PolicyVariables.condition(condition), List.of(), false)));
                }
                proxyRequests.put(proxy, request);
            }
            Map<String, List<Step>> targetRequests = new LinkedHashMap<>();
            Map<String, List<Step>> targetResponses = new LinkedHashMap<>();
            for (Map.Entry<String, Element> target : targets.entrySet()) {
                targetRequests.put(target.getKey(), phase(target.getValue(), "Request"));
            }
            for (Map.Entry<String, Element> target : targets.entrySet()) {
                targetResponses.put(target.getKey(), phase(target.getValue(), "Response"));
            }
            Map<Element, List<Step>> proxyResponses = new LinkedHashMap<>();
            for (Element proxy : proxies) {
                List<Step> response = new ArrayList<>(phase(proxy, "Response"));
                response.addAll(steps(Xml.children(Xml.path(proxy, "PostClientFlow", "Response"), "Step"),
                        endpoint(proxy) + " › PostClientFlow › Response", "Response", null));
                proxyResponses.put(proxy, response);
            }
            Map<Element, List<Step>> faults = new LinkedHashMap<>();
            for (Element endpoint : Stream.concat(proxies.stream(), targets.values().stream()).toList()) {
                faults.put(endpoint, faults(endpoint));
            }

            List<List<Step>> pipelines = new ArrayList<>();
            for (Element proxy : proxies) {
                Set<String> routed = Xml.children(proxy, "RouteRule").stream()
                        .map(rule -> Xml.text(rule, "TargetEndpoint"))
                        .filter(targets::containsKey)
                        .collect(Collectors.toCollection(LinkedHashSet::new));
                List<String> chosen = routed.isEmpty() ? Collections.singletonList(null) : List.copyOf(routed);
                for (String target : chosen) {
                    List<Step> pipeline = new ArrayList<>(proxyRequests.get(proxy));
                    if (target != null) pipeline.addAll(targetRequests.get(target));
                    if (target != null) pipeline.addAll(targetResponses.get(target));
                    pipeline.addAll(proxyResponses.get(proxy));
                    pipeline.addAll(faults.get(proxy));
                    if (target != null) pipeline.addAll(faults.get(targets.get(target)));
                    pipelines.add(pipeline);
                }
            }
            return pipelines;
        }

        /** PreFlow, conditional Flows and PostFlow of one phase of an endpoint. */
        private List<Step> phase(Element endpoint, String phase) throws IOException {
            String name = endpoint(endpoint);
            List<Step> result = new ArrayList<>(steps(Xml.children(Xml.path(endpoint, "PreFlow", phase), "Step"),
                    name + " › PreFlow › " + phase, phase, null));
            for (Element flow : Xml.children(Xml.path(endpoint, "Flows"), "Flow")) {
                result.addAll(steps(Xml.children(Xml.path(flow, phase), "Step"),
                        name + " › Flow " + Xml.nameOf(flow) + " › " + phase, phase, Xml.text(flow, "Condition")));
            }
            result.addAll(steps(Xml.children(Xml.path(endpoint, "PostFlow", phase), "Step"),
                    name + " › PostFlow › " + phase, phase, null));
            return result;
        }

        private List<Step> faults(Element endpoint) throws IOException {
            String name = endpoint(endpoint);
            List<Step> result = new ArrayList<>();
            for (Element rule : Xml.children(Xml.path(endpoint, "FaultRules"), "FaultRule")) {
                result.addAll(steps(Xml.children(rule, "Step"), name + " › FaultRule " + Xml.nameOf(rule), "Fault",
                        Xml.text(rule, "Condition")));
            }
            Element defaultRule = Xml.path(endpoint, "DefaultFaultRule");
            result.addAll(steps(Xml.children(defaultRule, "Step"), name + " › DefaultFaultRule", "Fault",
                    Xml.text(defaultRule, "Condition")));
            return result;
        }

        private List<Step> steps(List<Element> stepElements, String location, String phase, String flowCondition)
                throws IOException {
            List<Step> result = new ArrayList<>();
            for (Element step : stepElements) {
                String name = Xml.text(step, "Name");
                Element policy = name == null ? null : policies.get(name);
                if (policy == null) continue; // disabled, or missing (reported by the analysis)
                String condition = Stream.of(flowCondition, Xml.text(step, "Condition"))
                        .filter(Objects::nonNull)
                        .collect(Collectors.collectingAndThen(Collectors.joining(" AND "),
                                c -> c.isEmpty() ? null : c));
                PolicyVariables.Result variables = PolicyVariables.of(dir, policy, sharedFlows);
                List<Access> reads = new ArrayList<>(PolicyVariables.condition(condition));
                reads.addAll(variables.reads());
                result.add(add(new Step(bundle.name(), name, policy.getTagName(), location, phase, condition,
                        message(dedupe(reads), phase), message(variables.writes(), phase), variables.opaque())));
            }
            return result;
        }

        private Step add(Step step) {
            steps.add(step);
            return step;
        }

        private static String endpoint(Element endpoint) {
            return endpoint.getTagName() + " " + Xml.nameOf(endpoint);
        }

        /** {@code message} is the request in the request phase, the response in the response and fault phases. */
        private static List<Access> message(List<Access> accesses, String phase) {
            if (phase == null) return accesses;
            String message = phase.equals("Request") ? "request" : "response";
            return dedupe(accesses.stream()
                    .map(a -> a.name().equals("message") || a.name().startsWith("message.")
                            ? new Access(message + a.name().substring("message".length()), a.via(), a.optional())
                            : a)
                    .toList());
        }

        private static List<Access> dedupe(List<Access> accesses) {
            Map<String, Access> unique = new LinkedHashMap<>();
            accesses.forEach(a -> unique.putIfAbsent(a.name(), a));
            return List.copyOf(unique.values());
        }
    }
}
