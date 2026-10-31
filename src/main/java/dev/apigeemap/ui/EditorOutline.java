package dev.apigeemap.ui;

import dev.apigeemap.analysis.SourceMap;
import dev.apigeemap.analysis.VariableFlow;
import dev.apigeemap.analysis.Xml;
import dev.apigeemap.model.BundleReport;
import dev.apigeemap.model.BundleType;
import dev.apigeemap.model.Policy;
import org.w3c.dom.Element;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The flows of a bundle in the order they run, its policies and its variables, as the Editor page shows them next to
 * the text.
 */
record EditorOutline(List<Lane> lanes, List<PolicyEntry> policies, List<Variable> variables) {

    /** A variable a step reads that nothing sets for it. */
    record Unset(String name, String why) {
    }

    /** A step of a flow; {@code file} is null when no policy has that name. */
    record Step(String policy, String type, String file, boolean enabled, String condition, SourceMap.Span span,
                List<Unset> unset) {
    }

    /**
     * A list of steps: a PreFlow phase, a conditional Flow, a FaultRule, or a RouteRule, which has none.
     *
     * @param element the tag holding the steps, where a step can be added; null for a RouteRule
     * @param span    where {@code element} starts in {@code file}, or {@code parent}
     * @param parent  the tag to create {@code element} in when the endpoint does not have it yet; else null
     */
    record Segment(String label, String condition, String file, String element, SourceMap.Span span,
                   List<Step> steps, String parent) {
    }

    record Lane(String title, List<Segment> segments) {
    }

    /** @param order position of its first step in the order steps run; -1 when it is not attached */
    record PolicyEntry(String name, String type, String file, boolean enabled, int order, List<String> attachments) {
    }

    /** A step setting or reading a variable. {@code source} is how a read gets its value; null for a write. */
    record Use(String policy, String file, String location, int order, String source, String note) {
    }

    record Variable(String name, List<Use> setBy, List<Use> readBy) {
    }

    /** The flow as lines of text: each list of steps, in the order they run. */
    String text() {
        StringBuilder out = new StringBuilder();
        for (Lane lane : lanes) {
            for (Segment segment : lane.segments()) {
                out.append(lane.title()).append(" > ").append(segment.label());
                if (segment.condition() != null) out.append(" [").append(segment.condition()).append(']');
                out.append(": ");
                out.append(String.join(", ", segment.steps().stream().map(Step::policy).toList())).append('\n');
            }
        }
        return out.toString();
    }

    static EditorOutline of(BundleReport report) throws IOException {
        VariableFlow flow = VariableFlow.of(report);
        return new EditorOutline(new Lanes(report, flow).lanes(), policies(report, flow), variables(report, flow));
    }

    private static List<PolicyEntry> policies(BundleReport report, VariableFlow flow) {
        List<PolicyEntry> entries = new ArrayList<>();
        for (Policy policy : report.policies()) {
            int order = -1;
            for (int i = 0; i < flow.steps().size() && order < 0; i++) {
                VariableFlow.Step step = flow.steps().get(i);
                if (!step.type().equals("RouteRule") && step.policy().equals(policy.name())) order = i;
            }
            entries.add(new PolicyEntry(policy.name(), policy.type(), policy.file(), policy.enabled(), order,
                    policy.attachments().stream().map(a -> a.describe()).toList()));
        }
        return entries;
    }

    private static List<Variable> variables(BundleReport report, VariableFlow flow) {
        Map<String, String> files = new HashMap<>();
        report.policies().forEach(p -> files.put(p.name(), p.file()));
        Map<String, List<Use>> setBy = new LinkedHashMap<>();
        Map<String, List<Use>> readBy = new LinkedHashMap<>();
        List<VariableFlow.Step> steps = flow.steps();
        for (int i = 0; i < steps.size(); i++) {
            VariableFlow.Step step = steps.get(i);
            for (var write : step.writes()) {
                setBy.computeIfAbsent(write.name(), n -> new ArrayList<>()).add(
                        new Use(step.label(), files.get(step.policy()), step.location(), i, null, null));
            }
        }
        for (VariableFlow.Read read : flow.reads()) {
            VariableFlow.Step step = read.step();
            readBy.computeIfAbsent(read.variable().name(), n -> new ArrayList<>()).add(new Use(step.label(),
                    files.get(step.policy()), step.location(), steps.indexOf(step), read.source().name(), read.note()));
        }
        Map<String, Variable> variables = new LinkedHashMap<>();
        setBy.forEach((name, uses) -> variables.put(name, new Variable(name, uses, readBy.getOrDefault(name, List.of()))));
        readBy.forEach((name, uses) -> variables.putIfAbsent(name, new Variable(name, List.of(), uses)));
        return List.copyOf(variables.values());
    }

    /** Reads the endpoints of a bundle into lanes, in the order {@link VariableFlow} runs them. */
    private static final class Lanes {

        private record Endpoint(Element root, String file) {

            String name() {
                return root.getTagName() + " " + Xml.nameOf(root);
            }
        }

        private final BundleReport report;
        private final Path dir;
        private final Map<String, Policy> policies = new HashMap<>();
        private final Map<String, List<Unset>> unset = new HashMap<>();

        Lanes(BundleReport report, VariableFlow flow) {
            this.report = report;
            this.dir = Path.of(report.path());
            report.policies().forEach(p -> policies.put(p.name(), p));
            for (VariableFlow.Read read : flow.reads()) {
                String why = switch (read.source()) {
                    case SET_LATER -> "only later steps set it";
                    case UNSET -> read.note() != null ? read.note() : "no step sets it";
                    default -> null;
                };
                if (why != null) {
                    unset.computeIfAbsent(key(read.step().location(), read.step().policy()), k -> new ArrayList<>())
                            .add(new Unset(read.variable().name(), why));
                }
            }
        }

        private static String key(String location, String policy) {
            return location + "\u0000" + policy;
        }

        List<Lane> lanes() throws IOException {
            if (report.type() == BundleType.SHARED_FLOW) return sharedFlow();
            List<Endpoint> proxies = endpoints("proxies");
            List<Endpoint> targets = endpoints("targets");
            List<Lane> lanes = new ArrayList<>();
            for (Endpoint proxy : proxies) add(lanes, proxy.name() + " request", phase(proxy, "Request"));
            for (Endpoint proxy : proxies) add(lanes, proxy.name() + " routes", routes(proxy));
            for (Endpoint target : targets) add(lanes, target.name() + " request", phase(target, "Request"));
            for (Endpoint target : targets) add(lanes, target.name() + " response", phase(target, "Response"));
            for (Endpoint proxy : proxies) {
                List<Segment> response = phase(proxy, "Response");
                segment(response, proxy, Xml.path(proxy.root(), "PostClientFlow", "Response"), "PostClientFlow",
                        null, proxy.name() + " › PostClientFlow › Response");
                add(lanes, proxy.name() + " response", response);
            }
            for (Endpoint endpoint : proxies) add(lanes, endpoint.name() + " faults", faults(endpoint));
            for (Endpoint endpoint : targets) add(lanes, endpoint.name() + " faults", faults(endpoint));
            return lanes;
        }

        private List<Lane> sharedFlow() throws IOException {
            List<Lane> lanes = new ArrayList<>();
            for (Endpoint flow : endpoints("sharedflows")) {
                List<Segment> segments = new ArrayList<>();
                segment(segments, flow, flow.root(), Xml.nameOf(flow.root()), null, flow.name());
                add(lanes, flow.name(), segments);
            }
            return lanes;
        }

        private static void add(List<Lane> lanes, String title, List<Segment> segments) {
            if (!segments.isEmpty()) lanes.add(new Lane(title, segments));
        }

        private List<Endpoint> endpoints(String folder) throws IOException {
            List<Endpoint> endpoints = new ArrayList<>();
            for (Path file : Xml.xmlFiles(dir.resolve(folder))) {
                Element root = Xml.parse(file);
                new SourceMap(new String(Files.readAllBytes(file), StandardCharsets.UTF_8)).mark(root);
                endpoints.add(new Endpoint(root, Xml.relativePath(dir, file)));
            }
            return endpoints;
        }

        private List<Segment> phase(Endpoint endpoint, String phase) {
            List<Segment> segments = new ArrayList<>();
            Element preFlow = Xml.path(endpoint.root(), "PreFlow");
            if (Xml.path(preFlow, phase) == null) {
                Element parent = preFlow != null ? preFlow : endpoint.root();
                segments.add(new Segment("PreFlow", null, endpoint.file(), phase, SourceMap.spanOf(parent), List.of(),
                        parent.getTagName()));
            }
            segment(segments, endpoint, Xml.path(preFlow, phase), "PreFlow", null,
                    endpoint.name() + " › PreFlow › " + phase);
            for (Element flow : Xml.children(Xml.path(endpoint.root(), "Flows"), "Flow")) {
                segment(segments, endpoint, Xml.path(flow, phase), Xml.nameOf(flow), Xml.text(flow, "Condition"),
                        endpoint.name() + " › Flow " + Xml.nameOf(flow) + " › " + phase);
            }
            segment(segments, endpoint, Xml.path(endpoint.root(), "PostFlow", phase), "PostFlow", null,
                    endpoint.name() + " › PostFlow › " + phase);
            return segments;
        }

        private static List<Segment> routes(Endpoint proxy) {
            List<Segment> segments = new ArrayList<>();
            for (Element rule : Xml.children(proxy.root(), "RouteRule")) {
                String target = Xml.text(rule, "TargetEndpoint");
                segments.add(new Segment(Xml.nameOf(rule) + (target == null ? " (no target)" : " → " + target),
                        Xml.text(rule, "Condition"), proxy.file(), null, SourceMap.spanOf(rule), List.of(), null));
            }
            return segments;
        }

        private List<Segment> faults(Endpoint endpoint) {
            List<Segment> segments = new ArrayList<>();
            for (Element rule : Xml.children(Xml.path(endpoint.root(), "FaultRules"), "FaultRule")) {
                segment(segments, endpoint, rule, Xml.nameOf(rule), Xml.text(rule, "Condition"),
                        endpoint.name() + " › FaultRule " + Xml.nameOf(rule));
            }
            Element defaultRule = Xml.path(endpoint.root(), "DefaultFaultRule");
            segment(segments, endpoint, defaultRule, "DefaultFaultRule", Xml.text(defaultRule, "Condition"),
                    endpoint.name() + " › DefaultFaultRule");
            return segments;
        }

        /** @param location the {@link VariableFlow.Step#location} of its steps */
        private void segment(List<Segment> segments, Endpoint endpoint, Element holder, String label, String condition,
                             String location) {
            if (holder == null) return;
            List<Step> steps = new ArrayList<>();
            for (Element step : Xml.children(holder, "Step")) {
                String name = Xml.text(step, "Name");
                Policy policy = policies.get(name);
                steps.add(new Step(name, policy == null ? null : policy.type(), policy == null ? null : policy.file(),
                        policy != null && policy.enabled(), Xml.text(step, "Condition"), SourceMap.spanOf(step),
                        unset.getOrDefault(key(location, name), List.of())));
            }
            segments.add(new Segment(label, condition, endpoint.file(), holder.getTagName(), SourceMap.spanOf(holder),
                    steps, null));
        }
    }
}
