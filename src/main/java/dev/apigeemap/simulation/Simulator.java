package dev.apigeemap.simulation;

import dev.apigeemap.analysis.Xml;
import dev.apigeemap.model.BundleReport;
import dev.apigeemap.model.Policy;
import dev.apigeemap.model.SharedFlowLink;
import dev.apigeemap.simulation.Simulation.Change;
import dev.apigeemap.simulation.Simulation.Entry;
import dev.apigeemap.simulation.Simulation.Input;
import dev.apigeemap.simulation.Simulation.Response;
import dev.apigeemap.simulation.Simulation.Result;
import dev.apigeemap.simulation.Simulation.Status;
import org.w3c.dom.Element;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Plays one call through a proxy, in the order Apigee runs it, without Apigee: the conditions and routes are evaluated,
 * the first conditional flow that matches is taken, and the target answers what it is told to. Policies that only
 * change the call run for real ({@link Policies}); the others are taken to succeed and say so in the result.
 */
public final class Simulator {

    /** A policy failed: the flow stops and the fault rules take over. */
    static final class Fault extends RuntimeException {
        final String name;
        final String status;

        Fault(String name, String status, String message) {
            super(message);
            this.name = name;
            this.status = status;
        }
    }

    private final BundleReport report;
    private final List<Entry> entries = new ArrayList<>();
    private final List<String> warnings = new ArrayList<>();
    private final Exchange exchange = new Exchange();
    private final Input input;
    private Element faultEndpoint;

    private Simulator(BundleReport report, Input input) {
        this.report = report;
        this.input = input;
    }

    public static Result run(BundleReport report, Input input) throws IOException {
        return new Simulator(report, input).run();
    }

    private Result run() throws IOException {
        Path dir = Path.of(report.path());
        List<Element> proxies = new ArrayList<>();
        for (Path file : Xml.xmlFiles(dir.resolve("proxies"))) proxies.add(Xml.parse(file));
        Map<String, Element> targets = new LinkedHashMap<>();
        for (Path file : Xml.xmlFiles(dir.resolve("targets"))) {
            Element target = Xml.parse(file);
            targets.put(Xml.nameOf(target), target);
        }
        if (proxies.isEmpty()) throw new IOException("This bundle has no ProxyEndpoint");
        Element proxy = start(proxies);

        String fault = null;
        try {
            faultEndpoint = proxy;
            Element proxyFlow = request(proxy);
            Element target = route(proxy, targets);
            if (target != null) {
                faultEndpoint = target;
                Element targetFlow = request(target);
                callTarget();
                exchange.current = "response";
                response(target, targetFlow);
            } else {
                exchange.current = "response";
                exchange.message("response").status = "200";
            }
            faultEndpoint = proxy;
            response(proxy, proxyFlow);
            steps(report, Xml.children(Xml.path(proxy, "PostClientFlow", "Response"), "Step"),
                    name(proxy) + " › PostClientFlow › Response");
        } catch (Fault f) {
            fault = f.name;
            fault(f, proxy);
        }
        Exchange.Message response = exchange.message("response");
        return new Result(List.copyOf(entries), new Response(response.status == null ? "200" : response.status,
                response.reason, new LinkedHashMap<>(response.headers), response.content), fault, warnings);
    }

    /** Sets the request up, and picks the ProxyEndpoint whose base path it calls. */
    private Element start(List<Element> proxies) {
        String path = input.path() == null || input.path().isBlank() ? "/" : input.path().strip();
        int mark = path.indexOf('?');
        String query = mark < 0 ? "" : path.substring(mark + 1);
        if (mark >= 0) path = path.substring(0, mark);
        Exchange.Message request = exchange.message("request");
        request.verb = input.verb() == null || input.verb().isBlank() ? "GET" : input.verb().strip();
        request.path = path;
        request.content = input.body() == null || input.body().isEmpty() ? null : input.body();
        request.headers.putAll(input.headers());
        for (String pair : query.split("&")) {
            if (pair.isEmpty()) continue;
            int equals = pair.indexOf('=');
            request.query.put(equals < 0 ? pair : pair.substring(0, equals), equals < 0 ? "" : pair.substring(equals + 1));
        }
        input.variables().forEach(exchange::set);
        exchange.set("client.ip", "127.0.0.1");
        exchange.set("system.uuid", "00000000-0000-0000-0000-000000000000");
        exchange.set("messageid", "simulated");

        Element chosen = null;
        String basePath = null;
        for (Element proxy : proxies) {
            String candidate = Objects.requireNonNullElse(Xml.text(proxy, "HTTPProxyConnection", "BasePath"), "/");
            String prefix = candidate.endsWith("/") ? candidate.substring(0, candidate.length() - 1) : candidate;
            if ((path.equals(prefix) || path.startsWith(prefix + "/"))
                    && (basePath == null || candidate.length() > basePath.length())) {
                chosen = proxy;
                basePath = candidate;
            }
        }
        if (chosen == null) {
            chosen = proxies.get(0);
            basePath = Objects.requireNonNullElse(Xml.text(chosen, "HTTPProxyConnection", "BasePath"), "/");
            warnings.add("The path is under no base path of the proxy: Apigee would not route it here");
        }
        exchange.set("proxy.basepath", basePath);
        String prefix = basePath.endsWith("/") ? basePath.substring(0, basePath.length() - 1) : basePath;
        exchange.set("proxy.pathsuffix", path.startsWith(prefix) ? path.substring(prefix.length()) : path);
        return chosen;
    }

    private static String name(Element endpoint) {
        return endpoint.getTagName() + " " + Xml.nameOf(endpoint);
    }

    /** The request side of an endpoint; answers its conditional flow, which its response side runs too. */
    private Element request(Element endpoint) {
        steps(report, Xml.children(Xml.path(endpoint, "PreFlow", "Request"), "Step"), name(endpoint) + " › PreFlow › Request");
        Element flow = matching(endpoint);
        flow(endpoint, flow, "Request");
        steps(report, Xml.children(Xml.path(endpoint, "PostFlow", "Request"), "Step"), name(endpoint) + " › PostFlow › Request");
        return flow;
    }

    private void response(Element endpoint, Element flow) {
        steps(report, Xml.children(Xml.path(endpoint, "PreFlow", "Response"), "Step"), name(endpoint) + " › PreFlow › Response");
        flow(endpoint, flow, "Response");
        steps(report, Xml.children(Xml.path(endpoint, "PostFlow", "Response"), "Step"), name(endpoint) + " › PostFlow › Response");
    }

    private void flow(Element endpoint, Element flow, String phase) {
        if (flow == null) return;
        steps(report, Xml.children(Xml.path(flow, phase), "Step"), name(endpoint) + " › Flow " + Xml.nameOf(flow) + " › " + phase);
    }

    /** The first conditional flow that matches, once the PreFlow ran; Apigee takes it for the whole call. */
    private Element matching(Element endpoint) {
        for (Element flow : Xml.children(Xml.path(endpoint, "Flows"), "Flow")) {
            String condition = Xml.text(flow, "Condition");
            boolean matches = condition == null || test(condition);
            entries.add(new Entry(report.name(), name(endpoint) + " › Flow " + Xml.nameOf(flow), Xml.nameOf(flow), "Flow",
                    null, matches ? Status.RAN : Status.SKIPPED, condition, null, List.of()));
            if (matches) return flow;
        }
        return null;
    }

    /** The TargetEndpoint of the first RouteRule that matches; null when it has none. */
    private Element route(Element proxy, Map<String, Element> targets) {
        for (Element rule : Xml.children(proxy, "RouteRule")) {
            String condition = Xml.text(rule, "Condition");
            boolean matches = condition == null || test(condition);
            String target = Xml.text(rule, "TargetEndpoint");
            entries.add(new Entry(report.name(), name(proxy) + " › RouteRule " + Xml.nameOf(rule), Xml.nameOf(rule),
                    "RouteRule", null, matches ? Status.RAN : Status.SKIPPED, condition,
                    matches ? (target == null ? "No target: the proxy answers itself" : "Goes to " + target) : null,
                    List.of()));
            if (!matches) continue;
            if (target == null) return null;
            Element element = targets.get(target);
            if (element == null) throw new Fault("TargetNotFound", "500", "No TargetEndpoint named " + target);
            return element;
        }
        warnings.add("No RouteRule matches: the proxy answers itself");
        return null;
    }

    private void callTarget() {
        Exchange.Message response = exchange.message("response");
        response.status = input.status() == null || input.status().isBlank() ? "200" : input.status().strip();
        response.content = input.targetBody() == null || input.targetBody().isEmpty() ? null : input.targetBody();
        if (response.status.compareTo("400") >= 0 && response.status.length() == 3) {
            exchange.current = "response";
            throw new Fault("ErrorResponseCode", response.status, "The target answered " + response.status);
        }
    }

    /** Runs the fault rules of where the fault happened, then those of the ProxyEndpoint if none of them matched. */
    private void fault(Fault fault, Element proxy) {
        exchange.current = "response";
        exchange.set("fault.name", fault.name);
        exchange.set("error.message", fault.getMessage());
        exchange.set("error.status.code", fault.status);
        Exchange.Message response = exchange.message("response");
        if (response.status == null || !(fault.name.equals("RaiseFault") || fault.name.equals("ErrorResponseCode"))) {
            response.status = fault.status;
            response.content = "{\"fault\":{\"faultstring\":\"" + fault.getMessage().replace("\"", "'")
                    + "\",\"detail\":{\"errorcode\":\"" + fault.name + "\"}}}";
            response.headers.put("Content-Type", "application/json");
        }
        warnings.add("The order of fault rules between TargetEndpoint and ProxyEndpoint is an approximation, and "
                + "PostClientFlow is not run after a fault");
        try {
            boolean handled = faultRules(faultEndpoint);
            if (!handled && faultEndpoint != proxy) faultRules(proxy);
        } catch (Fault again) {
            warnings.add("A fault rule failed in turn: " + again.getMessage());
        }
    }

    /** @return true when a fault rule matched */
    private boolean faultRules(Element endpoint) {
        List<Element> rules = new ArrayList<>(Xml.children(Xml.path(endpoint, "FaultRules"), "FaultRule"));
        if (endpoint.getTagName().equals("ProxyEndpoint")) Collections.reverse(rules);
        boolean handled = false;
        for (Element rule : rules) {
            String condition = Xml.text(rule, "Condition");
            if (condition != null && !test(condition)) continue;
            steps(report, Xml.children(rule, "Step"), name(endpoint) + " › FaultRule " + Xml.nameOf(rule));
            handled = true;
            break;
        }
        Element defaultRule = Xml.path(endpoint, "DefaultFaultRule");
        if (defaultRule != null && (!handled || "true".equalsIgnoreCase(Xml.text(defaultRule, "AlwaysEnforce")))) {
            steps(report, Xml.children(defaultRule, "Step"), name(endpoint) + " › DefaultFaultRule");
            handled = true;
        }
        return handled;
    }

    private boolean test(String condition) {
        try {
            return Conditions.test(condition, exchange::get);
        } catch (IllegalArgumentException e) {
            warnings.add("Condition taken as false: " + condition + " (" + e.getMessage() + ")");
            return false;
        }
    }

    private void steps(BundleReport bundle, List<Element> steps, String location) {
        Map<String, Policy> policies = new HashMap<>();
        bundle.policies().forEach(p -> policies.put(p.name(), p));
        for (Element step : steps) {
            String name = Xml.text(step, "Name");
            Policy policy = policies.get(name);
            String condition = Xml.text(step, "Condition");
            if (policy == null) {
                entries.add(new Entry(bundle.name(), location, name, null, null, Status.FAILED, condition,
                        "No policy has this name", List.of()));
                throw new Fault("StepDefinitionNotFound", "500", "No policy named " + name);
            }
            if (!policy.enabled()) {
                entries.add(entry(bundle, location, policy, Status.SKIPPED, condition, "Disabled", List.of()));
                continue;
            }
            if (condition != null && !test(condition)) {
                entries.add(entry(bundle, location, policy, Status.SKIPPED, condition, null, List.of()));
                continue;
            }
            run(bundle, location, policy, condition);
        }
    }

    private Entry entry(BundleReport bundle, String location, Policy policy, Status status, String condition, String note,
                        List<Change> changes) {
        return new Entry(bundle.name(), location, policy.name(), policy.type(), policy.file(), status, condition, note,
                changes);
    }

    private void run(BundleReport bundle, String location, Policy policy, String condition) {
        Map<String, String> before = exchange.snapshot();
        Element xml;
        try {
            xml = Xml.parse(Path.of(bundle.path()).resolve(policy.file()));
        } catch (IOException e) {
            throw new Fault("ExecutionFailed", "500", e.getMessage());
        }
        boolean continues = "true".equalsIgnoreCase(xml.getAttribute("continueOnError"));
        int place = entries.size();
        Status status;
        String note;
        Fault raised = null;
        try {
            if (input.failing().contains(policy.name())) {
                Policies.Failure failure = Policies.failure(policy.type());
                throw new Fault(failure.name(), failure.status(), "Failed on request: " + failure.name());
            }
            if (policy.type().equals("FlowCallout")) {
                note = flowCallout(xml, bundle, location);
                status = note == null ? Status.RAN : Status.NOT_SIMULATED;
            } else {
                Policies.Outcome outcome = Policies.run(xml, policy, Path.of(bundle.path()), exchange);
                status = outcome.status();
                note = outcome.note();
            }
        } catch (Fault fault) {
            raised = fault;
            status = Status.FAILED;
            note = fault.getMessage() + (continues ? " (continueOnError: the flow goes on)" : "");
        }
        entries.add(place, entry(bundle, location, policy, status, condition, note, changes(before)));
        if (raised != null && !continues) throw raised;
        if (raised != null) exchange.set("fault.name", raised.name);
    }

    /** Runs the shared flow in place; answers why it could not, or null. */
    private String flowCallout(Element xml, BundleReport bundle, String location) {
        String name = Xml.text(xml, "SharedFlowBundle");
        for (Element parameter : Xml.children(Xml.path(xml, "Parameters"), "Parameter")) {
            String value = parameter.hasAttribute("ref") ? exchange.get(parameter.getAttribute("ref")) : Xml.text(parameter);
            exchange.set(parameter.getAttribute("name"), exchange.template(value));
        }
        BundleReport shared = bundle.sharedFlows().stream().filter(l -> l.name().equals(name))
                .map(SharedFlowLink::report).filter(Objects::nonNull).findFirst().orElse(null);
        if (shared == null) return "The shared flow " + name + " is not available locally";
        try {
            Path dir = Path.of(shared.path());
            List<Path> files = Xml.xmlFiles(dir.resolve("sharedflows"));
            List<Path> entry = files.stream().filter(f -> f.getFileName().toString().equals("default.xml")).toList();
            for (Path file : entry.isEmpty() ? files : entry) {
                steps(shared, Xml.children(Xml.parse(file), "Step"), location + " › " + name);
            }
            return null;
        } catch (IOException e) {
            return "The shared flow " + name + " could not be read";
        }
    }

    private List<Change> changes(Map<String, String> before) {
        Map<String, String> after = exchange.snapshot();
        Set<String> names = new LinkedHashSet<>(before.keySet());
        names.addAll(after.keySet());
        List<Change> changes = new ArrayList<>();
        for (String name : names) {
            String was = before.get(name);
            String is = after.get(name);
            if (Objects.equals(was, is)) continue;
            boolean hidden = name.startsWith("private.");
            changes.add(new Change(name, hidden && was != null ? "(private)" : was, hidden && is != null ? "(private)" : is));
        }
        return changes;
    }
}
