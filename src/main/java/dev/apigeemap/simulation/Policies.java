package dev.apigeemap.simulation;

import dev.apigeemap.analysis.Xml;
import dev.apigeemap.model.Policy;
import dev.apigeemap.protocol.Json;
import dev.apigeemap.simulation.Simulation.Status;
import org.w3c.dom.Element;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** What each type of policy does to a simulated call. */
final class Policies {

    /** How a policy ended when it did not raise a fault. */
    record Outcome(Status status, String note) {
    }

    /** The fault a policy of a type raises when it is asked to fail. */
    record Failure(String name, String status) {
    }

    private static final Map<String, Failure> FAILURES = Map.ofEntries(
            Map.entry("VerifyAPIKey", new Failure("InvalidApiKey", "401")),
            Map.entry("OAuthV2", new Failure("InvalidAccessToken", "401")),
            Map.entry("VerifyJWT", new Failure("InvalidToken", "401")),
            Map.entry("BasicAuthentication", new Failure("UnresolvedVariable", "500")),
            Map.entry("AccessControl", new Failure("IPDeniedAccess", "403")),
            Map.entry("Quota", new Failure("QuotaViolation", "429")),
            Map.entry("SpikeArrest", new Failure("SpikeArrestViolation", "429")),
            Map.entry("JSONThreatProtection", new Failure("ExecutionFailed", "400")),
            Map.entry("XMLThreatProtection", new Failure("ExecutionFailed", "400")),
            Map.entry("RegularExpressionProtection", new Failure("ThreatDetected", "400")));

    /** Types taken to succeed: they depend on something outside the proxy, or only protect it. */
    private static final Set<String> ASSUMED = Set.of("VerifyAPIKey", "OAuthV2", "VerifyJWT", "GenerateJWT", "DecodeJWT",
            "BasicAuthentication", "AccessControl", "Quota", "SpikeArrest", "JSONThreatProtection",
            "XMLThreatProtection", "RegularExpressionProtection", "LookupCache", "PopulateCache", "InvalidateCache",
            "ResponseCache", "MessageLogging", "StatisticsCollector", "ServiceCallout", "KeyValueMapOperations",
            "AccessEntity");

    private Policies() {
    }

    static Failure failure(String type) {
        return FAILURES.getOrDefault(type, new Failure("ExecutionFailed", "500"));
    }

    static Outcome run(Element xml, Policy policy, Path bundle, Exchange exchange) {
        return switch (policy.type()) {
            case "AssignMessage" -> assignMessage(xml, exchange);
            case "ExtractVariables" -> extractVariables(xml, exchange);
            case "RaiseFault" -> raiseFault(xml, exchange);
            case "Javascript" -> javascript(xml, bundle, exchange);
            default -> ASSUMED.contains(policy.type()) ? assumed(xml, policy, exchange)
                    : new Outcome(Status.NOT_SIMULATED, "What it does is not in the rest of this trace");
        };
    }

    private static Outcome assumed(Element xml, Policy policy, Exchange exchange) {
        String name = policy.name();
        switch (policy.type()) {
            case "VerifyAPIKey" -> {
                exchange.set("client_id", "simulated");
                exchange.set("verifyapikey." + name + ".client_id", "simulated");
            }
            case "OAuthV2" -> exchange.set("client_id", "simulated");
            case "LookupCache" -> {
                exchange.set("lookupcache." + name + ".cachehit", "false");
                return new Outcome(Status.ASSUMED, "A cache miss");
            }
            case "ServiceCallout" -> {
                return new Outcome(Status.ASSUMED, "Not called: set what its response gives in Variables");
            }
            case "KeyValueMapOperations" -> {
                return new Outcome(Status.ASSUMED, "Not read: set its values in Variables");
            }
            default -> {
            }
        }
        return new Outcome(Status.ASSUMED, "Taken to succeed");
    }

    private static String ownMessage(Element xml, Exchange exchange) {
        Element assignTo = Xml.path(xml, "AssignTo");
        if (assignTo == null) return exchange.current;
        String name = Xml.text(assignTo);
        if (name != null && !name.isBlank()) return name.strip();
        String type = assignTo.getAttribute("type");
        return type.isEmpty() ? exchange.current : type;
    }

    private static Outcome assignMessage(Element xml, Exchange exchange) {
        String message = ownMessage(xml, exchange);
        boolean ignore = "true".equalsIgnoreCase(Xml.text(xml, "IgnoreUnresolvedVariables"));
        Element copy = Xml.path(xml, "Copy");
        if (copy != null) copy(copy, message, exchange);
        Element remove = Xml.path(xml, "Remove");
        if (remove != null) remove(remove, message, exchange);
        Element add = Xml.path(xml, "Add");
        if (add != null) assign(add, message, exchange, true);
        Element set = Xml.path(xml, "Set");
        if (set != null) assign(set, message, exchange, false);
        for (Element variable : Xml.children(xml, "AssignVariable")) {
            String name = Xml.text(variable, "Name");
            String ref = Xml.text(variable, "Ref");
            String value = ref != null ? exchange.get(ref) : null;
            if (value == null && Xml.path(variable, "Template") != null) value = exchange.template(Xml.text(variable, "Template"));
            if (value == null) value = Xml.text(variable, "Value");
            exchange.set(name, value);
        }
        return new Outcome(Status.RAN, ignore ? null : unresolved(xml, exchange));
    }

    /** The first variable of the policy's templates without a value, which fails it. */
    private static String unresolved(Element xml, Exchange exchange) {
        Matcher matcher = Pattern.compile("\\{([A-Za-z_][\\w.-]*)}").matcher(xml.getTextContent());
        while (matcher.find()) {
            if (exchange.get(matcher.group(1)) == null) {
                throw new Simulator.Fault("UnresolvedVariable", "500", "No value for " + matcher.group(1));
            }
        }
        return null;
    }

    private static void copy(Element copy, String message, Exchange exchange) {
        String source = copy.getAttribute("source");
        String from = source.isEmpty() ? exchange.current : source;
        for (Element header : Xml.children(Xml.path(copy, "Headers"), "Header")) {
            String name = header.getAttribute("name");
            exchange.set(message + ".header." + name, exchange.get(from + ".header." + name));
        }
        for (Element param : Xml.children(Xml.path(copy, "QueryParams"), "QueryParam")) {
            String name = param.getAttribute("name");
            exchange.set(message + ".queryparam." + name, exchange.get(from + ".queryparam." + name));
        }
        if ("true".equalsIgnoreCase(Xml.text(copy, "Payload"))) exchange.set(message + ".content", exchange.get(from + ".content"));
    }

    private static void remove(Element remove, String message, Exchange exchange) {
        Exchange.Message target = exchange.message(message);
        Element headers = Xml.path(remove, "Headers");
        if (headers != null) {
            List<Element> named = Xml.children(headers, "Header");
            if (named.isEmpty()) target.headers.clear();
            named.forEach(h -> target.headers.remove(h.getAttribute("name")));
        }
        Element params = Xml.path(remove, "QueryParams");
        if (params != null) {
            List<Element> named = Xml.children(params, "QueryParam");
            if (named.isEmpty()) target.query.clear();
            named.forEach(p -> target.query.remove(p.getAttribute("name")));
        }
        if (Xml.path(remove, "Payload") != null && !"false".equalsIgnoreCase(Xml.text(remove, "Payload"))) target.content = null;
    }

    /** {@code <Add>} and {@code <Set>}; an added header that exists stays as it is. */
    private static void assign(Element block, String message, Exchange exchange, boolean add) {
        for (Element header : Xml.children(Xml.path(block, "Headers"), "Header")) {
            String name = message + ".header." + header.getAttribute("name");
            if (!add || exchange.get(name) == null) exchange.set(name, exchange.template(Xml.text(header)));
        }
        for (Element param : Xml.children(Xml.path(block, "QueryParams"), "QueryParam")) {
            String name = message + ".queryparam." + param.getAttribute("name");
            if (!add || exchange.get(name) == null) exchange.set(name, exchange.template(Xml.text(param)));
        }
        Exchange.Message target = exchange.message(message);
        Element payload = Xml.path(block, "Payload");
        if (payload != null) {
            target.content = exchange.template(Xml.text(payload));
            if (payload.hasAttribute("contentType")) target.headers.put("Content-Type", payload.getAttribute("contentType"));
        }
        String status = Xml.text(block, "StatusCode");
        if (status != null) target.status = exchange.template(status);
        String reason = Xml.text(block, "ReasonPhrase");
        if (reason != null) target.reason = exchange.template(reason);
        String verb = Xml.text(block, "Verb");
        if (verb != null) target.verb = exchange.template(verb);
        String path = Xml.text(block, "Path");
        if (path != null) target.path = exchange.template(path);
    }

    private static Outcome extractVariables(Element xml, Exchange exchange) {
        String source = Xml.text(xml, "Source");
        String message = source == null ? exchange.current : source.strip();
        String prefix = Xml.text(xml, "VariablePrefix");
        String start = prefix == null ? "apigee." : prefix.isBlank() ? "" : prefix.strip() + ".";
        for (Element header : Xml.children(xml, "Header")) {
            pattern(header, exchange.get(message + ".header." + header.getAttribute("name")), start, exchange);
        }
        for (Element param : Xml.children(xml, "QueryParam")) {
            pattern(param, exchange.get(message + ".queryparam." + param.getAttribute("name")), start, exchange);
        }
        for (Element path : Xml.children(xml, "URIPath")) pattern(path, exchange.get("proxy.pathsuffix"), start, exchange);
        for (Element variable : Xml.children(xml, "Variable")) {
            pattern(variable, exchange.get(variable.getAttribute("name")), start, exchange);
        }
        Element json = Xml.path(xml, "JSONPayload");
        if (json != null) {
            Object document;
            try {
                document = Json.parse(String.valueOf(exchange.get(message + ".content")));
            } catch (RuntimeException e) {
                document = null;
            }
            for (Element variable : Xml.children(json, "Variable")) {
                Object value = jsonPath(document, Xml.text(variable, "JSONPath"));
                if (value != null) exchange.set(start + variable.getAttribute("name"), value instanceof Map || value instanceof List ? Json.write(value) : number(value));
            }
        }
        return new Outcome(Status.RAN, Xml.path(xml, "XMLPayload") != null || Xml.path(xml, "FormParam") != null
                ? "XMLPayload and FormParam are not read here" : null);
    }

    private static String number(Object value) {
        return value instanceof Double d && d == Math.rint(d) ? String.valueOf(d.longValue()) : String.valueOf(value);
    }

    /** Takes the {@code {name}} parts of the first {@code <Pattern>} that matches. */
    private static void pattern(Element holder, String value, String start, Exchange exchange) {
        if (value == null) return;
        for (Element pattern : Xml.children(holder, "Pattern")) {
            List<String> names = new ArrayList<>();
            Matcher part = Pattern.compile("\\{([^}]+)}").matcher(Xml.text(pattern));
            StringBuilder regex = new StringBuilder();
            int from = 0;
            while (part.find()) {
                regex.append(Pattern.quote(Xml.text(pattern).substring(from, part.start()))).append("(.+?)");
                names.add(part.group(1));
                from = part.end();
            }
            regex.append(Pattern.quote(Xml.text(pattern).substring(from)));
            Matcher matcher = Pattern.compile(regex.toString()).matcher(value);
            if (!matcher.matches()) continue;
            for (int i = 0; i < names.size(); i++) exchange.set(start + names.get(i), matcher.group(i + 1));
            return;
        }
    }

    /** {@code $.a.b[0].c}; null when it leads nowhere. */
    private static Object jsonPath(Object document, String path) {
        if (path == null || !path.startsWith("$")) return null;
        Object value = document;
        Matcher step = Pattern.compile("\\.([^.\\[]+)|\\[(\\d+)]").matcher(path.substring(1));
        while (step.find() && value != null) {
            if (step.group(1) != null) {
                value = value instanceof Map<?, ?> map ? map.get(step.group(1)) : null;
            } else {
                int index = Integer.parseInt(step.group(2));
                value = value instanceof List<?> list && index < list.size() ? list.get(index) : null;
            }
        }
        return value;
    }

    private static Outcome raiseFault(Element xml, Exchange exchange) {
        Element response = Xml.path(xml, "FaultResponse");
        exchange.message("response").status = "500";
        if (response != null) {
            Element set = Xml.path(response, "Set");
            if (set != null) assign(set, "response", exchange, false);
            Element add = Xml.path(response, "Add");
            if (add != null) assign(add, "response", exchange, true);
        }
        String status = exchange.message("response").status;
        throw new Simulator.Fault("RaiseFault", status, "Raises a fault with status " + status);
    }

    private static Outcome javascript(Element xml, Path bundle, Exchange exchange) {
        List<String> sources = new ArrayList<>();
        try {
            for (Element include : Xml.children(xml, "IncludeURL")) sources.add(resource(Xml.text(include), bundle));
            String url = Xml.text(xml, "ResourceURL");
            if (url != null) sources.add(resource(url, bundle));
            else if (Xml.text(xml, "Source") != null) sources.add(Xml.text(xml, "Source"));
        } catch (IOException e) {
            return new Outcome(Status.NOT_SIMULATED, e.getMessage() + " is not in the bundle");
        }
        String problem = Scripts.run(sources, exchange);
        if (problem != null) throw new Simulator.Fault("ScriptExecutionFailed", "500", problem);
        return new Outcome(Status.RAN, null);
    }

    /** The text of a {@code jsc://} resource of the bundle. */
    private static String resource(String url, Path bundle) throws IOException {
        Path file = bundle.resolve("resources/jsc").resolve(url.replaceFirst("^jsc://", "")).normalize();
        if (!file.startsWith(bundle.normalize()) || !Files.isRegularFile(file)) throw new IOException(url);
        return new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
    }
}
