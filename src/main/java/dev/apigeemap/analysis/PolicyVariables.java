package dev.apigeemap.analysis;

import org.w3c.dom.Attr;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

import java.io.IOException;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Flow variables one policy reads and writes, read from its XML, and from its scripts for Javascript and Python
 * Script policies. {@code message} stands for the message of the phase the policy runs in; {@link VariableFlow}
 * turns it into {@code request} or {@code response}.
 */
public final class PolicyVariables {

    /**
     * One variable a policy uses. {@code name} ends with {@code .*} for a family of variables, e.g.
     * {@code verifyapikey.VA-Key.*}; {@code via} says where the policy names it (an element, a script, a shared flow).
     * An optional read uses the variable when it exists and does without it otherwise.
     */
    public record Access(String name, String via, boolean optional) {

        public Access(String name, String via) {
            this(name, via, false);
        }
    }

    /**
     * @param opaque true when the policy may use variables this analysis cannot name: a Java callout, a script that
     *               computes variable names or does not parse, a shared flow that is not resolved
     */
    public record Result(List<Access> reads, List<Access> writes, boolean opaque) {

        static final Result OPAQUE = new Result(List.of(), List.of(), true);
    }

    /** {@code {name}} in message templates. Functions such as {@code {escapeJSON(x)}} are left out. */
    private static final Pattern TEMPLATE = Pattern.compile("\\{([A-Za-z_][\\w-]*(?:\\.[\\w-]+)*)}");

    /** Policy types whose element texts are message templates. */
    private static final Set<String> TEMPLATED = Set.of("AssignMessage", "RaiseFault", "ServiceCallout",
            "MessageLogging");

    /** Variables a policy type sets under its own name, e.g. {@code verifyapikey.VA-Key.client_id}. */
    private static final Map<String, String> OWN_VARIABLES = Map.ofEntries(
            Map.entry("VerifyAPIKey", "verifyapikey"),
            Map.entry("ServiceCallout", "servicecallout"),
            Map.entry("LookupCache", "lookupcache"),
            Map.entry("PopulateCache", "populatecache"),
            Map.entry("InvalidateCache", "invalidatecache"),
            Map.entry("ResponseCache", "responsecache"),
            Map.entry("Quota", "ratelimit"),
            Map.entry("SpikeArrest", "ratelimit"),
            Map.entry("VerifyJWT", "jwt"),
            Map.entry("GenerateJWT", "jwt"),
            Map.entry("DecodeJWT", "jwt"),
            Map.entry("VerifyJWS", "jws"),
            Map.entry("GenerateJWS", "jws"),
            Map.entry("DecodeJWS", "jws"),
            Map.entry("AccessEntity", "AccessEntity"),
            Map.entry("JavaCallout", "javacallout"));

    /** Elements of AssignMessage Set/Add/Remove/Copy, and the part of the message they change. */
    private static final Map<String, String> MESSAGE_PARTS = Map.of(
            "Headers", "header", "QueryParams", "queryparam", "FormParams", "formparam");

    private static final Map<String, String> MESSAGE_FIELDS = Map.of(
            "Payload", "content", "Verb", "verb", "Path", "path", "StatusCode", "status.code",
            "ReasonPhrase", "reason.phrase", "Version", "version");

    /** Words of conditions that are not variables. */
    private static final Set<String> OPERATORS = Set.of("and", "or", "not", "matchespath", "matches", "like",
            "javaregex", "likepath", "equals", "notequals", "is", "isnot", "greaterthan", "lesserthan",
            "greaterthanorequals", "lesserthanorequals", "startswith", "equalscaseinsensitive", "true", "false",
            "null");

    private PolicyVariables() {
    }

    /**
     * @param sharedFlows what a shared flow reads and writes, by name; null when the shared flow is not resolved
     */
    public static Result of(Path bundleDir, Element policy, Function<String, Result> sharedFlows) throws IOException {
        Collector c = new Collector();
        String type = policy.getTagName();
        String name = Xml.nameOf(policy);
        boolean decode = "Decode".equalsIgnoreCase(Xml.text(policy, "Operation"));

        for (Element element : Xml.descendants(policy, "*")) {
            NamedNodeMap attributes = element.getAttributes();
            for (int i = 0; i < attributes.getLength(); i++) {
                Attr attribute = (Attr) attributes.item(i);
                String attr = attribute.getName();
                String value = attribute.getValue().trim();
                if (attr.equals("assignTo")) {
                    c.write(value, element.getTagName() + "@assignTo");
                } else if (attr.equals("ref") || attr.endsWith("Ref")) {
                    // BasicAuthentication Decode writes the user and password to the variables it names
                    if (decode && type.equals("BasicAuthentication")) c.write(value, element.getTagName() + "@ref");
                    else c.read(value, element.getTagName() + "@" + attr);
                }
            }
            switch (element.getTagName()) {
                case "OutputVariable" -> c.write(Xml.text(element), "OutputVariable");
                case "AssignTo" -> {
                    if (!type.equals("AssignMessage")) c.write(Xml.text(element), "AssignTo");
                }
                case "Source" -> {
                    if (!type.equals("Javascript")) c.read(Xml.text(element), "Source");
                }
                default -> {
                }
            }
        }

        switch (type) {
            case "AssignMessage" -> assignMessage(policy, c);
            case "ExtractVariables" -> extractVariables(policy, c);
            case "ServiceCallout" -> serviceCallout(policy, c);
            case "Javascript" -> {
                for (Map.Entry<String, String> script : ScriptAnalyzer.scripts(bundleDir, policy).entrySet()) {
                    String file = script.getKey().equals("inline") ? "inline script" : script.getKey();
                    c.script(ScriptAnalyzer.analyze(script.getValue(), script.getKey()), file);
                }
            }
            case "Script" -> {
                for (Map.Entry<String, String> script : ScriptAnalyzer.pythonScripts(bundleDir, policy).entrySet()) {
                    c.script(ScriptAnalyzer.analyzePython(script.getValue()), script.getKey());
                }
            }
            case "JavaCallout" -> c.opaque = true;
            case "FlowCallout" -> flowCallout(policy, c, sharedFlows);
            default -> {
            }
        }
        if (TEMPLATED.contains(type)) templates(policy, c);
        String own = OWN_VARIABLES.get(type);
        if (own != null) c.write(own + "." + name + ".*", type);
        if (type.equals("GetOAuthV2Info")) {
            for (String prefix : List.of("oauthv2accesstoken", "oauthv2authcode", "oauthv2refreshtoken",
                    "oauthv2client")) {
                c.write(prefix + "." + name + ".*", type);
            }
        }
        return c.result();
    }

    /** Variables a step or flow condition reads, e.g. {@code request.verb} in {@code request.verb = "GET"}. */
    public static List<Access> condition(String condition) {
        Collector c = new Collector();
        if (condition == null) return List.of();
        String code = condition.replaceAll("\"(?:[^\"\\\\]|\\\\.)*\"|'(?:[^'\\\\]|\\\\.)*'", " ");
        Matcher matcher = Pattern.compile("[A-Za-z_][\\w-]*(?:\\.[\\w-]+)*").matcher(code);
        while (matcher.find()) {
            if (!OPERATORS.contains(matcher.group().toLowerCase(Locale.ROOT))) c.read(matcher.group(), "condition");
        }
        return c.result().reads();
    }

    /** Set, Add, Remove and Copy change the message of AssignTo; AssignVariable sets a plain variable. */
    private static void assignMessage(Element policy, Collector c) {
        Element assignTo = Xml.path(policy, "AssignTo");
        String target = Xml.text(assignTo);
        if (target == null && "true".equals(Xml.attr(assignTo, "createNew"))) target = Xml.attr(assignTo, "type");
        if (target == null) target = "message";
        if (Xml.text(assignTo) != null) c.write(target, "AssignTo");
        for (String operation : List.of("Set", "Add", "Remove", "Copy")) {
            for (Element block : Xml.children(policy, operation)) {
                messageParts(block, target, operation, c);
                if (operation.equals("Copy")) {
                    String source = Xml.attr(block, "source");
                    c.read(source == null ? "message" : source, "Copy@source");
                }
            }
        }
        for (Element variable : Xml.children(policy, "AssignVariable")) {
            c.write(Xml.text(variable, "Name"), "AssignVariable");
            c.read(Xml.text(variable, "Ref"), "AssignVariable/Ref");
        }
    }

    private static void messageParts(Element block, String message, String via, Collector c) {
        for (Element child : Xml.children(block)) {
            String part = MESSAGE_PARTS.get(child.getTagName());
            String field = MESSAGE_FIELDS.get(child.getTagName());
            if (part != null) {
                for (Element item : Xml.children(child)) {
                    String itemName = Xml.attr(item, "name");
                    if (itemName != null) c.write(message + "." + part + "." + itemName, via + "/" + child.getTagName());
                }
            } else if (field != null) {
                c.write(message + "." + field, via + "/" + child.getTagName());
            }
        }
    }

    private static void extractVariables(Element policy, Collector c) {
        String source = Xml.text(policy, "Source");
        if (source == null) source = "message";
        for (Map.Entry<String, String> part : Map.of("Header", "header", "QueryParam", "queryparam",
                "FormParam", "formparam").entrySet()) {
            for (Element element : Xml.children(policy, part.getKey())) {
                String name = Xml.attr(element, "name");
                if (name != null) c.read(source + "." + part.getValue() + "." + name, part.getKey());
            }
        }
        if (!Xml.children(policy, "URIPath").isEmpty()) c.read("proxy.pathsuffix", "URIPath");
        for (String payload : List.of("JSONPayload", "XMLPayload")) {
            if (!Xml.children(policy, payload).isEmpty()) c.read(source + ".content", payload);
        }

        String prefix = Xml.text(policy, "VariablePrefix");
        for (Element variable : Xml.descendants(policy, "Variable")) {
            String name = Xml.attr(variable, "name");
            if (name != null) c.write(prefix == null ? name : prefix + "." + name, "Variable");
        }
        for (Element pattern : Xml.descendants(policy, "Pattern")) {
            Matcher matcher = TEMPLATE.matcher(String.valueOf(Xml.text(pattern)));
            while (matcher.find()) {
                c.write(prefix == null ? matcher.group(1) : prefix + "." + matcher.group(1), "Pattern");
            }
        }
    }

    /**
     * The request variable is built by the policy when it has Set/Add/Copy/Remove children. Without children, the
     * policy sends the message an earlier step built under that name, or a new GET request when there is none.
     */
    private static void serviceCallout(Element policy, Collector c) {
        Element request = Xml.path(policy, "Request");
        if (request != null) {
            String variable = Xml.attr(request, "variable");
            if (variable != null) {
                if (Xml.children(request).isEmpty()) c.optionalRead(variable, "Request@variable");
                else c.write(variable, "Request@variable");
                messageParts(request, variable, "Request", c);
            }
        }
        String response = Xml.text(policy, "Response");
        c.write(response == null ? "calloutResponse" : response, "Response");
    }

    private static void flowCallout(Element policy, Collector c, Function<String, Result> sharedFlows) {
        for (Element parameter : Xml.descendants(policy, "Parameter")) {
            c.write(Xml.attr(parameter, "name"), "Parameter");
        }
        String sharedFlow = Xml.text(policy, "SharedFlowBundle");
        Result called = sharedFlow == null ? null : sharedFlows.apply(sharedFlow);
        if (called == null) {
            c.opaque = true;
            return;
        }
        called.reads().forEach(a -> c.reads.putIfAbsent(a.name(),
                new Access(a.name(), sharedFlow + " › " + a.via(), a.optional())));
        called.writes().forEach(a -> c.write(a.name(), sharedFlow + " › " + a.via()));
        c.opaque |= called.opaque();
    }

    /** {@code {variable}} in element texts; a Payload may use its own delimiters (variablePrefix/variableSuffix). */
    private static void templates(Element policy, Collector c) {
        for (Element element : Xml.descendants(policy, "*")) {
            if (element.getTagName().equals("Value") || element.getTagName().equals("Ref")) continue;
            StringBuilder text = new StringBuilder();
            for (Node n = element.getFirstChild(); n != null; n = n.getNextSibling()) {
                if (n.getNodeType() == Node.TEXT_NODE || n.getNodeType() == Node.CDATA_SECTION_NODE) {
                    text.append(n.getNodeValue());
                }
            }
            if (text.isEmpty()) continue;
            String prefix = Xml.attr(element, "variablePrefix");
            String suffix = Xml.attr(element, "variableSuffix");
            Pattern pattern = prefix != null && suffix != null
                    ? Pattern.compile(Pattern.quote(prefix) + "([A-Za-z_][\\w-]*(?:\\.[\\w-]+)*)" + Pattern.quote(suffix))
                    : TEMPLATE;
            Matcher matcher = pattern.matcher(text);
            while (matcher.find()) c.read(matcher.group(1), element.getTagName() + " template");
        }
    }

    private static final class Collector {
        private final Map<String, Access> reads = new LinkedHashMap<>();
        private final Map<String, Access> writes = new LinkedHashMap<>();
        private boolean opaque;

        void read(String name, String via) {
            if (name != null && !name.isBlank()) reads.putIfAbsent(name.trim(), new Access(name.trim(), via));
        }

        void optionalRead(String name, String via) {
            if (name != null && !name.isBlank()) reads.putIfAbsent(name.trim(), new Access(name.trim(), via, true));
        }

        void write(String name, String via) {
            if (name != null && !name.isBlank()) writes.putIfAbsent(name.trim(), new Access(name.trim(), via));
        }

        void script(ScriptAnalyzer.Facts facts, String file) {
            facts.reads().forEach(name -> read(name, file));
            facts.writes().forEach(name -> write(name, file));
            opaque |= facts.dynamicWrites() || facts.error() != null;
        }

        Result result() {
            return new Result(List.copyOf(reads.values()), List.copyOf(writes.values()), opaque);
        }
    }
}
