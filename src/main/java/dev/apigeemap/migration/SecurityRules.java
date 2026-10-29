package dev.apigeemap.migration;

import dev.apigeemap.analysis.Xml;
import dev.apigeemap.model.BundleReport;
import dev.apigeemap.model.Dependency;
import dev.apigeemap.model.DependencyKind;
import dev.apigeemap.model.Policy;
import org.w3c.dom.Element;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static dev.apigeemap.migration.Finding.Category.SECURITY;
import static dev.apigeemap.migration.MigrationContext.names;
import static dev.apigeemap.model.Issue.Severity.ERROR;
import static dev.apigeemap.model.Issue.Severity.INFO;
import static dev.apigeemap.model.Issue.Severity.WARN;

final class SecurityRules {

    static final Pattern SECRET = Pattern.compile(
            "(?i)(password|passwd|pwd|secret|api[_.-]?key|client[_.-]?secret|token|credential|authorization)");
    /** {@code password = "literal"} in JavaScript, with at least 6 characters of value. */
    private static final Pattern JS_SECRET = Pattern.compile(
            "(?i)[\"']?([\\w.-]*(?:password|passwd|secret|api[_-]?key|client[_-]?secret|token)[\\w.-]*)[\"']?"
                    + "\\s*[:=]\\s*[\"']([^\"'{}\\s]{6,})[\"']");
    private static final Pattern URL_CREDENTIALS = Pattern.compile("://[^/@{}\\s]+:[^/@\\s]+@");

    private static final Set<String> AUTHENTICATION = Set.of("VerifyAPIKey", "OAuthV2", "VerifyJWT", "VerifyJWS",
            "BasicAuthentication", "ValidateSAMLAssertion", "HMAC", "AccessControl", "Ldap");
    private static final Set<String> THREAT_PROTECTION = Set.of("JSONThreatProtection", "XMLThreatProtection",
            "RegularExpressionProtection", "OASValidation", "MessageValidation");
    private static final Set<String> WEAK_PROTOCOLS = Set.of("SSLv3", "TLSv1", "TLSv1.1");

    private SecurityRules() {
    }

    static List<Rule> all() {
        return List.of(
                new Rule("SEC-01", SECURITY, "No authentication", SecurityRules::authentication),
                new Rule("SEC-02", SECURITY, "No payload threat protection", SecurityRules::threatProtection),
                new Rule("SEC-03", SECURITY, "Credentials in clear text", SecurityRules::hardcodedSecrets),
                new Rule("SEC-04", SECURITY, "KVM secrets visible in Debug", SecurityRules::kvmSecretsVisibleInDebug),
                new Rule("SEC-05", SECURITY, "Backend TLS", SecurityRules::backendTls),
                new Rule("SEC-06", SECURITY, "CORS open to every origin", SecurityRules::permissiveCors));
    }

    private static void authentication(MigrationContext ctx) {
        if (!ctx.isProxy() || usesAny(ctx, AUTHENTICATION)) return;
        ctx.manual(WARN, ctx.report.name(), "No authentication policy in the proxy or in the shared flows it calls",
                "Verify the caller in the ProxyEndpoint PreFlow (VerifyAPIKey, OAuthV2, VerifyJWT), unless a flow"
                        + " hook already does it (flow hooks are not visible from the bundle).",
                MigrationContext.wholeBundle());
    }

    private static void threatProtection(MigrationContext ctx) {
        if (!ctx.isProxy() || usesAny(ctx, THREAT_PROTECTION)) return;
        ctx.manual(INFO, ctx.report.name(), "No payload threat protection in the proxy or its shared flows",
                "Add JSONThreatProtection / XMLThreatProtection (or OASValidation) on requests that carry a body.",
                MigrationContext.wholeBundle());
    }

    /** True when an active policy of one of the types runs in the bundle or in a shared flow it calls. */
    private static boolean usesAny(MigrationContext ctx, Set<String> types) {
        List<BundleReport> chain = new ArrayList<>(List.of(ctx.report));
        chain.addAll(ctx.reachable(ctx.report));
        return chain.stream().flatMap(r -> r.policies().stream())
                .anyMatch(p -> p.active() && types.contains(p.type()));
    }

    private static void hardcodedSecrets(MigrationContext ctx) throws IOException {
        String action = "Move the value to an encrypted KVM, read it into a private.* variable, and rotate it:"
                + " it is in source control and in every bundle export.";
        for (Policy policy : ctx.policies("AssignMessage")) {
            Element root = ctx.xml(policy);
            List<String> found = new ArrayList<>();
            for (String element : List.of("Header", "QueryParam", "FormParam")) {
                for (Element param : Xml.descendants(root, element)) {
                    String name = Xml.attr(param, "name");
                    String value = Xml.text(param);
                    if (name != null && secret(name, value)) found.add(element + " " + name);
                }
            }
            for (Element variable : Xml.descendants(root, "AssignVariable")) {
                String name = Xml.text(variable, "Name");
                if (name != null && secret(name, Xml.text(variable, "Value"))) {
                    found.add("variable " + name);
                }
            }
            if (!found.isEmpty()) {
                ctx.manual(ERROR, policy.name(), "Credentials in clear text: " + names(found), action, ctx.on(policy));
            }
        }
        for (Policy policy : ctx.policies("KeyValueMapOperations")) {
            List<String> keys = new ArrayList<>();
            for (Element entry : Xml.descendants(ctx.xml(policy), "Entry")) {
                String key = Xml.descendants(entry, "Parameter").stream().map(Xml::text)
                        .reduce((a, b) -> a + "." + b).orElse("");
                if (SECRET.matcher(key).find() && Xml.text(entry, "Value") != null) keys.add(key);
            }
            if (!keys.isEmpty()) {
                ctx.manual(ERROR, policy.name(), "InitialEntries ship secret values in the bundle: " + names(keys),
                        "Remove the InitialEntries and load the values into the KVM with the management API.",
                        ctx.on(policy));
            }
        }
        for (String file : ctx.workspace.resources("jsc")) {
            Matcher matcher = JS_SECRET.matcher(ctx.workspace.read(file));
            List<String> hits = new ArrayList<>();
            while (matcher.find()) {
                if (!locator(matcher.group(1), matcher.group(2))) hits.add(matcher.group().replace(matcher.group(2), "***"));
            }
            if (hits.isEmpty()) continue;
            List<Finding.Subject> subjects = new ArrayList<>(ctx.onFile(file));
            for (Scripts.Script script : Scripts.of(ctx.report)) {
                if (script.file().equals(file)) subjects.addAll(ctx.on(script));
            }
            ctx.manual(ERROR, file, "Credentials in clear text: " + names(hits), action, subjects);
        }
        for (Dependency dependency : ctx.report.dependencies()) {
            if (dependency.kind() == DependencyKind.TARGET_URL && URL_CREDENTIALS.matcher(dependency.name()).find()) {
                ctx.manual(ERROR, HybridRules.users(dependency), "Credentials embedded in a URL", action,
                        ctx.on(dependency));
            }
        }
    }

    /** A literal value under a secret-looking name, unless it is where the secret lives (tokenUrl = "https://..."). */
    private static boolean secret(String name, String value) {
        return value != null && !value.contains("{") && SECRET.matcher(name).find() && !locator(name, value);
    }

    /** URLs, paths and names of endpoints: {@code tokenUrl}, {@code token_endpoint}, {@code "/oauth/token"}. */
    private static boolean locator(String name, String value) {
        return value.contains("://") || value.startsWith("/")
                || name.matches("(?i).*(url|uri|endpoint|host|path)");
    }

    private static void kvmSecretsVisibleInDebug(MigrationContext ctx) throws IOException {
        for (Policy policy : ctx.policies("KeyValueMapOperations")) {
            for (Element get : Xml.children(ctx.xml(policy), "Get")) {
                String assignTo = Xml.attr(get, "assignTo");
                if (assignTo == null || assignTo.startsWith("private.") || !SECRET.matcher(assignTo).find()) continue;
                ctx.manual(WARN, policy.name(), "Secret read from the KVM into " + assignTo
                                + ", which is visible in Debug sessions",
                        "Assign it to private." + assignTo + " and update the policies that read it.",
                        ctx.on(policy));
            }
        }
    }

    private static void backendTls(MigrationContext ctx) throws IOException {
        for (String file : ctx.workspace.xmlFiles("targets")) {
            Element root = ctx.workspace.root(file);
            tls(ctx, "TargetEndpoint " + Xml.nameOf(root), Xml.path(root, "HTTPTargetConnection"), ctx.onFile(file));
        }
        for (Policy policy : ctx.policies("ServiceCallout")) {
            tls(ctx, policy.name(), Xml.path(ctx.xml(policy), "HTTPTargetConnection"), ctx.on(policy));
        }
    }

    private static void tls(MigrationContext ctx, String location, Element connection,
                            List<Finding.Subject> subjects) {
        if (connection == null) return;
        String url = Xml.text(connection, "URL");
        Element ssl = Xml.path(connection, "SSLInfo");
        boolean sslEnabled = ssl != null && "true".equalsIgnoreCase(Xml.text(ssl, "Enabled"));
        if (url != null && url.startsWith("http://")) {
            ctx.manual(INFO, location, "Backend called over plain HTTP: " + url,
                    "Use HTTPS if the backend leaves the cluster network.", subjects);
        }
        if ((sslEnabled || (url != null && url.startsWith("https://"))) && Xml.text(ssl, "TrustStore") == null) {
            ctx.manual(WARN, location, "TLS to the backend without a truststore: its certificate is not verified",
                    "Add a TrustStore (through a reference) holding the backend CA, and set IgnoreValidationErrors"
                            + " to false.", subjects);
        }
        List<String> weak = Xml.descendants(ssl, "Protocol").stream().map(Xml::text)
                .filter(WEAK_PROTOCOLS::contains).toList();
        if (!weak.isEmpty()) {
            ctx.manual(WARN, location, "Obsolete TLS protocols allowed: " + names(weak), "Allow TLSv1.2 and TLSv1.3 only.",
                    subjects);
        }
    }

    private static void permissiveCors(MigrationContext ctx) throws IOException {
        for (Policy policy : ctx.policies("AssignMessage")) {
            for (Element header : Xml.descendants(ctx.xml(policy), "Header")) {
                if ("access-control-allow-origin".equalsIgnoreCase(Xml.attr(header, "name"))
                        && "*".equals(Xml.text(header))) {
                    ctx.manual(WARN, policy.name(), "CORS allows every origin (Access-Control-Allow-Origin: *)",
                            "Use the CORS policy with the explicit list of allowed origins.", ctx.on(policy));
                }
            }
        }
    }
}
