package dev.apigeemap.migration;

import dev.apigeemap.analysis.ScriptAnalyzer;
import dev.apigeemap.analysis.Xml;
import dev.apigeemap.model.Attachment;
import dev.apigeemap.model.BundleReport;
import dev.apigeemap.model.Dependency;
import dev.apigeemap.model.DependencyKind;
import dev.apigeemap.model.Policy;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static dev.apigeemap.migration.Finding.Category.PERFORMANCE;
import static dev.apigeemap.model.Issue.Severity.INFO;
import static dev.apigeemap.model.Issue.Severity.WARN;

final class PerformanceRules {

    private static final Pattern COMMENTS = Pattern.compile("//[^\\n]*|/\\*.*?\\*/", Pattern.DOTALL);
    /** {@code context.setVariable('name', 'literal');} */
    private static final Pattern SET_LITERAL = Pattern.compile(
            "context\\.setVariable\\(\\s*(['\"])[^'\"]+\\1\\s*,\\s*(['\"])[^'\"]*\\2\\s*\\)\\s*;?");

    private PerformanceRules() {
    }

    static List<Rule> all() {
        return List.of(
                new Rule("PERF-01", PERFORMANCE, "Logging outside the PostClientFlow",
                        PerformanceRules::loggingOutsidePostClientFlow),
                new Rule("PERF-02", PERFORMANCE, "Blocking httpClient calls in JavaScript",
                        PerformanceRules::blockingHttpClient),
                new Rule("PERF-03", PERFORMANCE, "JavaScript that only assigns constants",
                        PerformanceRules::javascriptForAssignments),
                new Rule("PERF-04", PERFORMANCE, "Python Script policies", PerformanceRules::pythonScripts),
                new Rule("PERF-05", PERFORMANCE, "Quota not distributed or synchronous", PerformanceRules::quotas),
                new Rule("PERF-06", PERFORMANCE, "Cache entries without expiry", PerformanceRules::cacheExpiry));
    }

    /**
     * MessageLogging delays the response unless it runs in the PostClientFlow, after the response is sent.
     * Checked in API proxies, directly and through FlowCallouts to shared flows that log.
     */
    private static void loggingOutsidePostClientFlow(MigrationContext ctx) throws IOException {
        if (!ctx.isProxy()) return;
        String action = "Attach the logging to the ProxyEndpoint PostClientFlow so it runs after the response is sent.";
        for (Policy policy : ctx.policies("MessageLogging")) {
            String flows = blockingFlows(policy);
            if (flows != null) ctx.manual(WARN, policy.name(), "MessageLogging runs in " + flows, action);
        }
        for (Policy policy : ctx.policies("FlowCallout")) {
            String flows = blockingFlows(policy);
            String sharedFlow = Xml.text(ctx.xml(policy), "SharedFlowBundle");
            if (flows == null || sharedFlow == null) continue;
            List<String> chain = loggingChain(ctx, sharedFlow, new HashSet<>());
            if (chain == null) continue;
            ctx.manual(WARN, policy.name(), "Logs through " + String.join(" › ", chain) + " from " + flows,
                    action + " Split the logging out of the shared flow if it also does other work.");
        }
    }

    /** Flows other than PostClientFlow the policy runs in, or null. */
    private static String blockingFlows(Policy policy) {
        if (!policy.active()) return null;
        String flows = policy.attachments().stream()
                .map(Attachment::flow)
                .filter(f -> !f.equals("PostClientFlow"))
                .distinct()
                .collect(Collectors.joining(", "));
        return flows.isEmpty() ? null : flows;
    }

    /** Path from the shared flow down to the first active MessageLogging policy, or null. */
    private static List<String> loggingChain(MigrationContext ctx, String sharedFlow, Set<String> visited) {
        BundleReport report = ctx.sharedFlows.get(sharedFlow);
        if (report == null || !visited.add(sharedFlow)) return null;
        for (Policy policy : report.policies()) {
            if (policy.active() && policy.type().equals("MessageLogging")) return List.of(sharedFlow, policy.name());
        }
        for (Dependency dependency : report.dependencies()) {
            if (dependency.kind() != DependencyKind.SHARED_FLOW || !dependency.active()) continue;
            List<String> rest = loggingChain(ctx, dependency.name(), visited);
            if (rest != null) {
                List<String> chain = new ArrayList<>(List.of(sharedFlow));
                chain.addAll(rest);
                return chain;
            }
        }
        return null;
    }

    /** Read from the syntax tree, so calls in comments do not count; a text search when the script does not parse. */
    private static void blockingHttpClient(MigrationContext ctx) throws IOException {
        Set<String> reported = new HashSet<>();
        for (Scripts.Script script : Scripts.of(ctx.report)) {
            if (script.python()) continue;
            ScriptAnalyzer.Facts facts = script.facts();
            boolean blocking = facts.error() == null ? facts.httpClient() && facts.waits()
                    : script.source().contains("httpClient") && script.source().contains("waitForComplete");
            if (!blocking || !reported.add(script.policy())) continue;
            ctx.manual(WARN, script.policy(), "JavaScript calls httpClient and blocks on waitForComplete()",
                    "Use a ServiceCallout, or the callback form of httpClient.send without waitForComplete().");
        }
    }

    private static void javascriptForAssignments(MigrationContext ctx) throws IOException {
        for (Policy policy : ctx.policies("Javascript")) {
            String script = script(ctx, policy);
            if (script == null) continue;
            String code = COMMENTS.matcher(script).replaceAll("");
            if (!code.contains("setVariable") || !SET_LITERAL.matcher(code).replaceAll("").isBlank()) continue;
            ctx.manual(INFO, policy.name(), "JavaScript only assigns literal values to variables",
                    "Replace it with an AssignMessage policy (AssignVariable): no script engine call per request.");
        }
    }

    private static void pythonScripts(MigrationContext ctx) {
        for (Policy policy : ctx.policies("Script")) {
            if (!policy.attached()) continue;
            ctx.manual(WARN, policy.name(), "Python Script policy runs on an embedded Jython interpreter",
                    "Rewrite it in JavaScript or as a Java callout: Jython is slow and limited to Python 2 syntax.");
        }
    }

    /**
     * A Quota that is not distributed counts per runtime instance, so the real limit grows with the number of pods;
     * a synchronous one updates the shared counter on every call, which adds latency.
     */
    private static void quotas(MigrationContext ctx) throws IOException {
        for (Policy policy : ctx.policies("Quota")) {
            if (!policy.attached()) continue;
            String distributed = Xml.text(ctx.xml(policy), "Distributed");
            if (!"true".equalsIgnoreCase(distributed)) {
                ctx.manual(WARN, policy.name(), "Quota is not distributed: each runtime instance counts on its own",
                        "Set <Distributed>true</Distributed>, or the effective limit grows with the number of"
                                + " runtime pods.");
            }
            if ("true".equalsIgnoreCase(Xml.text(ctx.xml(policy), "Synchronous"))) {
                ctx.manual(WARN, policy.name(), "Quota updates its counter synchronously on every call",
                        "Remove <Synchronous>true</Synchronous> unless the limit must be exact: the default"
                                + " asynchronous update avoids the extra latency.");
            }
        }
    }

    private static void cacheExpiry(MigrationContext ctx) throws IOException {
        for (String type : List.of("PopulateCache", "ResponseCache")) {
            for (Policy policy : ctx.policies(type)) {
                if (!policy.attached() || Xml.path(ctx.xml(policy), "ExpirySettings") != null) continue;
                ctx.manual(WARN, policy.name(), type + " has no ExpirySettings",
                        "Set ExpirySettings (TimeoutInSec, TimeOfDay or ExpiryDate): entries without one stay"
                                + " until evicted and can serve stale data.");
            }
        }
    }

    /** Main script of a Javascript policy, when it is in the bundle. */
    private static String script(MigrationContext ctx, Policy policy) throws IOException {
        String url = Xml.text(ctx.xml(policy), "ResourceURL");
        if (url == null || !url.startsWith("jsc://")) return null;
        String file = "resources/jsc/" + url.substring("jsc://".length());
        return ctx.workspace.exists(file) ? ctx.workspace.read(file) : null;
    }
}
