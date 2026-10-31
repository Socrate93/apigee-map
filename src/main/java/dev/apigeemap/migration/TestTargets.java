package dev.apigeemap.migration;

import dev.apigeemap.analysis.Xml;
import dev.apigeemap.model.Attachment;
import dev.apigeemap.model.BundleReport;
import dev.apigeemap.model.BundleType;
import dev.apigeemap.model.Policy;
import org.w3c.dom.Element;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * What a test plan must cover, read from the proxy and the shared flows it calls rather than left to whoever prepares
 * the plan: the conditional flows, route rules and fault rules of the endpoints, the faults the proxy raises, the
 * OAuth operations, the checks that reject requests, the callouts and scripts, the steps that run only on a
 * condition, and what the migration changes. Each point has an id that stays the same while the files do, which the
 * cases of a plan list in {@link TestPlans.Case#covers()}.
 */
public final class TestTargets {

    /**
     * @param id          stable, e.g. {@code flow:default/GetOrder} or {@code fault:orders/RF-NoKey}
     * @param kind        one of flow, route, faultRule, fault, change, oauth, check, callout, script, condition
     * @param description what to test, for the person reading the plan and for whoever prepares it
     */
    public record Target(String id, String kind, String bundle, String description) {
    }

    /** At most this many points, the first kinds of {@link #ORDER} first. */
    static final int MAX = 80;
    static final int MAX_CHANGES = 25;
    private static final List<String> ORDER = List.of("flow", "route", "faultRule", "fault", "change", "oauth",
            "check", "callout", "script", "condition");
    private static final Set<String> CHECKS = Set.of("VerifyAPIKey", "BasicAuthentication", "AccessControl",
            "JSONThreatProtection", "XMLThreatProtection", "RegularExpressionProtection", "MessageValidation",
            "SpikeArrest", "Quota", "CORS");
    private static final Set<String> CALLOUTS = Set.of("ServiceCallout", "ExternalCallout");
    private static final Set<String> SCRIPTS = Set.of("Javascript", "XSL", "Script");

    private TestTargets() {
    }

    /**
     * The points of the proxy and of its shared flows, and those of the findings of its migration that change
     * how it runs on hybrid or that the migrator rewrites, except those about policies no flow runs.
     */
    public static List<Target> of(BundleReport root, List<Finding> findings) throws IOException {
        Map<String, Target> targets = new LinkedHashMap<>();
        Set<String> unattached = new HashSet<>();
        for (BundleReport bundle : FixContext.bundles(root).values()) {
            Path dir = Path.of(bundle.path());
            // the conditions of the flows and fault rules, which the steps in them share
            Map<String, String> conditions = new HashMap<>();
            for (String folder : List.of("proxies", "targets")) {
                for (Element endpoint : endpoints(dir, folder)) {
                    String key = endpoint.getTagName() + "/" + Xml.nameOf(endpoint) + "/";
                    Xml.children(Xml.path(endpoint, "Flows"), "Flow").forEach(flow -> conditions.put(
                            key + "Flow " + Xml.nameOf(flow), Xml.text(flow, "Condition")));
                    Xml.children(Xml.path(endpoint, "FaultRules"), "FaultRule").forEach(rule -> conditions.put(
                            key + "FaultRule " + Xml.nameOf(rule), Xml.text(rule, "Condition")));
                }
            }
            String where = bundle.type() == BundleType.SHARED_FLOW ? " of the shared flow " + bundle.name() : "";
            for (Element endpoint : endpoints(dir, "proxies")) {
                String name = Xml.nameOf(endpoint);
                Element flows = Xml.path(endpoint, "Flows");
                for (Element flow : Xml.children(flows, "Flow")) {
                    String condition = Xml.text(flow, "Condition");
                    add(targets, new Target("flow:" + name + "/" + Xml.nameOf(flow), "flow", bundle.name(),
                            "Flow " + Xml.nameOf(flow) + " of the ProxyEndpoint " + name
                                    + (condition == null ? ", without a condition" : " [" + condition + "]")));
                }
                for (Element rule : Xml.children(endpoint, "RouteRule")) {
                    String condition = Xml.text(rule, "Condition");
                    if (condition == null) continue;
                    String target = Objects.requireNonNullElse(Xml.text(rule, "TargetEndpoint"),
                            Objects.requireNonNullElse(Xml.text(rule, "URL"), "no target"));
                    add(targets, new Target("route:" + name + "/" + Xml.nameOf(rule), "route", bundle.name(),
                            "Route rule " + Xml.nameOf(rule) + " to " + target + " [" + condition + "]"));
                }
            }
            for (String folder : List.of("proxies", "targets")) {
                for (Element endpoint : endpoints(dir, folder)) {
                    for (Element rule : Xml.children(Xml.path(endpoint, "FaultRules"), "FaultRule")) {
                        String condition = Xml.text(rule, "Condition");
                        add(targets, new Target("faultRule:" + Xml.nameOf(endpoint) + "/" + Xml.nameOf(rule),
                                "faultRule", bundle.name(), "Fault rule " + Xml.nameOf(rule) + " of the "
                                + endpoint.getTagName() + " " + Xml.nameOf(endpoint)
                                + (condition == null ? "" : " [" + condition + "]")));
                    }
                }
            }
            for (Policy policy : bundle.policies()) {
                if (!policy.active()) {
                    unattached.add(bundle.name() + "/" + policy.file());
                    continue;
                }
                String kind = policy.type().equals("RaiseFault") ? "fault"
                        : policy.type().equals("OAuthV2") ? "oauth"
                        : CHECKS.contains(policy.type()) ? "check"
                        : CALLOUTS.contains(policy.type()) ? "callout"
                        : SCRIPTS.contains(policy.type()) ? "script"
                        : policy.attachments().stream().allMatch(a -> ownCondition(a, conditions)) ? "condition"
                        : null;
                if (kind == null) continue;
                add(targets, new Target(kind + ":" + bundle.name() + "/" + policy.name(), kind, bundle.name(),
                        policy.type() + " " + policy.name() + where + " (" + attachments(policy) + ")"));
            }
        }
        findings.stream().filter(f -> f.category() == Finding.Category.HYBRID || f.fix() == Finding.Fix.AUTO)
                .filter(f -> f.subjects().stream().noneMatch(subject -> unattached.contains(subject.bundle() + "/"
                        + subject.file())))
                .limit(MAX_CHANGES).forEach(f -> add(targets, new Target("change:" + f.rule() + ":" + f.bundle()
                        + "/" + (f.subjects().isEmpty() ? f.location() : f.subjects().get(0).file()), "change",
                        f.bundle(), f.message())));
        return targets.values().stream().sorted(Comparator.comparingInt(t -> ORDER.indexOf(t.kind()))).limit(MAX)
                .toList();
    }

    /** The points no case of the plan covers, in their order. */
    public static List<Target> uncovered(List<Target> targets, TestPlans.Plan plan) {
        Set<String> covered = plan.cases().stream().flatMap(c -> c.covers().stream()).collect(Collectors.toSet());
        return targets.stream().filter(t -> !covered.contains(t.id())).toList();
    }

    /** Whether the step runs on a condition of its own, rather than on that of its flow or fault rule only. */
    private static boolean ownCondition(Attachment attachment, Map<String, String> conditions) {
        return attachment.condition() != null && !attachment.condition().equals(conditions.get(
                attachment.endpointType() + "/" + attachment.endpoint() + "/" + attachment.flow()));
    }

    private static void add(Map<String, Target> targets, Target target) {
        targets.putIfAbsent(target.id(), target);
    }

    private static List<Element> endpoints(Path dir, String folder) throws IOException {
        List<Element> roots = new ArrayList<>();
        for (Path file : Xml.xmlFiles(dir.resolve(folder))) roots.add(Xml.parse(file));
        return roots;
    }

    private static String attachments(Policy policy) {
        return policy.attachments().stream().map(Attachment::describe).distinct().limit(3)
                .collect(Collectors.joining("; "));
    }
}
