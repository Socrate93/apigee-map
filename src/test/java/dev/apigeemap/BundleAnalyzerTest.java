package dev.apigeemap;

import dev.apigeemap.analysis.BundleAnalyzer;
import dev.apigeemap.analysis.BundleLocator;
import dev.apigeemap.analysis.SharedFlowRepository;
import dev.apigeemap.model.BundleReport;
import dev.apigeemap.model.BundleType;
import dev.apigeemap.model.Dependency;
import dev.apigeemap.model.DependencyKind;
import dev.apigeemap.model.Issue;
import dev.apigeemap.model.Policy;
import dev.apigeemap.model.SharedFlowLink;
import dev.apigeemap.render.HtmlRenderer;
import dev.apigeemap.render.JsonRenderer;
import dev.apigeemap.render.MermaidRenderer;
import dev.apigeemap.render.ReportView;
import dev.apigeemap.render.TextRenderer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BundleAnalyzerTest {

    private static final Path PROXY = Path.of("examples/orders-api");
    private static final Path SHARED_FLOWS = Path.of("examples/sharedflows");

    private static BundleReport report;

    @BeforeAll
    static void analyze() throws IOException {
        SharedFlowRepository repository = SharedFlowRepository.scan(List.of(SHARED_FLOWS));
        report = new BundleAnalyzer(repository).analyze(BundleLocator.locate(PROXY));
    }

    @Test
    void readsDescriptor() {
        assertEquals(BundleType.API_PROXY, report.type());
        assertEquals("orders-api", report.name());
        assertEquals("3", report.revision());
    }

    @Test
    void findsEndpointDependencies() {
        assertTrue(has(report, DependencyKind.VIRTUAL_HOST, "secure"));
        assertTrue(has(report, DependencyKind.VIRTUAL_HOST, "partners"));
        assertTrue(has(report, DependencyKind.TARGET_SERVER, "orders-backend-1"));
        assertTrue(has(report, DependencyKind.TARGET_SERVER, "orders-backend-dr"));
        assertTrue(has(report, DependencyKind.KEYSTORE, "orders-keystore-ref"));
        assertTrue(has(report, DependencyKind.TRUSTSTORE, "backend-truststore"));
        assertTrue(has(report, DependencyKind.TARGET_URL, "http://legacy-orders.internal:8080/orders"));
    }

    @Test
    void findsPolicyDependencies() {
        Dependency kvm = find(report, DependencyKind.KVM, "orders-config");
        assertEquals("environment", kvm.usages().get(0).details().get("scope"));
        assertEquals("true", kvm.usages().get(0).details().get("encrypted"));
        assertEquals("Flow getOrder", kvm.usages().get(0).attachments().get(0).flow());

        Dependency cache = find(report, DependencyKind.CACHE, "orders-cache");
        assertEquals(2, cache.usages().size());

        assertTrue(find(report, DependencyKind.TARGET_URL,
                "https://customers.internal/api/customers/{request.queryparam.customerId}").dynamic());
        assertTrue(has(report, DependencyKind.RESOURCE, "jsc://format-order.js"));
    }

    @Test
    void marksUnattachedAndDisabledPoliciesInactive() {
        assertFalse(find(report, DependencyKind.KVM, "legacy-config").active());
        Policy quota = report.policies().stream().filter(p -> p.name().equals("Q-Partner")).findFirst().orElseThrow();
        assertFalse(quota.enabled());
        assertTrue(quota.attached());
    }

    @Test
    void resolvesSharedFlowsRecursively() {
        SharedFlowLink security = link(report, "sf-security");
        assertEquals(SharedFlowLink.Status.RESOLVED, security.status());
        assertTrue(has(security.report(), DependencyKind.KVM, "security-secrets"));
        assertTrue(has(security.report(), DependencyKind.CACHE, "(default shared cache)"));

        SharedFlowLink nestedLogging = link(security.report(), "sf-logging");
        assertEquals(SharedFlowLink.Status.RESOLVED, nestedLogging.status());
        assertTrue(has(nestedLogging.report(), DependencyKind.SYSLOG, "syslog.internal:514"));

        assertTrue(ReportView.flatten(report).stream()
                .anyMatch(f -> f.dependency().kind() == DependencyKind.KVM && f.via().equals(List.of("sf-security"))));
    }

    @Test
    void reportsIssues() {
        List<String> messages = ReportView.allIssues(report).stream().map(i -> i.issue().message()).toList();
        assertTrue(messages.stream().anyMatch(m -> m.contains("jsc://common-utils.js")));
        assertTrue(messages.stream().anyMatch(m -> m.contains("KVM-Legacy-Unused is not attached")));
        assertTrue(messages.stream().anyMatch(m -> m.startsWith("Hardcoded URL http://legacy-orders")));
        assertFalse(ReportView.hasErrors(report));
    }

    @Test
    void withoutSharedFlowDirectoryLinksAreNotSearched() throws IOException {
        BundleReport alone = new BundleAnalyzer(SharedFlowRepository.empty()).analyze(BundleLocator.locate(PROXY));
        assertEquals(SharedFlowLink.Status.NOT_SEARCHED, link(alone, "sf-security").status());
        assertTrue(alone.issues().stream().anyMatch(i -> i.severity() == Issue.Severity.INFO
                && i.message().contains("--sharedflows")));
    }

    @Test
    void analyzesASharedFlowOnItsOwn() throws IOException {
        BundleReport sf = new BundleAnalyzer(SharedFlowRepository.empty())
                .analyze(BundleLocator.locate(SHARED_FLOWS.resolve("sf-security")));
        assertEquals(BundleType.SHARED_FLOW, sf.type());
        assertEquals("sf-security", sf.name());
        assertTrue(sf.policies().stream().allMatch(Policy::attached));
    }

    @Test
    void rendersAllFormats() {
        assertTrue(new TextRenderer().render(report).contains("Key value maps"));
        assertTrue(new JsonRenderer().render(report).contains("\"name\": \"orders-api\""));
        String mermaid = new MermaidRenderer().render(report);
        assertTrue(mermaid.startsWith("flowchart LR"));
        assertTrue(mermaid.contains("-.->"), "inactive dependencies are dashed");
        assertTrue(new HtmlRenderer().render(report).contains("class=\"mermaid\""));
    }

    @Test
    void groupsGraphNodesByTypeForClickableClusters() {
        MermaidRenderer.Diagram diagram = new MermaidRenderer().diagram(report);
        assertTrue(diagram.source().contains("subgraph k_KVM[\"Key value maps\"]"));
        assertTrue(diagram.source().contains("subgraph k_SHARED_FLOW[\"Shared flows\"]"));
        assertTrue(diagram.nodeKeys().containsValue("KVM:security-secrets"));
        assertFalse(diagram.nodeKeys().containsValue("API_PROXY:orders-api"), "the analyzed bundle is not in a cluster");

        String html = new HtmlRenderer().render(report);
        assertTrue(html.contains("data-kind=\"KVM\" data-key=\"KVM:orders-config\""));
        assertTrue(html.contains("<button type=\"button\" class=\"card\" data-kind=\"CACHE\">"));
    }

    @Test
    void sharedFlowAnalyzedAsRootStaysOutsideClusters() throws IOException {
        BundleReport sf = new BundleAnalyzer(SharedFlowRepository.scan(List.of(SHARED_FLOWS)))
                .analyze(BundleLocator.locate(SHARED_FLOWS.resolve("sf-security")));
        MermaidRenderer.Diagram diagram = new MermaidRenderer().diagram(sf);
        assertFalse(diagram.nodeKeys().containsValue("SHARED_FLOW:sf-security"));
        assertTrue(diagram.nodeKeys().containsValue("SHARED_FLOW:sf-logging"));
    }

    private static boolean has(BundleReport r, DependencyKind kind, String name) {
        return r.dependencies().stream().anyMatch(d -> d.kind() == kind && d.name().equals(name));
    }

    private static Dependency find(BundleReport r, DependencyKind kind, String name) {
        return r.dependencies().stream()
                .filter(d -> d.kind() == kind && d.name().equals(name))
                .findFirst()
                .orElseThrow(() -> new AssertionError(kind + " " + name + " not found"));
    }

    private static SharedFlowLink link(BundleReport r, String name) {
        SharedFlowLink link = r.sharedFlows().stream().filter(l -> l.name().equals(name)).findFirst().orElse(null);
        assertNotNull(link, "shared flow link " + name);
        return link;
    }
}
