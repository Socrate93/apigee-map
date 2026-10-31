package dev.apigeemap.migration;

import dev.apigeemap.analysis.BundleAnalyzer;
import dev.apigeemap.analysis.BundleLocator;
import dev.apigeemap.analysis.SharedFlowRepository;
import dev.apigeemap.model.BundleReport;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TestTargetsTest {

    private static final Path ORDERS = Path.of("examples/orders-api");
    private static final Path SHARED_FLOWS = Path.of("examples/sharedflows");

    @Test
    void readsWhatAPlanMustCoverFromTheProxyAndItsSharedFlows() throws IOException {
        List<TestTargets.Target> targets = orders();

        assertEquals(List.of(
                "flow:default/getOrder",
                "route:default/legacy",
                "faultRule:default/invalid-key",
                "change:HYB-02:orders-api/proxies/default.xml",
                "change:HYB-06:orders-api/policies/JS-Format.xml",
                "change:HYB-07:orders-api/targets/default.xml",
                "change:DES-01:orders-api/targets/legacy.xml",
                "check:orders-api/Verify-API-Key",
                "callout:orders-api/SC-Customer",
                "script:orders-api/JS-Format",
                "condition:sf-security/FC-Logging"), targets.stream().map(TestTargets.Target::id).toList(),
                "the steps that share the condition of their flow, and the findings about a policy no flow runs, "
                        + "are not points of their own");
        assertEquals("Route rule legacy to legacy [request.header.X-Legacy = \"true\"]", targets.get(1).description());
        assertTrue(targets.get(10).description().startsWith("FlowCallout FC-Logging of the shared flow sf-security"));
        assertEquals("sf-security", targets.get(10).bundle());
    }

    @Test
    void tellsThePointsNoCaseCovers() throws IOException {
        List<TestTargets.Target> targets = orders();
        TestPlans.Plan plan = TestPlans.plan(Map.of("summary", "Covers the orders.", "cases", List.of(
                Map.of("name", "Get an order", "method", "GET", "path", "/v1/orders/1",
                        "purpose", "Checks that the order is returned with its customer.",
                        "covers", List.of("flow:default/getOrder", "callout:orders-api/SC-Customer",
                                "flow:default/getOrder")),
                Map.of("name", "No key", "method", "GET", "path", "/v1/orders/1",
                        "covers", List.of("check:orders-api/Verify-API-Key", "faultRule:default/invalid-key")))));

        assertEquals(List.of("flow:default/getOrder", "callout:orders-api/SC-Customer"), plan.cases().get(0).covers());
        assertEquals("Checks that the order is returned with its customer.", plan.cases().get(0).purpose());
        assertEquals(List.of("route:default/legacy", "change:HYB-02:orders-api/proxies/default.xml",
                "change:HYB-06:orders-api/policies/JS-Format.xml", "change:HYB-07:orders-api/targets/default.xml",
                "change:DES-01:orders-api/targets/legacy.xml", "script:orders-api/JS-Format",
                "condition:sf-security/FC-Logging"), TestTargets.uncovered(targets, plan).stream()
                .map(TestTargets.Target::id).toList());
    }

    private static List<TestTargets.Target> orders() throws IOException {
        SharedFlowRepository repository = SharedFlowRepository.scan(List.of(SHARED_FLOWS));
        BundleReport analysis = new BundleAnalyzer(repository).analyze(BundleLocator.locate(ORDERS));
        List<Finding> findings = new Migrator(MigrationOptions.DEFAULT, repository).migrate(analysis, null).findings();
        return TestTargets.of(analysis, findings);
    }
}
