package dev.apigeemap;

import dev.apigeemap.analysis.BundleAnalyzer;
import dev.apigeemap.analysis.BundleLocator;
import dev.apigeemap.analysis.SharedFlowRepository;
import dev.apigeemap.migration.BundleMigration;
import dev.apigeemap.migration.Finding;
import dev.apigeemap.migration.MigrationReport;
import dev.apigeemap.migration.Migrator;
import dev.apigeemap.model.BundleReport;
import dev.apigeemap.model.Issue;
import dev.apigeemap.render.MigrationHtmlRenderer;
import dev.apigeemap.render.MigrationTextRenderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MigratorTest {

    private static final Path ORDERS = Path.of("examples/orders-api");
    private static final Path LEGACY = Path.of("examples/legacy-edge-api");
    private static final Path SHARED_FLOWS = Path.of("examples/sharedflows");

    @TempDir
    Path tmp;

    @Test
    void rewritesOrdersApiAndItsSharedFlows() throws IOException {
        Path out = tmp.resolve("out");
        MigrationReport report = new Migrator().migrate(analyze(ORDERS, true), out);

        assertTrue(report.applied());
        assertEquals(List.of("orders-api", "sf-logging", "sf-security"),
                report.bundles().stream().map(BundleMigration::name).toList());
        Path proxy = out.resolve("orders-api/apiproxy");
        assertTrue(Files.isRegularFile(out.resolve("sharedflows/sf-logging/sharedflowbundle/sf-logging.xml")));

        String endpoint = Files.readString(proxy.resolve("proxies/default.xml"));
        assertFalse(endpoint.contains("<VirtualHost>"));
        assertTrue(endpoint.contains("<BasePath>/v1/orders</BasePath>"));

        String legacy = Files.readString(proxy.resolve("targets/legacy.xml"));
        assertFalse(legacy.contains("<URL>"));
        assertTrue(legacy.contains("<Server name=\"ts-legacy-orders-internal-8080\"/>"));
        assertTrue(legacy.contains("<Path>/orders</Path>"));
        assertTrue(Files.readString(out.resolve("targetservers.json")).contains("\"port\": 8080"));

        assertFalse(Files.exists(proxy.resolve("policies/KVM-Legacy-Unused.xml")));
        assertTrue(Files.exists(ORDERS.resolve("apiproxy/policies/KVM-Legacy-Unused.xml")), "source is untouched");
        assertTrue(Files.readString(ORDERS.resolve("apiproxy/proxies/default.xml")).contains("<VirtualHost>"));
        assertEquals(Files.readString(ORDERS.resolve("apiproxy/policies/LC-Orders.xml")),
                Files.readString(proxy.resolve("policies/LC-Orders.xml")), "untouched files are copied as-is");
    }

    @Test
    void reportsLoggingReachedThroughNestedSharedFlows() throws IOException {
        MigrationReport report = new Migrator().migrate(analyze(ORDERS, true), null);
        Finding logging = find(report, "PERF-01");
        assertEquals("FC-Security", logging.location());
        assertTrue(logging.message().contains("sf-security › sf-logging › ML-Syslog"));
        assertTrue(logging.message().contains("PreFlow"));
        assertTrue(report.findings().stream().noneMatch(f -> f.rule().equals("SEC-01")), "VerifyAPIKey is present");
    }

    @Test
    void listsWhatHybridNeeds() throws IOException {
        MigrationReport report = new Migrator().migrate(analyze(ORDERS, true), null);
        assertTrue(hasResource(report, "KVM", "orders-config"));
        assertTrue(hasResource(report, "KVM", "security-secrets"), "dependencies of shared flows are included");
        assertTrue(hasResource(report, "Shared flow", "sf-logging"));
        assertTrue(hasResource(report, "Reference", "orders-keystore-ref"));
        assertTrue(hasResource(report, "Environment group hostnames", "partners"));
        assertTrue(hasResource(report, "Target server (new)", "ts-legacy-orders-internal-8080"));
        assertTrue(hasResource(report, "Outbound connection", "syslog.internal:514"));
        assertFalse(hasResource(report, "KVM", "legacy-config"), "unused policies need nothing");
    }

    @Test
    void handlesEdgeOnlyFeatures() throws IOException {
        Path out = tmp.resolve("legacy");
        MigrationReport report = new Migrator().migrate(analyze(LEGACY, false), out);
        Path proxy = out.resolve("legacy-edge-api/apiproxy");

        String dataCapture = Files.readString(proxy.resolve("policies/Stats-Orders.xml"));
        assertTrue(dataCapture.contains("<DataCapture name=\"Stats-Orders\""));
        assertTrue(dataCapture.contains("<DataCollector>dc_orderTotal</DataCollector>"));
        assertTrue(dataCapture.contains("<Collect ref=\"order.total\" default=\"0\"/>"));
        assertTrue(hasResource(report, "Data collector", "dc_partnerId"));

        String descriptor = Files.readString(proxy.resolve("legacy-edge-api.xml"));
        assertFalse(descriptor.contains("AM-Unused"));
        assertTrue(descriptor.startsWith("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<APIProxy"));

        assertManual(report, "HYB-03", Issue.Severity.ERROR, "CRL-Backend");
        assertManual(report, "HYB-04", Issue.Severity.ERROR, "TargetEndpoint node");
        assertManual(report, "HYB-05", Issue.Severity.ERROR, "ML-File");
        assertTrue(report.hasOpenErrors());
    }

    @Test
    void findsSecurityAndPerformanceAntiPatterns() throws IOException {
        MigrationReport report = new Migrator().migrate(analyze(LEGACY, false), null);
        assertManual(report, "SEC-01", Issue.Severity.WARN, "legacy-edge-api");
        assertManual(report, "SEC-03", Issue.Severity.ERROR, "AM-Partner-Auth");
        Finding jsSecret = report.findings().stream()
                .filter(f -> f.rule().equals("SEC-03") && f.location().endsWith("call-inventory.js"))
                .findFirst().orElseThrow();
        assertFalse(jsSecret.message().contains("a1b2c3d4e5f6"), "secret values are masked in the report");
        assertManual(report, "SEC-04", Issue.Severity.WARN, "KVM-Get-Token");
        assertManual(report, "SEC-06", Issue.Severity.WARN, "AM-CORS");
        assertTrue(report.findings().stream().anyMatch(f -> f.rule().equals("SEC-05") && f.message().contains("TLSv1")));
        assertManual(report, "PERF-02", Issue.Severity.WARN, "JS-Call-Inventory");
        assertManual(report, "PERF-03", Issue.Severity.INFO, "JS-Set-Flags");
        assertManual(report, "PERF-04", Issue.Severity.WARN, "Py-Legacy");
        assertTrue(find(report, "DES-03").message().contains("request.verb = \"POST\""));
    }

    @Test
    void dryRunWritesNothingAndKeepsAutoFixesAsOpenErrors() throws IOException {
        MigrationReport report = new Migrator().migrate(analyze(LEGACY, false), null);
        assertFalse(report.applied());
        assertEquals(Finding.Fix.AUTO, find(report, "HYB-01").fix());
        assertTrue(report.hasOpenErrors());
        assertTrue(new MigrationTextRenderer().render(report).contains("Changes to apply"));
        assertTrue(new MigrationHtmlRenderer().render(report).contains("data-filter=\"category=HYBRID\""));
    }

    @Test
    void refusesANonEmptyOutputFolder() throws IOException {
        Files.writeString(tmp.resolve("existing.txt"), "keep me");
        BundleReport analysis = analyze(ORDERS, false);
        assertThrows(IOException.class, () -> new Migrator().migrate(analysis, tmp));
    }

    @Test
    void migrateCommandWritesBundlesAndFailsStrictOnManualErrors() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        Path report = tmp.resolve("report.html");
        int code = Main.run(new String[]{"migrate", LEGACY.toString(), "--out", tmp.resolve("out").toString(),
                "-o", report.toString(), "--strict"}, new PrintStream(out), new PrintStream(err));
        assertEquals(3, code);
        assertTrue(Files.readString(report).startsWith("<!doctype html>"));
        assertTrue(Files.isDirectory(tmp.resolve("out/legacy-edge-api/apiproxy")));

        int ok = Main.run(new String[]{"migrate", ORDERS.toString(), "-s", SHARED_FLOWS.toString(), "--strict"},
                new PrintStream(out), new PrintStream(err));
        assertEquals(0, ok);
    }

    private static BundleReport analyze(Path bundle, boolean withSharedFlows) throws IOException {
        SharedFlowRepository repository = withSharedFlows
                ? SharedFlowRepository.scan(List.of(SHARED_FLOWS))
                : SharedFlowRepository.empty();
        return new BundleAnalyzer(repository).analyze(BundleLocator.locate(bundle));
    }

    private static Finding find(MigrationReport report, String rule) {
        return report.findings().stream().filter(f -> f.rule().equals(rule)).findFirst()
                .orElseThrow(() -> new AssertionError(rule + " not reported"));
    }

    private static void assertManual(MigrationReport report, String rule, Issue.Severity severity, String location) {
        assertTrue(report.findings().stream().anyMatch(f -> f.rule().equals(rule) && f.severity() == severity
                        && f.fix() == Finding.Fix.MANUAL && f.location().equals(location)),
                rule + " " + severity + " on " + location);
    }

    private static boolean hasResource(MigrationReport report, String kind, String name) {
        return report.resources().stream().anyMatch(r -> r.kind().equals(kind) && r.name().equals(name));
    }
}
