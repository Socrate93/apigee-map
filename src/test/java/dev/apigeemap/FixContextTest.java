package dev.apigeemap;

import dev.apigeemap.analysis.BundleAnalyzer;
import dev.apigeemap.analysis.BundleLocator;
import dev.apigeemap.analysis.SharedFlowRepository;
import dev.apigeemap.migration.Finding;
import dev.apigeemap.migration.Finding.Subject;
import dev.apigeemap.migration.FixContext;
import dev.apigeemap.migration.FixContext.PolicyContext;
import dev.apigeemap.migration.FixContext.SourceFile;
import dev.apigeemap.migration.FixContext.VariableRead;
import dev.apigeemap.migration.MigrationOptions;
import dev.apigeemap.migration.MigrationReport;
import dev.apigeemap.migration.Migrator;
import dev.apigeemap.model.BundleReport;
import dev.apigeemap.model.Issue;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FixContextTest {

    private static final Path SHARED_FLOWS = Path.of("examples/sharedflows");

    @Test
    void bringsThePolicyItsScriptsItsEndpointAndWhoSetsWhatItReads() throws IOException {
        Map<String, BundleReport> bundles = bundles("examples/orders-api");
        FixContext context = FixContext.of(finding("orders-api", "AM-Backend-Auth",
                new Subject("orders-api", "policies/AM-Backend-Auth.xml")), bundles);

        PolicyContext auth = context.policies().get(0);
        assertEquals("AM-Backend-Auth", auth.name());
        assertEquals(List.of("TargetEndpoint default › PreFlow › Request"), auth.runs());
        VariableRead password = auth.reads().stream().filter(r -> r.variable().equals("private.backend.password"))
                .findFirst().orElseThrow();
        assertEquals("SET", password.source());
        assertEquals(List.of("KVM-Get-Config"), password.steps());
        assertEquals(List.of("policies/AM-Backend-Auth.xml", "targets/default.xml", "policies/KVM-Get-Config.xml"),
                paths(context));
    }

    @Test
    void bringsPoliciesOfTheSharedFlows() throws IOException {
        Map<String, BundleReport> bundles = bundles("examples/orders-api");
        FixContext context = FixContext.of(finding("orders-api", "FC-Security",
                new Subject("orders-api", "policies/FC-Security.xml"),
                new Subject("sf-logging", "policies/ML-Syslog.xml")), bundles);
        assertEquals(List.of("FC-Security", "ML-Syslog"), context.policies().stream().map(PolicyContext::name).toList());
        assertTrue(context.files().stream().anyMatch(f -> f.bundle().equals("sf-logging")
                && f.path().equals("policies/ML-Syslog.xml")));
    }

    @Test
    void givesABundleWideFindingTheDescriptorAndEndpoints() throws IOException {
        Map<String, BundleReport> bundles = bundles("examples/factorization-api");
        FixContext context = FixContext.of(finding("factorization-api", "factorization-api"), bundles);
        assertTrue(context.policies().isEmpty());
        assertEquals(List.of("factorization-api.xml", "proxies/default.xml", "targets/default.xml"), paths(context));
    }

    @Test
    void picksOneFindingOfTheMigration() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        String[] ambiguous = {"context", "examples/factorization-api", "--rule", "HYB-11"};
        assertEquals(1, Main.run(ambiguous, new PrintStream(out), new PrintStream(err)));
        assertTrue(err.toString().contains("3 HYB-11 findings, pick one with --at"), err.toString());

        // JS-Audit is the exact location of one finding, and part of JS-Audit-Copy, the location of another
        String[] args = {"context", "examples/factorization-api", "--rule", "HYB-11", "--at", "JS-Audit"};
        assertEquals(0, Main.run(args, new PrintStream(out), new PrintStream(err)));
        String markdown = out.toString();
        assertTrue(markdown.startsWith("# HYB-11 "), markdown);
        assertTrue(markdown.contains("### factorization-api/resources/jsc/audit.js\n\n```javascript\n"), markdown);
        assertTrue(!markdown.contains("audit-copy.js"), markdown);
    }

    @Test
    void rulesDeclareWhatTheirFindingsAreAbout() throws IOException {
        MigrationReport report = new Migrator(MigrationOptions.DEFAULT, SharedFlowRepository.scan(List.of(SHARED_FLOWS)))
                .migrate(new BundleAnalyzer(SharedFlowRepository.scan(List.of(SHARED_FLOWS)))
                        .analyze(BundleLocator.locate(Path.of("examples/factorization-api"))), null);
        // the location names the scripts only: the policies that run them come from the rule
        Finding copies = report.findings().stream().filter(f -> f.rule().equals("DES-10")
                && f.message().startsWith("Identical")).findFirst().orElseThrow();
        assertEquals(List.of(new Subject("factorization-api", "policies/JS-Audit-Copy.xml"),
                new Subject("factorization-api", "resources/jsc/audit-copy.js"),
                new Subject("factorization-api", "policies/JS-Audit.xml"),
                new Subject("factorization-api", "resources/jsc/audit.js")), copies.subjects());
        FixContext context = FixContext.of(copies, FixContext.bundles(new BundleAnalyzer(SharedFlowRepository.empty())
                .analyze(BundleLocator.locate(Path.of("examples/factorization-api")))));
        assertEquals(List.of("JS-Audit-Copy", "JS-Audit"), context.policies().stream().map(PolicyContext::name).toList());
        assertTrue(paths(context).contains("proxies/default.xml"));

        assertTrue(report.findings().stream().filter(f -> f.rule().startsWith("SEC-0") && f.location()
                .equals("factorization-api")).allMatch(f -> f.subjects().isEmpty()), "bundle-wide findings");
        assertTrue(report.findings().stream().filter(f -> !f.location().equals("factorization-api"))
                .noneMatch(f -> f.subjects().isEmpty()), "every other finding says what it is about");
    }

    private static Map<String, BundleReport> bundles(String bundle) throws IOException {
        return FixContext.bundles(new BundleAnalyzer(SharedFlowRepository.scan(List.of(SHARED_FLOWS)))
                .analyze(BundleLocator.locate(Path.of(bundle))));
    }

    private static Finding finding(String bundle, String location, Subject... subjects) {
        return new Finding("DES-12", Finding.Category.DESIGN, Issue.Severity.INFO, bundle, location, "Something",
                "Fix it", Finding.Fix.MANUAL, List.of(subjects));
    }

    private static List<String> paths(FixContext context) {
        return context.files().stream().map(SourceFile::path).toList();
    }
}
