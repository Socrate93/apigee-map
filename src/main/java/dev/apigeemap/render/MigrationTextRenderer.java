package dev.apigeemap.render;

import dev.apigeemap.migration.BundleMigration;
import dev.apigeemap.migration.EnvResource;
import dev.apigeemap.migration.Finding;
import dev.apigeemap.migration.MigrationReport;
import dev.apigeemap.model.Issue;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

public final class MigrationTextRenderer {

    public String render(MigrationReport report) {
        StringBuilder out = new StringBuilder();
        String title = "Migration to Apigee hybrid: " + report.name();
        out.append(title).append('\n').append("═".repeat(title.length())).append('\n');
        out.append(!report.applied() ? "Dry run: nothing written (pass --out <dir> to write the migrated bundles)"
                : report.outputDir() == null ? "Auto-fixes applied to the bundles themselves"
                : "Migrated bundles written to " + report.outputDir()).append('\n');

        List<Finding> findings = report.findings();
        section(out, "Summary");
        out.append(String.format("  %-22s %d%n", "Bundles", report.bundles().size()));
        out.append(String.format("  %-22s %d errors, %d warnings, %d info%n", "Findings",
                count(findings, Issue.Severity.ERROR), count(findings, Issue.Severity.WARN),
                count(findings, Issue.Severity.INFO)));
        long auto = findings.stream().filter(f -> f.fix() == Finding.Fix.AUTO).count();
        out.append(String.format("  %-22s %d %s, %d manual%n", "Fixes", auto,
                report.applied() ? "applied" : "automatic", findings.size() - auto));
        Map<Finding.Category, Integer> byCategory = new EnumMap<>(Finding.Category.class);
        findings.forEach(f -> byCategory.merge(f.category(), 1, Integer::sum));
        byCategory.forEach((category, n) -> out.append(String.format("  %-22s %d%n", category.label(), n)));

        for (BundleMigration bundle : report.bundles()) {
            section(out, bundle.name() + " (" + bundle.type().label() + ")");
            if (bundle.findings().isEmpty()) out.append("  No findings.\n");
            for (Finding finding : bundle.findings()) {
                out.append(String.format("  %-5s %-7s %-6s %s: %s%n", finding.severity(), finding.rule(),
                        fixLabel(finding, report.applied()), finding.location(), finding.message()));
                out.append("                       → ").append(finding.action()).append('\n');
            }
            if (!bundle.changes().isEmpty()) {
                out.append("\n  ").append(report.applied() ? "Changes" : "Changes to apply").append('\n');
                bundle.changes().forEach(c -> out.append("    • ").append(c).append('\n'));
            }
            if (bundle.output() != null) out.append("\n  Written to ").append(bundle.output()).append('\n');
        }

        section(out, "To create in the hybrid organization / environments (" + report.resources().size() + ")");
        for (EnvResource resource : report.resources()) {
            out.append(String.format("  %-28s %-30s %s%n", resource.kind(), resource.name(), resource.details()));
        }
        return out.toString();
    }

    static String fixLabel(Finding finding, boolean applied) {
        if (finding.fix() == Finding.Fix.MANUAL) return "manual";
        return applied ? "fixed" : "auto";
    }

    private static long count(List<Finding> findings, Issue.Severity severity) {
        return findings.stream().filter(f -> f.severity() == severity).count();
    }

    private static void section(StringBuilder out, String title) {
        out.append('\n').append(title).append('\n').append("─".repeat(title.length())).append('\n');
    }
}
