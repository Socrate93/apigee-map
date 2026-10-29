package dev.apigeemap.migration;

import dev.apigeemap.model.Issue;

import java.util.List;

/**
 * Migration of a bundle and of the shared flows it calls. When {@code applied} is false (dry run), AUTO findings
 * are fixable but nothing was written.
 */
public record MigrationReport(String name, boolean applied, String outputDir, List<BundleMigration> bundles,
                              List<EnvResource> resources) {

    public List<Finding> findings() {
        return bundles.stream().flatMap(b -> b.findings().stream()).toList();
    }

    /** Findings left out as false positives, not counted anywhere. */
    public List<FalsePositive.Hidden> falsePositives() {
        return bundles.stream().flatMap(b -> b.falsePositives().stream()).toList();
    }

    /** True when an ERROR still blocks the deployment: a manual one, or any one in dry run. */
    public boolean hasOpenErrors() {
        return findings().stream().anyMatch(f -> f.severity() == Issue.Severity.ERROR
                && (f.fix() == Finding.Fix.MANUAL || !applied));
    }
}
