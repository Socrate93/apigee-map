package dev.apigeemap.migration;

import dev.apigeemap.model.BundleType;

import java.util.List;

/**
 * Result for one bundle: findings, the changes the auto-fixes make (as a summary and file by file).
 * {@code output} is null in dry run.
 *
 * @param falsePositives the findings left out as false positives, with their reason
 * @param staleFalsePositives false positives of this bundle that matched no finding
 */
public record BundleMigration(String name, BundleType type, String source, String output, List<Finding> findings,
                              List<String> changes, List<FileChange> files,
                              List<FalsePositive.Hidden> falsePositives, List<FalsePositive> staleFalsePositives) {
}
