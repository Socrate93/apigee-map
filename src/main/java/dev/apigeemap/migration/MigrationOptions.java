package dev.apigeemap.migration;

import dev.apigeemap.model.Issue;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Tuning of a migration run.
 *
 * @param disabledRules   rule ids not to run (their auto-fixes are not applied either)
 * @param severities      severity overrides by rule id
 * @param namingPrefixes  accepted policy name prefixes by policy type, replacing the defaults of that type
 */
public record MigrationOptions(Set<String> disabledRules, Map<String, Issue.Severity> severities,
                               Map<String, List<String>> namingPrefixes) {

    public static final MigrationOptions DEFAULT = new MigrationOptions(Set.of(), Map.of(), Map.of());

    public MigrationOptions {
        disabledRules = Set.copyOf(disabledRules);
        severities = Map.copyOf(severities);
        namingPrefixes = Map.copyOf(namingPrefixes);
    }
}
