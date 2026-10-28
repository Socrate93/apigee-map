package dev.apigeemap.migration;

/** Public description of a migration rule, for settings screens and documentation. */
public record RuleInfo(String id, Finding.Category category, String title, boolean autoFix) {
}
