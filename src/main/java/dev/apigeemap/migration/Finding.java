package dev.apigeemap.migration;

import dev.apigeemap.model.Issue;

/**
 * One migration finding. {@code fix} tells whether the migrator rewrites the bundle itself ({@link Fix#AUTO})
 * or a person has to act ({@link Fix#MANUAL}); {@code action} says what to do in either case.
 */
public record Finding(String rule, Category category, Issue.Severity severity, String bundle, String location,
                      String message, String action, Fix fix) {

    public enum Category {
        HYBRID("Hybrid compatibility"),
        SECURITY("Security"),
        PERFORMANCE("Performance"),
        DESIGN("Design");

        private final String label;

        Category(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }
    }

    public enum Fix { AUTO, MANUAL }
}
