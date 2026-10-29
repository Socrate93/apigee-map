package dev.apigeemap.migration;

import dev.apigeemap.model.Issue;

import java.util.List;

/**
 * One migration finding. {@code fix} tells whether the migrator rewrites the bundle itself ({@link Fix#AUTO})
 * or a person has to act ({@link Fix#MANUAL}); {@code action} says what to do in either case.
 *
 * @param subjects the files the finding is about (policies, endpoints, scripts), declared by the rule; empty when
 *                 it is about the whole bundle
 */
public record Finding(String rule, Category category, Issue.Severity severity, String bundle, String location,
                      String message, String action, Fix fix, List<Subject> subjects) {

    /** A file of a bundle of the migration: {@code file} is bundle-relative, e.g. {@code policies/JS-Audit.xml}. */
    public record Subject(String bundle, String file) {
    }

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
