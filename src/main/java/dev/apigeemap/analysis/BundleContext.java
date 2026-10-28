package dev.apigeemap.analysis;

import dev.apigeemap.model.Issue;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** Mutable state accumulated while analyzing one bundle. */
final class BundleContext {

    final Path dir;
    final DependencyCollector deps = new DependencyCollector();
    final List<Issue> issues = new ArrayList<>();
    final Set<String> sharedFlowRefs = new LinkedHashSet<>();

    BundleContext(Path dir) {
        this.dir = dir;
    }

    void issue(Issue.Severity severity, String message) {
        issues.add(new Issue(severity, message));
    }
}
