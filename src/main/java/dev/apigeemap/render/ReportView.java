package dev.apigeemap.render;

import dev.apigeemap.model.BundleReport;
import dev.apigeemap.model.Dependency;
import dev.apigeemap.model.Issue;
import dev.apigeemap.model.SharedFlowLink;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/** Views across a report and the shared flows it calls (each shared flow is visited once). */
public final class ReportView {

    /** A dependency together with the chain of shared flows it comes through (empty when direct). */
    public record FlatDependency(Dependency dependency, List<String> via) {
    }

    public record BundleIssue(String bundle, Issue issue) {
    }

    private ReportView() {
    }

    public static List<FlatDependency> flatten(BundleReport report) {
        List<FlatDependency> result = new ArrayList<>();
        flatten(report, List.of(), result, new HashSet<>());
        return result;
    }

    private static void flatten(BundleReport report, List<String> via, List<FlatDependency> out, Set<String> visited) {
        report.dependencies().forEach(d -> out.add(new FlatDependency(d, via)));
        for (SharedFlowLink link : report.sharedFlows()) {
            if (link.report() == null || !visited.add(link.name())) continue;
            List<String> next = new ArrayList<>(via);
            next.add(link.name());
            flatten(link.report(), List.copyOf(next), out, visited);
        }
    }

    public static List<BundleIssue> allIssues(BundleReport report) {
        List<BundleIssue> result = new ArrayList<>();
        collectIssues(report, result, new HashSet<>());
        return result;
    }

    private static void collectIssues(BundleReport report, List<BundleIssue> out, Set<String> visited) {
        report.issues().forEach(issue -> out.add(new BundleIssue(report.name(), issue)));
        for (SharedFlowLink link : report.sharedFlows()) {
            if (link.report() != null && visited.add(link.name())) collectIssues(link.report(), out, visited);
        }
    }

    public static boolean hasErrors(BundleReport report) {
        return allIssues(report).stream().anyMatch(i -> i.issue().severity() == Issue.Severity.ERROR);
    }

    public static String details(Map<String, String> details) {
        return details.entrySet().stream()
                .map(e -> e.getKey() + "=" + e.getValue())
                .collect(Collectors.joining("  "));
    }
}
