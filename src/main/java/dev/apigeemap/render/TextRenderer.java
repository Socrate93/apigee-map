package dev.apigeemap.render;

import dev.apigeemap.model.Attachment;
import dev.apigeemap.model.BundleReport;
import dev.apigeemap.model.Dependency;
import dev.apigeemap.model.DependencyKind;
import dev.apigeemap.model.Endpoint;
import dev.apigeemap.model.Policy;
import dev.apigeemap.model.SharedFlowLink;
import dev.apigeemap.model.Usage;

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class TextRenderer {

    public String render(BundleReport report) {
        StringBuilder out = new StringBuilder();
        out.append(report.type().label()).append(": ").append(report.name());
        if (report.revision() != null) out.append("  (rev ").append(report.revision()).append(')');
        out.append('\n');
        if (report.description() != null) out.append(report.description()).append('\n');
        out.append(report.path()).append('\n');

        section(out, "Endpoints");
        for (Endpoint endpoint : report.endpoints()) {
            out.append("  ").append(endpoint.type()).append(' ').append(endpoint.name()).append('\n');
            endpoint.properties().forEach((k, v) -> out.append("      ").append(k).append(": ").append(v).append('\n'));
        }

        section(out, "Dependencies");
        if (report.dependencies().isEmpty()) out.append("  (none)\n");
        detailed(out, report.dependencies());

        if (!report.sharedFlows().isEmpty()) {
            section(out, "Shared flow tree");
            tree(out, report, "  ", new HashSet<>());
        }

        section(out, "Summary (direct and through shared flows)");
        Map<DependencyKind, Set<String>> byKind = new LinkedHashMap<>();
        for (ReportView.FlatDependency flat : ReportView.flatten(report)) {
            String name = flat.dependency().name();
            if (!flat.via().isEmpty()) name += " (via " + String.join(" › ", flat.via()) + ")";
            byKind.computeIfAbsent(flat.dependency().kind(), k -> new LinkedHashSet<>()).add(name);
        }
        byKind.entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .forEach(e -> out.append(String.format("  %-18s %s%n", e.getKey().plural(), String.join(", ", e.getValue()))));

        section(out, "Policies (" + report.policies().size() + ")");
        for (Policy policy : report.policies()) {
            String state = !policy.enabled() ? "disabled"
                    : !policy.attached() ? "not attached"
                    : policy.attachments().size() + " step(s)";
            out.append(String.format("  %-28s %-24s %s%n", policy.name(), policy.type(), state));
        }

        List<ReportView.BundleIssue> issues = ReportView.allIssues(report);
        section(out, "Issues (" + issues.size() + ")");
        for (ReportView.BundleIssue issue : issues) {
            out.append(String.format("  %-5s ", issue.issue().severity()));
            if (!issue.bundle().equals(report.name())) out.append('[').append(issue.bundle()).append("] ");
            out.append(issue.issue().message()).append('\n');
        }
        return out.toString();
    }

    private static void section(StringBuilder out, String title) {
        out.append('\n').append(title).append('\n').append("─".repeat(title.length())).append('\n');
    }

    private static void detailed(StringBuilder out, List<Dependency> dependencies) {
        DependencyKind current = null;
        for (Dependency dependency : dependencies) {
            if (dependency.kind() != current) {
                current = dependency.kind();
                out.append("  ").append(current.plural()).append('\n');
            }
            out.append("    • ").append(dependency.name()).append(flags(dependency)).append('\n');
            for (Usage usage : dependency.usages()) {
                out.append("        ← ").append(usage.label());
                if (!usage.active()) out.append(" (inactive)");
                if (!usage.details().isEmpty()) out.append("   ").append(ReportView.details(usage.details()));
                out.append('\n');
                for (Attachment attachment : usage.attachments()) {
                    out.append("            @ ").append(attachment.describe()).append('\n');
                }
            }
        }
    }

    private static void tree(StringBuilder out, BundleReport report, String indent, Set<String> visited) {
        for (SharedFlowLink link : report.sharedFlows()) {
            out.append(indent).append("▸ ").append(link.name());
            if (link.report() != null && link.report().revision() != null) {
                out.append(" (rev ").append(link.report().revision()).append(')');
            }
            out.append("  [").append(link.status().label()).append("]\n");
            if (link.report() == null) continue;
            if (!visited.add(link.name())) {
                out.append(indent).append("    (see above)\n");
                continue;
            }
            for (Dependency dependency : link.report().dependencies()) {
                if (dependency.kind() == DependencyKind.SHARED_FLOW) continue;
                out.append(indent).append("    ").append(dependency.kind().label()).append(": ")
                        .append(dependency.name()).append(flags(dependency)).append('\n');
            }
            tree(out, link.report(), indent + "    ", visited);
        }
    }

    private static String flags(Dependency dependency) {
        String flags = "";
        if (dependency.dynamic()) flags += "  (dynamic)";
        if (!dependency.active()) flags += "  (inactive)";
        return flags;
    }
}
