package dev.apigeemap.render;

import dev.apigeemap.model.BundleReport;
import dev.apigeemap.model.BundleType;
import dev.apigeemap.model.Dependency;
import dev.apigeemap.model.DependencyKind;
import dev.apigeemap.model.SharedFlowLink;
import dev.apigeemap.model.Usage;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Mermaid flowchart: one node per resource, shared across the proxy and the shared flows it calls.
 * Resources are grouped into one subgraph per dependency type, with id {@code k_<KIND>}.
 */
public final class MermaidRenderer {

    private static final String CLASS_DEFS = """
              classDef bundle fill:#1f6feb,stroke:#1f6feb,color:#ffffff
              classDef sharedflow fill:#8957e5,stroke:#8957e5,color:#ffffff
              classDef missing fill:#ffffff,stroke:#d1242f,color:#d1242f,stroke-dasharray:4 3
              classDef network fill:#dbeafe,stroke:#3b82f6,color:#1e3a8a
              classDef data fill:#dcfce7,stroke:#16a34a,color:#14532d
              classDef security fill:#fef3c7,stroke:#d97706,color:#78350f
              classDef code fill:#f3f4f6,stroke:#6b7280,color:#111827
            """;

    /** Mermaid source plus, for each node id, the {@code KIND:name} key of the resource it represents. */
    public record Diagram(String source, Map<String, String> nodeKeys) {
    }

    private record Shape(String open, String close) {
    }

    private static final class Graph {
        final Map<String, String> ids = new LinkedHashMap<>();
        final List<String> roots = new ArrayList<>();
        final Map<DependencyKind, List<String>> clusters = new EnumMap<>(DependencyKind.class);
        final Map<String, String> nodeKeys = new LinkedHashMap<>();
        final Set<String> edges = new LinkedHashSet<>();

        boolean has(String key) {
            return ids.containsKey(key);
        }

        /** {@code kind} null puts the node outside any cluster (the analyzed bundle itself). */
        String node(String key, DependencyKind kind, String label, String cssClass, Shape shape) {
            return ids.computeIfAbsent(key, k -> {
                String id = "n" + ids.size();
                String line = id + shape.open() + "\"" + label + "\"" + shape.close() + ":::" + cssClass;
                if (kind == null) {
                    roots.add(line);
                } else {
                    clusters.computeIfAbsent(kind, c -> new ArrayList<>()).add(line);
                    nodeKeys.put(id, key);
                }
                return id;
            });
        }

        void edge(String from, String to, String label, boolean active) {
            String arrow = active ? "-->" : "-.->";
            edges.add(from + " " + arrow + (label.isEmpty() ? "" : "|\"" + escape(label) + "\"|") + " " + to);
        }
    }

    public String render(BundleReport report) {
        return diagram(report).source();
    }

    public Diagram diagram(BundleReport report) {
        Graph graph = new Graph();
        String root = graph.node(bundleKey(report), null,
                report.type().label() + "<br/><b>" + escape(report.name()) + "</b>", "bundle", new Shape("[", "]"));
        emit(report, root, graph, new HashSet<>());

        StringBuilder out = new StringBuilder("flowchart LR\n");
        graph.roots.forEach(node -> out.append("  ").append(node).append('\n'));
        graph.clusters.forEach((kind, nodes) -> {
            out.append("  subgraph ").append(clusterId(kind)).append("[\"").append(kind.plural()).append("\"]\n");
            nodes.forEach(node -> out.append("    ").append(node).append('\n'));
            out.append("  end\n");
        });
        graph.edges.forEach(edge -> out.append("  ").append(edge).append('\n'));
        out.append(CLASS_DEFS);
        graph.clusters.keySet().forEach(kind -> out.append("  style ").append(clusterId(kind))
                .append(" fill:#f8f9fb,stroke:#c9ced8\n"));
        return new Diagram(out.toString(), Map.copyOf(graph.nodeKeys));
    }

    /** Matches the shared flow node key, so a root shared flow and its callers share one node. */
    private static String bundleKey(BundleReport report) {
        return (report.type() == BundleType.SHARED_FLOW ? DependencyKind.SHARED_FLOW.name() : report.type().name())
                + ":" + report.name();
    }

    public static String clusterId(DependencyKind kind) {
        return "k_" + kind.name();
    }

    private static void emit(BundleReport report, String from, Graph graph, Set<String> visited) {
        for (Dependency dependency : report.dependencies()) {
            if (dependency.kind() == DependencyKind.SHARED_FLOW) continue;
            String to = graph.node(dependency.kind() + ":" + dependency.name(), dependency.kind(),
                    dependency.kind().label() + "<br/>" + escape(dependency.name()),
                    cssClass(dependency.kind()), shape(dependency.kind()));
            graph.edge(from, to, origins(dependency.usages()), dependency.active());
        }
        for (SharedFlowLink link : report.sharedFlows()) {
            String key = DependencyKind.SHARED_FLOW + ":" + link.name();
            boolean firstVisit = !graph.has(key);
            boolean resolved = link.status() == SharedFlowLink.Status.RESOLVED;
            String label = "Shared flow<br/><b>" + escape(link.name()) + "</b>"
                    + (resolved || link.status() == SharedFlowLink.Status.CYCLE ? "" : "<br/><i>" + link.status().label() + "</i>");
            // Same key as a shared flow analyzed as root: a cycle back to it reuses the root node.
            String to = graph.node(key, DependencyKind.SHARED_FLOW, label, resolved || !firstVisit ? "sharedflow" : "missing",
                    new Shape("[[", "]]"));
            Dependency call = report.dependencies().stream()
                    .filter(d -> d.kind() == DependencyKind.SHARED_FLOW && d.name().equals(link.name()))
                    .findFirst().orElse(null);
            graph.edge(from, to, call == null ? "" : origins(call.usages()), call == null || call.active());
            if (link.report() != null && visited.add(link.name())) emit(link.report(), to, graph, visited);
        }
    }

    private static String origins(List<Usage> usages) {
        List<String> labels = usages.stream().map(Usage::label).distinct().toList();
        if (labels.size() <= 2) return String.join(", ", labels);
        return String.join(", ", labels.subList(0, 2)) + " +" + (labels.size() - 2);
    }

    private static Shape shape(DependencyKind kind) {
        return switch (kind) {
            case VIRTUAL_HOST -> new Shape("([", "])");
            case KVM, CACHE -> new Shape("[(", ")]");
            case TARGET_SERVER, TARGET_URL, LOCAL_PROXY -> new Shape("{{", "}}");
            case KEYSTORE, TRUSTSTORE -> new Shape("[/", "/]");
            case SHARED_FLOW -> new Shape("[[", "]]");
            case RESOURCE, SYSLOG -> new Shape("[", "]");
        };
    }

    private static String cssClass(DependencyKind kind) {
        return switch (kind) {
            case VIRTUAL_HOST, TARGET_SERVER, TARGET_URL, LOCAL_PROXY, SYSLOG -> "network";
            case KVM, CACHE -> "data";
            case KEYSTORE, TRUSTSTORE -> "security";
            case RESOURCE -> "code";
            case SHARED_FLOW -> "sharedflow";
        };
    }

    /** Mermaid entity codes, so quotes and angle brackets in names cannot break the label. */
    private static String escape(String text) {
        return text.replace("\"", "#quot;").replace("<", "#60;").replace(">", "#62;");
    }
}
