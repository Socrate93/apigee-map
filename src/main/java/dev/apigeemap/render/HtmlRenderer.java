package dev.apigeemap.render;

import dev.apigeemap.model.Attachment;
import dev.apigeemap.model.BundleReport;
import dev.apigeemap.model.DependencyKind;
import dev.apigeemap.model.Endpoint;
import dev.apigeemap.model.Issue;
import dev.apigeemap.model.Policy;
import dev.apigeemap.model.Usage;

import java.util.EnumMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/** Standalone HTML page: Mermaid graph (rendered from a CDN) plus dependency, policy and issue tables. */
public final class HtmlRenderer {

    private static final String MERMAID_JS = "https://cdn.jsdelivr.net/npm/mermaid@10.9.1/dist/mermaid.min.js";

    /**
     * Filters the dependency table by type (cards, graph clusters) or by resource (graph nodes).
     * Clicking the active filter again clears it.
     */
    private static final String SCRIPT = """
            const rows = [...document.querySelectorAll('#deps tr[data-kind]')];
            const bar = document.getElementById('filter');
            const graph = document.getElementById('graph');
            let current = null;

            function matches(filter, kind, key) {
              return filter.kind ? kind === filter.kind : key === filter.key;
            }

            function apply(filter) {
              rows.forEach(r => r.hidden = !!filter && !matches(filter, r.dataset.kind, r.dataset.key));
              document.querySelectorAll('.card[data-kind]').forEach(c =>
                c.classList.toggle('on', !!filter && filter.kind === c.dataset.kind));
              graph.querySelectorAll('g.cluster').forEach(g =>
                g.classList.toggle('on', !!filter && !!filter.kind && g.id === 'k_' + filter.kind));
              graph.querySelectorAll('g.node[data-key]').forEach(g =>
                g.classList.toggle('on', !!filter && matches(filter, g.dataset.key.split(':')[0], g.dataset.key)));
              graph.classList.toggle('filtered', !!filter);
              bar.hidden = !filter;
              if (filter) bar.querySelector('b').textContent = filter.label;
            }

            function toggle(filter, scroll) {
              const same = current && current.kind === filter.kind && current.key === filter.key;
              current = same ? null : filter;
              apply(current);
              if (current && scroll) document.getElementById('dependencies').scrollIntoView({behavior: 'smooth'});
            }

            bar.querySelector('button').addEventListener('click', () => { current = null; apply(null); });
            document.querySelectorAll('.card[data-kind]').forEach(c => c.addEventListener('click', () =>
              toggle({kind: c.dataset.kind, label: KINDS[c.dataset.kind]}, true)));

            mermaid.initialize({startOnLoad: false, flowchart: {htmlLabels: true}});
            mermaid.run({querySelector: '.mermaid'}).then(() => {
              graph.querySelectorAll('g.cluster').forEach(g => {
                const kind = g.id.replace(/^k_/, '');
                if (!KINDS[kind]) return;
                g.addEventListener('click', e => { e.stopPropagation(); toggle({kind, label: KINDS[kind]}, false); });
              });
              graph.querySelectorAll('g.node').forEach(g => {
                const match = g.id.match(/^flowchart-(n\\d+)-/);
                const key = match && NODE_KEYS[match[1]];
                if (!key) return;
                g.dataset.key = key;
                g.addEventListener('click', e => {
                  e.stopPropagation();
                  const kind = key.slice(0, key.indexOf(':'));
                  toggle({key, label: KINDS[kind] + ' · ' + key.slice(kind.length + 1)}, false);
                });
              });
            });
            """;

    static final String CSS = """
            :root{--bg:#f7f7f8;--fg:#1c1d21;--muted:#6b6f76;--card:#fff;--line:#e3e4e8;--accent:#1f6feb;--err:#d1242f;--warn:#9a6700;--info:#57606a}
            @media (prefers-color-scheme:dark){:root{--bg:#111215;--fg:#e8e9ec;--muted:#9a9ea6;--card:#1a1b1f;--line:#2c2e34;--accent:#4c8dff;--err:#ff7b72;--warn:#e3b341;--info:#9aa4b2}}
            *{box-sizing:border-box}
            body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
            main{max-width:1200px;margin:0 auto;padding:24px 16px 64px}
            h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:32px 0 12px}
            .meta{color:var(--muted);margin:0}
            .cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:8px;margin-top:16px}
            .card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px;color:inherit;font:inherit;text-align:left}
            button.card{cursor:pointer}button.card:hover{border-color:var(--accent)}
            .card.on{border-color:var(--accent);box-shadow:0 0 0 1px var(--accent)}
            .card b{display:block;font-size:20px}.card span{color:var(--muted);font-size:12px}
            .graph{background:#fff;border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto}
            .graph g.cluster,.graph g.node[data-key]{cursor:pointer}
            .graph g.cluster:hover>rect,.graph g.cluster.on>rect{stroke:#1f6feb!important;stroke-width:2px!important}
            .graph g.node.on{filter:drop-shadow(0 0 4px #1f6feb)}
            .graph.filtered g.node[data-key]:not(.on){opacity:.35}
            .hint{color:var(--muted);font-size:12px;margin:6px 0 0}
            .filter{display:flex;align-items:center;gap:8px;margin:0 0 8px;padding:6px 10px;border:1px solid var(--accent);border-radius:8px;background:var(--card)}
            .filter[hidden]{display:none}.filter button{margin-left:auto;font:inherit;cursor:pointer;background:none;border:1px solid var(--line);border-radius:6px;color:inherit;padding:2px 8px}
            .wrap{overflow-x:auto;border:1px solid var(--line);border-radius:8px}
            table{width:100%;border-collapse:collapse;background:var(--card)}
            th,td{text-align:left;vertical-align:top;padding:8px 10px;border-bottom:1px solid var(--line)}
            tr:last-child td{border-bottom:0}
            th{font-size:12px;color:var(--muted);font-weight:600;white-space:nowrap}
            code{font:12px ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}
            .at{color:var(--muted);font-size:12px}
            .tag{display:inline-block;font-size:11px;padding:0 6px;border-radius:10px;border:1px solid var(--line);color:var(--muted);margin-left:4px}
            tr.inactive td{opacity:.55}
            .ERROR{color:var(--err);font-weight:600}.WARN{color:var(--warn);font-weight:600}.INFO{color:var(--info)}
            """;

    public String render(BundleReport report) {
        List<ReportView.FlatDependency> flat = ReportView.flatten(report);
        List<ReportView.BundleIssue> issues = ReportView.allIssues(report);
        StringBuilder out = new StringBuilder();

        out.append("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">")
                .append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
                .append("<title>").append(esc(report.name())).append(" dependencies</title>")
                .append("<style>").append(CSS).append("</style></head><body><main>\n");

        out.append("<h1>").append(esc(report.name())).append("</h1><p class=\"meta\">")
                .append(report.type().label());
        if (report.revision() != null) out.append(" · rev ").append(esc(report.revision()));
        if (report.description() != null) out.append(" · ").append(esc(report.description()));
        out.append("</p><p class=\"meta\"><code>").append(esc(report.path())).append("</code></p>\n");

        Map<DependencyKind, Set<String>> counts = new EnumMap<>(DependencyKind.class);
        flat.forEach(f -> counts.computeIfAbsent(f.dependency().kind(), k -> new HashSet<>()).add(f.dependency().name()));
        out.append("<div class=\"cards\">");
        counts.forEach((kind, names) -> out.append("<button type=\"button\" class=\"card\" data-kind=\"")
                .append(kind.name()).append("\"><b>").append(names.size())
                .append("</b><span>").append(kind.plural()).append("</span></button>"));
        long problems = issues.stream().filter(i -> i.issue().severity() != Issue.Severity.INFO).count();
        out.append("<div class=\"card\"><b>").append(problems).append("</b><span>Errors &amp; warnings</span></div>");
        out.append("</div>\n");

        MermaidRenderer.Diagram diagram = new MermaidRenderer().diagram(report);
        out.append("<h2>Graph</h2><div class=\"graph\" id=\"graph\"><pre class=\"mermaid\">")
                .append(esc(diagram.source())).append("</pre></div>")
                .append("<p class=\"hint\">Click a type cluster, a node or a card to filter the dependencies.</p>\n");

        out.append("<h2 id=\"dependencies\">Dependencies</h2>")
                .append("<div class=\"filter\" id=\"filter\" hidden>Filter: <b></b><button type=\"button\">Show all</button></div>")
                .append("<div class=\"wrap\"><table id=\"deps\"><tr><th>Type</th><th>Name</th><th>Via</th>")
                .append("<th>Used by</th></tr>\n");
        for (ReportView.FlatDependency f : flat) {
            out.append("<tr data-kind=\"").append(f.dependency().kind().name()).append("\" data-key=\"")
                    .append(esc(f.dependency().kind() + ":" + f.dependency().name())).append("\"")
                    .append(f.dependency().active() ? "" : " class=\"inactive\"").append("><td>")
                    .append(f.dependency().kind().label()).append("</td><td><code>").append(esc(f.dependency().name()))
                    .append("</code>");
            if (f.dependency().dynamic()) out.append("<span class=\"tag\">dynamic</span>");
            if (!f.dependency().active()) out.append("<span class=\"tag\">inactive</span>");
            out.append("</td><td>").append(f.via().isEmpty() ? "direct" : esc(String.join(" › ", f.via())))
                    .append("</td><td>");
            for (Usage usage : f.dependency().usages()) out.append(usage(usage));
            out.append("</td></tr>\n");
        }
        out.append("</table></div>\n");

        out.append("<h2>Endpoints</h2><div class=\"wrap\"><table><tr><th>Type</th><th>Name</th><th>Configuration</th></tr>\n");
        for (Endpoint endpoint : report.endpoints()) {
            out.append("<tr><td>").append(endpoint.type()).append("</td><td>").append(esc(endpoint.name()))
                    .append("</td><td>");
            endpoint.properties().forEach((k, v) -> out.append("<div><span class=\"at\">").append(esc(k))
                    .append("</span> <code>").append(esc(v)).append("</code></div>"));
            out.append("</td></tr>\n");
        }
        out.append("</table></div>\n");

        out.append("<h2>Policies</h2><div class=\"wrap\"><table><tr><th>Name</th><th>Type</th><th>Attached at</th></tr>\n");
        for (Policy policy : report.policies()) {
            out.append("<tr").append(policy.active() ? "" : " class=\"inactive\"").append("><td>")
                    .append(esc(policy.name()));
            if (!policy.enabled()) out.append("<span class=\"tag\">disabled</span>");
            if (!policy.attached()) out.append("<span class=\"tag\">not attached</span>");
            out.append("</td><td>").append(esc(policy.type())).append("</td><td class=\"at\">")
                    .append(policy.attachments().stream().map(a -> esc(a.describe())).collect(Collectors.joining("<br>")))
                    .append("</td></tr>\n");
        }
        out.append("</table></div>\n");

        out.append("<h2>Issues</h2>");
        if (issues.isEmpty()) {
            out.append("<p class=\"meta\">No issues.</p>");
        } else {
            out.append("<div class=\"wrap\"><table><tr><th>Severity</th><th>Bundle</th><th>Message</th></tr>\n");
            for (ReportView.BundleIssue issue : issues) {
                out.append("<tr><td class=\"").append(issue.issue().severity()).append("\">")
                        .append(issue.issue().severity()).append("</td><td>").append(esc(issue.bundle()))
                        .append("</td><td>").append(esc(issue.issue().message())).append("</td></tr>\n");
            }
            out.append("</table></div>\n");
        }

        out.append("</main><script src=\"").append(MERMAID_JS).append("\"></script><script>\n")
                .append("const KINDS=").append(jsObject(kindLabels())).append(";\n")
                .append("const NODE_KEYS=").append(jsObject(diagram.nodeKeys())).append(";\n")
                .append(SCRIPT).append("</script></body></html>\n");
        return out.toString();
    }

    private static Map<String, String> kindLabels() {
        Map<String, String> labels = new LinkedHashMap<>();
        for (DependencyKind kind : DependencyKind.values()) labels.put(kind.name(), kind.plural());
        return labels;
    }

    /** JSON object literal safe to embed in a script element. */
    private static String jsObject(Map<String, String> map) {
        return map.entrySet().stream()
                .map(e -> jsString(e.getKey()) + ":" + jsString(e.getValue()))
                .collect(Collectors.joining(",", "{", "}"));
    }

    private static String jsString(String text) {
        return "\"" + text.replace("\\", "\\\\").replace("\"", "\\\"").replace("<", "\\u003c")
                .replace("\n", "\\n") + "\"";
    }

    private static String usage(Usage usage) {
        StringBuilder out = new StringBuilder("<div>").append(esc(usage.label()));
        if (!usage.active()) out.append("<span class=\"tag\">inactive</span>");
        if (!usage.details().isEmpty()) {
            out.append(" <span class=\"at\">").append(esc(ReportView.details(usage.details()))).append("</span>");
        }
        for (Attachment attachment : usage.attachments()) {
            out.append("<div class=\"at\">@ ").append(esc(attachment.describe())).append("</div>");
        }
        return out.append("</div>").toString();
    }

    static String esc(String text) {
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }
}
