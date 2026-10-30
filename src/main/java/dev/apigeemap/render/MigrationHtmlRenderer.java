package dev.apigeemap.render;

import dev.apigeemap.migration.BundleMigration;
import dev.apigeemap.migration.EnvResource;
import dev.apigeemap.migration.FalsePositive;
import dev.apigeemap.migration.Finding;
import dev.apigeemap.migration.MigrationReport;
import dev.apigeemap.migration.ProxyDocs;
import dev.apigeemap.model.Issue;

import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.regex.Pattern;

import static dev.apigeemap.render.HtmlRenderer.esc;

/**
 * Standalone HTML page: finding cards that filter the finding table, the documentation of the proxy when it was
 * written, changes per bundle, resources to create.
 */
public final class MigrationHtmlRenderer {

    private static final Pattern CODE = Pattern.compile("`([^`]+)`");
    private static final DateTimeFormatter DAY = DateTimeFormatter.ofPattern("yyyy-MM-dd").withZone(ZoneId.systemDefault());

    /** Cards filter the findings by severity, category or fix; clicking the active card clears the filter. */
    private static final String SCRIPT = """
            const rows = [...document.querySelectorAll('#findings tr[data-severity]')];
            let current = null;
            document.querySelectorAll('.card[data-filter]').forEach(card => card.addEventListener('click', () => {
              current = current === card.dataset.filter ? null : card.dataset.filter;
              const [key, value] = current ? current.split('=') : [];
              rows.forEach(r => r.hidden = !!current && r.dataset[key] !== value);
              document.querySelectorAll('.card[data-filter]').forEach(c => c.classList.toggle('on', c.dataset.filter === current));
            }));
            """;

    private static final String EXTRA_CSS = """
            .fix{font-size:11px;padding:1px 6px;border-radius:10px;white-space:nowrap}
            .fix.auto{background:#1f6feb22;color:var(--accent)}.fix.manual{border:1px solid var(--line);color:var(--muted)}
            td.action{color:var(--muted)}
            #findings{min-width:960px}#findings td:nth-child(2) code{white-space:nowrap;word-break:normal}
            ul.changes{margin:0;padding-left:18px}
            .doc p,.doc li{max-width:900px;line-height:1.5}.doc ul{padding-left:20px}
            .doc .stale{color:var(--warn)}
            """;

    public String render(MigrationReport report) {
        return render(report, null, true);
    }

    /**
     * @param doc     the documentation of the proxy, or null when it was never written
     * @param current false when the proxy changed since the documentation was written
     */
    public String render(MigrationReport report, ProxyDocs.Stored doc, boolean current) {
        List<Finding> findings = report.findings();
        StringBuilder out = new StringBuilder();
        out.append("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">")
                .append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
                .append("<title>").append(esc(report.name())).append(" hybrid migration</title>")
                .append("<style>").append(HtmlRenderer.CSS).append(EXTRA_CSS).append("</style></head><body><main>\n");

        out.append("<h1>").append(esc(report.name())).append(" → Apigee hybrid</h1><p class=\"meta\">")
                .append(report.applied() && report.outputDir() == null ? "Auto-fixes applied to the bundles themselves"
                        : report.applied() ? "Migrated bundles written to <code>" + esc(report.outputDir()) + "</code>"
                        : "Dry run: nothing written")
                .append(" · ").append(report.bundles().size()).append(" bundle(s)</p>\n");

        out.append("<div class=\"cards\">");
        for (Issue.Severity severity : Issue.Severity.values()) {
            card(out, "severity=" + severity, findings.stream().filter(f -> f.severity() == severity).count(),
                    switch (severity) {
                        case ERROR -> "Errors";
                        case WARN -> "Warnings";
                        case INFO -> "Info";
                    });
        }
        card(out, "fix=AUTO", findings.stream().filter(f -> f.fix() == Finding.Fix.AUTO).count(),
                report.applied() ? "Fixed automatically" : "Fixable automatically");
        card(out, "fix=MANUAL", findings.stream().filter(f -> f.fix() == Finding.Fix.MANUAL).count(), "Manual");
        for (Finding.Category category : Finding.Category.values()) {
            long n = findings.stream().filter(f -> f.category() == category).count();
            if (n > 0) card(out, "category=" + category, n, category.label());
        }
        out.append("</div>\n");

        if (doc != null) documentation(out, doc, current);

        out.append("<h2>Findings</h2>");
        if (findings.isEmpty()) {
            out.append("<p class=\"meta\">No findings.</p>\n");
        } else {
            out.append("<div class=\"wrap\"><table id=\"findings\"><tr><th>Severity</th><th>Rule</th><th>Bundle</th>")
                    .append("<th>Where</th><th>Finding</th><th>What to do</th><th>Fix</th></tr>\n");
            for (Finding f : findings) {
                String fix = MigrationTextRenderer.fixLabel(f, report.applied());
                out.append("<tr data-severity=\"").append(f.severity()).append("\" data-category=\"")
                        .append(f.category()).append("\" data-fix=\"").append(f.fix()).append("\"><td class=\"")
                        .append(f.severity()).append("\">").append(f.severity()).append("</td><td><code>")
                        .append(f.rule()).append("</code></td><td>").append(esc(f.bundle())).append("</td><td><code>")
                        .append(esc(f.location())).append("</code></td><td>").append(esc(f.message()))
                        .append("</td><td class=\"action\">").append(esc(f.action())).append("</td><td><span class=\"fix ")
                        .append(f.fix() == Finding.Fix.AUTO ? "auto" : "manual").append("\">").append(fix)
                        .append("</span></td></tr>\n");
            }
            out.append("</table></div>\n");
        }

        List<FalsePositive.Hidden> falsePositives = report.falsePositives();
        if (!falsePositives.isEmpty()) {
            out.append("<h2>Marked as false positives</h2>");
            out.append("<div class=\"wrap\"><table><tr><th>Rule</th><th>Bundle</th><th>Where</th><th>Finding</th>")
                    .append("<th>Why</th></tr>\n");
            for (FalsePositive.Hidden hidden : falsePositives) {
                Finding f = hidden.finding();
                out.append("<tr><td><code>").append(f.rule()).append("</code></td><td>").append(esc(f.bundle()))
                        .append("</td><td><code>").append(esc(f.location())).append("</code></td><td>")
                        .append(esc(f.message())).append("</td><td class=\"action\">").append(esc(hidden.reason()))
                        .append("</td></tr>\n");
            }
            out.append("</table></div>\n");
        }

        out.append("<h2>").append(report.applied() ? "Changes made" : "Changes the migration would make").append("</h2>");
        out.append("<div class=\"wrap\"><table><tr><th>Bundle</th><th>Changes</th></tr>\n");
        for (BundleMigration bundle : report.bundles()) {
            out.append("<tr><td>").append(esc(bundle.name())).append("<div class=\"at\">")
                    .append(bundle.type().label()).append("</div>");
            if (bundle.output() != null) out.append("<div class=\"at\"><code>").append(esc(bundle.output())).append("</code></div>");
            out.append("</td><td>");
            if (bundle.changes().isEmpty()) {
                out.append("<span class=\"at\">none</span>");
            } else {
                out.append("<ul class=\"changes\">");
                bundle.changes().forEach(c -> out.append("<li><code>").append(esc(c)).append("</code></li>"));
                out.append("</ul>");
            }
            out.append("</td></tr>\n");
        }
        out.append("</table></div>\n");

        out.append("<h2>To create in the hybrid organization / environments</h2>");
        out.append("<div class=\"wrap\"><table><tr><th>Kind</th><th>Name</th><th>Details</th><th>Needed by</th></tr>\n");
        for (EnvResource resource : report.resources()) {
            out.append("<tr><td>").append(esc(resource.kind())).append("</td><td><code>").append(esc(resource.name()))
                    .append("</code></td><td>").append(esc(resource.details())).append("</td><td>")
                    .append(esc(resource.requiredBy())).append("</td></tr>\n");
        }
        out.append("</table></div>\n");

        out.append("</main><script>\n").append(SCRIPT).append("</script></body></html>\n");
        return out.toString();
    }

    private static void documentation(StringBuilder out, ProxyDocs.Stored stored, boolean current) {
        ProxyDocs.Doc doc = stored.doc();
        out.append("<section class=\"doc\"><h2>What the proxy does</h2><p class=\"meta\">Written on ")
                .append(DAY.format(stored.written()));
        if (!current) out.append(" · <span class=\"stale\">the proxy changed since: it may be out of date</span>");
        out.append("</p><p>").append(inline(doc.summary())).append("</p>\n");
        if (!doc.operations().isEmpty()) {
            out.append("<h3>Operations</h3><div class=\"wrap\"><table><tr><th>Method</th><th>Path</th><th>Flow</th>")
                    .append("<th>What it does</th></tr>\n");
            for (ProxyDocs.Operation o : doc.operations()) {
                out.append("<tr><td><code>").append(esc(o.method())).append("</code></td><td><code>")
                        .append(esc(o.path().isEmpty() ? "/" : o.path())).append("</code></td><td>").append(esc(o.flow()))
                        .append("</td><td>").append(inline(o.description())).append("</td></tr>\n");
            }
            out.append("</table></div>\n");
        }
        points(out, "Security", doc.security());
        if (!doc.dependencies().isEmpty()) {
            out.append("<h3>Dependencies</h3><div class=\"wrap\"><table><tr><th>Name</th><th>Kind</th>")
                    .append("<th>Used for</th></tr>\n");
            for (ProxyDocs.Dependency d : doc.dependencies()) {
                out.append("<tr><td><code>").append(esc(d.name())).append("</code></td><td>").append(esc(kind(d.kind())))
                        .append("</td><td>").append(inline(d.description())).append("</td></tr>\n");
            }
            out.append("</table></div>\n");
        }
        points(out, "Errors", doc.errors());
        points(out, "Good to know", doc.notes());
        out.append("</section>\n");
    }

    private static void points(StringBuilder out, String title, List<String> points) {
        if (points.isEmpty()) return;
        out.append("<h3>").append(title).append("</h3><ul>");
        points.forEach(p -> out.append("<li>").append(inline(p)).append("</li>"));
        out.append("</ul>\n");
    }

    static String kind(String kind) {
        return switch (kind) {
            case "TARGET" -> "Target";
            case "CALLOUT" -> "Service callout";
            case "SHARED_FLOW" -> "Shared flow";
            case "KVM" -> "Key value map";
            case "CACHE" -> "Cache";
            default -> "Other";
        };
    }

    /** Escaped text, with what is in backticks as code. */
    static String inline(String text) {
        return CODE.matcher(esc(text)).replaceAll("<code>$1</code>");
    }

    private static void card(StringBuilder out, String filter, long count, String label) {
        out.append("<button type=\"button\" class=\"card\" data-filter=\"").append(filter).append("\"><b>")
                .append(count).append("</b><span>").append(esc(label)).append("</span></button>");
    }
}
