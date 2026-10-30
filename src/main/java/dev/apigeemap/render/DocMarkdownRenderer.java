package dev.apigeemap.render;

import dev.apigeemap.migration.ProxyDocs;

import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The functional documentation of a proxy as a Markdown file, with the same sections as in the migration report, to
 * keep next to the proxy or in a wiki. Texts keep their backticks as code; what Markdown would read as HTML or as a
 * table cell boundary is escaped.
 */
public final class DocMarkdownRenderer {

    private static final Pattern CODE = Pattern.compile("`[^`]+`");
    private static final DateTimeFormatter DAY = DateTimeFormatter.ofPattern("yyyy-MM-dd").withZone(ZoneId.systemDefault());

    /** @param current false when the proxy changed since the documentation was written */
    public String render(String proxy, ProxyDocs.Stored stored, boolean current) {
        ProxyDocs.Doc doc = stored.doc();
        StringBuilder out = new StringBuilder();
        out.append("# ").append(text(proxy)).append("\n\n");
        out.append("_Written on ").append(DAY.format(stored.written()));
        if (!current) out.append(". The proxy changed since: it may be out of date");
        out.append("._\n\n");
        out.append(text(doc.summary())).append('\n');

        if (!doc.operations().isEmpty()) {
            out.append("\n## Operations\n\n| Method | Path | Flow | What it does |\n|---|---|---|---|\n");
            for (ProxyDocs.Operation o : doc.operations()) {
                out.append("| ").append(code(o.method())).append(" | ").append(code(o.path().isEmpty() ? "/" : o.path()))
                        .append(" | ").append(cell(o.flow())).append(" | ").append(cell(o.description())).append(" |\n");
            }
        }
        points(out, "Security", doc.security());
        if (!doc.dependencies().isEmpty()) {
            out.append("\n## Dependencies\n\n| Name | Kind | Used for |\n|---|---|---|\n");
            for (ProxyDocs.Dependency d : doc.dependencies()) {
                out.append("| ").append(code(d.name())).append(" | ").append(MigrationHtmlRenderer.kind(d.kind()))
                        .append(" | ").append(cell(d.description())).append(" |\n");
            }
        }
        points(out, "Errors", doc.errors());
        points(out, "Good to know", doc.notes());
        return out.toString();
    }

    private static void points(StringBuilder out, String title, List<String> points) {
        if (points.isEmpty()) return;
        out.append("\n## ").append(title).append("\n\n");
        points.forEach(p -> out.append("- ").append(text(p)).append('\n'));
    }

    /** Text on one line, with angle brackets escaped outside its code spans so that Markdown does not read HTML. */
    private static String text(String text) {
        String line = text.strip().replaceAll("\\s*\\R\\s*", " ");
        StringBuilder out = new StringBuilder();
        Matcher matcher = CODE.matcher(line);
        int at = 0;
        while (matcher.find()) {
            out.append(escape(line.substring(at, matcher.start()))).append(matcher.group());
            at = matcher.end();
        }
        return out.append(escape(line.substring(at))).toString();
    }

    private static String escape(String text) {
        return text.replace("<", "&lt;").replace(">", "&gt;");
    }

    private static String cell(String text) {
        return text(text).replace("|", "\\|");
    }

    /** A code span that holds any text, backticks included. */
    private static String code(String text) {
        String fence = text.contains("`") ? "``" : "`";
        String padded = text.startsWith("`") || text.endsWith("`") ? " " + text + " " : text;
        return fence + padded.replaceAll("\\R", " ").replace("|", "\\|") + fence;
    }
}
