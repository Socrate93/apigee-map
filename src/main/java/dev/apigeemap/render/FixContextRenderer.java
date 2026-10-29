package dev.apigeemap.render;

import dev.apigeemap.migration.Finding;
import dev.apigeemap.migration.FixContext;
import dev.apigeemap.migration.FixContext.PolicyContext;
import dev.apigeemap.migration.FixContext.SourceFile;
import dev.apigeemap.migration.FixContext.VariableRead;
import dev.apigeemap.migration.FixContext.VariableUse;
import dev.apigeemap.protocol.Json;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** The context of a finding as Markdown, to read or to paste into a prompt, or as JSON. */
public final class FixContextRenderer {

    public String markdown(FixContext context) {
        Finding finding = context.finding();
        StringBuilder out = new StringBuilder();
        out.append("# ").append(finding.rule()).append(context.ruleTitle() == null ? "" : " " + context.ruleTitle())
                .append("\n\n");
        out.append("- Severity: ").append(finding.severity()).append(", ").append(finding.fix().name().toLowerCase())
                .append(" fix\n");
        out.append("- Bundle: ").append(finding.bundle()).append('\n');
        out.append("- Location: ").append(finding.location()).append('\n');
        out.append("- Finding: ").append(finding.message()).append('\n');
        out.append("- Action: ").append(finding.action()).append('\n');

        for (PolicyContext policy : context.policies()) {
            out.append("\n## Policy ").append(policy.name()).append(" (").append(policy.type()).append(", ")
                    .append(policy.bundle()).append('/').append(policy.file()).append(")\n");
            out.append("\nRuns at:\n");
            if (policy.runs().isEmpty()) out.append("- nowhere: attached to no flow\n");
            policy.runs().forEach(r -> out.append("- ").append(r).append('\n'));
            if (!policy.reads().isEmpty()) {
                out.append("\nReads:\n");
                for (VariableRead read : policy.reads()) {
                    out.append("- `").append(read.variable()).append("`: ").append(describe(read)).append('\n');
                }
            }
            if (!policy.readBy().isEmpty()) {
                out.append("\nWhat it sets is read by:\n");
                for (VariableUse use : policy.readBy()) {
                    out.append("- `").append(use.variable()).append("`: ").append(use.step()).append(" (")
                            .append(use.location()).append(")\n");
                }
            }
        }

        out.append("\n## Files\n");
        for (SourceFile file : context.files()) {
            String fence = file.content().contains("```") ? "````" : "```";
            out.append("\n### ").append(file.bundle()).append('/').append(file.path()).append("\n\n")
                    .append(fence).append(language(file.path())).append('\n').append(file.content());
            if (!file.content().endsWith("\n")) out.append('\n');
            out.append(fence).append('\n');
        }
        return out.toString();
    }

    public String json(FixContext context) {
        return Json.write(model(context)) + "\n";
    }

    public Map<String, Object> model(FixContext context) {
        Finding finding = context.finding();
        Map<String, Object> f = new LinkedHashMap<>();
        f.put("rule", finding.rule());
        f.put("title", context.ruleTitle());
        f.put("category", finding.category().name());
        f.put("severity", finding.severity().name());
        f.put("fix", finding.fix().name());
        f.put("bundle", finding.bundle());
        f.put("location", finding.location());
        f.put("message", finding.message());
        f.put("action", finding.action());

        List<Map<String, Object>> policies = context.policies().stream().map(p -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("bundle", p.bundle());
            m.put("name", p.name());
            m.put("type", p.type());
            m.put("file", p.file());
            m.put("runs", p.runs());
            m.put("reads", p.reads().stream().map(r -> {
                Map<String, Object> read = new LinkedHashMap<>();
                read.put("variable", r.variable());
                read.put("source", r.source());
                read.put("steps", r.steps());
                read.put("note", r.note());
                return read;
            }).toList());
            m.put("readBy", p.readBy().stream().map(u -> {
                Map<String, Object> use = new LinkedHashMap<>();
                use.put("variable", u.variable());
                use.put("step", u.step());
                use.put("location", u.location());
                return use;
            }).toList());
            return m;
        }).toList();
        List<Map<String, Object>> files = context.files().stream().map(file -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("bundle", file.bundle());
            m.put("path", file.path());
            m.put("content", file.content());
            return m;
        }).toList();

        Map<String, Object> model = new LinkedHashMap<>();
        model.put("finding", f);
        model.put("policies", policies);
        model.put("files", files);
        return model;
    }

    private static String describe(VariableRead read) {
        String steps = String.join(", ", read.steps());
        String note = read.note() == null ? "" : " (" + read.note() + ")";
        return switch (read.source()) {
            case "SET" -> "set earlier by " + steps;
            case "BUILT_IN" -> "set by Apigee";
            case "SET_LATER" -> "set only later, by " + steps + ": reads null here";
            case "UNKNOWN" -> "set by no step it can see; an earlier step may set it" + note;
            default -> "set by no step" + note;
        };
    }

    private static String language(String path) {
        int dot = path.lastIndexOf('.');
        return switch (dot < 0 ? "" : path.substring(dot + 1)) {
            case "xml" -> "xml";
            case "js" -> "javascript";
            case "py" -> "python";
            case "xsl", "xslt" -> "xml";
            default -> "";
        };
    }
}
