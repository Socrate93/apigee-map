package dev.apigeemap.render;

import dev.apigeemap.analysis.PolicyVariables.Access;
import dev.apigeemap.analysis.VariableFlow;
import dev.apigeemap.analysis.VariableFlow.Read;
import dev.apigeemap.analysis.VariableFlow.Source;
import dev.apigeemap.analysis.VariableFlow.Step;
import dev.apigeemap.protocol.Json;

import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/** The variable flow of a bundle, as text or JSON; for one policy, what it reads and who reads what it sets. */
public final class VariableFlowRenderer {

    public String text(VariableFlow flow, String policy) {
        StringBuilder out = new StringBuilder();
        String title = "Variables of " + flow.bundle().name() + " (" + flow.bundle().type().label() + ")"
                + (policy == null ? "" : ": " + policy);
        out.append(title).append('\n').append("═".repeat(title.length())).append('\n');
        if (policy == null) {
            out.append(String.format("%d steps; reads: %d set earlier, %d built-in, %d set later, %d set nowhere,"
                            + " %d unknown%n", flow.steps().size(), count(flow, Source.SET), count(flow, Source.BUILT_IN),
                    count(flow, Source.SET_LATER), count(flow, Source.UNSET), count(flow, Source.UNKNOWN)));
        }
        String location = null;
        for (Step step : steps(flow, policy)) {
            if (!step.location().equals(location)) {
                location = step.location();
                out.append('\n').append(location).append('\n');
            }
            out.append("  ").append(step.label()).append(step.type().equals("RouteRule") ? "" : " (" + step.type() + ")")
                    .append(step.condition() == null ? "" : "  [" + step.condition() + "]")
                    .append(step.opaque() ? "  — may use variables it does not name" : "").append('\n');
            for (Read read : reads(flow, step)) {
                out.append(String.format("    reads   %-40s %s%n", read.variable().name(), describe(read)));
            }
            for (Access write : step.writes()) {
                out.append(String.format("    writes  %-40s %s%n", write.name(), "(" + write.via() + ")"));
            }
        }
        if (policy != null) {
            List<Read> consumers = flow.consumersOf(policy);
            out.append("\nRead by\n");
            if (consumers.isEmpty()) out.append("  no step of the bundle\n");
            for (Read read : consumers) {
                out.append(String.format("  %-40s %s  (%s)%n", read.variable().name(), read.step().label(),
                        read.step().location()));
            }
        }
        return out.toString();
    }

    public String json(VariableFlow flow, String policy) {
        return Json.write(model(flow, policy)) + "\n";
    }

    /**
     * The JSON tree: steps in the order they run, each with an {@code index}; a read lists the steps that set it
     * as text ({@code producers}) and as indexes into {@code steps} ({@code producerSteps}).
     */
    public Map<String, Object> model(VariableFlow flow, String policy) {
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("bundle", flow.bundle().name());
        root.put("type", flow.bundle().type().label());
        List<Step> selected = steps(flow, policy);
        Map<Step, Integer> index = new IdentityHashMap<>();
        for (Step step : flow.steps()) index.put(step, index.size());
        List<Object> steps = new ArrayList<>();
        for (Step step : selected) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("index", index.get(step));
            entry.put("policy", step.policy());
            entry.put("label", step.label());
            entry.put("type", step.type());
            entry.put("location", step.location());
            entry.put("phase", step.phase());
            entry.put("condition", step.condition());
            entry.put("opaque", step.opaque());
            entry.put("reads", reads(flow, step).stream().map(read -> {
                Map<String, Object> r = new LinkedHashMap<>();
                r.put("name", read.variable().name());
                r.put("via", read.variable().via());
                r.put("source", read.source().name());
                r.put("producers", read.producers().stream().map(VariableFlowRenderer::where).toList());
                r.put("producerSteps", read.producers().stream().map(index::get).toList());
                r.put("note", read.note());
                return r;
            }).toList());
            entry.put("writes", step.writes().stream().map(w -> Map.of("name", w.name(), "via", w.via())).toList());
            steps.add(entry);
        }
        root.put("steps", steps);
        if (policy != null) {
            root.put("readBy", flow.consumersOf(policy).stream()
                    .map(read -> Map.of("name", read.variable().name(), "step", where(read.step())))
                    .toList());
        }
        return root;
    }

    private static List<Step> steps(VariableFlow flow, String policy) {
        return flow.steps().stream()
                .filter(s -> policy == null || (s.policy().equals(policy) && !s.type().equals("RouteRule")))
                .toList();
    }

    private static List<Read> reads(VariableFlow flow, Step step) {
        return flow.reads().stream().filter(r -> r.step() == step).toList();
    }

    private static long count(VariableFlow flow, Source source) {
        return flow.reads(source).size();
    }

    private static String describe(Read read) {
        String producers = read.producers().stream().map(Step::label).distinct().collect(Collectors.joining(", "));
        String via = "(" + read.variable().via() + ")" + (read.note() == null ? "" : "  " + read.note());
        return switch (read.source()) {
            case SET -> "← " + producers + "  " + via;
            case BUILT_IN -> "built-in  " + via;
            case SET_LATER -> "set later by " + producers + " !  " + via;
            case UNKNOWN -> "set nowhere visible, an earlier step may set it  " + via;
            case UNSET -> "set nowhere  " + via;
        };
    }

    private static String where(Step step) {
        return step.label() + " (" + step.location() + ")";
    }
}
