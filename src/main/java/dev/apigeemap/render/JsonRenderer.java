package dev.apigeemap.render;

import dev.apigeemap.model.BundleReport;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.RecordComponent;
import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/** Minimal JSON writer for the report records (no external dependency). */
public final class JsonRenderer {

    public String render(BundleReport report) {
        StringBuilder out = new StringBuilder();
        write(out, report, 0);
        return out.append('\n').toString();
    }

    private static void write(StringBuilder out, Object value, int depth) {
        switch (value) {
            case null -> out.append("null");
            case String s -> string(out, s);
            case Enum<?> e -> string(out, e.name());
            case Number n -> out.append(n);
            case Boolean b -> out.append(b);
            case Map<?, ?> map -> {
                List<Map.Entry<String, Object>> entries = new ArrayList<>();
                map.forEach((k, v) -> entries.add(new SimpleEntry<>(String.valueOf(k), v)));
                object(out, entries, depth);
            }
            case Collection<?> items -> array(out, items, depth);
            case Record record -> object(out, components(record), depth);
            default -> string(out, value.toString());
        }
    }

    private static List<Map.Entry<String, Object>> components(Record record) {
        List<Map.Entry<String, Object>> entries = new ArrayList<>();
        for (RecordComponent component : record.getClass().getRecordComponents()) {
            try {
                entries.add(new SimpleEntry<>(component.getName(), component.getAccessor().invoke(record)));
            } catch (IllegalAccessException | InvocationTargetException e) {
                throw new IllegalStateException("Cannot serialize " + component, e);
            }
        }
        return entries;
    }

    private static void object(StringBuilder out, List<Map.Entry<String, Object>> entries, int depth) {
        if (entries.isEmpty()) {
            out.append("{}");
            return;
        }
        out.append("{\n");
        for (int i = 0; i < entries.size(); i++) {
            indent(out, depth + 1);
            string(out, entries.get(i).getKey());
            out.append(": ");
            write(out, entries.get(i).getValue(), depth + 1);
            out.append(i < entries.size() - 1 ? ",\n" : "\n");
        }
        indent(out, depth);
        out.append('}');
    }

    private static void array(StringBuilder out, Collection<?> items, int depth) {
        if (items.isEmpty()) {
            out.append("[]");
            return;
        }
        out.append("[\n");
        int i = 0;
        for (Object item : items) {
            indent(out, depth + 1);
            write(out, item, depth + 1);
            out.append(++i < items.size() ? ",\n" : "\n");
        }
        indent(out, depth);
        out.append(']');
    }

    private static void indent(StringBuilder out, int depth) {
        out.append("  ".repeat(depth));
    }

    private static void string(StringBuilder out, String s) {
        out.append('"');
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) out.append(String.format("\\u%04x", (int) c));
                    else out.append(c);
                }
            }
        }
        out.append('"');
    }
}
