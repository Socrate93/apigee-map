package dev.apigeemap.ui;

import java.lang.reflect.RecordComponent;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal JSON support for the UI API, without dependencies. Parsing yields Map, List, String, Double, Boolean
 * or null; writing also accepts records (their components become fields), enums and any object via toString.
 */
final class Json {

    private Json() {
    }

    static String write(Object value) {
        StringBuilder out = new StringBuilder();
        write(value, out, "");
        return out.toString();
    }

    private static void write(Object value, StringBuilder out, String indent) {
        String inner = indent + "  ";
        switch (value) {
            case null -> out.append("null");
            case Boolean b -> out.append(b);
            case Number n -> out.append(n instanceof Double d && d == Math.rint(d) && !d.isInfinite()
                    ? String.valueOf(d.longValue()) : n.toString());
            case Map<?, ?> map -> {
                if (map.isEmpty()) {
                    out.append("{}");
                    return;
                }
                out.append("{\n");
                int i = 0;
                for (Map.Entry<?, ?> entry : map.entrySet()) {
                    out.append(inner);
                    string(String.valueOf(entry.getKey()), out);
                    out.append(": ");
                    write(entry.getValue(), out, inner);
                    out.append(++i < map.size() ? ",\n" : "\n");
                }
                out.append(indent).append('}');
            }
            case Collection<?> list -> {
                if (list.isEmpty()) {
                    out.append("[]");
                    return;
                }
                out.append("[\n");
                int i = 0;
                for (Object item : list) {
                    out.append(inner);
                    write(item, out, inner);
                    out.append(++i < list.size() ? ",\n" : "\n");
                }
                out.append(indent).append(']');
            }
            case Record record -> write(fields(record), out, indent);
            case Enum<?> e -> string(e.name(), out);
            default -> string(value.toString(), out);
        }
    }

    private static Map<String, Object> fields(Record record) {
        Map<String, Object> fields = new LinkedHashMap<>();
        for (RecordComponent component : record.getClass().getRecordComponents()) {
            try {
                component.getAccessor().setAccessible(true);
                fields.put(component.getName(), component.getAccessor().invoke(record));
            } catch (ReflectiveOperationException e) {
                throw new IllegalStateException(e);
            }
        }
        return fields;
    }

    private static void string(String text, StringBuilder out) {
        out.append('"');
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                // keeps the JSON safe to embed in HTML
                case '<' -> out.append("\\u003c");
                default -> {
                    if (c < 0x20) out.append(String.format("\\u%04x", (int) c));
                    else out.append(c);
                }
            }
        }
        out.append('"');
    }

    static Object parse(String text) {
        Parser parser = new Parser(text);
        Object value = parser.value();
        parser.skipWhitespace();
        if (parser.pos != text.length()) throw parser.error("Unexpected trailing content");
        return value;
    }

    private static final class Parser {
        private final String text;
        private int pos;

        Parser(String text) {
            this.text = text;
        }

        Object value() {
            skipWhitespace();
            if (pos >= text.length()) throw error("Unexpected end of input");
            char c = text.charAt(pos);
            return switch (c) {
                case '{' -> object();
                case '[' -> array();
                case '"' -> string();
                case 't' -> literal("true", Boolean.TRUE);
                case 'f' -> literal("false", Boolean.FALSE);
                case 'n' -> literal("null", null);
                default -> number();
            };
        }

        private Map<String, Object> object() {
            Map<String, Object> map = new LinkedHashMap<>();
            pos++;
            skipWhitespace();
            if (peek('}')) return map;
            do {
                skipWhitespace();
                if (!peekChar('"')) throw error("Expected a field name");
                String key = string();
                skipWhitespace();
                expect(':');
                map.put(key, value());
                skipWhitespace();
            } while (consume(','));
            expect('}');
            return map;
        }

        private List<Object> array() {
            List<Object> list = new ArrayList<>();
            pos++;
            skipWhitespace();
            if (peek(']')) return list;
            do {
                list.add(value());
                skipWhitespace();
            } while (consume(','));
            expect(']');
            return list;
        }

        private String string() {
            StringBuilder out = new StringBuilder();
            pos++;
            while (pos < text.length()) {
                char c = text.charAt(pos++);
                if (c == '"') return out.toString();
                if (c != '\\') {
                    out.append(c);
                    continue;
                }
                if (pos >= text.length()) break;
                char escaped = text.charAt(pos++);
                switch (escaped) {
                    case 'n' -> out.append('\n');
                    case 'r' -> out.append('\r');
                    case 't' -> out.append('\t');
                    case 'b' -> out.append('\b');
                    case 'f' -> out.append('\f');
                    case 'u' -> {
                        if (pos + 4 > text.length()) throw error("Invalid unicode escape");
                        out.append((char) Integer.parseInt(text.substring(pos, pos + 4), 16));
                        pos += 4;
                    }
                    default -> out.append(escaped);
                }
            }
            throw error("Unterminated string");
        }

        private Object literal(String word, Object value) {
            if (!text.startsWith(word, pos)) throw error("Unexpected token");
            pos += word.length();
            return value;
        }

        private Double number() {
            int start = pos;
            while (pos < text.length() && "+-0123456789.eE".indexOf(text.charAt(pos)) >= 0) pos++;
            if (start == pos) throw error("Unexpected character '" + text.charAt(pos) + "'");
            try {
                return Double.valueOf(text.substring(start, pos));
            } catch (NumberFormatException e) {
                throw error("Invalid number");
            }
        }

        void skipWhitespace() {
            while (pos < text.length() && Character.isWhitespace(text.charAt(pos))) pos++;
        }

        private boolean peek(char c) {
            if (peekChar(c)) {
                pos++;
                return true;
            }
            return false;
        }

        private boolean peekChar(char c) {
            return pos < text.length() && text.charAt(pos) == c;
        }

        private boolean consume(char c) {
            skipWhitespace();
            return peek(c);
        }

        private void expect(char c) {
            skipWhitespace();
            if (!peek(c)) throw error("Expected '" + c + "'");
        }

        IllegalArgumentException error(String message) {
            return new IllegalArgumentException(message + " at position " + pos);
        }
    }
}
