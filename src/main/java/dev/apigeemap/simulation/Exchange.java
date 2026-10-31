package dev.apigeemap.simulation;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** The flow variables and messages of one simulated call. */
final class Exchange {

    /** A request, a response, or a message a policy created. */
    static final class Message {
        final Map<String, String> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        final Map<String, String> query = new LinkedHashMap<>();
        String verb;
        String path;
        String content;
        String status;
        String reason;
    }

    /** {@code {variable}} or {@code {variable:default}}; functions and JSON are left as they are. */
    private static final Pattern TEMPLATE = Pattern.compile("\\{([A-Za-z_][\\w.-]*)(?::([^}]*))?}");

    private final Map<String, Message> messages = new LinkedHashMap<>();
    private final Map<String, String> variables = new LinkedHashMap<>();
    /** The message {@code message.*} stands for: the request, then the response. */
    String current = "request";

    Exchange() {
        messages.put("request", new Message());
        messages.put("response", new Message());
    }

    Message message(String name) {
        return messages.computeIfAbsent(name.equals("message") ? current : name, n -> new Message());
    }

    private record Field(Message message, String field) {
    }

    /** The message and field a name stands for, when it starts with the name of a message. */
    private Field field(String name) {
        String resolved = name.equals("message") || name.startsWith("message.")
                ? current + name.substring("message".length()) : name;
        int dot = resolved.indexOf('.');
        if (dot < 0) return null;
        Message message = messages.get(resolved.substring(0, dot));
        return message == null ? null : new Field(message, resolved.substring(dot + 1));
    }

    String get(String name) {
        Field field = field(name);
        if (field == null) return variables.get(name);
        Message message = field.message();
        String part = field.field();
        if (part.startsWith("header.")) return message.headers.get(part.substring(7));
        if (part.startsWith("queryparam.")) return message.query.get(part.substring(11));
        return switch (part) {
            case "content" -> message.content;
            case "verb" -> message.verb;
            case "path" -> message.path;
            case "uri" -> message.path == null ? null : message.path + queryString(message, "?");
            case "querystring" -> queryString(message, "");
            case "status", "status.code" -> message.status;
            case "reason.phrase" -> message.reason;
            default -> variables.get(name);
        };
    }

    private static String queryString(Message message, String prefix) {
        if (message.query.isEmpty()) return "";
        StringBuilder out = new StringBuilder(prefix);
        message.query.forEach((name, value) -> {
            if (out.length() > prefix.length()) out.append('&');
            out.append(name).append('=').append(value);
        });
        return out.toString();
    }

    /** @param value null removes it */
    void set(String name, String value) {
        Field field = field(name);
        if (field != null) {
            Message message = field.message();
            String part = field.field();
            if (part.startsWith("header.")) {
                put(message.headers, part.substring(7), value);
                return;
            }
            if (part.startsWith("queryparam.")) {
                put(message.query, part.substring(11), value);
                return;
            }
            switch (part) {
                case "content" -> message.content = value;
                case "verb" -> message.verb = value;
                case "path" -> message.path = value;
                case "status", "status.code" -> message.status = value;
                case "reason.phrase" -> message.reason = value;
                default -> put(variables, name, value);
            }
            return;
        }
        put(variables, name, value);
    }

    private static void put(Map<String, String> map, String name, String value) {
        if (value == null) map.remove(name);
        else map.put(name, value);
    }

    /** The text of a message template with its variables replaced; one without a value and a default becomes empty. */
    String template(String text) {
        if (text == null) return null;
        Matcher matcher = TEMPLATE.matcher(text);
        return matcher.replaceAll(match -> {
            String value = get(match.group(1));
            if (value == null) value = match.group(2) != null ? match.group(2) : "";
            return Matcher.quoteReplacement(value);
        });
    }

    /** Every value, by name. */
    Map<String, String> snapshot() {
        Map<String, String> values = new LinkedHashMap<>(variables);
        messages.forEach((name, message) -> {
            message.headers.forEach((header, value) -> values.put(name + ".header." + header, value));
            message.query.forEach((param, value) -> values.put(name + ".queryparam." + param, value));
            put(values, name + ".content", message.content);
            put(values, name + ".verb", message.verb);
            put(values, name + ".path", message.path);
            put(values, name + ".status.code", message.status);
            put(values, name + ".reason.phrase", message.reason);
        });
        return values;
    }
}
