package dev.apigeemap.migration;

import dev.apigeemap.protocol.Json;

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * What {@link TestRunner} reads from a response to chain the cases of a plan and compare their shapes: parameters of
 * a Location, fields of a JSON body, the first HTML form of a page. The exports do the same in their own language.
 */
final class Responses {

    /** An HTML form: where it is sent, how, and the values of its named inputs. */
    record Form(String action, String method, Map<String, String> fields) {
    }

    private static final Pattern FORM = Pattern.compile("<form\\b([^>]*)>(.*?)(?:</form\\s*>|$)",
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    private static final Pattern INPUT = Pattern.compile("<input\\b([^>]*)>", Pattern.CASE_INSENSITIVE);
    private static final Pattern ATTRIBUTE = Pattern.compile(
            "([A-Za-z_:][-A-Za-z0-9_:.]*)\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s\"'>]+))");
    private static final Pattern ENTITY = Pattern.compile("&(amp|lt|gt|quot|apos|#39|#(\\d+)|#x([0-9a-fA-F]+));");

    private Responses() {
    }

    /**
     * The first form of the page, its action resolved against the page URL; null when there is none. Its inputs are
     * those with a name, except buttons, unchecked boxes and files.
     */
    static Form form(String html, URI page) {
        Matcher form = FORM.matcher(html);
        if (!form.find()) return null;
        Map<String, String> attributes = attributes(form.group(1));
        String action = attributes.getOrDefault("action", "");
        String method = attributes.getOrDefault("method", "GET").toUpperCase();
        Map<String, String> fields = new LinkedHashMap<>();
        Matcher input = INPUT.matcher(form.group(2));
        while (input.find()) {
            Map<String, String> a = attributes(input.group(1));
            String type = a.getOrDefault("type", "text").toLowerCase();
            String name = a.get("name");
            if (name == null || name.isEmpty() || List.of("submit", "button", "image", "reset", "file").contains(type)
                    || (List.of("checkbox", "radio").contains(type) && !a.containsKey("checked"))) {
                continue;
            }
            fields.putIfAbsent(name, a.getOrDefault("value", ""));
        }
        return new Form(page.resolve(action.isEmpty() ? page.toString() : action.strip()).toString(),
                method.equals("POST") ? "POST" : "GET", fields);
    }

    private static Map<String, String> attributes(String tag) {
        Map<String, String> attributes = new LinkedHashMap<>();
        Matcher matcher = ATTRIBUTE.matcher(tag);
        while (matcher.find()) {
            String value = matcher.group(2) != null ? matcher.group(2)
                    : matcher.group(3) != null ? matcher.group(3) : matcher.group(4);
            attributes.putIfAbsent(matcher.group(1).toLowerCase(), unescape(value));
        }
        // a bare attribute such as checked
        Matcher bare = Pattern.compile("(?:^|\\s)(checked)(?=\\s|/|$)", Pattern.CASE_INSENSITIVE).matcher(tag);
        if (bare.find()) attributes.putIfAbsent("checked", "");
        return attributes;
    }

    private static String unescape(String text) {
        return ENTITY.matcher(text).replaceAll(m -> Matcher.quoteReplacement(switch (m.group(1)) {
            case "amp" -> "&";
            case "lt" -> "<";
            case "gt" -> ">";
            case "quot" -> "\"";
            case "apos", "#39" -> "'";
            default -> Character.toString(m.group(2) != null ? Integer.parseInt(m.group(2))
                    : Integer.parseInt(m.group(3), 16));
        }));
    }

    /** A parameter of the query string or of the fragment of a URL, decoded; null when absent. */
    static String param(String url, String key) {
        for (String part : List.of(after(url, '?', '#'), after(url, '#', (char) 0))) {
            String found = params(part).get(key);
            if (found != null) return found;
        }
        return null;
    }

    private static String after(String url, char start, char end) {
        int at = url.indexOf(start);
        if (at < 0) return "";
        int stop = end == 0 ? -1 : url.indexOf(end, at);
        return stop < 0 ? url.substring(at + 1) : url.substring(at + 1, stop);
    }

    /** The parameters of a query string, decoded, the first value of each. */
    static Map<String, String> params(String query) {
        Map<String, String> params = new LinkedHashMap<>();
        for (String pair : query.split("&")) {
            if (pair.isEmpty()) continue;
            int eq = pair.indexOf('=');
            String name = decode(eq < 0 ? pair : pair.substring(0, eq));
            params.putIfAbsent(name, eq < 0 ? "" : decode(pair.substring(eq + 1)));
        }
        return params;
    }

    private static String decode(String text) {
        try {
            return URLDecoder.decode(text, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return text;
        }
    }

    /**
     * What a Location looks like whatever the codes and states it holds: the URL without its parameter values, the
     * names of the query and fragment parameters sorted, and the scheme and host of the environment written {@code
     * {base}}, as they differ between Edge and hybrid. E.g. {@code {base}/cb?code&state}.
     */
    static String shape(String location, String base) {
        String url = relative(location, base);
        int cut = url.length();
        for (char c : new char[]{'?', '#'}) if (url.indexOf(c) >= 0) cut = Math.min(cut, url.indexOf(c));
        StringBuilder shape = new StringBuilder(url.substring(0, cut));
        String query = after(url, '?', '#');
        String fragment = after(url, '#', (char) 0);
        if (!query.isEmpty()) shape.append('?').append(String.join("&", new TreeSet<>(params(query).keySet())));
        if (!fragment.isEmpty()) shape.append('#').append(String.join("&", new TreeSet<>(params(fragment).keySet())));
        return shape.toString();
    }

    /**
     * A location with the scheme and host of the environment written {@code {base}}, so that the same redirect
     * reads the same on Edge and hybrid.
     */
    static String relative(String location, String base) {
        return location.startsWith(base) ? "{base}" + location.substring(base.length()) : location;
    }

    /** A field of a JSON body by its dotted path, as text; null when the body is not JSON or has no such field. */
    static String json(String body, String path) {
        Object value = parse(body);
        for (String part : path.split("\\.")) {
            if (value instanceof Map<?, ?> map) value = map.get(part);
            else if (value instanceof List<?> list && part.matches("\\d{1,4}") && Integer.parseInt(part) < list.size()) {
                value = list.get(Integer.parseInt(part));
            } else return null;
        }
        if (value == null) return null;
        return value instanceof String s ? s : Json.write(value);
    }

    /** The keys of a JSON object body, sorted; null when the body is not a JSON object. */
    static List<String> keys(String body) {
        return parse(body) instanceof Map<?, ?> map ? new ArrayList<>(new TreeSet<>(map.keySet().stream()
                .map(String::valueOf).toList())) : null;
    }

    private static Object parse(String body) {
        String text = body.strip();
        if (!text.startsWith("{") && !text.startsWith("[")) return null;
        try {
            return Json.parse(text);
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** Fields as a form-urlencoded body. */
    static String encode(Map<String, String> fields) {
        List<String> pairs = new ArrayList<>();
        fields.forEach((k, v) -> pairs.add(URLEncoder.encode(k, StandardCharsets.UTF_8) + "="
                + URLEncoder.encode(v, StandardCharsets.UTF_8)));
        return String.join("&", pairs);
    }

    /**
     * The fields a plan's body gives a form, {@code name=value} pairs joined by {@code &}, as written: the values are
     * not decoded, as they are variables' values.
     */
    static Map<String, String> fields(String body) {
        Map<String, String> fields = new LinkedHashMap<>();
        for (String pair : body.split("&")) {
            if (pair.isBlank()) continue;
            int eq = pair.indexOf('=');
            fields.put(eq < 0 ? pair.strip() : pair.substring(0, eq).strip(), eq < 0 ? "" : pair.substring(eq + 1));
        }
        return fields;
    }
}
