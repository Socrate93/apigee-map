package dev.apigeemap.migration;

import dev.apigeemap.protocol.Json;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A {@link TestPlans.Plan} written for a tool that runs it outside apigee-map, as {@link TestRunner} does: each request
 * goes to Edge then to hybrid, and the statuses and the headers the plan names must be the same. The cases that change
 * data run only when asked for, and redirects are not followed.
 */
public final class TestExports {

    /** What a plan can be written as. */
    public enum Format {
        POSTMAN("postman_collection.json", "application/json"),
        CURL("sh", "text/x-shellscript"),
        KARATE("feature", "text/plain");

        public final String extension;
        public final String contentType;

        Format(String extension, String contentType) {
            this.extension = extension;
            this.contentType = contentType;
        }

        /** From its name in any case; null when unknown. */
        public static Format of(String name) {
            for (Format format : values()) if (format.name().equalsIgnoreCase(String.valueOf(name))) return format;
            return null;
        }
    }

    private static final Pattern VARIABLE = Pattern.compile("\\{\\{([A-Za-z][A-Za-z0-9_]{0,39})}}");

    private TestExports() {
    }

    public static String write(Format format, String proxy, TestPlans.Plan plan) {
        return switch (format) {
            case POSTMAN -> postman(proxy, plan);
            case CURL -> curl(proxy, plan);
            case KARATE -> karate(proxy, plan);
        };
    }

    /** The name of the file, from the name of the proxy. */
    public static String fileName(Format format, String proxy) {
        return proxy.replaceAll("[^A-Za-z0-9._-]", "_") + "-regression." + format.extension;
    }

    // -------------------------------------------------------------------------------------------------------------
    // Postman
    // -------------------------------------------------------------------------------------------------------------

    /**
     * A Postman collection (v2.1): each request goes to {@code {{edgeUrl}}}, and its test script sends the same request
     * to {@code {{hybridUrl}}} and compares. The plan's variables are collection variables, empty, as the
     * environment URLs are; the cases that change data skip themselves unless {@code includeUnsafe} is true.
     */
    static String postman(String proxy, TestPlans.Plan plan) {
        List<Map<String, Object>> variables = new ArrayList<>();
        variables.add(variable("edgeUrl", "Scheme and host of the proxy on Edge, e.g. https://edge-api.example.com"));
        variables.add(variable("hybridUrl", "Scheme and host of the proxy on hybrid, e.g. https://hybrid-api.example.com"));
        variables.add(variable("includeUnsafe", "true to also run the requests that change data, on both environments"));
        plan.variables().forEach(v -> variables.add(variable(v.name(), v.description())));

        List<Map<String, Object>> items = new ArrayList<>();
        for (TestPlans.Case c : plan.cases()) {
            Map<String, Object> request = new LinkedHashMap<>();
            request.put("method", c.method());
            request.put("header", c.headers().stream()
                    .map(h -> Map.of("key", h.name(), "value", h.value())).toList());
            if (!c.body().isEmpty()) request.put("body", Map.of("mode", "raw", "raw", c.body()));
            request.put("url", Map.of("raw", "{{edgeUrl}}" + c.path()));
            String description = String.join("\n", java.util.stream.Stream.of(c.purpose(),
                    c.flow().isEmpty() ? "" : "Flow " + c.flow(), c.safe() ? "" : "Changes data on the backend")
                    .filter(t -> !t.isEmpty()).toList());
            if (!description.isEmpty()) request.put("description", description);

            Map<String, Object> item = new LinkedHashMap<>();
            item.put("name", c.name());
            item.put("request", request);
            item.put("protocolProfileBehavior", Map.of("followRedirects", false));
            List<Map<String, Object>> events = new ArrayList<>();
            if (!c.safe()) {
                events.add(event("prerequest", List.of(
                        "if (pm.variables.get('includeUnsafe') !== 'true') {",
                        "    console.log('Skipped, it changes data: " + js(c.name()) + "');",
                        "    pm.execution.skipRequest();",
                        "}")));
            }
            events.add(event("test", postmanTest(c)));
            item.put("event", events);
            items.add(item);
        }

        Map<String, Object> info = new LinkedHashMap<>();
        info.put("name", proxy + " regression tests");
        info.put("description", plan.summary() + (plan.warnings().isEmpty() ? ""
                : "\n\nBefore running:\n- " + String.join("\n- ", plan.warnings())));
        info.put("schema", "https://schema.getpostman.com/json/collection/v2.1.0/collection.json");
        Map<String, Object> collection = new LinkedHashMap<>();
        collection.put("info", info);
        collection.put("item", items);
        collection.put("variable", variables);
        return Json.write(collection) + "\n";
    }

    private static List<String> postmanTest(TestPlans.Case c) {
        List<String> lines = new ArrayList<>();
        lines.add("const edge = pm.response;");
        lines.add("pm.sendRequest({");
        lines.add("    url: pm.variables.replaceIn('{{hybridUrl}}' + " + literal(c.path()) + "),");
        lines.add("    method: '" + c.method() + "',");
        lines.add("    header: pm.request.headers.all().map(h => ({key: h.key, value: pm.variables.replaceIn(h.value)})),");
        if (!c.body().isEmpty()) {
            lines.add("    body: {mode: 'raw', raw: pm.variables.replaceIn(" + literal(c.body()) + ")},");
        }
        lines.add("}, (error, hybrid) => {");
        lines.add("    pm.test('Hybrid answers', () => pm.expect(error).to.equal(null));");
        lines.add("    if (error) return;");
        lines.add("    pm.test('Same status on Edge and hybrid', () => pm.expect(hybrid.code).to.equal(edge.code));");
        for (String header : c.compareHeaders()) {
            lines.add("    pm.test('Same " + js(header) + " on Edge and hybrid', () => pm.expect(hybrid.headers.get('"
                    + js(header) + "')).to.equal(edge.headers.get('" + js(header) + "')));");
        }
        if (c.expectedStatus() != 0) {
            lines.add("    pm.test('Status " + c.expectedStatus() + " as planned', () => pm.expect(edge.code).to.equal("
                    + c.expectedStatus() + "));");
        }
        lines.add("});");
        return lines;
    }

    private static Map<String, Object> variable(String key, String description) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("key", key);
        m.put("value", "");
        m.put("description", description);
        return m;
    }

    private static Map<String, Object> event(String listen, List<String> lines) {
        return Map.of("listen", listen, "script", Map.of("type", "text/javascript", "exec", lines));
    }

    /** A JavaScript string literal, in single quotes. */
    private static String literal(String text) {
        return "'" + js(text) + "'";
    }

    /** The text escaped for a single-quoted JavaScript string. */
    private static String js(String text) {
        StringBuilder out = new StringBuilder();
        for (char ch : text.toCharArray()) {
            switch (ch) {
                case '\\' -> out.append("\\\\");
                case '\'' -> out.append("\\'");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                case ' ' -> out.append("\\u2028");
                case ' ' -> out.append("\\u2029");
                default -> {
                    if (ch < ' ') out.append(String.format("\\u%04x", (int) ch));
                    else out.append(ch);
                }
            }
        }
        return out.toString();
    }

    // -------------------------------------------------------------------------------------------------------------
    // curl
    // -------------------------------------------------------------------------------------------------------------

    /**
     * A bash script that sends each request with curl to {@code $EDGE} then {@code $HYBRID}, prints how each case went
     * and exits with 1 when a case differs or fails. The plan's variables are environment variables of the same name;
     * the cases that change data run only with {@code INCLUDE_UNSAFE=1}.
     */
    static String curl(String proxy, TestPlans.Plan plan) {
        StringBuilder out = new StringBuilder();
        out.append("#!/usr/bin/env bash\n");
        out.append("# Regression tests of ").append(comment(proxy)).append(", run on Edge then on hybrid.\n");
        comment(out, plan.summary());
        out.append("#\n# Usage: EDGE=https://edge-api.example.com HYBRID=https://hybrid-api.example.com");
        plan.variables().forEach(v -> out.append(' ').append(v.name()).append("=..."));
        out.append(" bash ").append(fileName(Format.CURL, proxy)).append('\n');
        out.append("#   INCLUDE_UNSAFE=1 also runs the requests that change data, on both environments.\n");
        for (TestPlans.Variable v : plan.variables()) {
            out.append("#   ").append(v.name());
            if (!v.description().isEmpty()) out.append(": ").append(comment(v.description()));
            out.append('\n');
        }
        if (!plan.warnings().isEmpty()) {
            out.append("#\n# Before running:\n");
            plan.warnings().forEach(w -> out.append("#   - ").append(comment(w)).append('\n'));
        }
        out.append("""
                set -uo pipefail

                : "${EDGE:?Set EDGE to the scheme and host of the proxy on Edge}"
                : "${HYBRID:?Set HYBRID to the scheme and host of the proxy on hybrid}"
                """);
        for (TestPlans.Variable v : plan.variables()) {
            out.append(": \"${").append(v.name()).append(":?Set ").append(v.name()).append("}\"\n");
        }
        out.append("""
                EDGE="${EDGE%/}"
                HYBRID="${HYBRID%/}"
                work="$(mktemp -d)"
                trap 'rm -rf "$work"' EXIT
                same=0 different=0 errors=0 skipped=0

                # header <file> <name>: the values of a response header, joined by ", "
                header() {
                    grep -i "^$2:" "$1" | sed -e 's/^[^:]*:[[:space:]]*//' -e 's/[[:space:]]*$//' | paste -sd ',' - | sed 's/,/, /g'
                }

                # check <name> <path> <expected status, 0 for any> <compared headers> <curl arguments...>
                check() {
                    local name="$1" path="$2" expected="$3" compared="$4"
                    shift 4
                    local edge hybrid problems=()
                    edge=$(curl -sS -o /dev/null -D "$work/edge" -w '%{http_code}' --max-time 30 "$@" "$EDGE$path") \\
                        || { echo "ERROR      $name: Edge did not answer"; errors=$((errors + 1)); return; }
                    hybrid=$(curl -sS -o /dev/null -D "$work/hybrid" -w '%{http_code}' --max-time 30 "$@" "$HYBRID$path") \\
                        || { echo "ERROR      $name: hybrid did not answer"; errors=$((errors + 1)); return; }
                    [ "$edge" = "$hybrid" ] || problems+=("status $edge on Edge, $hybrid on hybrid")
                    local h a b
                    for h in $compared; do
                        a=$(header "$work/edge" "$h")
                        b=$(header "$work/hybrid" "$h")
                        [ "$a" = "$b" ] || problems+=("$h: '${a:-absent}' on Edge, '${b:-absent}' on hybrid")
                    done
                    if [ ${#problems[@]} -eq 0 ]; then
                        echo "SAME       $name ($edge)"
                        same=$((same + 1))
                    else
                        echo "DIFFERENT  $name"
                        printf '           %s\\n' "${problems[@]}"
                        different=$((different + 1))
                    fi
                    if [ "$expected" != 0 ] && [ "$edge" != "$expected" ]; then
                        echo "           Edge answered $edge, the plan expects $expected"
                    fi
                }

                # skip <name>
                skip() {
                    echo "SKIPPED    $1: it changes data, set INCLUDE_UNSAFE=1 to run it"
                    skipped=$((skipped + 1))
                }

                """);
        for (TestPlans.Case c : plan.cases()) {
            out.append('\n');
            comment(out, c.name() + (c.purpose().isEmpty() ? "" : ": " + c.purpose()));
            String indent = "";
            if (!c.safe()) {
                out.append("if [ \"${INCLUDE_UNSAFE:-0}\" = 1 ]; then\n");
                indent = "    ";
            }
            out.append(indent).append("check ").append(shell(c.name())).append(' ').append(shell(c.path()))
                    .append(' ').append(c.expectedStatus()).append(' ')
                    .append(shell(String.join(" ", c.compareHeaders())));
            out.append(c.method().equals("HEAD") ? " --head" : " -X " + c.method());
            for (TestPlans.Header h : c.headers()) {
                out.append(" \\\n").append(indent).append("    -H ").append(shell(h.name() + ": " + h.value()));
            }
            if (!c.body().isEmpty()) {
                out.append(" \\\n").append(indent).append("    --data-binary ").append(shell(c.body()));
            }
            out.append('\n');
            if (!c.safe()) out.append("else\n    skip ").append(shell(c.name())).append("\nfi\n");
        }
        out.append("""

                echo
                echo "$same same, $different different, $errors error(s), $skipped skipped"
                [ $((different + errors)) -eq 0 ]
                """);
        return out.toString();
    }

    /** A bash word that holds the text, with its {@code {{variables}}} expanded from the environment. */
    private static String shell(String text) {
        StringBuilder out = new StringBuilder();
        Matcher matcher = VARIABLE.matcher(text);
        int at = 0;
        while (matcher.find()) {
            out.append(quoted(text.substring(at, matcher.start())));
            out.append("\"${").append(matcher.group(1)).append("}\"");
            at = matcher.end();
        }
        out.append(quoted(text.substring(at)));
        return out.isEmpty() ? "''" : out.toString();
    }

    private static String quoted(String text) {
        return text.isEmpty() ? "" : "'" + text.replace("'", "'\\''") + "'";
    }

    private static void comment(StringBuilder out, String text) {
        for (String line : text.split("\n")) out.append("# ").append(line.strip()).append('\n');
    }

    private static String comment(String text) {
        return text.replaceAll("\\s*\\n\\s*", " ");
    }

    // -------------------------------------------------------------------------------------------------------------
    // Karate
    // -------------------------------------------------------------------------------------------------------------

    /**
     * A Karate feature: each scenario sends its request to {@code edgeUrl} then {@code hybridUrl} and matches the
     * statuses and headers. The URLs and the plan's variables are Java system properties ({@code -DedgeUrl=...}); the
     * scenarios that change data are tagged {@code @unsafe}, to leave out with {@code --tags ~@unsafe}.
     */
    static String karate(String proxy, TestPlans.Plan plan) {
        StringBuilder out = new StringBuilder();
        out.append("Feature: ").append(comment(proxy)).append(" regression tests, on Edge then on hybrid\n\n");
        for (String line : plan.summary().split("\n")) out.append("  ").append(line.strip()).append('\n');
        out.append("\n  Run with -DedgeUrl=https://edge-api.example.com -DhybridUrl=https://hybrid-api.example.com");
        plan.variables().forEach(v -> out.append(" -D").append(v.name()).append("=..."));
        out.append(",\n  and --tags ~@unsafe to leave out the requests that change data.\n");
        for (TestPlans.Variable v : plan.variables()) {
            if (!v.description().isEmpty()) {
                out.append("  ").append(v.name()).append(": ").append(comment(v.description())).append('\n');
            }
        }
        plan.warnings().forEach(w -> out.append("  Before running: ").append(comment(w)).append('\n'));

        out.append("\n  Background:\n");
        out.append("    * configure followRedirects = false\n");
        out.append("    * def edgeUrl = karate.properties['edgeUrl']\n");
        out.append("    * def hybridUrl = karate.properties['hybridUrl']\n");
        out.append("    * if (!edgeUrl || !hybridUrl) karate.fail('Set -DedgeUrl and -DhybridUrl')\n");
        out.append("    * def vars = {}\n");
        for (TestPlans.Variable v : plan.variables()) {
            out.append("    * vars['").append(v.name()).append("'] = karate.properties['").append(v.name())
                    .append("']\n");
            out.append("    * if (!vars['").append(v.name()).append("']) karate.fail('Set -D").append(v.name())
                    .append("')\n");
        }

        for (TestPlans.Case c : plan.cases()) {
            out.append('\n');
            if (!c.safe()) out.append("  @unsafe\n");
            out.append("  Scenario: ").append(comment(c.name())).append('\n');
            if (!c.purpose().isEmpty()) out.append("    # ").append(comment(c.purpose())).append('\n');
            out.append("    * def path = ").append(karateText(c.path())).append('\n');
            karateRequest(out, c, "edgeUrl");
            out.append("    * def edgeStatus = responseStatus\n");
            out.append("    * def edgeHeaders = {}\n");
            for (String header : c.compareHeaders()) {
                out.append("    * edgeHeaders['").append(js(header)).append("'] = karate.response.header('")
                        .append(js(header)).append("')\n");
            }
            karateRequest(out, c, "hybridUrl");
            out.append("    * match responseStatus == edgeStatus\n");
            for (String header : c.compareHeaders()) {
                out.append("    * match karate.response.header('").append(js(header)).append("') == edgeHeaders['")
                        .append(js(header)).append("']\n");
            }
            if (c.expectedStatus() != 0) out.append("    * match edgeStatus == ").append(c.expectedStatus()).append('\n');
        }
        return out.toString();
    }

    private static void karateRequest(StringBuilder out, TestPlans.Case c, String base) {
        out.append("    Given url ").append(base).append(" + path\n");
        for (TestPlans.Header h : c.headers()) {
            out.append("    And header ").append(h.name()).append(" = ").append(karateText(h.value())).append('\n');
        }
        if (!c.body().isEmpty()) out.append("    And request ").append(karateText(c.body())).append('\n');
        out.append("    When method ").append(c.method().toLowerCase()).append('\n');
    }

    /** A JavaScript expression of the text, its {@code {{variables}}} read from {@code vars}. */
    private static String karateText(String text) {
        List<String> parts = new ArrayList<>();
        Matcher matcher = VARIABLE.matcher(text);
        int at = 0;
        while (matcher.find()) {
            if (matcher.start() > at) parts.add(literal(text.substring(at, matcher.start())));
            parts.add("vars['" + matcher.group(1) + "']");
            at = matcher.end();
        }
        if (at < text.length() || parts.isEmpty()) parts.add(literal(text.substring(at)));
        return String.join(" + ", parts);
    }
}
