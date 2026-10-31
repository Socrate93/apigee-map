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

    /**
     * The indexes of the cases that run as a chain, each environment on its own: those that capture a value and
     * those that use one.
     */
    static java.util.Set<Integer> chain(TestPlans.Plan plan) {
        java.util.Set<String> captured = plan.captured();
        java.util.Set<Integer> chain = new java.util.TreeSet<>();
        for (int i = 0; i < plan.cases().size(); i++) {
            TestPlans.Case c = plan.cases().get(i);
            if (!c.captures().isEmpty() || TestRunner.uses(c).stream().anyMatch(captured::contains)) chain.add(i);
        }
        return chain;
    }

    /** The compared headers; with the Location too when the shapes are compared, as {@link TestRunner} does. */
    private static List<String> compared(TestPlans.Case c) {
        if (!c.shapeOnly() || c.compareHeaders().contains("location")) return c.compareHeaders();
        List<String> headers = new ArrayList<>(c.compareHeaders());
        headers.add("location");
        return headers;
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
     * environment URLs are; the cases that change data skip themselves unless {@code includeUnsafe} is true. The
     * cases of a chain are in two folders, run in order: on Edge, each keeping its answer, then on hybrid, each
     * matching Edge's; their captured values are collection variables prefixed with the environment.
     */
    static String postman(String proxy, TestPlans.Plan plan) {
        java.util.Set<Integer> chain = chain(plan);
        List<Map<String, Object>> variables = new ArrayList<>();
        variables.add(variable("edgeUrl", "Scheme and host of the proxy on Edge, e.g. https://edge-api.example.com"));
        variables.add(variable("hybridUrl", "Scheme and host of the proxy on hybrid, e.g. https://hybrid-api.example.com"));
        variables.add(variable("includeUnsafe", "true to also run the requests that change data, on both environments"));
        plan.variables().forEach(v -> variables.add(variable(v.name(), v.description())));

        List<Map<String, Object>> items = new ArrayList<>();
        for (int i = 0; i < plan.cases().size(); i++) {
            TestPlans.Case c = plan.cases().get(i);
            if (chain.contains(i)) {
                if (i == chain.iterator().next()) {
                    for (String env : List.of("edge", "hybrid")) items.add(postmanChain(plan, chain, env));
                }
                continue;
            }
            Map<String, Object> request = new LinkedHashMap<>();
            request.put("method", c.method());
            request.put("header", c.headers().stream()
                    .map(h -> Map.of("key", h.name(), "value", h.value())).toList());
            if (!c.body().isEmpty()) request.put("body", Map.of("mode", "raw", "raw", c.body()));
            request.put("url", "{{edgeUrl}}" + c.path());
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

    /** The folder of the chain on one environment. */
    private static Map<String, Object> postmanChain(TestPlans.Plan plan, java.util.Set<Integer> chain, String env) {
        java.util.Set<String> captured = plan.captured();
        String label = env.equals("edge") ? "Edge" : "hybrid";
        List<Map<String, Object>> items = new ArrayList<>();
        for (int i : chain) {
            TestPlans.Case c = plan.cases().get(i);
            Map<String, Object> request = new LinkedHashMap<>();
            request.put("method", c.form().isEmpty() ? c.method() : "POST");
            request.put("header", c.headers().stream()
                    .map(h -> Map.of("key", h.name(), "value", prefixed(h.value(), captured, env))).toList());
            String url;
            if (!c.form().isEmpty()) url = "{{" + env + "_" + c.form() + "}}";
            else if (c.path().startsWith("/")) url = "{{" + env + "Url}}" + prefixed(c.path(), captured, env);
            else url = prefixed(c.path(), captured, env);
            if (!c.form().isEmpty()) {
                // filled with the form's fields before it is sent
                request.put("body", Map.of("mode", "urlencoded", "urlencoded", List.of()));
            } else if (!c.body().isEmpty()) {
                request.put("body", Map.of("mode", "raw", "raw", prefixed(c.body(), captured, env)));
            }
            request.put("url", url);
            if (!c.purpose().isEmpty()) request.put("description", c.purpose());

            List<String> pre = new ArrayList<>();
            if (!c.safe()) {
                pre.add("if (pm.variables.get('includeUnsafe') !== 'true') {");
                pre.add("    console.log('Skipped, it changes data: " + js(c.name()) + "');");
                pre.add("    pm.execution.skipRequest();");
                pre.add("}");
            }
            List<String> needed = TestRunner.uses(c).stream().filter(captured::contains).toList();
            if (!needed.isEmpty()) {
                pre.add("const missing = [" + String.join(", ", needed.stream().map(TestExports::literal).toList())
                        + "].filter(n => !pm.collectionVariables.get('" + env + "_' + n));");
                pre.add("if (missing.length) {");
                pre.add("    pm.test('Captured ' + missing.join(', ') + ' on " + label + "', () => pm.expect(missing).to.be.empty);");
                pre.add("    pm.execution.skipRequest();");
                pre.add("}");
            }
            if (!c.form().isEmpty()) {
                pre.add("const form = JSON.parse(pm.collectionVariables.get('" + env + "_" + c.form() + "_form') || 'null');");
                pre.add("if (form) {");
                pre.add("const fields = Object.assign({}, form.fields);");
                Responses.fields(c.body()).forEach((k, v) -> pre.add("fields[" + literal(k)
                        + "] = pm.variables.replaceIn(" + literal(prefixed(v, captured, env)) + ");"));
                pre.add("pm.request.method = form.method;");
                pre.add("pm.request.body.update({mode: 'urlencoded', urlencoded: Object.keys(fields)"
                        + ".map(key => ({key: key, value: fields[key]}))});");
                pre.add("}");
            }

            List<String> test = new ArrayList<>(List.of(
                    "const base = pm.variables.get('" + env + "Url');",
                    "const page = pm.request.url.toString();",
                    "const resolve = (u, p) => /^https?:\\/\\//i.test(u) ? u : u.startsWith('//') ? p.split('//')[0] + u"
                            + " : u.startsWith('/') ? p.match(/^[a-z]+:\\/\\/[^\\/?#]*/i)[0] + u"
                            + " : p.replace(/[?#].*$/, '').replace(/\\/[^\\/]*$/, '/') + u;",
                    "const location = pm.response.headers.get('Location') ? resolve(pm.response.headers.get('Location'), page) : null;",
                    "const names = t => t.split('&').filter(p => p).map(p => p.split('=')[0]).sort().join('&');",
                    "const shape = u => { if (u.startsWith(base)) u = '{base}' + u.substring(base.length);"
                            + " const hash = u.indexOf('#'); const q = u.indexOf('?');"
                            + " let out = u.split(/[?#]/)[0];"
                            + " if (q >= 0 && (hash < 0 || q < hash)) out += '?' + names(u.substring(q + 1, hash < 0 ? u.length : hash));"
                            + " if (hash >= 0) out += '#' + names(u.substring(hash + 1)); return out; };",
                    "const param = (u, n) => { for (const p of u.split(/[?#]/).slice(1).join('&').split('&')) {"
                            + " const eq = p.indexOf('='); const k = decodeURIComponent((eq < 0 ? p : p.substring(0, eq)).replace(/\\+/g, ' '));"
                            + " if (k === n) return eq < 0 ? '' : decodeURIComponent(p.substring(eq + 1).replace(/\\+/g, ' ')); } return null; };",
                    "let body = null;",
                    "try { body = pm.response.json(); } catch (e) { body = null; }",
                    "const seen = {status: pm.response.code, headers: {}};"));
            for (String header : compared(c)) {
                String h = literal(header);
                if (header.equals("location")) {
                    test.add("seen.headers[" + h + "] = location == null ? null : " + (c.shapeOnly() ? "shape(location)"
                            : "location.startsWith(base) ? '{base}' + location.substring(base.length) : location") + ";");
                } else {
                    test.add("seen.headers[" + h + "] = pm.response.headers.get(" + h + ") == null ? null : "
                            + (c.shapeOnly() ? "'present'" : "pm.response.headers.get(" + h + ")") + ";");
                }
            }
            if (c.shapeOnly()) {
                test.add("seen.keys = body && typeof body === 'object' && !Array.isArray(body) ? Object.keys(body).sort() : null;");
            }
            if (env.equals("edge")) {
                test.add("pm.collectionVariables.set('seen_" + i + "', JSON.stringify(seen));");
            } else {
                test.add("pm.test('Same as on Edge', () => pm.expect(seen).to.deep.equal("
                        + "JSON.parse(pm.collectionVariables.get('seen_" + i + "') || 'null')));");
            }
            if (c.expectedStatus() != 0) {
                test.add("pm.test('Status " + c.expectedStatus() + " as planned', () => pm.expect(pm.response.code).to.equal("
                        + c.expectedStatus() + "));");
            }
            for (TestPlans.Capture capture : c.captures()) {
                String key = literal(capture.key());
                String variable = literal(env + "_" + capture.name());
                String value = switch (capture.from()) {
                    case "location" -> "location";
                    case "query" -> "location == null ? null : param(location, " + key + ")";
                    case "header" -> "pm.response.headers.get(" + key + ")";
                    case "json" -> "(() => { let v = body; for (const k of " + key + ".split('.')) v = v != null"
                            + " && typeof v === 'object' ? v[k] : null; return v == null ? null"
                            + " : typeof v === 'object' ? JSON.stringify(v) : String(v); })()";
                    default -> "(() => { const $ = require('cheerio').load(pm.response.text()); const f = $('form').first();"
                            + " if (!f.length) return null; const fields = {};"
                            + " f.find('input[name]').each((i, e) => { const t = ($(e).attr('type') || 'text').toLowerCase();"
                            + " if (['submit', 'button', 'image', 'reset', 'file'].includes(t)) return;"
                            + " if (['checkbox', 'radio'].includes(t) && $(e).attr('checked') === undefined) return;"
                            + " const n = $(e).attr('name'); if (!(n in fields)) fields[n] = $(e).attr('value') || ''; });"
                            + " const action = resolve(f.attr('action') || page, page);"
                            + " pm.collectionVariables.set(" + literal(env + "_" + capture.name() + "_form")
                            + ", JSON.stringify({action: action, method: (f.attr('method') || 'GET').toUpperCase(),"
                            + " fields: fields})); return action; })()";
                };
                test.add("pm.collectionVariables.set(" + variable + ", " + value + " || '');");
            }

            Map<String, Object> item = new LinkedHashMap<>();
            item.put("name", c.name());
            item.put("request", request);
            item.put("protocolProfileBehavior", Map.of("followRedirects", false));
            List<Map<String, Object>> events = new ArrayList<>();
            if (!pre.isEmpty()) events.add(event("prerequest", pre));
            events.add(event("test", test));
            item.put("event", events);
            items.add(item);
        }
        Map<String, Object> folder = new LinkedHashMap<>();
        folder.put("name", "Chained requests on " + label);
        folder.put("description", env.equals("edge")
                ? "Run before the hybrid folder: each answer is kept to compare with hybrid's."
                : "Run after the Edge folder: each answer must match Edge's.");
        folder.put("item", items);
        return folder;
    }

    /** The text with its captured values renamed for the environment, e.g. {@code {{edge_state}}}. */
    private static String prefixed(String text, java.util.Set<String> captured, String env) {
        return VARIABLE.matcher(text).replaceAll(m -> Matcher.quoteReplacement(captured.contains(m.group(1))
                ? "{{" + env + "_" + m.group(1) + "}}" : m.group()));
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
     * the cases that change data run only with {@code INCLUDE_UNSAFE=1}. The cases of a chain run on each
     * environment with its own captured values and cookies, and compare their shapes where the plan says so: the
     * Location by its parameter names, the headers by their presence, a JSON body by the names of its fields.
     */
    static String curl(String proxy, TestPlans.Plan plan) {
        java.util.Set<Integer> chain = chain(plan);
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
        if (!chain.isEmpty()) out.append(CURL_CHAIN);
        for (int i = 0; i < plan.cases().size(); i++) {
            TestPlans.Case c = plan.cases().get(i);
            if (chain.contains(i)) {
                curlChained(out, c, plan.captured());
                continue;
            }
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

    /** One case of a chain: sent to each environment with its captured values, then compared. */
    private static void curlChained(StringBuilder out, TestPlans.Case c, java.util.Set<String> captured) {
        out.append('\n');
        comment(out, c.name() + (c.purpose().isEmpty() ? "" : ": " + c.purpose()));
        String indent = "";
        if (!c.safe()) {
            out.append("if [ \"${INCLUDE_UNSAFE:-0}\" = 1 ]; then\n");
            indent = "    ";
        }
        out.append(indent).append("for env in edge hybrid; do\n");
        String inner = indent + "    ";
        java.util.Set<String> needed = new java.util.LinkedHashSet<>();
        for (String name : TestRunner.uses(c)) if (captured.contains(name)) needed.add(name);
        out.append(inner).append("begin \"$env\"");
        needed.forEach(n -> out.append(' ').append(n));
        out.append('\n');
        StringBuilder headers = new StringBuilder();
        for (TestPlans.Header h : c.headers()) {
            headers.append(" \\\n").append(inner).append("    -H ").append(shell(h.name() + ": " + h.value(), captured));
        }
        if (!c.form().isEmpty()) {
            out.append(inner).append("submit \"$env\" ").append(c.form());
            Responses.fields(c.body()).forEach((k, v) -> out.append(' ').append(quoted(k).isEmpty() ? "''" : quoted(k))
                    .append(' ').append(shell(v, captured)));
            out.append(headers).append('\n');
        } else {
            out.append(inner).append("request \"$env\" ").append(shell(c.path(), captured))
                    .append(c.method().equals("HEAD") ? " --head" : " -X " + c.method()).append(headers);
            if (!c.body().isEmpty()) {
                out.append(" \\\n").append(inner).append("    --data-binary ").append(shell(c.body(), captured));
            }
            out.append('\n');
        }
        for (TestPlans.Capture capture : c.captures()) {
            out.append(inner).append("capture \"$env\" ").append(capture.from()).append(' ').append(capture.name())
                    .append(' ').append(capture.key().isEmpty() ? "''" : quoted(capture.key())).append('\n');
        }
        out.append(indent).append("done\n");
        out.append(indent).append("compare ").append(shell(c.name())).append(' ').append(c.expectedStatus()).append(' ')
                .append(shell(String.join(" ", compared(c)))).append(' ').append(c.shapeOnly() ? 1 : 0).append('\n');
        if (!c.safe()) out.append("else\n    skip ").append(shell(c.name())).append("\nfi\n");
    }

    /** The functions the cases of a chain run with: one request per environment, then a comparison. */
    private static final String CURL_CHAIN = """
            # The cases of a chain run on each environment with what its earlier answers gave, in files of $work.
            for env in edge hybrid; do : > "$work/$env.cookies"; done

            # base <env>
            base() { if [ "$1" = edge ]; then printf '%s' "$EDGE"; else printf '%s' "$HYBRID"; fi; }

            # cap <env> <name>: a value captured on the environment
            cap() { cat "$work/$1.cap-$2" 2>/dev/null; }

            # begin <env> <captured names...>: starts a case, failed when a value it needs was not captured
            begin() {
                local env="$1" name
                shift
                rm -f "$work/$env.failed" "$work/$env.status" "$work/$env.headers" "$work/$env.body"
                : > "$work/$env.headers"
                : > "$work/$env.body"
                for name in "$@"; do
                    [ -s "$work/$env.cap-$name" ] || { echo "$name was not captured on $env" > "$work/$env.failed"; return; }
                done
            }

            # origin <url>: its scheme and host
            origin() { printf '%s' "$1" | sed -E 's#^([A-Za-z]+://[^/?#]*).*#\\1#'; }

            # resolve <url> <page>: the url, relative or not, from the page it was found on
            resolve() {
                case "$1" in
                    http://*|https://*) printf '%s' "$1" ;;
                    //*) printf '%s' "${2%%//*}$1" ;;
                    /*) printf '%s%s' "$(origin "$2")" "$1" ;;
                    '') printf '%s' "$2" ;;
                    *) printf '%s/%s' "$(printf '%s' "${2%%[?#]*}" | sed 's#/[^/]*$##')" "$1" ;;
                esac
            }

            # request <env> <path or URL> <curl arguments...>
            request() {
                local env="$1" target="$2" status
                shift 2
                [ -e "$work/$env.failed" ] && return
                case "$target" in
                    /*) target="$(base "$env")$target" ;;
                    http://*|https://*) ;;
                    *) echo "not a path nor a URL: $target" > "$work/$env.failed"; return ;;
                esac
                printf '%s' "$target" > "$work/$env.url"
                status=$(curl -sS -o "$work/$env.body" -D "$work/$env.headers" -w '%{http_code}' --max-time 30 \\
                    -b "$work/$env.cookies" -c "$work/$env.cookies" "$@" "$target") \\
                    || { echo "$env did not answer" > "$work/$env.failed"; return; }
                printf '%s' "$status" > "$work/$env.status"
            }

            # attr <tag> <name>: the value of an attribute of an HTML tag
            attr() {
                printf '%s' "$1" | grep -oiE "[[:space:]]$2[[:space:]]*=[[:space:]]*(\\\"[^\\\"]*\\\"|'[^']*'|[^[:space:]>]+)" | head -1 \\
                    | sed -E "s/^[^=]*=[[:space:]]*//; s/^[\\\"']//; s/[\\\"']$//" \\
                    | sed -e 's/&quot;/"/g' -e "s/&#39;/'/g" -e 's/&lt;/</g' -e 's/&gt;/>/g' -e 's/&amp;/\\&/g'
            }

            # keep_form <env> <name>: keeps the first form of the last page, its action, method and fields
            keep_form() {
                local env="$1" name="$2" page tag input type field
                page=$(tr '\\r\\n' '  ' < "$work/$env.body")
                tag=$(printf '%s' "$page" | grep -oiE '<form[^>]*>' | head -1)
                [ -n "$tag" ] || return 1
                resolve "$(attr "$tag" action)" "$(cat "$work/$env.url")" > "$work/$env.cap-$name"
                attr "$tag" method | tr '[:lower:]' '[:upper:]' > "$work/$env.method-$name"
                : > "$work/$env.form-$name"
                printf '%s' "$page" | sed 's#</[Ff][Oo][Rr][Mm].*##' | grep -oiE '<input[^>]*>' | while IFS= read -r input; do
                    type=$(attr "$input" type | tr '[:upper:]' '[:lower:]')
                    field=$(attr "$input" name)
                    case "$type" in submit|button|image|reset|file) continue ;; esac
                    case "$type" in checkbox|radio) printf '%s' "$input" | grep -qi 'checked' || continue ;; esac
                    [ -n "$field" ] && printf '%s\\t%s\\n' "$field" "$(attr "$input" value)" >> "$work/$env.form-$name"
                done
            }

            # submit <env> <form> <field> <value>... <curl arguments...>: sends a captured form with its fields and these
            submit() {
                local env="$1" name="$2" field value given=() args=() method
                shift 2
                [ -e "$work/$env.failed" ] && return
                while [ $# -ge 2 ] && [ "${1#-}" = "$1" ]; do
                    given+=("$1")
                    args+=(--data-urlencode "$1=$2")
                    shift 2
                done
                while IFS="$(printf '\\t')" read -r field value; do
                    case " ${given[*]-} " in *" $field "*) continue ;; esac
                    args+=(--data-urlencode "$field=$value")
                done < "$work/$env.form-$name"
                method=$(cat "$work/$env.method-$name")
                if [ "$method" = POST ]; then
                    request "$env" "$(cap "$env" "$name")" -X POST "${args[@]}" "$@"
                else
                    request "$env" "$(cap "$env" "$name" | sed 's/[?#].*//')" -G "${args[@]}" "$@"
                fi
            }

            # location <env>: the Location of the last answer, from the page it was asked to
            location() {
                local l
                l=$(header "$work/$1.headers" location)
                [ -n "$l" ] && resolve "$l" "$(cat "$work/$1.url")"
            }

            # param <url> <name>: a parameter of the query string or the fragment, decoded
            param() {
                local v
                v=$(printf '%s' "$1" | sed 's/^[^?#]*//' | tr '?#&' '\\n\\n\\n' | grep -E "^$2=" | head -1 | sed 's/^[^=]*=//')
                v="${v//+/ }"
                printf '%b' "${v//%/\\x}"
            }

            # capture <env> <from> <name> <key>: keeps a value of the last answer for the next cases
            capture() {
                local env="$1" from="$2" name="$3" key="$4" value=""
                [ -e "$work/$env.failed" ] && return
                case "$from" in
                    location) value=$(location "$env") ;;
                    query) value=$(param "$(location "$env")" "$key") ;;
                    header) value=$(header "$work/$env.headers" "$key") ;;
                    json) value=$(tr -d '\\r\\n' < "$work/$env.body" | grep -oE "\\\"${key##*.}\\\"[[:space:]]*:[[:space:]]*(\\\"[^\\\"]*\\\"|[0-9.eE+-]+|true|false)" \\
                        | head -1 | sed -E 's/^"[^"]*"[[:space:]]*:[[:space:]]*//; s/^"//; s/"$//') ;;
                    form) keep_form "$env" "$name" && value=$(cap "$env" "$name") ;;
                esac
                printf '%s' "$value" > "$work/$env.cap-$name"
                [ -n "$value" ] || echo "           nothing to capture as $name on $env"
            }

            # names <query>: the names of its parameters, sorted
            names() { printf '%s' "$1" | tr '&' '\n' | sed 's/=.*//' | grep -v '^$' | LC_ALL=C sort | paste -sd '&' -; }

            # shape <url> <base>: the url without its parameter values, the host of the environment as {base}
            shape() {
                local url="$1" path rest query="" fragment="" out
                case "$url" in "$2"*) url="{base}${url#"$2"}" ;; esac
                path="${url%%[?#]*}"
                rest="${url#"$path"}"
                case "$rest" in \\?*) query="${rest#\\?}"; query="${query%%#*}" ;; esac
                case "$rest" in *#*) fragment="${rest#*#}" ;; esac
                out="$path"
                [ -n "$query" ] && out="$out?$(names "$query")"
                [ -n "$fragment" ] && out="$out#$(names "$fragment")"
                printf '%s' "$out"
            }

            # seen <env> <header> <shape only>: a compared header as the environment answered it
            seen() {
                local v
                if [ "$2" = location ]; then
                    v=$(location "$1")
                    [ -z "$v" ] && return
                    if [ "$3" = 1 ]; then shape "$v" "$(base "$1")"; else case "$v" in "$(base "$1")"*) printf '{base}%s' "${v#"$(base "$1")"}" ;; *) printf '%s' "$v" ;; esac; fi
                else
                    v=$(header "$work/$1.headers" "$2")
                    if [ "$3" = 1 ] && [ -n "$v" ]; then printf present; else printf '%s' "$v"; fi
                fi
            }

            # keys <env>: the names of the fields of a JSON object body, at any depth, sorted, without jq
            keys() {
                tr -d '\\r\\n' < "$work/$1.body" | grep -q '^[[:space:]]*{' || return 0
                tr -d '\\r\\n' < "$work/$1.body" | grep -oE '"([^"\\\\]|\\\\.)*"[[:space:]]*:' \\
                    | sed -E 's/"[[:space:]]*:$//; s/^"//' | LC_ALL=C sort -u | paste -sd ',' - | sed 's/,/, /g'
            }

            # compare <name> <expected status, 0 for any> <compared headers> <shape only, 0 or 1>
            compare() {
                local name="$1" expected="$2" compared="$3" shape="$4" edge hybrid problems=() h a b
                if [ -e "$work/edge.failed" ] || [ -e "$work/hybrid.failed" ]; then
                    echo "ERROR      $name: $(cat "$work/edge.failed" "$work/hybrid.failed" 2>/dev/null | paste -sd ';' -)"
                    errors=$((errors + 1))
                    return
                fi
                edge=$(cat "$work/edge.status")
                hybrid=$(cat "$work/hybrid.status")
                [ "$edge" = "$hybrid" ] || problems+=("status $edge on Edge, $hybrid on hybrid")
                for h in $compared; do
                    a=$(seen edge "$h" "$shape")
                    b=$(seen hybrid "$h" "$shape")
                    [ "$a" = "$b" ] || problems+=("$h: '${a:-absent}' on Edge, '${b:-absent}' on hybrid")
                done
                if [ "$shape" = 1 ]; then
                    a=$(keys edge)
                    b=$(keys hybrid)
                    [ "$a" = "$b" ] || problems+=("JSON keys [${a}] on Edge, [${b}] on hybrid")
                fi
                if [ ${#problems[@]} -eq 0 ]; then
                    echo "SAME       $name ($edge)"
                    same=$((same + 1))
                else
                    echo "DIFFERENT  $name"
                    printf '           %s\\n' "${problems[@]}"
                    different=$((different + 1))
                fi
                [ "$expected" != 0 ] && [ "$edge" != "$expected" ] && echo "           Edge answered $edge, the plan expects $expected"
                [ "$expected" != 0 ] && [ "$hybrid" != "$expected" ] && echo "           hybrid answered $hybrid, the plan expects $expected"
                return 0
            }

            """;

    /** A bash word that holds the text, with its {@code {{variables}}} expanded from the environment. */
    private static String shell(String text) {
        return shell(text, java.util.Set.of());
    }

    /** Same, the captured values read with {@code cap "$env"} for the environment of the loop. */
    private static String shell(String text, java.util.Set<String> captured) {
        StringBuilder out = new StringBuilder();
        Matcher matcher = VARIABLE.matcher(text);
        int at = 0;
        while (matcher.find()) {
            out.append(quoted(text.substring(at, matcher.start())));
            out.append(captured.contains(matcher.group(1)) ? "\"$(cap \"$env\" " + matcher.group(1) + ")\""
                    : "\"${" + matcher.group(1) + "}\"");
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
     * scenarios that change data are tagged {@code @unsafe}, to leave out with {@code --tags ~@unsafe}. The cases of a
     * chain make one scenario that runs them all on Edge, then all on hybrid with fresh cookies, and matches what
     * each step answered on both.
     */
    static String karate(String proxy, TestPlans.Plan plan) {
        java.util.Set<Integer> chain = chain(plan);
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
        if (!chain.isEmpty()) out.append(KARATE_CHAIN);

        for (int i = 0; i < plan.cases().size(); i++) {
            TestPlans.Case c = plan.cases().get(i);
            if (chain.contains(i)) {
                if (i == chain.iterator().next()) karateChain(out, plan, chain);
                continue;
            }
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

    /** The functions the chain scenario runs with. */
    private static final String KARATE_CHAIN = """
                * def resolve =
                  \"\"\"
                  function(url, page) { return java.net.URI.create(page).resolve(url).toString() }
                  \"\"\"
                * def at = function(base, path) { return path.indexOf('/') == 0 ? base + path : path }
                * def param =
                  \"\"\"
                  function(url, name) {
                    var parts = url.split(/[?#]/).slice(1).join('&').split('&');
                    for (var i = 0; i < parts.length; i++) {
                      var eq = parts[i].indexOf('=');
                      var key = decodeURIComponent((eq < 0 ? parts[i] : parts[i].substring(0, eq)).replace(/\\+/g, ' '));
                      if (key == name) return eq < 0 ? '' : decodeURIComponent(parts[i].substring(eq + 1).replace(/\\+/g, ' '));
                    }
                    return null;
                  }
                  \"\"\"
                * def shape =
                  \"\"\"
                  function(url, base) {
                    if (url.indexOf(base) == 0) url = '{base}' + url.substring(base.length);
                    var names = function(text) {
                      return text.split('&').filter(function(p) { return p.length > 0 })
                        .map(function(p) { return p.split('=')[0] }).sort().join('&');
                    };
                    var cut = url.search(/[?#]/);
                    var out = cut < 0 ? url : url.substring(0, cut);
                    var hash = url.indexOf('#');
                    var query = url.indexOf('?') >= 0 && (hash < 0 || url.indexOf('?') < hash)
                      ? url.substring(url.indexOf('?') + 1, hash < 0 ? url.length : hash) : '';
                    if (query) out += '?' + names(query);
                    if (hash >= 0) out += '#' + names(url.substring(hash + 1));
                    return out;
                  }
                  \"\"\"
                * def formOf =
                  \"\"\"
                  function(html, page) {
                    var text = typeof html == 'string' ? html : karate.toString(html);
                    var form = /<form\\b([^>]*)>([\\s\\S]*?)(<\\/form\\s*>|$)/i.exec(text);
                    if (!form) return null;
                    var attr = function(tag, name) {
                      var m = new RegExp('\\\\s' + name + '\\\\s*=\\\\s*("([^"]*)"|\\'([^\\']*)\\'|([^\\\\s>]+))', 'i').exec(' ' + tag);
                      if (!m) return null;
                      var v = m[2] != null ? m[2] : m[3] != null ? m[3] : m[4];
                      return v.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
                    };
                    var fields = {};
                    var inputs = form[2].match(/<input\\b[^>]*>/gi) || [];
                    for (var i = 0; i < inputs.length; i++) {
                      var type = (attr(inputs[i], 'type') || 'text').toLowerCase();
                      var name = attr(inputs[i], 'name');
                      if (!name || ['submit', 'button', 'image', 'reset', 'file'].indexOf(type) >= 0) continue;
                      if ((type == 'checkbox' || type == 'radio') && !/\\schecked/i.test(inputs[i])) continue;
                      if (!(name in fields)) fields[name] = attr(inputs[i], 'value') || '';
                    }
                    return {action: resolve(attr(form[1], 'action') || page, page),
                      method: (attr(form[1], 'method') || 'GET').toUpperCase(), fields: fields};
                  }
                  \"\"\"
                * def seenOf =
                  \"\"\"
                  function(base, page, status, body, headers, shapeOnly) {
                    var seen = {status: status, headers: {}};
                    for (var i = 0; i < headers.length; i++) {
                      var value = karate.response.header(headers[i]);
                      if (value != null && headers[i] == 'location') {
                        value = resolve(value, page);
                        value = shapeOnly ? shape(value, base) : value.indexOf(base) == 0 ? '{base}' + value.substring(base.length) : value;
                      } else if (value != null && shapeOnly) {
                        value = 'present';
                      }
                      seen.headers[headers[i]] = value;
                    }
                    if (shapeOnly) seen.keys = body != null && typeof body == 'object' && !Array.isArray(body) ? Object.keys(body).sort() : null;
                    return seen;
                  }
                  \"\"\"
                * def capture =
                  \"\"\"
                  function(store, forms, from, name, key, page, body) {
                    var l = karate.response.header('location');
                    var location = l == null ? null : resolve(l, page);
                    var value = null;
                    if (from == 'location') value = location;
                    else if (from == 'query') value = location == null ? null : param(location, key);
                    else if (from == 'header') value = karate.response.header(key);
                    else if (from == 'json') {
                      value = body;
                      var parts = key.split('.');
                      for (var i = 0; i < parts.length && value != null; i++) value = typeof value == 'object' ? value[parts[i]] : null;
                      if (value != null && typeof value == 'object') value = JSON.stringify(value);
                    } else if (from == 'form') {
                      var form = formOf(body, page);
                      forms[name] = form;
                      value = form == null ? null : form.action;
                    }
                    if (value == null || value === '') karate.log('Nothing to capture as', name);
                    store[name] = value == null ? null : '' + value;
                  }
                  \"\"\"
            """;

    /**
     * The scenario of the chain: its cases on Edge, each answer kept, then on hybrid with fresh cookies, each answer
     * matched with Edge's and with the expected status.
     */
    private static void karateChain(StringBuilder out, TestPlans.Plan plan, java.util.Set<Integer> chain) {
        java.util.Set<String> captured = plan.captured();
        out.append('\n');
        if (chain.stream().anyMatch(i -> !plan.cases().get(i).safe())) out.append("  @unsafe\n");
        out.append("  Scenario: Chained requests, on Edge then on hybrid\n");
        out.append("    * def seen = {}\n");
        for (String env : List.of("edge", "hybrid")) {
            String label = env.equals("edge") ? "Edge" : "hybrid";
            String store = env + "Captured";
            String forms = env + "Forms";
            String base = env + "Url";
            out.append("    * def ").append(store).append(" = {}\n");
            out.append("    * def ").append(forms).append(" = {}\n");
            if (env.equals("hybrid")) out.append("    * configure cookies = null\n");
            for (int i : chain) {
                TestPlans.Case c = plan.cases().get(i);
                out.append("\n    # ").append(comment(c.name())).append(" (on ").append(label).append(")\n");
                for (String name : TestRunner.uses(c)) {
                    if (!captured.contains(name)) continue;
                    String map = name.equals(c.form()) ? forms : store;
                    out.append("    * if (!").append(map).append("['").append(name).append("']) karate.fail('")
                            .append(name).append(" was not captured on ").append(label).append("')\n");
                }
                if (!c.form().isEmpty()) {
                    out.append("    * def form = ").append(forms).append("['").append(c.form()).append("']\n");
                    out.append("    * def target = form.action\n");
                    List<String> given = new ArrayList<>();
                    Responses.fields(c.body()).forEach((k, v) -> given.add(literal(k) + ": "
                            + karateText(v, captured, store)));
                    out.append("    * def fields = karate.merge(form.fields, {").append(String.join(", ", given))
                            .append("})\n");
                    out.append("    Given url target\n");
                    for (TestPlans.Header h : c.headers()) {
                        out.append("    And header ").append(h.name()).append(" = ")
                                .append(karateText(h.value(), captured, store)).append('\n');
                    }
                    out.append("    And form fields fields\n");
                    out.append("    When method post\n");
                } else {
                    out.append("    * def target = at(").append(base).append(", ")
                            .append(karateText(c.path(), captured, store)).append(")\n");
                    out.append("    Given url target\n");
                    for (TestPlans.Header h : c.headers()) {
                        out.append("    And header ").append(h.name()).append(" = ")
                                .append(karateText(h.value(), captured, store)).append('\n');
                    }
                    if (!c.body().isEmpty()) {
                        out.append("    And request ").append(karateText(c.body(), captured, store)).append('\n');
                    }
                    out.append("    When method ").append(c.method().toLowerCase()).append('\n');
                }
                out.append("    * def got = seenOf(").append(base).append(", target, responseStatus, response, [")
                        .append(String.join(", ", compared(c).stream().map(TestExports::literal).toList()))
                        .append("], ").append(c.shapeOnly()).append(")\n");
                if (env.equals("edge")) out.append("    * seen[").append(i).append("] = got\n");
                else out.append("    * match got == seen[").append(i).append("]\n");
                if (c.expectedStatus() != 0) out.append("    * match got.status == ").append(c.expectedStatus()).append('\n');
                for (TestPlans.Capture capture : c.captures()) {
                    out.append("    * capture(").append(store).append(", ").append(forms).append(", ")
                            .append(literal(capture.from())).append(", ").append(literal(capture.name())).append(", ")
                            .append(literal(capture.key())).append(", target, response)\n");
                }
            }
        }
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
        return karateText(text, java.util.Set.of(), "");
    }

    /** Same, the captured values read from {@code store}. */
    private static String karateText(String text, java.util.Set<String> captured, String store) {
        List<String> parts = new ArrayList<>();
        Matcher matcher = VARIABLE.matcher(text);
        int at = 0;
        while (matcher.find()) {
            if (matcher.start() > at) parts.add(literal(text.substring(at, matcher.start())));
            parts.add((captured.contains(matcher.group(1)) ? store : "vars") + "['" + matcher.group(1) + "']");
            at = matcher.end();
        }
        if (at < text.length() || parts.isEmpty()) parts.add(literal(text.substring(at)));
        return String.join(" + ", parts);
    }
}
