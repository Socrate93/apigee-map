package dev.apigeemap.migration;

import dev.apigeemap.analysis.ScriptAnalyzer;
import dev.apigeemap.analysis.Xml;
import dev.apigeemap.model.BundleReport;
import dev.apigeemap.model.Policy;
import org.w3c.dom.Element;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Scripts run by the active Javascript and Python Script policies of a bundle, when they are in the bundle. */
final class Scripts {

    /** {@code flow.getVariable("name")} and friends in Python scripts. */
    private static final Pattern PYTHON_VARIABLE = Pattern.compile(
            "flow\\.(get|set|remove)Variable\\(\\s*(['\"])([^'\"]+)\\2");

    /**
     * @param file bundle-relative path, or "inline" for a Javascript Source element
     */
    record Script(String bundle, String policy, String file, String source, boolean python) {

        String label() {
            return bundle + "/" + (file.equals("inline") ? policy + " (inline)" : file);
        }

        ScriptAnalyzer.Facts facts() {
            if (!python) return ScriptAnalyzer.analyze(source, file);
            Set<String> reads = new LinkedHashSet<>();
            Set<String> writes = new LinkedHashSet<>();
            Matcher matcher = PYTHON_VARIABLE.matcher(source);
            while (matcher.find()) (matcher.group(1).equals("get") ? reads : writes).add(matcher.group(3));
            return new ScriptAnalyzer.Facts(List.copyOf(reads), List.copyOf(writes), false, false, List.of(),
                    List.of(), false, false, null);
        }
    }

    private Scripts() {
    }

    static List<Script> of(BundleReport bundle) throws IOException {
        Path dir = Path.of(bundle.path());
        List<Script> scripts = new ArrayList<>();
        for (Policy policy : bundle.policies()) {
            if (!policy.active()) continue;
            if (policy.type().equals("Javascript")) {
                Element xml = Xml.parse(dir.resolve(policy.file()));
                ScriptAnalyzer.scripts(dir, xml).forEach((file, source) ->
                        scripts.add(new Script(bundle.name(), policy.name(), file, source, false)));
            } else if (policy.type().equals("Script")) {
                Element xml = Xml.parse(dir.resolve(policy.file()));
                List<Element> urls = new ArrayList<>(Xml.children(xml, "IncludeURL"));
                urls.addAll(Xml.children(xml, "ResourceURL"));
                for (Element url : urls) {
                    String value = Xml.text(url);
                    if (value == null || !value.startsWith("py://")) continue;
                    String file = "resources/py/" + value.substring("py://".length());
                    if (Files.isRegularFile(dir.resolve(file))) {
                        scripts.add(new Script(bundle.name(), policy.name(), file, Files.readString(dir.resolve(file)),
                                true));
                    }
                }
            }
        }
        return scripts;
    }

    /**
     * Code tokens without comments and whitespace; string literals are one token each. Good enough to compare
     * scripts, not to run them (JavaScript regex literals are not recognized).
     */
    static List<String> tokens(String code, boolean python) {
        List<String> tokens = new ArrayList<>();
        int i = 0;
        int n = code.length();
        while (i < n) {
            char c = code.charAt(i);
            if (Character.isWhitespace(c)) {
                i++;
            } else if (python ? c == '#' : code.startsWith("//", i)) {
                while (i < n && code.charAt(i) != '\n') i++;
            } else if (!python && code.startsWith("/*", i)) {
                int end = code.indexOf("*/", i + 2);
                i = end < 0 ? n : end + 2;
            } else if (c == '"' || c == '\'' || c == '`') {
                String quote = python && code.startsWith(String.valueOf(c).repeat(3), i) ? String.valueOf(c).repeat(3)
                        : String.valueOf(c);
                int j = i + quote.length();
                while (j < n && !code.startsWith(quote, j)) j += code.charAt(j) == '\\' ? 2 : 1;
                j = Math.min(n, j + quote.length());
                tokens.add(code.substring(i, j));
                i = j;
            } else if (Character.isLetterOrDigit(c) || c == '_' || c == '$') {
                int j = i;
                while (j < n && (Character.isLetterOrDigit(code.charAt(j)) || code.charAt(j) == '_'
                        || code.charAt(j) == '$')) j++;
                tokens.add(code.substring(i, j));
                i = j;
            } else {
                tokens.add(String.valueOf(c));
                i++;
            }
        }
        return tokens;
    }

    /** Jaccard similarity of the token trigrams of two scripts, from 0 to 1. */
    static double similarity(List<String> a, List<String> b) {
        Set<List<String>> left = trigrams(a);
        Set<List<String>> right = trigrams(b);
        if (left.isEmpty() || right.isEmpty()) return 0;
        Set<List<String>> common = new HashSet<>(left);
        common.retainAll(right);
        return (double) common.size() / (left.size() + right.size() - common.size());
    }

    private static Set<List<String>> trigrams(List<String> tokens) {
        Set<List<String>> trigrams = new HashSet<>();
        for (int i = 0; i + 3 <= tokens.size(); i++) trigrams.add(tokens.subList(i, i + 3));
        return trigrams;
    }
}
