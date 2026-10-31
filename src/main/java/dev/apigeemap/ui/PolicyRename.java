package dev.apigeemap.ui;

import dev.apigeemap.analysis.VariableFlow;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.regex.MatchResult;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Renames a policy in the text of a bundle: the policy itself, the steps that run it, its line in the manifest and the
 * variables it sets under its name. Any other mention stays as it is and is listed, for the developer to look at.
 */
final class PolicyRename {

    private static final Pattern VALID_NAME = Pattern.compile("[A-Za-z0-9_-]+");

    /** One line that changes. */
    record Line(int line, String before, String after) {
    }

    /** A file that changes; {@code newPath} is null unless it moves. */
    record FileChange(String path, String newPath, List<Line> lines) {
    }

    /**
     * @param file      the policy file once renamed
     * @param unchanged {@code file:line} of the other mentions of the name
     */
    record Plan(String from, String to, String file, List<FileChange> files, List<String> unchanged) {
    }

    private final String from;
    private final String to;
    private final String policyFile;
    private final Map<String, String> changed = new LinkedHashMap<>();

    PolicyRename(String from, String to, String policyFile) {
        this.from = from;
        this.to = to;
        this.policyFile = policyFile;
    }

    /** @param texts the text files of the bundle, by bundle-relative path */
    Plan plan(Map<String, String> texts) {
        if (!VALID_NAME.matcher(to).matches()) {
            throw new UiService.UiException(400, "A policy name uses letters, digits, - and _ only");
        }
        if (to.equals(from)) throw new UiService.UiException(400, "This is already its name");
        String newPath = policyFile.substring(0, policyFile.lastIndexOf('/') + 1) + to + ".xml";
        if (!newPath.equals(policyFile) && texts.containsKey(newPath)) {
            throw new UiService.UiException(409, newPath + " already exists");
        }

        Pattern variable = Pattern.compile("(?<![\\w.-])((?i:" + String.join("|", scopes()) + ")\\.)"
                + Pattern.quote(from) + "(?![\\w-])");
        Pattern mention = Pattern.compile("(?<![\\w-])" + Pattern.quote(from) + "(?![\\w-])");
        List<FileChange> files = new ArrayList<>();
        List<String> unchanged = new ArrayList<>();
        for (Map.Entry<String, String> file : texts.entrySet()) {
            String path = file.getKey();
            String text = file.getValue();
            String renamed = replace(variable, specific(path, text));
            List<Line> lines = lines(text, renamed);
            boolean moves = path.equals(policyFile) && !newPath.equals(policyFile);
            if (!lines.isEmpty() || moves) {
                files.add(new FileChange(path, moves ? newPath : null, lines));
                changed.put(path, renamed);
            }
            unchanged.addAll(mentions(mention, path, renamed));
        }
        return new Plan(from, to, newPath, files, unchanged);
    }

    /** The new text of each file that changes, under its current path. */
    Map<String, String> changed() {
        return changed;
    }

    private static TreeSet<String> scopes() {
        TreeSet<String> scopes = new TreeSet<>(VariableFlow.policyScopes());
        scopes.add("javascript");
        return scopes;
    }

    /** What names the policy in the role the file has in the bundle. */
    private String specific(String path, String text) {
        String name = Pattern.quote(from);
        if (path.equals(policyFile)) {
            String root = replaceFirst("(<[A-Za-z][^>]*?\\sname\\s*=\\s*[\"'])" + name + "([\"'])", text);
            return replace(Pattern.compile("(<DisplayName>\\s*)" + name + "(\\s*</DisplayName>)"), root);
        }
        if (path.startsWith("proxies/") || path.startsWith("targets/")) {
            return replace(Pattern.compile("(<Name>\\s*)" + name + "(\\s*</Name>)"), text);
        }
        if (!path.contains("/") && path.endsWith(".xml")) {
            return replace(Pattern.compile("(<Policy>\\s*)" + name + "(\\s*</Policy>)"), text);
        }
        return text;
    }

    private String replaceFirst(String regex, String text) {
        Matcher matcher = Pattern.compile(regex).matcher(text);
        return matcher.find() ? matcher.replaceFirst(replacement(matcher)) : text;
    }

    private String replace(Pattern pattern, String text) {
        return pattern.matcher(text).replaceAll(this::replacement);
    }

    /** Keeps what the pattern matches around the name. */
    private String replacement(MatchResult match) {
        String before = match.group(1);
        String after = match.groupCount() > 1 ? match.group(2) : "";
        return Matcher.quoteReplacement(before + to + after);
    }

    private static List<Line> lines(String text, String renamed) {
        String[] before = text.split("\n", -1);
        String[] after = renamed.split("\n", -1);
        List<Line> lines = new ArrayList<>();
        for (int i = 0; i < before.length; i++) {
            if (!before[i].equals(after[i])) lines.add(new Line(i + 1, before[i].strip(), after[i].strip()));
        }
        return lines;
    }

    private static List<String> mentions(Pattern mention, String path, String text) {
        List<String> places = new ArrayList<>();
        String[] lines = text.split("\n", -1);
        for (int i = 0; i < lines.length; i++) {
            if (mention.matcher(lines[i]).find()) places.add(path + ":" + (i + 1));
        }
        return places;
    }
}
