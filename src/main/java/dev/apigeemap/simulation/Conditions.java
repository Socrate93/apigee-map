package dev.apigeemap.simulation;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Pattern;

/** Evaluates the conditions of steps, flows and routes, with Apigee's operators. */
final class Conditions {

    /** Words and symbols of the operators, in lower case, and what they do. */
    private static final Map<String, String> OPERATORS = Map.ofEntries(
            Map.entry("=", "eq"), Map.entry("==", "eq"), Map.entry("equals", "eq"), Map.entry("is", "eq"),
            Map.entry("!=", "ne"), Map.entry("notequals", "ne"), Map.entry("isnot", "ne"),
            Map.entry(":=", "eqi"), Map.entry("equalscaseinsensitive", "eqi"),
            Map.entry(">", "gt"), Map.entry("greaterthan", "gt"), Map.entry("<", "lt"), Map.entry("lesserthan", "lt"),
            Map.entry(">=", "ge"), Map.entry("greaterthanorequals", "ge"),
            Map.entry("<=", "le"), Map.entry("lesserthanorequals", "le"),
            Map.entry("~", "glob"), Map.entry("matches", "glob"), Map.entry("like", "glob"),
            Map.entry("~/", "path"), Map.entry("matchespath", "path"), Map.entry("likepath", "path"),
            Map.entry("~~", "regex"), Map.entry("javaregex", "regex"), Map.entry("startswith", "starts"));

    private record Token(String text, boolean quoted) {
    }

    private final List<Token> tokens;
    private final Function<String, String> variables;
    private int next;

    private Conditions(List<Token> tokens, Function<String, String> variables) {
        this.tokens = tokens;
        this.variables = variables;
    }

    /**
     * @param variables the value of a flow variable, or null
     * @throws IllegalArgumentException when the condition cannot be read
     */
    static boolean test(String condition, Function<String, String> variables) {
        Conditions parser = new Conditions(tokens(condition), variables);
        boolean result = parser.or();
        if (parser.next != parser.tokens.size()) throw new IllegalArgumentException("Cannot read: " + condition);
        return result;
    }

    private static List<Token> tokens(String text) {
        List<Token> tokens = new ArrayList<>();
        int i = 0;
        while (i < text.length()) {
            char c = text.charAt(i);
            if (Character.isWhitespace(c)) {
                i++;
            } else if (c == '"' || c == '\'') {
                int end = text.indexOf(c, i + 1);
                if (end < 0) throw new IllegalArgumentException("Unfinished text in: " + text);
                tokens.add(new Token(text.substring(i + 1, end), true));
                i = end + 1;
            } else if (c == '(' || c == ')') {
                tokens.add(new Token(String.valueOf(c), false));
                i++;
            } else if ("=!<>~:&|".indexOf(c) >= 0) {
                int start = i;
                while (i < text.length() && "=!<>~:&|/".indexOf(text.charAt(i)) >= 0) i++;
                tokens.add(new Token(text.substring(start, i), false));
            } else {
                int start = i;
                while (i < text.length() && !Character.isWhitespace(text.charAt(i))
                        && "()=!<>~:&|\"'".indexOf(text.charAt(i)) < 0) i++;
                tokens.add(new Token(text.substring(start, i), false));
            }
        }
        return tokens;
    }

    private Token peek() {
        return next < tokens.size() ? tokens.get(next) : null;
    }

    private boolean accept(String... words) {
        Token token = peek();
        if (token == null || token.quoted()) return false;
        for (String word : words) {
            if (token.text().equalsIgnoreCase(word)) {
                next++;
                return true;
            }
        }
        return false;
    }

    private boolean or() {
        boolean value = and();
        while (accept("or", "||")) value |= and();
        return value;
    }

    private boolean and() {
        boolean value = unary();
        while (accept("and", "&&")) value &= unary();
        return value;
    }

    private boolean unary() {
        if (accept("not", "!")) return !unary();
        if (accept("(")) {
            boolean value = or();
            if (!accept(")")) throw new IllegalArgumentException("Missing )");
            return value;
        }
        return comparison();
    }

    private boolean comparison() {
        String left = operand();
        Token token = peek();
        String operator = token == null || token.quoted() ? null : OPERATORS.get(token.text().toLowerCase(Locale.ROOT));
        if (operator == null) return left != null && !left.equalsIgnoreCase("false");
        next++;
        return compare(left, operator, operand());
    }

    private String operand() {
        Token token = peek();
        if (token == null) throw new IllegalArgumentException("Missing value");
        next++;
        if (token.quoted()) return token.text();
        String text = token.text();
        if (text.equalsIgnoreCase("null")) return null;
        if (text.equalsIgnoreCase("true") || text.equalsIgnoreCase("false")) return text.toLowerCase(Locale.ROOT);
        if (number(text) != null) return text;
        return variables.apply(text);
    }

    private static boolean compare(String left, String operator, String right) {
        if (operator.equals("ne")) return !compare(left, "eq", right);
        if (left == null || right == null) return operator.equals("eq") && left == null && right == null;
        Double a = number(left);
        Double b = number(right);
        return switch (operator) {
            case "eq" -> a != null && b != null ? a.equals(b) : left.equals(right);
            case "eqi" -> left.equalsIgnoreCase(right);
            case "gt" -> order(left, right, a, b) > 0;
            case "lt" -> order(left, right, a, b) < 0;
            case "ge" -> order(left, right, a, b) >= 0;
            case "le" -> order(left, right, a, b) <= 0;
            case "glob" -> Pattern.matches(glob(right), left);
            case "path" -> Pattern.matches(path(right), left);
            case "regex" -> Pattern.matches(right, left);
            case "starts" -> left.startsWith(right);
            default -> throw new IllegalArgumentException("Unknown operator " + operator);
        };
    }

    private static int order(String left, String right, Double a, Double b) {
        return a != null && b != null ? a.compareTo(b) : left.compareTo(right);
    }

    private static Double number(String text) {
        try {
            return Double.valueOf(text.strip());
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /** {@code *} stands for any text. */
    private static String glob(String pattern) {
        StringBuilder regex = new StringBuilder();
        for (String part : pattern.split("\\*", -1)) regex.append(Pattern.quote(part)).append(".*");
        return regex.substring(0, regex.length() - 2);
    }

    /** {@code /*} stands for one segment of a path, {@code /**} for any number of them. */
    private static String path(String pattern) {
        StringBuilder regex = new StringBuilder();
        for (int i = 0; i < pattern.length(); ) {
            if (pattern.startsWith("**", i)) {
                regex.append(".*");
                i += 2;
            } else if (pattern.charAt(i) == '*') {
                regex.append("[^/]*");
                i++;
            } else {
                regex.append(Pattern.quote(String.valueOf(pattern.charAt(i))));
                i++;
            }
        }
        return regex.toString();
    }
}
