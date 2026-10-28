package dev.apigeemap.analysis;

import org.mozilla.javascript.CompilerEnvirons;
import org.mozilla.javascript.Context;
import org.mozilla.javascript.EvaluatorException;
import org.mozilla.javascript.Parser;
import org.mozilla.javascript.Token;
import org.mozilla.javascript.ast.Assignment;
import org.mozilla.javascript.ast.AstNode;
import org.mozilla.javascript.ast.AstRoot;
import org.mozilla.javascript.ast.FunctionCall;
import org.mozilla.javascript.ast.InfixExpression;
import org.mozilla.javascript.ast.Name;
import org.mozilla.javascript.ast.NewExpression;
import org.mozilla.javascript.ast.PropertyGet;
import org.mozilla.javascript.ast.StringLiteral;
import org.mozilla.javascript.ast.VariableInitializer;

import org.w3c.dom.Element;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * What a JavaScript policy script does with flow variables and outbound HTTP calls, read from the syntax tree of
 * Rhino, the engine Apigee runs JavaScript policies on. Unlike a text search, it ignores comments and strings and
 * follows aliases of {@code context} ({@code var ctx = context;}).
 */
public final class ScriptAnalyzer {

    /** Placeholder for the computed part of a URL, e.g. {@code https://host/{…}}. */
    public static final String DYNAMIC = "{…}";

    /**
     * @param reads        flow variables read with context.getVariable, by literal name
     * @param writes       flow variables set or removed with context.setVariable/removeVariable, by literal name
     * @param dynamicReads true when a variable name is computed at runtime
     * @param dynamicWrites true when a variable name is computed at runtime
     * @param urls         literal URLs (or literal URL prefixes) called through httpClient or new Request(...)
     * @param httpClient   true when the script calls httpClient
     * @param waits        true when the script calls waitForComplete()
     * @param error        syntax error ("line N: message"), or null when the script parsed
     */
    public record Facts(List<String> reads, List<String> writes, boolean dynamicReads, boolean dynamicWrites,
                        List<String> urls, boolean httpClient, boolean waits, String error) {

        static Facts failed(String error) {
            return new Facts(List.of(), List.of(), false, false, List.of(), false, false, error);
        }
    }

    private ScriptAnalyzer() {
    }

    /**
     * Scripts of a Javascript policy that are in the bundle (IncludeURLs first, then ResourceURL, then an inline
     * Source), by bundle-relative path ("inline" for Source). Scripts outside the bundle are left out.
     */
    public static Map<String, String> scripts(Path bundleDir, Element policy) throws IOException {
        Map<String, String> scripts = new LinkedHashMap<>();
        List<Element> urls = new ArrayList<>(Xml.children(policy, "IncludeURL"));
        urls.addAll(Xml.children(policy, "ResourceURL"));
        for (Element url : urls) {
            String value = Xml.text(url);
            if (value == null || !value.startsWith("jsc://")) continue;
            String file = "resources/jsc/" + value.substring("jsc://".length());
            Path path = bundleDir.resolve(file);
            if (Files.isRegularFile(path)) scripts.put(file, Files.readString(path));
        }
        String inline = Xml.text(policy, "Source");
        if (inline != null) scripts.put("inline", inline);
        return scripts;
    }

    public static Facts analyze(String source, String name) {
        AstRoot root;
        try {
            root = parse(source, name);
        } catch (EvaluatorException first) {
            // Some scripts use a top-level return, which Apigee accepts: retry inside a function, same line numbers
            try {
                root = parse("(function(){" + source + "\n})();", name);
            } catch (EvaluatorException e) {
                return Facts.failed("line " + first.getLineNumber() + ": " + first.details());
            }
        }
        Set<String> contexts = new LinkedHashSet<>(List.of("context"));
        root.visit(node -> {
            AstNode target = null;
            AstNode value = null;
            if (node instanceof VariableInitializer init) {
                target = init.getTarget();
                value = init.getInitializer();
            } else if (node instanceof Assignment assignment && assignment.getType() == Token.ASSIGN) {
                target = assignment.getLeft();
                value = assignment.getRight();
            }
            if (target instanceof Name alias && value instanceof Name original
                    && contexts.contains(original.getIdentifier())) {
                contexts.add(alias.getIdentifier());
            }
            return true;
        });

        Collector collector = new Collector(contexts);
        root.visit(collector);
        return new Facts(List.copyOf(collector.reads), List.copyOf(collector.writes), collector.dynamicReads,
                collector.dynamicWrites, List.copyOf(collector.urls), collector.httpClient, collector.waits, null);
    }

    /** Syntax errors come in English whatever the machine's locale: Rhino reads it from the current Context. */
    private static AstRoot parse(String source, String name) {
        try (Context cx = Context.enter()) {
            cx.setLocale(Locale.ENGLISH);
            CompilerEnvirons env = new CompilerEnvirons();
            env.setLanguageVersion(Context.VERSION_ES6);
            env.setRecordingComments(false);
            env.setStrictMode(false);
            return new Parser(env).parse(source, name, 1);
        }
    }

    private static final class Collector implements org.mozilla.javascript.ast.NodeVisitor {

        private final Set<String> contexts;
        private final Set<String> reads = new LinkedHashSet<>();
        private final Set<String> writes = new LinkedHashSet<>();
        private final Set<String> urls = new LinkedHashSet<>();
        private boolean dynamicReads;
        private boolean dynamicWrites;
        private boolean httpClient;
        private boolean waits;

        Collector(Set<String> contexts) {
            this.contexts = contexts;
        }

        @Override
        public boolean visit(AstNode node) {
            if (node instanceof NewExpression request && request.getTarget() instanceof Name type
                    && type.getIdentifier().equals("Request")) {
                url(first(request));
            } else if (node instanceof FunctionCall call && call.getTarget() instanceof PropertyGet get) {
                String method = get.getProperty().getIdentifier();
                String object = get.getTarget() instanceof Name n ? n.getIdentifier() : null;
                if (method.equals("waitForComplete")) waits = true;
                if (contexts.contains(object)) {
                    switch (method) {
                        case "getVariable" -> dynamicReads |= !add(reads, first(call));
                        case "setVariable", "removeVariable" -> dynamicWrites |= !add(writes, first(call));
                        default -> {
                        }
                    }
                } else if ("httpClient".equals(object)) {
                    httpClient = true;
                    if (!method.equals("send")) url(first(call));
                }
            }
            return true;
        }

        private static AstNode first(FunctionCall call) {
            return call.getArguments().isEmpty() ? null : call.getArguments().get(0);
        }

        /** Adds a literal name; false when the name is computed. */
        private static boolean add(Set<String> names, AstNode argument) {
            if (!(argument instanceof StringLiteral literal)) return false;
            names.add(literal.getValue());
            return true;
        }

        /** {@code "https://host/x"} as is, {@code "https://host/" + id} as {@code https://host/{…}}. */
        private void url(AstNode argument) {
            if (argument instanceof StringLiteral literal) {
                urls.add(literal.getValue());
                return;
            }
            AstNode left = argument;
            while (left instanceof InfixExpression infix && infix.getType() == Token.ADD) left = infix.getLeft();
            if (left != argument && left instanceof StringLiteral prefix && prefix.getValue().matches("(?i)https?://.*")) {
                urls.add(prefix.getValue() + DYNAMIC);
            }
        }
    }
}
