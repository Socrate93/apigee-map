package dev.apigeemap;

import dev.apigeemap.history.Diffs;
import dev.apigeemap.migration.Finding;
import dev.apigeemap.migration.FixContext;
import dev.apigeemap.migration.FixContext.SourceFile;
import dev.apigeemap.protocol.BackendClient;
import dev.apigeemap.protocol.BackendConfig;
import dev.apigeemap.protocol.Json;
import dev.apigeemap.render.FixContextRenderer;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

/** {@code apigee-map fix}: asks the backend to fix one finding of migrate, and shows its proposal as a diff. */
final class FixCommand {

    static final String USAGE = """
            Usage: apigee-map fix <bundle> --rule <id> [options]

              Sends the context of one finding of migrate (see context --help) to the backend, which proposes
              a fix, and shows the proposed changes as a diff. Nothing is changed in the bundle.
              The client token is asked on the console without echo, or read from the first line of the standard
              input; it is never read from a file.

            Options:
                  --rule <id>          rule of the finding, e.g. PERF-03
                  --at <text>          only the findings whose location contains this text (when the rule has several)
              -s, --sharedflows <dir>  folder containing shared flows, repeatable
              -o, --output <file>      also write the proposal as JSON
                  --config <file>      backend settings (default ~/.apigee-map/backend.properties, else those of the jar)
              -h, --help               show this help
            """;

    private FixCommand() {
    }

    static int run(String[] args, PrintStream out, PrintStream err) {
        return run(args, FixCommand::readToken, out, err);
    }

    /** @param token asked once the finding is found, just before the backend is called */
    static int run(String[] args, Supplier<String> token, PrintStream out, PrintStream err) {
        String input = null;
        String rule = null;
        String at = null;
        Path output = null;
        Path config = BackendConfig.defaultFile();
        List<Path> sharedFlowDirs = new ArrayList<>();
        try {
            for (int i = 0; i < args.length; i++) {
                switch (args[i]) {
                    case "-h", "--help" -> {
                        out.print(USAGE);
                        return 0;
                    }
                    case "--rule" -> rule = Main.value(args, ++i);
                    case "--at" -> at = Main.value(args, ++i);
                    case "-s", "--sharedflows" -> sharedFlowDirs.add(Path.of(Main.value(args, ++i)));
                    case "-o", "--output" -> output = Path.of(Main.value(args, ++i));
                    case "--config" -> config = Path.of(Main.value(args, ++i));
                    default -> {
                        if (args[i].startsWith("-") || input != null) {
                            throw new IllegalArgumentException("Unexpected argument: " + args[i]);
                        }
                        input = args[i];
                    }
                }
            }
            if (input == null) throw new IllegalArgumentException("Missing <bundle>");
            if (rule == null) throw new IllegalArgumentException("Missing --rule");
        } catch (IllegalArgumentException e) {
            err.println("error: " + e.getMessage());
            err.print(USAGE);
            return 2;
        }

        try {
            FixContext context = ContextCommand.select(input, sharedFlowDirs, rule, at, err);
            if (context == null) return 1;
            Finding finding = context.finding();
            err.println("Asking for a fix of " + finding.rule() + " at " + finding.location() + "...");
            Object reply;
            try {
                reply = new BackendClient(BackendConfig.load(config, token.get())).call("fix", new FixContextRenderer().model(context));
            } catch (IOException | RuntimeException e) {
                BackendClient.report(e, err);
                reply = null;
            }
            if (!(reply instanceof Map<?, ?> proposal)) {
                err.println("error: " + BackendClient.UNAVAILABLE);
                return 1;
            }
            out.print(render(context, proposal));
            if (output != null) {
                Map<String, Object> written = new LinkedHashMap<>();
                for (String key : List.of("summary", "warnings", "edits")) written.put(key, proposal.get(key));
                Files.writeString(output, Json.write(written) + "\n");
                err.println("Written " + output.toAbsolutePath());
            }
            return 0;
        } catch (IOException e) {
            err.println("error: " + e.getMessage());
            return 1;
        }
    }

    /** The token typed on the console, or the first line of the standard input when there is no console. */
    private static String readToken() {
        Console console = System.console();
        if (console != null) {
            char[] typed = console.readPassword("Token: ");
            return typed == null ? null : new String(typed);
        }
        try {
            return new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8)).readLine();
        } catch (IOException e) {
            return null;
        }
    }

    /** The proposal: summary, warnings, then each edit with its diff against the files of the context. */
    static String render(FixContext context, Map<?, ?> proposal) {
        Finding finding = context.finding();
        StringBuilder out = new StringBuilder();
        out.append(finding.rule()).append(context.ruleTitle() == null ? "" : " " + context.ruleTitle())
                .append(" at ").append(finding.location()).append("\n\n");
        out.append(proposal.get("summary")).append('\n');
        if (proposal.get("warnings") instanceof List<?> warnings && !warnings.isEmpty()) {
            out.append("\nWarnings:\n");
            warnings.forEach(w -> out.append("  - ").append(w).append('\n'));
        }
        List<?> edits = proposal.get("edits") instanceof List<?> list ? list : List.of();
        if (edits.isEmpty()) out.append("\nNo change proposed.\n");
        for (Object item : edits) {
            if (!(item instanceof Map<?, ?> edit)) continue;
            String bundle = String.valueOf(edit.get("bundle"));
            String path = String.valueOf(edit.get("path"));
            String before = context.files().stream()
                    .filter(f -> f.bundle().equals(bundle) && f.path().equals(path))
                    .map(SourceFile::content).findFirst().orElse(null);
            String after = edit.get("content") instanceof String content ? content : null;
            out.append('\n').append(edit.get("action")).append(' ').append(bundle).append('/').append(path)
                    .append(": ").append(edit.get("reason")).append('\n')
                    .append(Diffs.unified(path, before, after));
        }
        return out.toString();
    }
}
