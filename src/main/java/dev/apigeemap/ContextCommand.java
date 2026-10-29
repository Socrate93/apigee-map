package dev.apigeemap;

import dev.apigeemap.analysis.BundleAnalyzer;
import dev.apigeemap.analysis.BundleLocator;
import dev.apigeemap.analysis.SharedFlowRepository;
import dev.apigeemap.migration.Finding;
import dev.apigeemap.migration.FixContext;
import dev.apigeemap.migration.MigrationOptions;
import dev.apigeemap.migration.MigrationReport;
import dev.apigeemap.migration.Migrator;
import dev.apigeemap.model.BundleReport;
import dev.apigeemap.render.FixContextRenderer;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** {@code apigee-map context}: what it takes to fix one finding of {@code migrate}, files included. */
final class ContextCommand {

    static final String USAGE = """
            Usage: apigee-map context <bundle> --rule <id> [options]

              Gathers what it takes to fix one finding of migrate: the finding, the policies it names with where
              they run and how their variables flow, and the source files involved (the policies, their scripts,
              the endpoints they run in, the policies that set or read their variables).

            Options:
                  --rule <id>          rule of the finding, e.g. PERF-03
                  --at <text>          only the findings whose location contains this text (when the rule has several)
              -s, --sharedflows <dir>  folder containing shared flows, repeatable
              -f, --format <format>    markdown (default), json
              -o, --output <file>      write to a file; json when the name ends with .json
              -h, --help               show this help
            """;

    private ContextCommand() {
    }

    static int run(String[] args, PrintStream out, PrintStream err) {
        String input = null;
        String rule = null;
        String at = null;
        String format = null;
        Path output = null;
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
                    case "-f", "--format" -> format = Main.value(args, ++i);
                    case "-o", "--output" -> output = Path.of(Main.value(args, ++i));
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
            if (format == null) {
                format = output != null && output.getFileName().toString().toLowerCase().endsWith(".json")
                        ? "json" : "markdown";
            }
            if (!format.equals("markdown") && !format.equals("json")) {
                throw new IllegalArgumentException("Unknown format " + format + " (markdown, json)");
            }
        } catch (IllegalArgumentException e) {
            err.println("error: " + e.getMessage());
            err.print(USAGE);
            return 2;
        }

        try {
            FixContext context = select(input, sharedFlowDirs, rule, at, err);
            if (context == null) return 1;
            FixContextRenderer renderer = new FixContextRenderer();
            String rendered = format.equals("json") ? renderer.json(context) : renderer.markdown(context);
            if (output != null) {
                Files.writeString(output, rendered);
                err.println("Written " + output.toAbsolutePath());
            } else {
                out.print(rendered);
            }
            return 0;
        } catch (IOException e) {
            err.println("error: " + e.getMessage());
            return 1;
        }
    }

    /**
     * Migrates the bundle (dry run) and gathers the context of its one finding of {@code rule} at {@code at}; null
     * when there is none or several, after saying so on {@code err}.
     */
    static FixContext select(String input, List<Path> sharedFlowDirs, String rule, String at, PrintStream err)
            throws IOException {
        Path bundle = BundleLocator.locate(Path.of(input));
        SharedFlowRepository repository = sharedFlowDirs.isEmpty()
                ? SharedFlowRepository.empty()
                : SharedFlowRepository.scan(sharedFlowDirs);
        BundleReport analysis = new BundleAnalyzer(repository).analyze(bundle);
        MigrationReport report = new Migrator(MigrationOptions.DEFAULT, repository).migrate(analysis, null);
        List<Finding> matches = report.findings().stream()
                .filter(f -> f.rule().equalsIgnoreCase(rule))
                .filter(f -> at == null || f.location().contains(at))
                .toList();
        // --at JS-Audit picks the finding at JS-Audit, not the one at JS-Audit-Copy too
        List<Finding> exact = matches.stream().filter(f -> f.location().equals(at)).toList();
        if (!exact.isEmpty()) matches = exact;
        if (matches.size() != 1) {
            err.println(matches.isEmpty()
                    ? "error: no " + rule + " finding" + (at == null ? "" : " at " + at) + " in " + analysis.name()
                    : "error: " + matches.size() + " " + rule + " findings, pick one with --at:");
            matches.forEach(f -> err.println("  " + f.bundle() + ": " + f.location()));
            return null;
        }
        return FixContext.of(matches.get(0), FixContext.bundles(analysis));
    }
}
