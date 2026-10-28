package dev.apigeemap;

import dev.apigeemap.analysis.BundleAnalyzer;
import dev.apigeemap.analysis.BundleLocator;
import dev.apigeemap.analysis.SharedFlowRepository;
import dev.apigeemap.migration.MigrationReport;
import dev.apigeemap.migration.MigrationOptions;
import dev.apigeemap.migration.Migrator;
import dev.apigeemap.model.BundleReport;
import dev.apigeemap.render.MigrationHtmlRenderer;
import dev.apigeemap.render.MigrationTextRenderer;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** {@code apigee-map migrate}: Edge for Private Cloud → Apigee hybrid report and rewritten bundles. */
final class MigrateCommand {

    static final String USAGE = """
            Usage: apigee-map migrate <bundle> [options]

              Checks the bundle and the shared flows it calls for Apigee hybrid incompatibilities and
              anti-patterns, and lists what to create in hybrid. With --out, also writes the rewritten bundles
              (the source bundles are never modified).

            Options:
              -s, --sharedflows <dir>  folder containing shared flows, repeatable; called shared flows are migrated too
                  --out <dir>          write the migrated bundles (and targetservers.json) to this empty folder
              -f, --format <format>    report format: text (default), html
              -o, --output <file>      write the report to a file; html when the name ends with .html
                  --strict             exit with code 3 when an error still needs manual work
              -h, --help               show this help
            """;

    private MigrateCommand() {
    }

    static int run(String[] args, PrintStream out, PrintStream err) {
        String input = null;
        String format = null;
        Path output = null;
        Path outDir = null;
        boolean strict = false;
        List<Path> sharedFlowDirs = new ArrayList<>();
        try {
            for (int i = 0; i < args.length; i++) {
                switch (args[i]) {
                    case "-h", "--help" -> {
                        out.print(USAGE);
                        return 0;
                    }
                    case "-s", "--sharedflows" -> sharedFlowDirs.add(Path.of(Main.value(args, ++i)));
                    case "--out" -> outDir = Path.of(Main.value(args, ++i));
                    case "-f", "--format" -> format = Main.value(args, ++i);
                    case "-o", "--output" -> output = Path.of(Main.value(args, ++i));
                    case "--strict" -> strict = true;
                    default -> {
                        if (args[i].startsWith("-") || input != null) {
                            throw new IllegalArgumentException("Unexpected argument: " + args[i]);
                        }
                        input = args[i];
                    }
                }
            }
            if (input == null) throw new IllegalArgumentException("Missing <bundle>");
            if (format == null) {
                boolean html = output != null && output.getFileName().toString().toLowerCase().matches(".*\\.html?");
                format = html ? "html" : "text";
            }
            if (!format.equals("text") && !format.equals("html")) {
                throw new IllegalArgumentException("Unknown format " + format + " (text, html)");
            }
        } catch (IllegalArgumentException e) {
            err.println("error: " + e.getMessage());
            err.print(USAGE);
            return 2;
        }

        try {
            Path bundle = BundleLocator.locate(Path.of(input));
            SharedFlowRepository repository = sharedFlowDirs.isEmpty()
                    ? SharedFlowRepository.empty()
                    : SharedFlowRepository.scan(sharedFlowDirs);
            BundleReport analysis = new BundleAnalyzer(repository).analyze(bundle);
            MigrationReport report = new Migrator(MigrationOptions.DEFAULT, repository).migrate(analysis, outDir);
            String rendered = format.equals("html")
                    ? new MigrationHtmlRenderer().render(report)
                    : new MigrationTextRenderer().render(report);
            if (output != null) {
                Files.writeString(output, rendered);
                err.println("Written " + output.toAbsolutePath());
            } else {
                out.print(rendered);
            }
            return strict && report.hasOpenErrors() ? 3 : 0;
        } catch (IOException e) {
            err.println("error: " + e.getMessage());
            return 1;
        }
    }
}
