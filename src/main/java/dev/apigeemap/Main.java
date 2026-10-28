package dev.apigeemap;

import dev.apigeemap.analysis.BundleAnalyzer;
import dev.apigeemap.analysis.BundleLocator;
import dev.apigeemap.analysis.SharedFlowRepository;
import dev.apigeemap.model.BundleReport;
import dev.apigeemap.render.HtmlRenderer;
import dev.apigeemap.render.JsonRenderer;
import dev.apigeemap.render.MermaidRenderer;
import dev.apigeemap.render.ReportView;
import dev.apigeemap.render.TextRenderer;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class Main {

    private static final String USAGE = """
            Usage: apigee-map <bundle> [options]
                   apigee-map migrate <bundle> [options]   (Apigee hybrid migration, see migrate --help)
                   apigee-map ui [options]                 (web UI, see ui --help)

              <bundle>                 apiproxy/ or sharedflowbundle/ folder, its parent folder, or a bundle .zip

            Options:
              -s, --sharedflows <dir>  folder containing shared flows (searched recursively for sharedflowbundle/),
                                       repeatable; FlowCallouts are followed recursively
              -f, --format <format>    text (default), json, mermaid, html
              -o, --output <file>      write to a file; the format is inferred from .json/.html/.mmd when -f is absent
                  --strict             exit with code 3 when the report contains ERROR issues
              -h, --help               show this help
            """;

    private Main() {
    }

    public static void main(String[] args) {
        System.exit(run(args, System.out, System.err));
    }

    static int run(String[] args, PrintStream out, PrintStream err) {
        if (args.length > 0 && args[0].equals("migrate")) {
            return MigrateCommand.run(Arrays.copyOfRange(args, 1, args.length), out, err);
        }
        if (args.length > 0 && args[0].equals("ui")) {
            return UiCommand.run(Arrays.copyOfRange(args, 1, args.length), out, err);
        }
        String input = null;
        String format = null;
        Path output = null;
        boolean strict = false;
        List<Path> sharedFlowDirs = new ArrayList<>();
        try {
            for (int i = 0; i < args.length; i++) {
                switch (args[i]) {
                    case "-h", "--help" -> {
                        out.print(USAGE);
                        return 0;
                    }
                    case "-s", "--sharedflows" -> sharedFlowDirs.add(Path.of(value(args, ++i)));
                    case "-f", "--format" -> format = value(args, ++i);
                    case "-o", "--output" -> output = Path.of(value(args, ++i));
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
            if (format == null) format = inferFormat(output);
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
            BundleReport report = new BundleAnalyzer(repository).analyze(bundle);
            String rendered = switch (format) {
                case "text" -> new TextRenderer().render(report);
                case "json" -> new JsonRenderer().render(report);
                case "mermaid" -> new MermaidRenderer().render(report);
                case "html" -> new HtmlRenderer().render(report);
                default -> {
                    err.println("error: unknown format " + format + " (text, json, mermaid, html)");
                    yield null;
                }
            };
            if (rendered == null) return 2;
            if (output != null) {
                Files.writeString(output, rendered);
                err.println("Written " + output.toAbsolutePath());
            } else {
                out.print(rendered);
            }
            return strict && ReportView.hasErrors(report) ? 3 : 0;
        } catch (IOException e) {
            err.println("error: " + e.getMessage());
            return 1;
        }
    }

    static String value(String[] args, int index) {
        if (index >= args.length) throw new IllegalArgumentException("Missing value for " + args[index - 1]);
        return args[index];
    }

    private static String inferFormat(Path output) {
        if (output == null) return "text";
        String name = output.getFileName().toString().toLowerCase();
        if (name.endsWith(".json")) return "json";
        if (name.endsWith(".html") || name.endsWith(".htm")) return "html";
        if (name.endsWith(".mmd") || name.endsWith(".mermaid")) return "mermaid";
        return "text";
    }
}
