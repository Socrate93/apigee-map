package dev.apigeemap;

import dev.apigeemap.analysis.BundleAnalyzer;
import dev.apigeemap.analysis.BundleLocator;
import dev.apigeemap.analysis.SharedFlowRepository;
import dev.apigeemap.analysis.VariableFlow;
import dev.apigeemap.render.VariableFlowRenderer;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** {@code apigee-map variables}: which step sets each flow variable a step reads. */
final class VariablesCommand {

    static final String USAGE = """
            Usage: apigee-map variables <bundle> [options]

              Lists, in the order Apigee runs the steps, the flow variables each step reads and writes, and for
              every read the earlier steps that set it (or: built-in, set later, set nowhere).

            Options:
              -s, --sharedflows <dir>  folder containing shared flows, repeatable; FlowCallouts bring their variables
                  --policy <name>      only this policy, with the steps that read what it sets
              -f, --format <format>    text (default), json
              -o, --output <file>      write to a file; json when the name ends with .json
              -h, --help               show this help
            """;

    private VariablesCommand() {
    }

    static int run(String[] args, PrintStream out, PrintStream err) {
        String input = null;
        String policy = null;
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
                    case "-s", "--sharedflows" -> sharedFlowDirs.add(Path.of(Main.value(args, ++i)));
                    case "--policy" -> policy = Main.value(args, ++i);
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
            if (format == null) {
                format = output != null && output.getFileName().toString().toLowerCase().endsWith(".json")
                        ? "json" : "text";
            }
            if (!format.equals("text") && !format.equals("json")) {
                throw new IllegalArgumentException("Unknown format " + format + " (text, json)");
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
            VariableFlow flow = VariableFlow.of(new BundleAnalyzer(repository).analyze(bundle));
            String name = policy;
            if (name != null && flow.steps().stream().noneMatch(s -> s.policy().equals(name))) {
                err.println("error: no step runs policy " + name + " in " + flow.bundle().name());
                return 1;
            }
            VariableFlowRenderer renderer = new VariableFlowRenderer();
            String rendered = format.equals("json") ? renderer.json(flow, policy) : renderer.text(flow, policy);
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
}
