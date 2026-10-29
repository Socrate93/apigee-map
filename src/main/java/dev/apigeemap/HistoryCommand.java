package dev.apigeemap;

import dev.apigeemap.analysis.BundleLocator;
import dev.apigeemap.history.SourceHistory;
import dev.apigeemap.history.SourceHistory.Step;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Set;

/** {@code apigee-map history}: the steps of a bundle changed in place, their diffs, and undoing one. */
final class HistoryCommand {

    static final String USAGE = """
            Usage: apigee-map history <bundle> [options]

              A bundle changed in place keeps a history: its original state, then one step per change (each rule
              applied by migrate --in-place, each change recorded with --record). Without option, lists the steps,
              newest first, and the changes not recorded yet.

            Options:
                  --record <message>   record the changes made since the last step as a new step
                  --diff <step>        what a step changed; "original" for every change since the original state
                  --revert <step>      undo a step with a new step (fails when a later step changes the same lines)
                  --history <dir>      where histories are kept (default ~/.apigee-map/history)
              -h, --help               show this help
            """;

    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")
            .withZone(ZoneId.systemDefault());

    private HistoryCommand() {
    }

    static int run(String[] args, PrintStream out, PrintStream err) {
        String input = null;
        String record = null;
        String diff = null;
        String revert = null;
        Path root = SourceHistory.defaultRoot();
        try {
            for (int i = 0; i < args.length; i++) {
                switch (args[i]) {
                    case "-h", "--help" -> {
                        out.print(USAGE);
                        return 0;
                    }
                    case "--record" -> record = Main.value(args, ++i);
                    case "--diff" -> diff = Main.value(args, ++i);
                    case "--revert" -> revert = Main.value(args, ++i);
                    case "--history" -> root = Path.of(Main.value(args, ++i));
                    default -> {
                        if (args[i].startsWith("-") || input != null) {
                            throw new IllegalArgumentException("Unexpected argument: " + args[i]);
                        }
                        input = args[i];
                    }
                }
            }
            if (input == null) throw new IllegalArgumentException("Missing <bundle>");
            if (Files.isRegularFile(Path.of(input))) throw new IllegalArgumentException("Expected a bundle folder");
            if ((record != null ? 1 : 0) + (diff != null ? 1 : 0) + (revert != null ? 1 : 0) > 1) {
                throw new IllegalArgumentException("--record, --diff and --revert exclude each other");
            }
        } catch (IllegalArgumentException e) {
            err.println("error: " + e.getMessage());
            err.print(USAGE);
            return 2;
        }

        try (SourceHistory history = SourceHistory.open(BundleLocator.locate(Path.of(input)), root)) {
            if (record != null) {
                Step step = history.record(record);
                err.println(step == null ? "Nothing changed since the last step" : "Recorded " + line(step));
            } else if (diff != null) {
                out.print(diff.equals("original") ? history.diffSinceOriginal() : history.diff(diff));
            } else if (revert != null) {
                err.println("Recorded " + line(history.revert(revert)));
            } else {
                for (Step step : history.steps()) out.println(line(step));
                Set<String> pending = history.pendingChanges();
                if (!pending.isEmpty()) {
                    out.println("\nNot recorded yet (--record <message>):");
                    pending.forEach(file -> out.println("  " + file));
                }
            }
            return 0;
        } catch (IOException e) {
            err.println("error: " + e.getMessage());
            return 1;
        }
    }

    private static String line(Step step) {
        String files = step.title().equals(SourceHistory.ORIGINAL) ? ""
                : "  (" + step.files().size() + (step.files().size() == 1 ? " file)" : " files)");
        return step.id() + "  " + TIME.format(step.time()) + "  " + step.title() + files;
    }
}
