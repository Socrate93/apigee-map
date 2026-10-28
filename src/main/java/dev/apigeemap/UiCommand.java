package dev.apigeemap;

import dev.apigeemap.ui.Settings;
import dev.apigeemap.ui.UiServer;

import java.awt.Desktop;
import java.io.IOException;
import java.io.PrintStream;
import java.net.URI;
import java.nio.file.Path;
import java.util.concurrent.CountDownLatch;

/** {@code apigee-map ui}: starts the local web UI and opens it in the browser. */
final class UiCommand {

    static final int DEFAULT_PORT = 8765;

    static final String USAGE = """
            Usage: apigee-map ui [options]

              Starts the web UI on http://127.0.0.1 (reachable from this computer only) and opens it in the browser.

            Options:
                  --port <port>        port to listen on (default 8765; a free port is used when it is taken)
                  --settings <file>    settings file (default ~/.apigee-map/settings.json)
                  --no-browser         do not open the browser
              -h, --help               show this help
            """;

    private UiCommand() {
    }

    static int run(String[] args, PrintStream out, PrintStream err) {
        int port = DEFAULT_PORT;
        Path settings = Settings.defaultFile();
        boolean browser = true;
        try {
            for (int i = 0; i < args.length; i++) {
                switch (args[i]) {
                    case "-h", "--help" -> {
                        out.print(USAGE);
                        return 0;
                    }
                    case "--port" -> port = Integer.parseInt(Main.value(args, ++i));
                    case "--settings" -> settings = Path.of(Main.value(args, ++i));
                    case "--no-browser" -> browser = false;
                    default -> throw new IllegalArgumentException("Unexpected argument: " + args[i]);
                }
            }
        } catch (IllegalArgumentException e) {
            err.println("error: " + e.getMessage());
            err.print(USAGE);
            return 2;
        }

        UiServer server;
        try {
            server = UiServer.start(settings, port);
        } catch (IOException e) {
            err.println("error: " + e.getMessage());
            return 1;
        }
        out.println("apigee-map UI running at " + server.url());
        out.println("Settings: " + settings.toAbsolutePath());
        out.println("Press Ctrl+C to stop.");
        if (browser) open(server.url(), err);

        CountDownLatch stopped = new CountDownLatch(1);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            server.stop();
            stopped.countDown();
        }));
        try {
            stopped.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return 0;
    }

    private static void open(String url, PrintStream err) {
        try {
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(URI.create(url));
                return;
            }
            String os = System.getProperty("os.name").toLowerCase();
            String[] command = os.contains("win") ? new String[]{"rundll32", "url.dll,FileProtocolHandler", url}
                    : os.contains("mac") ? new String[]{"open", url}
                    : new String[]{"xdg-open", url};
            new ProcessBuilder(command).start();
        } catch (IOException | RuntimeException e) {
            err.println("Open " + url + " in your browser (" + e.getMessage() + ")");
        }
    }
}
