package dev.apigeemap;

import dev.apigeemap.history.SourceHistory;
import dev.apigeemap.history.SourceHistory.Step;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HistoryTest {

    @TempDir
    Path tmp;

    @Test
    void migrateInPlaceRecordsOneStepPerRule() throws IOException {
        Path proxy = copy("examples/orders-api").resolve("apiproxy");
        copy("examples/sharedflows");
        Path endpoint = proxy.resolve("proxies/default.xml");
        SourceHistory.open(proxy, tmp.resolve("history")).close();
        // changed by hand after the history started: recorded before the auto-fixes
        Files.writeString(endpoint, Files.readString(endpoint).replace("/v1/orders", "/v2/orders"));

        assertEquals(0, migrate());
        assertFalse(Files.readString(endpoint).contains("<VirtualHost>"));
        assertFalse(Files.exists(proxy.resolve(".git")), "the repository stays out of the bundle");
        try (SourceHistory history = SourceHistory.open(proxy, tmp.resolve("history"))) {
            assertEquals(List.of("DES-07 Policies attached to no flow are removed",
                            "DES-01 Hardcoded target URLs moved to target servers",
                            "HYB-02 VirtualHost is ignored by hybrid", "Manual changes", SourceHistory.ORIGINAL),
                    history.steps().stream().map(Step::title).toList());
            assertEquals(List.of("policies/KVM-Legacy-Unused.xml"), history.steps().get(0).files());
            assertTrue(history.pendingChanges().isEmpty());
        }

        // the auto-fixes are in the bundle now: nothing left to do
        assertEquals(0, migrate());
        try (SourceHistory history = SourceHistory.open(proxy, tmp.resolve("history"))) {
            assertEquals(5, history.steps().size());
        }
    }

    @Test
    void recordsShowsAndRevertsSteps() throws IOException {
        Path proxy = copy("examples/orders-api").resolve("apiproxy");
        Path target = proxy.resolve("targets/legacy.xml");
        Path endpoint = proxy.resolve("proxies/default.xml");
        String original = Files.readString(target);
        try (SourceHistory history = SourceHistory.open(proxy, tmp.resolve("history"))) {
            assertNull(history.record("Nothing"));

            Files.writeString(target, original.replace(":8080", ":9090"));
            Files.writeString(proxy.resolve("resources/jsc/new.js"), "var x = 1;\n");
            assertEquals(Set.of("targets/legacy.xml", "resources/jsc/new.js"), history.pendingChanges());
            Step port = history.record("Port 9090");
            assertEquals(List.of("resources/jsc/new.js", "targets/legacy.xml"), port.files());
            assertTrue(history.diff(port.id()).lines().anyMatch(l -> l.startsWith("+") && l.contains(":9090/orders")));

            Files.writeString(endpoint, Files.readString(endpoint).replace("/v1/orders", "/v2/orders"));
            assertThrows(IOException.class, () -> history.revert(port.id()), "changes not recorded yet");
            history.record("Base path v2");

            Step undone = history.revert(port.id());
            assertEquals("Revert \"Port 9090\"", undone.title());
            assertEquals(original, Files.readString(target));
            assertFalse(Files.exists(proxy.resolve("resources/jsc/new.js")));
            assertTrue(Files.readString(endpoint).contains("/v2/orders"), "later steps are kept");
            assertTrue(history.diffSinceOriginal().contains("+        <BasePath>/v2/orders</BasePath>"));
            assertFalse(history.diffSinceOriginal().contains("legacy.xml"));
        }
    }

    @Test
    void refusesARevertThatConflictsWithALaterStep() throws IOException {
        Path proxy = copy("examples/orders-api").resolve("apiproxy");
        Path target = proxy.resolve("targets/legacy.xml");
        try (SourceHistory history = SourceHistory.open(proxy, tmp.resolve("history"))) {
            Files.writeString(target, Files.readString(target).replace(":8080", ":9090"));
            Step first = history.record("Port 9090");
            Files.writeString(target, Files.readString(target).replace(":9090", ":7070"));
            history.record("Port 7070");

            IOException error = assertThrows(IOException.class, () -> history.revert(first.id()));
            assertTrue(error.getMessage().contains("targets/legacy.xml"), error.getMessage());
            assertTrue(Files.readString(target).contains(":7070"), "nothing changed");
            assertTrue(history.pendingChanges().isEmpty());
            assertEquals(3, history.steps().size());
        }
    }

    private int migrate() {
        String[] args = {"migrate", tmp.resolve("orders-api").toString(), "-s", tmp.resolve("sharedflows").toString(),
                "--in-place", "--history", tmp.resolve("history").toString()};
        return Main.run(args, new PrintStream(new ByteArrayOutputStream()), new PrintStream(new ByteArrayOutputStream()));
    }

    private Path copy(String example) throws IOException {
        Path source = Path.of(example);
        Path target = tmp.resolve(source.getFileName().toString());
        try (Stream<Path> paths = Files.walk(source)) {
            for (Path path : paths.toList()) {
                Path copy = target.resolve(source.relativize(path).toString());
                if (Files.isDirectory(path)) {
                    Files.createDirectories(copy);
                } else {
                    Files.copy(path, copy);
                }
            }
        }
        return target;
    }
}
