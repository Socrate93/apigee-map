package dev.apigeemap.ui;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The backend operations in progress, one per kind and proxy, so that the page shows one running after it was left
 * and opened again, and a second ask for it waits for the first one instead of starting another. Kept in memory only:
 * they end with the app.
 */
final class Running {

    interface Operation {
        Map<String, Object> run() throws IOException;
    }

    private record Entry(Instant since, CompletableFuture<Map<String, Object>> result) {
    }

    private final Map<String, Entry> running = new ConcurrentHashMap<>();

    /** Runs the operation, or waits for the same one already running and answers what it answers. */
    Map<String, Object> run(String kind, String id, Operation operation) throws IOException {
        String key = kind + " " + id;
        Entry mine = new Entry(Instant.now(), new CompletableFuture<>());
        Entry existing = running.putIfAbsent(key, mine);
        if (existing != null) return join(existing.result());
        try {
            Map<String, Object> result = operation.run();
            mine.result().complete(result);
            return result;
        } catch (IOException | RuntimeException | Error e) {
            mine.result().completeExceptionally(e);
            throw e;
        } finally {
            running.remove(key, mine);
        }
    }

    /** When the operation of this kind started for the proxy, while it runs. */
    Optional<Instant> since(String kind, String id) {
        return Optional.ofNullable(running.get(kind + " " + id)).map(Entry::since);
    }

    private static Map<String, Object> join(CompletableFuture<Map<String, Object>> result) throws IOException {
        try {
            return result.join();
        } catch (CompletionException e) {
            if (e.getCause() instanceof IOException io) throw io;
            if (e.getCause() instanceof RuntimeException runtime) throw runtime;
            if (e.getCause() instanceof Error error) throw error;
            throw e;
        }
    }
}
