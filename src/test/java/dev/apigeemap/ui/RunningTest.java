package dev.apigeemap.ui;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RunningTest {

    /** A second ask while the operation runs waits for it and gets the same answer; then a new one can start. */
    @Test
    void sharesTheOperationThatRuns() throws Exception {
        Running running = new Running();
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger runs = new AtomicInteger();
        Running.Operation slow = () -> {
            runs.incrementAndGet();
            started.countDown();
            try {
                release.await();
            } catch (InterruptedException e) {
                throw new IOException(e);
            }
            return Map.of("doc", "written");
        };

        CompletableFuture<Map<String, Object>> first = CompletableFuture.supplyAsync(() -> call(running, slow));
        assertTrue(started.await(5, TimeUnit.SECONDS));
        assertTrue(running.since("document", "p").isPresent());
        assertTrue(running.since("document", "other").isEmpty());
        assertTrue(running.since("testPlan", "p").isEmpty());
        CompletableFuture<Map<String, Object>> second = CompletableFuture.supplyAsync(() -> call(running, slow));
        Thread.sleep(100);
        release.countDown();

        assertEquals(Map.of("doc", "written"), first.get(5, TimeUnit.SECONDS));
        assertEquals(Map.of("doc", "written"), second.get(5, TimeUnit.SECONDS));
        assertEquals(1, runs.get());
        assertTrue(running.since("document", "p").isEmpty(), "forgotten once it ended");
        call(running, slow);
        assertEquals(2, runs.get());
    }

    @Test
    void forgetsAFailedOperation() {
        Running running = new Running();
        assertThrows(IOException.class, () -> running.run("document", "p", () -> {
            throw new IOException("boom");
        }));
        assertTrue(running.since("document", "p").isEmpty());
    }

    private static Map<String, Object> call(Running running, Running.Operation operation) {
        try {
            return running.run("document", "p", operation);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
