package dev.apigeemap.ui;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;

class TokenStoreTest {

    private final AtomicReference<Instant> now = new AtomicReference<>(Instant.parse("2026-01-01T10:00:00Z"));
    private final TokenStore store = new TokenStore(now::get);

    @Test
    void forgetsTheToken30MinutesAfterItWasTyped() {
        assertEquals(Optional.empty(), store.get());
        store.set(" t ");
        later(Duration.ofMinutes(29));
        assertEquals(Optional.of("t"), store.get());
        later(Duration.ofMinutes(1));
        assertEquals(Optional.empty(), store.get());
    }

    @Test
    void aNewTokenStartsAnother30Minutes() {
        store.set("old");
        later(Duration.ofMinutes(20));
        store.set("new");
        later(Duration.ofMinutes(20));
        assertEquals(Optional.of("new"), store.get());
    }

    @Test
    void aBlankTokenForgetsIt() {
        store.set("t");
        store.set("  ");
        assertEquals(Optional.empty(), store.get());
    }

    private void later(Duration duration) {
        now.set(now.get().plus(duration));
    }
}
