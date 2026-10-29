package dev.apigeemap.ui;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * The client token typed in the Settings screen, kept in memory only and forgotten 30 minutes after it was typed:
 * past that, the UI behaves as if no token had been given.
 */
final class TokenStore {

    static final Duration LIFETIME = Duration.ofMinutes(30);

    private final Supplier<Instant> clock;
    private String token;
    private Instant expiry;

    TokenStore() {
        this(Instant::now);
    }

    TokenStore(Supplier<Instant> clock) {
        this.clock = clock;
    }

    /** Keeps the token for {@link #LIFETIME}; a blank one forgets the token. */
    synchronized void set(String value) {
        if (value == null || value.isBlank()) {
            token = null;
            expiry = null;
        } else {
            token = value.trim();
            expiry = clock.get().plus(LIFETIME);
        }
    }

    synchronized Optional<String> get() {
        if (token != null && !clock.get().isBefore(expiry)) set(null);
        return Optional.ofNullable(token);
    }
}
