package dev.apigeemap.idp;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** What the mock IdP has issued and seen. It outlives a restart of the server, so a change of settings keeps tokens. */
final class IdpState {

    /** A request waiting for a user, or pushed ahead of the authorize call. */
    record Pending(Map<String, String> request, long expires) {
    }

    record Code(String client, String redirectUri, String scope, String user, String nonce, String challenge,
                String method, long expires) {
    }

    /** @param grantId shared by the tokens of one grant, so that revoking a refresh token revokes them all */
    record Token(String value, boolean refresh, String client, String user, String scope, long expires, String grantId,
                 String thumbprint, String audience) {
    }

    record Device(String client, String userCode, String scope, String user, boolean denied, long expires) {
        Device approvedBy(String username) {
            return new Device(client, userCode, scope, username, false, expires);
        }

        Device refused() {
            return new Device(client, userCode, scope, null, true, expires);
        }
    }

    /** One request as the Mock IdP page lists it: no parameter is kept, so no credential either. */
    public record Entry(long time, String method, String path, int status, long ms, String client, String grant,
                        String certificate, String error) {
    }

    private static final int LOG_SIZE = 200;

    final Map<String, Pending> logins = new ConcurrentHashMap<>();
    final Map<String, Pending> pushed = new ConcurrentHashMap<>();
    final Map<String, Code> codes = new ConcurrentHashMap<>();
    final Map<String, Token> tokens = new ConcurrentHashMap<>();
    final Map<String, Device> devices = new ConcurrentHashMap<>();
    final Map<String, Long> assertions = new ConcurrentHashMap<>();
    private final IdpKeys keys = new IdpKeys();
    private final Deque<Entry> log = new ArrayDeque<>();

    IdpKeys keys() {
        return keys;
    }

    void sweep(long now) {
        logins.values().removeIf(p -> p.expires() < now);
        pushed.values().removeIf(p -> p.expires() < now);
        codes.values().removeIf(c -> c.expires() < now);
        tokens.values().removeIf(t -> t.expires() < now);
        devices.values().removeIf(d -> d.expires() < now);
        assertions.values().removeIf(expires -> expires < now);
    }

    void clear() {
        logins.clear();
        pushed.clear();
        codes.clear();
        tokens.clear();
        devices.clear();
        assertions.clear();
        synchronized (log) {
            log.clear();
        }
    }

    void log(Entry entry) {
        synchronized (log) {
            log.addFirst(entry);
            if (log.size() > LOG_SIZE) log.removeLast();
        }
    }

    List<Entry> log() {
        synchronized (log) {
            return new ArrayList<>(log);
        }
    }
}
