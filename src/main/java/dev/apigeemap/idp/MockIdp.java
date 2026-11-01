package dev.apigeemap.idp;

import java.io.IOException;
import java.net.BindException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The mock identity provider of the app: its settings, and its server, which the Mock IdP page starts and stops. It
 * runs in the process of the UI on its own port. A change of settings while it runs restarts it.
 */
public final class MockIdp {

    private final Path dir;
    private final IdpState state = new IdpState();
    private final IdpPki pki;
    private IdpConfig config;
    private IdpServer server;
    private String error = "";

    /** @param dir where its settings and certificates are kept */
    public MockIdp(Path dir) throws IOException {
        this.dir = dir;
        this.pki = new IdpPki(dir.resolve("certificates"));
        this.config = IdpConfig.load(file());
    }

    /** Starts it when it was running the last time the app stopped; a failure shows on the page. */
    public synchronized void startIfAsked() {
        if (!config.autoStart()) return;
        try {
            run();
        } catch (IOException | GeneralSecurityException e) {
            error = message(e);
        }
    }

    public synchronized Map<String, Object> status() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("config", config);
        status.put("running", server != null);
        status.put("error", error);
        status.put("options", Map.of("transports", IdpConfig.TRANSPORTS, "grants", IdpConfig.GRANTS, "authMethods",
                IdpConfig.AUTH_METHODS, "signingAlgs", IdpConfig.SIGNING_ALGS, "responseModes", IdpConfig.RESPONSE_MODES,
                "pkceMethods", IdpConfig.PKCE_METHODS));
        if (server != null) {
            status.put("url", server.url());
            status.put("issuer", server.issuer());
        }
        Path certificates = pki.dir().toAbsolutePath();
        Map<String, Object> files = new LinkedHashMap<>();
        files.put("dir", certificates.toString());
        files.put("ca", certificates.resolve("ca.pem").toString());
        files.put("certificate", certificates.resolve("client.pem").toString());
        files.put("key", certificates.resolve("client-key.pem").toString());
        files.put("keystore", certificates.resolve("client.p12").toString());
        files.put("subject", IdpPki.CLIENT_SUBJECT);
        status.put("certificates", files);
        status.put("tokens", state.tokens.size());
        status.put("log", state.log());
        return status;
    }

    public synchronized Map<String, Object> save(Object json) throws IOException, GeneralSecurityException {
        IdpConfig updated = IdpConfig.fromJson(json);
        boolean running = server != null;
        config = withAutoStart(updated, running);
        config.save(file());
        if (running) restart();
        return status();
    }

    public synchronized Map<String, Object> start() throws IOException, GeneralSecurityException {
        if (server == null) restart();
        config = withAutoStart(config, true);
        config.save(file());
        return status();
    }

    public synchronized Map<String, Object> stop() throws IOException {
        halt();
        config = withAutoStart(config, false);
        config.save(file());
        return status();
    }

    /** Forgets what was issued and the requests seen. */
    public synchronized Map<String, Object> clear() {
        state.clear();
        return status();
    }

    /** Stops it with the app, without changing what the next start does. */
    public synchronized void close() {
        halt();
    }

    private void restart() throws IOException, GeneralSecurityException {
        halt();
        try {
            run();
        } catch (IOException | GeneralSecurityException e) {
            error = message(e);
            throw e;
        }
    }

    private void run() throws IOException, GeneralSecurityException {
        try {
            server = IdpServer.start(config, state, pki);
            error = "";
        } catch (BindException e) {
            throw new IOException("Port " + config.port() + " is already in use", e);
        }
    }

    private void halt() {
        if (server != null) server.stop();
        server = null;
    }

    private Path file() {
        return dir.resolve("config.json");
    }

    private static String message(Exception e) {
        return String.valueOf(e.getMessage());
    }

    private static IdpConfig withAutoStart(IdpConfig c, boolean autoStart) {
        return new IdpConfig(autoStart, c.transport(), c.port(), c.issuer(), c.grants(), c.authMethods(), c.pkce(),
                c.pkceMethods(), c.tokenFormat(), c.signingAlg(), c.hmacSecret(), c.tokenType(), c.audience(),
                c.accessTokenTtl(), c.refreshTokenTtl(), c.idTokenTtl(), c.codeTtl(), c.refreshRotation(), c.boundTokens(),
                c.openId(), c.login(), c.consent(), c.requirePar(), c.responseModes(), c.introspectionAuth(), c.scopes(),
                c.extraClaims(), c.delayMs(), c.faultEndpoint(), c.faultStatus(), c.faultError(), c.clients(), c.users());
    }
}
