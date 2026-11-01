package dev.apigeemap.idp;

import dev.apigeemap.protocol.Json;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * What the mock identity provider does, set from the Mock IdP page and stored as JSON.
 *
 * @param transport         {@code http}, {@code tls}, {@code mtls-optional} (a client certificate is asked) or
 *                          {@code mtls-required}
 * @param issuer            the issuer of tokens; blank means the address of the server
 * @param grants            enabled grants, among {@link #GRANTS}
 * @param authMethods       enabled client authentication methods, among {@link #AUTH_METHODS}
 * @param pkce              {@code off}, {@code optional} or {@code required}
 * @param tokenFormat       {@code jwt} or {@code opaque}
 * @param boundTokens       access tokens carry the thumbprint of the client certificate (RFC 8705)
 * @param login             {@code auto} logs in the first user, or the login_hint; {@code form} shows a form
 * @param faultEndpoint     where the injected fault applies: blank for nowhere, {@code all}, or a path such as /token
 */
public record IdpConfig(boolean autoStart, String transport, int port, String issuer, List<String> grants,
                        List<String> authMethods, String pkce, List<String> pkceMethods, String tokenFormat,
                        String signingAlg, String hmacSecret, String tokenType, String audience, int accessTokenTtl,
                        int refreshTokenTtl, int idTokenTtl, int codeTtl, boolean refreshRotation, boolean boundTokens,
                        boolean openId, String login, boolean consent, boolean requirePar, List<String> responseModes,
                        boolean introspectionAuth, List<String> scopes, Map<String, Object> extraClaims, int delayMs,
                        String faultEndpoint, int faultStatus, String faultError, List<Client> clients,
                        List<User> users) {

    public static final List<String> TRANSPORTS = List.of("http", "tls", "mtls-optional", "mtls-required");
    public static final List<String> GRANTS = List.of("authorization_code", "implicit", "client_credentials", "password",
            "refresh_token", "device_code", "token_exchange", "jwt_bearer");
    public static final List<String> AUTH_METHODS = List.of("client_secret_basic", "client_secret_post",
            "client_secret_jwt", "private_key_jwt", "tls_client_auth", "none");
    public static final List<String> SIGNING_ALGS = List.of("RS256", "PS256", "ES256", "HS256");
    public static final List<String> RESPONSE_MODES = List.of("query", "fragment", "form_post");
    public static final List<String> PKCE_METHODS = List.of("S256", "plain");

    /**
     * @param authMethod the one way this client authenticates, among {@link #AUTH_METHODS}
     * @param grants     what it may use; empty means all that are enabled
     * @param scopes     what it may ask; empty means all
     * @param publicKey  PEM public key for {@code private_key_jwt}
     * @param tlsSubject certificate subject for {@code tls_client_auth}
     */
    public record Client(String id, String secret, String authMethod, List<String> redirectUris, List<String> grants,
                         List<String> scopes, String publicKey, String tlsSubject) {
    }

    public record User(String username, String password, String sub, String name, String email) {
    }

    public static IdpConfig defaults() {
        return new IdpConfig(false, "http", 8766, "", GRANTS, AUTH_METHODS, "optional", PKCE_METHODS, "jwt", "RS256",
                "mock-idp-hmac-secret-for-local-tests-only", "Bearer", "", 1800, 86400, 1800, 60, true, false, true, "auto",
                false, false, RESPONSE_MODES, true, List.of("openid", "profile", "email", "offline_access", "api.read",
                "api.write"), Map.of(), 0, "", 503, "temporarily_unavailable",
                List.of(new Client("demo-client", "demo-secret", "client_secret_basic",
                                List.of("http://localhost:3000/callback", "https://oauth.pstmn.io/v1/callback"),
                                List.of(), List.of(), "", ""),
                        new Client("spa-client", "", "none", List.of("http://localhost:3000/callback"),
                                List.of("authorization_code", "refresh_token"), List.of(), "", ""),
                        new Client("mtls-client", "", "tls_client_auth", List.of("http://localhost:3000/callback"),
                                List.of(), List.of(), "", IdpPki.CLIENT_SUBJECT),
                        new Client("apigee-broker", "broker-secret", "client_secret_basic",
                                List.of("https://localhost/oauth/v2/callback"),
                                List.of("authorization_code", "refresh_token"), List.of(), "", "")),
                List.of(new User("alice", "alice-password", "user-1001", "Alice Martin", "alice@example.com"),
                        new User("bob", "bob-password", "user-1002", "Bob Durand", "bob@example.com")));
    }

    static IdpConfig load(Path file) throws IOException {
        if (!Files.isRegularFile(file)) return defaults();
        try {
            return fromJson(Json.parse(Files.readString(file)));
        } catch (IllegalArgumentException e) {
            throw new IOException("Invalid mock IdP settings " + file + ": " + e.getMessage(), e);
        }
    }

    void save(Path file) throws IOException {
        Files.createDirectories(file.toAbsolutePath().getParent());
        Files.writeString(file, Json.write(this) + "\n");
    }

    /** Builds the settings from parsed JSON: what is missing keeps its default, what is invalid is rejected. */
    public static IdpConfig fromJson(Object json) {
        if (!(json instanceof Map<?, ?> map)) throw new IllegalArgumentException("Settings must be a JSON object");
        IdpConfig d = defaults();
        IdpConfig config = new IdpConfig(bool(map, "autoStart", d.autoStart),
                oneOf(map, "transport", d.transport, TRANSPORTS), number(map, "port", d.port, 0, 65535),
                text(map, "issuer", d.issuer), someOf(map, "grants", d.grants, GRANTS),
                someOf(map, "authMethods", d.authMethods, AUTH_METHODS),
                oneOf(map, "pkce", d.pkce, List.of("off", "optional", "required")),
                someOf(map, "pkceMethods", d.pkceMethods, PKCE_METHODS),
                oneOf(map, "tokenFormat", d.tokenFormat, List.of("jwt", "opaque")),
                oneOf(map, "signingAlg", d.signingAlg, SIGNING_ALGS), text(map, "hmacSecret", d.hmacSecret),
                text(map, "tokenType", d.tokenType), text(map, "audience", d.audience),
                number(map, "accessTokenTtl", d.accessTokenTtl, 1, Integer.MAX_VALUE),
                number(map, "refreshTokenTtl", d.refreshTokenTtl, 1, Integer.MAX_VALUE),
                number(map, "idTokenTtl", d.idTokenTtl, 1, Integer.MAX_VALUE),
                number(map, "codeTtl", d.codeTtl, 1, Integer.MAX_VALUE), bool(map, "refreshRotation", d.refreshRotation),
                bool(map, "boundTokens", d.boundTokens), bool(map, "openId", d.openId),
                oneOf(map, "login", d.login, List.of("auto", "form")), bool(map, "consent", d.consent),
                bool(map, "requirePar", d.requirePar), someOf(map, "responseModes", d.responseModes, RESPONSE_MODES),
                bool(map, "introspectionAuth", d.introspectionAuth), strings(map, "scopes", d.scopes),
                claims(map.get("extraClaims")), number(map, "delayMs", d.delayMs, 0, 60000),
                text(map, "faultEndpoint", d.faultEndpoint), number(map, "faultStatus", d.faultStatus, 400, 599),
                text(map, "faultError", d.faultError), clients(map.get("clients"), d.clients),
                users(map.get("users"), d.users));
        if (config.tokenType.isBlank()) throw new IllegalArgumentException("The token type cannot be blank");
        if (config.signingAlg.equals("HS256") && config.hmacSecret.length() < 32) {
            throw new IllegalArgumentException("HS256 needs a shared secret of at least 32 characters");
        }
        return config;
    }

    /** A client by its id, or null. */
    Client client(String id) {
        return clients.stream().filter(c -> c.id.equals(id)).findFirst().orElse(null);
    }

    /** A user by its name, or null. */
    User user(String username) {
        return users.stream().filter(u -> u.username.equals(username)).findFirst().orElse(null);
    }

    private static List<Client> clients(Object value, List<Client> fallback) {
        if (value == null) return fallback;
        if (!(value instanceof List<?> list)) throw new IllegalArgumentException("clients must be a list");
        List<Client> clients = new ArrayList<>();
        Set<String> ids = new LinkedHashSet<>();
        for (Object item : list) {
            if (!(item instanceof Map<?, ?> map)) throw new IllegalArgumentException("A client must be an object");
            String id = text(map, "id", "").trim();
            if (id.isEmpty()) throw new IllegalArgumentException("A client needs an id");
            if (!ids.add(id)) throw new IllegalArgumentException("Two clients have the id " + id);
            String method = oneOf(map, "authMethod", "client_secret_basic", AUTH_METHODS);
            String secret = text(map, "secret", "");
            if (method.startsWith("client_secret") && secret.isEmpty()) {
                throw new IllegalArgumentException("Client " + id + " needs a secret");
            }
            if (method.equals("client_secret_jwt") && secret.length() < 32) {
                throw new IllegalArgumentException("Client " + id + " needs a secret of at least 32 characters");
            }
            String publicKey = text(map, "publicKey", "");
            if (method.equals("private_key_jwt") && publicKey.isBlank()) {
                throw new IllegalArgumentException("Client " + id + " needs a public key");
            }
            String subject = text(map, "tlsSubject", "");
            if (method.equals("tls_client_auth") && subject.isBlank()) {
                throw new IllegalArgumentException("Client " + id + " needs a certificate subject");
            }
            clients.add(new Client(id, secret, method, strings(map, "redirectUris", List.of()),
                    someOf(map, "grants", List.of(), GRANTS), strings(map, "scopes", List.of()), publicKey, subject));
        }
        return clients;
    }

    private static List<User> users(Object value, List<User> fallback) {
        if (value == null) return fallback;
        if (!(value instanceof List<?> list)) throw new IllegalArgumentException("users must be a list");
        List<User> users = new ArrayList<>();
        Set<String> names = new LinkedHashSet<>();
        for (Object item : list) {
            if (!(item instanceof Map<?, ?> map)) throw new IllegalArgumentException("A user must be an object");
            String username = text(map, "username", "").trim();
            if (username.isEmpty()) throw new IllegalArgumentException("A user needs a name");
            if (!names.add(username)) throw new IllegalArgumentException("Two users are named " + username);
            String sub = text(map, "sub", "").trim();
            users.add(new User(username, text(map, "password", ""), sub.isEmpty() ? username : sub,
                    text(map, "name", ""), text(map, "email", "")));
        }
        return users;
    }

    private static Map<String, Object> claims(Object value) {
        if (value == null) return Map.of();
        if (!(value instanceof Map<?, ?> map)) throw new IllegalArgumentException("extraClaims must be a JSON object");
        Map<String, Object> claims = new LinkedHashMap<>();
        map.forEach((name, claim) -> claims.put(String.valueOf(name), claim));
        return claims;
    }

    private static String text(Map<?, ?> map, String key, String fallback) {
        Object value = map.get(key);
        return value == null ? fallback : String.valueOf(value);
    }

    private static boolean bool(Map<?, ?> map, String key, boolean fallback) {
        return map.get(key) instanceof Boolean value ? value : fallback;
    }

    private static int number(Map<?, ?> map, String key, int fallback, int min, int max) {
        Object value = map.get(key);
        if (value == null) return fallback;
        if (!(value instanceof Number number) || number.intValue() < min || number.intValue() > max) {
            throw new IllegalArgumentException(key + " must be a number from " + min + " to " + max);
        }
        return number.intValue();
    }

    private static String oneOf(Map<?, ?> map, String key, String fallback, List<String> allowed) {
        String value = text(map, key, fallback);
        if (!allowed.contains(value)) throw new IllegalArgumentException("Unknown " + key + ": " + value);
        return value;
    }

    private static List<String> someOf(Map<?, ?> map, String key, List<String> fallback, List<String> allowed) {
        List<String> values = strings(map, key, fallback);
        for (String value : values) {
            if (!allowed.contains(value)) throw new IllegalArgumentException("Unknown " + key + ": " + value);
        }
        return values;
    }

    private static List<String> strings(Map<?, ?> map, String key, List<String> fallback) {
        Object value = map.get(key);
        if (value == null) return fallback;
        if (!(value instanceof List<?> list)) throw new IllegalArgumentException(key + " must be a list");
        return list.stream().map(item -> String.valueOf(item).trim()).filter(s -> !s.isEmpty()).distinct().toList();
    }
}
