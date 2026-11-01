package dev.apigeemap.idp;

import dev.apigeemap.protocol.Json;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.spec.RSAPublicKeySpec;
import java.math.BigInteger;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MockIdpTest {

    private static final String REDIRECT = "http://localhost:3000/callback";
    private static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    @TempDir
    Path dir;

    private MockIdp idp;
    private final HttpClient http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();

    @AfterEach
    void stop() {
        if (idp != null) idp.close();
    }

    private String start(Map<String, Object> settings) throws Exception {
        Map<String, Object> all = new LinkedHashMap<>(Map.of("port", 0.0));
        all.putAll(settings);
        if (idp != null) idp.close();
        idp = new MockIdp(dir);
        idp.save(all);
        return (String) idp.start().get("url");
    }

    private HttpResponse<String> post(HttpClient client, String url, String basic, String... form) throws Exception {
        StringBuilder body = new StringBuilder();
        for (int i = 0; i < form.length; i += 2) {
            if (i > 0) body.append('&');
            body.append(form[i]).append('=').append(URLEncoder.encode(form[i + 1], StandardCharsets.UTF_8));
        }
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(url))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body.toString()));
        if (basic != null) {
            request.header("Authorization", "Basic "
                    + Base64.getEncoder().encodeToString(basic.getBytes(StandardCharsets.UTF_8)));
        }
        return client.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> get(String url) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create(url)).build(), HttpResponse.BodyHandlers.ofString());
    }

    private static Map<?, ?> json(HttpResponse<String> response) {
        return (Map<?, ?>) Json.parse(response.body());
    }

    private static Map<?, ?> payload(String jwt) {
        return (Map<?, ?>) Json.parse(new String(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]), StandardCharsets.UTF_8));
    }

    private static Map<String, String> query(String location) {
        Map<String, String> params = new LinkedHashMap<>();
        for (String pair : location.substring(location.indexOf('?') + 1).split("&")) {
            String[] parts = pair.split("=", 2);
            params.put(parts[0], URLDecoder.decode(parts[1], StandardCharsets.UTF_8));
        }
        return params;
    }

    private static String challenge() throws Exception {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256")
                .digest(VERIFIER.getBytes(StandardCharsets.US_ASCII)));
    }

    private String code(String url, String client, String... extra) throws Exception {
        StringBuilder authorize = new StringBuilder(url + "/authorize?response_type=code&client_id=" + client
                + "&redirect_uri=" + URLEncoder.encode(REDIRECT, StandardCharsets.UTF_8) + "&scope=openid%20profile&state=s1");
        for (String item : extra) authorize.append('&').append(item);
        HttpResponse<String> response = get(authorize.toString());
        assertEquals(302, response.statusCode(), response.body());
        Map<String, String> answer = query(response.headers().firstValue("Location").orElseThrow());
        assertEquals("s1", answer.get("state"));
        return answer.get("code");
    }

    @Test
    void clientCredentialsGiveASignedJwtTheJwksVerifies() throws Exception {
        String url = start(Map.of("audience", "orders"));
        HttpResponse<String> token = post(http, url + "/token", "demo-client:demo-secret", "grant_type", "client_credentials");
        assertEquals(200, token.statusCode(), token.body());
        String access = (String) json(token).get("access_token");
        Map<?, ?> claims = payload(access);
        assertEquals(url, claims.get("iss"));
        assertEquals("orders", claims.get("aud"));
        assertEquals("demo-client", claims.get("client_id"));
        assertNull(json(token).get("refresh_token"), "A client alone gets no refresh token");

        Map<?, ?> jwks = json(get(url + "/jwks"));
        Map<?, ?> rsa = (Map<?, ?>) ((List<?>) jwks.get("keys")).get(0);
        Base64.Decoder decoder = Base64.getUrlDecoder();
        PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(
                new BigInteger(1, decoder.decode((String) rsa.get("n"))), new BigInteger(1, decoder.decode((String) rsa.get("e")))));
        assertNotNull(IdpKeys.verify(access, key, null));
    }

    @Test
    void eachSigningAlgorithmSigns() throws Exception {
        for (String alg : List.of("PS256", "ES256", "HS256")) {
            String url = start(Map.of("signingAlg", alg));
            String access = (String) json(post(http, url + "/token", "demo-client:demo-secret",
                    "grant_type", "client_credentials")).get("access_token");
            String header = new String(Base64.getUrlDecoder().decode(access.split("\\.")[0]), StandardCharsets.UTF_8);
            assertEquals(alg, ((Map<?, ?>) Json.parse(header)).get("alg"));
        }
    }

    @Test
    void opaqueTokensAreNotJwts() throws Exception {
        String url = start(Map.of("tokenFormat", "opaque"));
        String access = (String) json(post(http, url + "/token", "demo-client:demo-secret",
                "grant_type", "client_credentials")).get("access_token");
        assertFalse(access.contains("."));
        assertEquals(true, json(post(http, url + "/introspect", "demo-client:demo-secret", "token", access)).get("active"));
    }

    @Test
    void codeFlowWithPkceGivesUserTokens() throws Exception {
        String url = start(Map.of("pkce", "required"));
        HttpResponse<String> refused = get(url + "/authorize?response_type=code&client_id=demo-client&state=s&redirect_uri="
                + URLEncoder.encode(REDIRECT, StandardCharsets.UTF_8));
        assertEquals("invalid_request", query(refused.headers().firstValue("Location").orElseThrow()).get("error"));

        String code = code(url, "demo-client", "code_challenge=" + challenge(), "code_challenge_method=S256", "nonce=n1");
        assertEquals("invalid_grant", json(post(http, url + "/token", "demo-client:demo-secret",
                "grant_type", "authorization_code", "code", code, "redirect_uri", REDIRECT, "code_verifier", "wrong")).get("error"));

        code = code(url, "demo-client", "code_challenge=" + challenge(), "code_challenge_method=S256", "nonce=n1");
        HttpResponse<String> token = post(http, url + "/token", "demo-client:demo-secret", "grant_type", "authorization_code",
                "code", code, "redirect_uri", REDIRECT, "code_verifier", VERIFIER);
        assertEquals(200, token.statusCode(), token.body());
        Map<?, ?> idToken = payload((String) json(token).get("id_token"));
        assertEquals("user-1001", idToken.get("sub"));
        assertEquals("n1", idToken.get("nonce"));

        assertEquals("invalid_grant", json(post(http, url + "/token", "demo-client:demo-secret", "grant_type",
                "authorization_code", "code", code, "redirect_uri", REDIRECT, "code_verifier", VERIFIER)).get("error"),
                "A code works once");

        HttpResponse<String> userinfo = http.send(HttpRequest.newBuilder(URI.create(url + "/userinfo"))
                .header("Authorization", "Bearer " + json(token).get("access_token")).build(), HttpResponse.BodyHandlers.ofString());
        assertEquals("Alice Martin", json(userinfo).get("name"));
    }

    @Test
    void refreshRotatesAndRevokingEndsTheGrant() throws Exception {
        String url = start(Map.of());
        Map<?, ?> first = json(post(http, url + "/token", "demo-client:demo-secret", "grant_type", "password",
                "username", "bob", "password", "bob-password", "scope", "openid api.read"));
        String refresh = (String) first.get("refresh_token");
        Map<?, ?> second = json(post(http, url + "/token", "demo-client:demo-secret", "grant_type", "refresh_token",
                "refresh_token", refresh));
        assertNotEquals(refresh, second.get("refresh_token"));
        assertEquals("invalid_grant", json(post(http, url + "/token", "demo-client:demo-secret", "grant_type",
                "refresh_token", "refresh_token", refresh)).get("error"));

        post(http, url + "/revoke", "demo-client:demo-secret", "token", (String) second.get("refresh_token"));
        assertEquals(false, json(post(http, url + "/introspect", "demo-client:demo-secret",
                "token", (String) second.get("access_token"))).get("active"));
    }

    @Test
    void wrongCredentialsAndDisabledGrantsAreRefused() throws Exception {
        String url = start(Map.of("grants", List.of("client_credentials"), "authMethods", List.of("client_secret_basic")));
        HttpResponse<String> wrong = post(http, url + "/token", "demo-client:nope", "grant_type", "client_credentials");
        assertEquals(401, wrong.statusCode());
        assertTrue(wrong.headers().firstValue("WWW-Authenticate").isPresent());
        assertEquals("unsupported_grant_type", json(post(http, url + "/token", "demo-client:demo-secret",
                "grant_type", "password", "username", "bob", "password", "bob-password")).get("error"));
        assertEquals("invalid_client", json(post(http, url + "/token", null, "grant_type", "client_credentials",
                "client_id", "demo-client", "client_secret", "demo-secret")).get("error"), "Post is not how it authenticates");
    }

    @Test
    void metadataFollowsTheSettings() throws Exception {
        String url = start(Map.of("grants", List.of("authorization_code"), "pkce", "off", "openId", false));
        Map<?, ?> metadata = json(get(url + "/.well-known/oauth-authorization-server"));
        assertEquals(List.of("authorization_code"), metadata.get("grant_types_supported"));
        assertEquals(List.of("code"), metadata.get("response_types_supported"));
        assertNull(metadata.get("code_challenge_methods_supported"));
        assertEquals(404, get(url + "/.well-known/openid-configuration").statusCode());
    }

    @Test
    void parMayBeRequired() throws Exception {
        String url = start(Map.of("requirePar", true));
        assertEquals(400, get(url + "/authorize?response_type=code&client_id=demo-client").statusCode());
        HttpResponse<String> pushed = post(http, url + "/par", "demo-client:demo-secret", "response_type", "code",
                "redirect_uri", REDIRECT, "state", "s1", "scope", "openid");
        assertEquals(201, pushed.statusCode(), pushed.body());
        String requestUri = URLEncoder.encode((String) json(pushed).get("request_uri"), StandardCharsets.UTF_8);
        HttpResponse<String> answer = get(url + "/authorize?client_id=demo-client&request_uri=" + requestUri);
        assertEquals(302, answer.statusCode(), answer.body());
        assertEquals(400, get(url + "/authorize?client_id=demo-client&request_uri=" + requestUri).statusCode(),
                "A request_uri works once");
    }

    @Test
    void theLoginFormChecksThePassword() throws Exception {
        String url = start(Map.of("login", "form"));
        HttpResponse<String> form = get(url + "/authorize?response_type=code&client_id=demo-client&scope=openid&redirect_uri="
                + URLEncoder.encode(REDIRECT, StandardCharsets.UTF_8));
        assertEquals(200, form.statusCode());
        String id = form.body().replaceAll("(?s).*name=\"login_request\" value=\"([^\"]+)\".*", "$1");
        assertEquals(401, post(http, url + "/login", null, "login_request", id, "username", "bob", "password", "no").statusCode());
        HttpResponse<String> done = post(http, url + "/login", null, "login_request", id, "username", "bob",
                "password", "bob-password");
        assertEquals(302, done.statusCode());
        assertNotNull(query(done.headers().firstValue("Location").orElseThrow()).get("code"));
    }

    @Test
    void deviceFlowWaitsForTheUser() throws Exception {
        String url = start(Map.of());
        Map<?, ?> device = json(post(http, url + "/device_authorization", "demo-client:demo-secret", "scope", "openid"));
        String deviceCode = (String) device.get("device_code");
        String[] poll = {"grant_type", "urn:ietf:params:oauth:grant-type:device_code", "device_code", deviceCode};
        assertEquals("authorization_pending", json(post(http, url + "/token", "demo-client:demo-secret", poll)).get("error"));
        post(http, url + "/device", null, "user_code", (String) device.get("user_code"), "username", "alice",
                "password", "alice-password", "action", "allow");
        assertNotNull(json(post(http, url + "/token", "demo-client:demo-secret", poll)).get("access_token"));
    }

    @Test
    void tokenExchangeKeepsTheSubject() throws Exception {
        String url = start(Map.of());
        String access = (String) json(post(http, url + "/token", "demo-client:demo-secret", "grant_type", "password",
                "username", "bob", "password", "bob-password", "scope", "api.read")).get("access_token");
        Map<?, ?> exchanged = json(post(http, url + "/token", "demo-client:demo-secret",
                "grant_type", "urn:ietf:params:oauth:grant-type:token-exchange", "subject_token", access, "audience", "billing"));
        assertEquals("billing", payload((String) exchanged.get("access_token")).get("aud"));
        assertEquals("user-1002", payload((String) exchanged.get("access_token")).get("sub"));
    }

    @Test
    void faultsAndDelaysAreInjected() throws Exception {
        String url = start(Map.of("faultEndpoint", "/token", "faultStatus", 503.0, "delayMs", 20.0));
        HttpResponse<String> token = post(http, url + "/token", "demo-client:demo-secret", "grant_type", "client_credentials");
        assertEquals(503, token.statusCode());
        assertEquals("temporarily_unavailable", json(token).get("error"));
        assertEquals(200, get(url + "/jwks").statusCode());
        List<?> log = (List<?>) idp.status().get("log");
        assertEquals(2, log.size());
        assertFalse(Json.write(log).contains("demo-secret"), "The log keeps no credential");
    }

    @Test
    void invalidSettingsAreRefused() throws Exception {
        idp = new MockIdp(dir);
        assertThrows(IllegalArgumentException.class, () -> idp.save(Map.of("transport", "ftp")));
        assertThrows(IllegalArgumentException.class, () -> idp.save(Map.of("signingAlg", "HS256", "hmacSecret", "short")));
        assertThrows(IllegalArgumentException.class, () -> idp.save(Map.of("clients", List.of(Map.of("id", "a",
                "authMethod", "tls_client_auth")))));
    }

    @Test
    void settingsAreKeptAndTheServerRestartsWithThem() throws Exception {
        String url = start(Map.of("tokenType", "DPoPish"));
        assertEquals("DPoPish", json(post(http, url + "/token", "demo-client:demo-secret",
                "grant_type", "client_credentials")).get("token_type"));
        idp.close();
        MockIdp again = new MockIdp(dir);
        assertEquals(true, ((IdpConfig) again.status().get("config")).autoStart());
        again.startIfAsked();
        try {
            assertEquals(true, again.status().get("running"));
            String restarted = (String) again.status().get("url");
            again.save(Map.of("port", 0.0, "tokenFormat", "opaque", "transport", "tls"));
            assertNotEquals(restarted, again.status().get("url"));
        } finally {
            again.close();
        }
    }

    @Test
    void mutualTlsIsRequiredAndAuthenticatesTheClient() throws Exception {
        String url = start(Map.of("transport", "mtls-required", "boundTokens", true));
        assertTrue(url.startsWith("https://"));

        HttpClient noCertificate = client(false);
        assertThrows(IOException.class, () -> post(noCertificate, url + "/token", "demo-client:demo-secret",
                "grant_type", "client_credentials"));

        HttpClient withCertificate = client(true);
        HttpResponse<String> token = post(withCertificate, url + "/token", null, "grant_type", "client_credentials",
                "client_id", "mtls-client");
        assertEquals(200, token.statusCode(), token.body());
        String access = (String) json(token).get("access_token");
        Map<?, ?> confirmation = (Map<?, ?>) payload(access).get("cnf");
        assertEquals(thumbprint(), confirmation.get("x5t#S256"));

        Map<?, ?> user = json(post(withCertificate, url + "/token", "demo-client:demo-secret", "grant_type", "password",
                "username", "bob", "password", "bob-password", "scope", "openid"));
        HttpResponse<String> userinfo = withCertificate.send(HttpRequest.newBuilder(URI.create(url + "/userinfo"))
                .header("Authorization", "Bearer " + user.get("access_token")).build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, userinfo.statusCode(), userinfo.body());
    }

    @Test
    void optionalMutualTlsBindsOnlyWhatComesWithACertificate() throws Exception {
        String url = start(Map.of("transport", "mtls-optional", "boundTokens", true));
        HttpResponse<String> plain = post(client(false), url + "/token", "demo-client:demo-secret",
                "grant_type", "password", "username", "bob", "password", "bob-password", "scope", "openid");
        assertEquals(200, plain.statusCode(), plain.body());
        assertNull(payload((String) json(plain).get("access_token")).get("cnf"));

        HttpResponse<String> bound = post(client(true), url + "/token", "demo-client:demo-secret",
                "grant_type", "password", "username", "bob", "password", "bob-password", "scope", "openid");
        String access = (String) json(bound).get("access_token");
        assertNotNull(payload(access).get("cnf"));
        HttpResponse<String> without = client(false).send(HttpRequest.newBuilder(URI.create(url + "/userinfo"))
                .header("Authorization", "Bearer " + access).build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(401, without.statusCode(), "A bound token is useless without its certificate");
    }

    private String thumbprint() throws Exception {
        try (InputStream in = Files.newInputStream(certificates().resolve("client.pem"))) {
            byte[] der = CertificateFactory.getInstance("X.509").generateCertificate(in).getEncoded();
            return Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(der));
        }
    }

    private Path certificates() {
        return dir.resolve("certificates");
    }

    private HttpClient client(boolean certificate) throws IOException, GeneralSecurityException {
        KeyStore trusted = KeyStore.getInstance(KeyStore.getDefaultType());
        trusted.load(null, null);
        try (InputStream in = Files.newInputStream(certificates().resolve("ca.pem"))) {
            trusted.setCertificateEntry("ca", CertificateFactory.getInstance("X.509").generateCertificate(in));
        }
        TrustManagerFactory trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trust.init(trusted);
        KeyManagerFactory keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        KeyStore own = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(certificates().resolve("client.p12"))) {
            own.load(in, "mock-idp".toCharArray());
        }
        keys.init(own, "mock-idp".toCharArray());
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(certificate ? keys.getKeyManagers() : null, trust.getTrustManagers(), null);
        return HttpClient.newBuilder().sslContext(context).followRedirects(HttpClient.Redirect.NEVER).build();
    }
}
