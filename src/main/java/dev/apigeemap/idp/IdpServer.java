package dev.apigeemap.idp;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsExchange;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import dev.apigeemap.idp.IdpConfig.Client;
import dev.apigeemap.idp.IdpConfig.User;
import dev.apigeemap.protocol.Json;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.stream.Collectors;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.security.auth.x500.X500Principal;

/**
 * The HTTP side of the mock identity provider: OAuth 2.0 and OpenID Connect endpoints behaving as {@link IdpConfig}
 * says. It listens on the loopback interface only, and everything it issues lives in {@link IdpState}.
 */
final class IdpServer {

    private static final String TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
    private static final String JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    private static final String DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code";
    private static final String CLIENT_ASSERTION = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    private static final Map<String, String> GRANT_NAMES = Map.of(TOKEN_EXCHANGE, "token_exchange",
            JWT_BEARER, "jwt_bearer", DEVICE_CODE, "device_code");
    private static final int DEVICE_TTL = 600;
    private static final int DEVICE_INTERVAL = 5;
    private static final SecureRandom RANDOM = new SecureRandom();

    /** An OAuth error answered as JSON. */
    private static final class OAuthError extends RuntimeException {
        final int status;
        final String code;

        OAuthError(int status, String code, String description) {
            super(description);
            this.status = status;
            this.code = code;
        }
    }

    /** One request being answered. */
    private static final class Call {
        final HttpExchange exchange;
        final Map<String, String> params;
        final X509Certificate certificate;
        String client = "";
        String grant = "";
        String error = "";
        int status = 200;

        Call(HttpExchange exchange, Map<String, String> params, X509Certificate certificate) {
            this.exchange = exchange;
            this.params = params;
            this.certificate = certificate;
        }

        String param(String name) {
            String value = params.get(name);
            return value == null || value.isEmpty() ? null : value;
        }
    }

    private final IdpConfig config;
    private final IdpState state;
    private final HttpServer server;
    private final ExecutorService executor = Executors.newFixedThreadPool(8);
    private final String scheme;
    private final String issuer;

    private IdpServer(IdpConfig config, IdpState state, HttpServer server, String scheme) {
        this.config = config;
        this.state = state;
        this.server = server;
        this.scheme = scheme;
        String own = scheme + "://localhost:" + server.getAddress().getPort();
        this.issuer = config.issuer().isBlank() ? own : config.issuer().replaceAll("/+$", "");
    }

    static IdpServer start(IdpConfig config, IdpState state, IdpPki pki) throws IOException, GeneralSecurityException {
        InetSocketAddress address = new InetSocketAddress(InetAddress.getLoopbackAddress(), config.port());
        boolean tls = !config.transport().equals("http");
        HttpServer http;
        if (tls) {
            HttpsServer https = HttpsServer.create(address, 0);
            https.setHttpsConfigurator(configurator(pki.serverContext(), config.transport()));
            http = https;
        } else {
            http = HttpServer.create(address, 0);
        }
        IdpServer idp = new IdpServer(config, state, http, tls ? "https" : "http");
        http.createContext("/", idp::handle);
        http.setExecutor(idp.executor);
        http.start();
        return idp;
    }

    private static HttpsConfigurator configurator(SSLContext context, String transport) {
        return new HttpsConfigurator(context) {
            @Override
            public void configure(HttpsParameters params) {
                SSLParameters ssl = getSSLContext().getDefaultSSLParameters();
                if (transport.equals("mtls-required")) ssl.setNeedClientAuth(true);
                else if (transport.equals("mtls-optional")) ssl.setWantClientAuth(true);
                params.setSSLParameters(ssl);
            }
        };
    }

    void stop() {
        server.stop(0);
        executor.shutdownNow();
    }

    int port() {
        return server.getAddress().getPort();
    }

    String url() {
        return scheme + "://localhost:" + port();
    }

    String issuer() {
        return issuer;
    }

    private void handle(HttpExchange exchange) throws IOException {
        long started = System.nanoTime();
        try (exchange) {
            Call call = new Call(exchange, params(exchange), certificate(exchange));
            String path = exchange.getRequestURI().getPath();
            try {
                if (config.delayMs() > 0) Thread.sleep(config.delayMs());
                if (config.faultEndpoint().equals("all") || config.faultEndpoint().equals(path)) {
                    throw new OAuthError(config.faultStatus(), config.faultError(), "Fault set in the mock IdP");
                }
                route(call, path);
            } catch (OAuthError e) {
                Map<String, Object> body = new LinkedHashMap<>();
                body.put("error", e.code);
                body.put("error_description", e.getMessage());
                if (e.code.equals("invalid_client") && exchange.getRequestHeaders().containsKey("Authorization")) {
                    exchange.getResponseHeaders().set("WWW-Authenticate", "Basic realm=\"mock-idp\"");
                }
                call.error = e.code;
                json(call, e.status, body);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (RuntimeException e) {
                call.error = "server_error";
                json(call, 500, Map.of("error", "server_error", "error_description", String.valueOf(e.getMessage())));
            }
            state.log(new IdpState.Entry(System.currentTimeMillis(), exchange.getRequestMethod(), path, call.status,
                    (System.nanoTime() - started) / 1_000_000, call.client, call.grant,
                    call.certificate == null ? "" : call.certificate.getSubjectX500Principal().getName(), call.error));
        }
    }

    private void route(Call call, String path) throws IOException {
        String method = call.exchange.getRequestMethod();
        boolean get = method.equals("GET");
        boolean post = method.equals("POST");
        switch (path) {
            case "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server" -> {
                if (path.endsWith("openid-configuration") && !config.openId()) notFound();
                json(call, 200, metadata());
            }
            case "/jwks" -> json(call, 200, state.keys().jwks());
            case "/authorize" -> {
                if (get || post) authorize(call);
                else notAllowed();
            }
            case "/login" -> {
                if (post) login(call);
                else notAllowed();
            }
            case "/par" -> {
                if (post) pushedRequest(call);
                else notAllowed();
            }
            case "/token" -> {
                if (post) token(call);
                else notAllowed();
            }
            case "/introspect" -> {
                if (post) introspect(call);
                else notAllowed();
            }
            case "/revoke" -> {
                if (post) revoke(call);
                else notAllowed();
            }
            case "/userinfo" -> {
                if (!config.openId()) notFound();
                if (get || post) userinfo(call);
                else notAllowed();
            }
            case "/device_authorization" -> {
                if (post) deviceAuthorization(call);
                else notAllowed();
            }
            case "/device" -> {
                if (get) deviceForm(call, call.param("user_code"), null);
                else if (post) deviceApprove(call);
                else notAllowed();
            }
            case "/logout" -> logout(call);
            default -> notFound();
        }
    }

    private static void notFound() {
        throw new OAuthError(404, "not_found", "Unknown endpoint");
    }

    private static void notAllowed() {
        throw new OAuthError(405, "invalid_request", "Method not allowed");
    }

    // ------------------------------------------------------------------------------------------------- metadata

    private Map<String, Object> metadata() {
        boolean grantDevice = enabled("device_code");
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("issuer", issuer);
        m.put("authorization_endpoint", issuer + "/authorize");
        m.put("token_endpoint", issuer + "/token");
        m.put("jwks_uri", issuer + "/jwks");
        m.put("introspection_endpoint", issuer + "/introspect");
        m.put("revocation_endpoint", issuer + "/revoke");
        m.put("pushed_authorization_request_endpoint", issuer + "/par");
        m.put("require_pushed_authorization_requests", config.requirePar());
        if (grantDevice) m.put("device_authorization_endpoint", issuer + "/device_authorization");
        m.put("scopes_supported", config.scopes());
        m.put("grant_types_supported", config.grants().stream().map(IdpServer::grantUri).filter(g -> g != null).toList());
        m.put("response_types_supported", responseTypes());
        m.put("response_modes_supported", config.responseModes());
        m.put("token_endpoint_auth_methods_supported", config.authMethods());
        m.put("token_endpoint_auth_signing_alg_values_supported", List.of("HS256", "RS256", "PS256", "ES256"));
        if (!config.pkce().equals("off")) m.put("code_challenge_methods_supported", config.pkceMethods());
        m.put("tls_client_certificate_bound_access_tokens", config.boundTokens());
        if (config.openId()) {
            m.put("userinfo_endpoint", issuer + "/userinfo");
            m.put("end_session_endpoint", issuer + "/logout");
            m.put("subject_types_supported", List.of("public"));
            m.put("id_token_signing_alg_values_supported", List.of(config.signingAlg()));
            m.put("claims_supported", List.of("sub", "name", "email", "iss", "aud", "exp", "iat", "nonce"));
        }
        return m;
    }

    private List<String> responseTypes() {
        List<String> types = new ArrayList<>();
        if (enabled("authorization_code")) types.add("code");
        if (enabled("implicit")) {
            types.add("token");
            if (config.openId()) types.addAll(List.of("id_token", "id_token token"));
        }
        if (enabled("authorization_code") && enabled("implicit") && config.openId()) types.add("code id_token");
        return types;
    }

    private static String grantUri(String grant) {
        return switch (grant) {
            case "implicit" -> null;
            case "device_code" -> DEVICE_CODE;
            case "token_exchange" -> TOKEN_EXCHANGE;
            case "jwt_bearer" -> JWT_BEARER;
            default -> grant;
        };
    }

    private boolean enabled(String grant) {
        return config.grants().contains(grant);
    }

    // ------------------------------------------------------------------------------------------------ authorize

    private void pushedRequest(Call call) throws IOException {
        Client client = authenticate(call);
        call.client = client.id();
        Map<String, String> pushed = new LinkedHashMap<>(call.params);
        List.of("client_secret", "client_assertion", "client_assertion_type").forEach(pushed::remove);
        pushed.put("client_id", client.id());
        checkAuthorize(pushed);
        String uri = "urn:ietf:params:oauth:request_uri:" + random();
        state.pushed.put(uri, new IdpState.Pending(pushed, now() + 90));
        json(call, 201, Map.of("request_uri", uri, "expires_in", 90));
    }

    private void authorize(Call call) throws IOException {
        Map<String, String> request = new LinkedHashMap<>(call.params);
        String requestUri = call.param("request_uri");
        if (requestUri != null) {
            IdpState.Pending pushed = state.pushed.remove(requestUri);
            if (pushed == null || pushed.expires() < now()) {
                throw new OAuthError(400, "invalid_request_uri", "Unknown or expired request_uri");
            }
            request = new LinkedHashMap<>(pushed.request());
        } else if (config.requirePar()) {
            throw new OAuthError(400, "invalid_request", "Pushed authorization requests are required");
        }
        call.client = String.valueOf(request.get("client_id"));
        call.grant = String.valueOf(request.get("response_type"));
        Client client = redirectable(request);
        request.putIfAbsent("redirect_uri", client.redirectUris().get(0));
        try {
            checkAuthorize(request);
        } catch (OAuthError e) {
            redirectError(call, request, e);
            return;
        }
        String hint = request.get("login_hint");
        User hinted = hint == null ? null : config.user(hint);
        if (config.login().equals("auto") && !config.consent()) {
            User user = hinted != null ? hinted : config.users().stream().findFirst().orElse(null);
            if (user == null) {
                redirectError(call, request, new OAuthError(400, "login_required", "No user is configured"));
                return;
            }
            complete(call, request, client, user);
            return;
        }
        if ("none".equals(request.get("prompt"))) {
            redirectError(call, request, new OAuthError(400, "login_required", "The user has to log in"));
            return;
        }
        String id = random();
        state.logins.put(id, new IdpState.Pending(request, now() + 600));
        loginForm(call, id, client, request.get("scope"), hint, null);
    }

    /** The client of an authorize request and that its redirect_uri is registered: errors here are not redirected. */
    private Client redirectable(Map<String, String> request) {
        String id = request.get("client_id");
        Client client = id == null ? null : config.client(id);
        if (client == null) throw new OAuthError(400, "invalid_client", "Unknown client");
        String redirectUri = request.get("redirect_uri");
        if (redirectUri == null ? client.redirectUris().size() != 1 : !client.redirectUris().contains(redirectUri)) {
            throw new OAuthError(400, "invalid_request", "The redirect_uri is not registered for this client");
        }
        return client;
    }

    private void checkAuthorize(Map<String, String> request) {
        Client client = redirectable(request);
        String type = String.valueOf(request.get("response_type"));
        Set<String> parts = new LinkedHashSet<>(Arrays.asList(type.split(" ")));
        boolean code = parts.contains("code");
        boolean implicit = parts.contains("token") || parts.contains("id_token");
        if (!responseTypes().contains(String.join(" ", parts))) {
            throw new OAuthError(400, "unsupported_response_type", "Unsupported response_type " + type);
        }
        if (code && !allowed(client, "authorization_code") || implicit && !allowed(client, "implicit")) {
            throw new OAuthError(400, "unauthorized_client", "This client may not use response_type " + type);
        }
        String mode = request.get("response_mode");
        if (mode != null && !config.responseModes().contains(mode)) {
            throw new OAuthError(400, "invalid_request", "Unsupported response_mode " + mode);
        }
        if (implicit && "query".equals(mode)) {
            throw new OAuthError(400, "invalid_request", "Tokens cannot be returned in the query");
        }
        String scope = scope(request.get("scope"), client, null);
        if (scopes(scope).contains("openid") && parts.contains("id_token") && request.get("nonce") == null) {
            throw new OAuthError(400, "invalid_request", "A nonce is required with an id_token");
        }
        if (parts.contains("id_token") && !scopes(scope).contains("openid")) {
            throw new OAuthError(400, "invalid_scope", "An id_token needs the openid scope");
        }
        if (!code) return;
        String challenge = request.get("code_challenge");
        if (config.pkce().equals("required") && challenge == null) {
            throw new OAuthError(400, "invalid_request", "code_challenge is required");
        }
        if (client.authMethod().equals("none") && challenge == null && !config.pkce().equals("off")) {
            throw new OAuthError(400, "invalid_request", "A public client needs a code_challenge");
        }
        if (challenge != null && !config.pkce().equals("off")) {
            String method = request.getOrDefault("code_challenge_method", "plain");
            if (!config.pkceMethods().contains(method)) {
                throw new OAuthError(400, "invalid_request", "Unsupported code_challenge_method " + method);
            }
        }
    }

    private void login(Call call) throws IOException {
        String id = String.valueOf(call.params.get("login_request"));
        IdpState.Pending pending = state.logins.get(id);
        if (pending == null || pending.expires() < now()) {
            throw new OAuthError(400, "invalid_request", "The login has expired, start again");
        }
        Map<String, String> request = pending.request();
        Client client = redirectable(request);
        call.client = client.id();
        call.grant = String.valueOf(request.get("response_type"));
        if ("deny".equals(call.param("action"))) {
            state.logins.remove(id);
            redirectError(call, request, new OAuthError(400, "access_denied", "The user refused"));
            return;
        }
        User user;
        if (config.login().equals("auto")) {
            user = config.users().stream().findFirst().orElse(null);
        } else {
            user = config.user(String.valueOf(call.params.get("username")));
            if (user == null || !user.password().equals(call.params.get("password"))) {
                call.error = "login_failed";
                call.status = 401;
                loginForm(call, id, client, request.get("scope"), call.param("username"), "Wrong user name or password");
                return;
            }
        }
        state.logins.remove(id);
        complete(call, request, client, user);
    }

    private void complete(Call call, Map<String, String> request, Client client, User user) throws IOException {
        Set<String> parts = Set.of(request.get("response_type").split(" "));
        String scope = scope(request.get("scope"), client, null);
        Map<String, String> answer = new LinkedHashMap<>();
        String nonce = request.get("nonce");
        String code = null;
        if (parts.contains("code")) {
            code = random();
            state.codes.put(code, new IdpState.Code(client.id(), request.get("redirect_uri"), scope, user.username(), nonce,
                    config.pkce().equals("off") ? null : request.get("code_challenge"),
                    request.getOrDefault("code_challenge_method", "plain"), now() + config.codeTtl()));
            answer.put("code", code);
        }
        if (parts.contains("token")) {
            IdpState.Token access = accessToken(client, user, scope, audience(null, client), call.certificate, random());
            answer.put("access_token", access.value());
            answer.put("token_type", config.tokenType());
            answer.put("expires_in", String.valueOf(config.accessTokenTtl()));
            answer.put("scope", scope);
        }
        if (parts.contains("id_token")) {
            answer.put("id_token", idToken(client, user, nonce, code, answer.get("access_token")));
        }
        if (request.get("state") != null) answer.put("state", request.get("state"));
        answer.put("iss", issuer);
        redirect(call, request, answer, parts.size() > 1 || !parts.contains("code"));
    }

    private void redirectError(Call call, Map<String, String> request, OAuthError error) throws IOException {
        call.error = error.code;
        Map<String, String> answer = new LinkedHashMap<>();
        answer.put("error", error.code);
        answer.put("error_description", error.getMessage());
        if (request.get("state") != null) answer.put("state", request.get("state"));
        answer.put("iss", issuer);
        String type = String.valueOf(request.get("response_type"));
        redirect(call, request, answer, !type.equals("code") && type.contains("token"));
    }

    private void redirect(Call call, Map<String, String> request, Map<String, String> answer, boolean tokens)
            throws IOException {
        String redirectUri = request.get("redirect_uri");
        String mode = request.getOrDefault("response_mode", tokens ? "fragment" : "query");
        if (mode.equals("form_post")) {
            StringBuilder fields = new StringBuilder();
            answer.forEach((name, value) -> fields.append("<input type=\"hidden\" name=\"").append(html(name))
                    .append("\" value=\"").append(html(value)).append("\">"));
            html(call, 200, "<!doctype html><title>Redirecting</title><body onload=\"document.forms[0].submit()\">"
                    + "<form method=\"post\" action=\"" + html(redirectUri) + "\">" + fields
                    + "<noscript><button>Continue</button></noscript></form></body>");
            return;
        }
        String query = form(answer);
        String separator = mode.equals("fragment") ? "#" : redirectUri.contains("?") ? "&" : "?";
        call.exchange.getResponseHeaders().set("Location", redirectUri + separator + query);
        send(call, 302, "text/plain", new byte[0]);
    }

    private void loginForm(Call call, String id, Client client, String scope, String username, String error)
            throws IOException {
        StringBuilder page = new StringBuilder(PAGE_START).append("<h1>Mock IdP</h1><p><b>").append(html(client.id()))
                .append("</b> asks for access");
        if (scope != null) page.append(" to <code>").append(html(scope)).append("</code>");
        page.append("</p>");
        if (error != null) page.append("<p class=\"bad\">").append(html(error)).append("</p>");
        page.append("<form method=\"post\" action=\"/login\"><input type=\"hidden\" name=\"login_request\" value=\"")
                .append(html(id)).append("\">");
        if (config.login().equals("form")) {
            page.append("<label>User name<input name=\"username\" autofocus autocomplete=\"username\" value=\"")
                    .append(html(username == null ? "" : username)).append("\"></label>")
                    .append("<label>Password<input name=\"password\" type=\"password\"></label>");
        }
        page.append("<button name=\"action\" value=\"allow\">")
                .append(config.login().equals("form") ? "Log in" : "Allow").append("</button>");
        if (config.consent()) page.append(" <button name=\"action\" value=\"deny\">Deny</button>");
        html(call, call.status, page.append("</form></main></body>").toString());
    }

    private static final String PAGE_START = "<!doctype html><meta charset=\"utf-8\"><title>Mock IdP</title>"
            + "<style>body{font:15px system-ui;background:#f6f7f9;color:#1c1d21}main{max-width:360px;margin:64px auto;"
            + "padding:24px;background:#fff;border:1px solid #e3e4e8;border-radius:8px}h1{font-size:20px;margin-top:0}"
            + "label{display:block;margin:12px 0}input:not([type=hidden]){display:block;width:100%;box-sizing:border-box;"
            + "padding:6px;margin-top:4px}button{padding:6px 14px;margin-top:8px}.bad{color:#d1242f}</style><body><main>";

    // ---------------------------------------------------------------------------------------------------- token

    private void token(Call call) throws IOException {
        String grantType = call.param("grant_type");
        if (grantType == null) throw new OAuthError(400, "invalid_request", "grant_type is required");
        String grant = GRANT_NAMES.getOrDefault(grantType, grantType);
        call.grant = grant;
        Client client = authenticate(call);
        call.client = client.id();
        if (!IdpConfig.GRANTS.contains(grant) || grant.equals("implicit") || !enabled(grant)) {
            throw new OAuthError(400, "unsupported_grant_type", "Grant " + grantType + " is not enabled");
        }
        if (!allowed(client, grant)) throw new OAuthError(400, "unauthorized_client", "Grant not allowed for this client");
        switch (grant) {
            case "authorization_code" -> codeGrant(call, client);
            case "client_credentials" -> {
                if (client.authMethod().equals("none")) {
                    throw new OAuthError(400, "unauthorized_client", "A public client has no credentials");
                }
                String scope = scope(call.param("scope"), client, "openid");
                tokens(call, client, null, scope, null, null, false);
            }
            case "password" -> {
                User user = config.user(String.valueOf(call.params.get("username")));
                if (user == null || !user.password().equals(call.params.get("password"))) {
                    throw new OAuthError(400, "invalid_grant", "Wrong user name or password");
                }
                tokens(call, client, user, scope(call.param("scope"), client, null), null, null, true);
            }
            case "refresh_token" -> refreshGrant(call, client);
            case "device_code" -> deviceGrant(call, client);
            case "token_exchange" -> exchangeGrant(call, client);
            default -> jwtBearerGrant(call, client);
        }
    }

    private void codeGrant(Call call, Client client) throws IOException {
        String value = String.valueOf(call.params.get("code"));
        IdpState.Code code = state.codes.remove(value);
        if (code == null || code.expires() < now() || !code.client().equals(client.id())) {
            throw new OAuthError(400, "invalid_grant", "Unknown, used or expired code");
        }
        String redirectUri = call.param("redirect_uri");
        if (redirectUri != null ? !redirectUri.equals(code.redirectUri()) : client.redirectUris().size() != 1) {
            throw new OAuthError(400, "invalid_grant", "The redirect_uri differs from the authorization request");
        }
        if (code.challenge() != null) {
            String verifier = call.param("code_verifier");
            if (verifier == null) throw new OAuthError(400, "invalid_grant", "code_verifier is required");
            String computed = code.method().equals("S256") ? IdpKeys.base64(sha256(verifier.getBytes(
                    StandardCharsets.US_ASCII))) : verifier;
            if (!computed.equals(code.challenge())) {
                throw new OAuthError(400, "invalid_grant", "The code_verifier does not match");
            }
        }
        tokens(call, client, config.user(code.user()), code.scope(), code.nonce(), null, true);
    }

    private void refreshGrant(Call call, Client client) throws IOException {
        String value = String.valueOf(call.params.get("refresh_token"));
        IdpState.Token refresh = state.tokens.get(value);
        if (refresh == null || !refresh.refresh() || refresh.expires() < now() || !refresh.client().equals(client.id())) {
            throw new OAuthError(400, "invalid_grant", "Unknown, revoked or expired refresh token");
        }
        String scope = refresh.scope();
        String asked = call.param("scope");
        if (asked != null) {
            if (!scopes(scope).containsAll(scopes(asked))) {
                throw new OAuthError(400, "invalid_scope", "A refresh cannot widen the scope");
            }
            scope = asked;
        }
        if (config.refreshRotation()) state.tokens.remove(value);
        tokens(call, client, refresh.user() == null ? null : config.user(refresh.user()), scope, null,
                config.refreshRotation() ? refresh.grantId() : null, true);
    }

    private void deviceGrant(Call call, Client client) throws IOException {
        String value = String.valueOf(call.params.get("device_code"));
        IdpState.Device device = state.devices.get(value);
        if (device == null || !device.client().equals(client.id())) {
            throw new OAuthError(400, "invalid_grant", "Unknown device code");
        }
        if (device.expires() < now()) {
            state.devices.remove(value);
            throw new OAuthError(400, "expired_token", "The device code has expired");
        }
        if (device.denied()) {
            state.devices.remove(value);
            throw new OAuthError(400, "access_denied", "The user refused");
        }
        if (device.user() == null) throw new OAuthError(400, "authorization_pending", "Waiting for the user");
        state.devices.remove(value);
        tokens(call, client, config.user(device.user()), device.scope(), null, null, true);
    }

    private void exchangeGrant(Call call, Client client) throws IOException {
        IdpState.Token subject = state.tokens.get(String.valueOf(call.params.get("subject_token")));
        if (subject == null || subject.refresh() || subject.expires() < now()) {
            throw new OAuthError(400, "invalid_grant", "The subject_token is not active");
        }
        String asked = call.param("scope");
        if (asked != null && !scopes(subject.scope()).containsAll(scopes(asked))) {
            throw new OAuthError(400, "invalid_scope", "An exchange cannot widen the scope");
        }
        String scope = asked == null ? subject.scope() : asked;
        User user = subject.user() == null ? null : config.user(subject.user());
        IdpState.Token access = accessToken(client, user, scope, audience(call.param("audience"), client),
                call.certificate, random());
        Map<String, Object> answer = new LinkedHashMap<>();
        answer.put("access_token", access.value());
        answer.put("issued_token_type", "urn:ietf:params:oauth:token-type:access_token");
        answer.put("token_type", config.tokenType());
        answer.put("expires_in", config.accessTokenTtl());
        answer.put("scope", scope);
        json(call, 200, answer);
    }

    private void jwtBearerGrant(Call call, Client client) throws IOException {
        Map<String, Object> claims = verifiedAssertion(String.valueOf(call.params.get("assertion")), client, "invalid_grant");
        User user = config.users().stream().filter(u -> u.sub().equals(claims.get("sub"))
                || u.username().equals(claims.get("sub"))).findFirst().orElse(null);
        if (user == null) throw new OAuthError(400, "invalid_grant", "The assertion names an unknown user");
        tokens(call, client, user, scope(call.param("scope"), client, null), null, null, false);
    }

    /** Answers the tokens of a grant; {@code grantId} carries on the family of a rotated refresh token. */
    private void tokens(Call call, Client client, User user, String scope, String nonce, String grantId, boolean refresh)
            throws IOException {
        String family = grantId != null ? grantId : random();
        IdpState.Token access = accessToken(client, user, scope, audience(call.param("audience"), client),
                call.certificate, family);
        Map<String, Object> answer = new LinkedHashMap<>();
        answer.put("access_token", access.value());
        answer.put("token_type", config.tokenType());
        answer.put("expires_in", config.accessTokenTtl());
        answer.put("scope", scope);
        if (refresh && enabled("refresh_token") && allowed(client, "refresh_token") && user != null) {
            String value = random();
            state.tokens.put(value, new IdpState.Token(value, true, client.id(), user.username(), scope,
                    now() + config.refreshTokenTtl(), family, access.thumbprint(), access.audience()));
            answer.put("refresh_token", value);
        }
        if (config.openId() && user != null && scopes(scope).contains("openid")) {
            answer.put("id_token", idToken(client, user, nonce, null, access.value()));
        }
        state.sweep(now());
        json(call, 200, answer);
    }

    private IdpState.Token accessToken(Client client, User user, String scope, String audience, X509Certificate certificate,
                                       String family) {
        String thumbprint = config.boundTokens() && certificate != null ? thumbprint(certificate) : null;
        long issued = now();
        long expires = issued + config.accessTokenTtl();
        String value;
        if (config.tokenFormat().equals("jwt")) {
            Map<String, Object> claims = new LinkedHashMap<>(config.extraClaims());
            claims.put("iss", issuer);
            claims.put("sub", user == null ? client.id() : user.sub());
            claims.put("aud", audience);
            claims.put("iat", issued);
            claims.put("nbf", issued);
            claims.put("exp", expires);
            claims.put("jti", random());
            claims.put("client_id", client.id());
            claims.put("scope", scope);
            if (thumbprint != null) claims.put("cnf", Map.of("x5t#S256", thumbprint));
            value = state.keys().sign(claims, config.signingAlg(), config.hmacSecret());
        } else {
            value = random();
        }
        IdpState.Token token = new IdpState.Token(value, false, client.id(), user == null ? null : user.username(), scope,
                expires, family, thumbprint, audience);
        state.tokens.put(value, token);
        return token;
    }

    private String idToken(Client client, User user, String nonce, String code, String accessToken) {
        long issued = now();
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", issuer);
        claims.put("sub", user.sub());
        claims.put("aud", client.id());
        claims.put("iat", issued);
        claims.put("exp", issued + config.idTokenTtl());
        claims.put("auth_time", issued);
        if (nonce != null) claims.put("nonce", nonce);
        if (code != null) claims.put("c_hash", halfHash(code));
        if (accessToken != null) claims.put("at_hash", halfHash(accessToken));
        claims.put("name", user.name());
        claims.put("email", user.email());
        return state.keys().sign(claims, config.signingAlg(), config.hmacSecret());
    }

    private static String halfHash(String value) {
        byte[] hash = sha256(value.getBytes(StandardCharsets.US_ASCII));
        return IdpKeys.base64(Arrays.copyOf(hash, hash.length / 2));
    }

    private String audience(String asked, Client client) {
        if (asked != null) return asked;
        return config.audience().isBlank() ? client.id() : config.audience();
    }

    // --------------------------------------------------------------------------------- client authentication

    /** The client of a request, authenticated the one way it is registered with. */
    private Client authenticate(Call call) {
        String basic = call.exchange.getRequestHeaders().getFirst("Authorization");
        String id = call.param("client_id");
        String secret = call.param("client_secret");
        String assertion = call.param("client_assertion");
        String method;
        if (basic != null && basic.regionMatches(true, 0, "Basic ", 0, 6)) {
            String[] pair = decodeBasic(basic.substring(6));
            id = pair[0];
            secret = pair[1];
            method = "client_secret_basic";
        } else if (assertion != null) {
            if (!CLIENT_ASSERTION.equals(call.param("client_assertion_type"))) {
                throw invalidClient("Unknown client_assertion_type");
            }
            id = String.valueOf(unverifiedClaims(assertion).get("iss"));
            method = "assertion";
        } else if (secret != null) {
            method = "client_secret_post";
        } else if (id != null && call.certificate != null) {
            method = "tls_client_auth";
        } else {
            method = "none";
        }
        Client client = id == null ? null : config.client(id);
        if (client == null) throw invalidClient("Unknown client");
        call.client = client.id();
        String registered = client.authMethod();
        if (!config.authMethods().contains(registered)) throw invalidClient(registered + " is not enabled");
        if (method.equals("assertion")) {
            if (!registered.endsWith("_jwt")) throw invalidClient("This client uses " + registered);
            verifiedAssertion(assertion, client, "invalid_client");
            return client;
        }
        if (!method.equals(registered)) {
            // a public client may still send its id along with a certificate
            if (!(method.equals("tls_client_auth") && registered.equals("none"))) {
                throw invalidClient("This client uses " + registered);
            }
            return client;
        }
        switch (method) {
            case "client_secret_basic", "client_secret_post" -> {
                if (!MessageDigest.isEqual(client.secret().getBytes(StandardCharsets.UTF_8),
                        String.valueOf(secret).getBytes(StandardCharsets.UTF_8))) {
                    throw invalidClient("Wrong client secret");
                }
            }
            case "tls_client_auth" -> {
                X500Principal registeredSubject = new X500Principal(client.tlsSubject());
                if (!registeredSubject.equals(call.certificate.getSubjectX500Principal())) {
                    throw invalidClient("The certificate is not the one of this client");
                }
            }
            default -> {
            }
        }
        return client;
    }

    private Map<String, Object> verifiedAssertion(String assertion, Client client, String error) {
        Map<String, Object> claims;
        try {
            PublicKey key = client.publicKey().isBlank() ? null : IdpKeys.publicKey(client.publicKey());
            String secret = client.secret().length() >= 32 ? client.secret() : null;
            claims = IdpKeys.verify(assertion, key, secret);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            claims = null;
        }
        if (claims == null) throw new OAuthError(error.equals("invalid_client") ? 401 : 400, error, "Bad assertion signature");
        boolean audience = claims.get("aud") instanceof List<?> list
                ? list.contains(issuer) || list.contains(issuer + "/token")
                : issuer.equals(claims.get("aud")) || (issuer + "/token").equals(claims.get("aud"));
        boolean live = claims.get("exp") instanceof Number exp && exp.longValue() > now();
        if (!audience || !live) {
            throw new OAuthError(error.equals("invalid_client") ? 401 : 400, error, "Expired assertion or wrong audience");
        }
        Object jti = claims.get("jti");
        if (jti != null && state.assertions.putIfAbsent(String.valueOf(jti), now() + 600) != null) {
            throw new OAuthError(error.equals("invalid_client") ? 401 : 400, error, "This assertion was already used");
        }
        return claims;
    }

    private static Map<?, ?> unverifiedClaims(String assertion) {
        String[] parts = assertion.split("\\.");
        try {
            if (parts.length == 3 && Json.parse(new String(Base64.getUrlDecoder().decode(parts[1]),
                    StandardCharsets.UTF_8)) instanceof Map<?, ?> claims) {
                return claims;
            }
        } catch (IllegalArgumentException e) {
            // answered below
        }
        throw invalidClient("Not a JWT");
    }

    private static String[] decodeBasic(String encoded) {
        try {
            String decoded = new String(Base64.getDecoder().decode(encoded.trim()), StandardCharsets.UTF_8);
            int colon = decoded.indexOf(':');
            if (colon < 0) throw invalidClient("Malformed Basic credentials");
            return new String[]{decode(decoded.substring(0, colon)), decode(decoded.substring(colon + 1))};
        } catch (IllegalArgumentException e) {
            throw invalidClient("Malformed Basic credentials");
        }
    }

    private static OAuthError invalidClient(String description) {
        return new OAuthError(401, "invalid_client", description);
    }

    private boolean allowed(Client client, String grant) {
        return enabled(grant) && (client.grants().isEmpty() || client.grants().contains(grant));
    }

    /** The scope of a request, each one known and allowed; nothing asked means all of them but {@code refused}. */
    private String scope(String asked, Client client, String refused) {
        Set<String> scopes = asked == null ? new LinkedHashSet<>(client.scopes().isEmpty() ? config.scopes() : client.scopes())
                : scopes(asked);
        if (refused != null && asked == null) scopes.remove(refused);
        if (!config.openId() && asked == null) scopes.remove("openid");
        for (String scope : scopes) {
            boolean known = config.scopes().contains(scope) && (client.scopes().isEmpty() || client.scopes().contains(scope));
            if (!known || scope.equals("openid") && !config.openId()) {
                throw new OAuthError(400, "invalid_scope", "Scope not allowed: " + scope);
            }
        }
        return String.join(" ", scopes);
    }

    private static Set<String> scopes(String scope) {
        return scope == null || scope.isBlank() ? new LinkedHashSet<>()
                : new LinkedHashSet<>(Arrays.asList(scope.trim().split("\\s+")));
    }

    // --------------------------------------------------------------------------------- tokens in use, devices

    private void introspect(Call call) throws IOException {
        if (config.introspectionAuth()) call.client = authenticate(call).id();
        IdpState.Token token = state.tokens.get(String.valueOf(call.params.get("token")));
        if (token == null || token.expires() < now()) {
            json(call, 200, Map.of("active", false));
            return;
        }
        Map<String, Object> answer = new LinkedHashMap<>();
        answer.put("active", true);
        answer.put("client_id", token.client());
        answer.put("token_type", token.refresh() ? "refresh_token" : config.tokenType());
        answer.put("scope", token.scope());
        answer.put("exp", token.expires());
        answer.put("iss", issuer);
        answer.put("aud", token.audience());
        answer.put("sub", token.user() == null ? token.client() : config.user(token.user()) == null ? token.user()
                : config.user(token.user()).sub());
        if (token.user() != null) answer.put("username", token.user());
        if (token.thumbprint() != null) answer.put("cnf", Map.of("x5t#S256", token.thumbprint()));
        json(call, 200, answer);
    }

    private void revoke(Call call) throws IOException {
        Client client = authenticate(call);
        call.client = client.id();
        IdpState.Token token = state.tokens.get(String.valueOf(call.params.get("token")));
        // RFC 7009: an unknown token is answered like a revoked one
        if (token != null && token.client().equals(client.id())) {
            state.tokens.remove(token.value());
            if (token.refresh()) state.tokens.values().removeIf(other -> other.grantId().equals(token.grantId()));
        }
        send(call, 200, "application/json", new byte[0]);
    }

    private void userinfo(Call call) throws IOException {
        String header = call.exchange.getRequestHeaders().getFirst("Authorization");
        String prefix = config.tokenType() + " ";
        String value = header != null && header.regionMatches(true, 0, prefix, 0, prefix.length())
                ? header.substring(prefix.length()) : call.param("access_token");
        IdpState.Token token = value == null ? null : state.tokens.get(value);
        if (token == null || token.refresh() || token.expires() < now()) {
            call.exchange.getResponseHeaders().set("WWW-Authenticate", config.tokenType() + " error=\"invalid_token\"");
            throw new OAuthError(401, "invalid_token", "Unknown, revoked or expired token");
        }
        if (token.thumbprint() != null && (call.certificate == null
                || !token.thumbprint().equals(thumbprint(call.certificate)))) {
            throw new OAuthError(401, "invalid_token", "This token is bound to another certificate");
        }
        if (!scopes(token.scope()).contains("openid") || token.user() == null) {
            throw new OAuthError(403, "insufficient_scope", "The openid scope of a user is required");
        }
        User user = config.user(token.user());
        if (user == null) throw new OAuthError(401, "invalid_token", "The user no longer exists");
        call.client = token.client();
        Map<String, Object> answer = new LinkedHashMap<>();
        answer.put("sub", user.sub());
        if (scopes(token.scope()).contains("profile")) {
            answer.put("name", user.name());
            answer.put("preferred_username", user.username());
        }
        if (scopes(token.scope()).contains("email")) answer.put("email", user.email());
        json(call, 200, answer);
    }

    private void deviceAuthorization(Call call) throws IOException {
        if (!enabled("device_code")) throw new OAuthError(400, "unsupported_grant_type", "Device flow is not enabled");
        Client client = authenticate(call);
        call.client = client.id();
        String scope = scope(call.param("scope"), client, null);
        String deviceCode = random();
        String userCode = random().substring(0, 8).toUpperCase().replaceAll("[-_]", "X");
        state.devices.put(deviceCode, new IdpState.Device(client.id(), userCode, scope, null, false, now() + DEVICE_TTL));
        Map<String, Object> answer = new LinkedHashMap<>();
        answer.put("device_code", deviceCode);
        answer.put("user_code", userCode);
        answer.put("verification_uri", issuer + "/device");
        answer.put("verification_uri_complete", issuer + "/device?user_code=" + userCode);
        answer.put("expires_in", DEVICE_TTL);
        answer.put("interval", DEVICE_INTERVAL);
        json(call, 200, answer);
    }

    private void deviceForm(Call call, String userCode, String error) throws IOException {
        StringBuilder page = new StringBuilder(PAGE_START).append("<h1>Connect a device</h1>");
        if (error != null) page.append("<p class=\"bad\">").append(html(error)).append("</p>");
        page.append("<form method=\"post\" action=\"/device\"><label>Code<input name=\"user_code\" value=\"")
                .append(html(userCode == null ? "" : userCode)).append("\"></label>")
                .append("<label>User name<input name=\"username\"></label>")
                .append("<label>Password<input name=\"password\" type=\"password\"></label>")
                .append("<button name=\"action\" value=\"allow\">Allow</button> ")
                .append("<button name=\"action\" value=\"deny\">Deny</button></form></main></body>");
        html(call, call.status, page.toString());
    }

    private void deviceApprove(Call call) throws IOException {
        String userCode = String.valueOf(call.params.get("user_code")).trim();
        Map.Entry<String, IdpState.Device> found = state.devices.entrySet().stream()
                .filter(e -> e.getValue().userCode().equals(userCode)).findFirst().orElse(null);
        if (found == null || found.getValue().expires() < now()) {
            call.status = 400;
            call.error = "invalid_user_code";
            deviceForm(call, userCode, "Unknown or expired code");
            return;
        }
        IdpState.Device device = found.getValue();
        call.client = device.client();
        if ("deny".equals(call.param("action"))) {
            state.devices.put(found.getKey(), device.refused());
        } else {
            User user = config.user(String.valueOf(call.params.get("username")));
            if (user == null || !user.password().equals(call.params.get("password"))) {
                call.status = 401;
                call.error = "login_failed";
                deviceForm(call, userCode, "Wrong user name or password");
                return;
            }
            state.devices.put(found.getKey(), device.approvedBy(user.username()));
        }
        html(call, 200, PAGE_START + "<h1>Done</h1><p>You can go back to your device.</p></main></body>");
    }

    private void logout(Call call) throws IOException {
        String redirectUri = call.param("post_logout_redirect_uri");
        boolean registered = redirectUri != null && config.clients().stream()
                .anyMatch(c -> c.redirectUris().contains(redirectUri));
        if (!registered) {
            html(call, 200, PAGE_START + "<h1>Logged out</h1></main></body>");
            return;
        }
        String state = call.param("state");
        String target = redirectUri + (state == null ? "" : (redirectUri.contains("?") ? "&" : "?")
                + "state=" + URLEncoder.encode(state, StandardCharsets.UTF_8));
        call.exchange.getResponseHeaders().set("Location", target);
        send(call, 302, "text/plain", new byte[0]);
    }

    // --------------------------------------------------------------------------------------------------- helpers

    private static X509Certificate certificate(HttpExchange exchange) {
        if (!(exchange instanceof HttpsExchange secure)) return null;
        try {
            Certificate[] chain = secure.getSSLSession().getPeerCertificates();
            return chain.length > 0 && chain[0] instanceof X509Certificate certificate ? certificate : null;
        } catch (SSLPeerUnverifiedException e) {
            return null;
        }
    }

    private static String thumbprint(X509Certificate certificate) {
        try {
            return IdpKeys.base64(sha256(certificate.getEncoded()));
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] sha256(byte[] bytes) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(bytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static Map<String, String> params(HttpExchange exchange) throws IOException {
        Map<String, String> params = new LinkedHashMap<>();
        addForm(exchange.getRequestURI().getRawQuery(), params);
        String type = exchange.getRequestHeaders().getFirst("Content-Type");
        try (InputStream in = exchange.getRequestBody()) {
            byte[] body = in.readAllBytes();
            if (type != null && type.toLowerCase().startsWith("application/x-www-form-urlencoded")) {
                addForm(new String(body, StandardCharsets.UTF_8), params);
            }
        }
        return params;
    }

    private static void addForm(String form, Map<String, String> params) {
        if (form == null || form.isEmpty()) return;
        for (String pair : form.split("&")) {
            int eq = pair.indexOf('=');
            try {
                params.put(decode(eq < 0 ? pair : pair.substring(0, eq)), eq < 0 ? "" : decode(pair.substring(eq + 1)));
            } catch (IllegalArgumentException e) {
                // a malformed pair counts as absent
            }
        }
    }

    private static String decode(String text) {
        return URLDecoder.decode(text, StandardCharsets.UTF_8);
    }

    private static String form(Map<String, String> values) {
        return values.entrySet().stream().map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "="
                + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8)).collect(Collectors.joining("&"));
    }

    private static String html(String text) {
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
                .replace("'", "&#39;");
    }

    private static String random() {
        byte[] bytes = new byte[24];
        RANDOM.nextBytes(bytes);
        return IdpKeys.base64(bytes);
    }

    private static long now() {
        return System.currentTimeMillis() / 1000;
    }

    private static void json(Call call, int status, Object value) throws IOException {
        send(call, status, "application/json", Json.write(value).getBytes(StandardCharsets.UTF_8));
    }

    private static void html(Call call, int status, String page) throws IOException {
        send(call, status, "text/html; charset=utf-8", page.getBytes(StandardCharsets.UTF_8));
    }

    private static void send(Call call, int status, String type, byte[] bytes) throws IOException {
        call.status = status;
        HttpExchange exchange = call.exchange;
        exchange.getResponseHeaders().set("Content-Type", type);
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.getResponseHeaders().set("Pragma", "no-cache");
        exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
        if (bytes.length == 0) return;
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }
}
