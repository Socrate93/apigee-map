package dev.apigeemap.protocol;

import java.io.IOException;
import java.io.PrintStream;
import java.net.ProxySelector;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Sends encrypted requests to the backend, through the proxy and the certificates of the machine.
 * <p>
 * A request is {@code {id, ts, token, type, body}} sealed in an {@link Envelope}; the response is
 * {@code {id, ok, body}} or {@code {id, ok: false, error}}, sealed with the key of that request.
 */
public final class BackendClient {

    /** What users see when a feature of the backend fails, whatever the cause: the details stay in the exception. */
    public static final String UNAVAILABLE = "This feature is not available. Please contact administrator";

    /** A fix takes a minute or two, up to the 10 minutes Cloud Run allows a request. */
    private static final Duration TIMEOUT = Duration.ofMinutes(10);

    /** The backend could not be reached: TLS, proxy, network or timeout. */
    public static final class Unreachable extends IOException {
        Unreachable(String message, Throwable cause) {
            super(message, cause);
        }
    }

    private final BackendConfig config;
    /** Null when TLS could not be set up, which {@link #tlsFailure} tells */
    private final HttpClient http;
    private final RuntimeException tlsFailure;

    public BackendClient(BackendConfig config) {
        this.config = config;
        HttpClient client = null;
        RuntimeException failure = null;
        try {
            client = HttpClient.newBuilder()
                    .version(HttpClient.Version.HTTP_1_1)
                    .connectTimeout(Duration.ofSeconds(15))
                    .proxy(ProxySelector.getDefault())
                    .sslContext(Trust.context())
                    .build();
        } catch (IllegalStateException e) {
            failure = e;
        }
        this.http = client;
        this.tlsFailure = failure;
    }

    /**
     * Writes why a call failed to the console: one line, and the stack trace when the backend could not be reached,
     * which is where the TLS or network cause shows.
     */
    public static void report(Exception e, PrintStream err) {
        err.println("Backend call failed: " + e.getMessage());
        if (e instanceof Unreachable) e.printStackTrace(err);
    }

    /** Calls an operation of the backend and returns the body of its response. */
    public Object call(String type, Object body) throws IOException {
        String id = UUID.randomUUID().toString();
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("id", id);
        request.put("ts", System.currentTimeMillis());
        request.put("token", config.token());
        request.put("type", type);
        request.put("body", body);
        Envelope.Sealed sealed = Envelope.seal(config.publicKey(), config.keyId(),
                Json.write(request).getBytes(StandardCharsets.UTF_8));

        HttpResponse<byte[]> response = send(sealed.wire());
        // The backend always answers 200: another status comes from something on the way (wrong url, proxy, outage)
        if (response.statusCode() != 200) {
            throw new IOException("No backend at " + config.url() + " (HTTP " + response.statusCode()
                    + "): check the url of the backend settings");
        }
        Object reply;
        try {
            reply = Json.parse(new String(sealed.exchange().openResponse(response.body()), StandardCharsets.UTF_8));
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            // what a backend answers to a request sealed for another key: it could not read it
            throw new IOException("The backend could not read the request: check the publicKey of the backend "
                    + "settings, it must be the one of this backend", e);
        }
        if (!(reply instanceof Map<?, ?> map)) throw new IOException("Unexpected answer from the backend");
        if (map.get("id") != null && !id.equals(map.get("id"))) {
            throw new IOException("The backend answered another request");
        }
        if (Boolean.TRUE.equals(map.get("ok"))) return map.get("body");
        int status = map.get("status") instanceof Number n ? n.intValue() : 0;
        throw new IOException(switch (status) {
            case 401 -> "The backend does not accept this client: check the token of the backend settings";
            case 408 -> "The clock of this machine is more than 5 minutes off: set it right and try again";
            case 409 -> "The backend already received this request: try again";
            case 400 -> "The backend could not understand the request: the app and the backend may not be of the "
                    + "same version";
            default -> "Backend error: " + map.get("error");
        });
    }

    private HttpResponse<byte[]> send(byte[] wire) throws IOException {
        HttpRequest request = HttpRequest.newBuilder(config.endpoint())
                .timeout(TIMEOUT)
                .header("Content-Type", "application/octet-stream")
                .POST(HttpRequest.BodyPublishers.ofByteArray(wire))
                .build();
        if (http == null) throw new Unreachable(tlsFailure.getMessage(), tlsFailure);
        try {
            return http.send(request, HttpResponse.BodyHandlers.ofByteArray());
        } catch (IOException e) {
            throw new Unreachable("Cannot reach the backend at " + config.url() + ": " + e, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted", e);
        }
    }
}
