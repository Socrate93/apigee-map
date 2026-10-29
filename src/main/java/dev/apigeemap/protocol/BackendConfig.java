package dev.apigeemap.protocol;

import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

/**
 * Where the app finds the backend, read from a properties file (by default {@code ~/.apigee-map/backend.properties},
 * or the {@code backend.properties} of the jar when it does not exist), and the client token, which is never written to
 * a file: the user types it.
 *
 * @param url       base URL of the backend; HTTPS unless it is on this machine
 * @param publicKey public key of the backend, printed by its keygen command
 * @param token     client token, printed by the token command of the backend
 */
public record BackendConfig(URI url, PublicKey publicKey, String token) {

    public BackendConfig {
        if (!"https".equals(url.getScheme()) && !("http".equals(url.getScheme()) && loopback(url.getHost()))) {
            throw new IllegalArgumentException("The backend url must use https: " + url);
        }
        if (token == null || token.isBlank()) throw new IllegalArgumentException("No token");
    }

    /** The settings of the jar, used when the default file does not exist. */
    private static final String BUILT_IN = "/backend.properties";

    public static Path defaultFile() {
        return Path.of(System.getProperty("user.home"), ".apigee-map", "backend.properties");
    }

    /**
     * The url and public key of the file, with the token the user typed; a token in the file is ignored. Without a
     * token, a random one is sent all the same: the backend refuses it, but the request looks like any other.
     */
    public static BackendConfig load(Path file, String token) throws IOException {
        Properties properties = new Properties();
        if (Files.isRegularFile(file)) {
            try (Reader reader = Files.newBufferedReader(file)) {
                properties.load(reader);
            }
        } else if (file.equals(defaultFile()) && BackendConfig.class.getResource(BUILT_IN) != null) {
            try (InputStream in = BackendConfig.class.getResourceAsStream(BUILT_IN)) {
                properties.load(in);
            }
        } else {
            throw new IOException("No backend settings in " + file + " (url and publicKey)");
        }
        List<String> missing = new ArrayList<>();
        for (String key : List.of("url", "publicKey")) {
            if (properties.getProperty(key, "").isBlank()) missing.add(key);
        }
        if (!missing.isEmpty()) throw new IOException("Missing in " + file + ": " + String.join(", ", missing));
        try {
            return new BackendConfig(URI.create(properties.getProperty("url").trim()),
                    Keys.publicKey(properties.getProperty("publicKey")),
                    token == null || token.isBlank() ? Keys.newToken() : token.trim());
        } catch (IllegalArgumentException e) {
            throw new IOException("Invalid backend settings in " + file + ": " + e.getMessage(), e);
        }
    }

    /** The key the requests are sealed for, also computed by the backend from its own public key. */
    public String keyId() {
        return Keys.keyId(publicKey);
    }

    public URI endpoint() {
        return URI.create(url.toString().replaceAll("/+$", "") + "/v1/exchange");
    }

    private static boolean loopback(String host) {
        try {
            return host != null && InetAddress.getByName(host).isLoopbackAddress();
        } catch (UnknownHostException e) {
            return false;
        }
    }
}
