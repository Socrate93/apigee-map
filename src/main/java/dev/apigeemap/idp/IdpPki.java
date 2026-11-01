package dev.apigeemap.idp;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * The local certificates of the mock IdP, made once with the keytool of the JDK running the app: an authority, a
 * certificate for the server, and one for clients. They only exist for tests on this computer.
 */
final class IdpPki {

    static final String CLIENT_SUBJECT = "CN=mtls-client,O=apigee-map mock";
    private static final char[] PASSWORD = "mock-idp".toCharArray();
    private static final Base64.Encoder PEM = Base64.getMimeEncoder(64, new byte[]{'\n'});

    private final Path dir;

    IdpPki(Path dir) {
        this.dir = dir;
    }

    Path dir() {
        return dir;
    }

    /** The authority trusted for client certificates and the certificate of the server. */
    SSLContext serverContext() throws IOException, GeneralSecurityException {
        create();
        KeyStore server = keyStore("server.p12");
        KeyManagerFactory keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keys.init(server, PASSWORD);
        TrustManagerFactory trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trust.init(keyStore("ca-trust.p12"));
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keys.getKeyManagers(), trust.getTrustManagers(), null);
        return context;
    }

    /** Makes what is missing. */
    void create() throws IOException, GeneralSecurityException {
        if (Files.isRegularFile(dir.resolve("client-key.pem"))) return;
        Files.createDirectories(dir);
        keytool("-genkeypair", "-alias", "ca", "-keyalg", "EC", "-groupname", "secp256r1", "-sigalg", "SHA256withECDSA",
                "-dname", "CN=apigee-map mock CA,O=apigee-map mock", "-ext", "bc:c", "-validity", "3650",
                "-keystore", "ca.p12");
        keytool("-exportcert", "-rfc", "-alias", "ca", "-keystore", "ca.p12", "-file", "ca.pem");
        keytool("-importcert", "-noprompt", "-alias", "ca", "-file", "ca.pem", "-keystore", "ca-trust.p12");
        certificate("server", "CN=localhost,O=apigee-map mock",
                "san=dns:localhost,ip:127.0.0.1", "eku=serverAuth");
        certificate("client", CLIENT_SUBJECT, "eku=clientAuth");
        KeyStore client = keyStore("client.p12");
        Key key = client.getKey("client", PASSWORD);
        Files.writeString(dir.resolve("client-key.pem"), "-----BEGIN PRIVATE KEY-----\n"
                + PEM.encodeToString(key.getEncoded()) + "\n-----END PRIVATE KEY-----\n");
    }

    private void certificate(String name, String subject, String... extensions) throws IOException {
        String store = name + ".p12";
        String request = name + ".csr";
        String certificate = name + ".pem";
        keytool("-genkeypair", "-alias", name, "-keyalg", "EC", "-groupname", "secp256r1", "-sigalg", "SHA256withECDSA",
                "-dname", subject, "-validity", "3650", "-keystore", store);
        keytool("-certreq", "-alias", name, "-keystore", store, "-file", request);
        List<String> sign = new ArrayList<>(List.of("-gencert", "-alias", "ca", "-keystore", "ca.p12", "-infile", request,
                "-outfile", certificate, "-rfc", "-validity", "3650"));
        for (String extension : extensions) {
            sign.add("-ext");
            sign.add(extension);
        }
        keytool(sign.toArray(String[]::new));
        keytool("-importcert", "-noprompt", "-trustcacerts", "-alias", "ca-" + name, "-file", "ca.pem", "-keystore", store);
        keytool("-importcert", "-noprompt", "-alias", name, "-file", certificate, "-keystore", store);
        Files.delete(dir.resolve(request));
    }

    private void keytool(String... args) throws IOException {
        boolean windows = System.getProperty("os.name").toLowerCase().contains("win");
        List<String> command = new ArrayList<>(List.of(
                Path.of(System.getProperty("java.home"), "bin", windows ? "keytool.exe" : "keytool").toString()));
        command.addAll(List.of(args));
        command.addAll(List.of("-storetype", "PKCS12", "-storepass", new String(PASSWORD)));
        Process process = new ProcessBuilder(command).directory(dir.toFile()).redirectErrorStream(true).start();
        try {
            String output = new String(process.getInputStream().readAllBytes());
            if (process.waitFor() != 0) throw new IOException("Could not make the certificates: " + output.trim());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while making the certificates", e);
        }
    }

    private KeyStore keyStore(String name) throws IOException, GeneralSecurityException {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(dir.resolve(name))) {
            store.load(in, PASSWORD);
        }
        return store;
    }
}
