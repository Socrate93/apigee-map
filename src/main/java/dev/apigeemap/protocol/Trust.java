package dev.apigeemap.protocol;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * TLS that trusts the certificates of the JDK and, on Windows and macOS, those of the machine (Windows store,
 * keychain), where a TLS inspection proxy installs its own CA. The JDK does not read them by default.
 */
final class Trust {

    private Trust() {
    }

    static SSLContext context() {
        try {
            List<X509ExtendedTrustManager> managers = new ArrayList<>(List.of(manager(null)));
            String os = System.getProperty("os.name", "");
            String machineStore = os.startsWith("Windows") ? "Windows-ROOT" : os.startsWith("Mac") ? "KeychainStore" : null;
            if (machineStore != null) {
                KeyStore machine = KeyStore.getInstance(machineStore);
                machine.load(null, null);
                managers.add(manager(machine));
            }
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, new TrustManager[]{new AnyOf(managers)}, null);
            return context;
        } catch (GeneralSecurityException | IOException e) {
            throw new IllegalStateException("Cannot set up TLS: " + e.getMessage(), e);
        }
    }

    private static X509ExtendedTrustManager manager(KeyStore store) throws GeneralSecurityException {
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init(store);
        for (TrustManager manager : factory.getTrustManagers()) {
            if (manager instanceof X509ExtendedTrustManager extended) return extended;
        }
        throw new KeyStoreException("No X.509 trust manager");
    }

    private interface Check {
        void run(X509ExtendedTrustManager manager) throws CertificateException;
    }

    /** Trusts a server when one of the managers does; each one also checks the host name. */
    private static final class AnyOf extends X509ExtendedTrustManager {

        private final List<X509ExtendedTrustManager> managers;

        AnyOf(List<X509ExtendedTrustManager> managers) {
            this.managers = managers;
        }

        private void any(Check check) throws CertificateException {
            CertificateException first = null;
            for (X509ExtendedTrustManager manager : managers) {
                try {
                    check.run(manager);
                    return;
                } catch (CertificateException e) {
                    if (first == null) first = e;
                }
            }
            throw first;
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
                throws CertificateException {
            any(m -> m.checkServerTrusted(chain, authType, socket));
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
                throws CertificateException {
            any(m -> m.checkServerTrusted(chain, authType, engine));
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            any(m -> m.checkServerTrusted(chain, authType));
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
                throws CertificateException {
            any(m -> m.checkClientTrusted(chain, authType, socket));
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
                throws CertificateException {
            any(m -> m.checkClientTrusted(chain, authType, engine));
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            any(m -> m.checkClientTrusted(chain, authType));
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return managers.stream().flatMap(m -> List.of(m.getAcceptedIssuers()).stream())
                    .toArray(X509Certificate[]::new);
        }
    }
}
