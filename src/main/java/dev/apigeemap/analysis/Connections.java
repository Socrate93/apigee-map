package dev.apigeemap.analysis;

import dev.apigeemap.model.DependencyKind;
import org.w3c.dom.Element;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static dev.apigeemap.analysis.Details.put;
import static dev.apigeemap.model.DependencyKind.KEYSTORE;
import static dev.apigeemap.model.DependencyKind.LOCAL_PROXY;
import static dev.apigeemap.model.DependencyKind.TARGET_SERVER;
import static dev.apigeemap.model.DependencyKind.TARGET_URL;
import static dev.apigeemap.model.DependencyKind.TRUSTSTORE;

/** HTTPTargetConnection / LocalTargetConnection, shared by TargetEndpoint and ServiceCallout. */
final class Connections {

    private static final String REFERENCE_PREFIX = "ref://";

    private Connections() {
    }

    /** Registers the connection dependencies and returns a summary for display. */
    static Map<String, String> http(Element conn, Origin origin, BundleContext ctx) {
        Map<String, String> summary = new LinkedHashMap<>();

        String url = Xml.text(conn, "URL");
        if (url != null) {
            summary.put("url", url);
            ctx.deps.add(TARGET_URL, url, origin.usage(Map.of()));
        }

        Element loadBalancer = Xml.path(conn, "LoadBalancer");
        if (loadBalancer != null) {
            String algorithm = Xml.text(loadBalancer, "Algorithm");
            String path = Xml.text(conn, "Path");
            List<String> servers = new ArrayList<>();
            for (Element server : Xml.children(loadBalancer, "Server")) {
                String name = Xml.attr(server, "name");
                if (name == null) continue;
                servers.add(name);
                Map<String, String> details = new LinkedHashMap<>();
                put(details, "algorithm", algorithm);
                put(details, "path", path);
                if ("true".equalsIgnoreCase(Xml.text(server, "IsFallback"))) details.put("fallback", "true");
                ctx.deps.add(TARGET_SERVER, name, origin.usage(details));
            }
            summary.put("targetServers", String.join(", ", servers));
            put(summary, "algorithm", algorithm);
            put(summary, "path", path);
        }

        Element ssl = Xml.path(conn, "SSLInfo");
        if (ssl != null && !"false".equalsIgnoreCase(Xml.text(ssl, "Enabled"))) {
            summary.put("ssl", "enabled");
            Map<String, String> keyStoreDetails = new LinkedHashMap<>();
            put(keyStoreDetails, "keyAlias", Xml.text(ssl, "KeyAlias"));
            put(keyStoreDetails, "clientAuth", Xml.text(ssl, "ClientAuthEnabled"));
            store(ctx, KEYSTORE, Xml.text(ssl, "KeyStore"), origin, keyStoreDetails, summary, "keyStore");
            store(ctx, TRUSTSTORE, Xml.text(ssl, "TrustStore"), origin, Map.of(), summary, "trustStore");
        }
        return summary;
    }

    static Map<String, String> local(Element conn, Origin origin, BundleContext ctx) {
        Map<String, String> summary = new LinkedHashMap<>();
        String proxy = Xml.text(conn, "APIProxy");
        String endpoint = Xml.text(conn, "ProxyEndpoint");
        String path = Xml.text(conn, "Path");
        if (proxy != null) {
            Map<String, String> details = new LinkedHashMap<>();
            put(details, "proxyEndpoint", endpoint);
            ctx.deps.add(LOCAL_PROXY, proxy, origin.usage(details));
            summary.put("localProxy", endpoint == null ? proxy : proxy + " › " + endpoint);
        } else if (path != null) {
            ctx.deps.add(LOCAL_PROXY, "path " + path, origin.usage(Map.of()));
            summary.put("localPath", path);
        }
        return summary;
    }

    private static void store(BundleContext ctx, DependencyKind kind, String value, Origin origin,
                              Map<String, String> baseDetails, Map<String, String> summary, String summaryKey) {
        if (value == null) return;
        Map<String, String> details = new LinkedHashMap<>(baseDetails);
        String name = value;
        if (value.startsWith(REFERENCE_PREFIX)) {
            name = value.substring(REFERENCE_PREFIX.length());
            details.put("via", "reference");
        }
        summary.put(summaryKey, value);
        ctx.deps.add(kind, name, origin.usage(details));
    }
}
