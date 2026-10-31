package dev.apigeemap.migration;

import dev.apigeemap.analysis.Xml;
import dev.apigeemap.model.BundleReport;
import dev.apigeemap.model.Policy;
import org.w3c.dom.Element;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * What kind of proxy a test plan is prepared for, read from its OAuthV2 policies and those of the shared flows it
 * calls: an OAuth authorization server issues tokens, which its tests get through redirects and callbacks; a proxy
 * that only verifies them is a standard one.
 *
 * @param kind       {@link #STANDARD} or {@link #AUTHORIZATION_SERVER}
 * @param grants     the grants it issues tokens with, e.g. {@code authorization code}
 * @param operations what else it does with tokens, e.g. {@code verify}
 */
public record ProxyProfile(String kind, List<String> grants, List<String> operations) {

    public static final String STANDARD = "standard";
    public static final String AUTHORIZATION_SERVER = "authorizationServer";

    private static final Map<String, String> GRANT_TYPES = Map.of(
            "authorization_code", "authorization code",
            "client_credentials", "client credentials",
            "password", "password",
            "refresh_token", "refresh token",
            "implicit", "implicit");
    private static final Map<String, String> TOKEN_OPERATIONS = Map.of(
            "VerifyAccessToken", "verify",
            "InvalidateToken", "revoke",
            "ValidateToken", "validate",
            "GetOAuthV2Info", "token info",
            "SetOAuthV2Info", "token attributes",
            "DeleteOAuthV2Info", "revoke",
            "RevokeOAuthV2", "revoke");

    public boolean authorizationServer() {
        return kind.equals(AUTHORIZATION_SERVER);
    }

    /** The profile read from the enabled policies of the proxy and its shared flows. */
    public static ProxyProfile of(BundleReport root) throws IOException {
        Set<String> grants = new LinkedHashSet<>();
        Set<String> operations = new LinkedHashSet<>();
        for (BundleReport bundle : FixContext.bundles(root).values()) {
            for (Policy policy : bundle.policies()) {
                if (!policy.enabled()) continue;
                if (!policy.type().equals("OAuthV2")) {
                    if (TOKEN_OPERATIONS.containsKey(policy.type())) operations.add(TOKEN_OPERATIONS.get(policy.type()));
                    continue;
                }
                Path file = Path.of(bundle.path()).resolve(policy.file());
                if (!Files.isRegularFile(file)) continue;
                Element xml = Xml.parse(file);
                String operation = Xml.text(xml, "Operation");
                switch (operation == null ? "" : operation.strip()) {
                    case "GenerateAuthorizationCode" -> grants.add("authorization code");
                    case "GenerateAccessTokenImplicitGrant" -> grants.add("implicit");
                    case "RefreshAccessToken" -> grants.add("refresh token");
                    case "GenerateAccessToken" -> {
                        List<Element> types = Xml.descendants(Xml.path(xml, "SupportedGrantTypes"), "GrantType");
                        if (types.isEmpty()) grants.add("access token");
                        for (Element type : types) {
                            String name = Xml.text(type);
                            if (name != null) grants.add(GRANT_TYPES.getOrDefault(name.strip(), name.strip()));
                        }
                    }
                    case "" -> {
                    }
                    default -> {
                        String known = TOKEN_OPERATIONS.get(operation.strip());
                        if (known != null) operations.add(known);
                    }
                }
            }
        }
        return new ProxyProfile(grants.isEmpty() ? STANDARD : AUTHORIZATION_SERVER, new ArrayList<>(grants),
                new ArrayList<>(operations));
    }

    /** The profile asked for: {@code standard} or {@code authorizationServer} replace the detected kind. */
    public ProxyProfile as(String chosen) {
        if (STANDARD.equals(chosen) || AUTHORIZATION_SERVER.equals(chosen)) {
            return new ProxyProfile(chosen, grants, operations);
        }
        return this;
    }
}
