package dev.apigeemap.migration;

import dev.apigeemap.analysis.BundleAnalyzer;
import dev.apigeemap.analysis.BundleLocator;
import dev.apigeemap.analysis.SharedFlowRepository;
import dev.apigeemap.model.BundleReport;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProxyProfileTest {

    @TempDir
    Path tmp;

    /** An OAuth authorization server like oauth-dev_01: authorize, callbacks, token, validation, revocation. */
    @Test
    void readsAnAuthorizationServerFromItsOAuthV2Policies() throws IOException {
        Path bundle = bundle("oauth-dev", Map.of(
                "OA-GenerateCode", oauth("GenerateAuthorizationCode", ""),
                "OA-Token", oauth("GenerateAccessToken", "<SupportedGrantTypes><GrantType>authorization_code</GrantType>"
                        + "<GrantType>client_credentials</GrantType><GrantType>custom_siteminder</GrantType>"
                        + "</SupportedGrantTypes>"),
                "OA-Implicit", oauth("GenerateAccessTokenImplicitGrant", ""),
                "OA-Refresh", oauth("RefreshAccessToken", ""),
                "OA-Verify", oauth("VerifyAccessToken", ""),
                "OA-Invalidate", oauth("InvalidateToken", ""),
                "OA-Disabled", oauth("GenerateAccessToken", "").replace("<OAuthV2 ", "<OAuthV2 enabled=\"false\" "),
                "Get-Info", "<GetOAuthV2Info name=\"Get-Info\"><AccessToken ref=\"t\"/></GetOAuthV2Info>"));
        ProxyProfile profile = ProxyProfile.of(analyze(bundle));

        assertTrue(profile.authorizationServer());
        assertEquals(List.of("authorization code", "client credentials", "custom_siteminder", "implicit",
                "refresh token"), profile.grants().stream().sorted().toList());
        assertEquals(List.of("revoke", "token info", "verify"), profile.operations().stream().sorted().toList());
        assertEquals(ProxyProfile.STANDARD, profile.as("standard").kind());
        assertEquals(profile, profile.as("anything else"));
    }

    /** A proxy that only verifies tokens is a standard one: its tests need a token, not the flow that issues it. */
    @Test
    void aProxyThatVerifiesTokensIsAStandardOne() throws IOException {
        Path bundle = bundle("orders", Map.of("OA-Verify", oauth("VerifyAccessToken", "")));
        ProxyProfile profile = ProxyProfile.of(analyze(bundle));
        assertFalse(profile.authorizationServer());
        assertEquals(List.of("verify"), profile.operations());
        assertEquals(ProxyProfile.AUTHORIZATION_SERVER, profile.as("authorizationServer").kind());
    }

    private static String oauth(String operation, String more) {
        return "<OAuthV2 name=\"P\"><Operation>" + operation + "</Operation>" + more + "</OAuthV2>";
    }

    private Path bundle(String name, Map<String, String> policies) throws IOException {
        Path root = tmp.resolve(name).resolve("apiproxy");
        Files.createDirectories(root.resolve("policies"));
        Files.createDirectories(root.resolve("proxies"));
        Files.writeString(root.resolve(name + ".xml"), "<APIProxy name=\"" + name + "\" revision=\"1\"/>");
        StringBuilder steps = new StringBuilder();
        for (Map.Entry<String, String> policy : policies.entrySet()) {
            Files.writeString(root.resolve("policies").resolve(policy.getKey() + ".xml"),
                    policy.getValue().replace("name=\"P\"", "name=\"" + policy.getKey() + "\""));
            steps.append("<Step><Name>").append(policy.getKey()).append("</Name></Step>");
        }
        Files.writeString(root.resolve("proxies/default.xml"), "<ProxyEndpoint name=\"default\"><PreFlow><Request>"
                + steps + "</Request></PreFlow><HTTPProxyConnection><BasePath>/oauth2/v1</BasePath>"
                + "</HTTPProxyConnection><RouteRule name=\"none\"/></ProxyEndpoint>");
        return root.getParent();
    }

    private static BundleReport analyze(Path bundle) throws IOException {
        return new BundleAnalyzer(SharedFlowRepository.scan(List.of())).analyze(BundleLocator.locate(bundle));
    }
}
