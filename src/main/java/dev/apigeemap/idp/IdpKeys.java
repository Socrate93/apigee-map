package dev.apigeemap.idp;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import dev.apigeemap.protocol.Json;

/** The signing keys of the mock IdP, kept for as long as the app runs, and compact JWTs signed with them. */
final class IdpKeys {

    private static final Base64.Encoder URL = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder URL_DECODER = Base64.getUrlDecoder();

    private final KeyPair rsa;
    private final KeyPair ec;
    private final String rsaId = UUID.randomUUID().toString();
    private final String ecId = UUID.randomUUID().toString();

    IdpKeys() {
        try {
            KeyPairGenerator rsaKeys = KeyPairGenerator.getInstance("RSA");
            rsaKeys.initialize(2048);
            rsa = rsaKeys.generateKeyPair();
            KeyPairGenerator ecKeys = KeyPairGenerator.getInstance("EC");
            ecKeys.initialize(new ECGenParameterSpec("secp256r1"));
            ec = ecKeys.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The public keys, in JWKS form. */
    Map<String, Object> jwks() {
        RSAPublicKey publicRsa = (RSAPublicKey) rsa.getPublic();
        ECPublicKey publicEc = (ECPublicKey) ec.getPublic();
        Map<String, Object> rsaKey = new LinkedHashMap<>();
        rsaKey.put("kty", "RSA");
        rsaKey.put("use", "sig");
        rsaKey.put("kid", rsaId);
        rsaKey.put("n", base64(unsigned(publicRsa.getModulus(), 256)));
        rsaKey.put("e", base64(publicRsa.getPublicExponent().toByteArray()));
        Map<String, Object> ecKey = new LinkedHashMap<>();
        ecKey.put("kty", "EC");
        ecKey.put("use", "sig");
        ecKey.put("kid", ecId);
        ecKey.put("crv", "P-256");
        ecKey.put("x", base64(unsigned(publicEc.getW().getAffineX(), 32)));
        ecKey.put("y", base64(unsigned(publicEc.getW().getAffineY(), 32)));
        return Map.of("keys", List.of(rsaKey, ecKey));
    }

    /** Signs {@code claims} with the key of {@code alg}; {@code hmacSecret} is the key of HS256. */
    String sign(Map<String, Object> claims, String alg, String hmacSecret) {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", alg);
        header.put("typ", "JWT");
        if (!alg.equals("HS256")) header.put("kid", alg.equals("ES256") ? ecId : rsaId);
        String content = base64(json(header)) + "." + base64(json(claims));
        try {
            byte[] bytes = content.getBytes(StandardCharsets.US_ASCII);
            byte[] signature;
            if (alg.equals("HS256")) {
                signature = hmac(hmacSecret, bytes);
            } else {
                Signature signer = signature(alg);
                signer.initSign(alg.equals("ES256") ? ec.getPrivate() : rsa.getPrivate());
                signer.update(bytes);
                signature = signer.sign();
            }
            return content + "." + base64(signature);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * The claims of a JWT whose signature checks, or null when it does not.
     *
     * @param key the public key of an asymmetric {@code alg}, null to refuse those
     * @param secret the secret of HS256, null to refuse it
     */
    static Map<String, Object> verify(String token, PublicKey key, String secret) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) return null;
        try {
            Object header = Json.parse(text(parts[0]));
            String alg = header instanceof Map<?, ?> map && map.get("alg") instanceof String name ? name : "";
            byte[] content = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII);
            byte[] signature = URL_DECODER.decode(parts[2]);
            boolean valid;
            if (alg.equals("HS256")) {
                valid = secret != null && MessageDigest.isEqual(hmac(secret, content), signature);
            } else if (key != null && List.of("RS256", "PS256", "ES256").contains(alg)) {
                Signature verifier = signature(alg);
                verifier.initVerify(key);
                verifier.update(content);
                valid = verifier.verify(signature);
            } else {
                valid = false;
            }
            if (!valid || !(Json.parse(text(parts[1])) instanceof Map<?, ?> claims)) return null;
            Map<String, Object> result = new LinkedHashMap<>();
            claims.forEach((name, value) -> result.put(String.valueOf(name), value));
            return result;
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            return null;
        }
    }

    /** A public key from PEM or base64 text, RSA or EC. */
    static PublicKey publicKey(String pem) throws GeneralSecurityException {
        byte[] der = Base64.getMimeDecoder().decode(pem.replaceAll("-----[A-Z ]+-----", ""));
        for (String type : List.of("RSA", "EC")) {
            try {
                return KeyFactory.getInstance(type).generatePublic(new X509EncodedKeySpec(der));
            } catch (GeneralSecurityException e) {
                // the other type, then
            }
        }
        throw new GeneralSecurityException("Not an RSA or EC public key");
    }

    static String base64(byte[] bytes) {
        return URL.encodeToString(bytes);
    }

    private static Signature signature(String alg) throws GeneralSecurityException {
        return switch (alg) {
            case "RS256" -> Signature.getInstance("SHA256withRSA");
            case "ES256" -> Signature.getInstance("SHA256withECDSAinP1363Format");
            case "PS256" -> {
                Signature pss = Signature.getInstance("RSASSA-PSS");
                pss.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
                yield pss;
            }
            default -> throw new GeneralSecurityException("Unknown algorithm " + alg);
        };
    }

    private static byte[] hmac(String secret, byte[] content) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        Key key = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(key);
        return mac.doFinal(content);
    }

    /** A positive number on exactly {@code length} bytes, as JWKs want it. */
    private static byte[] unsigned(BigInteger value, int length) {
        byte[] bytes = value.toByteArray();
        byte[] result = new byte[length];
        int copied = Math.min(bytes.length, length);
        System.arraycopy(bytes, bytes.length - copied, result, length - copied, copied);
        return result;
    }

    private static byte[] json(Object value) {
        return Json.write(value).replaceAll("\\n\\s*", "").getBytes(StandardCharsets.UTF_8);
    }

    private static String base64(String text) {
        return base64(text.getBytes(StandardCharsets.UTF_8));
    }

    private static String text(String encoded) {
        return new String(URL_DECODER.decode(encoded), StandardCharsets.UTF_8);
    }

}
