package dev.apigeemap.protocol;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HexFormat;

/** X25519 keys of the backend and client tokens, as the base64 text found in configuration files. */
public final class Keys {

    private static final SecureRandom RANDOM = new SecureRandom();

    private Keys() {
    }

    public static KeyPair generate() {
        try {
            return KeyPairGenerator.getInstance("X25519").generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("X25519 is not available in this JDK", e);
        }
    }

    public static String encode(Key key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public static PublicKey publicKey(String base64) {
        try {
            return KeyFactory.getInstance("X25519").generatePublic(new X509EncodedKeySpec(decode(base64)));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Invalid public key", e);
        }
    }

    public static PrivateKey privateKey(String base64) {
        try {
            return KeyFactory.getInstance("X25519").generatePrivate(new PKCS8EncodedKeySpec(decode(base64)));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Invalid private key", e);
        }
    }

    /** Short identifier of a public key: the first 8 bytes of its SHA-256, in hex. */
    public static String keyId(PublicKey key) {
        return HexFormat.of().formatHex(sha256(key.getEncoded()), 0, 8);
    }

    /** A random client token (128 bits, 22 characters of base64url). */
    public static String newToken() {
        byte[] token = new byte[16];
        RANDOM.nextBytes(token);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(token);
    }

    /** SHA-256 of a token, in hex: what the backend stores instead of the token. */
    public static String tokenHash(String token) {
        return HexFormat.of().formatHex(sha256(token.getBytes(StandardCharsets.UTF_8)));
    }

    private static byte[] decode(String base64) {
        try {
            return Base64.getDecoder().decode(base64.trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid base64 key", e);
        }
    }

    private static byte[] sha256(byte[] bytes) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(bytes);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
