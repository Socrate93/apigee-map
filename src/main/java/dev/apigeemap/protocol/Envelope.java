package dev.apigeemap.protocol;

import javax.crypto.Cipher;
import javax.crypto.KEM;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Encryption of the exchanges between the app and the backend, on top of TLS, so that a proxy that opens the TLS
 * connection only sees opaque bytes. Only the holder of the backend private key can read a request, and only the
 * app that sent it can read the response.
 * <p>
 * Built like HPKE (RFC 9180) with the JDK alone: DHKEM(X25519, HKDF-SHA256) gives a fresh secret for each request,
 * from which a request key and a response key are derived (HKDF-Expand); AES-256-GCM encrypts and authenticates
 * each direction.
 * <pre>
 * request  : version(1) | key id length(1) | key id | encapsulation(32) | nonce(12) | ciphertext and tag
 * response : version(1) | nonce(12) | ciphertext and tag
 * </pre>
 * The request header is authenticated along with the request. The response is authenticated with the request
 * encapsulation, so it cannot be swapped with the response to another request.
 */
public final class Envelope {

    public static final byte VERSION = 1;
    private static final int ENCAPSULATION = 32;
    private static final int NONCE = 12;
    private static final int TAG_BITS = 128;
    private static final SecureRandom RANDOM = new SecureRandom();

    private Envelope() {
    }

    /** A request ready to send, and the exchange that opens its response. */
    public record Sealed(byte[] wire, Exchange exchange) {
    }

    /** A request read by the backend, and the exchange that seals its response. */
    public record Opened(byte[] plaintext, Exchange exchange) {
    }

    /** The response key of one request: only the app that sealed the request and the backend know it. */
    public static final class Exchange {

        private final SecretKey responseKey;
        private final byte[] aad;

        private Exchange(SecretKey responseKey, byte[] encapsulation) {
            this.responseKey = responseKey;
            this.aad = concat(new byte[]{VERSION}, encapsulation);
        }

        public byte[] sealResponse(byte[] plaintext) {
            return concat(new byte[]{VERSION}, encrypt(responseKey, aad, plaintext));
        }

        public byte[] openResponse(byte[] wire) throws GeneralSecurityException {
            if (wire.length < 1 + NONCE || wire[0] != VERSION) throw new GeneralSecurityException("Malformed response");
            return decrypt(responseKey, aad, wire, 1);
        }
    }

    public static Sealed seal(PublicKey backend, String keyId, byte[] plaintext) {
        byte[] id = keyId.getBytes(StandardCharsets.US_ASCII);
        if (id.length > 255) throw new IllegalArgumentException("Key id too long");
        try {
            KEM.Encapsulated encapsulated = KEM.getInstance("DHKEM").newEncapsulator(backend).encapsulate();
            byte[] encapsulation = encapsulated.encapsulation();
            byte[] header = concat(new byte[]{VERSION, (byte) id.length}, id, encapsulation);
            byte[] secret = encapsulated.key().getEncoded();
            byte[] wire = concat(header, encrypt(key(secret, "request"), header, plaintext));
            return new Sealed(wire, new Exchange(key(secret, "response"), encapsulation));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Cannot encrypt for this public key", e);
        }
    }

    /** Opens a request sealed for {@code keyId}; any malformed, tampered or foreign request fails the same way. */
    public static Opened open(PrivateKey backend, String keyId, byte[] wire) throws GeneralSecurityException {
        if (wire.length < 2 || wire[0] != VERSION) throw new GeneralSecurityException("Malformed request");
        int idLength = wire[1] & 0xff;
        int headerLength = 2 + idLength + ENCAPSULATION;
        if (wire.length < headerLength + NONCE) throw new GeneralSecurityException("Malformed request");
        if (!keyId.equals(new String(wire, 2, idLength, StandardCharsets.US_ASCII))) {
            throw new GeneralSecurityException("Unknown key id");
        }
        byte[] header = Arrays.copyOf(wire, headerLength);
        byte[] encapsulation = Arrays.copyOfRange(wire, 2 + idLength, headerLength);
        byte[] secret = KEM.getInstance("DHKEM").newDecapsulator(backend).decapsulate(encapsulation).getEncoded();
        byte[] plaintext = decrypt(key(secret, "request"), header, wire, headerLength);
        return new Opened(plaintext, new Exchange(key(secret, "response"), encapsulation));
    }

    /** HKDF-Expand (RFC 5869) of one block: the DHKEM secret is already a uniform 32-byte key. */
    private static SecretKey key(byte[] secret, String direction) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret, "HmacSHA256"));
        mac.update(("apigee-map/" + VERSION + " " + direction).getBytes(StandardCharsets.US_ASCII));
        mac.update((byte) 1);
        return new SecretKeySpec(mac.doFinal(), "AES");
    }

    private static byte[] encrypt(SecretKey key, byte[] aad, byte[] plaintext) {
        byte[] nonce = new byte[NONCE];
        RANDOM.nextBytes(nonce);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(aad);
            return concat(nonce, cipher.doFinal(plaintext));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Decrypts {@code wire} from {@code offset}, where the nonce starts. */
    private static byte[] decrypt(SecretKey key, byte[] aad, byte[] wire, int offset) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, wire, offset, NONCE));
        cipher.updateAAD(aad);
        return cipher.doFinal(wire, offset + NONCE, wire.length - offset - NONCE);
    }

    private static byte[] concat(byte[]... parts) {
        int length = 0;
        for (byte[] part : parts) length += part.length;
        byte[] result = new byte[length];
        int position = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, result, position, part.length);
            position += part.length;
        }
        return result;
    }
}
