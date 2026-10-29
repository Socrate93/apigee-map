package dev.apigeemap.protocol;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

class EnvelopeTest {

    private final KeyPair backend = Keys.generate();
    private final String keyId = Keys.keyId(backend.getPublic());

    @Test
    void roundTripsARequestAndItsResponse() throws Exception {
        Envelope.Sealed sealed = Envelope.seal(backend.getPublic(), keyId, bytes("{\"type\":\"fix\"}"));
        assertFalse(new String(sealed.wire(), StandardCharsets.ISO_8859_1).contains("\"type\""));

        Envelope.Opened opened = Envelope.open(backend.getPrivate(), keyId, sealed.wire());
        assertArrayEquals(bytes("{\"type\":\"fix\"}"), opened.plaintext());

        byte[] response = opened.exchange().sealResponse(bytes("proposal"));
        assertArrayEquals(bytes("proposal"), sealed.exchange().openResponse(response));
    }

    @Test
    void rejectsEveryTamperedByte() {
        byte[] wire = Envelope.seal(backend.getPublic(), keyId, bytes("secret payload")).wire();
        for (int i = 0; i < wire.length; i++) {
            byte[] tampered = wire.clone();
            tampered[i] ^= 0x01;
            assertThrows(GeneralSecurityException.class, () -> Envelope.open(backend.getPrivate(), keyId, tampered),
                    "byte " + i);
        }
    }

    @Test
    void rejectsTruncatedRequests() {
        byte[] wire = Envelope.seal(backend.getPublic(), keyId, bytes("payload")).wire();
        for (int length = 0; length < wire.length; length++) {
            byte[] truncated = Arrays.copyOf(wire, length);
            assertThrows(GeneralSecurityException.class, () -> Envelope.open(backend.getPrivate(), keyId, truncated));
        }
    }

    @Test
    void onlyTheBackendKeyOpensARequest() {
        KeyPair other = Keys.generate();
        byte[] wire = Envelope.seal(backend.getPublic(), keyId, bytes("payload")).wire();
        assertThrows(GeneralSecurityException.class, () -> Envelope.open(other.getPrivate(), keyId, wire));
        byte[] foreign = Envelope.seal(other.getPublic(), Keys.keyId(other.getPublic()), bytes("payload")).wire();
        assertThrows(GeneralSecurityException.class, () -> Envelope.open(backend.getPrivate(), keyId, foreign));
    }

    @Test
    void aResponseOnlyOpensWithItsOwnRequest() throws Exception {
        Envelope.Sealed first = Envelope.seal(backend.getPublic(), keyId, bytes("first"));
        Envelope.Sealed second = Envelope.seal(backend.getPublic(), keyId, bytes("second"));
        Envelope.Opened opened = Envelope.open(backend.getPrivate(), keyId, second.wire());
        byte[] response = opened.exchange().sealResponse(bytes("for the second"));

        assertThrows(GeneralSecurityException.class, () -> first.exchange().openResponse(response));
        byte[] tampered = response.clone();
        tampered[tampered.length - 1] ^= 0x01;
        assertThrows(GeneralSecurityException.class, () -> second.exchange().openResponse(tampered));
    }

    @Test
    void keysRoundTripThroughText() {
        KeyPair decoded = new KeyPair(Keys.publicKey(Keys.encode(backend.getPublic())),
                Keys.privateKey(Keys.encode(backend.getPrivate())));
        assertEquals(keyId, Keys.keyId(decoded.getPublic()));
        assertEquals(16, keyId.length());
        assertThrows(IllegalArgumentException.class, () -> Keys.publicKey("not a key"));
        assertEquals(22, Keys.newToken().length());
        assertEquals(64, Keys.tokenHash(Keys.newToken()).length());
    }

    private static byte[] bytes(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }
}
