package dev.apigeemap.protocol;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The app (apigee-map) and the backend (apigee-map-backend) each carry a copy of this package. This test, identical
 * in both repositories, opens a request and its response sealed once with a fixed key: if one copy changes the wire
 * format, its test fails until the other copy follows. The key is a test key, used nowhere else.
 */
class ProtocolVectorTest {

    private static final String PRIVATE_KEY = "MC4CAQAwBQYDK2VuBCIEIC48s2gQXZULsUlcHFlxPxXZaj++7NPqkMGIhrSuKQyV";
    private static final String PUBLIC_KEY = "MCowBQYDK2VuAyEAAMpW4Q5tX5hHb6Rm+tFNUsGzdFA2galoTDW7rBgWsGo=";
    private static final String REQUEST = "ARA2ZGQ2ZmZmYjFkYzA3MmRikTzXA7K/bYO3aCv81lAoL60z4Hgr2r24Wk2crZCKn19oXipzN/57"
            + "TLM+qSLqaQgwboxhNxfyO6BrIY9k9Rlr7zrq3GeqJT/BDWhKkkk=";
    private static final String RESPONSE = "ARGhr/T7Cz4sTcDTJF2x/dz+dZ6/yKiGr6UGAspi0JuiwUIHjlCTAQ==";

    @Test
    void opensTheReferenceExchange() throws Exception {
        String keyId = Keys.keyId(Keys.publicKey(PUBLIC_KEY));
        assertEquals("6dd6fffb1dc072db", keyId);

        Envelope.Opened opened = Envelope.open(Keys.privateKey(PRIVATE_KEY), keyId, Base64.getDecoder().decode(REQUEST));
        assertEquals("{\"type\":\"vector\"}", new String(opened.plaintext(), StandardCharsets.UTF_8));
        byte[] response = opened.exchange().openResponse(Base64.getDecoder().decode(RESPONSE));
        assertEquals("{\"ok\":true}", new String(response, StandardCharsets.UTF_8));
    }
}
