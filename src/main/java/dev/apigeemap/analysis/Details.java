package dev.apigeemap.analysis;

import java.util.Map;

final class Details {

    private Details() {
    }

    static void put(Map<String, String> details, String key, String value) {
        if (value != null && !value.isBlank()) details.put(key, value);
    }
}
