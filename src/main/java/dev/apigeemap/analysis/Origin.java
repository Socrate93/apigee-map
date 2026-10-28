package dev.apigeemap.analysis;

import dev.apigeemap.model.Attachment;
import dev.apigeemap.model.Usage;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** The element currently being analyzed; turns into a {@link Usage} for each dependency it declares. */
record Origin(String type, String name, boolean active, List<Attachment> attachments) {

    Usage usage(Map<String, String> details) {
        return new Usage(type, name, active, Collections.unmodifiableMap(new LinkedHashMap<>(details)), attachments);
    }
}
