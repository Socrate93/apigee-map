package dev.apigeemap.model;

import java.util.List;
import java.util.Map;

/**
 * One place in the bundle that creates a dependency (a policy, a proxy endpoint, a target endpoint...).
 * A usage is inactive when it comes from a disabled policy or a policy attached to no flow.
 */
public record Usage(String originType, String origin, boolean active, Map<String, String> details,
                    List<Attachment> attachments) {

    public String label() {
        return originType.equals("policy") ? origin : originType + " " + origin;
    }
}
