package dev.apigeemap.model;

import java.util.Map;

/** A ProxyEndpoint, TargetEndpoint or SharedFlow with a summary of its configuration. */
public record Endpoint(String type, String name, Map<String, String> properties) {
}
