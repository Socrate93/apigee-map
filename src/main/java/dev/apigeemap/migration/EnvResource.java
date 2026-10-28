package dev.apigeemap.migration;

/** Something that must exist in the hybrid organization or environment before the bundles are deployed. */
public record EnvResource(String kind, String name, String details, String requiredBy) {
}
