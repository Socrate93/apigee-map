package dev.apigeemap.model;

import java.util.List;

/** An external resource the bundle needs at runtime. {@code dynamic} means the name is resolved from a variable. */
public record Dependency(DependencyKind kind, String name, boolean dynamic, List<Usage> usages) {

    public boolean active() {
        return usages.stream().anyMatch(Usage::active);
    }
}
