package dev.apigeemap.analysis;

import dev.apigeemap.model.Dependency;
import dev.apigeemap.model.DependencyKind;
import dev.apigeemap.model.Usage;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Merges usages of the same (kind, name) into a single dependency. */
final class DependencyCollector {

    private record Key(DependencyKind kind, String name) {
    }

    private final Map<Key, List<Usage>> usages = new LinkedHashMap<>();

    void add(DependencyKind kind, String name, Usage usage) {
        usages.computeIfAbsent(new Key(kind, name), k -> new ArrayList<>()).add(usage);
    }

    List<Dependency> build() {
        return usages.entrySet().stream()
                .map(e -> new Dependency(e.getKey().kind(), e.getKey().name(), e.getKey().name().contains("{"),
                        List.copyOf(e.getValue())))
                .sorted(Comparator.comparing(Dependency::kind))
                .toList();
    }
}
