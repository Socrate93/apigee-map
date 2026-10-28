package dev.apigeemap.model;

import java.util.List;

public record BundleReport(
        BundleType type,
        String name,
        String revision,
        String description,
        String path,
        List<Endpoint> endpoints,
        List<Policy> policies,
        List<Dependency> dependencies,
        List<SharedFlowLink> sharedFlows,
        List<Issue> issues) {
}
