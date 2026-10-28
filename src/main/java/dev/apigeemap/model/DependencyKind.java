package dev.apigeemap.model;

public enum DependencyKind {
    VIRTUAL_HOST("Virtual host", "Virtual hosts"),
    SHARED_FLOW("Shared flow", "Shared flows"),
    TARGET_SERVER("Target server", "Target servers"),
    TARGET_URL("URL", "URLs"),
    LOCAL_PROXY("Chained proxy", "Chained proxies"),
    KVM("KVM", "Key value maps"),
    CACHE("Cache", "Caches"),
    KEYSTORE("Keystore", "Keystores"),
    TRUSTSTORE("Truststore", "Truststores"),
    RESOURCE("Resource", "Resources"),
    SYSLOG("Syslog", "Syslog endpoints");

    private final String label;
    private final String plural;

    DependencyKind(String label, String plural) {
        this.label = label;
        this.plural = plural;
    }

    public String label() {
        return label;
    }

    public String plural() {
        return plural;
    }
}
