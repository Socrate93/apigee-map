package dev.apigeemap.model;

public enum BundleType {
    API_PROXY("API proxy"),
    SHARED_FLOW("Shared flow");

    private final String label;

    BundleType(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }
}
