package dev.apigeemap.migration;

/**
 * A finding marked as a false positive: left out of the findings, and its auto-fix not applied. It is matched on
 * its rule, bundle and location, not on its message, which may change; it covers every finding of the rule there.
 *
 * @param reason why it is not a problem, shown next to the finding
 */
public record FalsePositive(String rule, String bundle, String location, String reason) {

    public FalsePositive {
        rule = required(rule, "rule");
        bundle = required(bundle, "bundle");
        location = required(location, "location");
        reason = required(reason, "reason");
    }

    public boolean matches(String rule, String bundle, String location) {
        return this.rule.equals(rule) && this.bundle.equals(bundle) && this.location.equals(location);
    }

    /** The same rule, bundle and location. */
    public boolean sameFinding(FalsePositive other) {
        return matches(other.rule, other.bundle, other.location);
    }

    private static String required(String value, String name) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("A false positive needs a " + name);
        return value.trim();
    }

    /** A finding left out by a false positive, with its reason. */
    public record Hidden(Finding finding, String reason) {
    }
}
