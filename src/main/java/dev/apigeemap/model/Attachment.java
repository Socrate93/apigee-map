package dev.apigeemap.model;

/** Where a policy is attached: endpoint, flow, phase (Request/Response/Fault) and effective condition. */
public record Attachment(String endpointType, String endpoint, String flow, String phase, String condition) {

    public String describe() {
        var sb = new StringBuilder(endpoint).append(" › ").append(flow);
        if (phase != null) sb.append(" › ").append(phase);
        if (condition != null) sb.append("  [").append(condition).append(']');
        return sb.toString();
    }
}
