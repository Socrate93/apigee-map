package dev.apigeemap.model;

/** A shared flow called through FlowCallout; {@code report} is set only when it was found and analyzed. */
public record SharedFlowLink(String name, Status status, BundleReport report) {

    public enum Status {
        RESOLVED("resolved"),
        NOT_FOUND("not found"),
        NOT_SEARCHED("not resolved"),
        CYCLE("circular call"),
        ERROR("analysis error");

        private final String label;

        Status(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }
    }
}
