package dev.apigeemap.model;

import java.util.List;

public record Policy(String name, String type, String file, boolean enabled, List<Attachment> attachments) {

    public boolean attached() {
        return !attachments.isEmpty();
    }

    public boolean active() {
        return enabled && attached();
    }
}
