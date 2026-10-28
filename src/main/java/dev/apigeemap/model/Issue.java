package dev.apigeemap.model;

public record Issue(Severity severity, String message) {

    public enum Severity { ERROR, WARN, INFO }
}
