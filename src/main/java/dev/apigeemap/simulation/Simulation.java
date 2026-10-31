package dev.apigeemap.simulation;

import java.util.List;
import java.util.Map;
import java.util.Set;

/** What goes into a simulated call and what comes out of it. */
public final class Simulation {

    /**
     * @param path      as a client calls it, with its query string
     * @param status    what the target answers
     * @param variables values set before the first step, for what comes from outside the proxy (a KVM, a cache...)
     * @param failing   policies to fail, whatever they would do
     */
    public record Input(String verb, String path, Map<String, String> headers, String body, String status,
                        String targetBody, Map<String, String> variables, Set<String> failing) {
    }

    public enum Status {
        /** It ran as Apigee runs it. */
        RAN,
        /** It was not run: its condition is false, or it is disabled. */
        SKIPPED,
        /** It depends on something outside the proxy and is taken to succeed, or to fail when asked. */
        ASSUMED,
        /** The simulator does not run this type of policy: what it does is missing from what follows. */
        NOT_SIMULATED,
        /** It failed. */
        FAILED
    }

    /** A value a step changed; {@code before} or {@code after} is null when it did not exist. */
    public record Change(String name, String before, String after) {
    }

    /**
     * What happened at one place of the flow: a step, a conditional flow or a route.
     *
     * @param type the type of the policy; {@code Flow} or {@code RouteRule}
     * @param file the file of the policy in {@code bundle}; null for a flow or a route
     */
    public record Entry(String bundle, String location, String name, String type, String file, Status status,
                        String condition, String note, List<Change> changes) {
    }

    public record Response(String status, String reason, Map<String, String> headers, String body) {
    }

    /**
     * @param fault    the name of the fault that ended the flow, or null
     * @param warnings what the result does not cover
     */
    public record Result(List<Entry> entries, Response response, String fault, List<String> warnings) {
    }

    private Simulation() {
    }
}
