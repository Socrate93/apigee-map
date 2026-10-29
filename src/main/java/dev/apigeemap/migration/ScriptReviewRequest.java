package dev.apigeemap.migration;

import dev.apigeemap.migration.Finding.Subject;
import dev.apigeemap.model.BundleReport;
import dev.apigeemap.model.Issue;
import dev.apigeemap.model.Policy;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/** The scripts of a proxy to review, and what a review of them needs to know. */
public final class ScriptReviewRequest {

    /**
     * A script to review; a source found in several places is reviewed once, at the first of them.
     *
     * @param file the script file, or the policy file of an inline script
     */
    public record Target(String bundle, String policy, String file, boolean inline, String fingerprint) {
    }

    private ScriptReviewRequest() {
    }

    /** The JavaScript run by the active policies of the proxy and of the shared flows it calls, each source once. */
    public static List<Target> scripts(BundleReport root) throws IOException {
        Map<String, Target> targets = new LinkedHashMap<>();
        for (BundleReport bundle : FixContext.bundles(root).values()) {
            for (Scripts.Script script : Scripts.of(bundle)) {
                if (script.python()) continue;
                boolean inline = script.file().equals("inline");
                String file = inline ? policyFile(bundle, script.policy()) : script.file();
                String fingerprint = ScriptReviews.fingerprint(script.source());
                targets.putIfAbsent(fingerprint, new Target(bundle.name(), script.policy(), file, inline, fingerprint));
            }
        }
        return List.copyOf(targets.values());
    }

    /** The policies that run the targets, where they run, how their variables flow, and the files around them. */
    public static FixContext context(BundleReport root, List<Target> targets) throws IOException {
        Map<String, BundleReport> bundles = FixContext.bundles(root);
        List<Subject> subjects = new ArrayList<>();
        for (Target target : targets) {
            BundleReport bundle = bundles.get(target.bundle());
            String policy = policyFile(bundle, target.policy());
            if (policy != null) subjects.add(new Subject(target.bundle(), policy));
        }
        Finding review = new Finding("REV-01", Finding.Category.DESIGN, Issue.Severity.INFO, root.name(), "scripts",
                "Script review", "", Finding.Fix.MANUAL, subjects);
        return FixContext.of(review, bundles);
    }

    /** The findings about the targets or their policies, so that the review does not repeat them. */
    public static List<Finding> known(List<Finding> findings, FixContext context) {
        Set<String> files = context.policies().stream().map(p -> p.bundle() + "/" + p.file())
                .collect(Collectors.toSet());
        context.files().stream().filter(f -> f.path().startsWith("resources/jsc/"))
                .forEach(f -> files.add(f.bundle() + "/" + f.path()));
        return findings.stream().filter(f -> !f.rule().equals("REV-01"))
                .filter(f -> f.subjects().stream().anyMatch(s -> files.contains(s.bundle() + "/" + s.file())))
                .toList();
    }

    private static String policyFile(BundleReport bundle, String name) {
        if (bundle == null) return null;
        return bundle.policies().stream().filter(p -> p.name().equals(name)).map(Policy::file).findFirst()
                .orElse(null);
    }
}
