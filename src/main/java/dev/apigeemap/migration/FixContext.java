package dev.apigeemap.migration;

import dev.apigeemap.analysis.ScriptAnalyzer;
import dev.apigeemap.analysis.VariableFlow;
import dev.apigeemap.analysis.VariableFlow.Read;
import dev.apigeemap.analysis.VariableFlow.Step;
import dev.apigeemap.analysis.Xml;
import dev.apigeemap.model.Attachment;
import dev.apigeemap.model.BundleReport;
import dev.apigeemap.model.Policy;
import org.w3c.dom.Element;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * What it takes to fix one finding by hand, or to ask the backend to: the finding, the policies it is about with where
 * they run and how their variables flow (which steps set what they read, which steps read what they set), and the
 * source files involved. Policies that set or read their variables come with their XML too, not their scripts.
 *
 * <p>The rule declares what the finding is about ({@link Finding#subjects()}): policies bring their scripts and the
 * endpoints they run in; other files (endpoints, resources) come as they are. A finding about the whole bundle gets
 * the bundle descriptor and its endpoints.
 */
public record FixContext(Finding finding, String ruleTitle, List<PolicyContext> policies, List<SourceFile> files) {

    /** @param path bundle-relative, e.g. {@code policies/JS-Audit.xml} */
    public record SourceFile(String bundle, String path, String content) {
    }

    /** @param runs where it is attached, condition included */
    public record PolicyContext(String bundle, String name, String type, String file, List<String> runs,
                                List<VariableRead> reads, List<VariableUse> readBy) {
    }

    /** @param source a {@link VariableFlow.Source} name; {@code steps} set it earlier (SET) or later (SET_LATER) */
    public record VariableRead(String variable, String source, List<String> steps, String note) {
    }

    public record VariableUse(String variable, String step, String location) {
    }

    /** The bundle and the shared flows it calls, by name, as {@link #of} expects them. */
    public static Map<String, BundleReport> bundles(BundleReport root) {
        Map<String, BundleReport> bundles = new LinkedHashMap<>();
        bundles.put(root.name(), root);
        MigrationContext.collect(root, bundles);
        return bundles;
    }

    /** @param bundles the bundle of the finding, and those that hold its related policies */
    public static FixContext of(Finding finding, Map<String, BundleReport> bundles) throws IOException {
        BundleReport bundle = bundles.get(finding.bundle());
        if (bundle == null) throw new IllegalArgumentException("Unknown bundle " + finding.bundle());
        String title = Migrator.rules().stream().filter(r -> r.id().equals(finding.rule())).map(RuleInfo::title)
                .findFirst().orElse(null);
        Builder builder = new Builder(bundles);
        for (Finding.Subject subject : finding.subjects()) {
            BundleReport owner = bundles.get(subject.bundle());
            if (owner == null) continue;
            Policy policy = owner.policies().stream().filter(p -> p.file().equals(subject.file())).findFirst()
                    .orElse(null);
            if (policy != null) {
                builder.policy(owner, policy);
            } else {
                builder.file(owner, subject.file());
            }
        }

        if (builder.files.isEmpty()) {
            builder.file(bundle, descriptor(bundle));
            for (String dir : List.of("proxies", "targets", "sharedflows")) {
                for (Path file : Xml.xmlFiles(Path.of(bundle.path()).resolve(dir))) {
                    builder.file(bundle, Xml.relativePath(Path.of(bundle.path()), file));
                }
            }
        }
        return new FixContext(finding, title, List.copyOf(builder.policies), List.copyOf(builder.files.values()));
    }

    private static String descriptor(BundleReport bundle) throws IOException {
        Path dir = Path.of(bundle.path());
        List<Path> files = Xml.xmlFiles(dir);
        return files.isEmpty() ? null : Xml.relativePath(dir, files.get(0));
    }

    private static final class Builder {

        private final Map<String, BundleReport> bundles;
        private final Map<String, VariableFlow> flows = new LinkedHashMap<>();
        private final List<PolicyContext> policies = new ArrayList<>();
        private final Map<String, SourceFile> files = new LinkedHashMap<>();

        Builder(Map<String, BundleReport> bundles) {
            this.bundles = bundles;
        }

        void policy(BundleReport bundle, Policy policy) throws IOException {
            Path dir = Path.of(bundle.path());
            file(bundle, policy.file());
            Element xml = Xml.parse(dir.resolve(policy.file()));
            Map<String, String> scripts = switch (policy.type()) {
                case "Javascript" -> ScriptAnalyzer.scripts(dir, xml);
                case "Script" -> ScriptAnalyzer.pythonScripts(dir, xml);
                default -> Map.of();
            };
            scripts.forEach((path, source) -> {
                if (!path.equals("inline")) files.putIfAbsent(bundle.name() + "/" + path,
                        new SourceFile(bundle.name(), path, source));
            });
            for (Attachment attachment : policy.attachments()) {
                endpoint(bundle, attachment.endpointType(), attachment.endpoint());
            }

            VariableFlow flow = flow(bundle);
            List<VariableRead> reads = new ArrayList<>();
            for (Read read : flow.readsOf(policy.name())) {
                List<String> steps = read.producers().stream().map(Step::label).distinct().toList();
                VariableRead entry = new VariableRead(read.variable().name(), read.source().name(), steps, read.note());
                if (!reads.contains(entry)) reads.add(entry);
                for (Step producer : read.producers()) related(producer);
            }
            List<VariableUse> readBy = new ArrayList<>();
            for (Read read : flow.consumersOf(policy.name())) {
                VariableUse use = new VariableUse(read.variable().name(), read.step().label(), read.step().location());
                if (!readBy.contains(use)) readBy.add(use);
                related(read.step());
            }
            policies.add(new PolicyContext(bundle.name(), policy.name(), policy.type(), policy.file(),
                    policy.attachments().stream().map(a -> a.endpointType() + " " + a.describe()).distinct().toList(), reads, readBy));
        }

        /** The XML of a policy that sets or reads the variables of a named one. */
        private void related(Step step) throws IOException {
            BundleReport bundle = bundles.get(step.bundle());
            if (bundle == null) return;
            for (Policy policy : bundle.policies()) {
                if (policy.name().equals(step.policy())) file(bundle, policy.file());
            }
        }

        void endpoint(BundleReport bundle, String type, String name) throws IOException {
            String dir = switch (type) {
                case "ProxyEndpoint" -> "proxies";
                case "TargetEndpoint" -> "targets";
                default -> "sharedflows";
            };
            Path root = Path.of(bundle.path());
            for (Path file : Xml.xmlFiles(root.resolve(dir))) {
                if (Xml.nameOf(Xml.parse(file)).equals(name)) file(bundle, Xml.relativePath(root, file));
            }
        }

        void file(BundleReport bundle, String path) throws IOException {
            if (path == null || files.containsKey(bundle.name() + "/" + path)) return;
            Path file = Path.of(bundle.path()).resolve(path).normalize();
            if (!file.startsWith(Path.of(bundle.path()).normalize()) || !Files.isRegularFile(file)) return;
            files.put(bundle.name() + "/" + path, new SourceFile(bundle.name(), path, Files.readString(file)));
        }

        private VariableFlow flow(BundleReport bundle) throws IOException {
            VariableFlow flow = flows.get(bundle.name());
            if (flow == null) {
                flow = VariableFlow.of(bundle);
                flows.put(bundle.name(), flow);
            }
            return flow;
        }
    }
}
