package dev.apigeemap.ui;

import dev.apigeemap.analysis.BundleAnalyzer;
import dev.apigeemap.analysis.BundleLocator;
import dev.apigeemap.analysis.SourceMap;
import dev.apigeemap.analysis.VariableFlow;
import dev.apigeemap.analysis.Xml;
import dev.apigeemap.history.SourceHistory;
import dev.apigeemap.migration.Finding;
import dev.apigeemap.migration.FixContext;
import dev.apigeemap.migration.MigrationReport;
import dev.apigeemap.model.BundleReport;
import dev.apigeemap.model.Issue;
import dev.apigeemap.model.Policy;
import dev.apigeemap.render.FixContextRenderer;
import dev.apigeemap.simulation.Simulation;
import dev.apigeemap.simulation.Simulator;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.IOException;
import java.io.StringReader;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Stream;

import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import org.xml.sax.helpers.DefaultHandler;

/**
 * What the Editor page does: lists and reads the files of a proxy, checks what is being typed and saves it. Text that
 * is not saved yet is checked in a throwaway copy of the bundle, so the analysis and the rules run on it as they are.
 * The shared flows of the proxy are shown read-only: they are analyzed from their own folders.
 */
final class EditorService {

    /** Larger files, and those that are not UTF-8 text, are listed but not opened. */
    private static final long MAX_TEXT_SIZE = 1_000_000;
    /** Holds XML the analysis reads; XML under resources/ belongs to scripts and transformations. */
    private static final Set<String> ANALYZED_FOLDERS = Set.of("", "policies", "proxies", "targets", "sharedflows");
    /** Applications, which a request about the proxy does not need. */
    private static final List<String> UNSENT_FOLDERS = List.of("resources/node/", "resources/hosted/");
    /** A proxy is sent with a request when its text files hold at most this many characters. */
    private static final long MAX_COMPOSED = 400_000;

    /** A file of a bundle; {@code text} false when it cannot be opened in the editor. */
    record EditorFile(String path, boolean text) {
    }

    record EditorBundle(String name, boolean editable, List<EditorFile> files) {
    }

    /** A place in a file that needs attention, finding or not well-formed XML. */
    record Problem(String bundle, String file, SourceMap.Span span, String severity, String rule, String location,
                   String message, String action) {
    }

    /**
     * @param analyzed false when the XML is not well-formed, or when the bundle could not be analyzed: {@code
     *                 problems} then holds what stopped it, and the findings of the last check still stand
     * @param general  findings and issues about the proxy as a whole
     * @param outline  the flows and variables of what was checked; null when it could not be analyzed
     */
    record Check(boolean analyzed, List<Problem> problems, List<Problem> general, String error,
                 EditorOutline outline) {
    }

    private final UiService service;
    private final Path historyRoot;

    EditorService(UiService service, Path historyRoot) {
        this.service = service;
        this.historyRoot = historyRoot;
    }

    /** The bundles of the proxy, itself first, with their files. */
    Map<String, Object> workspace(String id) throws IOException {
        List<EditorBundle> bundles = new ArrayList<>();
        Path root = service.bundleDir(id);
        for (Map.Entry<String, Path> bundle : bundles(id).entrySet()) {
            boolean editable = bundle.getValue().equals(root);
            bundles.add(new EditorBundle(bundle.getKey(), editable, files(bundle.getValue())));
        }
        return Map.of("proxy", bundles.get(0).name(), "bundles", bundles, "catalog", PolicyCatalog.ENTRIES,
                "builtIns", VariableFlow.builtIns());
    }

    /**
     * Where the bundles of the proxy are, by name, itself first. A proxy saved with broken XML cannot be analyzed:
     * it still opens, alone and under its id, so that it can be repaired.
     */
    private Map<String, Path> bundles(String id) throws IOException {
        Path root = service.bundleDir(id);
        Map<String, Path> bundles = new LinkedHashMap<>();
        try {
            FixContext.bundles(service.analyzed(id)).values().forEach(bundle ->
                    bundles.put(bundle.name(), Path.of(bundle.path()).toAbsolutePath().normalize()));
        } catch (IOException | RuntimeException e) {
            bundles.put(id, root);
        }
        return bundles;
    }

    private static List<EditorFile> files(Path dir) throws IOException {
        try (Stream<Path> paths = Files.walk(dir)) {
            List<EditorFile> files = new ArrayList<>();
            for (Path file : paths.filter(Files::isRegularFile).sorted().toList()) {
                files.add(new EditorFile(Xml.relativePath(dir, file), text(file) != null));
            }
            return files;
        }
    }

    /** The content of a file, or null when it is too large or not UTF-8 text. */
    private static String text(Path file) throws IOException {
        if (Files.size(file) > MAX_TEXT_SIZE) return null;
        try {
            String text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(Files.readAllBytes(file))).toString();
            return text.indexOf('\0') >= 0 ? null : text;
        } catch (CharacterCodingException e) {
            return null;
        }
    }

    Map<String, Object> read(String id, String bundleName, String path) throws IOException {
        Path bundle = bundles(id).get(bundleName);
        if (bundle == null) throw new UiService.UiException(404, "Unknown bundle " + bundleName);
        Path file = inside(bundle, path);
        String content = Files.isRegularFile(file) ? text(file) : null;
        if (content == null) throw new UiService.UiException(404, "This file cannot be opened: " + path);
        return Map.of("content", content);
    }

    /**
     * Checks the proxy as it would be with {@code {buffers: [{path, content}]}} saved, in a copy of the bundle deleted
     * right after. Answers with the same check whatever the state of the text.
     */
    Check check(String id, Map<?, ?> request) throws IOException {
        String name = bundles(id).keySet().iterator().next();
        return inShadow(id, request, copy -> check(name, copy));
    }

    private Check check(String name, Path copy) throws IOException {
        List<Problem> syntax = syntax(name, copy);
        if (!syntax.isEmpty()) return new Check(false, syntax, List.of(), null, null);
        try {
            BundleReport report = service.analyzer().analyze(BundleLocator.locate(copy));
            return check(report, service.migrate(report));
        } catch (IOException | RuntimeException e) {
            return new Check(false, List.of(), List.of(),
                    String.valueOf(e.getMessage()).replace(copy.toString(), name), null);
        }
    }

    private interface InShadow<T> {
        T run(Path copy) throws IOException;
    }

    /** Runs {@code work} on a copy of the bundle with the {@code buffers} of the request, deleted right after. */
    private <T> T inShadow(String id, Map<?, ?> request, InShadow<T> work) throws IOException {
        Path bundle = service.bundleDir(id);
        Path shadow = Files.createTempDirectory("apigee-map-editor-");
        try {
            Path copy = shadow.resolve(bundle.getFileName().toString());
            copyTree(bundle, copy);
            for (Buffer buffer : buffers(request)) {
                Path file = inside(copy, buffer.path());
                if (buffer.deleted()) {
                    Files.deleteIfExists(file);
                } else {
                    Files.createDirectories(file.getParent());
                    Files.writeString(file, buffer.content());
                }
            }
            return work.run(copy);
        } finally {
            deleteTree(shadow);
        }
    }

    /**
     * Asks the backend about the text being edited, buffers included: to fix {@code {finding: {bundle, rule, location}}}
     * or to answer {@code {request, selection?: {path, text}}}. Nothing is kept or written. Answers {@code {summary,
     * warnings, edits, review}}, or {@code {error}}: {@code review} is what the checks say of the text with the edits.
     */
    Map<String, Object> assist(String id, Map<?, ?> request) throws IOException {
        String name = bundles(id).keySet().iterator().next();
        return inShadow(id, request, copy -> {
            Check before = check(name, copy);
            if (!before.analyzed()) {
                throw new UiService.UiException(409, "Fix the XML of the proxy first: it cannot be analyzed");
            }
            BundleReport report = service.analyzer().analyze(BundleLocator.locate(copy));
            Map<String, Object> answer = request.get("finding") instanceof Map<?, ?> finding
                    ? fix(report, finding) : compose(report, before.outline(), copy, request);
            if (answer.containsKey("error")) return answer;
            @SuppressWarnings("unchecked")
            List<UiService.ProposedEdit> edits = (List<UiService.ProposedEdit>) answer.get("edits");
            for (UiService.ProposedEdit edit : edits) {
                if (!edit.bundle().equals(report.name())) continue;
                Path file = inside(copy, edit.path());
                if (edit.after() == null) {
                    Files.deleteIfExists(file);
                } else {
                    Files.createDirectories(file.getParent());
                    Files.writeString(file, edit.after());
                }
            }
            answer.put("review", review(before, check(name, copy)));
            return answer;
        });
    }

    /** Plays one call through the proxy as it would be with {@code buffers} saved; see {@link Simulator}. */
    Simulation.Result simulate(String id, Map<?, ?> request) throws IOException {
        String name = bundles(id).keySet().iterator().next();
        return inShadow(id, request, copy -> {
            Check check = check(name, copy);
            if (!check.analyzed()) {
                throw new UiService.UiException(409, "Fix the XML of the proxy first: it cannot be analyzed");
            }
            return Simulator.run(service.analyzer().analyze(BundleLocator.locate(copy)), input(request));
        });
    }

    private static Simulation.Input input(Map<?, ?> request) {
        Set<String> failing = new LinkedHashSet<>();
        if (request.get("failing") instanceof List<?> names) names.forEach(n -> failing.add(String.valueOf(n)));
        return new Simulation.Input(string(request, "verb"), string(request, "path"), strings(request, "headers"),
                string(request, "body"), string(request, "status"), string(request, "targetBody"),
                strings(request, "variables"), failing);
    }

    private static String string(Map<?, ?> request, String name) {
        return request.get(name) instanceof String value ? value : null;
    }

    private static Map<String, String> strings(Map<?, ?> request, String name) {
        Map<String, String> values = new LinkedHashMap<>();
        if (request.get(name) instanceof Map<?, ?> map) {
            map.forEach((key, value) -> values.put(String.valueOf(key), String.valueOf(value)));
        }
        return values;
    }

    private Map<String, Object> fix(BundleReport report, Map<?, ?> picked) throws IOException {
        Finding finding = service.migrate(report).findings().stream()
                .filter(f -> f.bundle().equals(picked.get("bundle")) && f.rule().equals(picked.get("rule"))
                        && f.location().equals(picked.get("location")))
                .findFirst().orElseThrow(() -> new UiService.UiException(404, "This finding is gone"));
        FixContext context = FixContext.of(finding, FixContext.bundles(report));
        return service.ask("fix", new FixContextRenderer().model(context), context.files());
    }

    private Map<String, Object> compose(BundleReport report, EditorOutline outline, Path copy, Map<?, ?> request)
            throws IOException {
        if (!(request.get("request") instanceof String asked) || asked.isBlank()) {
            throw new UiService.UiException(400, "Say what you need");
        }
        List<FixContext.SourceFile> files = new ArrayList<>();
        long size = 0;
        for (EditorFile file : files(copy)) {
            if (!file.text() || UNSENT_FOLDERS.stream().anyMatch(file.path()::startsWith)) continue;
            String content = text(copy.resolve(file.path()));
            size += content.length();
            files.add(new FixContext.SourceFile(report.name(), file.path(), content));
        }
        if (size > MAX_COMPOSED) throw new UiService.UiException(413, "This proxy is too large to be sent at once");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("proxy", report.name());
        body.put("request", asked);
        if (request.get("selection") != null) body.put("selection", request.get("selection"));
        body.put("flow", outline.text());
        body.put("files", files);
        return service.ask("compose", body, files);
    }

    /** What changes between two checks: {@code {analyzed, added, resolved}}. */
    private static Map<String, Object> review(Check before, Check after) {
        Map<String, Object> review = new LinkedHashMap<>();
        review.put("analyzed", after.analyzed());
        if (!after.analyzed()) {
            review.put("added", after.problems());
            review.put("resolved", 0);
            return review;
        }
        List<String> had = before.problems().stream().map(EditorService::identity).toList();
        List<String> has = after.problems().stream().map(EditorService::identity).toList();
        review.put("added", after.problems().stream().filter(p -> !had.contains(identity(p))).toList());
        review.put("resolved", had.stream().filter(p -> !has.contains(p)).count());
        return review;
    }

    private static String identity(Problem problem) {
        return problem.rule() + "\u0000" + problem.bundle() + "\u0000" + problem.file() + "\u0000" + problem.location();
    }

    private static Check check(BundleReport report, MigrationReport migration) throws IOException {
        List<Problem> problems = new ArrayList<>();
        List<Problem> general = new ArrayList<>();
        Map<String, BundleReport> bundles = FixContext.bundles(report);
        for (Finding finding : migration.findings()) {
            List<Finding.Subject> placed = placed(finding.subjects());
            if (placed.isEmpty()) general.add(problem(finding, null, null));
            for (Finding.Subject subject : placed) {
                problems.add(problem(finding, subject, subject.span() != null ? subject.span()
                        : start(bundles.get(subject.bundle()), subject.file())));
            }
        }
        for (Issue issue : report.issues()) {
            general.add(new Problem(report.name(), null, null, issue.severity().name(), null, null, issue.message(),
                    null));
        }
        return new Check(true, problems, general, null, EditorOutline.of(report));
    }

    /** One subject per file: a rule that points at a place in a file names the file as a whole too, for its context. */
    private static List<Finding.Subject> placed(List<Finding.Subject> subjects) {
        Map<String, Finding.Subject> byFile = new LinkedHashMap<>();
        for (Finding.Subject subject : subjects) {
            byFile.merge(subject.bundle() + "/" + subject.file(), subject,
                    (first, other) -> first.span() != null ? first : other);
        }
        return List.copyOf(byFile.values());
    }

    private static Problem problem(Finding finding, Finding.Subject subject, SourceMap.Span span) {
        return new Problem(subject == null ? finding.bundle() : subject.bundle(),
                subject == null ? null : subject.file(), span, finding.severity().name(), finding.rule(),
                finding.location(), finding.message(), finding.action());
    }

    /** Where to show a finding about a whole file: its first tag. */
    private static SourceMap.Span start(BundleReport bundle, String file) throws IOException {
        Path path = bundle == null ? null : Path.of(bundle.path()).resolve(file);
        if (path == null || !Files.isRegularFile(path)) return new SourceMap.Span(1, 1, 1, 1);
        return new SourceMap(new String(Files.readAllBytes(path), StandardCharsets.UTF_8)).start();
    }

    /** Where the XML the analysis reads is not well-formed. */
    private static List<Problem> syntax(String bundle, Path dir) throws IOException {
        List<Problem> problems = new ArrayList<>();
        try (Stream<Path> paths = Files.walk(dir, 2)) {
            for (Path file : paths.filter(p -> Files.isRegularFile(p) && p.toString().endsWith(".xml")).sorted().toList()) {
                String path = Xml.relativePath(dir, file);
                int slash = path.lastIndexOf('/');
                if (!ANALYZED_FOLDERS.contains(slash < 0 ? "" : path.substring(0, slash))) continue;
                Problem problem = syntax(bundle, path, new String(Files.readAllBytes(file), StandardCharsets.UTF_8));
                if (problem != null) problems.add(problem);
            }
        }
        return problems;
    }

    private static Problem syntax(String bundle, String path, String text) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            var builder = factory.newDocumentBuilder();
            builder.setErrorHandler(new DefaultHandler());
            builder.parse(new InputSource(new StringReader(text)));
            return null;
        } catch (SAXParseException e) {
            SourceMap.Span at = new SourceMap(text).line(Math.max(1, e.getLineNumber()));
            return new Problem(bundle, path, at == null ? new SourceMap.Span(1, 1, 1, 1) : at, "ERROR", null, null,
                    e.getMessage(), null);
        } catch (SAXException | IOException | javax.xml.parsers.ParserConfigurationException e) {
            return new Problem(bundle, path, new SourceMap.Span(1, 1, 1, 1), "ERROR", null, null, e.getMessage(), null);
        }
    }

    /**
     * Writes {@code {files: [{path, content, base}]}} to the proxy and records them as one step of its history, after
     * the changes made by hand before. Nothing is written when a file is no longer {@code base}, the text it was
     * opened with. A file without {@code base} is new, and must not exist yet.
     */
    synchronized SourceHistory.Step save(String id, Map<?, ?> request) throws IOException {
        Path bundle = service.bundleDir(id);
        List<Buffer> files = buffers(request);
        if (files.isEmpty()) throw new UiService.UiException(400, "Nothing to save");
        Map<Path, String> writes = new LinkedHashMap<>();
        for (Buffer file : files) {
            Path path = inside(bundle, file.path());
            if (file.deleted()) {
                if (!Objects.equals(text(path), file.base())) {
                    throw new UiService.UiException(409, file.path() + " changed since it was opened: reload the page");
                }
            } else if (file.base() == null) {
                if (Files.exists(path)) throw new UiService.UiException(409, file.path() + " already exists");
            } else if (!Files.isRegularFile(path)) {
                throw new UiService.UiException(404, "Unknown file " + file.path());
            } else if (!Objects.equals(text(path), file.base())) {
                throw new UiService.UiException(409, file.path() + " changed since it was opened: reload the page");
            }
            writes.put(path, file.deleted() ? null : file.content());
        }
        try (SourceHistory history = SourceHistory.open(bundle, historyRoot)) {
            history.record("Manual changes");
            for (Map.Entry<Path, String> write : writes.entrySet()) {
                if (write.getValue() == null) {
                    Files.delete(write.getKey());
                } else {
                    Files.createDirectories(write.getKey().getParent());
                    Files.writeString(write.getKey(), write.getValue());
                }
            }
            return history.record(files.size() == 1 ? "Edit " + files.get(0).path() : "Edit " + files.size() + " files");
        }
    }

    /**
     * What renaming a policy of the proxy changes, from the saved files; with {@code apply} true in {@code {from, to,
     * apply}} also writes it, as one step of history.
     */
    synchronized PolicyRename.Plan rename(String id, Map<?, ?> request) throws IOException {
        if (!(request.get("from") instanceof String from) || !(request.get("to") instanceof String to)) {
            throw new UiService.UiException(400, "Missing policy name");
        }
        Path bundle = service.bundleDir(id);
        Policy policy = service.analyzed(id).policies().stream().filter(p -> p.name().equals(from)).findFirst()
                .orElseThrow(() -> new UiService.UiException(404, "Unknown policy " + from));
        Map<String, String> texts = new LinkedHashMap<>();
        for (EditorFile file : files(bundle)) {
            if (file.text()) texts.put(file.path(), text(bundle.resolve(file.path())));
        }
        PolicyRename rename = new PolicyRename(from, to, policy.file());
        PolicyRename.Plan plan = rename.plan(texts);
        if (!Boolean.TRUE.equals(request.get("apply"))) return plan;
        try (SourceHistory history = SourceHistory.open(bundle, historyRoot)) {
            history.record("Manual changes");
            for (Map.Entry<String, String> changed : rename.changed().entrySet()) {
                Files.writeString(bundle.resolve(changed.getKey()), changed.getValue());
            }
            if (!plan.file().equals(policy.file())) {
                Files.move(bundle.resolve(policy.file()), bundle.resolve(plan.file()));
            }
            history.record("Rename policy " + from + " to " + to);
        }
        return plan;
    }

    /** @param deleted true when the file goes away; it then has no content */
    private record Buffer(String path, String content, String base, boolean deleted) {
    }

    private static List<Buffer> buffers(Map<?, ?> request) {
        Object list = request.containsKey("files") ? request.get("files") : request.get("buffers");
        if (!(list instanceof List<?> items)) return List.of();
        List<Buffer> buffers = new ArrayList<>();
        for (Object item : items) {
            if (item instanceof Map<?, ?> map && map.get("path") instanceof String path) {
                boolean deleted = Boolean.TRUE.equals(map.get("deleted"));
                if (!deleted && !(map.get("content") instanceof String)) continue;
                buffers.add(new Buffer(path, map.get("content") instanceof String content ? content : null,
                        map.get("base") instanceof String base ? base : null, deleted));
            }
        }
        return buffers;
    }

    /** A bundle-relative path, refusing anything outside the bundle. */
    private static Path inside(Path dir, String path) {
        if (path == null || path.isBlank()) throw new UiService.UiException(400, "Missing file");
        Path root = dir.toAbsolutePath().normalize();
        Path file = root.resolve(path).normalize();
        if (!file.startsWith(root) || file.equals(root)) throw new UiService.UiException(400, "Not a file of the bundle: " + path);
        return file;
    }

    private static void copyTree(Path source, Path target) throws IOException {
        try (Stream<Path> paths = Files.walk(source)) {
            for (Path path : paths.toList()) {
                Path copy = target.resolve(source.relativize(path).toString());
                if (Files.isDirectory(path)) {
                    Files.createDirectories(copy);
                } else {
                    Files.copy(path, copy);
                }
            }
        }
    }

    private static void deleteTree(Path dir) throws IOException {
        try (Stream<Path> paths = Files.walk(dir)) {
            for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path);
        }
    }
}
