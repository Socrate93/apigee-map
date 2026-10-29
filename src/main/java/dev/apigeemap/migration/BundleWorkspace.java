package dev.apigeemap.migration;

import dev.apigeemap.analysis.Xml;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.XMLConstants;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.IOException;
import java.io.StringWriter;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * In-memory copy of a bundle that rules read and change. {@link #writeTo(Path)} copies the source folder and applies
 * the changes to the copy (untouched files are copied byte for byte); {@link #applyInPlace()} writes them to the
 * source folder itself.
 */
final class BundleWorkspace {

    private static final Pattern PROLOG = Pattern.compile("^\\s*<\\?xml[^>]*\\?>\\s*");

    private final Path dir;
    private final Map<String, Document> documents = new HashMap<>();
    private final Set<String> modified = new LinkedHashSet<>();
    private final Map<String, String> replaced = new LinkedHashMap<>();
    private final Set<String> deleted = new LinkedHashSet<>();
    private final List<String> changes = new ArrayList<>();

    BundleWorkspace(Path dir) {
        this.dir = dir;
    }

    /** Root element of a bundle file, e.g. {@code root("policies/AM-Auth.xml")}; parsed once, then shared. */
    Element root(String file) throws IOException {
        Document document = documents.get(file);
        if (document == null) {
            document = Xml.parse(dir.resolve(file)).getOwnerDocument();
            documents.put(file, document);
        }
        return document.getDocumentElement();
    }

    /** XML files of a bundle sub-folder ({@code ""} for the descriptor), as bundle-relative paths. */
    List<String> xmlFiles(String folder) throws IOException {
        return Xml.xmlFiles(folder.isEmpty() ? dir : dir.resolve(folder)).stream()
                .map(p -> Xml.relativePath(dir, p))
                .filter(f -> !deleted.contains(f))
                .toList();
    }

    /** All files under resources/{type}/ (e.g. "jsc"), as bundle-relative paths. */
    List<String> resources(String type) throws IOException {
        Path folder = dir.resolve("resources").resolve(type);
        if (!Files.isDirectory(folder)) return List.of();
        try (Stream<Path> files = Files.walk(folder)) {
            return files.filter(Files::isRegularFile).map(p -> Xml.relativePath(dir, p)).sorted().toList();
        }
    }

    boolean exists(String file) {
        return !deleted.contains(file) && Files.isRegularFile(dir.resolve(file));
    }

    String read(String file) throws IOException {
        return Files.readString(dir.resolve(file));
    }

    void modified(String file, String change) {
        modified.add(file);
        changes.add(file + ": " + change);
    }

    void replace(String file, String content, String change) {
        replaced.put(file, content);
        changes.add(file + ": " + change);
    }

    void delete(String file, String change) {
        deleted.add(file);
        changes.add(file + ": " + change);
    }

    boolean isDeleted(String file) {
        return deleted.contains(file);
    }

    List<String> changes() {
        return List.copyOf(changes);
    }

    /** Before/after content of every changed file, without writing anything. */
    List<FileChange> preview() throws IOException {
        Set<String> files = new LinkedHashSet<>(modified);
        files.addAll(replaced.keySet());
        files.addAll(deleted);
        List<FileChange> result = new ArrayList<>();
        for (String file : files) {
            String after = deleted.contains(file) ? null
                    : replaced.containsKey(file) ? matchLineEndings(file, replaced.get(file))
                    : serialize(file);
            result.add(new FileChange(file, read(file), after));
        }
        return result;
    }

    void writeTo(Path target) throws IOException {
        try (Stream<Path> paths = Files.walk(dir)) {
            paths.forEach(source -> copy(source, target.resolve(dir.relativize(source).toString())));
        } catch (UncheckedIOException e) {
            throw e.getCause();
        }
        write(target);
    }

    boolean hasPendingChanges() {
        return !modified.isEmpty() || !replaced.isEmpty() || !deleted.isEmpty();
    }

    /** Writes the changes made so far to the source folder, and goes on from there; returns what changed. */
    List<FileChange> applyInPlace() throws IOException {
        List<FileChange> applied = preview();
        write(dir);
        modified.clear();
        replaced.clear();
        deleted.clear();
        return applied;
    }

    private void write(Path target) throws IOException {
        for (String file : modified) {
            if (!deleted.contains(file) && !replaced.containsKey(file)) {
                Files.writeString(target.resolve(file), serialize(file));
            }
        }
        for (Map.Entry<String, String> entry : replaced.entrySet()) {
            if (!deleted.contains(entry.getKey())) {
                Files.writeString(target.resolve(entry.getKey()), matchLineEndings(entry.getKey(), entry.getValue()));
            }
        }
        for (String file : deleted) Files.deleteIfExists(target.resolve(file));
    }

    private static void copy(Path source, Path destination) {
        try {
            if (Files.isDirectory(source)) {
                Files.createDirectories(destination);
            } else {
                Files.copy(source, destination);
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** Serializes a changed document, keeping the original XML declaration (or its absence). */
    private String serialize(String file) throws IOException {
        Matcher prolog = PROLOG.matcher(Files.readString(dir.resolve(file)));
        try {
            TransformerFactory factory = TransformerFactory.newInstance();
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
            Transformer transformer = factory.newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
            StringWriter out = new StringWriter();
            transformer.transform(new DOMSource(documents.get(file)), new StreamResult(out));
            String body = out.toString();
            return matchLineEndings(file, (prolog.lookingAt() ? prolog.group() : "")
                    + (body.endsWith("\n") ? body : body + "\n"));
        } catch (TransformerException e) {
            throw new IOException("Cannot write " + file + ": " + e.getMessage(), e);
        }
    }

    /**
     * Uses the line endings of the original file: the XML parser turns CRLF into LF, and bundles checked out on
     * Windows are often CRLF, so without this every line of a changed file would differ.
     */
    private String matchLineEndings(String file, String content) throws IOException {
        String lf = content.replace("\r\n", "\n");
        return read(file).contains("\r\n") ? lf.replace("\n", "\r\n") : lf;
    }
}
