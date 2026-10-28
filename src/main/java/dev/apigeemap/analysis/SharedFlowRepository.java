package dev.apigeemap.analysis;

import org.w3c.dom.Element;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

/** Index of local sharedflowbundle/ folders, by declared name and by enclosing folder name. */
public final class SharedFlowRepository {

    private static final int MAX_DEPTH = 5;

    private final Map<String, Path> byName = new LinkedHashMap<>();

    private SharedFlowRepository() {
    }

    public static SharedFlowRepository empty() {
        return new SharedFlowRepository();
    }

    public static SharedFlowRepository scan(List<Path> roots) throws IOException {
        SharedFlowRepository repository = new SharedFlowRepository();
        for (Path root : roots) {
            if (!Files.isDirectory(root)) throw new IOException("Shared flows directory not found: " + root);
            try (Stream<Path> paths = Files.walk(root, MAX_DEPTH)) {
                paths.filter(p -> Files.isDirectory(p) && p.getFileName().toString().equals("sharedflowbundle"))
                        .forEach(repository::register);
            } catch (UncheckedIOException e) {
                throw e.getCause();
            }
        }
        return repository;
    }

    private void register(Path bundleDir) {
        Path dir = bundleDir.toAbsolutePath().normalize();
        try {
            Element descriptor = BundleAnalyzer.descriptor(dir);
            String declared = Xml.attr(descriptor, "name");
            if (declared != null) byName.putIfAbsent(declared, dir);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        if (dir.getParent() != null) byName.putIfAbsent(dir.getParent().getFileName().toString(), dir);
    }

    public boolean isEmpty() {
        return byName.isEmpty();
    }

    /** Every indexed sharedflowbundle/ folder, with its declared (or folder) name. */
    public Map<Path, String> bundles() {
        Map<Path, String> bundles = new LinkedHashMap<>();
        byName.forEach((name, dir) -> bundles.putIfAbsent(dir, name));
        return bundles;
    }

    public Optional<Path> find(String name) {
        return Optional.ofNullable(byName.get(name));
    }
}
