package dev.apigeemap.analysis;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/** Accepts an apiproxy/ or sharedflowbundle/ folder, its parent folder, or an exported bundle zip. */
public final class BundleLocator {

    private static final List<String> BUNDLE_DIRS = List.of("apiproxy", "sharedflowbundle");

    private BundleLocator() {
    }

    public static Path locate(Path input) throws IOException {
        Path path = input.toAbsolutePath().normalize();
        if (!Files.exists(path)) throw new IOException("Not found: " + input);
        if (Files.isRegularFile(path) && path.getFileName().toString().toLowerCase().endsWith(".zip")) {
            return locate(unzip(path));
        }
        if (!Files.isDirectory(path)) throw new IOException("Expected a bundle folder or a .zip: " + input);
        if (BUNDLE_DIRS.contains(path.getFileName().toString()) || looksLikeBundle(path)) return path;
        for (String candidate : BUNDLE_DIRS) {
            if (Files.isDirectory(path.resolve(candidate))) return path.resolve(candidate);
        }
        throw new IOException("No apiproxy/ or sharedflowbundle/ folder in " + input);
    }

    private static boolean looksLikeBundle(Path dir) {
        return Files.isDirectory(dir.resolve("policies"))
                && (Files.isDirectory(dir.resolve("proxies")) || Files.isDirectory(dir.resolve("sharedflows")));
    }

    private static Path unzip(Path zip) throws IOException {
        Path target = Files.createTempDirectory("apigee-map-");
        try (InputStream in = Files.newInputStream(zip); ZipInputStream entries = new ZipInputStream(in)) {
            for (ZipEntry entry; (entry = entries.getNextEntry()) != null; ) {
                Path out = target.resolve(entry.getName()).normalize();
                if (!out.startsWith(target)) throw new IOException("Unsafe zip entry: " + entry.getName());
                if (entry.isDirectory()) {
                    Files.createDirectories(out);
                } else {
                    Files.createDirectories(out.getParent());
                    Files.copy(entries, out);
                }
            }
        }
        return target;
    }
}
