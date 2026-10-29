package dev.apigeemap.history;

import org.eclipse.jgit.diff.DiffAlgorithm;
import org.eclipse.jgit.diff.DiffFormatter;
import org.eclipse.jgit.diff.EditList;
import org.eclipse.jgit.diff.RawText;
import org.eclipse.jgit.diff.RawTextComparator;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;

/** Unified diffs of two versions of a file, in the format of {@link SourceHistory#diff}. */
public final class Diffs {

    private Diffs() {
    }

    /** @param before null for a new file; {@code after} null for a removed one */
    public static String unified(String path, String before, String after) {
        RawText a = new RawText(bytes(before));
        RawText b = new RawText(bytes(after));
        EditList edits = DiffAlgorithm.getAlgorithm(DiffAlgorithm.SupportedAlgorithm.HISTOGRAM)
                .diff(RawTextComparator.DEFAULT, a, b);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (DiffFormatter formatter = new DiffFormatter(out)) {
            out.writeBytes(("--- " + (before == null ? "/dev/null" : "a/" + path) + "\n+++ "
                    + (after == null ? "/dev/null" : "b/" + path) + "\n").getBytes(StandardCharsets.UTF_8));
            formatter.format(edits, a, b);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return out.toString(StandardCharsets.UTF_8);
    }

    private static byte[] bytes(String text) {
        return text == null ? new byte[0] : text.getBytes(StandardCharsets.UTF_8);
    }
}
