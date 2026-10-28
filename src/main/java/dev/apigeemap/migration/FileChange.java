package dev.apigeemap.migration;

/** A bundle file the migration changes: {@code after} is null when the file is removed. */
public record FileChange(String path, String before, String after) {
}
