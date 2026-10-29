package dev.apigeemap.history;

import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.ResetCommand;
import org.eclipse.jgit.api.RevertCommand;
import org.eclipse.jgit.api.Status;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.eclipse.jgit.diff.DiffEntry;
import org.eclipse.jgit.diff.DiffFormatter;
import org.eclipse.jgit.diff.RawTextComparator;
import org.eclipse.jgit.lib.Constants;
import org.eclipse.jgit.lib.ObjectId;
import org.eclipse.jgit.lib.ObjectReader;
import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.lib.StoredConfig;
import org.eclipse.jgit.revwalk.RevCommit;
import org.eclipse.jgit.revwalk.RevWalk;
import org.eclipse.jgit.storage.file.FileRepositoryBuilder;
import org.eclipse.jgit.treewalk.AbstractTreeIterator;
import org.eclipse.jgit.treewalk.CanonicalTreeParser;
import org.eclipse.jgit.treewalk.EmptyTreeIterator;
import org.eclipse.jgit.util.FileUtils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * History of a bundle changed in place, step by step, as a git repository: the first step is the bundle as it
 * was, each change made since is a step that can be shown as a diff or reverted.
 *
 * <p>The repository lives outside the bundle ({@code <root>/<name>-<hash of its path>.git}, the bundle being its
 * work tree), so it never ends up in a migrated bundle nor in a repository the bundle is already part of. Its
 * history is tied to the path of the bundle: a bundle moved elsewhere starts a new one.
 */
public final class SourceHistory implements AutoCloseable {

    public static final String ORIGINAL = "Original";

    /** @param id abbreviated commit id; {@code files} are the bundle-relative paths the step changes */
    public record Step(String id, String message, Instant time, List<String> files) {

        /** First line of the message. */
        public String title() {
            int end = message.indexOf('\n');
            return (end < 0 ? message : message.substring(0, end)).strip();
        }
    }

    private final Path bundle;
    private final Git git;

    private SourceHistory(Path bundle, Git git) {
        this.bundle = bundle;
        this.git = git;
    }

    public static Path defaultRoot() {
        return Path.of(System.getProperty("user.home"), ".apigee-map", "history");
    }

    /** Whether the bundle folder has a history in {@code root}, without starting one. */
    public static boolean exists(Path bundle, Path root) {
        return Files.isDirectory(root.toAbsolutePath().normalize().resolve(key(bundle.toAbsolutePath().normalize())));
    }

    /** Opens the history of a bundle folder, starting it with the bundle as it is now when there is none yet. */
    public static SourceHistory open(Path bundle, Path root) throws IOException {
        Path dir = bundle.toAbsolutePath().normalize();
        if (!Files.isDirectory(dir)) throw new IOException("Not a folder: " + bundle);
        Path gitDir = root.toAbsolutePath().normalize().resolve(key(dir));
        if (Files.isDirectory(gitDir)) {
            Repository repository = new FileRepositoryBuilder().setGitDir(gitDir.toFile()).setWorkTree(dir.toFile())
                    .setMustExist(true).build();
            return new SourceHistory(dir, new Git(repository));
        }
        Files.createDirectories(gitDir.getParent());
        Repository repository = new FileRepositoryBuilder().setGitDir(gitDir.toFile()).setWorkTree(dir.toFile())
                .build();
        try {
            repository.create();
            // the link to the repository it leaves in the bundle would end up in migrated bundles
            Files.deleteIfExists(dir.resolve(Constants.DOT_GIT));
            repository.getRefDatabase().newUpdate(Constants.HEAD, false).link("refs/heads/main");
            StoredConfig config = repository.getConfig();
            // independent of the git settings of the machine: same content, same author, no signing
            config.setBoolean("core", null, "autocrlf", false);
            config.setString("user", null, "name", "apigee-map");
            config.setString("user", null, "email", "apigee-map@localhost");
            config.setBoolean("commit", null, "gpgSign", false);
            config.save();
            Path exclude = gitDir.resolve("info/exclude");
            Files.createDirectories(exclude.getParent());
            Files.writeString(exclude, ".DS_Store\nThumbs.db\n");
            SourceHistory history = new SourceHistory(dir, new Git(repository));
            history.commit(ORIGINAL, true);
            return history;
        } catch (IOException | RuntimeException e) {
            // a history without its original state would be opened as it is next time
            repository.close();
            FileUtils.delete(gitDir.toFile(), FileUtils.RECURSIVE | FileUtils.IGNORE_ERRORS);
            throw e;
        }
    }

    public Path bundle() {
        return bundle;
    }

    /** Files changed, added or removed since the last step, not recorded yet. */
    public Set<String> pendingChanges() throws IOException {
        try {
            Status status = git.status().call();
            Set<String> files = new TreeSet<>(status.getUncommittedChanges());
            files.addAll(status.getUntracked());
            return files;
        } catch (GitAPIException e) {
            throw new IOException(e.getMessage(), e);
        }
    }

    /** Records the changes made since the last step as a new step; null when nothing changed. */
    public Step record(String message) throws IOException {
        return commit(message, false);
    }

    /** Newest first; the last one is {@link #ORIGINAL}. */
    public List<Step> steps() throws IOException {
        List<Step> steps = new ArrayList<>();
        try {
            for (RevCommit commit : git.log().call()) steps.add(step(commit));
        } catch (GitAPIException e) {
            throw new IOException(e.getMessage(), e);
        }
        return steps;
    }

    /** Unified diff of what a step changed. */
    public String diff(String step) throws IOException {
        try (RevWalk walk = new RevWalk(git.getRepository())) {
            RevCommit commit = walk.parseCommit(resolve(step));
            return format(parentTree(commit), tree(commit.getTree()));
        }
    }

    /** Unified diff of every recorded step since {@link #ORIGINAL}. */
    public String diffSinceOriginal() throws IOException {
        try (RevWalk walk = new RevWalk(git.getRepository())) {
            RevCommit head = walk.parseCommit(resolve("HEAD"));
            RevCommit original = head;
            while (original.getParentCount() > 0) original = walk.parseCommit(original.getParent(0));
            return format(tree(original.getTree()), tree(head.getTree()));
        }
    }

    /**
     * Undoes a step with a new step. The bundle must have no pending change; when a later step changes the same
     * lines, nothing is changed and an {@link IOException} says which files conflict.
     */
    public Step revert(String step) throws IOException {
        if (!pendingChanges().isEmpty()) {
            throw new IOException("The bundle has changes not recorded yet: record them before reverting a step");
        }
        try (RevWalk walk = new RevWalk(git.getRepository())) {
            RevCommit commit = walk.parseCommit(resolve(step));
            if (commit.getParentCount() == 0) throw new IOException("The original state cannot be reverted");
            RevertCommand revert = git.revert().include(commit);
            RevCommit done = revert.call();
            List<String> conflicts = revert.getUnmergedPaths() == null ? List.of() : revert.getUnmergedPaths();
            if (done == null || revert.getFailingResult() != null || !conflicts.isEmpty()) {
                git.reset().setMode(ResetCommand.ResetType.HARD).setRef("HEAD").call();
                throw new IOException("Step " + step + " cannot be reverted: " + (conflicts.isEmpty()
                        ? String.valueOf(revert.getFailingResult())
                        : "later steps change the same lines of " + String.join(", ", conflicts)));
            }
            return step(walk.parseCommit(done));
        } catch (GitAPIException e) {
            throw new IOException("Cannot revert " + step + ": " + e.getMessage(), e);
        }
    }

    @Override
    public void close() {
        git.getRepository().close();
        git.close();
    }

    private Step commit(String message, boolean always) throws IOException {
        try {
            if (!always && git.status().call().isClean()) return null;
            git.add().addFilepattern(".").call();
            git.add().addFilepattern(".").setUpdate(true).call();
            RevCommit commit = git.commit().setMessage(message).setAllowEmpty(true).setSign(false).call();
            try (RevWalk walk = new RevWalk(git.getRepository())) {
                return step(walk.parseCommit(commit));
            }
        } catch (GitAPIException e) {
            throw new IOException("Cannot record " + message + ": " + e.getMessage(), e);
        }
    }

    private Step step(RevCommit commit) throws IOException {
        List<String> files = new ArrayList<>();
        try (DiffFormatter formatter = formatter(OutputStream.nullOutputStream())) {
            for (DiffEntry entry : formatter.scan(parentTree(commit), tree(commit.getTree()))) {
                files.add(entry.getChangeType() == DiffEntry.ChangeType.DELETE ? entry.getOldPath() : entry.getNewPath());
            }
        }
        return new Step(commit.abbreviate(7).name(), commit.getFullMessage().strip(),
                Instant.ofEpochSecond(commit.getCommitTime()), files);
    }

    private ObjectId resolve(String step) throws IOException {
        ObjectId id = git.getRepository().resolve(step + "^{commit}");
        if (id == null) throw new IOException("Unknown step " + step);
        return id;
    }

    private AbstractTreeIterator parentTree(RevCommit commit) throws IOException {
        if (commit.getParentCount() == 0) return new EmptyTreeIterator();
        try (RevWalk walk = new RevWalk(git.getRepository())) {
            return tree(walk.parseCommit(commit.getParent(0)).getTree());
        }
    }

    private AbstractTreeIterator tree(ObjectId tree) throws IOException {
        try (ObjectReader reader = git.getRepository().newObjectReader()) {
            return new CanonicalTreeParser(null, reader, tree);
        }
    }

    private String format(AbstractTreeIterator before, AbstractTreeIterator after) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (DiffFormatter formatter = formatter(out)) {
            formatter.format(before, after);
        }
        return out.toString(StandardCharsets.UTF_8);
    }

    private DiffFormatter formatter(OutputStream out) {
        DiffFormatter formatter = new DiffFormatter(out);
        formatter.setRepository(git.getRepository());
        formatter.setDiffComparator(RawTextComparator.DEFAULT);
        formatter.setDetectRenames(true);
        return formatter;
    }

    /** e.g. {@code orders-api-3f9c2a1b.git} for {@code .../orders-api/apiproxy}. */
    private static String key(Path dir) {
        String name = dir.getFileName().toString();
        if ((name.equals("apiproxy") || name.equals("sharedflowbundle")) && dir.getParent() != null) {
            name = dir.getParent().getFileName().toString();
        }
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(dir.toString().getBytes(StandardCharsets.UTF_8));
            return name + "-" + HexFormat.of().formatHex(hash, 0, 4) + ".git";
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
