package dev.apigeemap.migration;

import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static dev.apigeemap.migration.Finding.Category.DESIGN;

/** Remarks of the script reviews ({@link ScriptReviews}), reported for the scripts reviewed as they are now. */
final class ReviewRules {

    private ReviewRules() {
    }

    static List<Rule> all() {
        return List.of(new Rule("REV-01", DESIGN, "Script review", ReviewRules::scriptReview));
    }

    /** Each remark is a manual finding in its own category, at {@code <script>:<line> <title>}. */
    private static void scriptReview(MigrationContext ctx) throws IOException {
        Set<String> locations = new HashSet<>();
        for (Scripts.Script script : Scripts.of(ctx.report)) {
            if (script.python()) continue;
            List<ScriptReviews.Remark> remarks = ctx.reviews.get(ScriptReviews.fingerprint(script.source()))
                    .orElse(List.of());
            String file = script.file().equals("inline") ? script.policy() + " (inline)" : script.file();
            for (ScriptReviews.Remark remark : remarks) {
                String where = file + (remark.line() > 0 ? ":" + remark.line() : "") + " " + remark.title();
                String location = where;
                for (int n = 2; !locations.add(location); n++) location = where + " (" + n + ")";
                ctx.manual(remark.category(), remark.severity(), location, remark.message(), remark.action(),
                        ctx.on(script, remark.line()));
            }
        }
    }
}
