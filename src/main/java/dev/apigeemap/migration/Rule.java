package dev.apigeemap.migration;

import java.io.IOException;

/**
 * A check run on each bundle; it reports findings and may rewrite the bundle through the workspace.
 * {@code autoFix} tells whether it can rewrite the bundle (disabling the rule disables the fix).
 */
record Rule(String id, Finding.Category category, String title, boolean autoFix, Check check) {

    @FunctionalInterface
    interface Check {
        void run(MigrationContext ctx) throws IOException;
    }

    Rule(String id, Finding.Category category, String title, Check check) {
        this(id, category, title, false, check);
    }

    RuleInfo info() {
        return new RuleInfo(id, category, title, autoFix);
    }
}
