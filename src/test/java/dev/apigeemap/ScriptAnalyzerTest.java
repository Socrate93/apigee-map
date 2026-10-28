package dev.apigeemap;

import dev.apigeemap.analysis.ScriptAnalyzer;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScriptAnalyzerTest {

    @Test
    void readsVariablesThroughAliasesAndIgnoresComments() {
        ScriptAnalyzer.Facts facts = ScriptAnalyzer.analyze("""
                // context.getVariable("commented.out")
                var c = context;
                var a = c.getVariable("order.id");
                context.setVariable("order.checked", "true");
                context.removeVariable("tmp");
                var label = "context.getVariable('in.a.string')";
                """, "a.js");
        assertNull(facts.error());
        assertEquals(List.of("order.id"), facts.reads());
        assertEquals(List.of("order.checked", "tmp"), facts.writes());
        assertFalse(facts.dynamicReads());
    }

    @Test
    void findsCallsAndComputedNames() {
        ScriptAnalyzer.Facts facts = ScriptAnalyzer.analyze("""
                var name = "x." + 1;
                context.setVariable(name, context.getVariable("prefix." + name));
                var exchange = httpClient.get("https://stock.internal/items/" + context.getVariable("sku"));
                httpClient.send(new Request("http://localhost:7000/audit", "POST"));
                exchange.waitForComplete();
                """, "b.js");
        assertTrue(facts.dynamicReads());
        assertTrue(facts.dynamicWrites());
        assertEquals(List.of("https://stock.internal/items/{…}", "http://localhost:7000/audit"), facts.urls());
        assertTrue(facts.httpClient());
        assertTrue(facts.waits());
    }

    @Test
    void acceptsTopLevelReturnAndReportsSyntaxErrorsInEnglish() {
        assertNull(ScriptAnalyzer.analyze("if (!context.getVariable(\"a\")) return;\n", "c.js").error());
        assertEquals("line 1: missing ) after condition",
                ScriptAnalyzer.analyze("if (true { x(); }", "d.js").error());
    }
}
