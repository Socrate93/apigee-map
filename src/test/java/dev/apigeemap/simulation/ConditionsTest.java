package dev.apigeemap.simulation;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConditionsTest {

    private static final Map<String, String> VARIABLES = Map.of("request.verb", "GET", "proxy.pathsuffix", "/orders/12",
            "count", "10", "cache.hit", "false", "name", "Orders", "my-var", "x");

    private static boolean test(String condition) {
        return Conditions.test(condition, VARIABLES::get);
    }

    @Test
    void comparesVariablesAndLiterals() {
        assertTrue(test("request.verb = \"GET\""));
        assertTrue(test("request.verb != 'POST'"));
        assertTrue(test("count = 10.0"));
        assertTrue(test("count > 9"));
        assertTrue(test("count GreaterThanOrEquals 10"));
        assertFalse(test("count LesserThan 3"));
        assertTrue(test("name EqualsCaseInsensitive \"orders\""));
        assertTrue(test("name := \"ORDERS\""));
        assertTrue(test("my-var = \"x\""));
        assertTrue(test("cache.hit = false"));
    }

    @Test
    void aVariableWithoutValueIsNull() {
        assertTrue(test("missing = null"));
        assertFalse(test("missing = \"x\""));
        assertTrue(test("missing != \"x\""));
        assertFalse(test("missing"));
        assertTrue(test("request.verb"));
        assertFalse(test("cache.hit"));
    }

    @Test
    void matchesPathsAndPatterns() {
        assertTrue(test("proxy.pathsuffix MatchesPath \"/orders/*\""));
        assertFalse(test("proxy.pathsuffix MatchesPath \"/*\""));
        assertTrue(test("proxy.pathsuffix ~/ \"/**\""));
        assertTrue(test("proxy.pathsuffix Matches \"/orders*\""));
        assertTrue(test("proxy.pathsuffix JavaRegex \"/orders/[0-9]+\""));
        assertTrue(test("proxy.pathsuffix ~~ \".*12\""));
        assertTrue(test("proxy.pathsuffix StartsWith \"/orders\""));
    }

    @Test
    void combinesWithPrecedenceAndParentheses() {
        assertTrue(test("(proxy.pathsuffix MatchesPath \"/orders/*\") and (request.verb = \"GET\")"));
        assertTrue(test("request.verb = \"POST\" or request.verb = \"GET\" and count = 10"));
        assertFalse(test("(request.verb = \"POST\" or request.verb = \"GET\") and count = 3"));
        assertTrue(test("not (request.verb = \"POST\")"));
        assertTrue(test("!(request.verb = \"POST\") && count = 10"));
    }

    @Test
    void refusesWhatItCannotRead() {
        assertThrows(IllegalArgumentException.class, () -> test("(request.verb = \"GET\""));
        assertThrows(IllegalArgumentException.class, () -> test("request.verb = "));
        assertThrows(IllegalArgumentException.class, () -> test("request.verb = \"GET"));
    }
}
