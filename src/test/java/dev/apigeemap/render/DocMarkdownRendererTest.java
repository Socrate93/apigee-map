package dev.apigeemap.render;

import dev.apigeemap.migration.ProxyDocs;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DocMarkdownRendererTest {

    private static final ProxyDocs.Doc DOC = new ProxyDocs.Doc("Exposes the orders.\nChecks `<VerifyAPIKey>` first.",
            List.of(new ProxyDocs.Operation("GET", "/orders/{id}", "GetOrder", "Returns one order | or a 404."),
                    new ProxyDocs.Operation("ANY", "", "", "Anything else gets <b>404</b>.")),
            List.of("`VerifyAPIKey` on every operation"),
            List.of(new ProxyDocs.Dependency("orders-backend", "TARGET", "The order service"),
                    new ProxyDocs.Dependency("a`b", "QUEUE", "Odd name")),
            List.of(), List.of("Expects the `orders` KVM"));

    @Test
    void writesTheSectionsOfTheReport() {
        String markdown = new DocMarkdownRenderer().render("orders-api",
                new ProxyDocs.Stored(DOC, "f", Instant.parse("2026-10-30T12:00:00Z")), true);
        assertEquals("""
                # orders-api

                _Written on 2026-10-30._

                Exposes the orders. Checks `<VerifyAPIKey>` first.

                ## Operations

                | Method | Path | Flow | What it does |
                |---|---|---|---|
                | `GET` | `/orders/{id}` | GetOrder | Returns one order \\| or a 404. |
                | `ANY` | `/` |  | Anything else gets &lt;b&gt;404&lt;/b&gt;. |

                ## Security

                - `VerifyAPIKey` on every operation

                ## Dependencies

                | Name | Kind | Used for |
                |---|---|---|
                | `orders-backend` | Target | The order service |
                | ``a`b`` | Other | Odd name |

                ## Good to know

                - Expects the `orders` KVM
                """, markdown);
    }

    @Test
    void saysWhenTheProxyChangedSince() {
        String markdown = new DocMarkdownRenderer().render("orders-api",
                new ProxyDocs.Stored(DOC, "f", Instant.parse("2026-10-30T12:00:00Z")), false);
        assertTrue(markdown.contains("_Written on 2026-10-30. The proxy changed since: it may be out of date._"),
                markdown);
    }
}
