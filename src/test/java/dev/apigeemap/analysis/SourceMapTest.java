package dev.apigeemap.analysis;

import dev.apigeemap.analysis.SourceMap.Span;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Element;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class SourceMapTest {

    @TempDir
    Path tmp;

    @Test
    void marksEachElementWithWhereItIs() throws IOException {
        String text = """
                <?xml version="1.0"?>
                <!-- <NotAnElement> -->
                <Root name="a>b">
                  <One>text</One>
                  <![CDATA[ <Nor> ]]>
                  <Two a="1"
                       b="2">
                    <Three/>
                  </Two>
                </Root>
                """;
        Element root = parseAndMark(text);

        assertEquals(new Span(3, 1, 3, 18), SourceMap.spanOf(root), "the start tag of an element on several lines");
        assertEquals(new Span(4, 3, 4, 18), SourceMap.spanOf(Xml.path(root, "One")), "a whole element on one line");
        assertEquals(new Span(6, 3, 7, 14), SourceMap.spanOf(Xml.path(root, "Two")));
        assertEquals(new Span(8, 5, 8, 13), SourceMap.spanOf(Xml.path(root, "Two", "Three")));
    }

    @Test
    void countsLinesTheSameWithWindowsLineEndings() throws IOException {
        Element root = parseAndMark("<Root>\r\n  <One/>\r\n</Root>\r\n");

        assertEquals(new Span(2, 3, 2, 9), SourceMap.spanOf(Xml.path(root, "One")));
        assertEquals(new Span(2, 3, 2, 9), new SourceMap("<Root>\r\n  <One/>\r\n</Root>\r\n").line(2));
    }

    @Test
    void toleratesMalformedXml() {
        assertEquals(new Span(1, 1, 1, 7), new SourceMap("<Root>\n  <One></Two>\n  <Unfinished a=\"").start());
        assertEquals(new Span(1, 1, 1, 8), new SourceMap("no tags\nat all").start());
    }

    @Test
    void findsTextAndLines() {
        SourceMap map = new SourceMap("first\n  second one\n");

        assertEquals(new Span(2, 3, 2, 9), map.find("second"));
        assertNull(map.find("third"));
        assertEquals(new Span(2, 3, 2, 13), map.line(2));
        assertNull(map.line(9));
    }

    @Test
    void anElementTheTextDoesNotMatchHasNoSpan() {
        assertNull(SourceMap.spanOf(null));
    }

    private Element parseAndMark(String text) throws IOException {
        Path file = tmp.resolve("file.xml");
        Files.writeString(file, text);
        Element root = Xml.parse(file);
        new SourceMap(text).mark(root);
        return root;
    }
}
