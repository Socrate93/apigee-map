package dev.apigeemap.analysis;

import org.w3c.dom.Element;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.List;

/**
 * Where things are in the text of a file. The DOM keeps no positions, so {@link #mark} walks the tags of the text
 * next to the elements of a parsed document and leaves each element its {@link Span}, which stays with it when rules
 * move or remove elements. The scan of the tags tolerates malformed XML: it reports what it could read.
 */
public final class SourceMap {

    /** A range of a file: lines and columns start at 1, and the end is exclusive. */
    public record Span(int line, int column, int endLine, int endColumn) {
    }

    private static final String SPAN = "apigee-map.span";

    private static final class Tag {
        final String name;
        final int start;
        final int startEnd;
        final List<Tag> children = new ArrayList<>();
        int end;

        Tag(String name, int start, int startEnd) {
            this.name = name;
            this.start = start;
            this.startEnd = startEnd;
            this.end = startEnd;
        }
    }

    private final String text;
    private final int[] lines;

    public SourceMap(String text) {
        this.text = text;
        this.lines = lineStarts(text);
    }

    /** What {@link #mark} left on the element, or null. */
    public static Span spanOf(Element element) {
        return element == null ? null : (Span) element.getUserData(SPAN);
    }

    /** Marks the elements of a document parsed from this text; those the text does not match are left unmarked. */
    public void mark(Element root) {
        Tag tag = root();
        if (tag != null) mark(root, tag);
    }

    private void mark(Element element, Tag tag) {
        if (!element.getTagName().equals(tag.name)) return;
        element.setUserData(SPAN, span(tag), null);
        List<Element> children = Xml.children(element);
        for (int i = 0; i < Math.min(children.size(), tag.children.size()); i++) {
            mark(children.get(i), tag.children.get(i));
        }
    }

    /** The first tag of the text, or the first line of a text that holds none. */
    public Span start() {
        Tag root = root();
        return root != null ? span(root.start, root.startEnd) : line(1);
    }

    /** First occurrence of the text, or null. */
    public Span find(String needle) {
        int at = needle.isEmpty() ? -1 : text.indexOf(needle);
        return at < 0 ? null : span(at, at + needle.length());
    }

    /** A line without its indentation, or null when the text has no such line. */
    public Span line(int number) {
        if (number < 1 || number > lines.length) return null;
        int start = lines[number - 1];
        int end = number < lines.length ? lines[number] - 1 : text.length();
        if (end > start && text.charAt(end - 1) == '\r') end--;
        int first = start;
        while (first < end && Character.isWhitespace(text.charAt(first))) first++;
        return span(first == end ? start : first, end);
    }

    public Span span(int start, int end) {
        int line = lineOf(start);
        int endLine = lineOf(end);
        return new Span(line + 1, start - lines[line] + 1, endLine + 1, end - lines[endLine] + 1);
    }

    /** The whole element when it fits on a line, its start tag otherwise. */
    private Span span(Tag tag) {
        return lineOf(tag.start) == lineOf(tag.end) ? span(tag.start, tag.end) : span(tag.start, tag.startEnd);
    }

    private int lineOf(int offset) {
        int found = Arrays.binarySearch(lines, offset);
        return found >= 0 ? found : -found - 2;
    }

    private static int[] lineStarts(String text) {
        int count = 1;
        for (int i = 0; i < text.length(); i++) if (text.charAt(i) == '\n') count++;
        int[] starts = new int[count];
        int line = 0;
        for (int i = 0; i < text.length(); i++) if (text.charAt(i) == '\n') starts[++line] = i + 1;
        return starts;
    }

    /** The tree of tags of the text, or null when it holds none. */
    private Tag root() {
        Tag root = null;
        Deque<Tag> open = new ArrayDeque<>();
        int i = 0;
        while ((i = text.indexOf('<', i)) >= 0) {
            if (text.startsWith("<!--", i)) {
                i = after("-->", i + 4);
            } else if (text.startsWith("<![CDATA[", i)) {
                i = after("]]>", i + 9);
            } else if (text.startsWith("<?", i)) {
                i = after("?>", i + 2);
            } else if (text.startsWith("<!", i)) {
                i = after(">", i + 2);
            } else if (text.startsWith("</", i)) {
                int end = after(">", i + 2);
                String name = text.substring(i + 2, Math.max(i + 2, end - 1)).strip();
                close(open, name, end);
                i = end;
            } else {
                int end = tagEnd(i + 1);
                if (end < 0) break;
                Tag tag = new Tag(name(i + 1), i, end);
                if (open.isEmpty()) {
                    if (root == null) root = tag;
                } else {
                    open.peek().children.add(tag);
                }
                if (text.charAt(end - 2) != '/') open.push(tag);
                i = end;
            }
        }
        return root;
    }

    /** Closes the innermost open tag of that name, and those left open inside it. */
    private static void close(Deque<Tag> open, String name, int end) {
        if (open.stream().noneMatch(tag -> tag.name.equals(name))) return;
        Tag closed;
        do {
            closed = open.pop();
            closed.end = end;
        } while (!closed.name.equals(name));
    }

    private int after(String marker, int from) {
        int at = text.indexOf(marker, from);
        return at < 0 ? text.length() : at + marker.length();
    }

    /** Offset after the {@code >} of a tag, skipping quoted attribute values; -1 when the text ends before it. */
    private int tagEnd(int from) {
        char quote = 0;
        for (int i = from; i < text.length(); i++) {
            char c = text.charAt(i);
            if (quote != 0) {
                if (c == quote) quote = 0;
            } else if (c == '"' || c == '\'') {
                quote = c;
            } else if (c == '>') {
                return i + 1;
            }
        }
        return -1;
    }

    private String name(int from) {
        int i = from;
        while (i < text.length() && !Character.isWhitespace(text.charAt(i)) && text.charAt(i) != '/'
                && text.charAt(i) != '>') {
            i++;
        }
        return text.substring(from, i);
    }
}
