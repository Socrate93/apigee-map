package dev.apigeemap.analysis;

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/** Null-tolerant DOM helpers: every accessor accepts a null element and returns null/empty. */
public final class Xml {

    private Xml() {
    }

    public static Element parse(Path file) throws IOException {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setXIncludeAware(false);
            factory.setExpandEntityReferences(false);
            return factory.newDocumentBuilder().parse(file.toFile()).getDocumentElement();
        } catch (ParserConfigurationException | SAXException e) {
            throw new IOException("Invalid XML in " + file + ": " + e.getMessage(), e);
        }
    }

    public static List<Path> xmlFiles(Path dir) throws IOException {
        if (!Files.isDirectory(dir)) return List.of();
        try (Stream<Path> files = Files.list(dir)) {
            return files.filter(p -> Files.isRegularFile(p) && p.getFileName().toString().endsWith(".xml"))
                    .sorted()
                    .toList();
        }
    }

    /** Path of {@code file} relative to {@code base}, always with / so it reads the same on every OS. */
    public static String relativePath(Path base, Path file) {
        return base.relativize(file).toString().replace('\\', '/');
    }

    public static List<Element> children(Element parent, String name) {
        List<Element> result = new ArrayList<>();
        if (parent == null) return result;
        for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n instanceof Element e && e.getTagName().equals(name)) result.add(e);
        }
        return result;
    }

    /** Every child element. */
    public static List<Element> children(Element parent) {
        List<Element> result = new ArrayList<>();
        if (parent == null) return result;
        for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n instanceof Element e) result.add(e);
        }
        return result;
    }

    public static List<Element> descendants(Element parent, String name) {
        List<Element> result = new ArrayList<>();
        if (parent == null) return result;
        NodeList nodes = parent.getElementsByTagName(name);
        for (int i = 0; i < nodes.getLength(); i++) result.add((Element) nodes.item(i));
        return result;
    }

    /** First child at the given path of direct children, e.g. {@code path(conn, "SSLInfo", "KeyStore")}. */
    public static Element path(Element element, String... names) {
        Element current = element;
        for (String name : names) {
            if (current == null) return null;
            List<Element> matches = children(current, name);
            current = matches.isEmpty() ? null : matches.get(0);
        }
        return current;
    }

    public static String text(Element element) {
        if (element == null) return null;
        String text = element.getTextContent().trim();
        return text.isEmpty() ? null : text;
    }

    public static String text(Element element, String... names) {
        return text(path(element, names));
    }

    public static String attr(Element element, String name) {
        if (element == null) return null;
        String value = element.getAttribute(name).trim();
        return value.isEmpty() ? null : value;
    }

    /** Literal value, or {@code {variable}} when the element uses a {@code ref} attribute. */
    public static String valueOrRef(Element element) {
        String ref = attr(element, "ref");
        return ref != null ? "{" + ref + "}" : text(element);
    }

    public static String nameOf(Element element) {
        String name = attr(element, "name");
        return name != null ? name : "default";
    }
}
