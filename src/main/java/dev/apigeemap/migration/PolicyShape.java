package dev.apigeemap.migration;

import dev.apigeemap.analysis.Xml;
import org.w3c.dom.Attr;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * A policy flattened to {path → value}, without what identifies it (name attribute, DisplayName), so two policies
 * that do the same thing have equal shapes and near copies differ in a few values.
 * Paths look like {@code AssignMessage/Set/Headers/Header[2]@name}.
 */
record PolicyShape(String type, Map<String, String> values) {

    static PolicyShape of(Element root) {
        Map<String, String> values = new LinkedHashMap<>();
        walk(root, root.getTagName(), true, values);
        return new PolicyShape(root.getTagName(), values);
    }

    /** Paths whose values differ; null when the two policies do not have the same structure. */
    List<String> differences(PolicyShape other) {
        if (!type.equals(other.type) || !values.keySet().equals(other.values.keySet())) return null;
        List<String> paths = new ArrayList<>();
        values.forEach((path, value) -> {
            if (!value.equals(other.values.get(path))) paths.add(path);
        });
        return paths;
    }

    private static void walk(Element element, String path, boolean root, Map<String, String> values) {
        NamedNodeMap attributes = element.getAttributes();
        Map<String, String> sorted = new TreeMap<>();
        for (int i = 0; i < attributes.getLength(); i++) {
            Attr attribute = (Attr) attributes.item(i);
            String name = attribute.getName();
            if (root && name.equals("name") || name.startsWith("xmlns")) continue;
            sorted.put(name, attribute.getValue());
        }
        sorted.forEach((name, value) -> values.put(path + "@" + name, value));

        List<Element> children = new ArrayList<>();
        for (Node child = element.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child instanceof Element e && !(root && e.getTagName().equals("DisplayName"))) children.add(e);
        }
        Map<String, Integer> counts = new HashMap<>();
        children.forEach(c -> counts.merge(c.getTagName(), 1, Integer::sum));
        Map<String, Integer> seen = new HashMap<>();
        for (Element child : children) {
            String tag = child.getTagName();
            int index = seen.merge(tag, 1, Integer::sum);
            walk(child, path + "/" + tag + (counts.get(tag) > 1 ? "[" + index + "]" : ""), false, values);
        }
        if (children.isEmpty()) {
            String text = Xml.text(element);
            if (text != null || sorted.isEmpty()) values.put(path, text == null ? "" : text);
        }
    }
}
