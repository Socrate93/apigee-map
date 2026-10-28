package dev.apigeemap.migration;

import org.w3c.dom.Element;
import org.w3c.dom.Node;

/** DOM edits that keep the surrounding indentation tidy. */
final class Dom {

    private Dom() {
    }

    /** Whitespace preceding the element (its indentation), or a newline when there is none. */
    static String indentOf(Element element) {
        Node previous = element.getPreviousSibling();
        if (previous != null && previous.getNodeType() == Node.TEXT_NODE && previous.getTextContent().isBlank()) {
            return previous.getTextContent();
        }
        return "\n";
    }

    /** Removes the element together with the indentation in front of it. */
    static void remove(Element element) {
        Node parent = element.getParentNode();
        Node previous = element.getPreviousSibling();
        if (previous != null && previous.getNodeType() == Node.TEXT_NODE && previous.getTextContent().isBlank()) {
            parent.removeChild(previous);
        }
        parent.removeChild(element);
    }

    /** Inserts {@code added} right before {@code anchor}, on its own line with the anchor's indentation. */
    static void insertBefore(Element anchor, Element added) {
        Node parent = anchor.getParentNode();
        parent.insertBefore(added, anchor);
        parent.insertBefore(anchor.getOwnerDocument().createTextNode(indentOf(added)), anchor);
    }

    static Element element(Element context, String name, String text) {
        Element element = context.getOwnerDocument().createElement(name);
        if (text != null) element.setTextContent(text);
        return element;
    }

    /** Escapes text for an XML attribute value or element content. */
    static String escape(String text) {
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }
}
