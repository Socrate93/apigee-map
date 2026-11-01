package dev.apigeemap.simulation;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import javax.xml.XMLConstants;
import javax.xml.namespace.NamespaceContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathEvaluationResult;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import javax.xml.xpath.XPathNodes;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/** Reads the XML body of a simulated message with XPath, for ExtractVariables. */
final class XmlPayload {

    private XmlPayload() {
    }

    /** The message as a document, or null when it holds no well-formed XML. */
    static Document parse(String text) {
        if (text == null) return null;
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            builder.setErrorHandler(new DefaultHandler());
            return builder.parse(new InputSource(new StringReader(text)));
        } catch (ParserConfigurationException | SAXException | IOException e) {
            return null;
        }
    }

    /**
     * What an XPath selects: the text of its first node, or all its nodes as XML for a {@code nodeset}.
     *
     * @return null when it selects nothing
     * @throws IllegalArgumentException when it is not a valid XPath
     */
    static String value(Document document, String path, boolean nodeset, Map<String, String> namespaces) {
        XPath xpath = XPathFactory.newInstance().newXPath();
        xpath.setNamespaceContext(new NamespaceContext() {
            @Override
            public String getNamespaceURI(String prefix) {
                return namespaces.getOrDefault(prefix, XMLConstants.NULL_NS_URI);
            }

            @Override
            public String getPrefix(String uri) {
                return null;
            }

            @Override
            public Iterator<String> getPrefixes(String uri) {
                return Collections.emptyIterator();
            }
        });
        try {
            XPathEvaluationResult<?> result = xpath.evaluateExpression(path, document);
            return switch (result.type()) {
                case NODESET -> nodes(list((XPathNodes) result.value()), nodeset);
                case NODE -> nodes(List.of((Node) result.value()), nodeset);
                case NUMBER -> Policies.number(result.value());
                default -> String.valueOf(result.value());
            };
        } catch (XPathExpressionException | TransformerException e) {
            throw new IllegalArgumentException(path, e);
        }
    }

    private static List<Node> list(XPathNodes nodes) {
        List<Node> list = new ArrayList<>();
        nodes.forEach(list::add);
        return list;
    }

    private static String nodes(List<Node> nodes, boolean nodeset) throws TransformerException {
        if (nodes.isEmpty()) return null;
        if (!nodeset) return nodes.get(0).getTextContent();
        StringBuilder out = new StringBuilder();
        for (Node node : nodes) out.append(node.getNodeType() == Node.ELEMENT_NODE ? xml(node) : node.getTextContent());
        return out.toString();
    }

    private static String xml(Node node) throws TransformerException {
        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        StringWriter out = new StringWriter();
        transformer.transform(new DOMSource(node), new StreamResult(out));
        return out.toString();
    }
}
