package io.just.sast.frontend.asm;

import io.just.sast.model.ApplicationResourceFacts;
import io.just.sast.run.InputBudget;

import javax.xml.XMLConstants;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.xml.sax.Attributes;
import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

/**
 * Bounded SAX parser for deployment/configuration resource facts.
 *
 * <p>The parser recognizes only generic handler/request-map and servlet descriptor shapes. It
 * never resolves external entities, invokes a target class, or evaluates a configuration
 * expression. Unrelated XML resources are ignored before parser construction.</p>
 */
final class ApplicationResourceParser {
    private static final int MAX_ELEMENTS = 100_000;
    private static final int MAX_TEXT_CHARS = 1_000_000;
    private static final Set<String> RESOURCE_MARKERS = Set.of(
            "<handler", "<request-map", "<servlet", "<web-app");

    private ApplicationResourceParser() {
    }

    static final class Collector {
        private final List<ApplicationResourceFacts.RouteBinding> routeBindings = new ArrayList<>();
        private final List<String> reasons = new ArrayList<>();
        private final Map<String, HandlerSpec> handlers = new LinkedHashMap<>();
        private final List<RouteSpec> routes = new ArrayList<>();
        private final List<ServletBinding> servletBindings = new ArrayList<>();
        private final Set<String> seenResources = new LinkedHashSet<>();
        private final InputBudget budget;

        Collector(InputBudget budget) {
            this.budget = budget == null ? InputBudget.defaults() : budget;
        }

        void accept(String resourcePath, byte[] bytes) {
            String path = normalizePath(resourcePath);
            if (path.isBlank() || bytes == null || bytes.length == 0 || !path.endsWith(".xml")) {
                return;
            }
            if (!seenResources.add(path)) {
                reasons.add("APPLICATION_RESOURCE_DUPLICATE:" + path);
                return;
            }
            String probe = new String(bytes, StandardCharsets.UTF_8).toLowerCase(
                    java.util.Locale.ROOT);
            boolean candidate = RESOURCE_MARKERS.stream().anyMatch(probe::contains);
            if (!candidate) {
                return;
            }
            try {
                DocumentFacts document = parse(path, bytes, budget);
                document.handlers().forEach(handler -> handlers.putIfAbsent(
                        handler.key(), handler));
                routes.addAll(document.routes());
                servletBindings.addAll(document.servlets());
            } catch (IOException | SAXException | RuntimeException failure) {
                reasons.add("APPLICATION_RESOURCE_PARSE_FAILED:" + path);
            }
        }

        ApplicationResourceFacts finish() {
            for (RouteSpec route : routes) {
                HandlerSpec handler = resolveHandler(route.handlerName());
                String handlerClass = route.handlerClass();
                String handlerMethod = route.handlerMethod();
                String handlerType = "";
                if (handler != null) {
                    handlerType = handler.type();
                    if (handlerClass.isBlank()) {
                        handlerClass = handler.handlerClass();
                    }
                    if (handlerMethod.isBlank()) {
                        handlerMethod = "invoke";
                    }
                }
                ServletBinding servlet = servletFor(route.resourcePath());
                routeBindings.add(new ApplicationResourceFacts.RouteBinding(
                        route.resourcePath(), route.route(), route.handlerName(), handlerType,
                        handlerClass, handlerMethod,
                        servlet == null ? "" : servlet.servletClass(),
                        servlet == null ? "" : servlet.pattern()));
            }
            return new ApplicationResourceFacts(routeBindings, reasons);
        }

        private HandlerSpec resolveHandler(String name) {
            if (name == null || name.isBlank()) {
                return null;
            }
            HandlerSpec exact = handlers.values().stream()
                    .filter(value -> name.equals(value.name()))
                    .findFirst().orElse(null);
            if (exact != null) {
                return exact;
            }
            return handlers.values().stream()
                    .filter(value -> name.equals(value.type()))
                    .findFirst().orElse(null);
        }

        private ServletBinding servletFor(String resourcePath) {
            String parent = parentPath(resourcePath);
            List<ServletBinding> matches = servletBindings.stream()
                    .filter(value -> parent.equals(parentPath(value.resourcePath())))
                    .toList();
            return matches.size() == 1 ? matches.get(0) : null;
        }

        private static DocumentFacts parse(String path, byte[] bytes, InputBudget budget)
                throws IOException, SAXException {
            SAXParserFactory factory = SAXParserFactory.newInstance();
            factory.setNamespaceAware(true);
            factory.setValidating(false);
            setFeature(factory, "http://apache.org/xml/features/disallow-doctype-decl", true);
            setFeature(factory, "http://xml.org/sax/features/external-general-entities", false);
            setFeature(factory, "http://xml.org/sax/features/external-parameter-entities", false);
            setFeature(factory, "http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            try {
                factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            } catch (SAXException | javax.xml.parsers.ParserConfigurationException failure) {
                throw new SAXException("resource parser secure processing unavailable", failure);
            }
            SAXParser parser;
            try {
                parser = factory.newSAXParser();
            } catch (javax.xml.parsers.ParserConfigurationException failure) {
                throw new SAXException("resource parser configuration failed", failure);
            }
            Handler handler = new Handler(path, budget);
            EntityResolver denyExternal = (publicId, systemId) -> new InputSource(
                    new ByteArrayInputStream(new byte[0]));
            parser.getXMLReader().setEntityResolver(denyExternal);
            parser.parse(new ByteArrayInputStream(bytes), handler);
            return handler.facts();
        }

        private static void setFeature(SAXParserFactory factory, String feature, boolean value)
                throws SAXException {
            try {
                factory.setFeature(feature, value);
            } catch (javax.xml.parsers.ParserConfigurationException failure) {
                throw new SAXException("resource parser feature unavailable: " + feature, failure);
            }
        }

        private static String normalizePath(String value) {
            return value == null ? "" : value.trim().replace('\\', '/');
        }

        private static String parentPath(String path) {
            int slash = path == null ? -1 : path.lastIndexOf('/');
            return slash < 0 ? "" : path.substring(0, slash);
        }
    }

    private record HandlerSpec(String name, String type, String handlerClass) {
        String key() {
            return name + "\u0000" + type;
        }
    }

    private record RouteSpec(String resourcePath, String route, String handlerName,
                             String handlerClass, String handlerMethod) {
    }

    private record ServletBinding(String resourcePath, String servletClass, String pattern) {
    }

    private record DocumentFacts(List<HandlerSpec> handlers, List<RouteSpec> routes,
                                 List<ServletBinding> servlets) {
    }

    private static final class Handler extends DefaultHandler {
        private final String resourcePath;
        private final InputBudget budget;
        private final Deque<Frame> frames = new ArrayDeque<>();
        private final List<HandlerSpec> handlers = new ArrayList<>();
        private final List<RouteSpec> routes = new ArrayList<>();
        private final List<ServletDeclaration> declarations = new ArrayList<>();
        private final List<ServletMapping> mappings = new ArrayList<>();
        private int elements;
        private int textChars;

        private Handler(String resourcePath, InputBudget budget) {
            this.resourcePath = resourcePath;
            this.budget = budget == null ? InputBudget.defaults() : budget;
        }

        @Override
        public void startElement(String uri, String localName, String qName, Attributes attrs)
                throws SAXException {
            if (++elements > MAX_ELEMENTS || elements > budget.maxRuleNodes()) {
                throw new SAXException("resource element limit exceeded");
            }
            String name = elementName(localName, qName);
            Map<String, String> attributes = new LinkedHashMap<>();
            for (int i = 0; i < attrs.getLength(); i++) {
                attributes.put(attributeName(attrs, i), attrs.getValue(i));
            }
            if ("handler".equals(name)) {
                handlers.add(new HandlerSpec(attributes.getOrDefault("name", "").trim(),
                        attributes.getOrDefault("type", "").trim(),
                        attributes.getOrDefault("class", "").trim()));
            } else if ("event".equals(name)) {
                String route = requestMapRoute();
                if (!route.isBlank()) {
                    routes.add(new RouteSpec(resourcePath, route,
                            attributes.getOrDefault("type", "").trim(),
                            attributes.getOrDefault("path", "").trim(),
                            attributes.getOrDefault("invoke", "").trim()));
                }
            }
            frames.push(new Frame(name, attributes));
        }

        @Override
        public void characters(char[] chars, int start, int length) throws SAXException {
            if (length <= 0) {
                return;
            }
            textChars += length;
            if (textChars > MAX_TEXT_CHARS || textChars > budget.maxRuleScalarChars()) {
                throw new SAXException("resource text limit exceeded");
            }
            if (!frames.isEmpty()) {
                frames.peek().text.append(chars, start, length);
            }
        }

        @Override
        public void endElement(String uri, String localName, String qName) {
            if (frames.isEmpty()) {
                return;
            }
            Frame frame = frames.pop();
            Frame parent = frames.peek();
            String value = clean(frame.text.toString());
            if (parent != null && !value.isBlank()) {
                parent.children.put(frame.name, value);
            }
            if ("servlet".equals(frame.name)) {
                declarations.add(new ServletDeclaration(resourcePath,
                        frame.children.getOrDefault("servlet-name", ""),
                        frame.children.getOrDefault("servlet-class", "")));
            } else if ("servlet-mapping".equals(frame.name)) {
                mappings.add(new ServletMapping(resourcePath,
                        frame.children.getOrDefault("servlet-name", ""),
                        frame.children.getOrDefault("url-pattern", "")));
            }
        }

        private String requestMapRoute() {
            for (Frame frame : frames) {
                if ("request-map".equals(frame.name)) {
                    return frame.attributes.getOrDefault("uri", "").trim();
                }
            }
            return "";
        }

        private DocumentFacts facts() {
            List<ServletBinding> servlets = new ArrayList<>();
            for (ServletMapping mapping : mappings) {
                declarations.stream()
                        .filter(value -> value.resourcePath().equals(mapping.resourcePath())
                                && value.name().equals(mapping.name())
                                && !value.servletClass().isBlank())
                        .forEach(value -> servlets.add(new ServletBinding(
                                mapping.resourcePath(), value.servletClass(), mapping.pattern())));
            }
            return new DocumentFacts(List.copyOf(handlers), List.copyOf(routes), List.copyOf(servlets));
        }

        private static String elementName(String localName, String qName) {
            String value = localName == null || localName.isBlank() ? qName : localName;
            int colon = value == null ? -1 : value.indexOf(':');
            return clean(colon < 0 ? value : value.substring(colon + 1));
        }

        private static String attributeName(Attributes attrs, int index) {
            String value = attrs.getLocalName(index);
            if (value == null || value.isBlank()) {
                value = attrs.getQName(index);
            }
            int colon = value == null ? -1 : value.indexOf(':');
            return clean(colon < 0 ? value : value.substring(colon + 1));
        }

        private static String clean(String value) {
            return value == null ? "" : value.trim().replace('\r', '_').replace('\n', '_');
        }
    }

    private static final class Frame {
        private final String name;
        private final Map<String, String> attributes;
        private final Map<String, String> children = new LinkedHashMap<>();
        private final StringBuilder text = new StringBuilder();

        private Frame(String name, Map<String, String> attributes) {
            this.name = name;
            this.attributes = attributes;
        }
    }

    private record ServletDeclaration(String resourcePath, String name, String servletClass) {
    }

    private record ServletMapping(String resourcePath, String name, String pattern) {
    }
}
