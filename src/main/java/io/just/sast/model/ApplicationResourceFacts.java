package io.just.sast.model;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;

/**
 * Immutable, bounded application-resource facts recovered by the static frontend.
 *
 * <p>The model intentionally contains only deployment/configuration facts that can be
 * consumed by the application-entry owner.  It does not retain XML bytes, evaluate a
 * configuration language, or create a call edge.  A route becomes an external boundary only
 * when the same artifact contains a concrete servlet mapping for the resource.</p>
 */
public final class ApplicationResourceFacts {
    public static final int MODEL_VERSION = 1;

    /** One configuration route to a concrete request handler method. */
    public record RouteBinding(String resourcePath, String route, String handlerName,
                               String handlerType, String handlerClass, String handlerMethod,
                               String servletClass, String servletPattern) {
        public RouteBinding {
            resourcePath = required(resourcePath, "resourcePath");
            route = required(route, "route");
            handlerName = text(handlerName);
            handlerType = text(handlerType);
            handlerClass = normalizeClass(handlerClass);
            handlerMethod = text(handlerMethod);
            servletClass = normalizeClass(servletClass);
            servletPattern = text(servletPattern);
        }

        /** A route is externally controlled only when its deployment binding is concrete. */
        public boolean externalControlProven() {
            return !handlerClass.isBlank() && !handlerMethod.isBlank()
                    && !servletClass.isBlank() && !servletPattern.isBlank();
        }

        public String handlerMemberKey() {
            if (handlerClass.isBlank() || handlerMethod.isBlank()) {
                return "";
            }
            return handlerClass + "#" + handlerMethod;
        }
    }

    private final List<RouteBinding> routeBindings;
    private final List<String> completenessReasons;
    private final String semanticDigest;

    public ApplicationResourceFacts(List<RouteBinding> routeBindings,
                                    List<String> completenessReasons) {
        List<RouteBinding> bindings = new ArrayList<>();
        if (routeBindings != null) {
            bindings.addAll(routeBindings.stream().filter(Objects::nonNull).toList());
        }
        bindings.sort(Comparator.comparing(RouteBinding::resourcePath)
                .thenComparing(RouteBinding::route)
                .thenComparing(RouteBinding::handlerName)
                .thenComparing(RouteBinding::handlerClass)
                .thenComparing(RouteBinding::handlerMethod)
                .thenComparing(RouteBinding::servletClass)
                .thenComparing(RouteBinding::servletPattern));
        this.routeBindings = List.copyOf(bindings);
        this.completenessReasons = completenessReasons == null ? List.of()
                : completenessReasons.stream().filter(value -> value != null && !value.isBlank())
                .map(String::trim).distinct().sorted().toList();
        this.semanticDigest = digestCanonical();
    }

    public static ApplicationResourceFacts empty() {
        return new ApplicationResourceFacts(List.of(), List.of());
    }

    public List<RouteBinding> routeBindings() {
        return routeBindings;
    }

    public List<String> completenessReasons() {
        return completenessReasons;
    }

    public String semanticDigest() {
        return semanticDigest;
    }

    private String digestCanonical() {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            update(digest, "application-resource-facts-v" + MODEL_VERSION);
            routeBindings.forEach(value -> update(digest, "route=" + value));
            completenessReasons.forEach(value -> update(digest, "reason=" + value));
            StringBuilder result = new StringBuilder(64);
            for (byte value : digest.digest()) {
                result.append(String.format("%02x", value & 0xff));
            }
            return result.toString();
        } catch (NoSuchAlgorithmException impossible) {
            throw new AssertionError(impossible);
        }
    }

    private static void update(MessageDigest digest, String value) {
        digest.update(value.getBytes(StandardCharsets.UTF_8));
        digest.update((byte) '\n');
    }

    private static String required(String value, String field) {
        String normalized = text(value);
        if (normalized.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        return normalized;
    }

    private static String text(String value) {
        return value == null ? "" : value.trim().replace('\r', '_').replace('\n', '_');
    }

    private static String normalizeClass(String value) {
        String normalized = text(value);
        if (normalized.startsWith("L") && normalized.endsWith(";")) {
            normalized = normalized.substring(1, normalized.length() - 1);
        }
        return normalized.replace('.', '/');
    }
}
