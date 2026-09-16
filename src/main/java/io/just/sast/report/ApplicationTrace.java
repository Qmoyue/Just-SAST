package io.just.sast.report;

import io.just.sast.analysis.entry.ApplicationChainEvidence;
import io.just.sast.blackboard.ApplicationChainId;
import io.just.sast.blackboard.EvidenceAtom;
import io.just.sast.blackboard.EvidenceEdge;
import io.just.sast.blackboard.EvidenceNode;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * The report-facing projection of an application-entry join.
 *
 * <p>The legacy {@code Chain} deliberately starts at the deserialized object or callback.  That
 * is useful kernel evidence, but it is not an application path.  This immutable projection keeps
 * the application execution root, the binding/deserialization site and the typed prefix beside
 * the legacy chain key so every renderer can expose the same complete path without rewriting
 * chain identity or inferring an entry from a class name.</p>
 */
public record ApplicationTrace(
        String applicationEntryClass,
        String applicationEntryMethod,
        String applicationSiteClass,
        String applicationSiteMethod,
        String applicationSiteKind,
        String joinKind,
        String chainEntryMethod,
        String entryPrefixPath,
        String dependencyOwner,
        String terminalOwner,
        String terminalMethod) {

    public ApplicationTrace {
        applicationEntryClass = normalize(applicationEntryClass);
        applicationEntryMethod = normalize(applicationEntryMethod);
        applicationSiteClass = normalize(applicationSiteClass);
        applicationSiteMethod = normalize(applicationSiteMethod);
        applicationSiteKind = normalize(applicationSiteKind);
        joinKind = normalize(joinKind);
        chainEntryMethod = normalize(chainEntryMethod);
        entryPrefixPath = normalize(entryPrefixPath);
        dependencyOwner = normalize(dependencyOwner);
        terminalOwner = normalize(terminalOwner);
        terminalMethod = normalize(terminalMethod);
    }

    /**
     * Build one deterministic raw-chain-key map from the typed evidence graph.  The graph is the
     * only source of this projection; no notes, ranking text or class-name guessing is allowed.
     */
    public static Map<String, ApplicationTrace> fromEvidence(ApplicationChainEvidence evidence) {
        if (evidence == null || evidence.joins().isEmpty()) {
            return Map.of();
        }
        Map<String, EvidenceNode> nodes = new LinkedHashMap<>();
        evidence.graph().nodes().forEach(node -> nodes.putIfAbsent(node.id(), node));
        // The join graph deliberately does not put a raw chain key on reusable entry/site/
        // dependency atoms: doing so would defeat atom sharing and make IDs depend on every
        // path variant.  The evidence product already owns the typed decisions map, so derive
        // the raw-key ↔ application-chain-id relation from that map instead of guessing from a
        // class name or parsing a renderer note.
        Map<String, String> rawKeyByChainId = new java.util.TreeMap<>();
        evidence.decisions().forEach((rawKey, decision) -> {
            if (rawKey != null && !rawKey.isBlank() && "JOINED".equals(decision)) {
                rawKeyByChainId.put(ApplicationChainId.fromCanonical("chain", rawKey).value(),
                        rawKey);
            }
        });
        Map<String, ApplicationTrace> traces = new java.util.TreeMap<>();
        evidence.joins().values().stream()
                .sorted(Comparator.comparing(join -> join.applicationChainId().value()))
                .forEach(join -> {
                    EvidenceAtom entry = atom(nodes.get(join.applicationEntryAtomId()));
                    EvidenceAtom site = atom(nodes.get(join.applicationSiteAtomId()));
                    if (entry == null || site == null) {
                        return;
                    }
                    String chainKey = rawKeyByChainId.getOrDefault(
                            join.applicationChainId().value(), "");
                    // Compatibility evidence produced by pre-grouping callers may still carry
                    // a raw key attribute.  It is only a fallback; production joins use the
                    // typed decisions relation above.
                    if (chainKey.isBlank()) chainKey = attribute(site, "chain_key");
                    if (chainKey.isBlank()) chainKey = attribute(entry, "chain_key");
                    if (chainKey.isBlank()) {
                        return;
                    }
                    EvidenceAtom dependency = dependencyFor(join, nodes, chainKey);
                    EvidenceAtom terminal = terminalFor(join, dependency, nodes, evidence.graph().edges(),
                            chainKey);
                    ApplicationTrace trace = new ApplicationTrace(
                            entry.owner(), entry.member(), site.owner(), site.member(),
                            site.kind().name(), attribute(entry, "entry_join_kind"),
                            attribute(entry, "chain_entry_method"),
                            attribute(entry, "entry_prefix_path"),
                            dependency == null ? "UNKNOWN" : dependency.owner(),
                            terminal == null ? "UNKNOWN" : terminal.owner(),
                            terminal == null ? "UNKNOWN" : terminal.member());
                    traces.putIfAbsent(chainKey, trace);
                });
        return Map.copyOf(traces);
    }

    /** Human-readable application-root → legacy-chain path used by all report formats. */
    public String applicationPath(io.just.sast.blackboard.Chain chain) {
        Objects.requireNonNull(chain, "chain");
        String chainPath = CsvReporter.pathSummary(chain);
        if (entryPrefixPath.isBlank()) {
            return chainPath;
        }
        String prefix = entryPrefixPath;
        String chainStart = chain.entryClass() + "." + chain.entryMethod();
        String canonicalStart = chain.entryClass() + "#" + chain.entryMethod();
        String suffix = chainPath;
        int firstArrow = chainPath.indexOf(" -> ");
        if (firstArrow >= 0 && (prefix.endsWith(chainStart) || prefix.endsWith(canonicalStart))) {
            suffix = chainPath.substring(firstArrow + 4);
        } else if (chainPath.startsWith(chainStart)
                && (prefix.endsWith(chainStart) || prefix.endsWith(canonicalStart))) {
            suffix = "";
        }
        if (suffix.isBlank()) {
            return prefix;
        }
        return prefix + " -> " + suffix;
    }

    public String entryDisplay() {
        return applicationEntryClass + "." + applicationEntryMethod;
    }

    public String siteDisplay() {
        return applicationSiteClass + "." + applicationSiteMethod;
    }

    public String toCanonicalJson() {
        return "{\"application_entry_class\":\"" + esc(applicationEntryClass)
                + "\",\"application_entry_method\":\"" + esc(applicationEntryMethod)
                + "\",\"application_site_class\":\"" + esc(applicationSiteClass)
                + "\",\"application_site_method\":\"" + esc(applicationSiteMethod)
                + "\",\"application_site_kind\":\"" + esc(applicationSiteKind)
                + "\",\"join_kind\":\"" + esc(joinKind)
                + "\",\"chain_entry_method\":\"" + esc(chainEntryMethod)
                + "\",\"entry_prefix_path\":\"" + esc(entryPrefixPath)
                + "\",\"dependency_owner\":\"" + esc(dependencyOwner)
                + "\",\"terminal_owner\":\"" + esc(terminalOwner)
                + "\",\"terminal_method\":\"" + esc(terminalMethod) + "\"}";
    }

    private static EvidenceAtom dependencyFor(io.just.sast.blackboard.EntryChainJoinEvidence join,
                                               Map<String, EvidenceNode> nodes, String chainKey) {
        return nodes.values().stream()
                .filter(node -> node instanceof EvidenceAtom atom
                        && atom.kind() == EvidenceAtom.Kind.DEPENDENCY_SEGMENT
                        && (join != null && join.dependencySegmentId().value()
                        .equals(attribute(atom, "segment_id"))
                        || chainKey.equals(attribute(atom, "chain_key"))))
                .map(node -> (EvidenceAtom) node)
                .findFirst().orElse(null);
    }

    private static EvidenceAtom terminalFor(io.just.sast.blackboard.EntryChainJoinEvidence join,
                                            EvidenceAtom dependency,
                                            Map<String, EvidenceNode> nodes,
                                            List<EvidenceEdge> edges,
                                            String chainKey) {
        if (dependency != null && edges != null) {
            for (EvidenceEdge edge : edges) {
                if (!dependency.id().equals(edge.fromId())
                        || edge.kind() != EvidenceEdge.Kind.FLOWS_TO) {
                    continue;
                }
                EvidenceNode target = nodes.get(edge.toId());
                if (target instanceof EvidenceAtom atom
                        && atom.kind() == EvidenceAtom.Kind.TERMINAL_IMPACT) {
                    return atom;
                }
            }
        }
        return nodes.values().stream()
                .filter(node -> node instanceof EvidenceAtom atom
                        && atom.kind() == EvidenceAtom.Kind.TERMINAL_IMPACT
                        && chainKey.equals(attribute(atom, "chain_key")))
                .map(node -> (EvidenceAtom) node)
                .findFirst().orElse(null);
    }

    private static EvidenceAtom atom(EvidenceNode node) {
        return node instanceof EvidenceAtom value ? value : null;
    }

    private static String attribute(EvidenceAtom atom, String key) {
        if (atom == null) {
            return "";
        }
        String value = atom.attributes().get(key);
        return value == null ? "" : value.trim();
    }

    private static String normalize(String value) {
        return value == null || value.isBlank() ? "UNKNOWN" : value.trim();
    }

    private static String esc(String value) {
        StringBuilder out = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            switch (ch) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (ch < 0x20) {
                        out.append(String.format(java.util.Locale.ROOT, "\\u%04x", (int) ch));
                    } else {
                        out.append(ch);
                    }
                }
            }
        }
        return out.toString();
    }
}
