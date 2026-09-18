package io.just.sast.report;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.FindingState;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * The single typed projection owned by the public report boundary.
 *
 * <p>The analysis snapshot may contain kernel candidates, calibration data and renderer
 * telemetry. None of those values are serialized directly by the concise report. This value
 * object is built once, and both JSON and Markdown are rendered from it, so the two public
 * formats cannot silently disagree about findings or status.</p>
 */
public record ConciseReportProjection(
        String schemaVersion,
        String mode,
        Result result,
        List<Finding> findings,
        Provenance provenance) {

    public static final String SCHEMA_VERSION = "JUST-REPORT-V2";

    public enum Status {
        COMPLETE,
        PARTIAL,
        UNKNOWN
    }

    public enum GraphRole {
        ENTRY,
        SITE,
        SOURCE,
        DESERIALIZE,
        CALLBACK,
        BRIDGE,
        STEP,
        IMPACT,
        BOUNDARY
    }

    public record Result(String outcome, String coverage, int candidates, int exported,
                         List<String> limits) {
        public Result {
            outcome = required(outcome, "result outcome");
            coverage = required(coverage, "result coverage");
            if (candidates < 0 || exported < 0 || exported > candidates) {
                throw new IllegalArgumentException("report result counts are invalid");
            }
            limits = stableLimits(Objects.requireNonNull(limits, "result limits"));
        }
    }

    public record Method(String owner, String method, String descriptor,
                         String kind, String role) {
        public Method {
            owner = required(owner, "method owner");
            method = required(method, "method name");
            descriptor = required(descriptor, "method descriptor");
            kind = optional(kind);
            role = optional(role);
        }

        private static String optional(String value) {
            return value == null ? "" : value.trim();
        }
    }

    public record GraphNode(GraphRole role, String label) {
        public GraphNode {
            role = Objects.requireNonNull(role, "graph role");
            label = required(label, "graph label");
        }
    }

    public record Proof(String entry, String site, String input, String callback,
                        String bridge, String terminal, String feasibility) {
        public Proof {
            entry = required(entry, "entry proof");
            site = required(site, "site proof");
            input = required(input, "input proof");
            callback = required(callback, "callback proof");
            bridge = required(bridge, "bridge proof");
            terminal = required(terminal, "terminal proof");
            feasibility = required(feasibility, "feasibility proof");
        }
    }

    public record Finding(String id, Status status, Method entry, Method impact,
                          List<GraphNode> graph, Proof proof, List<String> limits) {
        public Finding {
            id = required(id, "finding id");
            status = Objects.requireNonNull(status, "finding status");
            entry = Objects.requireNonNull(entry, "finding entry");
            impact = Objects.requireNonNull(impact, "finding impact");
            graph = List.copyOf(Objects.requireNonNull(graph, "finding graph"));
            if (graph.isEmpty()) {
                throw new IllegalArgumentException("finding graph must not be empty");
            }
            proof = Objects.requireNonNull(proof, "finding proof");
            limits = stableLimits(Objects.requireNonNull(limits, "finding limits"));
            if (status == Status.COMPLETE && !limits.isEmpty()) {
                throw new IllegalArgumentException("complete finding cannot carry proof limits");
            }
            if (status != Status.COMPLETE && limits.isEmpty()) {
                throw new IllegalArgumentException("incomplete finding needs a named proof limit");
            }
        }
    }

    public record Provenance(String artifactSha256, String detail) {
        public Provenance {
            artifactSha256 = required(artifactSha256, "artifact SHA-256");
            detail = required(detail, "provenance detail");
        }
    }

    public ConciseReportProjection {
        if (!SCHEMA_VERSION.equals(schemaVersion)) {
            throw new IllegalArgumentException("unsupported concise report schema: "
                    + schemaVersion);
        }
        mode = normalizeMode(mode);
        result = Objects.requireNonNull(result, "report result");
        findings = List.copyOf(Objects.requireNonNull(findings, "report findings"));
        provenance = Objects.requireNonNull(provenance, "report provenance");
    }

    /** Build the public projection from one frozen internal snapshot. */
    public static ConciseReportProjection from(String mode,
                                               FindingOutputReader.Snapshot snapshot,
                                               ScanStatistics statistics) {
        Objects.requireNonNull(snapshot, "finding snapshot");
        Objects.requireNonNull(statistics, "scan statistics");
        String normalizedMode = normalizeMode(mode);
        List<FindingOutputReader.Finding> ordered = new ArrayList<>(snapshot.findings());
        ordered.sort((left, right) -> {
            int ranking = io.just.sast.chain.ChainRanking.compareEvidence(left.ranking(),
                    left.chain().key(), right.ranking(), right.chain().key());
            return ranking != 0 ? ranking : left.id().compareTo(right.id());
        });

        List<Finding> projected = new ArrayList<>();
        for (FindingOutputReader.Finding candidate : ordered) {
            if (!meaningful(candidate)) {
                // A candidate without both mechanism endpoints is analysis coverage, not a
                // report finding. It cannot satisfy the public entry/impact contract.
                continue;
            }
            ApplicationTrace trace = snapshot.applicationTrace(candidate.chain().key());
            if ("application".equals(normalizedMode)
                    && (!candidate.exported() || trace == null)) {
                // Application candidates without the producer-owned entry/site join are
                // coverage evidence, never public findings.
                continue;
            }
            boolean applicationMode = "application".equals(normalizedMode);
            ReportHopAudit.Result audit = ReportHopAudit.inspect(candidate, trace,
                    applicationMode);
            Status candidateStatus = status(candidate, applicationMode);
            Status auditedStatus = auditedStatus(candidateStatus, audit);
            projected.add(project(candidate, trace, applicationMode, audit, auditedStatus));
        }

        List<String> resultLimits = resultLimits(normalizedMode, snapshot, statistics, projected);
        String coverage = coverage(normalizedMode, statistics, resultLimits);
        String outcome = outcome(statistics, projected);
        int sourceCount = snapshot.findings().size();
        return new ConciseReportProjection(SCHEMA_VERSION, normalizedMode,
                new Result(outcome, coverage, sourceCount, projected.size(), resultLimits),
                projected,
                new Provenance(statistics.artifactHash(),
                        "static-only; target artifact identity is the scan-boundary SHA-256"));
    }

    /** Canonical JSON for report.json. */
    public String toJson() {
        StringBuilder out = new StringBuilder(4096)
                .append("{\"schema_version\":").append(quote(schemaVersion))
                .append(",\"mode\":").append(quote(mode))
                .append(",\"result\":{")
                .append("\"outcome\":").append(quote(result.outcome()))
                .append(",\"coverage\":").append(quote(result.coverage()))
                .append(",\"candidates\":").append(result.candidates())
                .append(",\"exported\":").append(result.exported());
        if (!result.limits().isEmpty()) {
            out.append(",\"limits\":").append(strings(result.limits()));
        }
        out.append("},\"findings\":[");
        for (int index = 0; index < findings.size(); index++) {
            if (index > 0) {
                out.append(',');
            }
            appendFindingJson(out, findings.get(index));
        }
        return out.append("],\"provenance\":{\"artifact_sha256\":")
                .append(quote(provenance.artifactSha256()))
                .append(",\"detail\":").append(quote(provenance.detail()))
                .append("}}").toString();
    }

    /** Human-readable report.md rendered from exactly the same projection as {@link #toJson()}. */
    public String toMarkdown() {
        StringBuilder out = new StringBuilder(4096)
                .append("# Just report\n\n")
                .append("## Result\n\n")
                .append("- Outcome: ").append(md(result.outcome())).append('\n')
                .append("- Coverage: ").append(md(result.coverage())).append('\n')
                .append("- Mode: ").append(md(mode)).append('\n')
                .append("- Candidates: ").append(result.candidates()).append('\n')
                .append("- Findings: ").append(findings.size()).append('\n')
                .append("- Artifact SHA-256: ").append(md(provenance.artifactSha256()))
                .append("\n");
        if (!result.limits().isEmpty()) {
            out.append("- Limits: ").append(md(String.join(", ", result.limits()))).append('\n');
        }
        out.append('\n');
        if (findings.isEmpty()) {
            out.append("No static finding was produced. An empty result is not proof that the "
                    + "artifact is safe.\n");
            if (!result.limits().isEmpty()) {
                out.append("Named limits: ").append(md(String.join(", ", result.limits())))
                        .append('\n');
            }
            return out.toString();
        }
        out.append("## Findings\n\n");
        for (int index = 0; index < findings.size(); index++) {
            Finding finding = findings.get(index);
            out.append("### ").append(index + 1).append(". ")
                    .append(md(finding.id())).append(" — ")
                    .append(md(finding.status().name())).append("\n\n")
                    .append("Entry: ").append(md(methodDisplay(finding.entry())))
                    .append("\n\n")
                    .append("Impact: ").append(md(methodDisplay(finding.impact())))
                    .append("\n\n")
                    .append("Graph:\n\n");
            for (int nodeIndex = 0; nodeIndex < finding.graph().size(); nodeIndex++) {
                if (nodeIndex > 0) {
                    out.append("    ↓\n");
                }
                GraphNode node = finding.graph().get(nodeIndex);
                out.append('[').append(node.role().name()).append("] ")
                        .append(md(node.label())).append('\n');
            }
            out.append("\nProof:\n\n")
                    .append("- entry: ").append(md(finding.proof().entry())).append('\n')
                    .append("- site: ").append(md(finding.proof().site())).append('\n')
                    .append("- input: ").append(md(finding.proof().input())).append('\n')
                    .append("- callback: ").append(md(finding.proof().callback())).append('\n')
                    .append("- bridge: ").append(md(finding.proof().bridge())).append('\n')
                    .append("- terminal: ").append(md(finding.proof().terminal())).append('\n')
                    .append("- feasibility: ").append(md(finding.proof().feasibility()))
                    .append('\n');
            if (!finding.limits().isEmpty()) {
                out.append("- limits: ").append(md(String.join(", ", finding.limits())))
                        .append('\n');
            }
            out.append('\n');
        }
        return out.toString();
    }

    private static Finding project(FindingOutputReader.Finding candidate,
                                   ApplicationTrace trace, boolean applicationMode,
                                   ReportHopAudit.Result audit, Status auditedStatus) {
        Chain chain = candidate.chain();
        Status status = auditedStatus;
        Method entry = applicationMode && trace != null
                ? applicationEntry(trace)
                : new Method(safe(chain.entryClass()), safe(chain.entryMethod()),
                descriptorOrUnknown(ChainIdentity.entryDescriptor(chain)),
                chain.entryKind(), "CHAIN_ENTRY");
        Method impact = new Method(safe(chain.sinkClass()), safe(chain.sinkMethod()),
                descriptorOrUnknown(ChainIdentity.sinkDescriptor(chain)),
                "", chain.terminalSink() ? "TERMINAL_IMPACT" : "CAPABILITY_BOUNDARY");
        List<GraphNode> graph = graph(chain, trace, applicationMode);
        Proof proof = proof(candidate, trace, applicationMode);
        return new Finding(candidate.id(), status, entry, impact, graph, proof,
                findingLimits(candidate, trace, applicationMode, status, audit));
    }

    /**
     * A materialized proof gap is a named partial result, never an empty result or an implicit
     * success. UNKNOWN is retained when the base candidate had no usable chain shape.
     */
    private static Status auditedStatus(Status candidateStatus, ReportHopAudit.Result audit) {
        if (audit == null || audit.passed() || candidateStatus != Status.COMPLETE) {
            return candidateStatus;
        }
        return audit.hops().isEmpty() ? Status.UNKNOWN : Status.PARTIAL;
    }

    private static Status status(FindingOutputReader.Finding candidate, boolean applicationMode) {
        if (applicationMode) {
            FindingState state = candidate.state();
            if (candidate.exported() && state.feasibility() == FindingState.Feasibility.SAT
                    && state.completeness() == FindingState.Completeness.COMPLETE
                    && state.impactComplete() && candidate.chain().terminalSink()) {
                return Status.COMPLETE;
            }
            if (candidate.exported() && meaningful(candidate)) {
                return Status.PARTIAL;
            }
            return Status.UNKNOWN;
        }
        Chain chain = candidate.chain();
        if (!meaningful(candidate)) {
            return Status.UNKNOWN;
        }
        if (chain.hops().isEmpty()) {
            return Status.UNKNOWN;
        }
        if (chain.terminalSink() && chain.unresolvedHops() == 0 && !chain.hops().isEmpty()) {
            return Status.COMPLETE;
        }
        return Status.PARTIAL;
    }

    private static boolean meaningful(FindingOutputReader.Finding candidate) {
        Chain chain = candidate.chain();
        return chain != null && chain.entryClass() != null && !chain.entryClass().isBlank()
                && chain.entryMethod() != null && !chain.entryMethod().isBlank()
                && chain.sinkClass() != null && !chain.sinkClass().isBlank()
                && chain.sinkMethod() != null && !chain.sinkMethod().isBlank();
    }

    private static List<String> findingLimits(FindingOutputReader.Finding candidate,
                                               ApplicationTrace trace,
                                               boolean applicationMode, Status status,
                                               ReportHopAudit.Result audit) {
        if (status == Status.COMPLETE) {
            return List.of();
        }
        LinkedHashSet<String> limits = new LinkedHashSet<>();
        Chain chain = candidate.chain();
        if (chain.unresolvedHops() > 0) {
            limits.add("UNRESOLVED_HOPS");
        }
        if (!chain.terminalSink()) {
            limits.add("TERMINAL_IMPACT_NOT_PROVEN");
        }
        if (applicationMode) {
            if (trace == null) {
                limits.add("APPLICATION_ENTRY_SITE_JOIN_NOT_PROVEN");
            }
            candidate.state().defaultFindingViolations().forEach(limits::add);
        } else if (status == Status.PARTIAL) {
            limits.add("STATIC_PROOF_GAP");
        }
        if (audit != null) {
            audit.limits().forEach(limits::add);
        }
        if (limits.isEmpty()) {
            limits.add(status == Status.UNKNOWN ? "STATIC_PROOF_UNKNOWN" : "STATIC_PROOF_GAP");
        }
        return stableLimits(limits);
    }

    private static Proof proof(FindingOutputReader.Finding candidate, ApplicationTrace trace,
                               boolean applicationMode) {
        Chain chain = candidate.chain();
        if (!applicationMode) {
            String bridge = hopKinds(chain);
            return new Proof("COMPONENT_CHAIN_ENTRY:" + methodDisplay(chain.entryClass(),
                            chain.entryMethod()),
                    "NOT_APPLICABLE_COMPONENT_MODE",
                    "STATIC_BYTECODE_CHAIN",
                    "STATIC_CALLBACK_KIND:" + safe(chain.entryKind()),
                    bridge,
                    chain.terminalSink() ? "PROVED:" + methodDisplay(chain.sinkClass(),
                            chain.sinkMethod()) : "CAPABILITY_ONLY:" + methodDisplay(
                            chain.sinkClass(), chain.sinkMethod()),
                    "STATIC_CHAIN_CONSTRAINTS");
        }
        if (trace == null) {
            return new Proof("NO_APPLICATION_ENTRY", "NO_APPLICATION_SITE", "UNKNOWN",
                    "UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN");
        }
        ApplicationTrace.JoinEvidence join = trace.joinEvidence();
        String input = join == null ? "UNKNOWN" : join.valueFlow();
        String callback = join == null ? safe(chain.entryKind()) : join.callbackSemantics();
        String bridge = join == null || join.bridgeEvidenceIds().isEmpty()
                ? trace.joinKind() : String.join(",", join.bridgeEvidenceIds());
        String feasibility = candidate.state().feasibility().name();
        return new Proof("PROVED:" + trace.entryDisplay(),
                "PROVED:" + trace.siteDisplay(),
                "PROVED:" + input,
                "PROVED:" + callback,
                "PROVED:" + safe(bridge),
                chain.terminalSink() ? "PROVED:" + methodDisplay(chain.sinkClass(),
                        chain.sinkMethod()) : "CAPABILITY_ONLY",
                feasibility);
    }

    private static List<GraphNode> graph(Chain chain, ApplicationTrace trace,
                                         boolean applicationMode) {
        List<GraphNode> nodes = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        if (applicationMode && trace != null) {
            addNode(nodes, seen, GraphRole.ENTRY,
                    methodDisplay(trace.applicationEntryClass(), trace.applicationEntryMethod()));
            addNode(nodes, seen, GraphRole.SITE,
                    methodDisplay(trace.applicationSiteClass(), trace.applicationSiteMethod()));
            addNode(nodes, seen, callbackRole(chain.entryKind()),
                    methodDisplay(chain.entryClass(), chain.entryMethod()));
            if (trace.joinEvidence() != null) {
                List<String> bridgeIds = trace.joinEvidence().bridgeEvidenceIds();
                String bridge = bridgeIds.isEmpty()
                        ? trace.joinKind() : String.join(",", bridgeIds);
                if (bridge != null && !bridge.isBlank()) {
                    addNode(nodes, seen, GraphRole.BRIDGE, "bridge:" + bridge);
                }
            }
        } else {
            addNode(nodes, seen, GraphRole.ENTRY,
                    methodDisplay(chain.entryClass(), chain.entryMethod()));
        }
        List<ChainHop> hops = new ArrayList<>(Objects.requireNonNull(chain.hops(), "chain hops"));
        java.util.Collections.reverse(hops);
        for (ChainHop hop : hops) {
            Objects.requireNonNull(hop, "chain hop");
            addNode(nodes, seen, GraphRole.STEP,
                    methodDisplay(hop.fromOwner(), hop.fromName()));
            addNode(nodes, seen, roleForHop(hop, chain),
                    methodDisplay(hop.toOwner(), hop.toName()));
        }
        addNode(nodes, seen, chain.terminalSink() ? GraphRole.IMPACT : GraphRole.BOUNDARY,
                methodDisplay(chain.sinkClass(), chain.sinkMethod()));
        return List.copyOf(nodes);
    }

    private static GraphRole roleForHop(ChainHop hop, Chain chain) {
        if (hop.toOwner() != null && hop.toOwner().equals(chain.sinkClass())
                && hop.toName() != null && hop.toName().equals(chain.sinkMethod())) {
            return chain.terminalSink() ? GraphRole.IMPACT : GraphRole.BOUNDARY;
        }
        if (hop.kind() == io.just.sast.blackboard.HopKind.NATIVE_CALLBACK
                || hop.kind() == io.just.sast.blackboard.HopKind.LAMBDA) {
            return GraphRole.CALLBACK;
        }
        return GraphRole.STEP;
    }

    private static GraphRole callbackRole(String entryKind) {
        if (entryKind == null) {
            return GraphRole.DESERIALIZE;
        }
        String normalized = entryKind.toLowerCase(Locale.ROOT);
        return normalized.contains("resolve") || normalized.contains("external")
                || normalized.contains("validate") ? GraphRole.CALLBACK : GraphRole.DESERIALIZE;
    }

    private static void addNode(List<GraphNode> nodes, Set<String> seen, GraphRole role,
                                String label) {
        if (seen.add(role.name() + "\u0000" + label)) {
            nodes.add(new GraphNode(role, label));
        }
    }

    private static Method applicationEntry(ApplicationTrace trace) {
        MethodKey key = parseMethodKey(trace.entryPrefixPath());
        if (key != null) {
            return new Method(key.owner(), key.name(), key.descriptor(),
                    trace.joinKind(), "APPLICATION_ENTRY");
        }
        return new Method(trace.applicationEntryClass(), trace.applicationEntryMethod(),
                "UNKNOWN", trace.joinKind(), "APPLICATION_ENTRY");
    }

    private record MethodKey(String owner, String name, String descriptor) {
    }

    private static MethodKey parseMethodKey(String path) {
        if (path == null || path.isBlank()) {
            return null;
        }
        String first = path.split("->", 2)[0];
        int hash = first.indexOf('#');
        int descriptor = first.indexOf('(', hash + 1);
        if (hash <= 0 || descriptor <= hash + 1) {
            return null;
        }
        String owner = first.substring(0, hash);
        String name = first.substring(hash + 1, descriptor);
        String desc = first.substring(descriptor);
        if (owner.isBlank() || name.isBlank() || desc.isBlank()) {
            return null;
        }
        return new MethodKey(owner, name, desc);
    }

    private static String hopKinds(Chain chain) {
        LinkedHashSet<String> kinds = new LinkedHashSet<>();
        for (ChainHop hop : chain.hops()) {
            if (hop != null && hop.kind() != null) {
                kinds.add(hop.kind().name());
            }
        }
        return kinds.isEmpty() ? "NO_TYPED_BRIDGE" : String.join(",", kinds);
    }

    private static List<String> resultLimits(String mode, FindingOutputReader.Snapshot snapshot,
                                              ScanStatistics statistics,
                                              List<Finding> findings) {
        LinkedHashSet<String> limits = new LinkedHashSet<>();
        limits.addAll(statistics.runOutcome().reasonCodes());
        limits.addAll(statistics.completenessReasons());
        if ("application".equals(mode) && snapshot.applicationTraces().isEmpty()) {
            limits.add("NO_APPLICATION_ENTRY");
        }
        if (findings.isEmpty()) {
            limits.add("NO_STATIC_FINDINGS");
        }
        if (findings.stream().anyMatch(finding -> finding.status() != Status.COMPLETE)) {
            limits.add("FINDING_PROOF_BOUNDED");
        }
        return stableLimits(limits);
    }

    private static String coverage(String mode, ScanStatistics statistics,
                                   List<String> limits) {
        if ("application".equals(mode) && limits.contains("NO_APPLICATION_ENTRY")) {
            return "BOUNDED";
        }
        String completeness = normalizeCoverage(statistics.completeness());
        String proof = normalizeCoverage(statistics.chainProofCompleteness());
        if ("UNKNOWN".equals(completeness) || "UNKNOWN".equals(proof)) {
            return "UNKNOWN";
        }
        return "COMPLETE".equals(completeness) && "COMPLETE".equals(proof)
                && limits.isEmpty() ? "COMPLETE" : "BOUNDED";
    }

    private static String outcome(ScanStatistics statistics, List<Finding> findings) {
        return switch (statistics.runOutcome().status()) {
            case FAILED, USAGE_ERROR -> "FAILED";
            case UNSUPPORTED -> "UNSUPPORTED";
            default -> findings.isEmpty() ? "NO_FINDINGS" : "FINDINGS_AVAILABLE";
        };
    }

    private static String normalizeCoverage(String value) {
        String normalized = required(value, "scan coverage").toUpperCase(Locale.ROOT);
        return switch (normalized) {
            case "COMPLETE" -> "COMPLETE";
            case "UNKNOWN" -> "UNKNOWN";
            case "BOUNDED", "PARTIAL", "NO_SURVIVING_CHAIN" -> "BOUNDED";
            default -> throw new IllegalArgumentException("unsupported scan coverage: " + value);
        };
    }

    private static String descriptorOrUnknown(String value) {
        return value == null || value.isBlank() ? "UNKNOWN" : value;
    }

    private static String methodDisplay(Method method) {
        return method.owner() + "#" + method.method();
    }

    private static String methodDisplay(String owner, String method) {
        return safe(owner) + "#" + safe(method);
    }

    private static String safe(String value) {
        return value == null || value.isBlank() ? "UNKNOWN" : value;
    }

    private static List<String> stableLimits(Iterable<String> input) {
        Objects.requireNonNull(input, "report limits");
        LinkedHashSet<String> normalized = new LinkedHashSet<>();
        for (String value : input) {
            if (value == null || value.isBlank()) {
                throw new IllegalArgumentException("report limit must not be blank");
            }
            String trimmed = value.trim();
            int detailSeparator = trimmed.indexOf(':');
            if (detailSeparator < 0) {
                normalized.add(trimmed.toUpperCase(Locale.ROOT));
            } else {
                normalized.add(trimmed.substring(0, detailSeparator).toUpperCase(Locale.ROOT)
                        + trimmed.substring(detailSeparator));
            }
        }
        return normalized.stream().sorted().toList();
    }

    private static String required(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value.trim();
    }

    private static String normalizeMode(String value) {
        String normalized = required(value, "report mode").toLowerCase(Locale.ROOT);
        if (!normalized.equals("component") && !normalized.equals("application")) {
            throw new IllegalArgumentException("unsupported report mode: " + value);
        }
        return normalized;
    }

    private static void appendFindingJson(StringBuilder out, Finding finding) {
        out.append("{\"id\":").append(quote(finding.id()))
                .append(",\"status\":").append(quote(finding.status().name()))
                .append(",\"entry\":");
        appendMethodJson(out, finding.entry());
        out.append(",\"impact\":");
        appendMethodJson(out, finding.impact());
        out.append(",\"graph\":[");
        for (int index = 0; index < finding.graph().size(); index++) {
            if (index > 0) {
                out.append(',');
            }
            GraphNode node = finding.graph().get(index);
            out.append("{\"role\":").append(quote(node.role().name()))
                    .append(",\"label\":").append(quote(node.label())).append('}');
        }
        out.append("],\"proof\":{")
                .append("\"entry\":").append(quote(finding.proof().entry()))
                .append(",\"site\":").append(quote(finding.proof().site()))
                .append(",\"input\":").append(quote(finding.proof().input()))
                .append(",\"callback\":").append(quote(finding.proof().callback()))
                .append(",\"bridge\":").append(quote(finding.proof().bridge()))
                .append(",\"terminal\":").append(quote(finding.proof().terminal()))
                .append(",\"feasibility\":").append(quote(finding.proof().feasibility()))
                .append('}');
        if (!finding.limits().isEmpty()) {
            out.append(",\"limits\":").append(strings(finding.limits()));
        }
        out.append('}');
    }

    private static void appendMethodJson(StringBuilder out, Method method) {
        out.append("{\"owner\":").append(quote(method.owner()))
                .append(",\"method\":").append(quote(method.method()))
                .append(",\"descriptor\":").append(quote(method.descriptor()));
        if (!method.kind().isBlank()) {
            out.append(",\"kind\":").append(quote(method.kind()));
        }
        if (!method.role().isBlank()) {
            out.append(",\"role\":").append(quote(method.role()));
        }
        out.append('}');
    }

    private static String strings(List<String> values) {
        StringBuilder out = new StringBuilder("[");
        for (int index = 0; index < values.size(); index++) {
            if (index > 0) {
                out.append(',');
            }
            out.append(quote(values.get(index)));
        }
        return out.append(']').toString();
    }

    private static String quote(String value) {
        StringBuilder out = new StringBuilder(value.length() + 2).append('"');
        for (int index = 0; index < value.length(); index++) {
            char ch = value.charAt(index);
            switch (ch) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (ch < 0x20) {
                        out.append(String.format(Locale.ROOT, "\\u%04x", (int) ch));
                    } else {
                        out.append(ch);
                    }
                }
            }
        }
        return out.append('"').toString();
    }

    private static String md(String value) {
        return value == null ? "" : value.replace("&", "&amp;")
                .replace("<", "&lt;").replace(">", "&gt;")
                .replace("|", "\\|").replace("\r", " ").replace("\n", " ");
    }
}
