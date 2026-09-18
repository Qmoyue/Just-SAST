package io.just.sast.report;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.FindingState;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.HopProvenance;
import io.just.sast.model.Descriptor;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * Report-boundary audit for one typed finding.
 *
 * <p>The solver owns facts and the report projection owns presentation, but neither may
 * silently turn a malformed or incomplete path into a complete report.  This audit is the
 * narrow seam between them: it checks every materialized hop and the application join axes
 * that the public status depends on.  It does not infer a missing hop, assign a type, or
 * execute a target class.</p>
 */
public final class ReportHopAudit {

    /** Per-hop findings retain their ordinal so an evidence consumer can locate the defect. */
    public record HopAudit(int index, List<String> issues) {
        public HopAudit {
            if (index < 0) {
                throw new IllegalArgumentException("hop index must be non-negative");
            }
            issues = stable(issues);
        }

        public boolean passed() {
            return issues.isEmpty();
        }

        private static List<String> stable(List<String> values) {
            if (values == null || values.isEmpty()) {
                return List.of();
            }
            return values.stream().filter(Objects::nonNull).filter(value -> !value.isBlank())
                    .map(String::trim).distinct().sorted().toList();
        }
    }

    /** Complete audit result used by the projection and by independent contract tests. */
    public record Result(List<HopAudit> hops, List<String> issues, List<String> limits) {
        public Result {
            hops = hops == null ? List.of() : List.copyOf(hops);
            issues = stable(issues);
            limits = stable(limits);
        }

        public boolean passed() {
            return issues.isEmpty();
        }

        private static List<String> stable(List<String> values) {
            if (values == null || values.isEmpty()) {
                return List.of();
            }
            return values.stream().filter(Objects::nonNull).filter(value -> !value.isBlank())
                    .map(String::trim).distinct().sorted().toList();
        }
    }

    private ReportHopAudit() {
    }

    /**
     * Audit one report candidate without solving or enriching it.
     *
     * <p>Application side-effect joins intentionally do not use typed callback assignability.
     * A deserializer may select an unrelated final class and run its setter before the framework
     * attempts to deliver the converter result to the declared controller parameter.  The
     * {@code DESERIALIZATION_SIDE_EFFECT} branch therefore requires deserialization evidence,
     * but never requires the setter owner to equal the controller parameter type.</p>
     */
    public static Result inspect(FindingOutputReader.Finding finding,
                                 ApplicationTrace trace, boolean applicationMode) {
        Objects.requireNonNull(finding, "finding");
        Chain chain = finding.chain();
        List<HopAudit> hopAudits = new ArrayList<>();
        List<String> issues = new ArrayList<>();

        if (chain.unresolvedHops() < 0) {
            issues.add("CONTROL_NEGATIVE_UNRESOLVED_HOPS");
        }
        if (blank(chain.entryClass()) || blank(chain.entryMethod())
                || blank(chain.sinkClass()) || blank(chain.sinkMethod())) {
            issues.add("OWNERSHIP_CHAIN_ENDPOINT_MISSING");
        }

        List<ChainHop> hops = chain.hops();
        for (int index = 0; index < hops.size(); index++) {
            int hopIndex = index;
            ChainHop hop = hops.get(index);
            List<String> hopIssues = new ArrayList<>();
            if (hop == null) {
                hopIssues.add("HOP_OWNERSHIP_MISSING");
                hopAudits.add(new HopAudit(index, hopIssues));
                issues.add(issueAt("HOP_OWNERSHIP_MISSING", index));
                continue;
            }
            auditOwnership(hop, hopIssues, applicationMode);
            auditDescriptor(hop, hopIssues);
            auditIdentity(hop, hopIssues, applicationMode);
            auditProvenance(hop, hopIssues);
            hopAudits.add(new HopAudit(index, hopIssues));
            hopIssues.forEach(value -> issues.add(issueAt(value, hopIndex)));
        }

        if (applicationMode) {
            auditApplication(finding, trace, issues);
        } else {
            auditComponent(finding, issues);
        }
        auditTerminal(finding, trace, applicationMode, issues);

        return new Result(hopAudits, issues, limitCodes(issues));
    }

    private static void auditOwnership(ChainHop hop, List<String> issues,
                                       boolean applicationMode) {
        if (blank(hop.fromOwner()) || blank(hop.fromName())
                || blank(hop.toOwner()) || blank(hop.toName())) {
            issues.add("HOP_OWNERSHIP_MISSING");
        }
        if (hop.kind() == null) {
            issues.add("HOP_KIND_MISSING");
        }
        if (hop.kind() == HopKind.FIELD_FLOW
                && (blank(hop.field()) || (applicationMode && blank(hop.fieldOwner())))) {
            issues.add("HOP_FIELD_OWNERSHIP_MISSING");
        }
    }

    private static void auditDescriptor(ChainHop hop, List<String> issues) {
        if (hop.kind() == null) {
            return;
        }
        if (hop.kind() == HopKind.FIELD_FLOW) {
            // A FIELD_FLOW descriptor, when present, is a field type in older producers.  Its
            // exact declaration is checked by the field/value owner, not as a method descriptor.
            return;
        }
        if (blank(hop.desc())) {
            issues.add("HOP_DESCRIPTOR_MISSING");
            return;
        }
        if (!validMethodDescriptor(hop.desc())) {
            issues.add("HOP_DESCRIPTOR_INVALID");
        }
    }

    private static void auditIdentity(ChainHop hop, List<String> issues,
                                      boolean applicationMode) {
        if (hop.argOrdinal() != null && hop.argOrdinal() < 0) {
            issues.add("HOP_ARGUMENT_IDENTITY_INVALID");
        }
        if (hop.kind() == HopKind.FIELD_FLOW && hop.argOrdinal() != null) {
            issues.add("HOP_FIELD_ARGUMENT_IDENTITY_INVALID");
        }
        if (hop.argOrdinal() == null || hop.desc() == null || hop.desc().isBlank()
                || hop.kind() == HopKind.FIELD_FLOW) {
            return;
        }
        // Enforce slot/descriptor agreement for materialized production chains.  Legacy
        // in-memory component fixtures without provenance intentionally remain compatible; a
        // real scan is enriched by HopProvenanceResolver before it reaches this boundary.
        if (!applicationMode && hop.provenance() == null) {
            return;
        }
        if (!validMethodDescriptor(hop.desc())) {
            return;
        }
        if (hop.argOrdinal() >= Descriptor.paramCount(hop.desc())) {
            issues.add("HOP_ARGUMENT_DESCRIPTOR_MISMATCH");
        }
    }

    private static void auditProvenance(ChainHop hop, List<String> issues) {
        HopProvenance provenance = hop.provenance();
        if (provenance == null) {
            return;
        }
        if (provenance.status() == HopProvenance.Status.PROVEN
                && (provenance.bytecodeOffset() == null || provenance.candidateCount() != 1
                || !validMethodDescriptor(provenance.methodDescriptor()))) {
            issues.add("HOP_PROVENANCE_INCONSISTENT");
        }
        if (provenance.status() == HopProvenance.Status.UNKNOWN
                && provenance.bytecodeOffset() != null) {
            issues.add("HOP_PROVENANCE_INCONSISTENT");
        }
    }

    private static void auditApplication(FindingOutputReader.Finding finding,
                                         ApplicationTrace trace, List<String> issues) {
        if (trace == null) {
            issues.add("APPLICATION_TRACE_MISSING");
            return;
        }
        if (unknown(trace.applicationEntryClass()) || unknown(trace.applicationEntryMethod())
                || unknown(trace.applicationSiteClass()) || unknown(trace.applicationSiteMethod())) {
            issues.add("APPLICATION_ENTRY_SITE_OWNERSHIP_UNKNOWN");
        }
        MethodRef prefix = parsePath(trace.entryPrefixPath());
        if (prefix == null) {
            issues.add("APPLICATION_ENTRY_DESCRIPTOR_UNKNOWN");
        } else if (!sameMethod(prefix, trace.applicationEntryClass(),
                trace.applicationEntryMethod())) {
            issues.add("APPLICATION_ENTRY_IDENTITY_MISMATCH");
        }

        MethodRef chainEntry = parsePath(trace.chainEntryMethod());
        if (chainEntry == null) {
            issues.add("CHAIN_ENTRY_IDENTITY_UNKNOWN");
        } else {
            Chain chain = finding.chain();
            String entryDescriptor = ChainIdentity.entryDescriptor(chain);
            if (!chainEntry.owner().equals(chain.entryClass())
                    || !chainEntry.name().equals(chain.entryMethod())) {
                issues.add("CHAIN_ENTRY_IDENTITY_MISMATCH");
            }
            if (!entryDescriptor.isBlank() && !entryDescriptor.equals(chainEntry.descriptor())) {
                issues.add("CHAIN_ENTRY_DESCRIPTOR_MISMATCH");
            }
            if (entryDescriptor.isBlank()) {
                issues.add("CHAIN_ENTRY_DESCRIPTOR_UNKNOWN");
            }
        }

        ApplicationTrace.JoinEvidence join = trace.joinEvidence();
        if (unknown(trace.joinKind())) {
            issues.add("BRIDGE_KIND_UNKNOWN");
        }
        if (join == null) {
            issues.add("BRIDGE_EVIDENCE_MISSING");
            return;
        }
        if (unknown(join.valueFlow()) || unknown(join.objectIdentity())
                || unknown(join.callbackSemantics()) || unknown(join.runtimeTypeProof())) {
            issues.add("BRIDGE_TYPED_AXES_UNKNOWN");
        }
        if (unknown(join.constructionConstraint())
                || !"SAT".equalsIgnoreCase(join.constructionConstraint())) {
            issues.add("CONTROL_CONSTRUCTION_NOT_SAT");
        }
        if ("DESERIALIZATION_SIDE_EFFECT".equals(trace.joinKind())
                && !"DESERIALIZATION".equals(join.callbackSemantics())) {
            issues.add("BRIDGE_DESERIALIZATION_SEMANTICS_MISMATCH");
        }
        if ("TYPED_BINDING_TARGET".equals(trace.joinKind())
                && "UNKNOWN".equals(join.runtimeTypeProof())) {
            issues.add("BRIDGE_TYPED_BINDING_TYPE_UNKNOWN");
        }
        FindingState state = finding.state();
        if (state.feasibility() != FindingState.Feasibility.SAT) {
            issues.add("CONTROL_FEASIBILITY_NOT_SAT");
        }
        if (state.completeness() != FindingState.Completeness.COMPLETE) {
            issues.add("CONTROL_COMPLETENESS_UNKNOWN");
        }
        if (state.chainProgress() != FindingState.ChainProgress.IMPACT_CHAIN_COMPLETE) {
            issues.add("CONTROL_IMPACT_INCOMPLETE");
        }
    }

    private static void auditComponent(FindingOutputReader.Finding finding, List<String> issues) {
        if (finding.chain().hops().isEmpty()) {
            issues.add("CHAIN_HOPS_MISSING");
        }
    }

    private static void auditTerminal(FindingOutputReader.Finding finding,
                                      ApplicationTrace trace, boolean applicationMode,
                                      List<String> issues) {
        Chain chain = finding.chain();
        if (!chain.terminalSink()) {
            return;
        }
        String sinkDescriptor = ChainIdentity.sinkDescriptor(chain);
        if (blank(sinkDescriptor)) {
            issues.add("TERMINAL_DESCRIPTOR_UNKNOWN");
        } else if (!validMethodDescriptor(sinkDescriptor)) {
            issues.add("TERMINAL_DESCRIPTOR_INVALID");
        }
        if (chain.hops().isEmpty()) {
            if (applicationMode && trace != null
                    && "DESERIALIZATION_SIDE_EFFECT".equals(trace.joinKind())) {
                // The side-effect join's dependency segment owns the terminal atom; the raw
                // callback chain may contain only the callback entry boundary.  Requiring a
                // synthetic setter -> controller call would be the exact Fastjson type error
                // this audit exists to prevent.
                return;
            }
            issues.add("TERMINAL_HOP_MISSING");
            return;
        }
        boolean terminalHop = chain.hops().stream().filter(Objects::nonNull).anyMatch(hop ->
                Objects.equals(chain.sinkClass(), hop.toOwner())
                        && Objects.equals(chain.sinkMethod(), hop.toName()));
        if (!terminalHop && !(applicationMode && trace != null
                && "DESERIALIZATION_SIDE_EFFECT".equals(trace.joinKind()))) {
            issues.add("TERMINAL_HOP_IDENTITY_MISSING");
        }
        if (applicationMode && trace != null
                && (unknown(trace.terminalOwner()) || unknown(trace.terminalMethod()))) {
            issues.add("TERMINAL_OWNERSHIP_UNKNOWN");
        } else if (applicationMode && trace != null
                && (!chain.sinkClass().equals(trace.terminalOwner())
                || !chain.sinkMethod().equals(trace.terminalMethod()))) {
            issues.add("TERMINAL_IDENTITY_MISMATCH");
        }
    }

    private static List<String> limitCodes(List<String> issues) {
        Set<String> codes = new LinkedHashSet<>();
        for (String issue : issues) {
            int boundary = issue.indexOf('[');
            codes.add((boundary < 0 ? issue : issue.substring(0, boundary))
                    .toUpperCase(Locale.ROOT));
        }
        return codes.stream().sorted().toList();
    }

    private static String issueAt(String issue, int index) {
        return issue + "[hop=" + index + "]";
    }

    private static boolean validMethodDescriptor(String descriptor) {
        if (blank(descriptor) || !descriptor.startsWith("(")) {
            return false;
        }
        try {
            int count = Descriptor.paramCount(descriptor);
            for (int index = 0; index < count; index++) {
                if (!validType(Descriptor.paramType(descriptor, index), false)) {
                    return false;
                }
            }
            return validType(Descriptor.returnType(descriptor), true);
        } catch (RuntimeException invalid) {
            return false;
        }
    }

    private static boolean validType(String descriptor, boolean returnType) {
        if (descriptor == null || descriptor.isBlank()) {
            return false;
        }
        int start = 0;
        while (start < descriptor.length() && descriptor.charAt(start) == '[') {
            start++;
        }
        if (start >= descriptor.length()) {
            return false;
        }
        String base = descriptor.substring(start);
        if (base.equals("V")) {
            return returnType && start == 0;
        }
        if (base.length() == 1 && "BCDFIJSZ".indexOf(base.charAt(0)) >= 0) {
            return true;
        }
        return base.startsWith("L") && base.endsWith(";") && base.length() > 2
                && base.indexOf('.') < 0 && base.indexOf('[') < 0;
    }

    private static MethodRef parsePath(String value) {
        if (blank(value)) {
            return null;
        }
        String first = value.split("->", 2)[0];
        int hash = first.indexOf('#');
        int open = first.indexOf('(', hash + 1);
        if (hash <= 0 || open <= hash + 1 || open == first.length()) {
            return null;
        }
        String owner = first.substring(0, hash);
        String name = first.substring(hash + 1, open);
        String descriptor = first.substring(open);
        return blank(owner) || blank(name) || !validMethodDescriptor(descriptor)
                ? null : new MethodRef(owner, name, descriptor);
    }

    private static boolean sameMethod(MethodRef path, String owner, String member) {
        if (path == null || blank(owner) || blank(member)) {
            return false;
        }
        int open = member.indexOf('(');
        String name = open < 0 ? member : member.substring(0, open);
        return path.owner().equals(owner) && path.name().equals(name)
                && (open < 0 || path.descriptor().equals(member.substring(open)));
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }

    private static boolean unknown(String value) {
        return blank(value) || "UNKNOWN".equalsIgnoreCase(value.trim());
    }

    private record MethodRef(String owner, String name, String descriptor) {
    }
}
