package io.just.sast.report;

import io.just.sast.analysis.hierarchy.ClassHierarchy;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;
import io.just.sast.chain.ChainPrecision;
import io.just.sast.chain.ChainRanking;
import io.just.sast.config.RuleSet;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Optional SARIF 2.1.0 view of the canonical static finding snapshot. */
public final class SarifReporter {

    private ClassHierarchy hierarchy;
    private RuleSet ruleSet;

    public SarifReporter withHierarchy(ClassHierarchy hierarchy) {
        this.hierarchy = hierarchy;
        return this;
    }

    public SarifReporter withRules(RuleSet ruleSet) {
        this.ruleSet = ruleSet;
        return this;
    }

    public void write(Path outDir, List<Chain> chains,
                      Map<String, String> calibrations, Map<String, List<String>> notes)
            throws IOException {
        write(ReportLayout.flat(outDir), chains, calibrations, notes);
    }

    public void write(ReportLayout layout, List<Chain> chains,
                      Map<String, String> calibrations, Map<String, List<String>> notes)
            throws IOException {
        write(layout, new FindingOutputReader().read(chains, calibrations, notes));
    }

    public void write(ReportLayout layout, FindingOutputReader.Snapshot output)
            throws IOException {
        write(layout, output, null);
    }

    public void write(ReportLayout layout, FindingOutputReader.Snapshot output,
                      io.just.sast.run.RunOutcome runOutcome) throws IOException {
        if (layout == null) {
            throw new IOException("report layout is null");
        }
        if (output == null) {
            throw new IOException("finding output snapshot is null");
        }
        List<Chain> chains = output.findings().stream()
                .map(FindingOutputReader.Finding::chain).toList();
        Map<String, List<String>> stableNotes = new java.util.TreeMap<>();
        for (FindingOutputReader.Finding finding : output.findings()) {
            stableNotes.putIfAbsent(finding.chain().key(), finding.notes());
        }
        Files.createDirectories(layout.evidence());
        StringBuilder sb = new StringBuilder();
        sb.append("{\n")
                .append("  \"version\": \"2.1.0\",\n")
                .append("  \"$schema\": \"https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json\",\n")
                .append("  \"runs\": [{\n")
                .append("    \"tool\": {\n      \"driver\": {\n")
                .append("        \"name\": \"just-sast\",\n")
                .append("        \"version\": \"0.2.1\",\n")
                .append("        \"informationUri\": \"https://github.com/just-sast/just\",\n")
                .append("        \"rules\": [").append(rulesArray()).append("]\n")
                .append("      }\n    },\n");
        if (runOutcome != null) {
            sb.append("    \"properties\": {\"just/run_outcome\":")
                    .append(runOutcome.toCanonicalJson()).append("},\n");
        }
        sb.append("    \"results\": [");
        List<String> results = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        List<Chain> orderedChains = new ArrayList<>(chains);
        orderedChains.sort(ChainRanking.comparator(stableNotes, Set.of()));
        for (Chain chain : orderedChains) {
            FindingOutputReader.Finding finding = output.byChainKey().get(chain.key());
            if (finding == null || !seen.add(resultIdentity(chain, chain.ruleId()))) {
                continue;
            }
            List<String> chainNotes = stableNotes.getOrDefault(chain.key(), List.of());
            ChainPrecision.Assessment precision = finding.precision();
            String props = "\"confidence\":\"" + escape(finding.confidence().bucket()) + "\""
                    + ",\"high_confidence\":" + finding.highConfidence()
                    + ",\"entry_kind\":\"" + escape(chain.entryKind()) + "\""
                    + ",\"entry_descriptor\":\"" + escape(entryDescriptor(chain)) + "\""
                    + ",\"sink_descriptor\":\"" + escape(sinkDescriptor(chain)) + "\""
                    + ",\"sink_role\":\"" + escape(chain.sinkRole()) + "\""
                    + ",\"sink_risk\":\"" + escape(chain.sinkRisk().name()) + "\""
                    + ",\"unresolved_hops\":" + chain.unresolvedHops()
                    + ",\"chain_length\":" + chain.hops().size()
                    + ",\"precision\":" + ChainPrecision.toJson(precision,
                    SarifReporter::escape, finding.highConfidence())
                    + ",\"construction\":"
                    + ReportEvidence.constructionJson(finding.construction())
                    + ",\"state\":{\"entry_status\":\""
                    + escape(finding.state().entryStatus().name())
                    + "\",\"chain_progress\":\""
                    + escape(finding.state().chainProgress().name())
                    + "\",\"feasibility\":\""
                    + escape(finding.state().feasibility().name())
                    + "\",\"completeness\":\""
                    + escape(finding.state().completeness().name())
                    + "\",\"risk\":\"" + escape(finding.state().risk().name())
                    + "\",\"eligibility\":\""
                    + escape(finding.state().eligibility().name()) + "\"}"
                    + ",\"violations\":" + jsonArray(finding.typedViolations());
            ApplicationTrace applicationTrace = output.applicationTrace(chain.key());
            if (applicationTrace != null) {
                props += ",\"application_entry_class\":\""
                        + escape(applicationTrace.applicationEntryClass())
                        + "\",\"application_entry_method\":\""
                        + escape(applicationTrace.applicationEntryMethod())
                        + "\",\"application_site_class\":\""
                        + escape(applicationTrace.applicationSiteClass())
                        + "\",\"application_site_method\":\""
                        + escape(applicationTrace.applicationSiteMethod())
                        + "\",\"application_site_kind\":\""
                        + escape(applicationTrace.applicationSiteKind())
                        + "\",\"application_join_kind\":\""
                        + escape(applicationTrace.joinKind())
                        + "\",\"application_path\":\""
                        + escape(applicationTrace.applicationPath(chain)) + "\"";
            }
            if (!chainNotes.isEmpty()) {
                props += ",\"notes\":" + jsonArray(chainNotes);
            }
            String level = "HIGH".equals(chain.severity()) || "CRITICAL".equals(chain.severity())
                    ? "error" : "warning";
            results.add("\n      {\n"
                    + "        \"ruleId\": \"" + escape(chain.ruleId()) + "\",\n"
                    + "        \"level\": \"" + level + "\",\n"
                    + "        \"message\": {\"text\": \""
                    + escape(chain.entryKind() + " → " + chain.sinkClass().replace('/', '.')
                    + "." + chain.sinkMethod()) + "\"},\n"
                    + "        \"locations\": [{\n"
                    + "          \"physicalLocation\": {\n"
                    + "            \"artifactLocation\": {\"uri\": \""
                    + escape(chain.entryClass() + ".class") + "\"}"
                    + regionOf(chain)
                    + "          }\n        }],\n"
                    + "        \"partialFingerprints\": {\"just/v1\": \""
                    + fingerprint(chain, chain.ruleId()) + "\"},\n"
                    + "        \"properties\": {" + props + "}\n"
                    + "      }");
        }
        sb.append(String.join(",", results)).append("\n    ]\n  }]\n}");
        AtomicFiles.writeUtf8(layout.evidence().resolve("findings.sarif"), sb.toString());
    }

    private String regionOf(Chain chain) {
        if (hierarchy == null) return "";
        for (ChainHop hop : chain.hops()) {
            if (hop.kind() == HopKind.ENTRY && hop.desc() != null) {
                var ci = hierarchy.classInfo(hop.fromOwner());
                var mi = ci != null ? ci.method(hop.fromName(), hop.desc()) : null;
                if (mi != null && mi.entryLine() > 0) {
                    return ",\n            \"region\": {\"startLine\": " + mi.entryLine() + "}\n";
                }
                break;
            }
        }
        return "\n";
    }

    private static String fingerprint(Chain chain, String ruleId) {
        String src = resultIdentity(chain, ruleId);
        try {
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(src.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (int i = 0; i < 8; i++) hex.append(String.format("%02x", digest[i]));
            return hex.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("required SHA-256 digest unavailable", e);
        }
    }

    private String rulesArray() {
        if (ruleSet == null) return "";
        List<String> rules = new ArrayList<>();
        Set<String> ids = new HashSet<>();
        for (var rule : ruleSet.sinks()) {
            if (ids.add(rule.id())) {
                rules.add("{\"id\": \"" + escape(rule.id())
                        + "\", \"shortDescription\": {\"text\": \""
                        + escape(rule.category()) + "\"}}");
            }
        }
        return String.join(",", rules);
    }

    private static String resultIdentity(Chain chain, String ruleId) {
        return ruleId + "|" + chain.category() + "|" + chain.entryClass() + "|"
                + chain.entryMethod() + "|" + entryDescriptor(chain) + "|" + chain.entryKind()
                + "|" + chain.sinkClass() + "|" + chain.sinkMethod() + "|"
                + sinkDescriptor(chain) + "|" + chain.sinkRole();
    }

    private static String entryDescriptor(Chain chain) {
        for (ChainHop hop : chain.hops()) {
            if (hop.kind() == HopKind.ENTRY && hop.desc() != null) return hop.desc();
        }
        return "";
    }

    private static String sinkDescriptor(Chain chain) {
        if (chain.sinkDescriptor() != null && !chain.sinkDescriptor().isEmpty()) {
            return chain.sinkDescriptor();
        }
        for (ChainHop hop : chain.hops()) {
            if (chain.sinkClass().equals(hop.toOwner()) && chain.sinkMethod().equals(hop.toName())
                    && hop.desc() != null && !hop.desc().isEmpty()) return hop.desc();
        }
        return "";
    }

    private static String jsonArray(List<String> items) {
        return "[" + items.stream().map(i -> "\"" + escape(i) + "\"")
                .reduce((a, b) -> a + "," + b).orElse("") + "]";
    }

    private static String escape(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }
}
