package io.just.sast.report;

import io.just.sast.analysis.hierarchy.ClassHierarchy;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.VerificationSummary;
import io.just.sast.chain.ChainRanking;
import io.just.sast.chain.ChainPrecision;
import io.just.sast.chain.ConfidenceScorer;
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

/**
 * C1: SARIF 2.1.0 输出（GitHub Code Scanning / IDE 集成标准格式）。
 * 每个链组（rule×入口×sink 去重）→ 一个 result：driver.rules 全量声明、severity→level 映射、
 * region.startLine 定位入口方法首行（需 withHierarchy）、uri 用内部名路径、confidence 口径与
 * findings.csv 一致（verify:confirmed / ConfidenceScorer）、partialFingerprints 供 PR 去重。
 */
public final class SarifReporter {

    private ClassHierarchy hierarchy;
    private RuleSet ruleSet;

    /** 供 startLine 解析的类层次（ScanPipeline 报告期接线；缺省不输出 region）。 */
    public SarifReporter withHierarchy(ClassHierarchy hierarchy) {
        this.hierarchy = hierarchy;
        return this;
    }

    /** 供 driver.rules 声明的规则集。 */
    public SarifReporter withRules(RuleSet ruleSet) {
        this.ruleSet = ruleSet;
        return this;
    }

    public void write(Path outDir, List<Chain> chains,
                      Map<String, String> calibrations, Map<String, List<String>> notes) throws IOException {
        write(ReportLayout.flat(outDir), chains, calibrations, notes, null);
    }

    public void write(ReportLayout layout, List<Chain> chains,
                      Map<String, String> calibrations, Map<String, List<String>> notes) throws IOException {
        write(layout, chains, calibrations, notes, null);
    }

    public void write(ReportLayout layout, List<Chain> chains,
                      Map<String, String> calibrations, Map<String, List<String>> notes,
                      VerificationSummary verification) throws IOException {
        chains = chains == null ? List.of() : chains;
        calibrations = calibrations == null ? Map.of() : calibrations;
        final Map<String, List<String>> stableNotes = notes == null ? Map.of() : notes;
        Files.createDirectories(layout.findings());
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"version\": \"2.1.0\",\n");
        sb.append("  \"$schema\": \"https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json\",\n");
        sb.append("  \"runs\": [{\n");
        sb.append("    \"tool\": {\n");
        sb.append("      \"driver\": {\n");
        sb.append("        \"name\": \"just-sast\",\n");
        sb.append("        \"version\": \"0.2.0\",\n");
        sb.append("        \"informationUri\": \"https://github.com/just-sast/just\",\n");
        sb.append("        \"rules\": [").append(rulesArray()).append("]\n");
        sb.append("      }\n");
        sb.append("    },\n");
        sb.append("    \"results\": [");
        List<String> results = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        Map<String, VerificationSummary.ChainResult> verificationByKey = verificationByKey(verification);
        boolean structuredVerification = verification != null;
        List<Chain> orderedChains = new ArrayList<>(chains);
        // All report projections must consume the same deterministic evidence tuple.  The
        // former SARIF-only "high confidence, then shortest path" order could disagree with
        // CSV/JSON/Markdown when two variants shared a dynamic status but differed in
        // construction, completeness, dispatch, or static evidence.  High-confidence remains
        // visible as a property; it is not a second, format-specific ranking contract.
        orderedChains.sort(ChainRanking.comparator(stableNotes, verificationByKey, Set.of()));
        for (Chain chain : orderedChains) {
            if (calibrations.containsKey(chain.key())) {
                continue;
            }
            String ruleId = chain.ruleId() != null ? chain.ruleId() : "unknown";
            if (!seen.add(resultIdentity(chain, ruleId))) {
                continue; // 同组变体只报一次（与 findings.csv 折叠口径一致）
            }
            List<String> chainNotes = stableNotes.getOrDefault(chain.key(), List.of());
            if (chainNotes == null) {
                chainNotes = List.of();
            }
            VerificationSummary.ChainResult verificationResult = verificationByKey.get(chain.key());
            ChainPrecision.Assessment precision = ChainPrecision.assess(chain, chainNotes,
                    verificationResult);
            String confidence = verificationResult != null ? verificationResult.status()
                    : structuredVerification ? "NOT_SELECTED"
                    : legacyConfidence(chain, chainNotes);
            String message = escape(chain.entryKind() + " → " + chain.sinkClass().replace('/', '.')
                    + "." + chain.sinkMethod());
            String props = "\"confidence\":\"" + escape(confidence) + "\""
                    + ",\"high_confidence\":"
                    + ChainPrecision.isHighConfidence(chain, chainNotes, verificationResult)
                    + ",\"entry_kind\":\"" + escape(chain.entryKind()) + "\""
                    + ",\"entry_descriptor\":\"" + escape(entryDescriptor(chain)) + "\""
                    + ",\"sink_descriptor\":\"" + escape(sinkDescriptor(chain)) + "\""
                    + ",\"sink_role\":\"" + escape(chain.sinkRole()) + "\""
                    + ",\"unresolved_hops\":" + chain.unresolvedHops()
                    + ",\"chain_length\":" + chain.hops().size()
                    + ",\"verification_status\":\"" + escape(confidence) + "\""
                    + ",\"verification_evidence\":\""
                    + escape(verificationResult == null ? "" : verificationResult.evidence()) + "\""
                    + ",\"backend\":\""
                    + escape(verificationResult == null ? "UNKNOWN" : verificationResult.backend()) + "\""
                    + ",\"jdk\":\""
                    + escape(verificationResult == null ? "UNKNOWN" : verificationResult.jdk()) + "\""
                    + ",\"policy_digest\":\""
                    + escape(verificationResult == null ? "UNKNOWN" : verificationResult.policyDigest()) + "\""
                    + ",\"sink_distorted\":"
                    + (verificationResult != null && verificationResult.sinkDistorted())
                    + ",\"sandbox_ready\":"
                    + (verificationResult != null && verificationResult.sandboxReady())
                    + ",\"precision\":"
                    + ChainPrecision.toJson(precision, SarifReporter::escape)
                    + ",\"construction\":"
                    + ReportEvidence.constructionJson(chain, chainNotes, verificationResult);
            if (!chainNotes.isEmpty()) {
                props += ",\"notes\":" + jsonArray(chainNotes);
            }
            results.add("\n      {\n"
                    + "        \"ruleId\": \"" + escape(ruleId) + "\",\n"
                    + "        \"level\": \"" + ("HIGH".equals(chain.severity()) || "CRITICAL".equals(chain.severity()) ? "error" : "warning") + "\",\n"
                    + "        \"message\": {\"text\": \"" + message + "\"},\n"
                    + "        \"locations\": [{\n"
                    + "          \"physicalLocation\": {\n"
                    + "            \"artifactLocation\": {\"uri\": \"" + chain.entryClass() + ".class\"},\n"
                    + regionOf(chain)
                    + "          }\n"
                    + "        }],\n"
                    + "        \"partialFingerprints\": {\"just/v1\": \"" + fingerprint(chain, ruleId) + "\"},\n"
                    + "        \"properties\": {" + props + "}\n"
                    + "      }");
        }
        sb.append(String.join(",", results));
        sb.append("\n    ]\n");
        sb.append("  }]\n");
        sb.append("}");
        AtomicFiles.writeUtf8(layout.findings().resolve("findings.sarif"), sb.toString());
    }

    private static String legacyConfidence(Chain chain, List<String> notes) {
        if (notes.stream().anyMatch("verify:confirmed"::equals)
                && !notes.stream().anyMatch("verify:sink-blocked"::equals)) {
            // Keep the legacy display label for downstream SARIF consumers; ordering uses
            // the normalized SINK_BLOCKED tier through ChainRanking.
            return "CONFIRMED";
        }
        String status = ConfidenceScorer.statusFromNotes(notes);
        return status.isBlank() ? ConfidenceScorer.score(chain, notes) : status;
    }

    /** 入口方法首行（ENTRY 跳携带描述符；层次/行号缺失输出空段——不造假日行号）。 */
    private String regionOf(Chain chain) {
        if (hierarchy == null) {
            return "";
        }
        for (ChainHop hop : chain.hops()) {
            if (hop.kind() == HopKind.ENTRY && hop.desc() != null) {
                var ci = hierarchy.classInfo(hop.fromOwner());
                var mi = ci != null ? ci.method(hop.fromName(), hop.desc()) : null;
                if (mi != null && mi.entryLine() > 0) {
                    return "            \"region\": {\"startLine\": " + mi.entryLine() + "},\n";
                }
                break;
            }
        }
        return "";
    }

    /** PR 去重指纹：rule×入口×sink 的稳定摘要（路径变体不产生新指纹）。 */
    private static String fingerprint(Chain chain, String ruleId) {
        String src = resultIdentity(chain, ruleId);
        try {
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(src.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (int i = 0; i < 8; i++) {
                hex.append(String.format("%02x", digest[i]));
            }
            return hex.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
            return Integer.toHexString(src.hashCode());
        }
    }

    /** driver.rules：sink 规则全量声明（result 引用的 ruleId 须在此，GitHub 渲染依赖）。 */
    private String rulesArray() {
        if (ruleSet == null) {
            return "";
        }
        List<String> rules = new ArrayList<>();
        Set<String> ids = new HashSet<>();
        for (var rule : ruleSet.sinks()) {
            if (!ids.add(rule.id())) {
                continue;
            }
            rules.add("{\"id\": \"" + escape(rule.id()) + "\", \"shortDescription\": {\"text\": \""
                    + escape(rule.category()) + "\"}}");
        }
        return String.join(",", rules);
    }

    private static String escape(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }

    private static Map<String, VerificationSummary.ChainResult> verificationByKey(
            VerificationSummary verification) {
        if (verification == null || verification.results().isEmpty()) {
            return Map.of();
        }
        Map<String, VerificationSummary.ChainResult> result = new java.util.HashMap<>();
        for (VerificationSummary.ChainResult item : verification.results()) {
            result.putIfAbsent(item.chainKey(), item);
        }
        return result;
    }

    private static String resultIdentity(Chain chain, String ruleId) {
        return ruleId + "|" + chain.category() + "|" + chain.entryClass() + "|" + chain.entryMethod()
                + "|" + entryDescriptor(chain) + "|" + chain.entryKind()
                + "|" + chain.sinkClass() + "|" + chain.sinkMethod()
                + "|" + sinkDescriptor(chain) + "|" + chain.sinkRole();
    }

    private static String entryDescriptor(Chain chain) {
        for (ChainHop hop : chain.hops()) {
            if (hop.kind() == HopKind.ENTRY && hop.desc() != null) {
                return hop.desc();
            }
        }
        return "";
    }

    private static String sinkDescriptor(Chain chain) {
        if (chain.sinkDescriptor() != null && !chain.sinkDescriptor().isEmpty()) {
            return chain.sinkDescriptor();
        }
        for (ChainHop hop : chain.hops()) {
            if (chain.sinkClass().equals(hop.toOwner()) && chain.sinkMethod().equals(hop.toName())
                    && hop.desc() != null && !hop.desc().isEmpty()) {
                return hop.desc();
            }
        }
        return "";
    }

    private static String jsonArray(List<String> items) {
        return "[" + items.stream().map(i -> "\"" + escape(i) + "\"")
                .reduce((a, b) -> a + "," + b).orElse("") + "]";
    }
}
