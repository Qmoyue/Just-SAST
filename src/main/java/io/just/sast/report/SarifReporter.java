package io.just.sast.report;

import io.just.sast.blackboard.Chain;
import io.just.sast.chain.ChainIds;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * C1: SARIF 2.1.0 输出（GitHub Code Scanning / IDE 集成标准格式）。
 * 每条链 → SARIF result（ruleId、message、properties、location 映射到入口类）。
 */
public final class SarifReporter {

    public void write(Path outDir, List<Chain> chains,
                      Map<String, String> calibrations, Map<String, List<String>> notes) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"version\": \"2.1.0\",\n");
        sb.append("  \"$schema\": \"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json\",\n");
        sb.append("  \"runs\": [{\n");
        sb.append("    \"tool\": {\n");
        sb.append("      \"driver\": {\n");
        sb.append("        \"name\": \"just-sast\",\n");
        sb.append("        \"version\": \"0.2.0\",\n");
        sb.append("        \"informationUri\": \"https://github.com/just-sast/just\"\n");
        sb.append("      }\n");
        sb.append("    },\n");
        sb.append("    \"results\": [\n");
        List<String> results = new ArrayList<>();
        int seq = 0;
        for (Chain chain : chains) {
            if (calibrations.containsKey(chain.key())) {
                continue;
            }
            seq++;
            List<String> chainNotes = notes.getOrDefault(chain.key(), List.of());
            String confidence = chainNotes.contains("verify:constructible") ? "FEASIBLE"
                    : "DEGRADED";
            String ruleId = chain.ruleId() != null ? chain.ruleId() : "unknown";
            String entryClassDotted = chain.entryClass().replace('/', '.');
            String message = escape(chain.entryKind() + " → " + chain.sinkClass().replace('/', '.') + "." + chain.sinkMethod());
            String props = "\"confidence\":\"" + confidence + "\""
                    + ",\"unresolved_hops\":" + chain.unresolvedHops()
                    + ",\"chain_length\":" + chain.hops().size();
            if (!chainNotes.isEmpty()) {
                props += ",\"notes\":" + jsonArray(chainNotes);
            }
            results.add("      {\n"
                    + "        \"ruleId\": \"" + ruleId + "\",\n"
                    + "        \"level\": \"warning\",\n"
                    + "        \"message\": {\"text\": \"" + message + "\"},\n"
                    + "        \"locations\": [{\n"
                    + "          \"physicalLocation\": {\n"
                    + "            \"artifactLocation\": {\"uri\": \"" + entryClassDotted + ".class\"}\n"
                    + "          }\n"
                    + "        }],\n"
                    + "        \"properties\": {" + props + "}\n"
                    + "      }");
        }
        sb.append(String.join(",\n", results));
        sb.append("\n    ]\n");
        sb.append("  }]\n");
        sb.append("}");
        Files.write(outDir.resolve("findings.sarif"), sb.toString().getBytes(StandardCharsets.UTF_8));
    }

    private static String escape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String jsonArray(List<String> items) {
        return "[" + items.stream().map(i -> "\"" + escape(i) + "\"")
                .reduce((a, b) -> a + "," + b).orElse("") + "]";
    }
}
