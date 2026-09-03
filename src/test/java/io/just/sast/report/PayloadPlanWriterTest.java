package io.just.sast.report;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.VerificationSummary;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;

class PayloadPlanWriterTest {

    @Test
    void writesInertFieldAndVerificationPlan(@TempDir Path temp) throws Exception {
        Chain chain = new Chain("R", "C", "HIGH", "app/Entry", "readObject",
                "readObject", "java/lang/Runtime", "exec", List.of(
                new ChainHop("app/Entry", "readObject", "app/Holder", "value",
                        HopKind.FIELD_FLOW, "value", "field-read", "", null)), 0);
        VerificationSummary verification = new VerificationSummary(
                "JVM_SANDBOX", 1, 1, 0, 1,
                Map.of("CONFIRMED", 1), Map.of(),
                List.of(new VerificationSummary.ChainResult(
                        1, chain.key(), "CONFIRMED", "SINK_REACHED",
                        "HIGH", 10, 1, 4)));

        new PayloadPlanWriter().write(temp, List.of(chain), Map.of(),
                Map.of(chain.key(), List.of("verify:constructible")), verification);

        String plan = Files.readString(temp.resolve("payload-plan.json"));
        assertTrue(plan.contains("\"mode\":\"INERT_OBJECT_GRAPH_PLAN\"")
                && plan.contains("\"strategy\":\"IN_MEMORY_REFERENCE\"")
                && plan.contains("\"status\":\"CONFIRMED\"")
                && plan.contains("\"shape_summary\":")
                && plan.contains("\"status\":\"SHAPE_PARTIAL\"")
                && plan.contains("NO_COMMAND_EXECUTION")
                && !plan.contains("\"payload_bytes\""));

        String readableJson = Files.readString(temp.resolve("payload.json"));
        String readableMarkdown = Files.readString(temp.resolve("payload.md"));
        assertTrue(readableJson.contains("\"steps\"")
                && readableJson.contains("\"execution\":\"RECORDED_BY_BOUNDED_CHILD_JVM\"")
                && readableJson.contains("\"verification_group\":\"unverified\"")
                && readableJson.contains("\"observed_boundary\":\"NOT_PROVEN\"")
                && !readableJson.contains("BLOCK_BEFORE_SINK_BODY"));
        assertTrue(readableMarkdown.contains("### Steps")
                && readableMarkdown.contains("SINK BOUNDARY")
                && readableMarkdown.contains("SINK BOUNDARY NOT PROVEN"));
    }

    @Test
    void keepsSinkBlockedBoundarySeparateFromPayloadExecution(@TempDir Path temp) throws Exception {
        Chain chain = new Chain("R", "C", "HIGH", "app/Entry", "readObject",
                "readObject", "java/lang/Runtime", "exec", List.of(), 0);
        VerificationSummary verification = new VerificationSummary(
                "JVM_SANDBOX", 1, 1, 0, 1,
                Map.of("SINK_BLOCKED", 1), Map.of(),
                List.of(new VerificationSummary.ChainResult(
                        1, chain.key(), "SINK_BLOCKED", "sink-canary",
                        "HIGH", 10, 1, 4, "SINK_CANARY_BOUNDARY")));

        new PayloadPlanWriter().write(temp, List.of(chain), Map.of(), Map.of(), verification);

        String readableJson = Files.readString(temp.resolve("payload.json"));
        String readableMarkdown = Files.readString(temp.resolve("payload.md"));
        assertTrue(readableJson.contains("\"status\":\"SINK_BLOCKED\"")
                        && readableJson.contains("\"observed_boundary\":\"SINK_BLOCKED_BEFORE_BODY\"")
                        && readableJson.contains("\"execution\":\"RECORDED_BY_BOUNDED_CHILD_JVM\"")
                        && readableJson.contains("\"verification_group\":\"boundary_only\""),
                "canary 边界必须与最终 payload 执行严格分离：\n" + readableJson);
        assertTrue(readableMarkdown.contains("SINK BLOCKED BEFORE BODY")
                        && readableMarkdown.contains("real prefix reached the canary")
                        && readableMarkdown.contains("No command, network, native load"),
                "人类可读视图必须说明 canary 边界和安全限制：\n" + readableMarkdown);
    }

    @Test
    void marksSafeEffectAsDistortedAndNotAsRealSinkExecution(@TempDir Path temp) throws Exception {
        Chain chain = new Chain("R", "C", "HIGH", "app/Entry", "readObject",
                "readObject", "java.lang.Runtime", "exec", List.of(), 0);
        VerificationSummary verification = new VerificationSummary(
                "OS_SANDBOX", 1, 1, 0, 1,
                Map.of("SAFE_EFFECT_OBSERVED", 1), Map.of(),
                List.of(new VerificationSummary.ChainResult(
                        1, chain.key(), "SAFE_EFFECT_OBSERVED", "SAFE_EFFECT_OBSERVED:COMMAND",
                        "HIGH", 10, 1, 4, "SAFE_EFFECT_OBSERVED")));

        new PayloadPlanWriter().write(temp, List.of(chain), Map.of(), Map.of(), verification);

        String readableJson = Files.readString(temp.resolve("payload.json"));
        String readableMarkdown = Files.readString(temp.resolve("payload.md"));
        assertTrue(readableJson.contains("SAFE_EFFECT_OBSERVED_WITH_DISTORTION")
                        && readableJson.contains("RECORDED_BY_BOUNDED_CHILD_JVM")
                        && readableJson.contains("\"verification_group\":\"unverified\"")
                        && !readableJson.contains("SAFE_SINK_EXECUTED"),
                "safe effect 必须保留失真且不能升级为真实 sink 执行：\n" + readableJson);
        assertTrue(readableMarkdown.contains("SAFE EFFECT OBSERVED; REAL SINK NOT ENTERED")
                        && readableMarkdown.contains("intentionally distorted")
                        && readableMarkdown.contains("does not prove RCE"),
                "人类可读视图必须明确 safe-exec 失真：\n" + readableMarkdown);
    }
}
