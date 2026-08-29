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
                && plan.contains("NO_COMMAND_EXECUTION")
                && !plan.contains("\"payload_bytes\""));
    }
}
