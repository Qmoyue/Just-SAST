package io.just.sast.report;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Application empty-result limits distinguish missing joins from rejected joined candidates. */
class ConciseReportApplicationLimitContractTest {

    @Test
    void joinedApplicationCandidateDoesNotClaimMissingApplicationEntry() {
        Chain chain = new Chain("JUST-SINK-COMMAND-EXEC-RUNTIME", "COMMAND", "HIGH",
                "dep/Gadget", "readObject", "readObject", "java/lang/Runtime", "exec",
                List.of(new ChainHop("dep/Gadget", "readObject", "java/lang/Runtime",
                        "exec", HopKind.DIRECT_CALL, null, "bytecode",
                        "(Ljava/lang/String;)Ljava/lang/Process;", 0)), 0,
                "(Ljava/lang/String;)Ljava/lang/Process;");
        FindingOutputReader.Snapshot base = new FindingOutputReader().read(
                List.of(chain), Map.of(), Map.of(), Map.of(), true);
        ApplicationTrace trace = new ApplicationTrace("app/Main", "main", "app/Main",
                "handle", "HTTP_SERVER", "HTTP_SERVER", "dep/Gadget#readObject()V",
                "app/Main#main([Ljava/lang/String;)V", "dep/Gadget", "java/lang/Runtime",
                "exec");
        FindingOutputReader.Snapshot snapshot = new FindingOutputReader.Snapshot(
                base.schemaVersion(), base.findings(), base.byChainKey(),
                Map.of(chain.key(), trace));

        ConciseReportProjection projection = ConciseReportProjection.from(
                "application", snapshot, ScanStatistics.empty());

        assertTrue(projection.findings().isEmpty());
        assertTrue(projection.result().limits().contains("NO_STATIC_FINDINGS"));
        assertFalse(projection.result().limits().contains("NO_APPLICATION_ENTRY"));
    }
}
