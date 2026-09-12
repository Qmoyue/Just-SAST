package io.just.sast.report;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.FindingState;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.VerificationSummary;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Contract coverage for additive v1/v2 finding shadow output. */
class FindingShadowWriterContractTest {

    @Test
    void projectionIsConservativeAndDeterministic() {
        Chain chain = chain();
        Map<String, List<String>> notes = Map.of(chain.key(), List.of("pattern:runtime"));
        FindingShadowWriter writer = new FindingShadowWriter();

        FindingShadowWriter.Document first = writer.build(List.of(chain), Map.of(), notes,
                VerificationSummary.empty("AUTO", 20));
        FindingShadowWriter.Document second = writer.build(List.of(chain), Map.of(), notes,
                VerificationSummary.empty("AUTO", 20));

        assertEquals(first.toCanonicalJson(), second.toCanonicalJson());
        assertEquals(first.digest(), second.digest());
        assertEquals(1, first.findings().size());
        FindingShadowWriter.FindingRecord record = first.findings().get(0);
        assertEquals(FindingState.EntryStatus.NO_APPLICATION_ENTRY,
                record.typed().state().entryStatus());
        assertEquals(FindingState.Feasibility.UNKNOWN,
                record.typed().state().feasibility());
        assertFalse(record.typed().state().defaultFindingEligible());
        assertTrue(record.differences().contains("V2_ENTRY_UNPROVEN"));
        assertTrue(record.differences().contains("LEGACY_TERMINAL_WITHOUT_TYPED_IMPACT"));
        assertTrue(first.toCanonicalJson().contains("\"violations\":["));
    }

    @Test
    void explicitTypedMarkersRemainAuditableAndCalibratedRowsAreNotDropped() throws Exception {
        Chain chain = chain();
        Map<String, List<String>> notes = Map.of(chain.key(), List.of(
                "entry:external", "progress:impact-chain-complete", "constraint:sat",
                "analysis:complete", "verify:sink-blocked"));
        FindingShadowWriter writer = new FindingShadowWriter();
        FindingState typedState = new FindingState(
                FindingState.EntryStatus.EXTERNAL_ENTRY,
                FindingState.ChainProgress.IMPACT_CHAIN_COMPLETE,
                FindingState.Feasibility.SAT,
                FindingState.Completeness.COMPLETE,
                FindingState.Verification.DYNAMIC_BOUNDARY_CONFIRMED,
                FindingState.Risk.MEDIUM);
        FindingShadowWriter.Document document = writer.build(List.of(chain),
                Map.of(chain.key(), "safe-config"), notes,
                VerificationSummary.empty("AUTO", 20),
                Map.of(chain.key(), typedState));
        FindingShadowWriter.FindingRecord record = document.findings().get(0);
        assertEquals(FindingState.EntryStatus.EXTERNAL_ENTRY,
                record.typed().state().entryStatus());
        assertEquals(FindingState.ChainProgress.IMPACT_CHAIN_COMPLETE,
                record.typed().state().chainProgress());
        assertEquals(FindingState.Feasibility.SAT, record.typed().state().feasibility());
        assertEquals(FindingState.Completeness.COMPLETE,
                record.typed().state().completeness());
        assertTrue(record.typed().state().defaultFindingEligible());
        assertFalse(record.legacy().exported());
        assertTrue(record.differences().contains("LEGACY_CALIBRATED_HIDDEN"));

        Path root = Files.createTempDirectory("just-finding-shadow-");
        ReportLayout layout = ReportLayout.create(root.resolve("report"));
        Path output = writer.write(layout, List.of(chain), Map.of(chain.key(), "safe-config"),
                notes, VerificationSummary.empty("AUTO", 20), Map.of(chain.key(), typedState));
        assertEquals(layout.meta().resolve("finding-v2-shadow.json"), output);
        String json = Files.readString(output);
        assertTrue(json.startsWith("{\"schema_version\":\"JUST-FINDING-D003-V1\""));
        assertTrue(json.contains("LEGACY_CALIBRATED_HIDDEN"));
        try (var paths = Files.list(layout.meta())) {
            assertEquals(0L, paths.filter(path -> path.getFileName().toString()
                    .contains(".tmp-")).count());
        }
    }

    @Test
    void duplicateAndUnknownDifferenceStatesFailClosed() {
        Chain chain = chain();
        FindingShadowWriter writer = new FindingShadowWriter();
        FindingShadowWriter.Document duplicate = writer.build(List.of(chain, chain), Map.of(),
                Map.of(), VerificationSummary.empty("DISABLED", 0));
        assertEquals(1, duplicate.findings().size());
        assertEquals(2, duplicate.findings().get(0).legacyCount());
        assertTrue(duplicate.findings().get(0).differences().contains(
                "V2_DUPLICATE_FINDING_ID"));
        assertThrows(IllegalArgumentException.class, () ->
                new FindingShadowWriter.FindingRecord(
                        "finding-0000000000000000000000000000000000000000000000000000000000000000",
                        1, duplicate.findings().get(0).legacy(),
                        duplicate.findings().get(0).typed(), List.of("not-a-code")));
    }

    private static Chain chain() {
        ChainHop hop = new ChainHop("app/Entry", "readObject", "java/lang/Runtime", "exec",
                HopKind.DIRECT_CALL, null, null, "(Ljava/lang/String;)Ljava/lang/Process;", 0);
        return new Chain("RULE-CMD", "command", "HIGH", "app/Entry", "readObject",
                "readObject", "java/lang/Runtime", "exec", List.of(hop), 0, "(Ljava/lang/String;)"
                , "TERMINAL");
    }
}
