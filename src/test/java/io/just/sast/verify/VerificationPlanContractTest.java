package io.just.sast.verify;

import io.just.sast.blackboard.Chain;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** P2.5 protection: the typed plan must preserve the legacy deterministic selection contract. */
class VerificationPlanContractTest {

    @Test
    void planIsDeterministicImmutableAndMatchesLegacySelection(@TempDir Path tmp) throws Exception {
        Path target = tmp.resolve("target.jar");
        try (var output = new java.util.jar.JarOutputStream(Files.newOutputStream(target))) {
            output.putNextEntry(new java.util.jar.JarEntry("app/Entry.class"));
            output.write(new byte[]{0});
            output.closeEntry();
        }
        Chain application = chain("app/Entry", "app/Sink", "readObject");
        Chain dependency = chain("dep/Entry", "java/lang/reflect/Method", "source");
        ParallelVerifier verifier = new ParallelVerifier(target, List.of(), null);
        VerificationPlan first = verifier.planChains(List.of(dependency, application), 2, Set.of());
        VerificationPlan second = verifier.planChains(List.of(application, dependency), 2, Set.of());

        assertEquals(verifier.selectChains(List.of(dependency, application), 2), first.selectedChains());
        assertEquals(first.selectedKeys(), second.selectedKeys());
        assertEquals(first.digest(), second.digest());
        assertEquals(2, first.inputCount());
        assertEquals(2, first.uniqueCount());
        assertEquals(first.selectedCount(), first.selectedChains().size());
        assertTrue(first.selectedChains().contains(application));
        assertThrows(UnsupportedOperationException.class,
                () -> first.selectedChains().add(application));
    }

    @Test
    void emptyAndInvalidBudgetsProduceExplicitEmptyPlans() {
        ParallelVerifier verifier = new ParallelVerifier(Path.of("."), List.of(), null);
        VerificationPlan empty = verifier.planChains(List.of(), 0, Set.of());
        assertEquals(0, empty.inputCount());
        assertEquals(0, empty.uniqueCount());
        assertEquals(List.of(), empty.selectedChains());
        assertEquals("EMPTY", empty.reasonCode());

        VerificationPlan invalid = verifier.planChains(null, -1, null);
        assertEquals("EMPTY", invalid.reasonCode());
        assertEquals(List.of(), invalid.selectedKeys());
    }

    @Test
    void normalizedQueueWithinBudgetIsNotDroppedByFamilyQuota() {
        VerificationPlanner planner = new VerificationPlanner(1, 4);
        Chain first = chain("app/First", "java/lang/Runtime", "source");
        Chain second = chain("app/Second", "java/lang/Runtime", "source");
        VerificationPlan plan = planner.plan(List.of(first, second), 2, Set.of(),
                ignored -> true, ignored -> 0,
                java.util.Comparator.comparing(Chain::key),
                chain -> "same-family");

        assertEquals(2, plan.selectedCount());
        assertEquals("SELECTED_ALL_WITHIN_BUDGET", plan.reasonCode());
    }

    private static Chain chain(String entry, String sink, String entryKind) {
        return new Chain("rule", "category", "HIGH", entry, "run", entryKind,
                sink, "invoke", List.of(), 0);
    }
}
