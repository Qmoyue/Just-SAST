package io.just.sast.cli;

import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ModeDemandPolicyContractTest {

    @Test
    void onePolicyOwnsModeDemandAndExportBoundary() {
        Set<String> roots = Set.of("app/Main", "app/Entry");

        ModeDemandPolicy component = ModeDemandPolicy.forMode(ScanMode.COMPONENT);
        assertFalse(component.applicationScopeKnown());
        assertFalse(component.requireApplicationJoin());
        assertEquals(roots, component.demandRootClasses(roots));
        assertEquals(roots, component.applicationClassNames(roots),
                "shared solver keeps component ownership roots for mechanism analysis");
        assertEquals("component", component.wireName());

        ModeDemandPolicy application = ModeDemandPolicy.forMode(ScanMode.APPLICATION);
        assertTrue(application.applicationScopeKnown());
        assertTrue(application.requireApplicationJoin());
        assertEquals(roots, application.demandRootClasses(roots));
        assertEquals(roots, application.applicationClassNames(roots));
        assertEquals("application", application.wireName());
    }
}
