package io.just.sast.analysis.taint;

import io.just.sast.model.FieldRef;
import io.just.sast.model.InsnFact;
import io.just.sast.model.Op;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Contract tests for descriptor-sensitive field identity and alias transfer. */
class FieldAliasTransferContractTest {

    @Test
    void descriptorAndStaticnessArePartOfTheDeclarationIdentity() {
        FieldAlias integer = new FieldAlias("pkg/T", "value", "I", false);
        FieldAlias object = new FieldAlias("pkg/T", "value", "Ljava/lang/Object;", false);
        FieldAlias staticInteger = new FieldAlias("pkg/T", "value", "I", true);

        assertFalse(FieldAliasTransfer.same(integer, object));
        assertFalse(FieldAliasTransfer.same(integer, staticInteger));
        assertTrue(FieldAliasTransfer.same(integer, new FieldAlias("pkg/T", "value", "I", false)));
        assertNotEquals(integer.canonical(), object.canonical());
    }

    @Test
    void missingDescriptorsRemainCompatibilityWildcardsOnly() {
        FieldAlias unknown = new FieldAlias("pkg/T", "value", "", false);
        FieldAlias exact = new FieldAlias("pkg/T", "value", "I", false);
        FieldAlias different = new FieldAlias("pkg/T", "value", "J", false);

        assertTrue(FieldAliasTransfer.same(unknown, exact));
        assertTrue(FieldAliasTransfer.same(exact, unknown));
        assertFalse(FieldAliasTransfer.same(exact, different));
    }

    @Test
    void instructionAndReadOriginsShareIdentityWithoutDroppingReceiver() {
        FieldRef ref = new FieldRef("pkg/T", "next", "Lpkg/U;");
        InsnFact read = new InsnFact(7, Op.GETFIELD, List.of(ref));
        FieldAlias alias = FieldAliasTransfer.declaration(read).orElseThrow();
        ValueOrigin receiver = new ValueOrigin.Param(0);
        ValueOrigin.FieldRead transferred = FieldAliasTransfer.read(alias, receiver);

        assertEquals(alias, FieldAliasTransfer.declaration(transferred).orElseThrow());
        assertEquals(receiver, transferred.receiver());
        assertEquals("pkg/T#next#Lpkg/U;#false", FieldAliasTransfer.legacyKey(alias));
        assertTrue(FieldAliasTransfer.declaration(new InsnFact(1, Op.NOP, List.of())).isEmpty());
    }
}
