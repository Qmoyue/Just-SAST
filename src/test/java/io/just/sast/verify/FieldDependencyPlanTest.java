package io.just.sast.verify;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 字段依赖计划契约：分析路径与探针编码使用同一稳定字段流。 */
class FieldDependencyPlanTest {

    @Test
    void encodesOnlyFieldFlowInStableOrder() {
        Chain chain = new Chain("R", "C", "HIGH", "app/Gadget", "readObject", "readObject",
                "java/lang/Runtime", "exec", List.of(
                new ChainHop("app/Gadget", "readObject", "app/Holder", "value",
                        HopKind.FIELD_FLOW, "value", "field-read", "", null),
                new ChainHop("app/Holder", "run", "java/lang/Runtime", "exec",
                        HopKind.DIRECT_CALL, null, "call", "()V", null)), 0);
        FieldDependencyPlan plan = FieldDependencyPlan.from(chain, "SERIAL");
        assertEquals("app/Gadget.value=app/Holder", plan.encodedFields());
        assertEquals("SERIAL", plan.triggerMode());
        assertEquals(1, plan.fields().size());
    }

    @Test
    void infersConcreteTargetWhenBackwardFieldHopOnlyHasOwnerType() {
        Chain chain = new Chain("R", "C", "HIGH", "app/Entry", "readObject", "readObject",
                "java/lang/Runtime", "exec", List.of(
                new ChainHop("app/Entry", "readObject", "app/Entry", "value",
                        HopKind.FIELD_FLOW, "value", "field-read", "", null),
                new ChainHop("app/Entry", "run", "app/Gadget", "run",
                        HopKind.VIRTUAL_DISPATCH, null, "dispatch", "()V", null),
                new ChainHop("app/Gadget", "run", "java/lang/Runtime", "exec",
                        HopKind.DIRECT_CALL, null, "call", "()V", null)), 0);
        FieldDependencyPlan plan = FieldDependencyPlan.from(chain, "SERIAL");
        assertEquals("app/Entry.value=app/Gadget", plan.encodedFields());
    }

    @Test
    void probeEncodingIsDelimiterSafeAndDeduplicated() {
        Chain chain = new Chain("R", "C", "HIGH", "app/Entry", "readObject", "readObject",
                "java/lang/Runtime", "exec", List.of(
                new ChainHop("app/Entry", "read,Object", "app/Entry", "value=part",
                        HopKind.FIELD_FLOW, "value,=part", "field-read", "", null),
                new ChainHop("app/Entry", "read,Object", "app/Entry", "value=part",
                        HopKind.FIELD_FLOW, "value,=part", "field-read", "", null)), 0);
        FieldDependencyPlan plan = FieldDependencyPlan.from(chain, "SERIAL");
        assertEquals(1, plan.fields().size());
        assertTrue(plan.encodedFieldsForProbe().startsWith("v2;"));
        assertTrue(plan.encodedFieldsForProbe().contains("value,=part"));
    }
}
