package io.just.sast.analysis.taint;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;

/**
 * Canonical ordering for abstract value origins.
 *
 * <p>Origin sets are semantically unordered, but a bounded backward walk turns their iteration
 * order into a user-visible choice when the work budget is reached. Keeping this comparator in
 * one small utility makes that choice explicit in both the forward snapshot and its consumers;
 * it is not a semantic ranking and never drops an origin.</p>
 */
public final class ValueOriginOrder {

    private static final Comparator<ValueOrigin> COMPARATOR =
            Comparator.comparing(ValueOriginOrder::key);

    private ValueOriginOrder() {
    }

    public static List<ValueOrigin> sorted(Collection<ValueOrigin> origins) {
        if (origins == null || origins.isEmpty()) {
            return List.of();
        }
        List<ValueOrigin> result = new ArrayList<>(origins.size());
        for (ValueOrigin origin : origins) {
            if (origin != null) {
                result.add(origin);
            }
        }
        result.sort(COMPARATOR);
        return result;
    }

    /** Stable, bounded identity for every sealed origin variant. */
    public static String key(ValueOrigin origin) {
        return key(origin, 0);
    }

    private static String key(ValueOrigin origin, int depth) {
        if (origin == null) {
            return "0:null";
        }
        if (depth > 8) {
            return "9:depth";
        }
        if (origin instanceof ValueOrigin.Param value) {
            return "1:param:" + value.slot();
        }
        if (origin instanceof ValueOrigin.Insn value) {
            return "2:insn:" + value.offset();
        }
        if (origin instanceof ValueOrigin.CallResult value) {
            return "3:call:" + value.callNodeId();
        }
        if (origin instanceof ValueOrigin.FieldRead value) {
            return "4:field:" + text(value.owner()) + ':' + text(value.field()) + ':'
                    + text(value.descriptor()) + ':' + value.isStatic() + ':'
                    + key(value.receiver(), depth + 1);
        }
        if (origin instanceof ValueOrigin.Constant value) {
            Object constant = value.value();
            return "5:constant:" + (constant == null ? "null"
                    : constant.getClass().getName() + ':' + String.valueOf(constant));
        }
        return "6:unknown";
    }

    private static String text(String value) {
        return value == null ? "" : value;
    }
}
