package io.just.sast.cpg.build;

import io.just.sast.cpg.graph.Graph;
import io.just.sast.cpg.graph.Node;
import io.just.sast.model.Descriptor;
import io.just.sast.model.FieldRef;
import io.just.sast.model.InsnFact;
import io.just.sast.model.InvokeDynamicRef;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.MethodRef;
import io.just.sast.model.Op;
import io.just.sast.model.TypeRef;
import io.just.sast.model.TypedBridgeFact;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Bounded, protocol-neutral JVM value transfer for one straight-line method.
 *
 * <p>This owner records only physical value identity and invocation slots.  It does not know
 * JDBC, JAAS, JNDI, a driver package, or any other protocol vocabulary; those owners consume
 * the immutable invocation facts after this seam.  Unsupported control flow or stack shapes
 * make the whole result incomplete so a protocol owner can publish its own explicit UNKNOWN
 * fact instead of receiving a guessed value.</p>
 */
final class StaticValueFlow {

    private StaticValueFlow() {
    }

    static Result analyze(Graph graph, MethodInfo method) {
        Objects.requireNonNull(graph, "value-flow graph");
        Objects.requireNonNull(method, "value-flow method");
        if (method.instructions().isEmpty()) {
            return new Result(List.of(), true);
        }
        if (!method.tryCatch().isEmpty()
                || method.instructions().stream().anyMatch(insn -> insn.op().isCondJump()
                || insn.op().isUncondJump() || insn.op().isSwitch())) {
            return new Result(List.of(), false);
        }

        String hostMethodKey = CpgBuilder.methodKey(method.owner(), method.name(),
                method.descriptor());
        List<Value> stack = new ArrayList<>();
        Map<Integer, Value> locals = new java.util.HashMap<>();
        List<Invocation> invocations = new ArrayList<>();
        for (InsnFact insn : method.instructions()) {
            if (!transfer(graph, hostMethodKey, insn, stack, locals, invocations)) {
                return new Result(List.of(), false);
            }
        }
        return new Result(invocations, true);
    }

    private static boolean transfer(Graph graph, String hostMethodKey, InsnFact insn,
                                    List<Value> stack, Map<Integer, Value> locals,
                                    List<Invocation> invocations) {
        if (insn == null || insn.op() == null) {
            return false;
        }
        switch (insn.op()) {
            case NOP, IINC -> {
                return true;
            }
            case ACONST_NULL -> stack.add(Value.nullValue(hostMethodKey, insn.offset()));
            case ICONST_M1, ICONST_0, ICONST_1, ICONST_2, ICONST_3, ICONST_4, ICONST_5,
                    FCONST_0, FCONST_1, FCONST_2, BIPUSH, SIPUSH ->
                    stack.add(Value.unknown(hostMethodKey, insn.offset(), "I", false));
            case LCONST_0, LCONST_1 ->
                    stack.add(Value.unknown(hostMethodKey, insn.offset(), "J", true));
            case DCONST_0, DCONST_1 ->
                    stack.add(Value.unknown(hostMethodKey, insn.offset(), "D", true));
            case LDC -> {
                Object constant = insn.constant();
                if (constant instanceof String value) {
                    stack.add(Value.known(hostMethodKey, insn.offset(), "Ljava/lang/String;",
                            value));
                } else {
                    stack.add(Value.unknown(hostMethodKey, insn.offset(),
                            constant instanceof Long ? "J"
                                    : constant instanceof Double ? "D" : "Ljava/lang/Object;",
                            constant instanceof Long || constant instanceof Double));
                }
            }
            case ALOAD, ILOAD, FLOAD, LLOAD, DLOAD -> {
                Value value = locals.get(insn.varIndex());
                stack.add(value == null
                        ? Value.unknown(hostMethodKey, insn.offset(), "Ljava/lang/Object;",
                        insn.op() == Op.LLOAD || insn.op() == Op.DLOAD)
                        : value);
            }
            case ASTORE, ISTORE, FSTORE, LSTORE, DSTORE -> {
                Value value = pop(stack);
                if (value == null) {
                    return false;
                }
                locals.put(insn.varIndex(), value);
            }
            case NEW -> {
                String owner = internalName(insn.typeRef());
                if (owner == null) {
                    return false;
                }
                stack.add(Value.known(hostMethodKey, insn.offset(), "L" + owner + ";", null,
                        "allocation"));
            }
            case CHECKCAST -> {
                Value value = pop(stack);
                if (value == null) {
                    return false;
                }
                stack.add(value);
            }
            case GETSTATIC -> {
                FieldRef field = insn.fieldRef();
                if (field == null || !validTypeDescriptor(field.descriptor())) {
                    return false;
                }
                stack.add(Value.unknown(hostMethodKey, insn.offset(), field.descriptor(),
                        isCategory2(field.descriptor())));
            }
            case PUTSTATIC -> {
                if (pop(stack) == null) {
                    return false;
                }
            }
            case GETFIELD -> {
                if (pop(stack) == null) {
                    return false;
                }
                FieldRef field = insn.fieldRef();
                if (field == null || !validTypeDescriptor(field.descriptor())) {
                    return false;
                }
                stack.add(Value.unknown(hostMethodKey, insn.offset(), field.descriptor(),
                        isCategory2(field.descriptor())));
            }
            case PUTFIELD -> {
                if (pop(stack) == null || pop(stack) == null) {
                    return false;
                }
            }
            case DUP -> {
                Value value = peek(stack);
                if (value == null || value.category2()) {
                    return false;
                }
                stack.add(value);
            }
            case SWAP -> {
                if (stack.size() < 2 || stack.get(stack.size() - 1).category2()
                        || stack.get(stack.size() - 2).category2()) {
                    return false;
                }
                int top = stack.size() - 1;
                Value first = stack.get(top);
                stack.set(top, stack.get(top - 1));
                stack.set(top - 1, first);
            }
            case POP -> {
                if (pop(stack) == null) {
                    return false;
                }
            }
            case POP2 -> {
                Value value = pop(stack);
                if (value == null || (!value.category2() && pop(stack) == null)) {
                    return false;
                }
            }
            case IALOAD, FALOAD, AALOAD, BALOAD, CALOAD, SALOAD -> {
                if (!popTwo(stack)) {
                    return false;
                }
                stack.add(Value.unknown(hostMethodKey, insn.offset(), "Ljava/lang/Object;",
                        false));
            }
            case LALOAD, DALOAD -> {
                if (!popTwo(stack)) {
                    return false;
                }
                stack.add(Value.unknown(hostMethodKey, insn.offset(),
                        insn.op() == Op.LALOAD ? "J" : "D", true));
            }
            case IASTORE, FASTORE, AASTORE, BASTORE, CASTORE, SASTORE,
                    LASTORE, DASTORE -> {
                if (!popThree(stack)) {
                    return false;
                }
            }
            case INVOKEVIRTUAL, INVOKESPECIAL, INVOKESTATIC, INVOKEINTERFACE,
                    INVOKEDYNAMIC -> {
                return transferInvoke(graph, hostMethodKey, insn, stack, invocations);
            }
            case IRETURN, FRETURN, ARETURN, LRETURN, DRETURN, RETURN, ATHROW -> {
                if (insn.op() != Op.RETURN && pop(stack) == null) {
                    return false;
                }
            }
            case MONITORENTER, MONITOREXIT -> {
                if (pop(stack) == null) {
                    return false;
                }
            }
            default -> {
                return false;
            }
        }
        return true;
    }

    private static boolean transferInvoke(Graph graph, String hostMethodKey, InsnFact insn,
                                          List<Value> stack, List<Invocation> invocations) {
        String owner = null;
        String name;
        String descriptor;
        boolean dynamic = insn.op() == Op.INVOKEDYNAMIC;
        if (dynamic) {
            if (insn.operands().isEmpty()
                    || !(insn.operands().get(0) instanceof InvokeDynamicRef indy)) {
                return false;
            }
            name = indy.name();
            descriptor = indy.descriptor();
        } else {
            MethodRef ref = insn.methodRef();
            if (ref == null) {
                return false;
            }
            owner = ref.owner();
            name = ref.name();
            descriptor = ref.descriptor();
        }
        if (!validMethodDescriptor(descriptor)) {
            return false;
        }
        int argumentCount;
        try {
            argumentCount = Descriptor.paramCount(descriptor);
        } catch (RuntimeException invalidDescriptor) {
            return false;
        }
        boolean receiverRequired = !dynamic && insn.op() != Op.INVOKESTATIC;
        int required = argumentCount + (receiverRequired ? 1 : 0);
        if (stack.size() < required) {
            return false;
        }
        List<Value> arguments = new ArrayList<>(argumentCount);
        for (int index = argumentCount - 1; index >= 0; index--) {
            Value argument = pop(stack);
            if (argument == null) {
                return false;
            }
            arguments.add(0, argument);
        }
        Value receiver = receiverRequired ? pop(stack) : null;
        if (receiverRequired && receiver == null) {
            return false;
        }
        Node call = graph.findCallNode(hostMethodKey, insn.offset());
        if (call == null) {
            return false;
        }
        String returnType;
        try {
            returnType = Descriptor.returnType(descriptor);
        } catch (RuntimeException invalidDescriptor) {
            return false;
        }
        Value result = null;
        if (!"V".equals(returnType)) {
            result = Value.unknown(hostMethodKey, insn.offset(), returnType,
                    isCategory2(returnType), "return");
            stack.add(result);
        }
        invocations.add(new Invocation(call, owner, name, descriptor, call.invokeKind(),
                receiver, arguments, result));
        return true;
    }

    private static <T> T pop(List<T> stack) {
        return stack.isEmpty() ? null : stack.remove(stack.size() - 1);
    }

    private static <T> T peek(List<T> stack) {
        return stack.isEmpty() ? null : stack.get(stack.size() - 1);
    }

    private static boolean popTwo(List<Value> stack) {
        return pop(stack) != null && pop(stack) != null;
    }

    private static boolean popThree(List<Value> stack) {
        return popTwo(stack) && pop(stack) != null;
    }

    private static boolean validMethodDescriptor(String descriptor) {
        return descriptor != null && descriptor.startsWith("(")
                && descriptor.indexOf(')') > 0 && descriptor.indexOf(')') < descriptor.length() - 1;
    }

    private static boolean validTypeDescriptor(String descriptor) {
        return descriptor != null && !descriptor.isBlank();
    }

    private static boolean isCategory2(String descriptor) {
        return "J".equals(descriptor) || "D".equals(descriptor);
    }

    private static String internalName(TypeRef type) {
        if (type == null || type.descriptor() == null) {
            return null;
        }
        String descriptor = type.descriptor();
        if (descriptor.startsWith("L") && descriptor.endsWith(";")) {
            String value = descriptor.substring(1, descriptor.length() - 1);
            return value.isBlank() || value.indexOf('.') >= 0 ? null : value;
        }
        return descriptor.isBlank() || descriptor.startsWith("[")
                || descriptor.indexOf('.') >= 0 ? null : descriptor;
    }

    private static String token(String hostMethodKey, int offset, String kind) {
        return "value-flow-v1:" + hostMethodKey + ":" + offset + ":" + kind;
    }

    record Result(List<Invocation> invocations, boolean complete) {
        Result {
            invocations = List.copyOf(Objects.requireNonNull(invocations,
                    "value-flow invocations"));
        }
    }

    record Invocation(Node call, String owner, String name, String descriptor, String invokeKind,
                      Value receiver, List<Value> arguments, Value result) {
        Invocation {
            call = Objects.requireNonNull(call, "value-flow call");
            name = Objects.requireNonNull(name, "value-flow invocation name");
            descriptor = Objects.requireNonNull(descriptor, "value-flow invocation descriptor");
            invokeKind = Objects.requireNonNull(invokeKind, "value-flow invocation kind");
            arguments = List.copyOf(Objects.requireNonNull(arguments,
                    "value-flow invocation arguments"));
        }
    }

    record Value(ValueState state, TypedBridgeFact.FlowIdentity identity, String displayValue,
                 String descriptor, int producerOffset, boolean category2) {
        Value {
            state = Objects.requireNonNull(state, "value-flow state");
            identity = Objects.requireNonNull(identity, "value-flow identity");
            descriptor = Objects.requireNonNull(descriptor, "value-flow descriptor");
            if (descriptor.isBlank()) {
                throw new IllegalArgumentException("value-flow descriptor must not be blank");
            }
            if (producerOffset < -1) {
                throw new IllegalArgumentException("value-flow producer offset must be -1 or greater");
            }
            if (state != ValueState.KNOWN && displayValue != null) {
                throw new IllegalArgumentException(
                        "non-known value-flow value cannot carry display text");
            }
        }

        static Value known(String hostMethodKey, int offset, String descriptor,
                           String displayValue) {
            return known(hostMethodKey, offset, descriptor, displayValue, "constant");
        }

        static Value known(String hostMethodKey, int offset, String descriptor,
                           String displayValue, String kind) {
            return new Value(ValueState.KNOWN,
                    new TypedBridgeFact.FlowIdentity(token(hostMethodKey, offset, kind)),
                    displayValue, descriptor, offset, isCategory2(descriptor));
        }

        static Value nullValue(String hostMethodKey, int offset) {
            return new Value(ValueState.NULL,
                    new TypedBridgeFact.FlowIdentity(token(hostMethodKey, offset, "null")),
                    null, "Ljava/lang/Object;", offset, false);
        }

        static Value unknown(String hostMethodKey, int offset, String descriptor,
                             boolean category2) {
            return unknown(hostMethodKey, offset, descriptor, category2, "unknown");
        }

        static Value unknown(String hostMethodKey, int offset, String descriptor,
                             boolean category2, String kind) {
            return new Value(ValueState.UNKNOWN,
                    new TypedBridgeFact.FlowIdentity(token(hostMethodKey, offset, kind)),
                    null, descriptor, offset, category2);
        }
    }

    enum ValueState {
        KNOWN,
        NULL,
        UNKNOWN
    }
}
