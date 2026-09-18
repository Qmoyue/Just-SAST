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
import java.util.LinkedHashMap;
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
            case ICONST_M1, ICONST_0, ICONST_1, ICONST_2, ICONST_3, ICONST_4, ICONST_5 ->
                    stack.add(Value.integer(hostMethodKey, insn.offset(), integerConstant(insn.op())));
            case BIPUSH, SIPUSH ->
                    stack.add(Value.integer(hostMethodKey, insn.offset(), intOperand(insn)));
            case FCONST_0, FCONST_1, FCONST_2 ->
                    stack.add(Value.unknown(hostMethodKey, insn.offset(), "F", false));
            case LCONST_0, LCONST_1 ->
                    stack.add(Value.unknown(hostMethodKey, insn.offset(), "J", true));
            case DCONST_0, DCONST_1 ->
                    stack.add(Value.unknown(hostMethodKey, insn.offset(), "D", true));
            case LDC -> {
                Object constant = insn.constant();
                if (constant instanceof String value) {
                    stack.add(Value.known(hostMethodKey, insn.offset(), "Ljava/lang/String;",
                            value));
                } else if (constant instanceof TypeRef type
                        && classLiteralInternalName(type) != null) {
                    stack.add(Value.classLiteral(hostMethodKey, insn.offset(),
                            classLiteralInternalName(type)));
                } else if (constant instanceof Integer value) {
                    stack.add(Value.integer(hostMethodKey, insn.offset(), value));
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
            case ANEWARRAY -> {
                Value length = pop(stack);
                String component = internalName(insn.typeRef());
                if (length == null || component == null) {
                    return false;
                }
                int size = length.integerValue() == null ? -1 : length.integerValue();
                if (size < -1) {
                    return false;
                }
                String descriptor = "[L" + component + ";";
                stack.add(Value.array(hostMethodKey, insn.offset(), descriptor, component, size));
            }
            case NEWARRAY -> {
                Value length = pop(stack);
                if (length == null) {
                    return false;
                }
                int size = length.integerValue() == null ? -1 : length.integerValue();
                if (size < -1) {
                    return false;
                }
                stack.add(Value.array(hostMethodKey, insn.offset(), "[?", null, size));
            }
            case MULTIANEWARRAY -> {
                if (insn.operands().size() < 2 || !(insn.operands().get(0) instanceof TypeRef type)
                        || !(insn.operands().get(1) instanceof Integer dimensions)
                        || dimensions < 1) {
                    return false;
                }
                for (int dimension = 0; dimension < dimensions; dimension++) {
                    if (pop(stack) == null) {
                        return false;
                    }
                }
                stack.add(Value.array(hostMethodKey, insn.offset(), type.descriptor(), null, -1));
            }
            case CHECKCAST -> {
                Value value = pop(stack);
                if (value == null) {
                    return false;
                }
                TypeRef castType = insn.typeRef();
                if (castType == null || !validTypeDescriptor(castType.descriptor())) {
                    return false;
                }
                String castDescriptor = castDescriptor(castType);
                if (castDescriptor == null) {
                    return false;
                }
                stack.add(value.cast(castDescriptor));
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
            case AALOAD -> {
                Value index = pop(stack);
                Value array = pop(stack);
                if (index == null || array == null) {
                    return false;
                }
                Value element = array.arrayShape() == null || index.integerValue() == null
                        ? null : array.arrayShape().element(index.integerValue());
                stack.add(element == null
                        ? Value.unknown(hostMethodKey, insn.offset(), "Ljava/lang/Object;", false)
                        : element);
            }
            case IALOAD, FALOAD, BALOAD, CALOAD, SALOAD -> {
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
            case AASTORE -> {
                Value value = pop(stack);
                Value index = pop(stack);
                Value array = pop(stack);
                if (value == null || index == null || array == null) {
                    return false;
                }
                if (array.arrayShape() != null) {
                    if (index.integerValue() == null) {
                        array.arrayShape().markUnknown();
                    } else {
                        array.arrayShape().put(index.integerValue(), value);
                    }
                }
            }
            case IASTORE, FASTORE, BASTORE, CASTORE, SASTORE,
                    LASTORE, DASTORE -> {
                if (!popThree(stack)) {
                    return false;
                }
            }
            case ARRAYLENGTH -> {
                Value array = pop(stack);
                if (array == null) {
                    return false;
                }
                Integer length = array.arrayShape() == null
                        ? null : array.arrayShape().length();
                stack.add(length == null || length < 0
                        ? Value.unknown(hostMethodKey, insn.offset(), "I", false)
                        : Value.integer(hostMethodKey, insn.offset(), length));
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

    private static int integerConstant(Op op) {
        return switch (op) {
            case ICONST_M1 -> -1;
            case ICONST_0 -> 0;
            case ICONST_1 -> 1;
            case ICONST_2 -> 2;
            case ICONST_3 -> 3;
            case ICONST_4 -> 4;
            case ICONST_5 -> 5;
            default -> throw new IllegalArgumentException("not an integer constant opcode: " + op);
        };
    }

    private static int intOperand(InsnFact insn) {
        if (insn.operands().size() != 1 || !(insn.operands().get(0) instanceof Integer value)) {
            throw new IllegalArgumentException("integer opcode has no integer operand");
        }
        return value;
    }

    private static String classLiteralInternalName(TypeRef type) {
        if (type == null || type.descriptor() == null) {
            return null;
        }
        String descriptor = type.descriptor();
        if (!descriptor.startsWith("L") || !descriptor.endsWith(";")) {
            return null;
        }
        return internalName(type);
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

    private static String castDescriptor(TypeRef type) {
        String descriptor = type.descriptor();
        if (descriptor == null || descriptor.isBlank()) {
            return null;
        }
        if (descriptor.startsWith("L") && descriptor.endsWith(";")) {
            return descriptor;
        }
        if (descriptor.startsWith("[")) {
            return descriptor;
        }
        if (descriptor.indexOf('.') >= 0 || descriptor.indexOf(';') >= 0
                || descriptor.indexOf('(') >= 0 || descriptor.indexOf(')') >= 0) {
            return null;
        }
        return "L" + descriptor + ";";
    }

    private static String token(String hostMethodKey, int offset, String kind) {
        return "value-flow-v1:" + hostMethodKey + ":" + offset + ":" + kind;
    }

    /** Mutable only inside one local bytecode transfer; facts receive an immutable snapshot. */
    static final class ArrayShape {
        private final String descriptor;
        private final String component;
        private final int length;
        private final Map<Integer, Value> elements = new LinkedHashMap<>();
        private boolean valid = true;

        private ArrayShape(String descriptor, String component, int length) {
            this.descriptor = Objects.requireNonNull(descriptor, "array descriptor");
            this.component = component;
            this.length = length;
        }

        private void put(int index, Value value) {
            if (value == null || index < 0 || (length >= 0 && index >= length)) {
                valid = false;
                return;
            }
            elements.put(index, value);
        }

        private void markUnknown() {
            valid = false;
        }

        private Value element(int index) {
            return elements.get(index);
        }

        Integer length() {
            return length;
        }

        /** Return exact Class literals in array order, or null when any member is unresolved. */
        List<String> interfaceTypes() {
            if (!valid || !"[Ljava/lang/Class;".equals(descriptor)
                    || length < 0 || component == null
                    || !"java/lang/Class".equals(component)) {
                return null;
            }
            List<String> result = new ArrayList<>(length);
            for (int index = 0; index < length; index++) {
                Value value = elements.get(index);
                if (value == null || value.classLiteral() == null) {
                    return null;
                }
                result.add(value.classLiteral());
            }
            return List.copyOf(result);
        }
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
                 String descriptor, int producerOffset, boolean category2, Integer integerValue,
                 String classLiteral, ArrayShape arrayShape) {
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
            if (integerValue != null && !"I".equals(descriptor)) {
                throw new IllegalArgumentException("integer value-flow value must have I descriptor");
            }
            if (classLiteral != null && !(state == ValueState.KNOWN
                    && "Ljava/lang/Class;".equals(descriptor))) {
                throw new IllegalArgumentException("class literal value-flow shape is invalid");
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
                    displayValue, descriptor, offset, isCategory2(descriptor), null, null, null);
        }

        static Value nullValue(String hostMethodKey, int offset) {
            return new Value(ValueState.NULL,
                    new TypedBridgeFact.FlowIdentity(token(hostMethodKey, offset, "null")),
                    null, "Ljava/lang/Object;", offset, false, null, null, null);
        }

        static Value unknown(String hostMethodKey, int offset, String descriptor,
                             boolean category2) {
            return unknown(hostMethodKey, offset, descriptor, category2, "unknown");
        }

        static Value unknown(String hostMethodKey, int offset, String descriptor,
                             boolean category2, String kind) {
            return new Value(ValueState.UNKNOWN,
                    new TypedBridgeFact.FlowIdentity(token(hostMethodKey, offset, kind)),
                    null, descriptor, offset, category2, null, null, null);
        }

        static Value integer(String hostMethodKey, int offset, int value) {
            return new Value(ValueState.UNKNOWN,
                    new TypedBridgeFact.FlowIdentity(token(hostMethodKey, offset, "integer")),
                    null, "I", offset, false, value, null, null);
        }

        static Value classLiteral(String hostMethodKey, int offset, String internalName) {
            return new Value(ValueState.KNOWN,
                    new TypedBridgeFact.FlowIdentity(token(hostMethodKey, offset, "class-literal")),
                    null, "Ljava/lang/Class;", offset, false, null, internalName, null);
        }

        static Value array(String hostMethodKey, int offset, String descriptor,
                           String component, int length) {
            return new Value(ValueState.KNOWN,
                    new TypedBridgeFact.FlowIdentity(token(hostMethodKey, offset, "array")),
                    null, descriptor, offset, false, null, null,
                    new ArrayShape(descriptor, component, length));
        }

        Value cast(String castDescriptor) {
            return new Value(state, identity, displayValue, castDescriptor, producerOffset,
                    isCategory2(castDescriptor), integerValue, classLiteral, arrayShape);
        }
    }

    enum ValueState {
        KNOWN,
        NULL,
        UNKNOWN
    }
}
