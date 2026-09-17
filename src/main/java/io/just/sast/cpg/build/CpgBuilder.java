package io.just.sast.cpg.build;

import io.just.sast.cpg.graph.Graph;
import io.just.sast.cpg.graph.Node;
import io.just.sast.cpg.graph.NodeType;
import io.just.sast.model.LoadResult;
import io.just.sast.model.ProgramUniverse;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.Descriptor;
import io.just.sast.model.FieldRef;
import io.just.sast.model.HttpHandlerValue;
import io.just.sast.model.InsnFact;
import io.just.sast.model.InvokeDynamicRef;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.MethodRef;
import io.just.sast.model.Op;
import io.just.sast.model.TypeRef;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** CPG 构建：METHOD/CALL 核心节点、字段写入索引和紧凑方法语义切片。 */
public final class CpgBuilder {

    private static final String HTTP_SERVER_OWNER = "com/sun/net/httpserver/HttpServer";
    private static final String HTTP_SERVER_CREATE_CONTEXT = "createContext";
    private static final String HTTP_SERVER_CREATE_CONTEXT_DESCRIPTOR =
            "(Ljava/lang/String;Lcom/sun/net/httpserver/HttpHandler;)"
                    + "Lcom/sun/net/httpserver/HttpContext;";
    private static final String HTTP_HANDLER_DESCRIPTOR =
            "Lcom/sun/net/httpserver/HttpHandler;";

    /**
     * A binding API often receives its target class as a Class literal immediately before the
     * invocation (for example Jackson's readValue(String, Class)).  Retain only a small,
     * deterministic local window at the CPG seam; this is a typed hint for entry/site joining,
     * not a claim that arbitrary strings or class names are runtime-controlled.
     */
    private static final int CLASS_LITERAL_HINT_WINDOW = 6;
    /**
     * Keep a bounded string window for configuration calls whose value is supplied as a
     * constant (for example Fastjson's ParserConfig.addAccept).  This is deliberately a
     * frontend fact, just like classLiteralHints; downstream code must treat it as a typed
     * configuration hint and never as proof that an arbitrary runtime string is constant.
     */
    private static final int STRING_LITERAL_HINT_WINDOW = 6;

    public BuiltCpg build(LoadResult load) {
        return build(load == null ? null : load.programUniverse());
    }

    /** Build from the immutable frontend product; ASM must not be visible past this seam. */
    public BuiltCpg build(ProgramUniverse universe) {
        if (universe == null) {
            throw new IllegalArgumentException("program universe must not be null");
        }
        Graph graph = new Graph();
        FieldWriterIndex fieldWriters = new FieldWriterIndex();
        CpgIndex.Builder index = CpgIndex.builder();
        for (ClassInfo cls : universe.classes().values()) {
            for (MethodInfo method : cls.methods()) {
                var methodNode = graph.methodNode(method.owner(), method.name(), method.descriptor(), false);
                // Annotation type descriptors are stable frontend facts used by the
                // application-entry index.  Keep them as immutable metadata at the CPG seam;
                // route values and arbitrary annotation payloads deliberately do not cross it.
                methodNode.propsNote("methodAnnotationDescriptors", method.annotationDescriptors());
                methodNode.propsNote("classAnnotationDescriptors", cls.annotationDescriptors());
                methodNode.propsNote("methodAccess", method.access());
                methodNode.propsNote("classAccess", cls.access());
                methodNode.propsNote("classSuperName", cls.superName() == null ? "" : cls.superName());
                methodNode.propsNote("classInterfaces", cls.interfaces());
                CpgIndex.Builder.MethodSliceBuilder slice = index.start(method);
                for (InsnFact insn : method.instructions()) {
                    slice.accept(insn);
                    Op op = insn.op();
                    if (op.isInvoke()) {
                        addCall(graph, insn, cls.internalName(), method);
                    } else if (op.isFieldWrite()) {
                        FieldRef ref = insn.fieldRef();
                        fieldWriters.add(ref.owner(), ref.name(), ref.descriptor(), cls.internalName(),
                                method.owner(), method.name(), method.descriptor(),
                                insn.offset(), op == Op.PUTSTATIC);
                    } else if (op == Op.AASTORE && insn.offset() >= 3) {
                        // 数组字段写入（窗口近似）：javac 规范形态 [.. GETFIELD f][idx][value][AASTORE]
                        // ——GETFIELD 恰在 AASTORE 前 3 条。c.f[i]=v 的污点经字段粒度回溯（反向引擎）。
                        InsnFact arrayField = method.instructions().get(insn.offset() - 3);
                        if (arrayField.op() == Op.GETFIELD) {
                            FieldRef ref = arrayField.fieldRef();
                            fieldWriters.add(ref.owner(), ref.name(), ref.descriptor(), cls.internalName(),
                                    method.owner(), method.name(), method.descriptor(),
                                    insn.offset(), false);
                        }
                    }
                }
                annotateHttpHandlerValues(graph, method);
                for (var tryCatch : method.tryCatch()) {
                    slice.accept(tryCatch);
                }
                slice.finish();
            }
        }
        return new BuiltCpg(graph, fieldWriters, index.build());
    }

    private static void addCall(Graph graph, InsnFact insn, String clsName, MethodInfo enclosing) {
        String owner;
        String name;
        String desc;
        String invokeKind;
        Object indy = null;
        if (insn.op() == Op.INVOKEDYNAMIC) {
            InvokeDynamicRef ref = (InvokeDynamicRef) insn.operands().get(0);
            // Keep a missing bootstrap explicit at the model seam.  CallGraphBuilder records
            // UNKNOWN_BOOTSTRAP from the retained InvokeDynamicRef; it must not be converted
            // into a guessed owner or dropped call site here.
            owner = ref.bootstrap() == null ? null : ref.bootstrap().owner();
            name = ref.name();
            desc = ref.descriptor();
            invokeKind = "DYNAMIC";
            indy = ref;
        } else {
            MethodRef ref = insn.methodRef();
            owner = ref.owner();
            name = ref.name();
            desc = ref.descriptor();
            invokeKind = kindOf(insn.op());
        }
        var call = graph.addCallNode(owner, name, desc, invokeKind, indy, insn.offset(),
                enclosing.owner(), enclosing.name(), enclosing.descriptor());
        List<String> classLiteralHints = classLiteralHints(enclosing, insn.offset());
        if (!classLiteralHints.isEmpty()) {
            call.propsNote("classLiteralHints", classLiteralHints);
        }
        List<String> stringLiteralHints = stringLiteralHints(enclosing, insn.offset());
        if (!stringLiteralHints.isEmpty()) {
            call.propsNote("stringLiteralHints", stringLiteralHints);
        }
    }

    private static List<String> classLiteralHints(MethodInfo enclosing, int callOffset) {
        if (enclosing == null || callOffset <= 0) {
            return List.of();
        }
        int start = Math.max(0, callOffset - CLASS_LITERAL_HINT_WINDOW);
        Set<String> hints = new LinkedHashSet<>();
        for (int index = callOffset - 1; index >= start; index--) {
            InsnFact candidate = enclosing.instructions().get(index);
            if (candidate.op() != Op.LDC) {
                continue;
            }
            Object constant = candidate.constant();
            if (!(constant instanceof TypeRef type)) {
                continue;
            }
            String descriptor = type.descriptor();
            if (descriptor == null || descriptor.length() < 3
                    || !descriptor.startsWith("L") || !descriptor.endsWith(";")) {
                continue;
            }
            String internalName = descriptor.substring(1, descriptor.length() - 1);
            if (!internalName.isBlank() && internalName.indexOf('.') < 0) {
                hints.add(internalName);
            }
        }
        return hints.isEmpty() ? List.of() : List.copyOf(hints);
    }

    private static List<String> stringLiteralHints(MethodInfo enclosing, int callOffset) {
        if (enclosing == null || callOffset <= 0) {
            return List.of();
        }
        int start = Math.max(0, callOffset - STRING_LITERAL_HINT_WINDOW);
        Set<String> hints = new LinkedHashSet<>();
        for (int index = callOffset - 1; index >= start; index--) {
            InsnFact candidate = enclosing.instructions().get(index);
            if (candidate.op() != Op.LDC || !(candidate.constant() instanceof String value)) {
                continue;
            }
            if (!value.isBlank() && value.length() <= 512) {
                hints.add(value);
            }
        }
        return hints.isEmpty() ? List.of() : List.copyOf(hints);
    }

    private static String kindOf(Op op) {
        return switch (op) {
            case INVOKESTATIC -> "STATIC";
            case INVOKESPECIAL -> "SPECIAL";
            case INVOKEVIRTUAL -> "VIRTUAL";
            case INVOKEINTERFACE -> "INTERFACE";
            default -> "DYNAMIC";
        };
    }

    public static String methodKey(String owner, String name, String desc) {
        return owner + "#" + name + desc;
    }

    /**
     * Preserve the exact value producer consumed by an HTTP registration.  This is a small
     * JVM-stack interpreter at the frontend/CPG seam, intentionally limited to the value
     * identity needed by {@code HttpServer.createContext}.  It never invokes target code and
     * abandons the proof on control-flow or unsupported stack shapes instead of widening an
     * unknown value into a handler.
     */
    private static void annotateHttpHandlerValues(Graph graph, MethodInfo method) {
        if (graph == null || method == null || method.instructions().isEmpty()
                || !method.tryCatch().isEmpty()
                || method.instructions().stream().anyMatch(insn -> insn.op().isCondJump()
                || insn.op().isUncondJump() || insn.op().isSwitch())) {
            return;
        }
        String hostMethodKey = methodKey(method.owner(), method.name(), method.descriptor());
        List<FlowSlot> stack = new ArrayList<>();
        Map<Integer, FlowSlot> locals = new HashMap<>();
        for (InsnFact insn : method.instructions()) {
            if (!transferHttpHandlerInstruction(graph, hostMethodKey, insn, stack, locals)) {
                return;
            }
        }
    }

    private static boolean transferHttpHandlerInstruction(Graph graph, String hostMethodKey,
                                                           InsnFact insn, List<FlowSlot> stack,
                                                           Map<Integer, FlowSlot> locals) {
        if (insn == null || insn.op() == null) {
            return false;
        }
        switch (insn.op()) {
            case NOP, IINC -> {
                return true;
            }
            case ACONST_NULL, ICONST_M1, ICONST_0, ICONST_1, ICONST_2, ICONST_3, ICONST_4,
                    ICONST_5, FCONST_0, FCONST_1, FCONST_2, BIPUSH, SIPUSH ->
                    stack.add(FlowSlot.unknown(false));
            case LCONST_0, LCONST_1, DCONST_0, DCONST_1 ->
                    stack.add(FlowSlot.unknown(true));
            case LDC -> {
                Object constant = insn.constant();
                stack.add(FlowSlot.unknown(constant instanceof Long || constant instanceof Double));
            }
            case ALOAD, ILOAD, FLOAD, LLOAD, DLOAD ->
                    stack.add(locals.getOrDefault(insn.varIndex(), FlowSlot.unknown(false)));
            case ASTORE, ISTORE, FSTORE, LSTORE, DSTORE -> {
                FlowSlot value = pop(stack);
                if (value == null) {
                    return false;
                }
                locals.put(insn.varIndex(), value);
            }
            case NEW -> {
                TypeRef type = insn.typeRef();
                String owner = type == null ? null : type.descriptor();
                if (owner != null && owner.startsWith("L") && owner.endsWith(";")) {
                    owner = owner.substring(1, owner.length() - 1);
                }
                if (owner == null || owner.isBlank() || owner.indexOf('.') >= 0
                        || owner.startsWith("[")) {
                    return false;
                }
                stack.add(FlowSlot.allocation(owner, insn.offset()));
            }
            case CHECKCAST -> {
                FlowSlot value = pop(stack);
                if (value == null) {
                    return false;
                }
                stack.add(value);
            }
            case INSTANCEOF, ARRAYLENGTH -> {
                if (pop(stack) == null) {
                    return false;
                }
                stack.add(FlowSlot.unknown(false));
            }
            case GETSTATIC -> {
                FieldRef field = insn.fieldRef();
                if (field == null || !validTypeDescriptor(field.descriptor())) {
                    return false;
                }
                stack.add(FlowSlot.unknown(isCategory2(field.descriptor())));
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
                stack.add(FlowSlot.unknown(isCategory2(field.descriptor())));
            }
            case PUTFIELD -> {
                if (pop(stack) == null || pop(stack) == null) {
                    return false;
                }
            }
            case DUP -> {
                FlowSlot value = peek(stack);
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
                FlowSlot first = stack.get(top);
                stack.set(top, stack.get(top - 1));
                stack.set(top - 1, first);
            }
            case POP -> {
                if (pop(stack) == null) {
                    return false;
                }
            }
            case POP2 -> {
                FlowSlot value = pop(stack);
                if (value == null || (!value.category2() && pop(stack) == null)) {
                    return false;
                }
            }
            case IALOAD, FALOAD, AALOAD, BALOAD, CALOAD, SALOAD -> {
                if (!popTwo(stack)) {
                    return false;
                }
                stack.add(FlowSlot.unknown(false));
            }
            case LALOAD, DALOAD -> {
                if (!popTwo(stack)) {
                    return false;
                }
                stack.add(FlowSlot.unknown(true));
            }
            case IASTORE, FASTORE, AASTORE, BASTORE, CASTORE, SASTORE,
                    LASTORE, DASTORE -> {
                if (!popThree(stack)) {
                    return false;
                }
            }
            case INVOKEVIRTUAL, INVOKESPECIAL, INVOKESTATIC, INVOKEINTERFACE,
                    INVOKEDYNAMIC -> {
                return transferHttpHandlerInvoke(graph, hostMethodKey, insn, stack, locals);
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
                // A control-flow or unmodeled stack mutation invalidates the exact value
                // proof.  The caller then leaves the registration without a handler origin.
                return false;
            }
        }
        return true;
    }

    private static boolean transferHttpHandlerInvoke(Graph graph, String hostMethodKey,
                                                      InsnFact insn, List<FlowSlot> stack,
                                                      Map<Integer, FlowSlot> locals) {
        String descriptor;
        String owner = null;
        String name = null;
        if (insn.op() == Op.INVOKEDYNAMIC) {
            if (insn.operands().isEmpty()
                    || !(insn.operands().get(0) instanceof InvokeDynamicRef indy)) {
                return false;
            }
            descriptor = indy.descriptor();
            name = indy.name();
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
        boolean receiver = insn.op() != Op.INVOKESTATIC && insn.op() != Op.INVOKEDYNAMIC;
        int required = argumentCount + (receiver ? 1 : 0);
        if (stack.size() < required) {
            return false;
        }

        FlowSlot handler = null;
        if (HTTP_SERVER_OWNER.equals(owner) && HTTP_SERVER_CREATE_CONTEXT.equals(name)
                && HTTP_SERVER_CREATE_CONTEXT_DESCRIPTOR.equals(descriptor)
                && receiver && argumentCount == 2) {
            handler = stack.get(stack.size() - 1);
        }
        for (int i = 0; i < required; i++) {
            pop(stack);
        }

        Node call = graph.findCallNode(hostMethodKey, insn.offset());
        if (call == null) {
            return false;
        }
        if ("<init>".equals(name) && handler == null) {
            FlowSlot constructed = stack.isEmpty() ? null : stack.get(stack.size() - 1);
            if (constructed != null && constructed.handler() != null
                    && constructed.handler().kind() == HttpHandlerValue.Kind.ALLOCATION
                    && constructed.handler().constructionCallId() < 0) {
                replaceAllocation(stack, locals, constructed.handler(), call.id());
            }
        }

        String returnType = Descriptor.returnType(descriptor);
        if (!"V".equals(returnType)) {
            if (insn.op() == Op.INVOKEDYNAMIC && HTTP_HANDLER_DESCRIPTOR.equals(returnType)) {
                stack.add(new FlowSlot(new HandlerOrigin(HttpHandlerValue.Kind.LAMBDA,
                        insn.offset(), call.id(), -1, objectOwner(returnType), returnType), false));
            } else {
                stack.add(FlowSlot.unknown(isCategory2(returnType)));
            }
        }

        if (handler != null && handler.handler() != null) {
            HttpHandlerValue value = handler.toModel(hostMethodKey);
            if (value != null) {
                call.propsNote(HttpHandlerValue.GRAPH_NOTE_KEY, List.of(value));
            }
        }
        return true;
    }

    private static void replaceAllocation(List<FlowSlot> stack, Map<Integer, FlowSlot> locals,
                                           HandlerOrigin origin, long constructionCallId) {
        HandlerOrigin constructed = origin.withConstructionCallId(constructionCallId);
        for (int i = 0; i < stack.size(); i++) {
            FlowSlot value = stack.get(i);
            if (sameAllocation(value, origin)) {
                stack.set(i, new FlowSlot(constructed, false));
            }
        }
        for (Map.Entry<Integer, FlowSlot> entry : locals.entrySet()) {
            if (sameAllocation(entry.getValue(), origin)) {
                entry.setValue(new FlowSlot(constructed, false));
            }
        }
    }

    private static boolean sameAllocation(FlowSlot value, HandlerOrigin origin) {
        return value != null && value.handler() != null
                && value.handler().kind() == HttpHandlerValue.Kind.ALLOCATION
                && value.handler().producerOffset() == origin.producerOffset()
                && value.handler().typeOwner().equals(origin.typeOwner());
    }

    private static FlowSlot pop(List<FlowSlot> stack) {
        return stack.isEmpty() ? null : stack.remove(stack.size() - 1);
    }

    private static FlowSlot peek(List<FlowSlot> stack) {
        return stack.isEmpty() ? null : stack.get(stack.size() - 1);
    }

    private static boolean popTwo(List<FlowSlot> stack) {
        return pop(stack) != null && pop(stack) != null;
    }

    private static boolean popThree(List<FlowSlot> stack) {
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

    private static String objectOwner(String descriptor) {
        if (descriptor == null || descriptor.length() < 3 || descriptor.charAt(0) != 'L'
                || descriptor.charAt(descriptor.length() - 1) != ';') {
            return "unknown";
        }
        return descriptor.substring(1, descriptor.length() - 1);
    }

    private record HandlerOrigin(HttpHandlerValue.Kind kind, int producerOffset,
                                 long producerCallId, long constructionCallId,
                                 String typeOwner, String typeDescriptor) {
        private HandlerOrigin withConstructionCallId(long callId) {
            return new HandlerOrigin(kind, producerOffset, producerCallId, callId,
                    typeOwner, typeDescriptor);
        }
    }

    private record FlowSlot(HandlerOrigin handler, boolean category2) {
        private static FlowSlot unknown(boolean category2) {
            return new FlowSlot(null, category2);
        }

        private static FlowSlot allocation(String owner, int producerOffset) {
            return new FlowSlot(new HandlerOrigin(HttpHandlerValue.Kind.ALLOCATION,
                    producerOffset, -1, -1, owner, "L" + owner + ";"), false);
        }

        private HttpHandlerValue toModel(String hostMethodKey) {
            if (handler == null) {
                return null;
            }
            return new HttpHandlerValue(hostMethodKey, handler.producerOffset(), handler.kind(),
                    handler.producerCallId(), handler.constructionCallId(), handler.typeOwner(),
                    handler.typeDescriptor());
        }
    }
}
