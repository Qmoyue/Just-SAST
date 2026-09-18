package io.just.sast.cpg.build;

import io.just.sast.cpg.graph.Graph;
import io.just.sast.cpg.graph.Node;
import io.just.sast.cpg.graph.NodeType;
import io.just.sast.model.LoadResult;
import io.just.sast.model.ProgramUniverse;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.ClassForNameCallSite;
import io.just.sast.model.Descriptor;
import io.just.sast.model.FieldRef;
import io.just.sast.model.HttpHandlerValue;
import io.just.sast.model.InsnFact;
import io.just.sast.model.InvokeDynamicRef;
import io.just.sast.model.JdbcConnectionCallSite;
import io.just.sast.model.JndiReferenceFact;
import io.just.sast.model.MethodId;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.MethodRef;
import io.just.sast.model.Op;
import io.just.sast.model.TypeRef;
import io.just.sast.model.TypedBridgeFact;

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
                annotateJndiReferenceFacts(graph, method);
                annotateJdbcConnectionFacts(graph, method);
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
        ClassForNameCallSite.fromCall(call.id(),
                MethodId.of(enclosing.owner(), enclosing.name(),
                        enclosing.descriptor()),
                insn.offset(), owner, name, desc, invokeKind)
                .ifPresent(site -> call.propsNote(ClassForNameCallSite.GRAPH_NOTE_KEY, site));
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
     * Retain exact Reference object identity and its constructor/RefAddr fields at the CPG
     * seam.  This is a deliberately small straight-line transfer: aliases inside locals and
     * the operand stack retain the same allocation token, while unsupported control-flow or
     * stack shapes abandon the proof.  No target method is loaded or invoked.
     */
    private static void annotateJndiReferenceFacts(Graph graph, MethodInfo method) {
        if (graph == null || method == null || method.instructions().isEmpty()
                || !method.tryCatch().isEmpty()
                || method.instructions().stream().anyMatch(insn -> insn.op().isCondJump()
                || insn.op().isUncondJump() || insn.op().isSwitch())) {
            return;
        }
        String hostMethodKey = methodKey(method.owner(), method.name(), method.descriptor());
        List<ReferenceFlowSlot> stack = new ArrayList<>();
        Map<Integer, ReferenceFlowSlot> locals = new HashMap<>();
        List<ReferenceBuilder> references = new ArrayList<>();
        for (InsnFact insn : method.instructions()) {
            if (!transferJndiReferenceInstruction(graph, hostMethodKey, insn, stack, locals,
                    references)) {
                return;
            }
        }
        for (ReferenceBuilder reference : references) {
            if (!reference.constructed()) {
                continue;
            }
            Node construction = graph.findCallNode(hostMethodKey, reference.constructionOffset());
            if (construction == null) {
                throw new IllegalStateException("Reference constructor call is missing from CPG");
            }
            construction.propsNote(JndiReferenceFact.GRAPH_NOTE_KEY, reference.toFact());
        }
    }

    private static boolean transferJndiReferenceInstruction(
            Graph graph, String hostMethodKey, InsnFact insn, List<ReferenceFlowSlot> stack,
            Map<Integer, ReferenceFlowSlot> locals, List<ReferenceBuilder> references) {
        if (insn == null || insn.op() == null) {
            return false;
        }
        switch (insn.op()) {
            case NOP, IINC -> {
                return true;
            }
            case ACONST_NULL -> stack.add(ReferenceFlowSlot.string(
                    JndiReferenceFact.FieldValue.nullValue()));
            case ICONST_M1, ICONST_0, ICONST_1, ICONST_2, ICONST_3, ICONST_4, ICONST_5,
                    FCONST_0, FCONST_1, FCONST_2, BIPUSH, SIPUSH ->
                    stack.add(ReferenceFlowSlot.unknown(false));
            case LCONST_0, LCONST_1, DCONST_0, DCONST_1 ->
                    stack.add(ReferenceFlowSlot.unknown(true));
            case LDC -> {
                Object constant = insn.constant();
                if (constant instanceof String value) {
                    stack.add(ReferenceFlowSlot.string(JndiReferenceFact.FieldValue.known(value)));
                } else {
                    stack.add(ReferenceFlowSlot.unknown(
                            constant instanceof Long || constant instanceof Double));
                }
            }
            case ALOAD, ILOAD, FLOAD, LLOAD, DLOAD ->
                    stack.add(locals.getOrDefault(insn.varIndex(),
                            ReferenceFlowSlot.unknown(insn.op() == Op.LLOAD
                                    || insn.op() == Op.DLOAD)));
            case ASTORE, ISTORE, FSTORE, LSTORE, DSTORE -> {
                ReferenceFlowSlot value = pop(stack);
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
                if (JndiReferenceFact.REFERENCE_OWNER.equals(owner)) {
                    ReferenceBuilder reference = new ReferenceBuilder(hostMethodKey,
                            insn.offset());
                    references.add(reference);
                    stack.add(ReferenceFlowSlot.reference(reference));
                } else if (JndiReferenceFact.STRING_REF_ADDR_OWNER.equals(owner)) {
                    stack.add(ReferenceFlowSlot.address(new RefAddrBuilder(hostMethodKey,
                            insn.offset(), owner)));
                } else {
                    stack.add(ReferenceFlowSlot.unknown(false));
                }
            }
            case CHECKCAST -> {
                ReferenceFlowSlot value = pop(stack);
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
                stack.add(ReferenceFlowSlot.unknown(isCategory2(field.descriptor())));
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
                stack.add(ReferenceFlowSlot.unknown(isCategory2(field.descriptor())));
            }
            case PUTFIELD -> {
                if (pop(stack) == null || pop(stack) == null) {
                    return false;
                }
            }
            case DUP -> {
                ReferenceFlowSlot value = peek(stack);
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
                ReferenceFlowSlot first = stack.get(top);
                stack.set(top, stack.get(top - 1));
                stack.set(top - 1, first);
            }
            case POP -> {
                if (pop(stack) == null) {
                    return false;
                }
            }
            case POP2 -> {
                ReferenceFlowSlot value = pop(stack);
                if (value == null || (!value.category2() && pop(stack) == null)) {
                    return false;
                }
            }
            case INVOKEVIRTUAL, INVOKESPECIAL, INVOKESTATIC, INVOKEINTERFACE,
                    INVOKEDYNAMIC -> {
                return transferJndiReferenceInvoke(graph, hostMethodKey, insn, stack, locals);
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

    private static boolean transferJndiReferenceInvoke(
            Graph graph, String hostMethodKey, InsnFact insn, List<ReferenceFlowSlot> stack,
            Map<Integer, ReferenceFlowSlot> locals) {
        String owner = null;
        String name;
        String descriptor;
        boolean dynamic = insn.op() == Op.INVOKEDYNAMIC;
        if (dynamic) {
            if (insn.operands().isEmpty()
                    || !(insn.operands().get(0) instanceof InvokeDynamicRef invokedynamic)) {
                return false;
            }
            name = invokedynamic.name();
            descriptor = invokedynamic.descriptor();
        } else {
            MethodRef method = insn.methodRef();
            if (method == null) {
                return false;
            }
            owner = method.owner();
            name = method.name();
            descriptor = method.descriptor();
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
        List<ReferenceFlowSlot> arguments = new ArrayList<>(argumentCount);
        for (int index = argumentCount - 1; index >= 0; index--) {
            ReferenceFlowSlot argument = pop(stack);
            if (argument == null) {
                return false;
            }
            arguments.add(0, argument);
        }
        ReferenceFlowSlot receiver = receiverRequired ? pop(stack) : null;
        if (receiverRequired && receiver == null) {
            return false;
        }
        Node call = graph.findCallNode(hostMethodKey, insn.offset());
        if (call == null) {
            return false;
        }

        if (!dynamic && "<init>".equals(name)
                && JndiReferenceFact.REFERENCE_OWNER.equals(owner)
                && insn.op() == Op.INVOKESPECIAL
                && !initializeReference(receiver, descriptor, arguments, call)) {
            return false;
        }
        if (!dynamic && "<init>".equals(name)
                && JndiReferenceFact.STRING_REF_ADDR_OWNER.equals(owner)
                && insn.op() == Op.INVOKESPECIAL
                && !initializeRefAddr(receiver, descriptor, arguments, call)) {
            return false;
        }
        if (!dynamic && JndiReferenceFact.REFERENCE_OWNER.equals(owner)
                && "add".equals(name)
                && insn.op() == Op.INVOKEVIRTUAL
                && !addReferenceAddress(receiver, descriptor, arguments)) {
            return false;
        }
        if (!dynamic && JndiReferenceFact.REFERENCE_OWNER.equals(owner)
                && insn.op() == Op.INVOKEVIRTUAL
                && (("remove".equals(name)
                && JndiReferenceFact.REFERENCE_REMOVE_DESCRIPTOR.equals(descriptor))
                || ("clear".equals(name)
                && JndiReferenceFact.REFERENCE_CLEAR_DESCRIPTOR.equals(descriptor)))) {
            return false;
        }

        String returnType;
        try {
            returnType = Descriptor.returnType(descriptor);
        } catch (RuntimeException invalidDescriptor) {
            return false;
        }
        if (!"V".equals(returnType)) {
            stack.add("Ljava/lang/String;".equals(returnType)
                    ? ReferenceFlowSlot.string(JndiReferenceFact.FieldValue.unknown())
                    : ReferenceFlowSlot.unknown(isCategory2(returnType)));
        }
        return true;
    }

    private static boolean initializeReference(ReferenceFlowSlot receiver, String descriptor,
                                               List<ReferenceFlowSlot> arguments, Node call) {
        if (receiver == null || receiver.reference() == null) {
            return false;
        }
        ReferenceBuilder reference = receiver.reference();
        if (JndiReferenceFact.REFERENCE_CONSTRUCTOR_ONE_DESCRIPTOR.equals(descriptor)) {
            if (arguments.size() != 1) {
                return false;
            }
            reference.construct(call.id(), call.offset(), valueOf(arguments.get(0)),
                    JndiReferenceFact.FieldValue.absent(),
                    JndiReferenceFact.FieldValue.absent());
            return true;
        }
        if (JndiReferenceFact.REFERENCE_CONSTRUCTOR_ADDRESS_DESCRIPTOR.equals(descriptor)) {
            if (arguments.size() != 2) {
                return false;
            }
            reference.construct(call.id(), call.offset(), valueOf(arguments.get(0)),
                    JndiReferenceFact.FieldValue.absent(),
                    JndiReferenceFact.FieldValue.absent());
            return addAddress(reference, arguments.get(1));
        }
        if (JndiReferenceFact.REFERENCE_CONSTRUCTOR_FACTORY_DESCRIPTOR.equals(descriptor)) {
            if (arguments.size() != 3) {
                return false;
            }
            reference.construct(call.id(), call.offset(), valueOf(arguments.get(0)),
                    valueOf(arguments.get(1)), valueOf(arguments.get(2)));
            return true;
        }
        if (JndiReferenceFact.REFERENCE_CONSTRUCTOR_FULL_DESCRIPTOR.equals(descriptor)) {
            if (arguments.size() != 4) {
                return false;
            }
            reference.construct(call.id(), call.offset(), valueOf(arguments.get(0)),
                    valueOf(arguments.get(2)), valueOf(arguments.get(3)));
            return addAddress(reference, arguments.get(1));
        }
        return true;
    }

    private static boolean initializeRefAddr(ReferenceFlowSlot receiver, String descriptor,
                                             List<ReferenceFlowSlot> arguments, Node call) {
        if (receiver == null || receiver.address() == null
                || !JndiReferenceFact.STRING_REF_ADDR_CONSTRUCTOR_DESCRIPTOR.equals(descriptor)
                || arguments.size() != 2) {
            return false;
        }
        receiver.address().construct(call.id(), call.offset(), valueOf(arguments.get(0)),
                valueOf(arguments.get(1)));
        return true;
    }

    private static boolean addReferenceAddress(ReferenceFlowSlot receiver, String descriptor,
                                               List<ReferenceFlowSlot> arguments) {
        if (receiver == null || receiver.reference() == null
                || !receiver.reference().constructed()) {
            return false;
        }
        if (JndiReferenceFact.REFERENCE_ADD_ADDRESS_DESCRIPTOR.equals(descriptor)) {
            if (arguments.size() != 1) {
                return false;
            }
            return addAddress(receiver.reference(), arguments.get(0));
        }
        if (JndiReferenceFact.REFERENCE_ADD_INDEXED_ADDRESS_DESCRIPTOR.equals(descriptor)) {
            if (arguments.size() != 2) {
                return false;
            }
            return addAddress(receiver.reference(), arguments.get(1));
        }
        return false;
    }

    private static boolean addAddress(ReferenceBuilder reference, ReferenceFlowSlot value) {
        if (value == null || value.address() == null || !value.address().constructed()) {
            return false;
        }
        reference.add(value.address());
        return true;
    }

    private static JndiReferenceFact.FieldValue valueOf(ReferenceFlowSlot value) {
        return value == null || value.stringValue() == null
                ? JndiReferenceFact.FieldValue.unknown() : value.stringValue();
    }

    /**
     * Preserve the exact JDBC URL/Properties consumer and the finite straight-line value
     * identities that reach it.  This seam deliberately models only local aliases, allocation
     * identity, literal values and exact Properties mutations; it never evaluates a driver or
     * treats equal display text as a flow.
     */
    private static void annotateJdbcConnectionFacts(Graph graph, MethodInfo method) {
        String hostMethodKey = methodKey(method.owner(), method.name(), method.descriptor());
        if (method.instructions().isEmpty()) {
            return;
        }
        if (!method.tryCatch().isEmpty()
                || method.instructions().stream().anyMatch(insn -> insn.op().isCondJump()
                || insn.op().isUncondJump() || insn.op().isSwitch())) {
            annotateUnknownJdbcConnectionFacts(graph, method, hostMethodKey);
            return;
        }
        List<JdbcFlowSlot> stack = new ArrayList<>();
        Map<Integer, JdbcFlowSlot> locals = new HashMap<>();
        List<JdbcPropertyWrite> writes = new ArrayList<>();
        List<JdbcConnectionCapture> connections = new ArrayList<>();
        for (InsnFact insn : method.instructions()) {
            if (!transferJdbcInstruction(graph, method, hostMethodKey, insn, stack, locals,
                    writes, connections)) {
                annotateUnknownJdbcConnectionFacts(graph, method, hostMethodKey);
                return;
            }
        }
        for (JdbcConnectionCapture capture : connections) {
            List<JdbcConnectionCallSite.PropertyEntry> entries = writes.stream()
                    .filter(write -> write.receiver().token().equals(capture.properties().token()))
                    .map(write -> write.toModel(method))
                    .toList();
            TypedBridgeFact.CallSite callSite = jdbcCallSite(capture.call(), method);
            capture.call().propsNote(JdbcConnectionCallSite.GRAPH_NOTE_KEY,
                    JdbcConnectionCallSite.withValues(callSite, capture.kind(), capture.url(),
                            capture.properties(), entries));
        }
    }

    private static void annotateUnknownJdbcConnectionFacts(Graph graph, MethodInfo method,
                                                            String hostMethodKey) {
        MethodId hostMethod = MethodId.of(method.owner(), method.name(), method.descriptor());
        for (Node call : graph.callsOfMethod(hostMethodKey)) {
            JdbcConnectionCallSite.fromCall(call.id(), hostMethod, call.offset(), call.owner(),
                    call.name(), call.descriptor(), call.invokeKind())
                    .ifPresent(site -> call.propsNote(JdbcConnectionCallSite.GRAPH_NOTE_KEY, site));
        }
    }

    private static boolean transferJdbcInstruction(
            Graph graph, MethodInfo method, String hostMethodKey, InsnFact insn,
            List<JdbcFlowSlot> stack, Map<Integer, JdbcFlowSlot> locals,
            List<JdbcPropertyWrite> writes, List<JdbcConnectionCapture> connections) {
        if (insn == null || insn.op() == null) {
            return false;
        }
        switch (insn.op()) {
            case NOP, IINC -> {
                return true;
            }
            case ACONST_NULL -> stack.add(JdbcFlowSlot.nullValue(hostMethodKey, insn.offset()));
            case ICONST_M1, ICONST_0, ICONST_1, ICONST_2, ICONST_3, ICONST_4, ICONST_5,
                    FCONST_0, FCONST_1, FCONST_2, BIPUSH, SIPUSH ->
                    stack.add(JdbcFlowSlot.unknown(hostMethodKey, insn.offset(), "I", false));
            case LCONST_0, LCONST_1 ->
                    stack.add(JdbcFlowSlot.unknown(hostMethodKey, insn.offset(), "J", true));
            case DCONST_0, DCONST_1 ->
                    stack.add(JdbcFlowSlot.unknown(hostMethodKey, insn.offset(), "D", true));
            case LDC -> {
                Object constant = insn.constant();
                if (constant instanceof String value) {
                    stack.add(JdbcFlowSlot.knownString(hostMethodKey, insn.offset(), value));
                } else {
                    stack.add(JdbcFlowSlot.unknown(hostMethodKey, insn.offset(),
                            constant instanceof Long ? "J"
                                    : constant instanceof Double ? "D" : "Ljava/lang/Object;",
                            constant instanceof Long || constant instanceof Double));
                }
            }
            case ALOAD, ILOAD, FLOAD, LLOAD, DLOAD ->
                    stack.add(locals.getOrDefault(insn.varIndex(), JdbcFlowSlot.unknown(
                            hostMethodKey, insn.offset(), "Ljava/lang/Object;",
                            insn.op() == Op.LLOAD || insn.op() == Op.DLOAD)));
            case ASTORE, ISTORE, FSTORE, LSTORE, DSTORE -> {
                JdbcFlowSlot value = jdbcPop(stack);
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
                stack.add(JdbcFlowSlot.allocation(hostMethodKey, insn.offset(), owner));
            }
            case CHECKCAST -> {
                JdbcFlowSlot value = jdbcPop(stack);
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
                stack.add(JdbcFlowSlot.unknown(hostMethodKey, insn.offset(), field.descriptor(),
                        isCategory2(field.descriptor())));
            }
            case PUTSTATIC -> {
                if (jdbcPop(stack) == null) {
                    return false;
                }
            }
            case GETFIELD -> {
                if (jdbcPop(stack) == null) {
                    return false;
                }
                FieldRef field = insn.fieldRef();
                if (field == null || !validTypeDescriptor(field.descriptor())) {
                    return false;
                }
                stack.add(JdbcFlowSlot.unknown(hostMethodKey, insn.offset(), field.descriptor(),
                        isCategory2(field.descriptor())));
            }
            case PUTFIELD -> {
                if (jdbcPop(stack) == null || jdbcPop(stack) == null) {
                    return false;
                }
            }
            case DUP -> {
                JdbcFlowSlot value = jdbcPeek(stack);
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
                JdbcFlowSlot first = stack.get(top);
                stack.set(top, stack.get(top - 1));
                stack.set(top - 1, first);
            }
            case POP -> {
                if (jdbcPop(stack) == null) {
                    return false;
                }
            }
            case POP2 -> {
                JdbcFlowSlot value = jdbcPop(stack);
                if (value == null || (!value.category2() && jdbcPop(stack) == null)) {
                    return false;
                }
            }
            case IALOAD, FALOAD, AALOAD, BALOAD, CALOAD, SALOAD -> {
                if (!jdbcPopTwo(stack)) {
                    return false;
                }
                stack.add(JdbcFlowSlot.unknown(hostMethodKey, insn.offset(),
                        "Ljava/lang/Object;", false));
            }
            case LALOAD, DALOAD -> {
                if (!jdbcPopTwo(stack)) {
                    return false;
                }
                stack.add(JdbcFlowSlot.unknown(hostMethodKey, insn.offset(),
                        insn.op() == Op.LALOAD ? "J" : "D", true));
            }
            case IASTORE, FASTORE, AASTORE, BASTORE, CASTORE, SASTORE,
                    LASTORE, DASTORE -> {
                if (!jdbcPopThree(stack)) {
                    return false;
                }
            }
            case INVOKEVIRTUAL, INVOKESPECIAL, INVOKESTATIC, INVOKEINTERFACE,
                    INVOKEDYNAMIC -> {
                return transferJdbcInvoke(graph, method, hostMethodKey, insn, stack, writes,
                        connections);
            }
            case IRETURN, FRETURN, ARETURN, LRETURN, DRETURN, RETURN, ATHROW -> {
                if (insn.op() != Op.RETURN && jdbcPop(stack) == null) {
                    return false;
                }
            }
            case MONITORENTER, MONITOREXIT -> {
                if (jdbcPop(stack) == null) {
                    return false;
                }
            }
            default -> {
                return false;
            }
        }
        return true;
    }

    private static boolean transferJdbcInvoke(
            Graph graph, MethodInfo method, String hostMethodKey, InsnFact insn,
            List<JdbcFlowSlot> stack, List<JdbcPropertyWrite> writes,
            List<JdbcConnectionCapture> connections) {
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
        List<JdbcFlowSlot> arguments = new ArrayList<>(argumentCount);
        for (int index = argumentCount - 1; index >= 0; index--) {
            JdbcFlowSlot argument = jdbcPop(stack);
            if (argument == null) {
                return false;
            }
            arguments.add(0, argument);
        }
        JdbcFlowSlot receiver = receiverRequired ? jdbcPop(stack) : null;
        if (receiverRequired && receiver == null) {
            return false;
        }
        Node call = graph.findCallNode(hostMethodKey, insn.offset());
        if (call == null) {
            return false;
        }

        if (!dynamic && JdbcConnectionCallSite.matches(owner, name, descriptor,
                call.invokeKind())) {
            if (arguments.size() != 2) {
                return false;
            }
            JdbcConnectionCallSite.Kind kind = JdbcConnectionCallSite.DRIVER_MANAGER_OWNER
                    .equals(owner)
                    ? JdbcConnectionCallSite.Kind.DRIVER_MANAGER_GET_CONNECTION
                    : JdbcConnectionCallSite.Kind.DRIVER_CONNECT;
            connections.add(new JdbcConnectionCapture(call, kind,
                    arguments.get(0).value(), arguments.get(1).value()));
        }

        if (!dynamic && receiver != null && receiver.value().descriptor()
                .equals(JdbcConnectionCallSite.PROPERTIES_DESCRIPTOR)
                && JdbcConnectionCallSite.PropertyEntry.PROPERTIES_OWNER.equals(owner)
                && call.invokeKind().equals("VIRTUAL")
                && (JdbcConnectionCallSite.PropertyEntry.SET_PROPERTY_NAME.equals(name)
                || JdbcConnectionCallSite.PropertyEntry.PUT_NAME.equals(name))
                && arguments.size() == 2
                && (JdbcConnectionCallSite.PropertyEntry.SET_PROPERTY_DESCRIPTOR.equals(descriptor)
                || JdbcConnectionCallSite.PropertyEntry.PUT_DESCRIPTOR.equals(descriptor))) {
            writes.add(new JdbcPropertyWrite(call, receiver.value(), arguments.get(0).value(),
                    arguments.get(1).value()));
        }

        String returnType;
        try {
            returnType = Descriptor.returnType(descriptor);
        } catch (RuntimeException invalidDescriptor) {
            return false;
        }
        if (!"V".equals(returnType)) {
            stack.add(JdbcFlowSlot.unknown(hostMethodKey, insn.offset(), returnType,
                    isCategory2(returnType)));
        }
        return true;
    }

    private static TypedBridgeFact.CallSite jdbcCallSite(Node call, MethodInfo method) {
        return new TypedBridgeFact.CallSite(call.id(),
                MethodId.of(method.owner(), method.name(), method.descriptor()), call.offset(),
                call.owner(), call.name(), call.descriptor(), bridgeInvokeKind(call.invokeKind()));
    }

    private static TypedBridgeFact.CallSite propertyCallSite(Node call, MethodInfo method) {
        return jdbcCallSite(call, method);
    }

    private static TypedBridgeFact.InvokeKind bridgeInvokeKind(String value) {
        return switch (value) {
            case "STATIC" -> TypedBridgeFact.InvokeKind.STATIC;
            case "SPECIAL" -> TypedBridgeFact.InvokeKind.SPECIAL;
            case "VIRTUAL" -> TypedBridgeFact.InvokeKind.VIRTUAL;
            case "INTERFACE" -> TypedBridgeFact.InvokeKind.INTERFACE;
            case "DYNAMIC" -> TypedBridgeFact.InvokeKind.DYNAMIC;
            default -> throw new IllegalArgumentException("unknown JVM invoke kind: " + value);
        };
    }

    private static String jdbcToken(String hostMethodKey, int offset, String kind) {
        return "jdbc-" + kind + "-v1:" + hostMethodKey + ":" + offset;
    }

    private static <T> T jdbcPop(List<T> stack) {
        return stack.isEmpty() ? null : stack.remove(stack.size() - 1);
    }

    private static <T> T jdbcPeek(List<T> stack) {
        return stack.isEmpty() ? null : stack.get(stack.size() - 1);
    }

    private static boolean jdbcPopTwo(List<JdbcFlowSlot> stack) {
        return jdbcPop(stack) != null && jdbcPop(stack) != null;
    }

    private static boolean jdbcPopThree(List<JdbcFlowSlot> stack) {
        return jdbcPopTwo(stack) && jdbcPop(stack) != null;
    }

    private record JdbcFlowSlot(JdbcConnectionCallSite.ValueIdentity value, boolean category2) {
        private static JdbcFlowSlot knownString(String hostMethodKey, int offset, String value) {
            return new JdbcFlowSlot(JdbcConnectionCallSite.ValueIdentity.known(
                    jdbcToken(hostMethodKey, offset, "string"),
                    JdbcConnectionCallSite.URL_DESCRIPTOR, offset, value), false);
        }

        private static JdbcFlowSlot allocation(String hostMethodKey, int offset, String owner) {
            return new JdbcFlowSlot(JdbcConnectionCallSite.ValueIdentity.known(
                    jdbcToken(hostMethodKey, offset, "object"), "L" + owner + ";", offset, null),
                    false);
        }

        private static JdbcFlowSlot nullValue(String hostMethodKey, int offset) {
            return new JdbcFlowSlot(JdbcConnectionCallSite.ValueIdentity.nullValue(
                    jdbcToken(hostMethodKey, offset, "null"), "Ljava/lang/Object;", offset), false);
        }

        private static JdbcFlowSlot unknown(String hostMethodKey, int offset,
                                             String descriptor, boolean category2) {
            return new JdbcFlowSlot(JdbcConnectionCallSite.ValueIdentity.unknown(
                    jdbcToken(hostMethodKey, offset, "unknown"), descriptor, offset), category2);
        }
    }

    private record JdbcPropertyWrite(Node call, JdbcConnectionCallSite.ValueIdentity receiver,
                                     JdbcConnectionCallSite.ValueIdentity key,
                                     JdbcConnectionCallSite.ValueIdentity value) {
        private JdbcConnectionCallSite.PropertyEntry toModel(MethodInfo method) {
            TypedBridgeFact.CallSite callSite = propertyCallSite(call, method);
            String keyDescriptor = JdbcConnectionCallSite.PropertyEntry.SET_PROPERTY_NAME
                    .equals(call.name()) ? JdbcConnectionCallSite.URL_DESCRIPTOR : "Ljava/lang/Object;";
            String valueDescriptor = keyDescriptor;
            return new JdbcConnectionCallSite.PropertyEntry(callSite,
                    TypedBridgeFact.Slot.receiver("L"
                            + JdbcConnectionCallSite.PropertyEntry.PROPERTIES_OWNER + ";"),
                    TypedBridgeFact.Slot.argument(0, keyDescriptor),
                    TypedBridgeFact.Slot.argument(1, valueDescriptor), receiver, key, value);
        }
    }

    private record JdbcConnectionCapture(Node call, JdbcConnectionCallSite.Kind kind,
                                         JdbcConnectionCallSite.ValueIdentity url,
                                         JdbcConnectionCallSite.ValueIdentity properties) {
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

    private static <T> T pop(List<T> stack) {
        return stack.isEmpty() ? null : stack.remove(stack.size() - 1);
    }

    private static <T> T peek(List<T> stack) {
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

    private static final class ReferenceBuilder {
        private final String hostMethodKey;
        private final int allocationOffset;
        private final List<RefAddrBuilder> properties = new ArrayList<>();
        private JndiReferenceFact.FieldValue type = JndiReferenceFact.FieldValue.unknown();
        private JndiReferenceFact.FieldValue factoryClass = JndiReferenceFact.FieldValue.unknown();
        private JndiReferenceFact.FieldValue factoryLocation = JndiReferenceFact.FieldValue.unknown();
        private long constructionCallId = -1;
        private int constructionOffset = -1;

        private ReferenceBuilder(String hostMethodKey, int allocationOffset) {
            this.hostMethodKey = hostMethodKey;
            this.allocationOffset = allocationOffset;
        }

        private boolean constructed() {
            return constructionCallId >= 0;
        }

        private int constructionOffset() {
            return constructionOffset;
        }

        private void construct(long callId, int callOffset, JndiReferenceFact.FieldValue type,
                               JndiReferenceFact.FieldValue factoryClass,
                               JndiReferenceFact.FieldValue factoryLocation) {
            if (constructed()) {
                throw new IllegalStateException("Reference allocation initialized twice");
            }
            this.constructionCallId = callId;
            this.constructionOffset = callOffset;
            this.type = type;
            this.factoryClass = factoryClass;
            this.factoryLocation = factoryLocation;
        }

        private void add(RefAddrBuilder address) {
            properties.add(address);
        }

        private JndiReferenceFact toFact() {
            JndiReferenceFact.ObjectIdentity identity = new JndiReferenceFact.ObjectIdentity(
                    JndiReferenceFact.REFERENCE_OWNER, hostMethodKey, allocationOffset,
                    constructionOffset, constructionCallId);
            List<JndiReferenceFact.RefAddrFact> values = properties.stream()
                    .map(RefAddrBuilder::toFact)
                    .toList();
            return new JndiReferenceFact(identity, type, factoryClass, factoryLocation, values);
        }
    }

    private static final class RefAddrBuilder {
        private final String hostMethodKey;
        private final int allocationOffset;
        private final String owner;
        private JndiReferenceFact.FieldValue type = JndiReferenceFact.FieldValue.unknown();
        private JndiReferenceFact.FieldValue content = JndiReferenceFact.FieldValue.unknown();
        private long constructionCallId = -1;
        private int constructionOffset = -1;

        private RefAddrBuilder(String hostMethodKey, int allocationOffset, String owner) {
            this.hostMethodKey = hostMethodKey;
            this.allocationOffset = allocationOffset;
            this.owner = owner;
        }

        private boolean constructed() {
            return constructionCallId >= 0;
        }

        private void construct(long callId, int callOffset, JndiReferenceFact.FieldValue type,
                               JndiReferenceFact.FieldValue content) {
            if (constructed()) {
                throw new IllegalStateException("RefAddr allocation initialized twice");
            }
            this.constructionCallId = callId;
            this.constructionOffset = callOffset;
            this.type = type;
            this.content = content;
        }

        private JndiReferenceFact.RefAddrFact toFact() {
            return new JndiReferenceFact.RefAddrFact(new JndiReferenceFact.ObjectIdentity(owner,
                    hostMethodKey, allocationOffset, constructionOffset, constructionCallId),
                    type, content);
        }
    }

    private record ReferenceFlowSlot(ReferenceBuilder reference, RefAddrBuilder address,
                                     JndiReferenceFact.FieldValue stringValue,
                                     boolean category2) {
        private static ReferenceFlowSlot unknown(boolean category2) {
            return new ReferenceFlowSlot(null, null, null, category2);
        }

        private static ReferenceFlowSlot string(JndiReferenceFact.FieldValue value) {
            return new ReferenceFlowSlot(null, null, value, false);
        }

        private static ReferenceFlowSlot reference(ReferenceBuilder value) {
            return new ReferenceFlowSlot(value, null, null, false);
        }

        private static ReferenceFlowSlot address(RefAddrBuilder value) {
            return new ReferenceFlowSlot(null, value, null, false);
        }
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
