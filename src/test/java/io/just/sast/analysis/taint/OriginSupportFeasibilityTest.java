package io.just.sast.analysis.taint;

import io.just.sast.analysis.hierarchy.ClassHierarchy;
import io.just.sast.config.RuleEngine;
import io.just.sast.config.Match;
import io.just.sast.config.Rule;
import io.just.sast.config.RuleSet;
import io.just.sast.cpg.build.BuiltCpg;
import io.just.sast.cpg.build.CpgBuilder;
import io.just.sast.cpg.build.CpgIndex;
import io.just.sast.cpg.graph.Graph;
import io.just.sast.cpg.graph.Node;
import io.just.sast.cpg.graph.NodeType;
import io.just.sast.frontend.asm.FactsExtractor;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.FieldInfo;
import io.just.sast.model.LoadResult;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.Op;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.Type;

import java.lang.reflect.Modifier;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Regression contracts for local feasibility and opaque callback edges.
 *
 * <p>The fixtures are assembled from ASM nodes in memory.  They intentionally do not depend on
 * the ignored benchmark directory, so the same semantic checks run in a clean CI checkout.</p>
 */
class OriginSupportFeasibilityTest {

    @Test
    void constantBranchMakesSinkPathUnreachable() {
        MethodInfo method = constantBranchMethod();
        assertTrue(emptySupport().sinkPathProvablyUnreachable(method, 2),
                "a known IFEQ branch must remove only the impossible normal edge");
    }

    @Test
    void stringEqualityBranchUsesFiniteStringEvaluationAndItsCache() {
        MethodInfo method = stringEqualityBranchMethod();
        int guardedOffset = method.instructions().stream()
                .filter(insn -> insn.op() == Op.NOP)
                .findFirst()
                .orElseThrow()
                .offset();

        OriginSupport support = supportFor(method);
        assertTrue(support.sinkPathProvablyUnreachable(method, guardedOffset),
                "exact String equality must remove the impossible normal edge");
        assertTrue(support.finiteFilterEvaluations() > 0,
                "the bounded evaluator must expose that it inspected the conditional edges");
        assertTrue(support.finiteFilterRejections() > 0,
                "the bounded evaluator must expose the rejected false edge");
        List<FilterAnalysis.Evidence> evidence = support.finiteFilterEvidence();
        assertEquals(1, evidence.size(),
                "one conditional hotspot must produce one deterministic local evidence row");
        assertEquals(FilterAnalysis.Kind.CFG_PATH, evidence.get(0).kind());
        assertEquals(FilterAnalysis.Status.PROVABLY_UNREACHABLE, evidence.get(0).status());
        assertTrue(evidence.get(0).location().contains("@"));
        assertEquals(64, evidence.get(0).domainDigest().length());
        assertTrue(evidence.get(0).evaluated() >= evidence.get(0).retained()
                        + evidence.get(0).rejected(),
                "edge accounting must not lose an evaluated edge");
        assertTrue(support.sinkPathProvablyUnreachable(method, guardedOffset));
        assertEquals(1L, support.finiteFilterCacheHits(),
                "the method/offset proof identity must reuse the second query");
        assertEquals(evidence, support.finiteFilterEvidence(),
                "cache reuse must preserve byte-stable evidence");
    }

    @Test
    void unknownStringEqualityKeepsBothBranches() {
        MethodInfo method = unknownStringEqualityBranchMethod();
        int guardedOffset = method.instructions().stream()
                .filter(insn -> insn.op() == Op.NOP)
                .findFirst()
                .orElseThrow()
                .offset();

        assertFalse(supportFor(method).sinkPathProvablyUnreachable(method, guardedOffset),
                "a parameter-dependent String equality must remain UNKNOWN and preserve the path");
    }

    @Test
    void unknownBranchThroughBackwardLoopKeepsSinkPath() {
        MethodInfo method = backwardLoopBranchMethod();
        int sinkOffset = method.instructions().stream()
                .filter(insn -> insn.op() == Op.NOP)
                .findFirst()
                .orElseThrow()
                .offset();

        assertFalse(supportFor(method).sinkPathProvablyUnreachable(method, sinkOffset),
                "a sink reachable through one side of a loop must remain reachable when the branch is unknown");
    }

    @Test
    void branchTruthUsesTheSameAbstractStateAsTheSinkGuard() throws Exception {
        OriginSupport support = emptySupport();
        MethodInfo method = constantBranchMethod();
        ForwardOrigins.Result state = support.origins().compute(method);
        var branchTruth = OriginSupport.class.getDeclaredMethod("knownBranchResult",
                MethodInfo.class, ForwardOrigins.Result.class, io.just.sast.model.InsnFact.class);
        branchTruth.setAccessible(true);

        assertEquals(Boolean.TRUE, branchTruth.invoke(support, method, state, method.insnAt(1)),
                "the feasibility pass must fold the same constant branch used by sink pruning");
    }

    @Test
    void nativeCallbackUsesExplicitJniHop() {
        String owner = "fixture/NativeBridge";
        MethodInfo nativeMethod = emptyMethod(owner, "invokeNative", "()V",
                Modifier.PUBLIC | Modifier.NATIVE);
        MethodInfo callback = emptyMethod(owner, "onCallback", "()V", Modifier.PUBLIC);
        ClassInfo bridge = new ClassInfo(owner, "java/lang/Object", List.of(), Modifier.PUBLIC,
                List.of(nativeMethod, callback), List.of());
        ClassHierarchy hierarchy = new ClassHierarchy(Map.of(owner, bridge), null);

        Graph graph = new Graph();
        graph.methodNode(owner, nativeMethod.name(), nativeMethod.descriptor(), false);
        graph.methodNode(owner, callback.name(), callback.descriptor(), false);
        Node nativeCall = graph.addCallNode(owner, nativeMethod.name(), nativeMethod.descriptor(),
                "VIRTUAL", null, 0, "fixture/Host", "run", "()V");
        graph.freeze();

        OriginSupport support = new OriginSupport(graph, hierarchy,
                new RuleEngine(RuleSet.EMPTY, hierarchy), false);

        assertEquals(List.of(nativeCall), support.nativeCallbackSitesOf(callback));
        assertTrue(support.nativeCallbackSite(nativeCall, callback),
                "the same-receiver native callback must remain an explicit bounded edge");
        assertEquals("POINTS_TO_BOUNDED", support.receiverPrecision(nativeCall, nativeMethod,
                        owner, callback.name(), callback.descriptor(), null),
                "JNI callback receiver must carry the same bounded precision label used by the backward path");
    }

    @Test
    void methodCollectionReflectiveInvokeRecognizesTypedIteratorElement() {
        MethodNode method = new MethodNode(0, "run",
                "(Ljava/util/Iterator;Ljava/lang/Object;)Ljava/lang/Object;", null, null);
        method.instructions.add(new VarInsnNode(Op.ALOAD.code(), 1));
        method.instructions.add(new MethodInsnNode(Op.INVOKEINTERFACE.code(), "java/util/Iterator",
                "next", "()Ljava/lang/Object;", true));
        method.instructions.add(new TypeInsnNode(Op.CHECKCAST.code(), "java/lang/reflect/Method"));
        method.instructions.add(new VarInsnNode(Op.ALOAD.code(), 2));
        method.instructions.add(new InsnNode(Op.ACONST_NULL.code()));
        method.instructions.add(new MethodInsnNode(Op.INVOKEVIRTUAL.code(), "java/lang/reflect/Method",
                "invoke", "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false));
        method.instructions.add(new InsnNode(Op.ARETURN.code()));

        MethodInfo methodInfo = extract(method);
        ClassInfo host = new ClassInfo(methodInfo.owner(), "java/lang/Object", List.of(), Modifier.PUBLIC,
                List.of(methodInfo), List.of());
        LoadResult load = new LoadResult(Map.of(host.internalName(), host), List.of(), 1, 61);
        BuiltCpg cpg = new CpgBuilder().build(load);
        cpg.graph().freeze();
        ClassHierarchy hierarchy = new ClassHierarchy(load.classes(), null);
        OriginSupport support = new OriginSupport(cpg.graph(), hierarchy,
                new RuleEngine(RuleSet.EMPTY, hierarchy), false, cpg.index());
        Node invoke = cpg.graph().nodesOfType(NodeType.CALL).stream()
                .filter(node -> "java/lang/reflect/Method".equals(node.owner())
                        && "invoke".equals(node.name()))
                .findFirst()
                .orElseThrow();

        assertTrue(support.methodCollectionReflectiveInvokeSite(invoke),
                "a Method receiver obtained through Iterator.next and CHECKCAST must be recognized");
    }

    @Test
    void directOisCollectionViewIsNotAnExternalProxyInterfaceSite() {
        MethodNode method = new MethodNode(Modifier.PUBLIC, "run", "()V", null, null);
        method.instructions.add(new InsnNode(Op.ACONST_NULL.code()));
        method.instructions.add(new MethodInsnNode(Op.INVOKESPECIAL.code(),
                "java/io/ObjectInputStream", "<init>", "()V", false));
        method.instructions.add(new MethodInsnNode(Op.INVOKEVIRTUAL.code(),
                "java/io/ObjectInputStream", "readObject", "()Ljava/lang/Object;", false));
        method.instructions.add(new TypeInsnNode(Op.CHECKCAST.code(), "java/util/Collection"));
        method.instructions.add(new VarInsnNode(Op.ASTORE.code(), 1));
        method.instructions.add(new VarInsnNode(Op.ALOAD.code(), 1));
        method.instructions.add(new MethodInsnNode(Op.INVOKEINTERFACE.code(), "java/util/Collection",
                "iterator", "()Ljava/util/Iterator;", true));
        method.instructions.add(new VarInsnNode(Op.ASTORE.code(), 2));
        method.instructions.add(new VarInsnNode(Op.ALOAD.code(), 2));
        method.instructions.add(new MethodInsnNode(Op.INVOKEINTERFACE.code(), "java/util/Iterator",
                "hasNext", "()Z", true));
        method.instructions.add(new InsnNode(Op.POP.code()));
        method.instructions.add(new InsnNode(Op.RETURN.code()));

        MethodInfo methodInfo = extract("fixture/DeserializeHost", method);
        ClassInfo host = new ClassInfo(methodInfo.owner(), "java/lang/Object", List.of(),
                Modifier.PUBLIC, List.of(methodInfo), List.of());
        ClassInfo collectionType = new ClassInfo("java/util/Collection", "java/lang/Object", List.of(),
                Modifier.PUBLIC | Modifier.INTERFACE, List.of(), List.of());
        ClassInfo iteratorType = new ClassInfo("java/util/Iterator", "java/lang/Object", List.of(),
                Modifier.PUBLIC | Modifier.INTERFACE, List.of(), List.of());
        LoadResult load = new LoadResult(Map.of(host.internalName(), host,
                collectionType.internalName(), collectionType,
                iteratorType.internalName(), iteratorType), List.of(), 3, 61);
        BuiltCpg cpg = new CpgBuilder().build(load);
        cpg.graph().freeze();
        ClassHierarchy hierarchy = new ClassHierarchy(load.classes(), null);
        OriginSupport support = new OriginSupport(cpg.graph(), hierarchy,
                new RuleEngine(RuleSet.EMPTY, hierarchy), false, cpg.index());
        Node iterator = cpg.graph().nodesOfType(NodeType.CALL).stream()
                .filter(node -> "java/util/Collection".equals(node.owner())
                        && "iterator".equals(node.name()))
                .findFirst().orElseThrow();

        assertTrue(support.directDeserializationReceiver(iterator,
                        support.origins().compute(methodInfo)),
                "the immediate OIS result must remain the collection identity boundary");
        assertFalse(support.serializedProxyInterfaceCallSites().contains(iterator),
                "a standard container view must not be offered to an unrelated external proxy handler");
        assertTrue(support.serializedProxyInterfaceCallSites().stream()
                        .noneMatch(node -> "java/util/Iterator".equals(node.owner())
                                && "hasNext".equals(node.name())),
                "a derived iterator operation must remain owned by the container model");
    }

    @Test
    void deserializedContainerElementTypesRequireIteratorElementProvenance() {
        MethodNode method = new MethodNode(Modifier.PUBLIC, "run", "()V", null, null);
        method.instructions.add(new InsnNode(Op.ACONST_NULL.code()));
        method.instructions.add(new MethodInsnNode(Op.INVOKEVIRTUAL.code(),
                "java/io/ObjectInputStream", "readObject", "()Ljava/lang/Object;", false));
        method.instructions.add(new TypeInsnNode(Op.CHECKCAST.code(), "java/util/Collection"));
        method.instructions.add(new VarInsnNode(Op.ASTORE.code(), 1));
        method.instructions.add(new VarInsnNode(Op.ALOAD.code(), 1));
        method.instructions.add(new MethodInsnNode(Op.INVOKEINTERFACE.code(), "java/util/Collection",
                "iterator", "()Ljava/util/Iterator;", true));
        method.instructions.add(new VarInsnNode(Op.ASTORE.code(), 2));
        method.instructions.add(new VarInsnNode(Op.ALOAD.code(), 2));
        method.instructions.add(new MethodInsnNode(Op.INVOKEINTERFACE.code(), "java/util/Iterator",
                "next", "()Ljava/lang/Object;", true));
        method.instructions.add(new TypeInsnNode(Op.CHECKCAST.code(), "fixture/Element"));
        method.instructions.add(new InsnNode(Op.POP.code()));
        method.instructions.add(new InsnNode(Op.RETURN.code()));

        MethodInfo methodInfo = extract("fixture/DeserializeHost", method);
        ClassInfo host = new ClassInfo(methodInfo.owner(), "java/lang/Object", List.of(),
                Modifier.PUBLIC, List.of(methodInfo), List.of());
        MethodNode directMethod = new MethodNode(Modifier.PUBLIC, "direct", "()V", null, null);
        directMethod.instructions.add(new InsnNode(Op.ACONST_NULL.code()));
        directMethod.instructions.add(new MethodInsnNode(Op.INVOKEVIRTUAL.code(),
                "java/io/ObjectInputStream", "readObject", "()Ljava/lang/Object;", false));
        directMethod.instructions.add(new TypeInsnNode(Op.CHECKCAST.code(), "fixture/Element"));
        directMethod.instructions.add(new InsnNode(Op.POP.code()));
        directMethod.instructions.add(new InsnNode(Op.RETURN.code()));
        MethodInfo directMethodInfo = extract("fixture/DirectDeserializeHost", directMethod);
        ClassInfo directHost = new ClassInfo(directMethodInfo.owner(), "java/lang/Object",
                List.of(), Modifier.PUBLIC, List.of(directMethodInfo), List.of());
        ClassInfo collectionType = new ClassInfo("java/util/Collection", "java/lang/Object",
                List.of(), Modifier.PUBLIC | Modifier.INTERFACE, List.of(), List.of());
        ClassInfo iteratorType = new ClassInfo("java/util/Iterator", "java/lang/Object",
                List.of(), Modifier.PUBLIC | Modifier.INTERFACE, List.of(), List.of());
        ClassInfo serializable = new ClassInfo("java/io/Serializable", "java/lang/Object",
                List.of(), Modifier.PUBLIC | Modifier.INTERFACE, List.of(), List.of());
        ClassInfo element = new ClassInfo("fixture/Element", "java/lang/Object",
                List.of("java/io/Serializable"), Modifier.PUBLIC, List.of(), List.of());
        LoadResult load = new LoadResult(Map.of(host.internalName(), host,
                directHost.internalName(), directHost,
                collectionType.internalName(), collectionType,
                iteratorType.internalName(), iteratorType,
                serializable.internalName(), serializable,
                element.internalName(), element), List.of(), 6, 61);
        BuiltCpg cpg = new CpgBuilder().build(load);
        cpg.graph().freeze();
        ClassHierarchy hierarchy = new ClassHierarchy(load.classes(), null);
        OriginSupport support = new OriginSupport(cpg.graph(), hierarchy,
                new RuleEngine(RuleSet.EMPTY, hierarchy), false, cpg.index());

        assertEquals(Set.of("fixture/Element"),
                support.deserializedContainerElementTypes(methodInfo),
                "only a concrete serializable CHECKCAST of Iterator.next must bind an OIS element");
        assertTrue(support.hasDeserializedContainerElementAccess(methodInfo),
                "the iterator result must be recognized as a standard-container element access");
        assertEquals(Set.of(), support.deserializedContainerElementTypes(directMethodInfo),
                "a direct OIS.readObject CHECKCAST is not a container-element provenance proof");
        assertFalse(support.hasDeserializedContainerElementAccess(directMethodInfo),
                "a direct/root-object OIS result must not be classified as a container-element access");
    }

    @Test
    void typedInputFlowFollowsRenamedServiceAndAlternateDecoderModel() {
        MethodNode method = new MethodNode(Modifier.PUBLIC, "accept", "(Ljava/lang/String;)V",
                null, null);
        method.instructions.add(new TypeInsnNode(Op.NEW.code(), "java/io/ByteArrayInputStream"));
        method.instructions.add(new InsnNode(Op.DUP.code()));
        method.instructions.add(new VarInsnNode(Op.ALOAD.code(), 1));
        method.instructions.add(new MethodInsnNode(Op.INVOKESTATIC.code(),
                "fixture/codec/AltDecoder", "decode", "(Ljava/lang/String;)[B", false));
        method.instructions.add(new MethodInsnNode(Op.INVOKESPECIAL.code(),
                "java/io/ByteArrayInputStream", "<init>", "([B)V", false));
        method.instructions.add(new VarInsnNode(Op.ASTORE.code(), 2));
        method.instructions.add(new TypeInsnNode(Op.NEW.code(), "java/io/ObjectInputStream"));
        method.instructions.add(new InsnNode(Op.DUP.code()));
        method.instructions.add(new VarInsnNode(Op.ALOAD.code(), 2));
        method.instructions.add(new MethodInsnNode(Op.INVOKESPECIAL.code(),
                "java/io/ObjectInputStream", "<init>", "(Ljava/io/InputStream;)V", false));
        method.instructions.add(new MethodInsnNode(Op.INVOKEVIRTUAL.code(),
                "java/io/ObjectInputStream", "readObject", "()Ljava/lang/Object;", false));
        method.instructions.add(new TypeInsnNode(Op.CHECKCAST.code(), "java/util/Collection"));
        method.instructions.add(new MethodInsnNode(Op.INVOKEINTERFACE.code(), "java/util/Collection",
                "iterator", "()Ljava/util/Iterator;", true));
        method.instructions.add(new MethodInsnNode(Op.INVOKEINTERFACE.code(), "java/util/Iterator",
                "next", "()Ljava/lang/Object;", true));
        method.instructions.add(new TypeInsnNode(Op.CHECKCAST.code(), "fixture/RenamedElement"));
        method.instructions.add(new InsnNode(Op.POP.code()));
        method.instructions.add(new InsnNode(Op.RETURN.code()));

        MethodInfo hostMethod = extract("fixture/renamed/ImportService", method);
        ClassInfo service = new ClassInfo(hostMethod.owner(), "java/lang/Object", List.of(),
                Modifier.PUBLIC, List.of(hostMethod), List.of());
        ClassInfo element = new ClassInfo("fixture/RenamedElement", "java/lang/Object",
                List.of("java/io/Serializable"), Modifier.PUBLIC, List.of(), List.of());
        ClassInfo serializable = new ClassInfo("java/io/Serializable", "java/lang/Object",
                List.of(), Modifier.PUBLIC | Modifier.INTERFACE, List.of(), List.of());
        Rule.ModelRule decoder = new Rule.ModelRule("fixture-alt-decoder",
                new Rule.CallMatcher(Match.of("fixture/codec/AltDecoder"), Match.of("decode"),
                        Match.of("(Ljava/lang/String;)[B")), Map.of("return", List.of("arg0")));
        LoadResult load = new LoadResult(Map.of(service.internalName(), service,
                element.internalName(), element, serializable.internalName(), serializable),
                List.of(), 3, 61);
        BuiltCpg cpg = new CpgBuilder().build(load);
        cpg.graph().freeze();
        ClassHierarchy hierarchy = new ClassHierarchy(load.classes(), null);
        OriginSupport support = new OriginSupport(cpg.graph(), hierarchy,
                new RuleEngine(new RuleSet(List.of(), List.of(), List.of(), List.of(decoder),
                        List.of()), hierarchy), false, cpg.index());
        Node read = cpg.graph().nodesOfType(NodeType.CALL).stream()
                .filter(OriginSupport::isOisRead).findFirst().orElseThrow();

        OriginSupport.DeserializationInputFlow flow = support.proveDeserializationInput(hostMethod,
                read, Set.of("fixture/RenamedElement"));
        assertTrue(flow.proven(), "renamed service/element must use the generic typed input proof");
        assertEquals(Set.of(1), flow.parameterSlots());
        assertEquals(Set.of("fixture/RenamedElement"), flow.elementTypes());
        assertTrue(flow.stages().stream().anyMatch(stage -> stage.contains("fixture/codec/AltDecoder#decode")));

        OriginSupport opaque = new OriginSupport(cpg.graph(), hierarchy,
                new RuleEngine(RuleSet.EMPTY, hierarchy), false, cpg.index());
        OriginSupport.DeserializationInputFlow unknown = opaque.proveDeserializationInput(
                hostMethod, read, Set.of("fixture/RenamedElement"));
        assertFalse(unknown.proven(),
                "an unmodeled decoder must not be promoted to an external typed flow");
    }

    @Test
    void reflectiveDispatchBindsSerializedFieldsAcrossInterfaceCallback() {
        OriginSupport support = reflectiveDispatchSupport(true);

        OriginSupport.ReflectiveDispatchProof proof = support.proveReflectiveDispatch(
                Set.of("fixture/RenamedElement"),
                Set.of("fixture/RenamedElement#hashCode()I",
                        "fixture/ReflectiveBridge#invoke(Ljava/lang/Object;Ljava/lang/String;"
                                + "[Ljava/lang/Class;[Ljava/lang/Object;)Ljava/lang/Object;"));
        assertTrue(proof.established(), "serialized fields must reach the bounded reflective bridge");
        assertEquals(OriginSupport.ReflectiveDispatchProof.Status.BOUNDED, proof.status());
        assertEquals("BOUNDED", proof.methodNameResolution());
        assertEquals("BOUNDED", proof.descriptorResolution());
        assertTrue(proof.constrainedInputs().contains("serialized-method-name"));
    }

    @Test
    void reflectiveDispatchRejectsConstantMethodName() {
        OriginSupport support = reflectiveDispatchSupport(false);
        OriginSupport.ReflectiveDispatchProof proof = support.proveReflectiveDispatch(
                Set.of("fixture/RenamedElement"),
                Set.of("fixture/RenamedElement#hashCode()I",
                        "fixture/ReflectiveBridge#invoke(Ljava/lang/Object;Ljava/lang/String;"
                                + "[Ljava/lang/Class;[Ljava/lang/Object;)Ljava/lang/Object;"));

        assertFalse(proof.established(),
                "a constant lookup name is not a serialized-field constraint");
        assertTrue(proof.reasons().contains("REFLECTIVE_SERIALIZED_FIELDS_NOT_MAPPED"));
    }

    @Test
    void zeroArgumentReflectiveLookupRecoversEmptyClassArrayDescriptor() throws Exception {
        MethodNode method = new MethodNode(Modifier.PUBLIC | Modifier.STATIC, "run", "()V", null, null);
        method.instructions.add(new LdcInsnNode(Type.getObjectType("fixture/Target")));
        method.instructions.add(new LdcInsnNode("ping"));
        method.instructions.add(new InsnNode(Op.ICONST_0.code()));
        method.instructions.add(new TypeInsnNode(Op.ANEWARRAY.code(), "java/lang/Class"));
        method.instructions.add(new MethodInsnNode(Op.INVOKEVIRTUAL.code(), "java/lang/Class",
                "getMethod", "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false));
        method.instructions.add(new InsnNode(Op.POP.code()));
        method.instructions.add(new InsnNode(Op.RETURN.code()));

        MethodInfo hostMethod = extract("fixture/Host", method);
        MethodInfo targetMethod = emptyMethod("fixture/Target", "ping", "()V", Modifier.PUBLIC);
        ClassInfo host = new ClassInfo("fixture/Host", "java/lang/Object", List.of(), Modifier.PUBLIC,
                List.of(hostMethod), List.of());
        ClassInfo target = new ClassInfo("fixture/Target", "java/lang/Object", List.of(), Modifier.PUBLIC,
                List.of(targetMethod), List.of());
        LoadResult load = new LoadResult(Map.of(host.internalName(), host, target.internalName(), target),
                List.of(), 2, 61);
        BuiltCpg cpg = new CpgBuilder().build(load);
        cpg.graph().freeze();
        ClassHierarchy hierarchy = new ClassHierarchy(load.classes(), null);
        OriginSupport support = new OriginSupport(cpg.graph(), hierarchy,
                new RuleEngine(RuleSet.EMPTY, hierarchy), false, cpg.index());
        var lookup = hostMethod.instructions().stream()
                .filter(insn -> insn.op() == Op.INVOKEVIRTUAL
                        && insn.methodRef() != null
                        && "getMethod".equals(insn.methodRef().name()))
                .findFirst().orElseThrow();
        var descriptor = OriginSupport.class.getDeclaredMethod("reflectiveParameterDescriptor",
                MethodInfo.class, io.just.sast.model.InsnFact.class, io.just.sast.model.MethodRef.class);
        descriptor.setAccessible(true);

        assertEquals("()V", descriptor.invoke(support, hostMethod, lookup, lookup.methodRef()),
                "Class.getMethod(name) 的空 Class[] 必须恢复为零参数方法描述符");
    }

    @Test
    void javaBeanSiteKeepsBothDirectionsWhenHostUsesReadAndWriteMethod() {
        MethodNode method = new MethodNode(Modifier.PUBLIC | Modifier.STATIC, "run", "()V",
                null, null);
        method.instructions.add(new InsnNode(Op.ACONST_NULL.code()));
        method.instructions.add(new MethodInsnNode(Op.INVOKEVIRTUAL.code(),
                "java/beans/PropertyDescriptor", "getReadMethod", "()Ljava/lang/reflect/Method;",
                false));
        method.instructions.add(new InsnNode(Op.POP.code()));
        method.instructions.add(new InsnNode(Op.ACONST_NULL.code()));
        method.instructions.add(new MethodInsnNode(Op.INVOKEVIRTUAL.code(),
                "java/beans/PropertyDescriptor", "getWriteMethod", "()Ljava/lang/reflect/Method;",
                false));
        method.instructions.add(new InsnNode(Op.POP.code()));
        addReflectiveInvoke(method);
        addReflectiveInvoke(method);
        method.instructions.add(new InsnNode(Op.RETURN.code()));

        MethodInfo hostMethod = extract("fixture/BeanHost", method);
        ClassInfo host = new ClassInfo("fixture/BeanHost", "java/lang/Object", List.of(),
                Modifier.PUBLIC, List.of(hostMethod), List.of());
        LoadResult load = new LoadResult(Map.of(host.internalName(), host), List.of(), 1, 61);
        BuiltCpg cpg = new CpgBuilder().build(load);
        cpg.graph().freeze();
        ClassHierarchy hierarchy = new ClassHierarchy(load.classes(), null);
        OriginSupport support = new OriginSupport(cpg.graph(), hierarchy,
                new RuleEngine(RuleSet.EMPTY, hierarchy), false, cpg.index());

        assertEquals(2, support.javaBeanInvokeSitesOf("fixture/Bean", "getValue").size(),
                "同一宿主的 JavaBean 读方向必须保留");
        assertEquals(2, support.javaBeanInvokeSitesOf("fixture/Bean", "setValue").size(),
                "同一宿主的 JavaBean 写方向不能被读方向覆盖");
    }

    @Test
    void indexesConstructorLookupForConstructorNewInstance() {
        MethodNode method = new MethodNode(Modifier.PUBLIC | Modifier.STATIC, "run", "()V",
                null, null);
        method.instructions.add(new LdcInsnNode(Type.getObjectType("fixture/Target")));
        method.instructions.add(new InsnNode(Op.ICONST_0.code()));
        method.instructions.add(new TypeInsnNode(Op.ANEWARRAY.code(), "java/lang/Class"));
        method.instructions.add(new MethodInsnNode(Op.INVOKEVIRTUAL.code(), "java/lang/Class",
                "getConstructor", "([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;", false));
        method.instructions.add(new InsnNode(Op.ACONST_NULL.code()));
        method.instructions.add(new MethodInsnNode(Op.INVOKEVIRTUAL.code(),
                "java/lang/reflect/Constructor", "newInstance", "([Ljava/lang/Object;)Ljava/lang/Object;",
                false));
        method.instructions.add(new InsnNode(Op.POP.code()));
        method.instructions.add(new InsnNode(Op.RETURN.code()));

        MethodInfo hostMethod = extract("fixture/ConstructorHost", method);
        MethodInfo constructor = emptyMethod("fixture/Target", "<init>", "()V", Modifier.PUBLIC);
        ClassInfo host = new ClassInfo("fixture/ConstructorHost", "java/lang/Object", List.of(),
                Modifier.PUBLIC, List.of(hostMethod), List.of());
        ClassInfo target = new ClassInfo("fixture/Target", "java/lang/Object", List.of(),
                Modifier.PUBLIC, List.of(constructor), List.of());
        LoadResult load = new LoadResult(Map.of(host.internalName(), host, target.internalName(), target),
                List.of(), 2, 61);
        BuiltCpg cpg = new CpgBuilder().build(load);
        cpg.graph().freeze();
        ClassHierarchy hierarchy = new ClassHierarchy(load.classes(), null);
        OriginSupport support = new OriginSupport(cpg.graph(), hierarchy,
                new RuleEngine(RuleSet.EMPTY, hierarchy), false, cpg.index());
        Node allocation = cpg.graph().nodesOfType(NodeType.CALL).stream()
                .filter(node -> "java/lang/reflect/Constructor".equals(node.owner())
                        && "newInstance".equals(node.name()))
                .findFirst().orElseThrow();

        assertTrue(support.reflectiveSites().getOrDefault(allocation.id(), List.of())
                        .contains("fixture/Target"),
                "Constructor.newInstance 也必须保留 Class.getConstructor 的精确类来源");
    }

    @Test
    void frameworkReflectionIndexContainsOnlyMethodInvokeSites() {
        MethodNode method = new MethodNode(Modifier.PUBLIC | Modifier.STATIC, "run", "()V",
                null, null);
        method.instructions.add(new InsnNode(Op.ACONST_NULL.code()));
        method.instructions.add(new InsnNode(Op.ACONST_NULL.code()));
        method.instructions.add(new InsnNode(Op.ACONST_NULL.code()));
        method.instructions.add(new MethodInsnNode(Op.INVOKEVIRTUAL.code(),
                "java/lang/reflect/Method", "invoke",
                "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false));
        method.instructions.add(new InsnNode(Op.POP.code()));
        method.instructions.add(new InsnNode(Op.ACONST_NULL.code()));
        method.instructions.add(new MethodInsnNode(Op.INVOKEVIRTUAL.code(),
                "java/lang/reflect/Constructor", "newInstance", "([Ljava/lang/Object;)Ljava/lang/Object;",
                false));
        method.instructions.add(new InsnNode(Op.POP.code()));
        method.instructions.add(new InsnNode(Op.RETURN.code()));

        String owner = "org/apache/commons/fixture/Host";
        MethodInfo hostMethod = extract(owner, method);
        ClassInfo host = new ClassInfo(owner, "java/lang/Object", List.of(), Modifier.PUBLIC,
                List.of(hostMethod), List.of());
        LoadResult load = new LoadResult(Map.of(owner, host), List.of(), 1, 61);
        BuiltCpg cpg = new CpgBuilder().build(load);
        cpg.graph().freeze();
        ClassHierarchy hierarchy = new ClassHierarchy(load.classes(), null);
        Rule.SourceRule source = new Rule.SourceRule("T-FRAMEWORK", "deserialize",
                new Rule.CallMatcher(Match.of("org/apache/commons/fixture/Deserializer"),
                        Match.of("read"), null), null);
        OriginSupport support = new OriginSupport(cpg.graph(), hierarchy,
                new RuleEngine(new RuleSet(List.of(), List.of(), List.of(source), List.of(), List.of()),
                        hierarchy), false, cpg.index());

        assertEquals(1, support.frameworkMethodInvokeSites().size(),
                "framework reflection index must retain Method.invoke");
    }

    private static OriginSupport reflectiveDispatchSupport(boolean serializedMethodName) {
        MethodNode callback = new MethodNode(Modifier.PUBLIC, "hashCode", "()I", null, null);
        for (String field : List.of("object", "methodName", "paramTypes", "args")) {
            if ("methodName".equals(field) && !serializedMethodName) {
                callback.instructions.add(new LdcInsnNode("fixedMethod"));
                continue;
            }
            callback.instructions.add(new VarInsnNode(Op.ALOAD.code(), 0));
            String descriptor = switch (field) {
                case "object" -> "Ljava/lang/Object;";
                case "methodName" -> "Ljava/lang/String;";
                case "paramTypes" -> "[Ljava/lang/Class;";
                default -> "[Ljava/lang/Object;";
            };
            callback.instructions.add(new FieldInsnNode(Op.GETFIELD.code(),
                    "fixture/RenamedElement", field, descriptor));
        }
        callback.instructions.add(new MethodInsnNode(Op.INVOKESTATIC.code(),
                "fixture/ReflectiveBridge", "invoke",
                "(Ljava/lang/Object;Ljava/lang/String;[Ljava/lang/Class;[Ljava/lang/Object;)Ljava/lang/Object;",
                false));
        callback.instructions.add(new InsnNode(Op.POP.code()));
        callback.instructions.add(new InsnNode(Op.ICONST_0.code()));
        callback.instructions.add(new InsnNode(Op.IRETURN.code()));

        MethodNode bridge = new MethodNode(Modifier.PUBLIC | Modifier.STATIC, "invoke",
                "(Ljava/lang/Object;Ljava/lang/String;[Ljava/lang/Class;[Ljava/lang/Object;)Ljava/lang/Object;",
                null, null);
        bridge.instructions.add(new VarInsnNode(Op.ALOAD.code(), 0));
        bridge.instructions.add(new MethodInsnNode(Op.INVOKEVIRTUAL.code(), "java/lang/Object",
                "getClass", "()Ljava/lang/Class;", false));
        bridge.instructions.add(new VarInsnNode(Op.ASTORE.code(), 5));
        bridge.instructions.add(new VarInsnNode(Op.ALOAD.code(), 5));
        bridge.instructions.add(new VarInsnNode(Op.ALOAD.code(), 1));
        bridge.instructions.add(new VarInsnNode(Op.ALOAD.code(), 2));
        bridge.instructions.add(new MethodInsnNode(Op.INVOKEVIRTUAL.code(), "java/lang/Class",
                "getMethod", "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false));
        bridge.instructions.add(new VarInsnNode(Op.ASTORE.code(), 6));
        bridge.instructions.add(new VarInsnNode(Op.ALOAD.code(), 6));
        bridge.instructions.add(new VarInsnNode(Op.ALOAD.code(), 0));
        bridge.instructions.add(new VarInsnNode(Op.ALOAD.code(), 3));
        bridge.instructions.add(new MethodInsnNode(Op.INVOKEVIRTUAL.code(),
                "java/lang/reflect/Method", "invoke",
                "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false));
        bridge.instructions.add(new InsnNode(Op.ARETURN.code()));

        MethodInfo callbackInfo = extract("fixture/RenamedElement", callback);
        MethodInfo bridgeInfo = extract("fixture/ReflectiveBridge", bridge);
        List<FieldInfo> fields = List.of(
                new FieldInfo("fixture/RenamedElement", "object", "Ljava/lang/Object;", 0),
                new FieldInfo("fixture/RenamedElement", "methodName", "Ljava/lang/String;", 0),
                new FieldInfo("fixture/RenamedElement", "paramTypes", "[Ljava/lang/Class;", 0),
                new FieldInfo("fixture/RenamedElement", "args", "[Ljava/lang/Object;", 0));
        ClassInfo element = new ClassInfo("fixture/RenamedElement", "java/lang/Object",
                List.of("java/io/Serializable"), Modifier.PUBLIC,
                List.of(callbackInfo), fields);
        ClassInfo bridgeClass = new ClassInfo("fixture/ReflectiveBridge", "java/lang/Object",
                List.of(), Modifier.PUBLIC, List.of(bridgeInfo), List.of());
        ClassInfo serializable = new ClassInfo("java/io/Serializable", "java/lang/Object",
                List.of(), Modifier.PUBLIC | Modifier.INTERFACE, List.of(), List.of());
        LoadResult load = new LoadResult(Map.of(element.internalName(), element,
                bridgeClass.internalName(), bridgeClass, serializable.internalName(), serializable),
                List.of(), 3, 61);
        BuiltCpg cpg = new CpgBuilder().build(load);
        cpg.graph().freeze();
        ClassHierarchy hierarchy = new ClassHierarchy(load.classes(), null);
        return new OriginSupport(cpg.graph(), hierarchy,
                new RuleEngine(RuleSet.EMPTY, hierarchy), false, cpg.index());
    }

    @Test
    void indexesSerializableInvocationHandlerForExternallyAssembledProxy() {
        String handlerOwner = "fixture/ExternalHandler";
        String descriptor = OriginSupport.SERIALIZED_PROXY_HANDLER_DESCRIPTOR;
        MethodNode method = new MethodNode(Modifier.PUBLIC, "invoke", descriptor, null, null);
        method.instructions.add(new InsnNode(Op.ACONST_NULL.code()));
        method.instructions.add(new InsnNode(Op.ARETURN.code()));
        MethodInfo handlerMethod = extract(handlerOwner, method);
        ClassInfo handler = new ClassInfo(handlerOwner, "java/lang/Object",
                List.of("java/lang/reflect/InvocationHandler", "java/io/Serializable"),
                Modifier.PUBLIC | Modifier.FINAL, List.of(handlerMethod), List.of());

        Graph graph = new Graph();
        Node methodNode = graph.methodNode(handlerOwner, "invoke", descriptor, false);
        graph.freeze();
        ClassHierarchy hierarchy = new ClassHierarchy(Map.of(handlerOwner, handler), null);
        OriginSupport support = new OriginSupport(graph, hierarchy,
                new RuleEngine(RuleSet.EMPTY, hierarchy), false);

        assertTrue(support.isSerializedProxyHandler(handlerMethod));
        assertEquals(List.of(methodNode), support.serializedProxyHandlerMethods(),
                "serialized proxy callbacks must be indexed without requiring Proxy.newProxyInstance");
    }

    @Test
    void entryClosureDropsReachableMethodsWithNoTerminalDemand() {
        String app = "fixture/app/Ingress";
        String helper = "fixture/app/Noise";
        String relevant = "fixture/lib/Relevant";
        String runtime = "java/lang/Runtime";
        String sinkDesc = "(Ljava/lang/String;)Ljava/lang/Process;";
        Graph graph = new Graph();
        graph.methodNode(app, "handle", "()V", false);
        graph.methodNode(helper, "helper", "()V", false);
        graph.methodNode(relevant, "trigger", "()V", false);
        graph.methodNode(runtime, "exec", sinkDesc, true);
        Node helperCall = graph.addCallNode(helper, "helper", "()V", "STATIC", null, 0,
                app, "handle", "()V");
        Node relevantCall = graph.addCallNode(relevant, "trigger", "()V", "STATIC", null, 1,
                app, "handle", "()V");
        Node sink = graph.addCallNode(runtime, "exec", sinkDesc, "VIRTUAL", null, 0,
                relevant, "trigger", "()V");
        graph.addEdge(helperCall, graph.findMethodNode(helper, "helper", "()V"),
                io.just.sast.cpg.graph.EdgeType.INVOKES, "STATIC");
        graph.addEdge(relevantCall, graph.findMethodNode(relevant, "trigger", "()V"),
                io.just.sast.cpg.graph.EdgeType.INVOKES, "STATIC");
        graph.addEdge(sink, graph.findMethodNode(runtime, "exec", sinkDesc),
                io.just.sast.cpg.graph.EdgeType.INVOKES, "VIRTUAL");
        graph.freeze();

        Rule.SinkRule sinkRule = new Rule.SinkRule("runtime-exec", "COMMAND", "HIGH",
                new Rule.CallMatcher(Match.of(runtime), Match.of("exec"), Match.of(sinkDesc)),
                List.of(new Rule.TaintedPos.Arg(0)), Rule.SinkRole.TERMINAL);
        Rule.MagicEntryRule entryRule = new Rule.MagicEntryRule("app-handler", "handle",
                new Rule.MethodMatcher(Match.of("handle"), Match.of("()V"), false), null,
                "lifecycle");
        RuleEngine engine = new RuleEngine(new RuleSet(List.of(sinkRule), List.of(entryRule),
                List.of(), List.of(), List.of()), new ClassHierarchy(Map.of(), null));
        OriginSupport support = new OriginSupport(graph, new ClassHierarchy(Map.of(), null),
                engine, false, CpgIndex.empty(), Set.of(app), true,
                Set.of(app + "#handle()V"));

        Set<String> closure = support.entryDownstream(graph);
        assertTrue(closure.contains(relevant + "#trigger()V"),
                "terminal-relevant dependency method must remain in the entry demand closure");
        assertFalse(closure.contains(helper + "#helper()V"),
                "a reachable helper with no terminal demand must not expand the whole closure");
    }

    private static OriginSupport emptySupport() {
        Graph graph = new Graph();
        graph.freeze();
        ClassHierarchy hierarchy = new ClassHierarchy(Map.of(), null);
        return new OriginSupport(graph, hierarchy, new RuleEngine(RuleSet.EMPTY, hierarchy), false);
    }

    private static MethodInfo constantBranchMethod() {
        LabelNode taken = new LabelNode();
        MethodNode method = new MethodNode(0, "guard", "()V", null, null);
        method.instructions.add(new InsnNode(Op.ICONST_0.code()));
        method.instructions.add(new JumpInsnNode(Op.IFEQ.code(), taken));
        method.instructions.add(new InsnNode(Op.NOP.code()));
        method.instructions.add(new InsnNode(Op.RETURN.code()));
        method.instructions.add(taken);
        method.instructions.add(new InsnNode(Op.RETURN.code()));
        return extract(method);
    }

    private static MethodInfo stringEqualityBranchMethod() {
        LabelNode impossible = new LabelNode();
        MethodNode method = new MethodNode(Modifier.PUBLIC | Modifier.STATIC, "guarded", "()V",
                null, null);
        method.instructions.add(new LdcInsnNode("safe"));
        method.instructions.add(new LdcInsnNode("safe"));
        method.instructions.add(new MethodInsnNode(Op.INVOKEVIRTUAL.code(), "java/lang/String",
                "equals", "(Ljava/lang/Object;)Z", false));
        method.instructions.add(new JumpInsnNode(Op.IFEQ.code(), impossible));
        method.instructions.add(new InsnNode(Op.RETURN.code()));
        method.instructions.add(impossible);
        method.instructions.add(new InsnNode(Op.NOP.code()));
        method.instructions.add(new InsnNode(Op.RETURN.code()));
        return extract("fixture/StringGuard", method);
    }

    private static MethodInfo unknownStringEqualityBranchMethod() {
        LabelNode unknown = new LabelNode();
        MethodNode method = new MethodNode(Modifier.PUBLIC | Modifier.STATIC, "guarded",
                "(Ljava/lang/String;)V", null, null);
        method.instructions.add(new VarInsnNode(Op.ALOAD.code(), 0));
        method.instructions.add(new LdcInsnNode("safe"));
        method.instructions.add(new MethodInsnNode(Op.INVOKEVIRTUAL.code(), "java/lang/String",
                "equals", "(Ljava/lang/Object;)Z", false));
        method.instructions.add(new JumpInsnNode(Op.IFEQ.code(), unknown));
        method.instructions.add(new InsnNode(Op.RETURN.code()));
        method.instructions.add(unknown);
        method.instructions.add(new InsnNode(Op.NOP.code()));
        method.instructions.add(new InsnNode(Op.RETURN.code()));
        return extract("fixture/StringGuard", method);
    }

    private static MethodInfo backwardLoopBranchMethod() {
        LabelNode loop = new LabelNode();
        LabelNode sink = new LabelNode();
        MethodNode method = new MethodNode(Modifier.PUBLIC | Modifier.STATIC, "loopGuard",
                "(Z)V", null, null);
        method.instructions.add(new JumpInsnNode(Op.GOTO.code(), loop));
        method.instructions.add(loop);
        method.instructions.add(new VarInsnNode(Op.ILOAD.code(), 0));
        method.instructions.add(new JumpInsnNode(Op.IFNE.code(), sink));
        method.instructions.add(new JumpInsnNode(Op.GOTO.code(), loop));
        method.instructions.add(sink);
        method.instructions.add(new InsnNode(Op.NOP.code()));
        method.instructions.add(new InsnNode(Op.RETURN.code()));
        return extract("fixture/LoopGuard", method);
    }

    private static OriginSupport supportFor(MethodInfo method) {
        ClassInfo host = new ClassInfo(method.owner(), "java/lang/Object", List.of(), Modifier.PUBLIC,
                List.of(method), List.of());
        LoadResult load = new LoadResult(Map.of(host.internalName(), host), List.of(), 1, 61);
        BuiltCpg cpg = new CpgBuilder().build(load);
        cpg.graph().freeze();
        ClassHierarchy hierarchy = new ClassHierarchy(load.classes(), null);
        return new OriginSupport(cpg.graph(), hierarchy,
                new RuleEngine(RuleSet.EMPTY, hierarchy), false, cpg.index());
    }

    private static MethodInfo emptyMethod(String owner, String name, String descriptor, int access) {
        return new MethodInfo(owner, name, descriptor, access, List.of(), List.of(), false);
    }

    private static MethodInfo extract(MethodNode method) {
        return extract("fixture/Host", method);
    }

    private static MethodInfo extract(String owner, MethodNode method) {
        ClassNode node = new ClassNode();
        node.name = owner;
        node.superName = "java/lang/Object";
        node.methods.add(method);
        return new FactsExtractor().extract(node).methods().get(0);
    }

    private static void addReflectiveInvoke(MethodNode method) {
        method.instructions.add(new InsnNode(Op.ACONST_NULL.code()));
        method.instructions.add(new InsnNode(Op.ACONST_NULL.code()));
        method.instructions.add(new InsnNode(Op.ACONST_NULL.code()));
        method.instructions.add(new MethodInsnNode(Op.INVOKEVIRTUAL.code(),
                "java/lang/reflect/Method", "invoke",
                "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false));
        method.instructions.add(new InsnNode(Op.POP.code()));
    }
}
