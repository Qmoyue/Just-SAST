package io.just.sast.cpg.build;

import io.just.sast.cpg.graph.Graph;
import io.just.sast.cpg.graph.Node;
import io.just.sast.frontend.asm.FactsExtractor;
import io.just.sast.model.ArtifactProvenance;
import io.just.sast.model.ClassForNameCallSite;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.HessianProxyFactoryCallSite;
import io.just.sast.model.HessianReferenceProxyConstraint;
import io.just.sast.model.JndiReferenceFact;
import io.just.sast.model.LoadResult;
import io.just.sast.model.MethodId;
import io.just.sast.model.ProgramUniverse;
import io.just.sast.model.ProxyCreationCallSite;
import io.just.sast.model.TypedBridgeFact;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HessianReferenceProxyContractTest {

    @Test
    void exactReferenceTypeAndUrlReachHessianProxyCreation() {
        Fixture fixture = fixture();
        HessianReferenceProxyConstraint constraint = connect(fixture,
                fixture.reference(), fixture.proxyCreation());

        assertTrue(constraint.proved());
        assertEquals(HessianReferenceProxyConstraint.Status.PROVED, constraint.status());
        assertEquals(HessianReferenceProxyConstraint.Reason.NONE, constraint.reason());
        assertEquals(1, constraint.typeAddresses().size());
        assertEquals(1, constraint.urlAddresses().size());
        assertTrue(constraint.typeBridge().orElseThrow().proved());
        assertTrue(constraint.classBridge().orElseThrow().proved());
        assertTrue(constraint.urlBridge().orElseThrow().proved());
        assertEquals("fixture.Api", constraint.typeAddress().orElseThrow().content().value());
        assertEquals("http://example.invalid/hessian",
                constraint.urlAddress().orElseThrow().content().value());
        assertEquals(HessianProxyFactoryCallSite.CREATE_DESCRIPTOR,
                constraint.createCallSite().callSite().calleeDescriptor());
        assertEquals("create", constraint.proxyCreation().callSite().hostMethod().name());
        assertTrue(constraint.identity().contains("hessian-reference-proxy-v1|"));
    }

    @Test
    void cpgPublishesExactHessianCreateCallAndProxyFacts() {
        Fixture fixture = fixture();
        Node create = fixture.graph().callsOfMethod(fixture.factoryGetObjectKey()).stream()
                .filter(node -> HessianProxyFactoryCallSite.OWNER.equals(node.owner())
                        && HessianProxyFactoryCallSite.CREATE_NAME.equals(node.name()))
                .findFirst().orElseThrow();
        HessianProxyFactoryCallSite createFact = (HessianProxyFactoryCallSite) create.note(
                HessianProxyFactoryCallSite.GRAPH_NOTE_KEY);
        assertNotNull(createFact);
        assertEquals(HessianProxyFactoryCallSite.CREATE_DESCRIPTOR,
                createFact.callSite().calleeDescriptor());
        assertEquals(TypedBridgeFact.Slot.Position.ARGUMENT,
                createFact.apiSlot().position());
        assertEquals(1, createFact.urlSlot().ordinal());
        assertEquals(ProxyCreationCallSite.Status.PROVED, fixture.proxyCreation().status());
    }

    @Test
    void duplicateTypeAddressCannotChooseOneCandidate() {
        Fixture fixture = fixture();
        List<JndiReferenceFact.RefAddrFact> addresses = new ArrayList<>(
                fixture.reference().addresses());
        addresses.add(fixture.typeAddress());
        JndiReferenceFact duplicate = new JndiReferenceFact(fixture.reference().identity(),
                fixture.reference().type(), fixture.reference().factoryClass(),
                fixture.reference().factoryLocation(), addresses);

        HessianReferenceProxyConstraint constraint = connect(fixture, duplicate,
                fixture.proxyCreation());

        assertEquals(HessianReferenceProxyConstraint.Status.UNKNOWN, constraint.status());
        assertEquals(HessianReferenceProxyConstraint.Reason.TYPE_ADDRESS_AMBIGUOUS,
                constraint.reason());
        assertFalse(constraint.proved());
    }

    @Test
    void missingOrUnknownUrlRemainsPartial() {
        Fixture fixture = fixture();
        JndiReferenceFact missingUrl = new JndiReferenceFact(fixture.reference().identity(),
                fixture.reference().type(), fixture.reference().factoryClass(),
                fixture.reference().factoryLocation(), List.of(fixture.typeAddress()));
        HessianReferenceProxyConstraint missing = connect(fixture, missingUrl,
                fixture.proxyCreation());

        assertEquals(HessianReferenceProxyConstraint.Status.PARTIAL, missing.status());
        assertEquals(HessianReferenceProxyConstraint.Reason.URL_ADDRESS_MISSING,
                missing.reason());

        JndiReferenceFact.RefAddrFact unknownUrl = new JndiReferenceFact.RefAddrFact(
                fixture.urlAddress().identity(), fixture.urlAddress().type(),
                JndiReferenceFact.FieldValue.unknown());
        JndiReferenceFact unknown = new JndiReferenceFact(fixture.reference().identity(),
                fixture.reference().type(), fixture.reference().factoryClass(),
                fixture.reference().factoryLocation(), List.of(fixture.typeAddress(), unknownUrl));
        HessianReferenceProxyConstraint unknownConstraint = connect(fixture, unknown,
                fixture.proxyCreation());

        assertEquals(HessianReferenceProxyConstraint.Status.PARTIAL,
                unknownConstraint.status());
        assertEquals(HessianReferenceProxyConstraint.Reason.URL_VALUE_UNKNOWN,
                unknownConstraint.reason());
    }

    @Test
    void wrongFactoryClassDoesNotBecomeHessianFlow() {
        Fixture fixture = fixture();
        JndiReferenceFact wrongFactory = new JndiReferenceFact(fixture.reference().identity(),
                fixture.reference().type(), JndiReferenceFact.FieldValue.known("fixture.Other"),
                fixture.reference().factoryLocation(), fixture.reference().addresses());

        HessianReferenceProxyConstraint constraint = connect(fixture, wrongFactory,
                fixture.proxyCreation());

        assertEquals(HessianReferenceProxyConstraint.Status.UNKNOWN, constraint.status());
        assertEquals(HessianReferenceProxyConstraint.Reason.FACTORY_CLASS_MISMATCH,
                constraint.reason());
    }

    @Test
    void equalClassValueWithDifferentPhysicalIdentityIsUnknown() {
        Fixture fixture = fixture();
        TypedBridgeFact.Endpoint createApi = new TypedBridgeFact.Endpoint(
                new TypedBridgeFact.FlowIdentity("different-api-identity"),
                fixture.createFact().callSite(),
                HessianProxyFactoryCallSite.API_SLOT, fixture.classType(), fixture.factoryArtifact());
        HessianReferenceProxyConstraint constraint = connect(fixture,
                fixture.reference(), fixture.proxyCreation(), createApi);

        assertEquals(HessianReferenceProxyConstraint.Status.UNKNOWN, constraint.status());
        assertEquals(HessianReferenceProxyConstraint.Reason.CLASS_BRIDGE_UNKNOWN,
                constraint.reason());
        assertNotEquals(fixture.classIdentity(), createApi.identity().value());
    }

    @Test
    void partialProxyCreationKeepsConstraintPartial() {
        Fixture fixture = fixture();
        ProxyCreationCallSite partial = ProxyCreationCallSite.withValues(
                fixture.proxyCreation().callSite(), fixture.proxyCreation().classLoader(),
                ProxyCreationCallSite.InterfaceSet.unknown(
                        new TypedBridgeFact.FlowIdentity("unknown-interface-set"), 10),
                fixture.proxyCreation().handler(), fixture.proxyCreation().proxy());

        HessianReferenceProxyConstraint constraint = connect(fixture, fixture.reference(), partial);

        assertEquals(HessianReferenceProxyConstraint.Status.PARTIAL, constraint.status());
        assertEquals(HessianReferenceProxyConstraint.Reason.PROXY_CREATION_INCOMPLETE,
                constraint.reason());
        assertTrue(constraint.typeBridge().orElseThrow().proved());
        assertTrue(constraint.urlBridge().orElseThrow().proved());
    }

    @Test
    void wrongHessianCreateOwnerOrOverloadIsNotAnExactFact() {
        Fixture fixture = fixture();
        assertTrue(HessianProxyFactoryCallSite.fromCall(
                fixture.createNode().id(), fixture.factoryGetObjectMethod(),
                fixture.createNode().offset(), "fixture/OtherFactory", "create",
                HessianProxyFactoryCallSite.CREATE_DESCRIPTOR, "VIRTUAL").isEmpty());
        assertTrue(HessianProxyFactoryCallSite.fromCall(
                fixture.createNode().id(), fixture.factoryGetObjectMethod(),
                fixture.createNode().offset(), HessianProxyFactoryCallSite.OWNER, "create",
                "(Ljava/lang/Class;)Ljava/lang/Object;", "VIRTUAL").isEmpty());
        assertTrue(ClassForNameCallSite.fromCall(fixture.classForNameNode().id(),
                fixture.factoryGetObjectMethod(), fixture.classForNameNode().offset(),
                ClassForNameCallSite.OWNER, ClassForNameCallSite.NAME,
                "(Ljava/lang/String;Z)Ljava/lang/Class;", "STATIC").isEmpty());
    }

    private static HessianReferenceProxyConstraint connect(Fixture fixture,
                                                            JndiReferenceFact reference,
                                                            ProxyCreationCallSite proxy) {
        return connect(fixture, reference, proxy, fixture.createApiEndpoint());
    }

    private static HessianReferenceProxyConstraint connect(Fixture fixture,
                                                            JndiReferenceFact reference,
                                                            ProxyCreationCallSite proxy,
                                                            TypedBridgeFact.Endpoint createApi) {
        TypedBridgeFact.Endpoint typeContent = refAddrContentEndpoint(
                reference.addresses().stream()
                        .filter(address -> address.identity().equals(fixture.typeAddress().identity()))
                        .findFirst().orElse(fixture.typeAddress()), fixture.callerMethod(),
                fixture.applicationArtifact());
        TypedBridgeFact.Endpoint urlContent = refAddrContentEndpoint(
                reference.addresses().stream()
                        .filter(address -> address.identity().equals(fixture.urlAddress().identity()))
                        .findFirst().orElse(fixture.urlAddress()), fixture.callerMethod(),
                fixture.applicationArtifact());
        TypedBridgeFact.Endpoint className = new TypedBridgeFact.Endpoint(
                new TypedBridgeFact.FlowIdentity(fixture.classIdentity()),
                fixture.classForNameFact().callSite(), ClassForNameCallSite.ARGUMENT_SLOT,
                TypeIdHolder.STRING, fixture.factoryArtifact());
        TypedBridgeFact.Endpoint classResult = new TypedBridgeFact.Endpoint(
                new TypedBridgeFact.FlowIdentity(fixture.classIdentity()),
                fixture.classForNameFact().callSite(), ClassForNameCallSite.RESULT_SLOT,
                TypeIdHolder.CLASS, fixture.factoryArtifact());
        TypedBridgeFact.Endpoint createUrl = new TypedBridgeFact.Endpoint(
                new TypedBridgeFact.FlowIdentity("create-url"), fixture.createFact().callSite(),
                HessianProxyFactoryCallSite.URL_SLOT, TypeIdHolder.STRING,
                fixture.factoryArtifact());
        return HessianReferenceProxyConstraint.connect(reference, fixture.classForNameFact(),
                typeContent, className, classResult, fixture.createFact(), createApi, urlContent,
                createUrl, proxy);
    }

    private static TypedBridgeFact.Endpoint refAddrContentEndpoint(
            JndiReferenceFact.RefAddrFact address, MethodId host, ArtifactProvenance artifact) {
        TypedBridgeFact.CallSite call = new TypedBridgeFact.CallSite(
                address.identity().constructionCallId(), host,
                address.identity().constructionOffset(), JndiReferenceFact.STRING_REF_ADDR_OWNER,
                "<init>", JndiReferenceFact.STRING_REF_ADDR_CONSTRUCTOR_DESCRIPTOR,
                TypedBridgeFact.InvokeKind.SPECIAL);
        return new TypedBridgeFact.Endpoint(new TypedBridgeFact.FlowIdentity(
                address.identity().identity() + "|content"), call,
                TypedBridgeFact.Slot.argument(1, "Ljava/lang/String;"), TypeIdHolder.STRING,
                artifact);
    }

    private static Fixture fixture() {
        ClassInfo caller = extract(callerBytes());
        ClassInfo factory = extract(factoryBytes());
        LoadResult load = new LoadResult(Map.of(caller.internalName(), caller,
                factory.internalName(), factory), List.of(), 2, 61);
        ArtifactProvenance application = new ArtifactProvenance("hessian-app.jar",
                ArtifactProvenance.Role.APPLICATION, "A".repeat(64), 1200L);
        ArtifactProvenance dependency = new ArtifactProvenance("hessian.jar",
                ArtifactProvenance.Role.DEPENDENCY, "B".repeat(64), 2400L);
        ProgramUniverse universe = ProgramUniverse.of(load,
                Map.of(caller.internalName(), application, factory.internalName(), dependency),
                List.of(application, dependency));
        Graph graph = new CpgBuilder().build(universe).graph();

        String callerKey = caller.internalName() + "#build()Ljavax/naming/Reference;";
        String getObjectKey = factory.internalName() + "#getObjectInstance"
                + HessianReferenceProxyConstraint.GET_OBJECT_INSTANCE_DESCRIPTOR;
        String createKey = factory.internalName() + "#create"
                + HessianReferenceProxyConstraint.PROXY_CREATE_DESCRIPTOR;
        Node referenceConstructor = graph.callsOfMethod(callerKey).stream()
                .filter(node -> JndiReferenceFact.REFERENCE_OWNER.equals(node.owner())
                        && "<init>".equals(node.name())
                        && JndiReferenceFact.REFERENCE_CONSTRUCTOR_FACTORY_DESCRIPTOR
                        .equals(node.descriptor()))
                .findFirst().orElseThrow();
        JndiReferenceFact reference = (JndiReferenceFact) referenceConstructor.note(
                JndiReferenceFact.GRAPH_NOTE_KEY);
        Node classForName = graph.callsOfMethod(getObjectKey).stream()
                .filter(node -> ClassForNameCallSite.OWNER.equals(node.owner())
                        && ClassForNameCallSite.NAME.equals(node.name()))
                .findFirst().orElseThrow();
        Node create = graph.callsOfMethod(getObjectKey).stream()
                .filter(node -> HessianProxyFactoryCallSite.OWNER.equals(node.owner())
                        && HessianProxyFactoryCallSite.CREATE_NAME.equals(node.name()))
                .findFirst().orElseThrow();
        Node proxy = graph.callsOfMethod(createKey).stream()
                .filter(node -> ProxyCreationCallSite.OWNER.equals(node.owner())
                        && ProxyCreationCallSite.NAME.equals(node.name()))
                .findFirst().orElseThrow();
        ClassForNameCallSite classForNameFact = (ClassForNameCallSite) classForName.note(
                ClassForNameCallSite.GRAPH_NOTE_KEY);
        HessianProxyFactoryCallSite createFact = (HessianProxyFactoryCallSite) create.note(
                HessianProxyFactoryCallSite.GRAPH_NOTE_KEY);
        ProxyCreationCallSite proxyFact = (ProxyCreationCallSite) proxy.note(
                ProxyCreationCallSite.GRAPH_NOTE_KEY);
        assertNotNull(reference);
        assertNotNull(classForNameFact);
        assertNotNull(createFact);
        assertNotNull(proxyFact);
        return new Fixture(graph, callerKey, getObjectKey, caller,
                MethodId.of(factory.internalName(), "getObjectInstance",
                        HessianReferenceProxyConstraint.GET_OBJECT_INSTANCE_DESCRIPTOR),
                MethodId.of(caller.internalName(), "build",
                        "()Ljavax/naming/Reference;"), reference, classForName,
                classForNameFact, create, createFact, proxyFact, application, dependency);
    }

    private static ClassInfo extract(byte[] bytes) {
        org.objectweb.asm.tree.ClassNode node = new org.objectweb.asm.tree.ClassNode();
        new ClassReader(bytes).accept(node, 0);
        return new FactsExtractor().extract(node);
    }

    private static byte[] callerBytes() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "fixture/HessianReferenceHost", null,
                "java/lang/Object", null);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "build", "()Ljavax/naming/Reference;", null, null);
        method.visitCode();
        method.visitTypeInsn(Opcodes.NEW, JndiReferenceFact.REFERENCE_OWNER);
        method.visitInsn(Opcodes.DUP);
        method.visitLdcInsn("test");
        method.visitLdcInsn("com.caucho.hessian.client.HessianProxyFactory");
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitMethodInsn(Opcodes.INVOKESPECIAL, JndiReferenceFact.REFERENCE_OWNER,
                "<init>", JndiReferenceFact.REFERENCE_CONSTRUCTOR_FACTORY_DESCRIPTOR, false);
        method.visitVarInsn(Opcodes.ASTORE, 0);

        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitTypeInsn(Opcodes.NEW, JndiReferenceFact.STRING_REF_ADDR_OWNER);
        method.visitInsn(Opcodes.DUP);
        method.visitLdcInsn("type");
        method.visitLdcInsn("fixture.Api");
        method.visitMethodInsn(Opcodes.INVOKESPECIAL, JndiReferenceFact.STRING_REF_ADDR_OWNER,
                "<init>", JndiReferenceFact.STRING_REF_ADDR_CONSTRUCTOR_DESCRIPTOR, false);
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, JndiReferenceFact.REFERENCE_OWNER, "add",
                "(L" + JndiReferenceFact.REF_ADDR_OWNER + ";)V", false);

        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitTypeInsn(Opcodes.NEW, JndiReferenceFact.STRING_REF_ADDR_OWNER);
        method.visitInsn(Opcodes.DUP);
        method.visitLdcInsn("url");
        method.visitLdcInsn("http://example.invalid/hessian");
        method.visitMethodInsn(Opcodes.INVOKESPECIAL, JndiReferenceFact.STRING_REF_ADDR_OWNER,
                "<init>", JndiReferenceFact.STRING_REF_ADDR_CONSTRUCTOR_DESCRIPTOR, false);
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, JndiReferenceFact.REFERENCE_OWNER, "add",
                "(L" + JndiReferenceFact.REF_ADDR_OWNER + ";)V", false);
        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitInsn(Opcodes.ARETURN);
        method.visitMaxs(6, 1);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] factoryBytes() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC,
                HessianProxyFactoryCallSite.OWNER, null, "java/lang/Object", null);

        MethodVisitor getObject = writer.visitMethod(Opcodes.ACC_PUBLIC,
                "getObjectInstance", HessianReferenceProxyConstraint.GET_OBJECT_INSTANCE_DESCRIPTOR,
                null, null);
        getObject.visitCode();
        getObject.visitLdcInsn("fixture.Api");
        getObject.visitMethodInsn(Opcodes.INVOKESTATIC, ClassForNameCallSite.OWNER,
                ClassForNameCallSite.NAME, ClassForNameCallSite.DESCRIPTOR, false);
        getObject.visitVarInsn(Opcodes.ASTORE, 5);
        getObject.visitVarInsn(Opcodes.ALOAD, 0);
        getObject.visitVarInsn(Opcodes.ALOAD, 5);
        getObject.visitLdcInsn("http://example.invalid/hessian");
        getObject.visitMethodInsn(Opcodes.INVOKEVIRTUAL, HessianProxyFactoryCallSite.OWNER,
                HessianProxyFactoryCallSite.CREATE_NAME,
                HessianProxyFactoryCallSite.CREATE_DESCRIPTOR, false);
        getObject.visitInsn(Opcodes.ARETURN);
        getObject.visitMaxs(3, 6);
        getObject.visitEnd();

        MethodVisitor create = writer.visitMethod(Opcodes.ACC_PUBLIC,
                "create", HessianReferenceProxyConstraint.PROXY_CREATE_DESCRIPTOR, null, null);
        create.visitCode();
        create.visitVarInsn(Opcodes.ALOAD, 3);
        create.visitInsn(Opcodes.ICONST_2);
        create.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Class");
        create.visitInsn(Opcodes.DUP);
        create.visitInsn(Opcodes.ICONST_0);
        create.visitLdcInsn(Type.getObjectType("fixture/Api"));
        create.visitInsn(Opcodes.AASTORE);
        create.visitInsn(Opcodes.DUP);
        create.visitInsn(Opcodes.ICONST_1);
        create.visitLdcInsn(Type.getObjectType("com/caucho/hessian/io/HessianRemoteObject"));
        create.visitInsn(Opcodes.AASTORE);
        create.visitTypeInsn(Opcodes.NEW, "fixture/Handler");
        create.visitInsn(Opcodes.DUP);
        create.visitMethodInsn(Opcodes.INVOKESPECIAL, "fixture/Handler", "<init>", "()V",
                false);
        create.visitMethodInsn(Opcodes.INVOKESTATIC, ProxyCreationCallSite.OWNER,
                ProxyCreationCallSite.NAME, ProxyCreationCallSite.DESCRIPTOR, false);
        create.visitInsn(Opcodes.ARETURN);
        create.visitMaxs(8, 4);
        create.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static final class TypeIdHolder {
        private static final io.just.sast.model.TypeId STRING =
                io.just.sast.model.TypeId.of("java/lang/String");
        private static final io.just.sast.model.TypeId CLASS =
                io.just.sast.model.TypeId.of("java/lang/Class");
    }

    private record Fixture(
            Graph graph,
            String callerKey,
            String factoryGetObjectKey,
            ClassInfo caller,
            MethodId factoryGetObjectMethod,
            MethodId callerMethod,
            JndiReferenceFact reference,
            Node classForNameNode,
            ClassForNameCallSite classForNameFact,
            Node createNode,
            HessianProxyFactoryCallSite createFact,
            ProxyCreationCallSite proxyCreation,
            ArtifactProvenance applicationArtifact,
            ArtifactProvenance factoryArtifact) {

        private JndiReferenceFact.RefAddrFact typeAddress() {
            return reference.addresses().stream()
                    .filter(address -> address.type().isKnown()
                            && "type".equals(address.type().value()))
                    .findFirst().orElseThrow();
        }

        private JndiReferenceFact.RefAddrFact urlAddress() {
            return reference.addresses().stream()
                    .filter(address -> address.type().isKnown()
                            && "url".equals(address.type().value()))
                    .findFirst().orElseThrow();
        }

        private String classIdentity() {
            return "api-class-value";
        }

        private io.just.sast.model.TypeId classType() {
            return TypeIdHolder.CLASS;
        }

        private TypedBridgeFact.Endpoint createApiEndpoint() {
            return new TypedBridgeFact.Endpoint(new TypedBridgeFact.FlowIdentity(classIdentity()),
                    createFact.callSite(),
                    HessianProxyFactoryCallSite.API_SLOT, classType(), factoryArtifact);
        }

    }
}
