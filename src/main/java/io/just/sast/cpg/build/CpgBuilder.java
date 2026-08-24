package io.just.sast.cpg.build;

import io.just.sast.cpg.graph.Graph;
import io.just.sast.cpg.graph.NodeType;
import io.just.sast.model.LoadResult;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.FieldRef;
import io.just.sast.model.InsnFact;
import io.just.sast.model.InvokeDynamicRef;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.MethodRef;
import io.just.sast.model.Op;

import java.util.HashMap;
import java.util.Map;

/** CPG 构建：METHOD 节点 + CALL 节点（含调用事实），收集字段写入索引。 */
public final class CpgBuilder {

    public BuiltCpg build(LoadResult load) {
        Graph graph = new Graph();
        FieldWriterIndex fieldWriters = new FieldWriterIndex();
        for (ClassInfo cls : load.classes().values()) {
            for (MethodInfo method : cls.methods()) {
                graph.methodNode(method.owner(), method.name(), method.descriptor(), false);
                for (InsnFact insn : method.instructions()) {
                    Op op = insn.op();
                    if (op.isInvoke()) {
                        graph.addNode(NodeType.CALL, callProps(insn, cls.internalName(), method));
                    } else if (op.isFieldWrite()) {
                        FieldRef ref = insn.fieldRef();
                        fieldWriters.add(ref.owner(), ref.name(), cls.internalName(),
                                method.owner(), method.name(), method.descriptor(),
                                insn.offset(), op == Op.PUTSTATIC);
                    } else if (op == Op.AASTORE && insn.offset() >= 3) {
                        // 数组字段写入（窗口近似）：javac 规范形态 [.. GETFIELD f][idx][value][AASTORE]
                        // ——GETFIELD 恰在 AASTORE 前 3 条。c.f[i]=v 的污点经字段粒度回溯（反向引擎）。
                        InsnFact arrayField = method.instructions().get(insn.offset() - 3);
                        if (arrayField.op() == Op.GETFIELD) {
                            FieldRef ref = arrayField.fieldRef();
                            fieldWriters.add(ref.owner(), ref.name(), cls.internalName(),
                                    method.owner(), method.name(), method.descriptor(),
                                    insn.offset(), false);
                        }
                    }
                }
            }
        }
        return new BuiltCpg(graph, fieldWriters);
    }

    private static Map<String, Object> callProps(InsnFact insn, String clsName, MethodInfo enclosing) {
        Map<String, Object> props = new HashMap<>();
        if (insn.op() == Op.INVOKEDYNAMIC) {
            InvokeDynamicRef indy = (InvokeDynamicRef) insn.operands().get(0);
            props.put("owner", indy.bootstrap().owner());
            props.put("name", indy.name());
            props.put("desc", indy.descriptor());
            props.put("invokeKind", "DYNAMIC");
            props.put("indy", indy);
        } else {
            MethodRef ref = insn.methodRef();
            props.put("owner", ref.owner());
            props.put("name", ref.name());
            props.put("desc", ref.descriptor());
            props.put("invokeKind", kindOf(insn.op()));
        }
        props.put("offset", insn.offset());
        props.put("methodOwner", enclosing.owner());
        props.put("methodName", enclosing.name());
        props.put("methodDesc", enclosing.descriptor());
        return props;
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
}
