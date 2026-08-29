package io.just.sast.frontend.asm;

import io.just.sast.model.ClassInfo;
import io.just.sast.model.FieldInfo;
import io.just.sast.model.FieldRef;
import io.just.sast.model.HandleRef;
import io.just.sast.model.InsnFact;
import io.just.sast.model.InvokeDynamicRef;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.MethodRef;
import io.just.sast.model.Op;
import io.just.sast.model.SwitchCase;
import io.just.sast.model.SwitchRef;
import io.just.sast.model.TryCatchFact;
import io.just.sast.model.TypeRef;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.MultiANewArrayInsnNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** ASM ClassNode → 自研 model。本类是 ASM 与内部模型的唯一边界。 */
public final class FactsExtractor {

    public ClassInfo extract(ClassNode node) {
        List<MethodInfo> methods = new ArrayList<>(node.methods.size());
        for (MethodNode m : node.methods) {
            methods.add(extractMethod(node.name, m));
        }
        List<FieldInfo> fields = new ArrayList<>(node.fields.size());
        for (FieldNode f : node.fields) {
            fields.add(new FieldInfo(node.name, f.name, f.desc, f.access, f.value));
        }
        return new ClassInfo(node.name, node.superName, List.copyOf(node.interfaces),
                node.access, List.copyOf(methods), List.copyOf(fields));
    }

    private MethodInfo extractMethod(String owner, MethodNode m) {
        // 第一遍：给 label 分配偏移（偏移 = 该 label 处下一个指令的下标），统计调试信息
        Map<LabelNode, Integer> labelOffsets = new HashMap<>();
        List<AbstractInsnNode> insns = new ArrayList<>();
        boolean hasDebug = false;
        int firstLine = -1;
        for (AbstractInsnNode insn = m.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn.getType() == AbstractInsnNode.LABEL) {
                labelOffsets.put((LabelNode) insn, insns.size());
            } else if (insn.getType() == AbstractInsnNode.LINE) {
                hasDebug = true; // 不计入偏移
                if (firstLine < 0) {
                    firstLine = ((LineNumberNode) insn).line;
                }
            } else if (insn.getType() == AbstractInsnNode.FRAME) {
                // 不计入偏移
            } else {
                insns.add(insn);
            }
        }

        List<InsnFact> facts = new ArrayList<>(insns.size());
        for (int i = 0; i < insns.size(); i++) {
            AbstractInsnNode insn = insns.get(i);
            Op op = Op.fromCode(insn.getOpcode());
            facts.add(new InsnFact(i, op, operands(insn, labelOffsets)));
        }

        List<TryCatchFact> tryCatch = new ArrayList<>(m.tryCatchBlocks.size());
        for (TryCatchBlockNode tc : m.tryCatchBlocks) {
            tryCatch.add(new TryCatchFact(
                    labelOffset(labelOffsets, tc.start),
                    labelOffset(labelOffsets, tc.end),
                    labelOffset(labelOffsets, tc.handler),
                    tc.type));
        }
        return new MethodInfo(owner, m.name, m.desc, m.access, List.copyOf(facts),
                List.copyOf(tryCatch), hasDebug, firstLine);
    }

    /** label 引用缺失说明指令序列异常——解析失败计入诊断，绝不静默生成指向 offset 0 的假边。 */
    private static int labelOffset(Map<LabelNode, Integer> labelOffsets, LabelNode label) {
        Integer offset = labelOffsets.get(label);
        if (offset == null) {
            throw new IllegalStateException("label 未注册: " + label);
        }
        return offset;
    }

    private List<Object> operands(AbstractInsnNode insn, Map<LabelNode, Integer> labelOffsets) {
        switch (insn.getType()) {
            case AbstractInsnNode.VAR_INSN:
                return List.of(((VarInsnNode) insn).var);
            case AbstractInsnNode.INT_INSN:
                return List.of(((IntInsnNode) insn).operand);
            case AbstractInsnNode.IINC_INSN:
                IincInsnNode iinc = (IincInsnNode) insn;
                return List.of(iinc.var, iinc.incr);
            case AbstractInsnNode.LDC_INSN:
                return List.of(mapConstant(((LdcInsnNode) insn).cst));
            case AbstractInsnNode.METHOD_INSN: {
                MethodInsnNode m = (MethodInsnNode) insn;
                return List.of(new MethodRef(m.owner, m.name, m.desc));
            }
            case AbstractInsnNode.FIELD_INSN: {
                FieldInsnNode f = (FieldInsnNode) insn;
                return List.of(new FieldRef(f.owner, f.name, f.desc));
            }
            case AbstractInsnNode.TYPE_INSN:
                return List.of(new TypeRef(((TypeInsnNode) insn).desc));
            case AbstractInsnNode.JUMP_INSN:
                return List.of(labelOffset(labelOffsets, ((JumpInsnNode) insn).label));
            case AbstractInsnNode.TABLESWITCH_INSN: {
                TableSwitchInsnNode sw = (TableSwitchInsnNode) insn;
                List<SwitchCase> cases = new ArrayList<>(sw.labels.size());
                for (int i = 0; i < sw.labels.size(); i++) {
                    cases.add(new SwitchCase(sw.min + i, labelOffset(labelOffsets, sw.labels.get(i))));
                }
                return List.of(new SwitchRef(List.copyOf(cases),
                        labelOffset(labelOffsets, sw.dflt)));
            }
            case AbstractInsnNode.LOOKUPSWITCH_INSN: {
                LookupSwitchInsnNode sw = (LookupSwitchInsnNode) insn;
                List<SwitchCase> cases = new ArrayList<>(sw.keys.size());
                for (int i = 0; i < sw.keys.size(); i++) {
                    cases.add(new SwitchCase(sw.keys.get(i), labelOffset(labelOffsets, sw.labels.get(i))));
                }
                return List.of(new SwitchRef(List.copyOf(cases),
                        labelOffset(labelOffsets, sw.dflt)));
            }
            case AbstractInsnNode.INVOKE_DYNAMIC_INSN: {
                InvokeDynamicInsnNode indy = (InvokeDynamicInsnNode) insn;
                Handle bsm = indy.bsm;
                HandleRef bsmRef = new HandleRef(bsm.getTag(), bsm.getOwner(), bsm.getName(), bsm.getDesc());
                List<Object> args = new ArrayList<>(indy.bsmArgs.length);
                for (Object arg : indy.bsmArgs) {
                    args.add(mapConstant(arg));
                }
                return List.of(new InvokeDynamicRef(indy.name, indy.desc, bsmRef, List.copyOf(args)));
            }
            case AbstractInsnNode.MULTIANEWARRAY_INSN: {
                MultiANewArrayInsnNode m = (MultiANewArrayInsnNode) insn;
                return List.of(new TypeRef(m.desc), m.dims);
            }
            default:
                return List.of();
        }
    }

    private Object mapConstant(Object cst) {
        if (cst instanceof Type t) {
            return new TypeRef(t.getDescriptor());
        }
        if (cst instanceof Handle h) {
            return new HandleRef(h.getTag(), h.getOwner(), h.getName(), h.getDesc());
        }
        if (cst instanceof org.objectweb.asm.ConstantDynamic dyn) {
            return dyn.getName(); // 简化：仅保留名称
        }
        return cst; // String / Integer / Long / Float / Double
    }
}
