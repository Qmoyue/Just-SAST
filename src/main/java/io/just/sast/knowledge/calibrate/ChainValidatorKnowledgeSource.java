package io.just.sast.knowledge.calibrate;

import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.KnowledgeSource;
import io.just.sast.blackboard.Phase;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.Descriptor;
import io.just.sast.model.FieldInfo;
import io.just.sast.util.JustLogger;

import java.lang.reflect.Modifier;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

/**
 * 链校验知识源（CALIBRATION 阶段）。
 * 三层校验均保守——只拒绝可证明不可能的链：
 * 1. 可行性：字段声明存在 / 方法可解析
 * 2. 类型流：来源类型（final 精确）与形参类型非子类型关系
 * 3. 序列化可行性：字段声明类型无可序列化子类闭包
 */
public final class ChainValidatorKnowledgeSource implements KnowledgeSource {

    private Blackboard bb;
    // 序列化可行性缓存
    private final java.util.Map<String, Boolean> serializablePossible = new HashMap<>();

    @Override
    public String id() {
        return "chain-validator";
    }

    @Override
    public Set<EventType> interests() {
        return Set.of(EventType.SCAN_COMPLETE);
    }

    @Override
    public Phase phase() {
        return Phase.CALIBRATION;
    }

    @Override
    public int priority() {
        return 100;
    }

    @Override
    public void init(Blackboard blackboard) {
        this.bb = blackboard;
    }

    @Override
    public void onEvent(Blackboard bb, Event event) {
        if (event.type() != EventType.SCAN_COMPLETE) {
            return;
        }
        int pasm = 0;
        int typeflow = 0;
        int serialize = 0;
        int guardDegrade = 0;
        int constraintReject = 0;
        for (Chain chain : bb.chains()) {
            // 1. PASM 可行性
            String reason = pasmReject(chain);
            if (reason != null) {
                bb.calibrateChain(chain.key(), reason);
                pasm++;
                continue;
            }
            // 2. 类型流
            reason = typeflowReject(chain);
            if (reason != null) {
                bb.calibrateChain(chain.key(), reason);
                typeflow++;
                continue;
            }
            // 3. 序列化可行性
            reason = serializeReject(chain);
            if (reason != null) {
                bb.calibrateChain(chain.key(), reason);
                serialize++;
                continue;
            }
            // 4. equals 卫式降级（V4：不删链，标注降级——JDD 别名分析的最小子集）
            if (equalsGuardConflict(chain)) {
                bb.chainNote(chain.key(), "degrade:guard-equals");
                guardDegrade++;
            }
            // 5. V10-lite 约束图矛盾
            reason = constraintContradiction(chain);
            if (reason != null) {
                bb.calibrateChain(chain.key(), reason);
                constraintReject++;
            }
        }
        JustLogger.info("链校验：PASM 拒绝 {}，类型流拒绝 {}，序列化 {}，卫式 {}，约束 {}（共 {} 条）",
                pasm, typeflow, serialize, guardDegrade, constraintReject, bb.chains().size());
    }

    // ---- 1. PASM 可行性 ----

    private String pasmReject(Chain chain) {
        for (ChainHop hop : chain.hops()) {
            if (hop.kind() == HopKind.ENTRY || hop.kind() == HopKind.LAMBDA) {
                continue;
            }
            if (hop.kind() == HopKind.FIELD_FLOW) {
                String owner = fieldOwnerOf(hop);
                String declaring = bb.hierarchy().resolveField(owner, hop.field());
                if (declaring == null && bb.hierarchy().superclassChainResolvable(owner)) {
                    return "field-not-declared:" + owner + "." + hop.field();
                }
                continue;
            }
            if (hop.desc() == null || hop.desc().isEmpty()) {
                continue;
            }
            if (bb.hierarchy().classInfo(hop.toOwner()) == null) {
                continue;
            }
            if (bb.hierarchy().resolveMethod(hop.toOwner(), hop.toName(), hop.desc()) == null) {
                return "method-not-declared:" + hop.toOwner() + "." + hop.toName() + hop.desc();
            }
        }
        return null;
    }

    // ---- 2. 类型流 ----

    private String typeflowReject(Chain chain) {
        var hops = chain.hops();
        for (int i = 0; i + 1 < hops.size(); i++) {
            ChainHop hop = hops.get(i);
            if (hop.argOrdinal() == null || hop.desc() == null || hop.desc().isEmpty()) {
                continue;
            }
            // Lambda 边界跳（lambda$xxx 实现方法）：类型流不适用——
            // lambda 捕获变量与调用参数的类型关系不遵循普通方法调用规则
            if (hop.toName() != null && hop.toName().startsWith("lambda$")) {
                continue;
            }
            String param = Descriptor.paramType(hop.desc(), hop.argOrdinal());
            if (param == null || !param.startsWith("L")) {
                continue;
            }
            String source = sourceType(hops.get(i + 1), chain);
            if (source == null || !source.startsWith("L")) {
                continue;
            }
            String sourceClass = source.substring(1, source.length() - 1);
            String paramClass = param.substring(1, param.length() - 1);
            var sourceInfo = bb.hierarchy().classInfo(sourceClass);
            var paramInfo = bb.hierarchy().classInfo(paramClass);
            if (sourceInfo == null || paramInfo == null) {
                continue;
            }
            if (!Modifier.isFinal(sourceInfo.access())) {
                // 非 final 也参与（U3 类型传播强化）：双侧可解析且无共同子类（互非子型、
                // 加载子类型闭包无交集、均非接口）→ 值不可能同时是两型
                if (sourceInfo.isInterface() || paramInfo.isInterface()) {
                    continue; // 接口实现开放，不可证
                }
                if (bb.hierarchy().isSubtypeOf(sourceClass, paramClass)
                        || bb.hierarchy().isSubtypeOf(paramClass, sourceClass)) {
                    continue;
                }
                boolean common = false;
                for (String sub : bb.hierarchy().loadedSubtypes(sourceClass)) {
                    if (bb.hierarchy().isSubtypeOf(sub, paramClass)) {
                        common = true;
                        break;
                    }
                }
                if (!common) {
                    return "typeflow:" + sourceClass + "-!->" + paramClass;
                }
                continue;
            }
            if (!bb.hierarchy().isSubtypeOf(sourceClass, paramClass)) {
                return "typeflow:" + sourceClass + "-!->" + paramClass;
            }
        }
        return null;
    }

    private String sourceType(ChainHop hop, Chain chain) {
        if (hop.kind() == HopKind.ENTRY) {
            return "L" + chain.entryClass() + ";";
        }
        if (hop.kind() == HopKind.FIELD_FLOW && hop.field() != null) {
            String declaring = bb.hierarchy().resolveField(fieldOwnerOf(hop), hop.field());
            if (declaring == null) {
                return null;
            }
            ClassInfo cls = bb.hierarchy().classInfo(declaring);
            if (cls == null || cls.field(hop.field()) == null) {
                return null;
            }
            return cls.field(hop.field()).descriptor();
        }
        if (hop.argOrdinal() != null && hop.desc() != null && !hop.desc().isEmpty()) {
            return Descriptor.paramType(hop.desc(), hop.argOrdinal());
        }
        return null;
    }

    // ---- 3. 序列化可行性 ----

    private String serializeReject(Chain chain) {
        for (ChainHop hop : chain.hops()) {
            if (hop.kind() != HopKind.FIELD_FLOW || hop.field() == null) {
                continue;
            }
            String declaring = bb.hierarchy().resolveField(fieldOwnerOf(hop), hop.field());
            if (declaring == null || !bb.hierarchy().isSerializable(declaring)) {
                continue;
            }
            ClassInfo cls = bb.hierarchy().classInfo(declaring);
            FieldInfo field = cls != null ? cls.field(hop.field()) : null;
            if (field == null || !field.descriptor().startsWith("L")) {
                continue;
            }
            String typeClass = field.descriptor().substring(1, field.descriptor().length() - 1);
            if (bb.hierarchy().classInfo(typeClass) == null
                    || bb.hierarchy().classInfo("java/io/Serializable") == null) {
                continue;
            }
            if (!serializableValuePossible(typeClass)) {
                return "non-serializable-field:" + declaring + "." + hop.field() + ":" + typeClass;
            }
        }
        return null;
    }

    /**
     * V10-lite 约束图矛盾：链上 FIELD_FLOW 跳的类型约束沿链传递——
     * 互斥类型对（互非子型且无共同子类）构成矛盾。
     * pairwise typeflow 的链级传递闭包升级（无 Z3 纯 Java）。
     */
    private String constraintContradiction(Chain chain) {
        var hops = chain.hops();
        java.util.List<String[]> constraints = new java.util.ArrayList<>();
        for (int i = 0; i < hops.size(); i++) {
            ChainHop hop = hops.get(i);
            if (hop.kind() != HopKind.FIELD_FLOW || hop.field() == null) {
                continue;
            }
            String declaring = bb.hierarchy().resolveField(fieldOwnerOf(hop), hop.field());
            ClassInfo cls = bb.hierarchy().classInfo(declaring != null ? declaring : fieldOwnerOf(hop));
            FieldInfo field = cls != null ? cls.field(hop.field()) : null;
            if (field == null || !field.descriptor().startsWith("L")) {
                continue;
            }
            String fieldType = field.descriptor().substring(1, field.descriptor().length() - 1);
            String sourceType = sourceTypeOf(hop, chain);
            if (sourceType != null && sourceType.startsWith("L")) {
                constraints.add(new String[] {fieldType, sourceType.substring(1, sourceType.length() - 1)});
            }
        }
        if (constraints.size() < 3) {
            return null;
        }
        for (String[] c : constraints) {
            if (!bb.hierarchy().isSubtypeOf(c[0], c[1]) && !bb.hierarchy().isSubtypeOf(c[1], c[0])) {
                var a = bb.hierarchy().classInfo(c[0]);
                var b = bb.hierarchy().classInfo(c[1]);
                if (a != null && b != null && !a.isInterface() && !b.isInterface()) {
                    boolean common = false;
                    for (String sub : bb.hierarchy().loadedSubtypes(c[0])) {
                        if (bb.hierarchy().isSubtypeOf(sub, c[1])) {
                            common = true;
                            break;
                        }
                    }
                    if (!common) {
                        return "constraint-cycle:" + c[0] + "-x-" + c[1];
                    }
                }
            }
        }
        return null;
    }

    private String sourceTypeOf(ChainHop hop, Chain chain) {
        if (hop.kind() == HopKind.ENTRY) {
            return "L" + chain.entryClass() + ";";
        }
        if (hop.kind() == HopKind.FIELD_FLOW && hop.field() != null) {
            String declaring = bb.hierarchy().resolveField(fieldOwnerOf(hop), hop.field());
            ClassInfo cls = bb.hierarchy().classInfo(declaring != null ? declaring : fieldOwnerOf(hop));
            FieldInfo field = cls != null ? cls.field(hop.field()) : null;
            return field != null ? field.descriptor() : null;
        }
        return null;
    }

    /** New producers retain the field's declaration owner; old extensions used toOwner. */
    private static String fieldOwnerOf(ChainHop hop) {
        if (hop == null) {
            return "";
        }
        return hop.fieldOwner() == null || hop.fieldOwner().isBlank()
                ? hop.toOwner() : hop.fieldOwner();
    }

    /**
     * #2 对象编号别名追踪（JDD 806 FP 消除原理的精确版）：
     * 链上有 equals 调用时，获取 equals 的两个 receiver 的 origin set——
     * 若有共同 origin（同一对象）→ 别名等价确认 → 链不可行。
     * 检测方式：在入口方法体中找 equals 调用点，用 ForwardOrigins 获取两个操作数 origin。
     */
    private boolean equalsGuardConflict(Chain chain) {
        boolean hasEquals = chain.hops().stream()
                .anyMatch(hop -> hop.kind() == HopKind.DIRECT_CALL
                        && hop.toName().equals("equals")
                        && hop.desc() != null && hop.desc().contains("Ljava/lang/Object;)Z"));
        if (!hasEquals || chain.hops().size() <= 4) {
            return false;
        }
        // 在入口方法体内找 equals 调用点，检查两个操作数的 origin 是否有交集
        var entryInfo = bb.hierarchy().classInfo(chain.entryClass());
        if (entryInfo == null) {
            return false;
        }
        var support = bb.originSupport();
        for (var method : entryInfo.methods()) {
            if (!method.name().equals(chain.entryMethod())) {
                continue;
            }
            var result = support.origins().compute(method);
            for (var insn : method.instructions()) {
                if (!insn.op().isInvoke() || insn.operands().isEmpty()) {
                    continue;
                }
                if (!(insn.operands().get(0) instanceof io.just.sast.model.MethodRef ref)
                        || !ref.name().equals("equals")
                        || !ref.descriptor().contains("Ljava/lang/Object;)Z")) {
                    continue;
                }
                var state = result.stateBefore().get(insn.offset());
                if (state == null || state.stack().size() < 2) {
                    continue;
                }
                // equals(Object obj) 静态调用：receiver=stack[-2], arg=stack[-1]
                // equals 虚调用：receiver=stack[-2], arg=stack[-1]
                var receiverOrigins = state.stack().get(state.stack().size() - 2).origins();
                var argOrigins = state.stack().get(state.stack().size() - 1).origins();
                // 检查是否有共同 origin（对象身份等价）
                for (var r : receiverOrigins) {
                    if (argOrigins.contains(r)) {
                        return true; // 别名等价确认——同一对象的两个引用
                    }
                }
            }
        }
        return false;
    }

    private boolean serializableValuePossible(String type) {
        Boolean cached = serializablePossible.get(type);
        if (cached != null) {
            return cached;
        }
        serializablePossible.put(type, Boolean.FALSE);
        boolean result = bb.hierarchy().isSubtypeOf(type, "java/io/Serializable");
        if (!result) {
            // The declared type is not the runtime type.  java.lang.reflect.Proxy is
            // Serializable, so any interface-typed field may legally carry a serializable
            // proxy when its InvocationHandler is serializable.  This is a possibility
            // proof, not a claim that every implementation is serializable; rejecting the
            // whole chain here would turn ordinary framework proxy gadgets into false
            // negatives (the dynamic verifier remains responsible for the concrete value).
            ClassInfo declared = bb.hierarchy().classInfo(type);
            if (declared != null && declared.isInterface()) {
                serializablePossible.put(type, Boolean.TRUE);
                return true;
            }
            if (ancestorChainUnresolvable(type)) {
                serializablePossible.put(type, Boolean.TRUE);
                return true;
            }
            for (String sub : bb.hierarchy().loadedSubtypes(type)) {
                if (serializableValuePossible(sub)) {
                    result = true;
                    break;
                }
            }
        }
        serializablePossible.put(type, result);
        return result;
    }

    private boolean ancestorChainUnresolvable(String type) {
        String cur = type;
        Set<String> visited = new HashSet<>();
        while (cur != null && visited.add(cur)) {
            ClassInfo ci = bb.hierarchy().classInfo(cur);
            if (ci == null) {
                return true;
            }
            cur = ci.superName();
        }
        return false;
    }
}
