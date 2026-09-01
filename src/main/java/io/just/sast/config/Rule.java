package io.just.sast.config;

import io.just.sast.blackboard.ObjectGraphPlan;

import java.util.List;
import java.util.Map;
import java.util.Set;

/** 规则模型：sink（起点）与 magic-entry（终点）。 */
public sealed interface Rule {

    String id();

    /** 调用匹配：owner/name/descriptor，descriptor 为 null 表示不限制。 */
    record CallMatcher(Match owner, Match name, Match descriptor) {

        public boolean matches(String owner, String name, String desc) {
            return this.owner.matches(owner) && this.name.matches(name)
                    && (descriptor == null || descriptor.matches(desc));
        }

        /** owner 为字面量时的类型名（供层次匹配：调用点 owner 为其子类型/实现类时命中）；正则返回 null。 */
        public String ownerType() {
            return owner.isRegex() ? null : owner.pattern();
        }

        /** name/descriptor 匹配（不含 owner），供层次命中复用。 */
        public boolean matchesRest(String name, String desc) {
            return this.name.matches(name) && (descriptor == null || descriptor.matches(desc));
        }
    }

    /**
     * 方法匹配（用于 magic-entry）。privateOnly：要求方法为 private
     * （OIS 机制只回调 private readObject/readObjectNoData/writeObject——ObjectStreamClass 语义）。
     */
    record MethodMatcher(Match name, Match descriptor, boolean privateOnly) {

        public boolean matches(String name, String desc) {
            return this.name.matches(name) && (descriptor == null || descriptor.matches(desc));
        }
    }

    /** 污点位置：第 index 个参数，或 receiver。 */
    sealed interface TaintedPos {
        record Arg(int index) implements TaintedPos {}
        enum Receiver implements TaintedPos { INSTANCE }
    }

    /**
     * A capability sink is a dangerous capability boundary (reflection, class loading,
     * proxy construction, etc.) that still needs a downstream terminal effect before a
     * report can describe an end-to-end exploit.  A terminal sink is the final effect
     * boundary represented by the finding.  This is rule data, not a hard-coded class list.
     */
    enum SinkRole {
        CAPABILITY,
        TERMINAL;

        public static SinkRole parse(String value) {
            if (value == null || value.isBlank()) {
                return TERMINAL;
            }
            return switch (value.trim().toLowerCase(java.util.Locale.ROOT)) {
                case "capability", "capability-sink", "intermediate" -> CAPABILITY;
                case "terminal", "terminal-sink", "effect" -> TERMINAL;
                default -> throw new IllegalArgumentException(
                        "sink role must be capability or terminal: " + value);
            };
        }
    }

    /** sink 规则：调用匹配 + 需要污点的位置。 */
    record SinkRule(String id, String category, String severity, CallMatcher call,
                    List<TaintedPos> tainted, SinkRole role) implements Rule {
        public SinkRule {
            if (id == null || id.isBlank()) {
                throw new IllegalArgumentException("sink id must not be blank");
            }
            if (call == null) {
                throw new IllegalArgumentException("sink call must not be null");
            }
            tainted = tainted == null ? List.of() : List.copyOf(tainted);
            role = role == null ? SinkRole.TERMINAL : role;
        }

        /** Compatibility constructor for extensions written before sink roles. */
        public SinkRule(String id, String category, String severity, CallMatcher call,
                        List<TaintedPos> tainted) {
            this(id, category, severity, call, tainted, SinkRole.TERMINAL);
        }

        public boolean terminal() {
            return role == SinkRole.TERMINAL;
        }
    }

    /**
     * magic-entry 规则：方法匹配 + 所在类需实现 implementsType（如 java/io/Serializable）。
     * implementsType 为 null 表示不限制。
     */
    record MagicEntryRule(String id, String entryKind, MethodMatcher method, String implementsType,
                          String direction) implements Rule {
        public MagicEntryRule {
            direction = normalizeDirection(direction, entryKind);
        }

        /** Compatibility constructor for extensions written before directional entries. */
        public MagicEntryRule(String id, String entryKind, MethodMatcher method, String implementsType) {
            this(id, entryKind, method, implementsType, null);
        }

        private static String normalizeDirection(String value, String kind) {
            String normalized = value == null || value.isBlank()
                    ? inferDirection(kind) : value.trim().toLowerCase(java.util.Locale.ROOT);
            if (!"deserialize".equals(normalized) && !"serialize".equals(normalized)
                    && !"lifecycle".equals(normalized)) {
                throw new IllegalArgumentException("magic-entry direction must be deserialize/serialize/lifecycle: "
                        + value);
            }
            return normalized;
        }

        private static String inferDirection(String kind) {
            if (kind == null) {
                return "lifecycle";
            }
            return switch (kind) {
                case "readObject", "readObjectNoData", "readResolve", "readExternal",
                        "validateObject", "proxyInvoke", "resolveClass", "resolveProxyClass" -> "deserialize";
                case "writeObject", "writeReplace" -> "serialize";
                default -> "lifecycle";
            };
        }
    }

    /** 安全配置声明（挂在 source 规则上，SafeConfig 知识源消费）。owner 为前缀匹配，methods 精确匹配。 */
    record SafeConfigDecl(Match owner, Set<String> methods, Boolean safeValue) {}

    /**
     * source 规则：替代反序列化框架入口调用点（Kryo/SnakeYAML/XStream/Hessian/Fastjson 等）。
     * bridge = serialize（toString→getter 反射）或 deserialize（load→构造器/setter 反射）。
     * safeConfig 非 null 时：同方法内先安全配置后入口调用（偏移序）→ 入口链抑制。
     *
     * tainted 是可选的 source 输入前置条件，语法与 sink 的 tainted 相同。为空表示
     * 该调用本身就是外部反序列化边界；非空表示二次反序列化/转换桥，只有指定输入
     * 已从真实入口取得污点时，调用结果才能 materialize 为新的对象图。这样可以把
     * ``byte[] -> ObjectInputStream`` 之类的桥接规则与普通框架入口区分开，避免
     * 仅因依赖包中存在一个工具方法就把所有 JavaBean 方法提升为外部输入。
     */
    record SourceRule(String id, String bridge, CallMatcher call, SafeConfigDecl safeConfig,
                      List<TaintedPos> tainted) implements Rule {
        /** Compatibility constructor for extensions written before source preconditions. */
        public SourceRule(String id, String bridge, CallMatcher call, SafeConfigDecl safeConfig) {
            this(id, bridge, call, safeConfig, List.of());
        }

        public SourceRule {
            tainted = tainted == null ? List.of() : List.copyOf(tainted);
        }
    }

    /**
     * model 规则（tabby actions 模式）：声明式方法摘要——无字节码体的外部/JDK 方法的污点传播。
     * targets: 污点到达位置 → 来源位置集合。如 {return: [arg0]} 表示 arg0 的污点传播到返回值；
     * {this: [arg1]} 表示 arg1 的污点投毒整个接收者对象（容器投毒，Map.put 语义）。
     */
    record ModelRule(String id, CallMatcher call, Map<String, List<String>> actions) implements Rule {}

    /** 片段跳：类#方法（可选字段流）。 */
    record HopSpec(String cls, String method, String field) {}

    /**
     * chain-fragment 规则（IOCD-lite）：声明式已知链片段——全部锚点类在图中可解析才生效，
     * Fragment 知识源据此合成链（公开 gadget 知识库化，"规则做数据"的延伸）。
     */
    record FragmentRule(String id, String entryClass, String entryKind,
                        List<HopSpec> hops, String sinkOwner, String sinkName,
                        String sinkDescriptor, ObjectGraphPlan constructionPlan) implements Rule {
        /** 兼容旧的程序化规则构造；YAML 可用 sinkDescriptor 消除重载歧义。 */
        public FragmentRule(String id, String entryClass, String entryKind,
                            List<HopSpec> hops, String sinkOwner, String sinkName) {
            this(id, entryClass, entryKind, hops, sinkOwner, sinkName, null, null);
        }

        /** Compatibility constructor for fragment rules without an object-shape plan. */
        public FragmentRule(String id, String entryClass, String entryKind,
                            List<HopSpec> hops, String sinkOwner, String sinkName,
                            String sinkDescriptor) {
            this(id, entryClass, entryKind, hops, sinkOwner, sinkName, sinkDescriptor, null);
        }

        public FragmentRule {
            constructionPlan = constructionPlan == null || constructionPlan.isEmpty()
                    ? null : constructionPlan;
        }
    }
}
