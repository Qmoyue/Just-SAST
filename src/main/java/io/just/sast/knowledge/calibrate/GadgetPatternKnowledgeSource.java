package io.just.sast.knowledge.calibrate;

import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.KnowledgeSource;
import io.just.sast.blackboard.Phase;
import io.just.sast.util.JustLogger;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 已知 gadget 模式识别（CALIBRATION 阶段，借鉴 marshalsec 链分类 + JDD 可利用性验证）。
 * 链路径**覆盖某模式全部关键类**（集合包含判定）时写链级注释（黑板 chainNotes），
 * 报告层输出 findings.patterns 列并给证据分 +2/模式。
 * 不产链不拒链——纯排序增强，帮分析者一眼识别"这是 CC1 型链"。
 */
public final class GadgetPatternKnowledgeSource implements KnowledgeSource {

    /** 已知 gadget 模式：名称 + 必须全部出现的类前缀集合。 */
    private record Pattern(String name, Set<String> requiredClasses) {}

    private static final List<Pattern> PATTERNS = List.of(
            new Pattern("CC1", Set.of(
                    "org/apache/commons/collections/functors/InvokerTransformer",
                    "org/apache/commons/collections/functors/ChainedTransformer")),
            new Pattern("CC2", Set.of(
                    "org/apache/commons/collections/functors/InvokerTransformer",
                    "org/apache/commons/collections/comparators/TransformingComparator")),
            new Pattern("CC3", Set.of(
                    "com/sun/org/apache/xalan/internal/xsltc/trax/TemplatesImpl",
                    "org/apache/commons/collections/functors/InstantiateTransformer")),
            new Pattern("CC5", Set.of(
                    "javax/management/BadAttributeValueExpException",
                    "org/apache/commons/collections/keyvalue/TiedMapEntry",
                    "org/apache/commons/collections/map/LazyMap")),
            new Pattern("CC6", Set.of(
                    "org/apache/commons/collections/keyvalue/TiedMapEntry",
                    "org/apache/commons/collections/map/LazyMap")),
            new Pattern("CC7", Set.of(
                    "java/util/Hashtable",
                    "org/apache/commons/collections/map/LazyMap")),
            new Pattern("Spring1", Set.of(
                    "org/springframework/core/SerializableTypeWrapper$MethodInvokeTypeProvider",
                    "org/springframework/aop/framework/AdvisedSupport")),
            new Pattern("Rome", Set.of(
                    "com/sun/syndication/feed/impl/EqualsBean",
                    "com/sun/syndication/feed/impl/ToStringBean")),
            new Pattern("Jdk7u21", Set.of(
                    "sun/reflect/annotation/AnnotationInvocationHandler",
                    "com/sun/org/apache/xalan/internal/xsltc/trax/TemplatesImpl")),
            new Pattern("CB1", Set.of(
                    "org/apache/commons/beanutils/BeanComparator",
                    "com/sun/org/apache/xalan/internal/xsltc/trax/TemplatesImpl")),
            new Pattern("SignedObject二次反序列化", Set.of(
                    "java/security/SignedObject",
                    "com/sun/syndication/feed/impl/EqualsBean")));

    private Blackboard bb;

    @Override
    public String id() {
        return "gadget-pattern";
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
        return 400;
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
        Map<String, Integer> patternCounts = new HashMap<>();
        for (Chain chain : bb.chains()) {
            if (bb.calibrationOf(chain.key()) != null) {
                continue;
            }
            String matched = matchPattern(chain);
            if (matched != null) {
                patternCounts.merge(matched, 1, Integer::sum);
                bb.chainNote(chain.key(), "pattern:" + matched);
            }
        }
        if (!patternCounts.isEmpty()) {
            JustLogger.info("已知 gadget 模式：{}",
                    patternCounts.entrySet().stream()
                            .map(e -> e.getKey() + "×" + e.getValue())
                            .collect(java.util.stream.Collectors.joining(", ")));
        }
    }

    /** 链路径是否覆盖某模式的全部关键类（每个必需类都有一条路径类以之为前缀）。 */
    private String matchPattern(Chain chain) {
        Set<String> pathClasses = new HashSet<>();
        pathClasses.add(chain.entryClass());
        for (ChainHop hop : chain.hops()) {
            pathClasses.add(hop.fromOwner());
            pathClasses.add(hop.toOwner());
        }
        for (Pattern pattern : PATTERNS) {
            boolean allPresent = pattern.requiredClasses().stream()
                    .allMatch(required -> pathClasses.stream().anyMatch(c -> c.startsWith(required)));
            if (allPresent) {
                return pattern.name();
            }
        }
        return null;
    }
}
