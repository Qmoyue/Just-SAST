package io.just.sast.cpg.graph;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** 图节点：不可变 id/type/props + 可变质量注释 + 邻接表。 */
public final class Node {

    private final long id;
    private final NodeType type;
    /*
     * METHOD/CALL 节点的这些字段占绝大多数访问量。用字段保存它们，避免每个调用点
     * 都持有一个 Map 及其 entry 数组；extras 只承载 indy 等低频属性。
     */
    private final String owner;
    private final String name;
    private final String desc;
    private final String invokeKind;
    private final String methodOwner;
    private final String methodName;
    private final String methodDesc;
    private final Integer offset;
    private final Boolean external;
    private final Map<String, Object> extras;
    private volatile Map<String, Object> propsView;
    private Map<String, Object> notes;
    /*
     * Most METHOD/CALL nodes have no incoming or outgoing edge.  Allocating two
     * ArrayList objects for every node made large application jars pay for empty
     * adjacency lists.  Keep the lists lazy; the public read-only view remains the
     * same and graph construction is single-threaded.
     */
    private List<Edge> out;
    private List<Edge> in;
    private volatile List<Edge> readOnlyOut;
    private volatile List<Edge> readOnlyIn;

    Node(long id, NodeType type, Map<String, Object> props) {
        this.id = id;
        this.type = type;
        Map<String, Object> values = props == null ? Map.of() : props;
        this.owner = string(values.get("owner"));
        this.name = string(values.get("name"));
        this.desc = string(values.get("desc"));
        this.invokeKind = string(values.get("invokeKind"));
        this.methodOwner = string(values.get("methodOwner"));
        this.methodName = string(values.get("methodName"));
        this.methodDesc = string(values.get("methodDesc"));
        this.offset = integer(values.get("offset"));
        this.external = values.containsKey("external") ? Boolean.valueOf(Boolean.TRUE.equals(values.get("external")))
                : null;
        this.extras = extras(values);
    }

    /** Compact METHOD constructor; method nodes have no sparse property map. */
    Node(long id, String owner, String name, String desc, boolean external) {
        this.id = id;
        this.type = NodeType.METHOD;
        this.owner = owner;
        this.name = name;
        this.desc = desc;
        this.invokeKind = null;
        this.methodOwner = null;
        this.methodName = null;
        this.methodDesc = null;
        this.offset = null;
        this.external = Boolean.valueOf(external);
        this.extras = Map.of();
    }

    /** 紧凑的调用点构造入口；避免 CpgBuilder 为每个 invoke 创建临时属性 Map。 */
    public Node(long id, String owner, String name, String desc, String invokeKind,
                Object indy, int offset, String methodOwner, String methodName,
                String methodDesc) {
        this.id = id;
        this.type = NodeType.CALL;
        this.owner = owner;
        this.name = name;
        this.desc = desc;
        this.invokeKind = invokeKind;
        this.methodOwner = methodOwner;
        this.methodName = methodName;
        this.methodDesc = methodDesc;
        this.offset = offset;
        this.external = null;
        this.extras = indy == null ? Map.of() : Map.of("indy", indy);
    }

    private static String string(Object value) {
        return value == null ? null : value.toString();
    }

    private static Integer integer(Object value) {
        return value instanceof Number number ? number.intValue()
                : value == null ? null : Integer.valueOf(value.toString());
    }

    private static Map<String, Object> extras(Map<String, Object> values) {
        if (values.isEmpty()) {
            return Map.of();
        }
        Map<String, Object> copy = new HashMap<>(values);
        for (String key : List.of("owner", "name", "desc", "invokeKind", "methodOwner",
                "methodName", "methodDesc", "offset", "external")) {
            copy.remove(key);
        }
        return copy.isEmpty() ? Map.of() : Map.copyOf(copy);
    }

    /** 分析过程中追加的质量注释（props 不可变，notes 供知识源写）。 */
    public synchronized void propsNote(String key, Object value) {
        if (notes == null) {
            notes = new HashMap<>();
        }
        notes.put(key, value);
    }

    public long id() {
        return id;
    }

    public NodeType type() {
        return type;
    }

    /** METHOD/CALL 高频属性的类型化读取，避免热路径 Map 视图与装箱。 */
    public String owner() {
        return owner;
    }

    public String name() {
        return name;
    }

    public String descriptor() {
        return desc;
    }

    public String invokeKind() {
        return invokeKind;
    }

    public String methodOwner() {
        return methodOwner;
    }

    public String methodName() {
        return methodName;
    }

    public String methodDescriptor() {
        return methodDesc;
    }

    public int offset() {
        return offset == null ? -1 : offset;
    }

    public Object prop(String key) {
        if (key == null) {
            return extras.get(null);
        }
        return switch (key) {
            case "owner" -> owner;
            case "name" -> name;
            case "desc" -> desc;
            case "invokeKind" -> invokeKind;
            case "methodOwner" -> methodOwner;
            case "methodName" -> methodName;
            case "methodDesc" -> methodDesc;
            case "offset" -> offset;
            case "external" -> external;
            default -> extras.get(key);
        };
    }

    public String strProp(String key) {
        Object v = prop(key);
        return v != null ? v.toString() : null;
    }

    /** 属性全序键，供规则/索引缓存复用，避免热路径重复拼接。 */
    public String matcherKey() {
        return owner + "|" + name + "|" + desc;
    }

    /** 延迟构造兼容视图；正常分析只走 prop/strProp，不支付 Map 重建成本。 */
    public Map<String, Object> props() {
        Map<String, Object> view = propsView;
        if (view != null) {
            return view;
        }
        Map<String, Object> copy = new LinkedHashMap<>();
        put(copy, "owner", owner);
        put(copy, "name", name);
        put(copy, "desc", desc);
        put(copy, "invokeKind", invokeKind);
        put(copy, "indy", extras.get("indy"));
        put(copy, "offset", offset);
        put(copy, "methodOwner", methodOwner);
        put(copy, "methodName", methodName);
        put(copy, "methodDesc", methodDesc);
        put(copy, "external", external);
        for (Map.Entry<String, Object> entry : extras.entrySet()) {
            copy.putIfAbsent(entry.getKey(), entry.getValue());
        }
        view = Map.copyOf(copy);
        propsView = view;
        return view;
    }

    private static void put(Map<String, Object> map, String key, Object value) {
        if (value != null) {
            map.put(key, value);
        }
    }

    public List<Edge> out() {
        List<Edge> view = readOnlyOut;
        if (view == null) {
            view = out == null || out.isEmpty() ? List.of() : Collections.unmodifiableList(out);
            readOnlyOut = view;
        }
        return view;
    }

    /** 构建/分析阶段质量注释；只读消费者用此接口读取 dispatch/truncation 等边界信号。 */
    public Object note(String key) {
        Map<String, Object> current = notes;
        return current == null ? null : current.get(key);
    }

    public Map<String, Object> notes() {
        Map<String, Object> current = notes;
        return current == null ? Map.of() : Map.copyOf(current);
    }

    public List<Edge> in() {
        List<Edge> view = readOnlyIn;
        if (view == null) {
            view = in == null || in.isEmpty() ? List.of() : Collections.unmodifiableList(in);
            readOnlyIn = view;
        }
        return view;
    }

    void freezeAdjacency() {
        readOnlyOut = out == null || out.isEmpty() ? List.of() : Collections.unmodifiableList(out);
        readOnlyIn = in == null || in.isEmpty() ? List.of() : Collections.unmodifiableList(in);
    }

    void addOut(Edge e) {
        if (out == null) {
            out = new ArrayList<>(2);
        }
        out.add(e);
    }

    void addIn(Edge e) {
        if (in == null) {
            in = new ArrayList<>(1);
        }
        in.add(e);
    }

    @Override
    public String toString() {
        return type + "#" + id + props();
    }
}
