package io.just.sast.model;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/** JVM 描述符工具。 */
public final class Descriptor {

    /**
     * 描述符在调用图、前后向污点和验证器之间被反复查询。解析结果只依赖描述符
     * 字符串，因此用有界进程级缓存复用不可变 shape；达到上限后仍按原算法解析，
     * 不以缓存容量改变分析结果。这样既避免大规模扫描的重复 substring/charAt，
     * 又不让长期运行的多目标扫描因恶意唯一描述符无限增长。
     */
    private static final int CACHE_CAP = 32_768;
    private static final ConcurrentHashMap<String, Shape> SHAPES = new ConcurrentHashMap<>();

    private record Shape(List<String> types, List<Integer> staticSlots,
                         List<Integer> instanceSlots) {
    }

    private Descriptor() {}

    /** 方法描述符的参数个数（不含 this）。 */
    public static int paramCount(String methodDescriptor) {
        return shape(methodDescriptor).types().size();
    }

    /** 每个参数（含 this，若非静态）占用的槽位数。 */
    public static List<Integer> argSlots(String methodDescriptor, boolean isStatic) {
        Shape parsed = shape(methodDescriptor);
        return isStatic ? parsed.staticSlots() : parsed.instanceSlots();
    }

    /** 参数局部槽 → 参数序数（0 基，不含 this）；实例方法 slot 0（this/receiver）返回 -1；非参数槽（wide 次槽等）返回 -2。 */
    public static int paramOrdinal(String methodDescriptor, boolean isStatic, int slot) {
        List<Integer> slots = argSlots(methodDescriptor, isStatic);
        int cur = 0;
        for (int i = 0; i < slots.size(); i++) {
            if (cur == slot) {
                return isStatic ? i : i - 1;
            }
            cur += slots.get(i);
        }
        return -2;
    }

    /** 第 ordinal 个参数（0 基，不含 this）的类型子串（如 "Ljava/lang/String;"、"I"）；越界返回 null。 */
    public static String paramType(String methodDescriptor, int ordinal) {
        Shape parsed = shape(methodDescriptor);
        return ordinal >= 0 && ordinal < parsed.types().size()
                ? parsed.types().get(ordinal) : null;
    }

    /** 返回类型：方法描述符 ')' 之后的部分。 */
    public static String returnType(String methodDescriptor) {
        int close = methodDescriptor.indexOf(')');
        return close >= 0 ? methodDescriptor.substring(close + 1) : "Ljava/lang/Object;";
    }

    private static Shape shape(String descriptor) {
        Shape cached = SHAPES.get(descriptor);
        if (cached != null) {
            return cached;
        }
        Shape parsed = parse(descriptor);
        // 不阻塞或淘汰已有条目；超出容量时只放弃本次缓存。
        if (SHAPES.size() < CACHE_CAP) {
            Shape previous = SHAPES.putIfAbsent(descriptor, parsed);
            return previous != null ? previous : parsed;
        }
        return parsed;
    }

    private static Shape parse(String methodDescriptor) {
        int open = methodDescriptor.indexOf('(');
        int close = methodDescriptor.indexOf(')', open);
        String args = methodDescriptor.substring(open + 1, close);
        List<String> types = new ArrayList<>();
        List<Integer> widths = new ArrayList<>();
        int i = 0;
        while (i < args.length()) {
            int start = i;
            i = next(args, i);
            String type = args.substring(start, i);
            types.add(type);
            widths.add(type.equals("J") || type.equals("D") ? 2 : 1);
        }
        List<Integer> staticSlots = List.copyOf(widths);
        List<Integer> instanceSlots = new ArrayList<>(widths.size() + 1);
        instanceSlots.add(1);
        instanceSlots.addAll(widths);
        return new Shape(List.copyOf(types), staticSlots, List.copyOf(instanceSlots));
    }

    private static int next(String args, int i) {
        char c = args.charAt(i);
        if (c == '[') {
            int j = i;
            while (args.charAt(j) == '[') {
                j++;
            }
            return args.charAt(j) == 'L' ? args.indexOf(';', j) + 1 : j + 1;
        }
        if (c == 'L') {
            return args.indexOf(';', i) + 1;
        }
        return i + 1;
    }
}
