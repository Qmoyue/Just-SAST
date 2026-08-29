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
import io.just.sast.model.TypeRef;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.ArrayDeque;
import java.util.Collections;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * 为完整扫描规划 JDK 类的最小安全闭包。
 *
 * <p>旧实现把反序列化相关模块的每个 JDK 方法体都放进 CPG。这里先读取轻量级
 * class header，再从应用引用和规则片段类型建立闭包；只有闭包中的类才交给完整事实
 * 抽取。JDK 的隐式回调不是“凭空可达”的普通根，只有被目标/依赖字节码引用或被规则
 * 片段锚定时才物化；其方法体内部的机制边界由调用图和对象图知识源处理。该选择不依赖
 * 样本名称，也不改变分析预算、调用分发上限或规则语义。</p>
 */
public final class JdkClassSelector {

    private JdkClassSelector() {
    }

    /** 由规则层映射出的 magic-entry 方法种子，避免 frontend 依赖 Rule 类型。 */
    public record EntrySeed(String namePattern, boolean nameRegex,
                            String descriptorPattern, boolean descriptorRegex,
                            boolean privateOnly, String implementsType, String entryKind) {
    }

    /** 不含方法体的 class header，仅供闭包规划与层次判断。 */
    public record ClassHeader(String name, String superName, List<String> interfaces,
                              int access, List<MethodHeader> methods) {
        public ClassHeader {
            interfaces = interfaces == null ? List.of() : List.copyOf(interfaces);
            methods = methods == null ? List.of() : List.copyOf(methods);
        }
    }

    public record MethodHeader(String name, String descriptor, int access) {
    }

    public record Selection(List<ClassBytes> classes, int availableClasses,
                            int headerClasses, int initialSeeds,
                            int implicitEntrySeeds, int closureClasses) {
        public Selection {
            classes = classes == null ? List.of() : List.copyOf(classes);
        }
    }

    /** 只解析 header；错误类不进入 header 索引，但若是显式类型种子仍会保留给正式解析。 */
    public static Map<String, ClassHeader> indexHeaders(List<ClassBytes> available) {
        Map<String, ClassHeader> headers = new LinkedHashMap<>();
        if (available == null) {
            return headers;
        }
        for (ClassBytes bytes : available) {
            if (headers.containsKey(bytes.className())) {
                continue;
            }
            try {
                headers.put(bytes.className(), readHeader(bytes.bytes()));
            } catch (RuntimeException ignored) {
                // 正式 frontend 仍会对显式种子执行完整解析并记录诊断。
            }
        }
        return Collections.unmodifiableMap(headers);
    }

    /**
     * 从所有可用 JDK 字节中选择应用与规则可达的闭包。
     *
     * @param available JDK 来源的全部 class bytes（只读规划输入）
     * @param initial 已解析的 target/deps 类
     * @param typeSeeds 规则中明确出现的字面量 owner/fragment 类型
     * @param entrySeeds 规则中的 magic-entry 方法签名（仅保留在选择契约中；不再把所有
     *                   JDK 隐式回调类作为全局根）
     */
    public static List<ClassBytes> select(List<ClassBytes> available,
                                          Map<String, ClassInfo> initial,
                                          Set<String> typeSeeds,
                                          List<EntrySeed> entrySeeds) {
        return selectDetailed(available, initial, typeSeeds, entrySeeds).classes();
    }

    public static Selection selectDetailed(List<ClassBytes> available,
                                           Map<String, ClassInfo> initial,
                                           Set<String> typeSeeds,
                                           List<EntrySeed> entrySeeds) {
        if (available == null || available.isEmpty()) {
            return new Selection(List.of(), 0, 0, 0, 0, 0);
        }
        Map<String, ClassBytes> bytesByName = new LinkedHashMap<>();
        for (ClassBytes bytes : available) {
            bytesByName.putIfAbsent(bytes.className(), bytes);
        }
        Map<String, ClassHeader> jdkHeaders = indexHeaders(available);
        Map<String, ClassHeader> knownHeaders = new LinkedHashMap<>();
        if (initial != null) {
            for (ClassInfo info : initial.values()) {
                knownHeaders.put(info.internalName(), headerOf(info));
            }
        }
        knownHeaders.putAll(jdkHeaders);

        Set<String> selected = new LinkedHashSet<>();
        if (typeSeeds != null) {
            for (String seed : typeSeeds) {
                enqueue(seed, bytesByName, selected);
            }
        }
        if (initial != null) {
            for (ClassInfo info : initial.values()) {
                for (String reference : referencesOf(info)) {
                    enqueue(reference, bytesByName, selected);
                }
            }
        }
        int initialSeeds = selected.size();
        // 不把所有 JDK readObject/hashCode 等方法作为全局 class-body 种子。
        // 这些方法只有在应用调用边、对象图字段或声明式片段真正需要时才应进入
        // CPG；否则每个 JDK 平台实现都会成为一棵独立的分析根。保留 entrySeeds
        // 参数是为了让 frontend 与规则层保持解耦，并让 Selection 继续报告该
        // 维度；“0”是有意的 demand-driven 结果，而非解析失败。
        int implicitEntrySeeds = 0;

        // A selected platform class is not useful in isolation when its superclass or
        // interface declaration is missing: method resolution then falls back to lazy disk
        // probes during the parallel analysis phase, invalidating hierarchy caches and making
        // the result dependent on which sink reaches the probe first.  Close only the structural
        // ancestor relation here.  We deliberately do not follow method/field descriptors or
        // every implementation of an interface; that closure is the source of the previous JDK
        // graph explosion.  The bounded structural closure is universal and keeps the exact
        // on-demand policy for unrelated platform bodies.
        Deque<String> structural = new ArrayDeque<>(selected);
        while (!structural.isEmpty()) {
            String name = structural.removeFirst();
            ClassHeader header = knownHeaders.get(name);
            if (header == null) {
                continue;
            }
            if (header.superName() != null && enqueueAndReport(header.superName(), bytesByName, selected)) {
                structural.addLast(header.superName());
            }
            for (String itf : header.interfaces()) {
                if (enqueueAndReport(itf, bytesByName, selected)) {
                    structural.addLast(itf);
                }
            }
        }

        // 只在 seed 层选类，不沿每个 JDK 类的全部方法体递归展开。JDK 类体内部的
        // 同类调用仍会随该类完整进入 CPG；跨类调用由现有外部方法解析与规则模型处理。
        // 这样不会把 Class/reflect 等平台实现的整个引用闭包重新物化。
        List<ClassBytes> result = new ArrayList<>();
        for (ClassBytes bytes : available) {
            if (selected.contains(bytes.className())) {
                result.add(bytes);
            }
        }
        return new Selection(List.copyOf(result), available.size(), jdkHeaders.size(),
                initialSeeds, implicitEntrySeeds, selected.size());
    }

    private static boolean matchesEntry(ClassHeader header, List<CompiledEntrySeed> seeds,
                                        Map<String, ClassHeader> knownHeaders) {
        if (seeds == null || seeds.isEmpty()) {
            return false;
        }
        for (CompiledEntrySeed seed : seeds) {
            for (MethodHeader method : header.methods()) {
                if (!seed.matchesName(method.name()) || !seed.matchesDescriptor(method.descriptor())) {
                    continue;
                }
                if (seed.privateOnly() && !Modifier.isPrivate(method.access())) {
                    continue;
                }
                if (seed.implementsType() == null
                        || isSubtype(header.name(), seed.implementsType(), knownHeaders)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * 只有 JVM/序列化机制会隐式调用的 entry 才需要在没有应用类型引用时全局入队。
     * equals/hashCode/compare/toString 等普通虚方法仍按应用实际引用进入闭包；它们的
     * JDK 实现不可能凭空成为链入口，遍历所有平台实现只会重建原来的图爆炸。
     */
    private static boolean matchesImplicitEntry(ClassHeader header,
                                                List<CompiledEntrySeed> seeds,
                                                Map<String, ClassHeader> knownHeaders) {
        for (CompiledEntrySeed seed : seeds) {
            if (!isImplicitEntry(seed.entryKind()) || !matchesEntry(header, List.of(seed), knownHeaders)) {
                continue;
            }
            return true;
        }
        return false;
    }

    private static boolean isImplicitEntry(String entryKind) {
        return "readObject".equals(entryKind)
                || "readObjectNoData".equals(entryKind)
                || "readExternal".equals(entryKind)
                || "readResolve".equals(entryKind)
                || "proxyInvoke".equals(entryKind)
                || "validateObject".equals(entryKind);
    }

    private static List<CompiledEntrySeed> compileEntrySeeds(List<EntrySeed> seeds) {
        if (seeds == null || seeds.isEmpty()) {
            return List.of();
        }
        List<CompiledEntrySeed> result = new ArrayList<>(seeds.size());
        for (EntrySeed seed : seeds) {
            result.add(new CompiledEntrySeed(
                    seed.nameRegex() ? null : seed.namePattern(),
                    seed.nameRegex() ? Pattern.compile(regexBody(seed.namePattern())) : null,
                    seed.descriptorPattern() == null || !seed.descriptorRegex()
                            ? seed.descriptorPattern() : null,
                    seed.descriptorPattern() != null && seed.descriptorRegex()
                            ? Pattern.compile(regexBody(seed.descriptorPattern())) : null,
                    seed.privateOnly(), seed.implementsType(), seed.entryKind()));
        }
        return List.copyOf(result);
    }

    private static String regexBody(String pattern) {
        if (pattern == null) {
            return "";
        }
        return pattern.startsWith("~") ? "^(?:" + pattern.substring(1) + ")$" :
                "^(?:" + Pattern.quote(pattern) + ")$";
    }

    private static void enqueue(String name, Map<String, ClassBytes> bytesByName,
                                Set<String> selected) {
        if (name != null && bytesByName.containsKey(name)) {
            selected.add(name);
        }
    }

    private static boolean enqueueAndReport(String name, Map<String, ClassBytes> bytesByName,
                                            Set<String> selected) {
        if (name == null || !bytesByName.containsKey(name)) {
            return false;
        }
        return selected.add(name);
    }

    private static boolean isSubtype(String name, String expected,
                                     Map<String, ClassHeader> headers) {
        if (name == null || expected == null) {
            return false;
        }
        if (name.equals(expected)) {
            return true;
        }
        Deque<String> work = new ArrayDeque<>();
        Set<String> visited = new HashSet<>();
        work.add(name);
        while (!work.isEmpty()) {
            String current = work.removeFirst();
            if (!visited.add(current)) {
                continue;
            }
            ClassHeader header = headers.get(current);
            if (header == null) {
                continue;
            }
            if (expected.equals(header.superName()) || header.interfaces().contains(expected)) {
                return true;
            }
            if (header.superName() != null) {
                work.addLast(header.superName());
            }
            work.addAll(header.interfaces());
        }
        return false;
    }

    private static ClassHeader readHeader(byte[] bytes) {
        HeaderVisitor visitor = new HeaderVisitor();
        new ClassReader(bytes).accept(visitor, ClassReader.SKIP_CODE
                | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        return visitor.header();
    }

    private static ClassHeader headerOf(ClassInfo info) {
        List<MethodHeader> methods = info.methods().stream()
                .map(m -> new MethodHeader(m.name(), m.descriptor(), m.access()))
                .toList();
        return new ClassHeader(info.internalName(), info.superName(), info.interfaces(),
                info.access(), methods);
    }

    private static Set<String> referencesOf(ClassInfo info) {
        Set<String> result = new LinkedHashSet<>();
        addName(result, info.superName());
        info.interfaces().forEach(name -> addName(result, name));
        for (FieldInfo field : info.fields()) {
            addDescriptor(result, field.descriptor());
        }
        for (MethodInfo method : info.methods()) {
            addDescriptor(result, method.descriptor());
            for (InsnFact insn : method.instructions()) {
                addOperands(result, insn.operands());
            }
            method.tryCatch().forEach(tc -> addName(result, tc.type()));
        }
        return result;
    }

    private static void addOperands(Set<String> result, List<Object> operands) {
        for (Object operand : operands) {
            if (operand instanceof MethodRef ref) {
                addName(result, ref.owner());
                addDescriptor(result, ref.descriptor());
            } else if (operand instanceof FieldRef ref) {
                addName(result, ref.owner());
                addDescriptor(result, ref.descriptor());
            } else if (operand instanceof TypeRef ref) {
                addDescriptor(result, ref.descriptor());
            } else if (operand instanceof HandleRef ref) {
                addName(result, ref.owner());
                addDescriptor(result, ref.descriptor());
            } else if (operand instanceof InvokeDynamicRef ref) {
                addDescriptor(result, ref.descriptor());
                addName(result, ref.bootstrap().owner());
                addDescriptor(result, ref.bootstrap().descriptor());
                addOperands(result, ref.bootstrapArgs());
            }
        }
    }

    private static void addDescriptor(Set<String> result, String descriptor) {
        if (descriptor == null || descriptor.isEmpty()) {
            return;
        }
        if (!descriptor.startsWith("(") && descriptor.indexOf('L') < 0
                && descriptor.indexOf('[') < 0) {
            addName(result, descriptor);
            return;
        }
        for (int i = 0; i < descriptor.length(); i++) {
            if (descriptor.charAt(i) != 'L') {
                continue;
            }
            int end = descriptor.indexOf(';', i);
            if (end < 0) {
                return;
            }
            addName(result, descriptor.substring(i + 1, end));
            i = end;
        }
    }

    private static void addName(Set<String> result, String name) {
        if (name == null || name.isEmpty() || name.startsWith("[")
                || name.length() == 1 || !name.contains("/")) {
            return;
        }
        result.add(name);
    }

    private static final class HeaderVisitor extends ClassVisitor {
        private String name;
        private String superName;
        private List<String> interfaces = List.of();
        private int access;
        private final List<MethodHeader> methods = new ArrayList<>();

        private HeaderVisitor() {
            super(Opcodes.ASM9);
        }

        @Override
        public void visit(int version, int access, String name, String signature,
                          String superName, String[] interfaces) {
            this.name = name;
            this.access = access;
            this.superName = superName;
            this.interfaces = interfaces == null ? List.of() : List.of(interfaces);
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor,
                                         String signature, String[] exceptions) {
            methods.add(new MethodHeader(name, descriptor, access));
            return null;
        }

        private ClassHeader header() {
            return new ClassHeader(name, superName, interfaces, access, methods);
        }
    }

    private record CompiledEntrySeed(String nameLiteral, Pattern namePattern,
                                     String descriptorLiteral, Pattern descriptorPattern,
                                     boolean privateOnly, String implementsType, String entryKind) {
        private boolean matchesName(String value) {
            return namePattern != null ? namePattern.matcher(value).matches()
                    : nameLiteral == null || nameLiteral.equals(value);
        }

        private boolean matchesDescriptor(String value) {
            return descriptorPattern != null ? descriptorPattern.matcher(value).matches()
                    : descriptorLiteral == null || descriptorLiteral.equals(value);
        }
    }
}
