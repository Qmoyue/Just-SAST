package io.just.sast.verify.legacy;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Java 8-compatible fork-per-chain verifier. */
public final class LegacyChainVerifyProbe {

    private static final int MAX_SERIALIZED_BYTES = 8 * 1024 * 1024;
    private static final String PROTOCOL_PREFIX = "JUST_VERIFY_V1:";
    private static String protocolToken = "";
    private static ClassLoader applicationLoader;

    private LegacyChainVerifyProbe() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("usage: LegacyChainVerifyProbe <entry|method|mode> [hops] [sink]");
            System.exit(2);
            return;
        }
        String[] entryParts = args[0].split("\\|", -1);
        if (entryParts.length < 2 || entryParts[0].length() == 0 || entryParts[1].length() == 0) {
            System.err.println("usage: LegacyChainVerifyProbe <entryClass|entryMethod|mode> [hops] [sink]");
            System.exit(2);
            return;
        }
        String entryClass = entryParts[0];
        String entryMethod = entryParts[1];
        String mode = entryParts.length > 2 ? entryParts[2] : "DIRECT";
        String entryDescriptor = entryParts.length > 3 ? entryParts[3] : "";
        protocolToken = args.length > 5 ? args[5] : "";

        List<String[]> fieldLinks = parseLinks(args.length > 1 ? args[1] : "");
        String[] sink = parseSink(args.length > 2 ? args[2] : "");
        String sinkClass = sink[0];
        String sinkMethod = sink[1];
        String sinkDescriptor = sink[2];

        try {
            installApplicationLoader();
            try {
                LegacySandboxSecurityManager.install(Paths.get(System.getProperty("java.io.tmpdir", ".")));
            } catch (Throwable sandboxFailure) {
                emit("SANDBOX_UNAVAILABLE: " + sandboxFailure.getClass().getSimpleName());
                System.exit(3);
                return;
            }
            // Keep stack formatting and collection initialization outside the gadget call. Some
            // old runtimes initialize these classes lazily and can otherwise obscure the result.
            try {
                load("java.util.IdentityHashMap");
            } catch (Throwable ignored) {
            }

            Map<String, Object> instances = new HashMap<String, Object>();
            Class<?> entryType = load(entryClass);
            Method selectedEntry = findMethod(entryType, entryMethod, entryDescriptor);
            boolean staticEntry = selectedEntry != null
                    && Modifier.isStatic(selectedEntry.getModifiers());
            Object entryInstance;
            try {
                entryInstance = newInstance(entryType, isSerializationMode(mode));
            } catch (Exception constructionFailure) {
                if (!staticEntry) {
                    throw constructionFailure;
                }
                entryInstance = null;
            }
            if (entryInstance != null) {
                instances.put(entryClass, entryInstance);
            }

            // Materialize both ends. Reverse FIELD_FLOW paths commonly name an intermediate
            // owner only on the left side; creating both sides avoids a false partial result.
            for (String[] link : fieldLinks) {
                ensureInstance(instances, link[0], isSerializationMode(mode));
                ensureInstance(instances, link[2], isSerializationMode(mode));
            }

            List<String> unlinked = new ArrayList<String>();
            for (String[] link : fieldLinks) {
                linkField(instances, entryInstance, link, unlinked);
            }
            fillSimpleFields(instances);
            if (!unlinked.isEmpty()) {
                emit("PARTIAL_PATH: field-unlinked=" + unlinked.size());
                System.exit(0);
                return;
            }

            trigger(entryType, entryInstance, entryMethod, entryDescriptor, mode);
            if (LegacySinkCanaryGate.wasReached()) {
                emit("SINK_BLOCKED: " + sinkClass);
                System.err.println("SINK_REACHED: " + sinkClass + "." + sinkMethod
                        + " (canary-latched)");
            } else if ("SERIAL".equals(mode) || "PROXY".equals(mode)
                    || mode.startsWith("TRIGGER_")) {
                emit("CONCRETE_REACHED: " + mode);
            } else {
                emit("EXECUTED");
            }
            System.exit(0);
        } catch (Throwable failure) {
            String marker = markerSpec(failure);
            if (marker != null && sameSink(marker, sinkClass, sinkMethod, sinkDescriptor)
                    && entryReached(failure, entryClass, entryMethod)) {
                emit("SINK_BLOCKED: " + sinkClass);
                System.err.println("SINK_REACHED: " + sinkClass + "." + sinkMethod + " (canary)");
                System.exit(1);
                return;
            }
            if (sinkDescriptor.length() == 0 && reachesSink(failure, sinkClass, sinkMethod)
                    && entryReached(failure, entryClass, entryMethod)) {
                emit("UNTESTABLE: sink-frame-without-canary");
                System.err.println("SINK_REACHED: " + sinkClass + "." + sinkMethod
                        + " without canary (not confirmed)");
                System.exit(0);
                return;
            }
            String detail = failure.getMessage();
            if (detail == null) {
                detail = "";
            }
            detail = detail.replace('\n', ' ').replace("\r", "");
            if (detail.length() > 120) {
                detail = detail.substring(0, 120);
            }
            emit("PARTIAL_PATH: " + failure.getClass().getSimpleName()
                    + (detail.length() == 0 ? "" : ": " + detail));
            System.exit(0);
        }
    }

    private static void emit(String status) {
        System.out.println(PROTOCOL_PREFIX + (protocolToken == null ? "" : protocolToken)
                + ":" + status);
    }

    private static List<String[]> parseLinks(String encoded) {
        List<String[]> result = new ArrayList<String[]>();
        if (encoded == null || encoded.length() == 0) {
            return result;
        }
        if (encoded.startsWith("v2;")) {
            int cursor = 3;
            while (cursor < encoded.length()) {
                String[] values = new String[3];
                for (int i = 0; i < values.length; i++) {
                    int colon = encoded.indexOf(':', cursor);
                    if (colon <= cursor) {
                        return new ArrayList<String[]>();
                    }
                    int length;
                    try {
                        length = Integer.parseInt(encoded.substring(cursor, colon));
                    } catch (NumberFormatException malformed) {
                        return new ArrayList<String[]>();
                    }
                    int start = colon + 1;
                    int end = start + length;
                    if (length < 0 || end < start || end > encoded.length()) {
                        return new ArrayList<String[]>();
                    }
                    values[i] = encoded.substring(start, end);
                    cursor = end;
                }
                result.add(values);
            }
            return result;
        }
        for (String hop : encoded.split(",")) {
            int equal = hop.indexOf('=');
            if (equal < 0) {
                continue;
            }
            String left = hop.substring(0, equal);
            int dot = left.lastIndexOf('.');
            if (dot < 0) {
                continue;
            }
            result.add(new String[]{left.substring(0, dot), left.substring(dot + 1),
                    hop.substring(equal + 1)});
        }
        return result;
    }

    private static String[] parseSink(String encoded) {
        String target = encoded == null ? "" : encoded;
        String descriptor = "";
        int bar = target.lastIndexOf('|');
        if (bar > 0) {
            descriptor = target.substring(bar + 1);
            target = target.substring(0, bar);
        }
        int dot = target.lastIndexOf('.');
        if (dot <= 0) {
            return new String[]{"", "", descriptor};
        }
        return new String[]{target.substring(0, dot).replace('/', '.'), target.substring(dot + 1), descriptor};
    }

    private static void ensureInstance(Map<String, Object> instances, String internalName,
                                       boolean serializationMode) {
        String name = internalName.replace('/', '.');
        if (instances.containsKey(name)) {
            return;
        }
        try {
            instances.put(name, newInstance(load(name), serializationMode));
        } catch (Throwable ignored) {
            // Link phase records the missing owner/target as a partial path.
        }
    }

    private static void linkField(Map<String, Object> instances, Object entryInstance,
                                  String[] link, List<String> unlinked) {
        String fromClass = link[0].replace('/', '.');
        String toClass = link[2].replace('/', '.');
        Object from = instances.get(fromClass);
        Object to = instances.get(toClass);
        if (from == null) {
            unlinked.add(fromClass + "." + link[1] + ":owner-missing");
            return;
        }
        Field field = findField(from.getClass(), link[1]);
        if (field == null) {
            unlinked.add(fromClass + "." + link[1] + ":field-missing");
            return;
        }
        try {
            field.setAccessible(true);
            if (to != null && field.getType().isInstance(to)) {
                field.set(from, to);
            } else if (field.getType() == Object.class) {
                // Keep generic Object fields useful for reflective chains: when the
                // inferred target is unavailable, a safe method-name value is more
                // faithful than recursively assigning the entry host itself.
                field.set(from, to == null ? "toString" : to);
            } else if (Map.class.isAssignableFrom(field.getType())
                    || Set.class.isAssignableFrom(field.getType())
                    || List.class.isAssignableFrom(field.getType())) {
                Object collection = newCollection(field.getType());
                if (collection == null || to == null) {
                    unlinked.add(fromClass + "." + link[1] + ":collection-unlinked");
                    return;
                }
                if (collection instanceof Map) {
                    ((Map<Object, Object>) collection).put(to, "echo CHAIN_OK");
                } else if (collection instanceof Set) {
                    ((Set<Object>) collection).add(to);
                } else {
                    ((List<Object>) collection).add(to);
                }
                field.set(from, collection);
            } else if (!field.getType().isPrimitive() && field.getType() != String.class
                    && !field.getType().isEnum()) {
                unlinked.add(fromClass + "." + link[1] + ":type-mismatch");
            }
        } catch (Throwable failure) {
            unlinked.add(fromClass + "." + link[1] + ":" + failure.getClass().getSimpleName());
        }
    }

    private static void fillSimpleFields(Map<String, Object> instances) {
        for (Object instance : instances.values()) {
            for (Class<?> type = instance.getClass(); type != null && type != Object.class;
                 type = type.getSuperclass()) {
                Field[] fields = type.getDeclaredFields();
                for (Field field : fields) {
                    if (Modifier.isStatic(field.getModifiers())) {
                        continue;
                    }
                    try {
                        field.setAccessible(true);
                        if (field.get(instance) != null) {
                            continue;
                        }
                        Class<?> fieldType = field.getType();
                        if (fieldType == String.class || fieldType == Object.class) {
                            field.set(instance, "toString");
                        } else if (fieldType.isArray()) {
                            field.set(instance, Array.newInstance(fieldType.getComponentType(), 0));
                        } else if (fieldType == int.class || fieldType == Integer.class) {
                            field.set(instance, Integer.valueOf(0));
                        } else if (fieldType == boolean.class || fieldType == Boolean.class) {
                            field.set(instance, Boolean.FALSE);
                        } else if (Map.class.isAssignableFrom(fieldType)
                                || Set.class.isAssignableFrom(fieldType)) {
                            Object collection = newCollection(fieldType);
                            if (collection != null) {
                                field.set(instance, collection);
                            }
                        }
                    } catch (Throwable ignored) {
                    }
                }
            }
        }
    }

    private static void trigger(Class<?> entryType, Object entry, String entryMethod,
                                String entryDescriptor, String mode)
            throws Exception {
        if ("TRIGGER_HASH".equals(mode)) {
            new HashMap<Object, Object>().put(entry, "echo CHAIN_OK");
            return;
        }
        if ("TRIGGER_COMPARETO".equals(mode)) {
            java.util.TreeSet<Object> set = new java.util.TreeSet<Object>();
            set.add(newInstance(entryType, isSerializationMode(mode)));
            set.add(entry);
            return;
        }
        if ("TRIGGER_COMPARATOR".equals(mode)) {
            if (!(entry instanceof java.util.Comparator)) {
                throw new IllegalStateException("entry-not-comparator");
            }
            java.util.TreeMap<Object, Object> map = new java.util.TreeMap<Object, Object>(
                    (java.util.Comparator<Object>) entry);
            map.put("CHAIN_LEFT", "left");
            map.put("CHAIN_RIGHT", "right");
            return;
        }
        if ("TRIGGER_CONTAINS".equals(mode)) {
            List<Object> values = new ArrayList<Object>();
            values.add(new Object());
            values.contains(entry);
            return;
        }
        if ("PROXY".equals(mode)) {
            if (!java.lang.reflect.InvocationHandler.class.isAssignableFrom(entryType)) {
                throw new IllegalStateException("entry-not-handler");
            }
            LegacySandboxSecurityManager.beginProxyBootstrap();
            Object proxy;
            try {
                proxy = java.lang.reflect.Proxy.newProxyInstance(
                        applicationLoader, new Class[]{Runnable.class},
                        (java.lang.reflect.InvocationHandler) entry);
            } finally {
                LegacySandboxSecurityManager.endProxyBootstrap();
            }
            ((Runnable) proxy).run();
            return;
        }
        if ("SERIAL".equals(mode)) {
            LegacySandboxSecurityManager.beginSerializationBootstrap();
            try {
                ByteArrayOutputStream output = new ByteArrayOutputStream();
                ObjectOutputStream objectOutput = new ObjectOutputStream(output);
                objectOutput.writeObject(entry);
                objectOutput.close();
                byte[] bytes = output.toByteArray();
                if (bytes.length > MAX_SERIALIZED_BYTES) {
                    throw new IllegalStateException("serialized-object-too-large");
                }
                ObjectInputStream objectInput = new ObjectInputStream(new BoundedInputStream(
                        new ByteArrayInputStream(bytes), MAX_SERIALIZED_BYTES));
                try {
                    objectInput.readObject();
                } finally {
                    objectInput.close();
                }
            } finally {
                LegacySandboxSecurityManager.endSerializationBootstrap();
            }
            return;
        }
        Method method = findMethod(entryType, entryMethod, entryDescriptor);
        if (method == null) {
            throw new IllegalStateException("entry-method-missing");
        }
        method.setAccessible(true);
        if ("SOURCE".equals(mode)) {
            Class<?>[] types = method.getParameterTypes();
            Object[] values = new Object[types.length];
            for (int i = 0; i < types.length; i++) {
                values[i] = sourceValue(types[i]);
            }
            method.invoke(entry, values);
        } else if (method.getParameterTypes().length == 1
                && method.getParameterTypes()[0] == String.class) {
            method.invoke(entry, "echo CHAIN_OK");
        } else {
            method.invoke(entry);
        }
    }

    private static boolean isSerializationMode(String mode) {
        return "SERIAL".equals(mode) || mode.startsWith("TRIGGER_");
    }

    private static Object newInstance(Class<?> type, boolean serializationMode) throws Exception {
        if (serializationMode && java.io.Serializable.class.isAssignableFrom(type)) {
            Object allocated = allocateWithoutConstructor(type);
            if (allocated != null) {
                return allocated;
            }
            throw new IllegalStateException("constructor-free allocation unavailable: "
                    + type.getName());
        }
        Constructor<?>[] constructors = type.getDeclaredConstructors();
        Constructor<?> best = null;
        for (Constructor<?> constructor : constructors) {
            if (constructor.getParameterTypes().length == 0) {
                best = constructor;
                break;
            }
            if (best == null || constructor.getParameterTypes().length
                    < best.getParameterTypes().length) {
                best = constructor;
            }
        }
        if (best == null) {
            throw new IllegalStateException("no constructor: " + type.getName());
        }
        best.setAccessible(true);
        Class<?>[] parameterTypes = best.getParameterTypes();
        Object[] values = new Object[parameterTypes.length];
        for (int i = 0; i < parameterTypes.length; i++) {
            values[i] = defaultValue(parameterTypes[i]);
        }
        return best.newInstance(values);
    }

    private static Object allocateWithoutConstructor(Class<?> type) {
        boolean bootstrap = false;
        try {
            LegacySandboxSecurityManager.beginSerializationBootstrap();
            bootstrap = true;
            Class<?> unsafeType = ClassLoader.getSystemClassLoader().loadClass("sun.misc.Unsafe");
            Field field = unsafeType.getDeclaredField("theUnsafe");
            field.setAccessible(true);
            Object unsafe = field.get(null);
            Method allocate = unsafeType.getMethod("allocateInstance", Class.class);
            return allocate.invoke(unsafe, type);
        } catch (Throwable ignored) {
            return null;
        } finally {
            if (bootstrap) {
                LegacySandboxSecurityManager.endSerializationBootstrap();
            }
        }
    }

    private static Object defaultValue(Class<?> type) {
        if (type == String.class || type == Object.class) return "toString";
        if (type == int.class) return Integer.valueOf(0);
        if (type == long.class) return Long.valueOf(0L);
        if (type == short.class) return Short.valueOf((short) 0);
        if (type == byte.class) return Byte.valueOf((byte) 0);
        if (type == boolean.class) return Boolean.FALSE;
        if (type == char.class) return Character.valueOf('a');
        if (type == float.class) return Float.valueOf(0.0f);
        if (type == double.class) return Double.valueOf(0.0d);
        if (type.isArray()) return Array.newInstance(type.getComponentType(), 0);
        return null;
    }

    private static Object sourceValue(Class<?> type) {
        if (type == String.class || type == CharSequence.class) return "{}";
        if (type == Object.class) return new java.util.LinkedHashMap<Object, Object>();
        if (type == byte[].class) return "{}".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        if (type == char[].class) return "{}".toCharArray();
        if (InputStream.class.isAssignableFrom(type)) {
            return new ByteArrayInputStream("{}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }
        if (java.io.Reader.class.isAssignableFrom(type)) return new java.io.StringReader("{}");
        if (java.io.OutputStream.class.isAssignableFrom(type)) return new java.io.ByteArrayOutputStream();
        if (Map.class.isAssignableFrom(type)) return new HashMap<Object, Object>();
        if (Set.class.isAssignableFrom(type)) return new HashSet<Object>();
        if (List.class.isAssignableFrom(type)) return new ArrayList<Object>();
        if (type == Class.class) return Object.class;
        if (type.isArray()) return Array.newInstance(type.getComponentType(), 0);
        if (type.isPrimitive()) return defaultValue(type);
        if (type.isEnum()) {
            Object[] values = type.getEnumConstants();
            return values != null && values.length > 0 ? values[0] : null;
        }
        return null;
    }

    private static Object newCollection(Class<?> type) {
        if (!Map.class.isAssignableFrom(type) && !Set.class.isAssignableFrom(type)
                && !List.class.isAssignableFrom(type)) return null;
        boolean abstractType = type.isInterface() || Modifier.isAbstract(type.getModifiers());
        if (!abstractType) {
            try {
                Constructor<?> constructor = type.getDeclaredConstructor();
                constructor.setAccessible(true);
                return constructor.newInstance();
            } catch (Throwable ignored) {
                return null;
            }
        }
        if (java.util.SortedMap.class.isAssignableFrom(type)) return new java.util.TreeMap<Object, Object>();
        if (Map.class.isAssignableFrom(type)) return new HashMap<Object, Object>();
        if (java.util.SortedSet.class.isAssignableFrom(type)) return new java.util.TreeSet<Object>();
        if (Set.class.isAssignableFrom(type)) return new HashSet<Object>();
        if (List.class.isAssignableFrom(type)) return new ArrayList<Object>();
        return null;
    }

    private static Class<?> load(String name) throws ClassNotFoundException {
        ClassLoader loader = applicationLoader != null
                ? applicationLoader : Thread.currentThread().getContextClassLoader();
        if (loader == null) {
            throw new ClassNotFoundException(name);
        }
        return loader.loadClass(name);
    }

    /** Keep the legacy probe/agent loader out of the target application loader. */
    private static void installApplicationLoader() {
        if (applicationLoader != null) {
            return;
        }
        List<URL> urls = new ArrayList<URL>();
        String classPath = System.getProperty("just.verify.target-cp", "");
        if (classPath.length() == 0) {
            // Compatibility for manually launched legacy probes; production children pass a
            // target-only classpath so the system loader does not expose verifier classes.
            classPath = System.getProperty("java.class.path", "");
        }
        String probeJar = System.getProperty("just.verify.probe-jar", "");
        String normalizedProbe = probeJar.length() == 0 ? ""
                : Paths.get(probeJar).toAbsolutePath().normalize().toString();
        String[] entries = classPath.split(java.util.regex.Pattern.quote(
                java.io.File.pathSeparator));
        for (String entry : entries) {
            if (entry.length() == 0) {
                continue;
            }
            try {
                Path normalized = Paths.get(entry).toAbsolutePath().normalize();
                if (normalizedProbe.length() > 0 && normalized.toString().equals(normalizedProbe)) {
                    continue;
                }
                urls.add(normalized.toUri().toURL());
            } catch (RuntimeException | java.net.MalformedURLException ignored) {
                // A malformed optional entry must not widen the target loader.
            }
        }
        ClassLoader parent = ClassLoader.getSystemClassLoader().getParent();
        if (urls.isEmpty()) {
            applicationLoader = parent;
            return;
        }
        try {
            applicationLoader = new URLClassLoader(urls.toArray(new URL[urls.size()]), parent);
            Thread.currentThread().setContextClassLoader(applicationLoader);
        } catch (RuntimeException ignored) {
            applicationLoader = parent;
        }
    }

    private static Field findField(Class<?> type, String name) {
        for (Class<?> current = type; current != null; current = current.getSuperclass()) {
            try {
                return current.getDeclaredField(name);
            } catch (NoSuchFieldException ignored) {
            }
        }
        return null;
    }

    private static Method findMethod(Class<?> type, String name) {
        return findMethod(type, name, "");
    }

    private static Method findMethod(Class<?> type, String name, String descriptor) {
        if (descriptor != null && descriptor.length() > 0) {
            Class<?>[] parameters = parameterTypes(descriptor);
            if (parameters == null) return null;
            try {
                Method publicMethod = type.getMethod(name, parameters);
                if (descriptor.equals(methodDescriptor(publicMethod))) return publicMethod;
            } catch (NoSuchMethodException ignored) {
            } catch (LinkageError ignored) {
                return null;
            }
            for (Class<?> current = type; current != null; current = current.getSuperclass()) {
                try {
                    Method method = current.getDeclaredMethod(name, parameters);
                    return descriptor.equals(methodDescriptor(method)) ? method : null;
                } catch (NoSuchMethodException ignored) {
                } catch (LinkageError ignored) {
                    return null;
                }
            }
            return null;
        }
        try {
            for (Method method : type.getMethods()) {
                if (method.getName().equals(name)) return method;
            }
            for (Class<?> current = type; current != null; current = current.getSuperclass()) {
                for (Method method : current.getDeclaredMethods()) {
                    if (method.getName().equals(name)) return method;
                }
            }
        } catch (LinkageError ignored) {
            // Without a descriptor, reflection cannot safely disambiguate a method after an
            // optional signature failed to resolve. Keep the result partial.
        }
        return null;
    }

    private static Class<?>[] parameterTypes(String descriptor) {
        if (descriptor.length() < 3 || descriptor.charAt(0) != '(') return null;
        List<Class<?>> result = new ArrayList<Class<?>>();
        int[] cursor = new int[]{1};
        try {
            while (cursor[0] < descriptor.length() && descriptor.charAt(cursor[0]) != ')') {
                result.add(descriptorType(descriptor, cursor));
            }
            if (cursor[0] >= descriptor.length() || descriptor.charAt(cursor[0]) != ')') return null;
            cursor[0]++;
            descriptorType(descriptor, cursor);
            return cursor[0] == descriptor.length()
                    ? result.toArray(new Class<?>[result.size()]) : null;
        } catch (ClassNotFoundException | LinkageError | RuntimeException ignored) {
            return null;
        }
    }

    private static Class<?> descriptorType(String descriptor, int[] cursor)
            throws ClassNotFoundException {
        if (cursor[0] >= descriptor.length()) throw new IllegalArgumentException("truncated descriptor");
        char marker = descriptor.charAt(cursor[0]++);
        switch (marker) {
            case 'B': return byte.class;
            case 'C': return char.class;
            case 'D': return double.class;
            case 'F': return float.class;
            case 'I': return int.class;
            case 'J': return long.class;
            case 'S': return short.class;
            case 'Z': return boolean.class;
            case 'V': return void.class;
            case 'L':
                int end = descriptor.indexOf(';', cursor[0]);
                if (end < 0) throw new IllegalArgumentException("unterminated object type");
                String binaryName = descriptor.substring(cursor[0], end).replace('/', '.');
                cursor[0] = end + 1;
                return load(binaryName);
            case '[':
                Class<?> component = descriptorType(descriptor, cursor);
                if (component == void.class) throw new IllegalArgumentException("void array");
                return Array.newInstance(component, 0).getClass();
            default: throw new IllegalArgumentException("unknown descriptor type: " + marker);
        }
    }

    private static boolean matchesDescriptor(Method method, String descriptor) {
        return descriptor == null || descriptor.length() == 0 || descriptor.equals(methodDescriptor(method));
    }

    private static String methodDescriptor(Method method) {
        StringBuilder out = new StringBuilder("(");
        for (Class<?> parameter : method.getParameterTypes()) out.append(typeDescriptor(parameter));
        return out.append(')').append(typeDescriptor(method.getReturnType())).toString();
    }

    private static String typeDescriptor(Class<?> type) {
        if (type.isArray()) return type.getName().replace('.', '/');
        if (!type.isPrimitive()) return "L" + type.getName().replace('.', '/') + ";";
        if (type == void.class) return "V";
        if (type == boolean.class) return "Z";
        if (type == byte.class) return "B";
        if (type == char.class) return "C";
        if (type == short.class) return "S";
        if (type == int.class) return "I";
        if (type == long.class) return "J";
        if (type == float.class) return "F";
        return "D";
    }

    private static String markerSpec(Throwable top) {
        int depth = 0;
        for (Throwable current = top; current != null && depth++ < 6; current = current.getCause()) {
            if (LegacySinkReachedError.class.getName().equals(current.getClass().getName())) {
                return current.getMessage();
            }
        }
        return null;
    }

    private static boolean sameSink(String spec, String sinkClass, String sinkMethod, String descriptor) {
        if (spec == null) return false;
        int first = spec.indexOf('#');
        if (first <= 0) return false;
        String methodAndDescriptor = spec.substring(first + 1);
        int second = methodAndDescriptor.indexOf('#');
        String method = second < 0 ? methodAndDescriptor : methodAndDescriptor.substring(0, second);
        String canaryDescriptor = second < 0 ? "" : methodAndDescriptor.substring(second + 1);
        return spec.substring(0, first).replace('/', '.').equals(sinkClass)
                && method.equals(sinkMethod)
                && (second < 0 || descriptor.length() == 0 || descriptor.equals(canaryDescriptor));
    }

    private static boolean entryReached(Throwable top, String entryClass, String entryMethod) {
        int depth = 0;
        for (Throwable current = top; current != null && depth++ < 6; current = current.getCause()) {
            for (StackTraceElement frame : current.getStackTrace()) {
                if (entryClass.equals(frame.getClassName()) && entryMethod.equals(frame.getMethodName())) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean reachesSink(Throwable top, String sinkClass, String sinkMethod) {
        if (sinkClass.length() == 0 || sinkMethod.length() == 0) return false;
        int depth = 0;
        for (Throwable current = top; current != null && depth++ < 6; current = current.getCause()) {
            StackTraceElement[] frames = current.getStackTrace();
            for (StackTraceElement frame : frames) {
                if (sinkClass.equals(frame.getClassName()) && sinkMethod.equals(frame.getMethodName())) {
                    return true;
                }
            }
            if (frames.length == 0 && getStackTrace(current).indexOf(
                    "at " + sinkClass + "." + sinkMethod + "(") >= 0) return true;
        }
        return false;
    }

    private static String getStackTrace(Throwable failure) {
        java.io.StringWriter writer = new java.io.StringWriter();
        failure.printStackTrace(new java.io.PrintWriter(writer));
        return writer.toString();
    }

    private static final class BoundedInputStream extends FilterInputStream {
        private final long limit;
        private long count;

        private BoundedInputStream(InputStream input, long limit) {
            super(input);
            this.limit = limit;
        }

        @Override
        public int read() throws IOException {
            if (count >= limit) return -1;
            int value = super.read();
            if (value >= 0) count++;
            return value;
        }

        @Override
        public int read(byte[] buffer, int offset, int length) throws IOException {
            if (count >= limit) return -1;
            int allowed = (int) Math.min((long) length, limit - count);
            int read = super.read(buffer, offset, allowed);
            if (read > 0) count += read;
            return read;
        }
    }
}
