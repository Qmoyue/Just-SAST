package io.just.sast.verify;

import io.just.sast.verify.boot.SinkExecutionGate;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Forked, scanner-owned contract for the exact real-sink transformer.  This is deliberately
 * separate from the OS-runner contract: it proves that the target body and verifier-owned JNI
 * fixture really execute, while the opt-in platform tests prove the enclosing OS boundary.
 */
class RealSinkExecutionContractTest {

    @Test
    void exactBodyUsesTypedFixedArgumentsAndStopsNestedFileConstructor() throws Exception {
        ProcessResult result = runChild("body");
        assertEquals(0, result.exitCode(), result.output());
        assertTrue(result.output().contains("BODY=JUST_SAFE_BODY"), result.output());
        assertTrue(result.output().contains("body=1"), result.output());
        assertTrue(result.output().contains("body_returned=1"), result.output());
        assertTrue(result.output().contains("nested_blocked=1"), result.output());
    }

    @Test
    void exactSystemLoadLibraryUsesOnlyTheVerifierOwnedFixture() throws Exception {
        Assumptions.assumeTrue(System.getProperty("os.name", "").toLowerCase()
                .contains("win"), "the checked-in contract fixture is Windows x64");
        ProcessResult result = runChild("jni");
        assertEquals(0, result.exitCode(), result.output());
        assertTrue(result.output().contains("JNI=4a555354"), result.output());
        assertTrue(result.output().contains("native_load=1"), result.output());
        assertTrue(result.output().contains("native_call=1"), result.output());
    }

    @Test
    void nestedConstructorTransformationLoadsAsVerifierValidBytecode() throws Exception {
        ProcessResult result = runChild("constructor");
        assertEquals(0, result.exitCode(), result.output());
        assertTrue(result.output().contains("CONSTRUCTOR=JUST_SAFE_CONSTRUCTOR_BODY"),
                result.output());
        assertTrue(result.output().contains("nested_blocked=1"), result.output());
    }

    @Test
    void exactRuntimeExecReachesTheRealApiWithAFixedCommand() throws Exception {
        ProcessResult result = runChild("runtime");
        assertEquals(0, result.exitCode(), result.output());
        assertTrue(result.output().contains("RUNTIME=0"), result.output());
        assertTrue(result.output().contains("call=1"), result.output());
        assertTrue(result.output().contains("sanitizer=COMMAND_ARRAY_FIXED_JAVA_VERSION"),
                result.output());
    }

    private static ProcessResult runChild(String mode) throws Exception {
        Path java = Path.of(System.getProperty("java.home"), "bin",
                System.getProperty("os.name", "").toLowerCase().contains("win")
                        ? "java.exe" : "java");
        Process process = new ProcessBuilder(java.toString(), "-cp",
                System.getProperty("java.class.path"),
                RealSinkExecutionContractMain.class.getName(), mode)
                .redirectErrorStream(true)
                .start();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (InputStream input = process.getInputStream()) {
            input.transferTo(output);
        }
        return new ProcessResult(process.waitFor(),
                output.toString(StandardCharsets.UTF_8));
    }

    private record ProcessResult(int exitCode, String output) {
    }
}

/** Child entry point kept in test sources so it never becomes a release capability. */
final class RealSinkExecutionContractMain {
    private static final String TOKEN = "contract-token-real-sink";
    private static final String BODY_CLASS = "fixture/RealSinkFixture";
    private static final String BODY_METHOD = "sink";
    private static final String BODY_DESC = "(Ljava/lang/String;I)Ljava/lang/String;";
    private static final String CONSTRUCTOR_CLASS = "fixture/RealSinkConstructorFixture";
    private static final String CONSTRUCTOR_DESC = "(Ljava/lang/String;)Ljava/lang/String;";
    private static final String RUNTIME_CLASS = "fixture/RuntimeExecFixture";
    private static final String RUNTIME_METHOD = "trigger";
    private static final String RUNTIME_DESC = "(Ljava/lang/String;)I";
    private static final String JNI_CLASS = "fixture/NativeFixture";
    private static final String JNI_METHOD = "trigger";
    private static final String JNI_DESC = "()I";

    public static void main(String[] args) throws Exception {
        switch (args.length == 0 ? "" : args[0]) {
            case "body" -> runBody();
            case "constructor" -> runConstructor();
            case "runtime" -> runRuntime();
            case "jni" -> runJni();
            default -> throw new IllegalArgumentException("unknown contract mode");
        }
    }

    private static void runBody() throws Exception {
        String sink = BODY_CLASS + "#" + BODY_METHOD + "#" + BODY_DESC;
        SinkExecutionGate.setExecution("REAL_SANITIZED", BODY_CLASS, BODY_METHOD,
                sink, TOKEN, Files.createTempDirectory("just-real-body-").toString(),
                Path.of(System.getProperty("java.home"), "bin", "java.exe").toString());
        byte[] bytes = transform("fixture/RealSinkFixture.class",
                Map.of(BODY_CLASS, Set.of(BODY_METHOD + "#" + BODY_DESC)),
                "APPLICATION_BODY", BODY_CLASS, BODY_METHOD, BODY_DESC, Map.of());
        Class<?> type = new DefiningLoader().define(BODY_CLASS.replace('/', '.'), bytes);
        Object instance = type.getConstructor().newInstance();
        Object value = type.getMethod(BODY_METHOD, String.class, int.class)
                .invoke(instance, "attacker-value", 99);
        System.out.println("BODY=" + value + ";body=" + (SinkExecutionGate.bodyEntered() ? 1 : 0)
                + ";body_returned=" + (SinkExecutionGate.bodyReturned() ? 1 : 0)
                + ";nested_blocked=" + (SinkExecutionGate.nestedBlocked() ? 1 : 0)
                + ";sanitizer=" + SinkExecutionGate.sanitizer());
    }

    private static void runConstructor() throws Exception {
        Path scratch = Files.createTempDirectory("just-real-constructor-");
        String sink = CONSTRUCTOR_CLASS + "#sink#" + CONSTRUCTOR_DESC;
        SinkExecutionGate.setExecution("REAL_SANITIZED", CONSTRUCTOR_CLASS, "sink", sink,
                TOKEN, scratch.toString(), Path.of(System.getProperty("java.home"), "bin",
                        "java.exe").toString());
        byte[] bytes = transform("fixture/RealSinkConstructorFixture.class",
                Map.of(CONSTRUCTOR_CLASS, Set.of("sink#" + CONSTRUCTOR_DESC)),
                "APPLICATION_BODY", CONSTRUCTOR_CLASS, "sink", CONSTRUCTOR_DESC, Map.of());
        Class<?> type = new DefiningLoader().define(CONSTRUCTOR_CLASS.replace('/', '.'), bytes);
        Object value = type.getMethod("sink", String.class).invoke(
                type.getConstructor().newInstance(), "attacker-value");
        System.out.println("CONSTRUCTOR=" + value + ";nested_blocked="
                + (SinkExecutionGate.nestedBlocked() ? 1 : 0));
    }

    private static void runRuntime() throws Exception {
        String sink = "java/lang/Runtime#exec#([Ljava/lang/String;)Ljava/lang/Process;";
        Path java = Path.of(System.getProperty("java.home"), "bin",
                System.getProperty("os.name", "").toLowerCase().contains("win")
                        ? "java.exe" : "java");
        SinkExecutionGate.setExecution("REAL_SANITIZED", RUNTIME_CLASS, RUNTIME_METHOD,
                sink, TOKEN, Files.createTempDirectory("just-real-runtime-").toString(),
                java.toString());
        byte[] bytes = transform("fixture/RuntimeExecFixture.class",
                Map.of("java/lang/Runtime", Set.of("exec#([Ljava/lang/String;)Ljava/lang/Process;")),
                "RUNTIME_EXEC", RUNTIME_CLASS, RUNTIME_METHOD, RUNTIME_DESC, Map.of());
        Class<?> type = new DefiningLoader().define(RUNTIME_CLASS.replace('/', '.'), bytes);
        Object value = type.getMethod(RUNTIME_METHOD, String.class)
                .invoke(null, "attacker-value");
        System.out.println("RUNTIME=" + value + ";call="
                + (SinkExecutionGate.callObserved() ? 1 : 0)
                + ";sanitizer=" + SinkExecutionGate.sanitizer());
    }

    private static void runJni() throws Exception {
        Path scratch = Files.createTempDirectory("just-real-jni-");
        Path nativePath = scratch.resolve("just-safe-jni.dll");
        try (InputStream input = RealSinkExecutionContractMain.class.getResourceAsStream(
                "/native/windows-x86-64/just-safe-jni.dll")) {
            if (input == null) throw new IOException("native fixture missing");
            Files.copy(input, nativePath);
        }
        String sink = "java/lang/System#loadLibrary#(Ljava/lang/String;)V";
        SinkExecutionGate.setExecution("REAL_SANITIZED", JNI_CLASS, JNI_METHOD, sink,
                TOKEN, scratch.toString(), Path.of(System.getProperty("java.home"), "bin",
                        "java.exe").toString());
        String mapping = "v1," + hex("just-safe-jni.dll") + "=" + hex(nativePath.toString());
        SinkExecutionGate.setNativeMap(TOKEN, mapping);
        byte[] bytes = transform("fixture/NativeFixture.class",
                Map.of("java/lang/System", Set.of("loadLibrary#(Ljava/lang/String;)V")),
                "NATIVE_FIXTURE", JNI_CLASS, JNI_METHOD, JNI_DESC,
                Map.of(JNI_CLASS, Set.of("value#()I")));
        Class<?> type = new NativeDefiningLoader(nativePath).define(JNI_CLASS.replace('/', '.'), bytes);
        Object value = type.getMethod(JNI_METHOD).invoke(null);
        System.out.println("JNI=" + Integer.toHexString((Integer) value)
                + ";native_load=" + (SinkExecutionGate.nativeLoadSucceeded() ? 1 : 0)
                + ";native_call=" + (SinkExecutionGate.nativeCallObserved() ? 1 : 0));
    }

    private static byte[] transform(String resource, Map<String, Set<String>> sinks,
                                    String kind, String entryClass, String entryMethod,
                                    String entryDescriptor,
                                    Map<String, Set<String>> nativeIndex) throws IOException {
        try (InputStream input = RealSinkExecutionContractMain.class.getResourceAsStream(
                "/" + resource)) {
            if (input == null) throw new IOException("fixture missing: " + resource);
            return new SinkCanaryAgent.CanaryTransformer(sinks, TOKEN, true, kind,
                    entryClass, entryMethod, entryDescriptor, nativeIndex)
                    .transform(null, resource.substring(0, resource.length() - ".class".length()),
                            null, null, input.readAllBytes());
        }
    }

    private static String hex(String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        StringBuilder result = new StringBuilder(bytes.length * 2);
        for (byte item : bytes) result.append(String.format("%02x", item & 0xff));
        return result.toString();
    }

    private static class DefiningLoader extends ClassLoader {
        private DefiningLoader() {
            super(RealSinkExecutionContractMain.class.getClassLoader());
        }

        protected Class<?> define(String name, byte[] bytes) {
            return defineClass(name, bytes, 0, bytes.length);
        }
    }

    private static final class NativeDefiningLoader extends DefiningLoader {
        private final Path nativePath;

        private NativeDefiningLoader(Path nativePath) {
            this.nativePath = nativePath;
        }

        @Override
        protected String findLibrary(String name) {
            return "just-safe-jni".equals(name) ? nativePath.toString()
                    : super.findLibrary(name);
        }
    }
}
