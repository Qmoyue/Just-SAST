package io.just.sast.frontend.asm;

import io.just.sast.run.InputBudget;
import io.just.sast.util.IoUtil;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Frontend-owned bytecode fact extractor for the bounded native-method index used by the
 * verifier.  Keeping ASM here prevents the verifier/runtime layer from parsing class files.
 */
public final class NativeMethodIndex {
    private static final int MAX_CLASS_BYTES = 8 * 1024 * 1024;

    private NativeMethodIndex() {
    }

    public static List<String> read(String owner, InputStream input, int limit) throws IOException {
        return read(owner, input, limit, InputBudget.defaults());
    }

    /** Read a class under the shared versioned input budget. */
    public static List<String> read(String owner, InputStream input, int limit,
                                    InputBudget budget) throws IOException {
        InputBudget policy = budget == null ? InputBudget.defaults() : budget;
        return read(owner, input, limit, policy, policy.tracker());
    }

    /**
     * Read a class while contributing to a caller-owned tracker.  Candidate-local callers use
     * this overload so indexing several owners cannot reset the aggregate class/byte/time
     * budget for each stream; the compatibility overload above deliberately keeps its historical
     * one-stream accounting.
     */
    public static List<String> read(String owner, InputStream input, int limit,
                                    InputBudget budget, InputBudget.Tracker tracker)
            throws IOException {
        if (owner == null || owner.isBlank() || input == null || limit <= 0) {
            return List.of();
        }
        InputBudget policy = budget == null ? InputBudget.defaults() : budget;
        InputBudget.Tracker accounting = tracker == null ? policy.tracker() : tracker;
        int cap = (int) Math.min((long) MAX_CLASS_BYTES, policy.maxEntryBytes());
        byte[] bytes;
        try {
            bytes = IoUtil.readAll(input, cap, accounting);
        } catch (IOException bounded) {
            throw new IOException("CLASS_PARSE_BYTES_CAP:" + cap, bounded);
        }
        if (bytes.length == 0) {
            return List.of();
        }
        ClassFileLimits.validate(bytes, policy, accounting);
        List<String> result = new ArrayList<>();
        new ClassReader(bytes).accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                              String signature, String[] exceptions) {
                if ((access & Opcodes.ACC_NATIVE) != 0 && result.size() < limit) {
                    result.add(owner + '#' + name + '#' + descriptor);
                }
                return null;
            }
        }, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        return List.copyOf(result);
    }

    /** Locate the ASM code source for the lifecycle test-probe classpath, if present. */
    public static Path asmCodeSource(ClassLoader loader) {
        try {
            Class<?> asm = Class.forName("org.objectweb.asm.ClassVisitor", false, loader);
            if (asm.getProtectionDomain() == null
                    || asm.getProtectionDomain().getCodeSource() == null) {
                return null;
            }
            return Path.of(asm.getProtectionDomain().getCodeSource().getLocation().toURI());
        } catch (ClassNotFoundException | URISyntaxException | RuntimeException | LinkageError ignored) {
            return null;
        }
    }
}
