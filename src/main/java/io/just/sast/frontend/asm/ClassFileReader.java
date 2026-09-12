package io.just.sast.frontend.asm;

import io.just.sast.model.ClassInfo;
import io.just.sast.run.InputBudget;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.ClassNode;

import java.io.IOException;

/** 单个 class 字节 → ClassInfo。无跨调用状态。 */
public final class ClassFileReader {

    private final FactsExtractor extractor = new FactsExtractor();

    public ClassInfo read(byte[] bytes) {
        ClassNode node = new ClassNode();
        new ClassReader(bytes).accept(node, ClassReader.SKIP_FRAMES);
        return extractor.extract(node);
    }

    /** Read after the allocation-free structural budget preflight. */
    public ClassInfo read(byte[] bytes, InputBudget budget) throws IOException {
        return read(bytes, budget, null);
    }

    /** Read with parser progress charged to a caller-owned tracker. */
    public ClassInfo read(byte[] bytes, InputBudget budget,
                          InputBudget.Tracker tracker) throws IOException {
        if (tracker != null) {
            tracker.checkTime();
        }
        ClassFileLimits.validate(bytes, budget, tracker);
        if (tracker != null) {
            tracker.checkTime();
        }
        return read(bytes);
    }

    /** class 文件头：CA FE BA BE | minor(u2) | major(u2)，major 在偏移 6-7。 */
    public static int majorOf(byte[] bytes) {
        if (bytes.length < 8) {
            return 0;
        }
        return ((bytes[6] & 0xFF) << 8) | (bytes[7] & 0xFF);
    }
}
