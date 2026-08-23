package io.just.sast.frontend.asm;

import io.just.sast.model.ClassInfo;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.ClassNode;

/** 单个 class 字节 → ClassInfo。无跨调用状态。 */
public final class ClassFileReader {

    private final FactsExtractor extractor = new FactsExtractor();

    public ClassInfo read(byte[] bytes) {
        ClassNode node = new ClassNode();
        new ClassReader(bytes).accept(node, ClassReader.SKIP_FRAMES);
        return extractor.extract(node);
    }

    /** class 文件头：CA FE BA BE | minor(u2) | major(u2)，major 在偏移 6-7。 */
    public static int majorOf(byte[] bytes) {
        if (bytes.length < 8) {
            return 0;
        }
        return ((bytes[6] & 0xFF) << 8) | (bytes[7] & 0xFF);
    }
}
