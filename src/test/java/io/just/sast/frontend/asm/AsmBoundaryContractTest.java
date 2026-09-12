package io.just.sast.frontend.asm;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertTrue;

class AsmBoundaryContractTest {

    @Test
    void productionAsmReferencesStayInsideFrontendPackage() throws Exception {
        Path root = Path.of("src", "main", "java");
        try (var files = Files.walk(root)) {
            for (Path file : (Iterable<Path>) files.filter(path -> path.toString().endsWith(".java"))::iterator) {
                String normalized = file.toString().replace('\\', '/');
                if (normalized.contains("/frontend/asm/")) {
                    continue;
                }
                String source = Files.readString(file);
                assertTrue(!source.contains("org.objectweb.asm"),
                        "ASM reference leaked outside frontend: " + normalized);
            }
        }
    }
}
