package io.just.sast.verify;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.util.Map;
import java.util.Set;

/**
 * Stable premain compatibility facade. Bytecode parsing/instrumentation lives in the frontend
 * package; the verifier package exposes only the historical entry point and test seam.
 */
public final class SinkCanaryAgent {
    private SinkCanaryAgent() {
    }

    public static void premain(String args, Instrumentation instrumentation) {
        io.just.sast.frontend.asm.SinkCanaryAgent.premain(args, instrumentation);
    }

    public static class CanaryTransformer
            extends io.just.sast.frontend.asm.SinkCanaryAgent.CanaryTransformer
            implements ClassFileTransformer {
        public CanaryTransformer(Map<String, Set<String>> sinks) {
            super(sinks);
        }

        public CanaryTransformer(Map<String, Set<String>> sinks, String token) {
            super(sinks, token);
        }

        public CanaryTransformer(Map<String, Set<String>> sinks, String token,
                                 boolean real, String realKind) {
            super(sinks, token, real, realKind);
        }

        public CanaryTransformer(Map<String, Set<String>> sinks, String token,
                                 boolean real, String realKind,
                                 String entryClass, String entryMethod,
                                 String entryDescriptor, Map<String, Set<String>> nativeIndex) {
            super(sinks, token, real, realKind, entryClass, entryMethod,
                    entryDescriptor, nativeIndex);
        }
    }
}
