package io.just.sast.blackboard;

import io.just.sast.model.ArtifactProvenance;

/**
 * Typed location evidence for one chain hop.
 *
 * <p>A location is proven only when the frozen CPG contains one exact call site.  Synthetic
 * bridge hops, field edges and ambiguous call-site matches remain explicit UNKNOWN values; a
 * report consumer must never mistake a missing offset for a guessed one.</p>
 */
public record HopProvenance(
        Status status,
        Basis basis,
        String methodDescriptor,
        Integer bytecodeOffset,
        int candidateCount,
        ArtifactProvenance artifact) {

    public enum Status {
        PROVEN,
        UNKNOWN
    }

    public enum Basis {
        CALLSITE_EXACT,
        CALLSITE_AMBIGUOUS,
        CALLSITE_NOT_FOUND,
        ENTRY_BOUNDARY,
        FIELD_FLOW_NO_CALLSITE,
        SYNTHETIC_HOP,
        MISSING_DESCRIPTOR,
        GRAPH_UNAVAILABLE
    }

    public HopProvenance {
        status = status == null ? Status.UNKNOWN : status;
        basis = basis == null ? Basis.SYNTHETIC_HOP : basis;
        methodDescriptor = methodDescriptor == null || methodDescriptor.isBlank()
                ? "UNKNOWN" : methodDescriptor.trim();
        if (bytecodeOffset != null && bytecodeOffset < 0) {
            throw new IllegalArgumentException("bytecode offset must be non-negative");
        }
        if (candidateCount < 0) {
            throw new IllegalArgumentException("call-site candidate count must be non-negative");
        }
        if (status == Status.PROVEN && bytecodeOffset == null) {
            throw new IllegalArgumentException("proven hop location requires a bytecode offset");
        }
        if (status == Status.UNKNOWN && bytecodeOffset != null) {
            throw new IllegalArgumentException("unknown hop location cannot carry an offset");
        }
    }

    public static HopProvenance exact(String methodDescriptor, int bytecodeOffset,
                                      ArtifactProvenance artifact) {
        return new HopProvenance(Status.PROVEN, Basis.CALLSITE_EXACT, methodDescriptor,
                bytecodeOffset, 1, artifact);
    }

    public static HopProvenance unknown(String methodDescriptor, Basis basis, int candidateCount,
                                        ArtifactProvenance artifact) {
        return new HopProvenance(Status.UNKNOWN, basis, methodDescriptor, null,
                candidateCount, artifact);
    }
}
