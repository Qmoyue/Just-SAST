package io.just.sast.knowledge.engine;

import java.util.List;

/**
 * Immutable dispatch resolver products.  The resolver may observe hierarchy revisions while it
 * searches; revision is carried with every snapshot so a caller can reject stale cache entries
 * rather than inferring freshness from a mutable map or a free-form note.
 */
public final class ForwardDispatch {
    private ForwardDispatch() {
        // Namespace for typed products; no mutable resolver state is kept here.
    }

    public record Key(String owner, String name, String descriptor) {
        public Key {
            owner = normalize(owner);
            name = normalize(name);
            descriptor = normalize(descriptor);
        }
    }

    public record SelectionKey(String declaredOwner, String universeOwner, String name,
                               String descriptor, boolean serializedValue) {
        public SelectionKey {
            declaredOwner = normalize(declaredOwner);
            universeOwner = normalize(universeOwner);
            name = normalize(name);
            descriptor = normalize(descriptor);
        }
    }

    public record Target(String candidateOwner, String resolvedOwner) {
        public Target {
            candidateOwner = normalize(candidateOwner);
            resolvedOwner = normalize(resolvedOwner);
        }
    }

    public record Candidates(long revision, List<String> raw, boolean truncated) {
        public Candidates {
            if (revision < 0) {
                throw new IllegalArgumentException("negative hierarchy revision");
            }
            raw = raw == null ? List.of() : List.copyOf(raw);
        }
    }

    public record ResolvedCandidates(long revision, List<Target> targets, boolean truncated) {
        public ResolvedCandidates {
            if (revision < 0) {
                throw new IllegalArgumentException("negative hierarchy revision");
            }
            targets = targets == null ? List.of() : List.copyOf(targets);
        }
    }

    private static String normalize(String value) {
        return value == null ? "" : value;
    }
}
