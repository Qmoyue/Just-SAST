package io.just.sast.blackboard;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * Owns the mutable chain/evidence state for one scan.
 *
 * <p>The blackboard remains the collaboration boundary, but it should not also be the
 * implementation of chain identity, merge, calibration and note storage.  Keeping those
 * related maps behind one small owner makes key transfer atomic and leaves the rest of the
 * blackboard focused on facts, events and scan-wide state.</p>
 */
final class ChainStore {

    record AddResult(boolean accepted, boolean publishFoundEvent) {
    }

    private final List<Chain> chains = new ArrayList<>();
    private final Set<String> chainKeys = new HashSet<>();
    private final Map<String, String> semanticKeys = new HashMap<>();
    private final Map<String, Chain> chainsByKey = new HashMap<>();
    /** Key-to-slot index keeps semantic replacement out of the O(number of chains) hot path. */
    private final Map<String, Integer> chainIndexes = new HashMap<>();
    private final Map<String, String> calibrations = new HashMap<>();
    private final Map<String, List<String>> notes = new HashMap<>();
    private long revision;
    private long sortedRevision = -1L;
    private List<Chain> sortedSnapshot = List.of();

    synchronized AddResult add(Chain chain) {
        if (chain == null) {
            return new AddResult(false, false);
        }
        String semanticKey = ChainMerge.semanticKey(chain);
        String existingKey = semanticKeys.get(semanticKey);
        if (existingKey != null) {
            Chain existing = chainsByKey.get(existingKey);
            Chain chosen = ChainMerge.preferred(existing, chain);
            Chain other = chosen == existing ? chain : existing;
            mergeReasons(chosen, other);
            if (chosen == existing) {
                return new AddResult(false, false);
            }
            Integer index = chainIndexes.get(existingKey);
            if (index == null || index < 0 || index >= chains.size()
                    || !java.util.Objects.equals(chains.get(index).key(), existingKey)) {
                return new AddResult(false, false);
            }
            chains.set(index, chosen);
            chainKeys.remove(existingKey);
            chainKeys.add(chosen.key());
            chainsByKey.remove(existingKey);
            chainsByKey.put(chosen.key(), chosen);
            chainIndexes.remove(existingKey);
            chainIndexes.put(chosen.key(), index);
            semanticKeys.put(semanticKey, chosen.key());
            transferEvidence(existingKey, chosen.key());
            revision++;
            sortedRevision = -1L;
            return new AddResult(true, false);
        }
        if (!chainKeys.add(chain.key())) {
            return new AddResult(false, false);
        }
        chains.add(chain);
        chainsByKey.put(chain.key(), chain);
        chainIndexes.put(chain.key(), chains.size() - 1);
        semanticKeys.put(semanticKey, chain.key());
        revision++;
        sortedRevision = -1L;
        return new AddResult(true, true);
    }

    synchronized List<Chain> snapshot() {
        if (sortedRevision != revision) {
            List<Chain> snapshot = new ArrayList<>(chains);
            snapshot.sort(Comparator.comparing(Chain::key));
            sortedSnapshot = List.copyOf(snapshot);
            sortedRevision = revision;
        }
        return sortedSnapshot;
    }

    synchronized void sortForPhase() {
        chains.sort(Comparator.comparing(Chain::key));
        rebuildIndexes();
        sortedSnapshot = List.copyOf(chains);
        sortedRevision = revision;
    }

    synchronized void calibrate(String chainKey, String reason) {
        if (chainKey != null && !chainKey.isBlank() && reason != null && !reason.isBlank()) {
            calibrations.put(chainKey, reason);
        }
    }

    synchronized String calibrationOf(String chainKey) {
        return calibrations.get(chainKey);
    }

    synchronized Map<String, String> calibrations() {
        return java.util.Collections.unmodifiableMap(new TreeMap<>(calibrations));
    }

    synchronized int calibrationCount() {
        return calibrations.size();
    }

    synchronized void note(String chainKey, String note) {
        if (chainKey == null || chainKey.isBlank() || note == null || note.isBlank()) {
            return;
        }
        List<String> chainNotes = notes.computeIfAbsent(chainKey, ignored -> new ArrayList<>(1));
        if (!chainNotes.contains(note)) {
            chainNotes.add(note);
            chainNotes.sort(String::compareTo);
        }
    }

    synchronized List<String> notesOf(String chainKey) {
        List<String> chainNotes = notes.get(chainKey);
        return chainNotes == null || chainNotes.isEmpty() ? List.of() : List.copyOf(chainNotes);
    }

    private void rebuildIndexes() {
        chainIndexes.clear();
        for (int index = 0; index < chains.size(); index++) {
            chainIndexes.put(chains.get(index).key(), index);
        }
    }

    private void mergeReasons(Chain chosen, Chain other) {
        for (String reason : ChainMerge.reasons(other)) {
            note(chosen.key(), "merge:hop-reason=" + reason);
        }
        for (String reason : ChainMerge.reasons(chosen)) {
            note(chosen.key(), "merge:hop-reason=" + reason);
        }
    }

    private void transferEvidence(String oldKey, String newKey) {
        List<String> oldNotes = notes.remove(oldKey);
        if (oldNotes != null) {
            for (String note : oldNotes) {
                note(newKey, note);
            }
        }
        String oldCalibration = calibrations.remove(oldKey);
        if (oldCalibration != null) {
            calibrations.putIfAbsent(newKey, oldCalibration);
        }
    }
}
