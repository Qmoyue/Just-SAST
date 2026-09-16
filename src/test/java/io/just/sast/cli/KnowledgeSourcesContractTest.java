package io.just.sast.cli;

import io.just.sast.blackboard.KnowledgeSource;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KnowledgeSourcesContractTest {

    @Test
    void bundledKnowledgeSourcesHaveACompleteTypedRegistration() {
        List<KnowledgeSource> sources = KnowledgeSources.discover();

        assertFalse(sources.isEmpty());
        assertTrue(sources.stream().allMatch(source -> source.id() != null
                && !source.id().isBlank()
                && source.interests() != null
                && source.interests().stream().noneMatch(Objects::isNull)
                && source.phase() != null
                && source.contractVersion() == KnowledgeSource.CONTRACT_VERSION));
        assertNotEquals(0, sources.stream().map(KnowledgeSource::id).distinct().count());
        assertTrue(sources.stream().map(KnowledgeSource::id).distinct().count()
                == sources.size(), "knowledge source ids must be unique");
    }
}
