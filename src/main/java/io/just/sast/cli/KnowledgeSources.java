package io.just.sast.cli;

import io.just.sast.blackboard.KnowledgeSource;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.ServiceLoader;
import java.util.ServiceConfigurationError;
import java.util.Set;
import java.util.Comparator;
import java.util.Iterator;

/** 知识源装配：ServiceLoader 单轨注册（内置与插件统一经 META-INF/services 声明）。 */
public final class KnowledgeSources {

    private KnowledgeSources() {}

    public static List<KnowledgeSource> discover() {
        List<KnowledgeSource> sources = new ArrayList<>();
        Set<String> ids = new HashSet<>();
        Iterator<ServiceLoader.Provider<KnowledgeSource>> providers =
                ServiceLoader.load(KnowledgeSource.class).stream().iterator();
        while (true) {
            ServiceLoader.Provider<KnowledgeSource> provider;
            try {
                if (!providers.hasNext()) {
                    break;
                }
                provider = providers.next();
            } catch (ServiceConfigurationError failure) {
                throw discoveryFailure("PROVIDER_ENUMERATION", failure);
            }
            KnowledgeSource ks;
            try {
                ks = provider.get();
                validateAndAdd(ks, ids, sources);
            } catch (ServiceConfigurationError | LinkageError failure) {
                throw discoveryFailure("PROVIDER_INITIALIZATION", failure);
            } catch (RuntimeException failure) {
                throw discoveryFailure("PROVIDER_CONTRACT", failure);
            }
        }
        sources.sort(Comparator.comparingInt((KnowledgeSource source) -> source.phase().ordinal())
                .thenComparingInt(KnowledgeSource::priority)
                .thenComparing(KnowledgeSource::id));
        return sources;
    }

    private static IllegalStateException discoveryFailure(String phase, Throwable failure) {
        return new IllegalStateException("KNOWLEDGE_SOURCE_DISCOVERY_FAILED:" + phase,
                failure);
    }

    private static void validateAndAdd(KnowledgeSource ks, Set<String> ids,
                                       List<KnowledgeSource> sources) {
        if (ks == null || ks.id() == null || ks.id().isBlank()) {
            throw new IllegalStateException("KNOWLEDGE_SOURCE_INVALID:EMPTY_ID");
        }
        String id = ks.id();
        int contractVersion = ks.contractVersion();
        if (contractVersion != KnowledgeSource.CONTRACT_VERSION) {
            throw new IllegalStateException("KNOWLEDGE_SOURCE_INVALID:VERSION:" + id);
        }
        Set<io.just.sast.blackboard.EventType> interests = ks.interests();
        if (ks.phase() == null || interests == null || interests.stream()
                .anyMatch(java.util.Objects::isNull)) {
            throw new IllegalStateException("KNOWLEDGE_SOURCE_INVALID:METADATA:" + id);
        }
        if (!ids.add(id)) {
            throw new IllegalStateException("KNOWLEDGE_SOURCE_INVALID:DUPLICATE_ID:" + id);
        } else {
            sources.add(ks);
        }
    }
}
