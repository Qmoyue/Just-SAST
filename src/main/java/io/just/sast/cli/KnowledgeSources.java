package io.just.sast.cli;

import io.just.sast.blackboard.KnowledgeSource;
import io.just.sast.util.JustLogger;

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
                // A broken optional provider must not hide valid providers that follow it.
                JustLogger.warn("知识源加载失败，已继续发现其余知识源: {}", failure.toString());
                continue;
            }
            KnowledgeSource ks;
            try {
                ks = provider.get();
                validateAndAdd(ks, ids, sources);
            } catch (ServiceConfigurationError | LinkageError failure) {
                JustLogger.warn("知识源初始化失败，已忽略: {}", failure.toString());
            } catch (RuntimeException failure) {
                // Metadata is plugin code too; a throwing id/phase/interests method is a
                // malformed provider, not a reason to abort discovery of built-ins.
                JustLogger.warn("知识源契约检查失败，已忽略: {}", failure.toString());
            }
        }
        sources.sort(Comparator.comparingInt((KnowledgeSource source) -> source.phase().ordinal())
                .thenComparingInt(KnowledgeSource::priority)
                .thenComparing(KnowledgeSource::id));
        return sources;
    }

    private static void validateAndAdd(KnowledgeSource ks, Set<String> ids,
                                       List<KnowledgeSource> sources) {
        if (ks == null || ks.id() == null || ks.id().isBlank()) {
            JustLogger.warn("知识源契约无效，缺少非空 id，已忽略");
            return;
        }
        String id = ks.id();
        int contractVersion = ks.contractVersion();
        if (contractVersion != KnowledgeSource.CONTRACT_VERSION) {
            JustLogger.warn("知识源契约版本不兼容，已忽略: {} v{}（当前 v{}）",
                    id, contractVersion, KnowledgeSource.CONTRACT_VERSION);
            return;
        }
        Set<io.just.sast.blackboard.EventType> interests = ks.interests();
        if (ks.phase() == null || interests == null || interests.stream()
                .anyMatch(java.util.Objects::isNull)) {
            JustLogger.warn("知识源契约无效，phase/interests 不完整，已忽略: {}", id);
            return;
        }
        if (!ids.add(id)) {
            JustLogger.warn("知识源 id 重复，已忽略: {}", id);
        } else {
            sources.add(ks);
        }
    }
}
