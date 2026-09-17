package io.just.sast.frontend.asm;

import io.just.sast.model.ClassInfo;
import io.just.sast.model.FieldInfo;
import io.just.sast.model.FieldRef;
import io.just.sast.model.HandleRef;
import io.just.sast.model.InsnFact;
import io.just.sast.model.InvokeDynamicRef;
import io.just.sast.model.LoadResult;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.MethodRef;
import io.just.sast.model.Op;
import io.just.sast.model.TryCatchFact;
import io.just.sast.model.TypeRef;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.InputStream;
import java.io.IOException;
import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import io.just.sast.run.InputBudget;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BytecodeFrontendTest {

    @TempDir
    Path temp;

    @Test
    void rejectsClassPathAndInternalNameMismatch() throws Exception {
        byte[] bytes = fixtureBytes();
        BytecodeFrontend.Inputs inputs = new BytecodeFrontend.Inputs(
                List.of(new ClassBytes("wrong/Name", bytes, "wrong/Name.class")),
                List.of(), List.of());

        var result = new BytecodeFrontend().load(inputs);

        assertTrue(result.classes().isEmpty());
        assertEquals(1, result.diagnosticCount());
        assertTrue(result.diagnostics().get(0).message().contains("CLASS_NAME_MISMATCH"),
                result.diagnostics().toString());
    }

    @Test
    void reportsDuplicateClassWhenMergingInputs() throws Exception {
        byte[] bytes = fixtureBytes();
        String name = "io/just/sast/frontend/asm/BytecodeFrontendTest";
        BytecodeFrontend.Inputs inputs = new BytecodeFrontend.Inputs(
                List.of(new ClassBytes(name, bytes, "first.class"),
                        new ClassBytes(name, bytes, "second.class")),
                List.of(), List.of());

        var result = new BytecodeFrontend().load(inputs);

        assertEquals(1, result.classCount());
        assertTrue(result.completenessReasons().contains("DUPLICATE_CLASS:" + name),
                result.completenessReasons().toString());
    }

    @Test
    void missingTypeFactsAreExactAndNeverInferCoordinates() {
        String owner = "fixture/Entry";
        MethodInfo method = new MethodInfo(owner, "run",
                "(Lmissing/Parameter;[Lmissing/Array;)Lmissing/Return;",
                Modifier.PUBLIC,
                List.of(
                        new InsnFact(0, Op.INVOKEVIRTUAL, List.of(new MethodRef(
                                "missing/Owner", "call", "()Lmissing/Result;"))),
                        new InsnFact(1, Op.GETFIELD, List.of(new FieldRef(
                                "missing/FieldOwner", "value", "Lmissing/FieldValue;"))),
                        new InsnFact(2, Op.CHECKCAST, List.of(new TypeRef("Lmissing/Type;"))),
                        new InsnFact(3, Op.LDC, List.of(new HandleRef(1, "missing/Handle",
                                "load", "(Lmissing/HandleArg;)Lmissing/HandleRet;"))),
                        new InsnFact(4, Op.INVOKEDYNAMIC, List.of(new InvokeDynamicRef(
                                "make", "(Lmissing/DynamicArg;)Lmissing/DynamicRet;",
                                new HandleRef(6, "missing/Bootstrap", "bootstrap",
                                        "(Lmissing/BootstrapArg;)Lmissing/BootstrapResult;"),
                                List.of(new TypeRef("Lmissing/BootstrapType;"),
                                        new MethodRef("missing/BootstrapTarget", "target",
                                                "()Lmissing/BootstrapResult;"))))),
                        new InsnFact(5, Op.RETURN, List.of())),
                List.of(new TryCatchFact(0, 5, 5, "missing/Error")), false, -1,
                List.of("Lmissing/MethodAnnotation;"));
        ClassInfo entry = new ClassInfo(owner, "missing/Base", List.of("missing/Interface"),
                Modifier.PUBLIC, List.of(method),
                List.of(new FieldInfo(owner, "values", "[Lmissing/Field;", Modifier.PRIVATE,
                        null, "Ljava/util/List<Lmissing/Generic;>;")),
                List.of("Lmissing/Annotation;"));
        ClassInfo defined = new ClassInfo("missing/Defined", "java/lang/Object", List.of(),
                Modifier.PUBLIC, List.of(new MethodInfo("missing/Defined", "value", "()V",
                        Modifier.PUBLIC, List.of(new InsnFact(0, Op.RETURN, List.of())),
                        List.of(), false)), List.of());
        MethodInfo definedReference = new MethodInfo(owner, "defined", "()Lmissing/Defined;",
                Modifier.PUBLIC, List.of(new InsnFact(0, Op.RETURN, List.of())), List.of(), false);
        entry = new ClassInfo(owner, entry.superName(), entry.interfaces(), entry.access(),
                List.of(method, definedReference), entry.fields(), entry.annotationDescriptors());

        LoadResult load = new LoadResult(Map.of(entry.internalName(), entry,
                defined.internalName(), defined), List.of(), 2, 61);

        assertEquals(List.of(
                "missing/Annotation", "missing/Array", "missing/Base", "missing/Bootstrap",
                "missing/BootstrapArg",
                "missing/BootstrapResult", "missing/BootstrapTarget", "missing/BootstrapType",
                "missing/DynamicArg", "missing/DynamicRet", "missing/Error", "missing/Field",
                "missing/FieldOwner", "missing/FieldValue", "missing/Generic", "missing/Handle",
                "missing/HandleArg", "missing/HandleRet", "missing/Interface", "missing/MethodAnnotation",
                "missing/Owner", "missing/Parameter", "missing/Result", "missing/Return",
                "missing/Type"), BytecodeFrontend.missingNonPlatformTypes(load));
    }

    @Test
    void legacyInputsWithoutCallerContextAreExplicitlyPartial() throws Exception {
        byte[] bytes = fixtureBytes();
        String name = "io/just/sast/frontend/asm/BytecodeFrontendTest";
        BytecodeFrontend.Inputs inputs = new BytecodeFrontend.Inputs(
                List.of(new ClassBytes(name, bytes, "legacy.class")), List.of(), List.of());

        var result = new BytecodeFrontend().load(inputs);

        assertEquals(1, result.classCount());
        assertTrue(result.completenessReasons().contains(
                "INPUT_BUDGET_CALLER_CONTEXT_MISSING"), result.completenessReasons().toString());
    }

    @Test
    void inputsCannotClaimCallerContextWithoutTracker() throws Exception {
        byte[] bytes = fixtureBytes();
        String name = "io/just/sast/frontend/asm/BytecodeFrontendTest";
        BytecodeFrontend.Inputs forged = new BytecodeFrontend.Inputs(
                List.of(new ClassBytes(name, bytes, "forged.class")), List.of(), List.of(),
                null, true);

        assertTrue(!forged.callerContextProvided(),
                "a null tracker must fail closed even when a legacy caller sets the flag");
        var result = new BytecodeFrontend().load(forged);
        assertTrue(result.completenessReasons().contains(
                "INPUT_BUDGET_CALLER_CONTEXT_MISSING"), result.completenessReasons().toString());
    }

    @Test
    void inputsExposeClosedCallerContextStatus() throws Exception {
        byte[] bytes = fixtureBytes();
        String name = "io/just/sast/frontend/asm/BytecodeFrontendTest";
        BytecodeFrontend.Inputs missing = new BytecodeFrontend.Inputs(
                List.of(new ClassBytes(name, bytes, "missing.class")), List.of(), List.of());
        assertEquals(BytecodeFrontend.CallerContextStatus.MISSING,
                missing.callerContextStatus());

        BytecodeFrontend.Inputs local = new BytecodeFrontend.Inputs(
                List.of(new ClassBytes(name, bytes, "local.class")), List.of(), List.of(),
                InputBudget.defaults().tracker(), false);
        assertEquals(BytecodeFrontend.CallerContextStatus.LOCAL_TRACKER,
                local.callerContextStatus());

        BytecodeFrontend.Inputs owned = new BytecodeFrontend.Inputs(
                List.of(new ClassBytes(name, bytes, "owned.class")), List.of(), List.of(),
                InputBudget.defaults().tracker(), true);
        assertEquals(BytecodeFrontend.CallerContextStatus.CALLER_OWNED,
                owned.callerContextStatus());
    }

    @Test
    void compatibilityReadWithoutCallerTrackerRemainsExplicitlyPartial() throws Exception {
        Path input = temp.resolve("legacy-read");
        Path relative = Path.of("io", "just", "sast", "frontend", "asm",
                "BytecodeFrontendTest.class");
        Files.createDirectories(input.resolve(relative).getParent());
        Files.write(input.resolve(relative), fixtureBytes());

        BytecodeFrontend frontend = new BytecodeFrontend();
        BytecodeFrontend.Inputs inputs = frontend.read(List.of(input));
        assertTrue(!inputs.callerContextProvided(),
                "the compatibility read overload must not claim scan-wide ownership");

        var result = frontend.load(inputs);
        assertTrue(result.completenessReasons().contains(
                "INPUT_BUDGET_CALLER_CONTEXT_MISSING"), result.completenessReasons().toString());
    }

    @Test
    void typedUniverseCarriesContentIdentityWithoutRetainingRawBytes() throws Exception {
        Path input = Files.createTempDirectory("just-frontend-");
        Path classFile = input.resolve("io/just/sast/frontend/asm/BytecodeFrontendTest.class");
        Files.createDirectories(classFile.getParent());
        try {
            Files.write(classFile, fixtureBytes());
            var universe = new BytecodeFrontend().loadUniverse(List.of(input));
            assertEquals(1, universe.artifacts().size());
            assertTrue(universe.artifacts().get(0).hasContentDigest());
            assertEquals(1, universe.classCount());
            assertTrue(universe.semanticDigest().matches("[0-9a-f]{64}"));
        } finally {
            try (var walk = Files.walk(input)) {
                walk.sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
                    try {
                        Files.deleteIfExists(path);
                    } catch (Exception ignored) {
                    }
                });
            }
        }
    }

    @Test
    void streamingUsesCallerOwnedTrackerAcrossMultipleArtifacts() throws Exception {
        Path first = temp.resolve("first");
        Path second = temp.resolve("second");
        Path relative = Path.of("io", "just", "sast", "frontend", "asm",
                "BytecodeFrontendTest.class");
        Files.createDirectories(first.resolve(relative).getParent());
        Files.createDirectories(second.resolve(relative).getParent());
        Files.write(first.resolve(relative), fixtureBytes());
        Files.write(second.resolve(relative), fixtureBytes());

        InputBudget defaults = InputBudget.defaults();
        InputBudget tiny = new InputBudget(defaults.schemaVersion(), defaults.maxPhysicalBytes(),
                defaults.maxCompressedBytes(), defaults.maxUncompressedBytes(), defaults.maxEntryBytes(),
                defaults.maxCompressionRatio(), 12, defaults.maxArchiveNesting(), defaults.maxClassEntries(),
                defaults.maxRuleInputBytes(), defaults.maxRuleCodePoints(), defaults.maxRuleAliases(),
                defaults.maxRuleNestingDepth(), defaults.maxRuleDocuments(), defaults.maxRuleCount(),
                defaults.maxRuleCollectionItems(), defaults.maxRuleNodes(), defaults.maxRuleScalarChars(),
                defaults.maxPathChars(), defaults.maxParseMillis());
        InputBudget.Tracker tracker = tiny.tracker();

        var result = new BytecodeFrontend(tiny).loadStreaming(List.of(first, second), 0, tracker);

        assertEquals(1, result.classCount(), "the second artifact must hit the shared entry cap");
        assertTrue(result.completenessReasons().stream()
                .anyMatch(reason -> reason.startsWith("ARCHIVE_ENTRY_CAP")
                        || reason.startsWith("ARCHIVE_ENTRY_BYTES_CAP")),
                result.completenessReasons().toString());
        assertEquals(13, tracker.entries(), "the caller tracker must observe both artifacts");
    }

    @Test
    void readThenLoadRetainsCallerTrackerInsteadOfResettingParserBudget() throws Exception {
        Path input = temp.resolve("raw-input");
        Path relative = Path.of("io", "just", "sast", "frontend", "asm",
                "BytecodeFrontendTest.class");
        Files.createDirectories(input.resolve(relative).getParent());
        Files.write(input.resolve(relative), fixtureBytes());

        class FailingAfterReadTracker extends InputBudget.Tracker {
            private boolean fail;

            FailingAfterReadTracker(InputBudget budget) {
                super(budget);
            }

            void failOnNextCheck() {
                fail = true;
            }

            @Override
            public synchronized void checkTime() throws IOException {
                if (fail) {
                    throw new IOException("CONTRACT_CALLER_TRACKER_REUSED");
                }
                super.checkTime();
            }
        }

        FailingAfterReadTracker tracker = new FailingAfterReadTracker(InputBudget.defaults());
        BytecodeFrontend frontend = new BytecodeFrontend(InputBudget.defaults());
        BytecodeFrontend.Inputs inputs = frontend.read(List.of(input), 0, tracker);
        tracker.failOnNextCheck();

        var result = frontend.load(inputs);

        assertEquals(1, result.diagnosticCount(),
                "load(Inputs) must continue using the read caller tracker");
        assertTrue(result.diagnostics().get(0).message()
                        .contains("CONTRACT_CALLER_TRACKER_REUSED"),
                result.diagnostics().toString());
    }

    @Test
    void scopedStreamingKeepsOnlyFirstArtifactClassesAsApplicationOwned() throws Exception {
        Path application = temp.resolve("application");
        Path dependency = temp.resolve("dependency");
        Path applicationClass = application.resolve("io/just/sast/frontend/asm/BytecodeFrontendTest.class");
        Path dependencyClass = dependency.resolve(
                "io/just/sast/analysis/entry/ApplicationEntryIndexContractTest.class");
        Files.createDirectories(applicationClass.getParent());
        Files.createDirectories(dependencyClass.getParent());
        Files.write(applicationClass, fixtureBytes());
        try (InputStream input = BytecodeFrontendTest.class.getResourceAsStream(
                "/io/just/sast/analysis/entry/ApplicationEntryIndexContractTest.class")) {
            if (input == null) {
                throw new IOException("test fixture class resource is missing");
            }
            Files.write(dependencyClass, input.readAllBytes());
        }

        BytecodeFrontend.ScopedLoad scoped = new BytecodeFrontend(InputBudget.defaults())
                .loadStreamingWithApplicationScope(List.of(application, dependency), 0,
                        InputBudget.defaults().tracker());

        assertEquals(2, scoped.load().classCount());
        assertTrue(scoped.applicationClassNames().contains(
                "io/just/sast/frontend/asm/BytecodeFrontendTest"));
        assertTrue(!scoped.applicationClassNames().contains(
                "io/just/sast/analysis/entry/ApplicationEntryIndexContractTest"));
    }

    @Test
    void scopedStreamingCapturesDirectArtifactIndexesAndConflicts() throws Exception {
        Path application = temp.resolve("application-conflict");
        Path dependency = temp.resolve("dependency-conflict");
        Path relative = Path.of("io", "just", "sast", "frontend", "asm",
                "BytecodeFrontendTest.class");
        Files.createDirectories(application.resolve(relative).getParent());
        Files.createDirectories(dependency.resolve(relative).getParent());
        Files.write(application.resolve(relative), fixtureBytes());
        Files.write(dependency.resolve(relative), fixtureBytes());

        BytecodeFrontend.ScopedLoad scoped = new BytecodeFrontend(InputBudget.defaults())
                .loadStreamingWithApplicationScope(List.of(application, dependency), 17,
                        InputBudget.defaults().tracker());
        String className = "io/just/sast/frontend/asm/BytecodeFrontendTest";

        assertEquals(0, scoped.classArtifactIndexes().get(className));
        assertEquals(List.of(1), scoped.duplicateArtifactIndexes().get(className));
        assertTrue(scoped.applicationClassNames().contains(className));
    }

    @Test
    void scopedStreamingExcludesEmbeddedFatJarLibrariesFromApplicationOwnership() throws Exception {
        byte[] appBytes = fixtureBytes();
        byte[] dependencyBytes;
        try (InputStream input = BytecodeFrontendTest.class.getResourceAsStream(
                "/io/just/sast/analysis/entry/ApplicationEntryIndexContractTest.class")) {
            if (input == null) {
                throw new IOException("dependency fixture class resource is missing");
            }
            dependencyBytes = input.readAllBytes();
        }
        Path nested = temp.resolve("dependency.jar");
        try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(nested))) {
            zip.putNextEntry(new ZipEntry("io/just/sast/analysis/entry/ApplicationEntryIndexContractTest.class"));
            zip.write(dependencyBytes);
            zip.closeEntry();
        }
        Path fat = temp.resolve("application-fat.jar");
        try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(fat))) {
            zip.putNextEntry(new ZipEntry(
                    "BOOT-INF/classes/io/just/sast/frontend/asm/BytecodeFrontendTest.class"));
            zip.write(appBytes);
            zip.closeEntry();
            zip.putNextEntry(new ZipEntry("BOOT-INF/lib/dependency.jar"));
            zip.write(Files.readAllBytes(nested));
            zip.closeEntry();
        }

        BytecodeFrontend.ScopedLoad scoped = new BytecodeFrontend(InputBudget.defaults())
                .loadStreamingWithApplicationScope(List.of(fat), 17,
                        InputBudget.defaults().tracker());

        assertEquals(2, scoped.load().classCount());
        assertTrue(scoped.applicationClassNames().contains(
                "io/just/sast/frontend/asm/BytecodeFrontendTest"));
        assertTrue(!scoped.applicationClassNames().contains(
                "io/just/sast/analysis/entry/ApplicationEntryIndexContractTest"),
                "embedded BOOT-INF/lib classes must remain dependency-owned");
        assertEquals(List.of("nested:BOOT-INF/lib/dependency.jar"), scoped.artifactDetails().get(
                "io/just/sast/analysis/entry/ApplicationEntryIndexContractTest"));
    }

    @Test
    void scopedStreamingExcludesEmbeddedWarLibrariesFromApplicationOwnership() throws Exception {
        byte[] appBytes = fixtureBytes();
        byte[] dependencyBytes;
        try (InputStream input = BytecodeFrontendTest.class.getResourceAsStream(
                "/io/just/sast/analysis/entry/ApplicationEntryIndexContractTest.class")) {
            if (input == null) {
                throw new IOException("dependency fixture class resource is missing");
            }
            dependencyBytes = input.readAllBytes();
        }

        Path nested = temp.resolve("war-dependency.jar");
        try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(nested))) {
            zip.putNextEntry(new ZipEntry("io/just/sast/analysis/entry/ApplicationEntryIndexContractTest.class"));
            zip.write(dependencyBytes);
            zip.closeEntry();
        }
        Path war = temp.resolve("application.war");
        try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(war))) {
            zip.putNextEntry(new ZipEntry(
                    "WEB-INF/classes/io/just/sast/frontend/asm/BytecodeFrontendTest.class"));
            zip.write(appBytes);
            zip.closeEntry();
            zip.putNextEntry(new ZipEntry("WEB-INF/lib/war-dependency.jar"));
            zip.write(Files.readAllBytes(nested));
            zip.closeEntry();
        }

        BytecodeFrontend.ScopedLoad scoped = new BytecodeFrontend(InputBudget.defaults())
                .loadStreamingWithApplicationScope(List.of(war), 17,
                        InputBudget.defaults().tracker());

        assertEquals(2, scoped.load().classCount());
        assertTrue(scoped.applicationClassNames().contains(
                "io/just/sast/frontend/asm/BytecodeFrontendTest"));
        assertTrue(!scoped.applicationClassNames().contains(
                "io/just/sast/analysis/entry/ApplicationEntryIndexContractTest"),
                "embedded WEB-INF/lib classes must remain dependency-owned");
    }

    @Test
    void scopedStreamingAcceptsUnicodeAndSpaceDirectoryPaths() throws Exception {
        Path input = temp.resolve("目录 with spaces").resolve("app classes");
        Path relative = Path.of("io", "just", "sast", "frontend", "asm",
                "BytecodeFrontendTest.class");
        Files.createDirectories(input.resolve(relative).getParent());
        Files.write(input.resolve(relative), fixtureBytes());

        BytecodeFrontend.ScopedLoad scoped = new BytecodeFrontend(InputBudget.defaults())
                .loadStreamingWithApplicationScope(List.of(input), 17,
                        InputBudget.defaults().tracker());

        assertEquals(1, scoped.load().classCount());
        assertTrue(scoped.load().diagnostics().isEmpty(), scoped.load().diagnostics().toString());
        assertTrue(scoped.applicationClassNames().contains(
                "io/just/sast/frontend/asm/BytecodeFrontendTest"));
    }

    private static byte[] fixtureBytes() throws Exception {
        try (InputStream input = BytecodeFrontendTest.class.getResourceAsStream(
                "/io/just/sast/frontend/asm/BytecodeFrontendTest.class")) {
            if (input == null) {
                throw new IllegalStateException("test class resource missing");
            }
            return input.readAllBytes();
        }
    }
}
