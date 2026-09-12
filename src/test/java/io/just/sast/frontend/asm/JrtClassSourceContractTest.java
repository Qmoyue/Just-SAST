package io.just.sast.frontend.asm;

import io.just.sast.run.InputBudget;
import io.just.sast.util.ArchiveLimits;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;

/** Contract for JRT class-entry identity checks shared by the runtime and external providers. */
class JrtClassSourceContractTest {

    @Test
    void runtimeProviderLoadsCoreClassesWhenNofollowIsUnsupported() {
        try (JrtClassSource jrt = JrtClassSource.runtime()) {
            assertTrue(jrt.loadBytes("java/util/List") != null,
                    "the immutable JRT provider rejects NOFOLLOW_LINKS; the source must use its "
                            + "provider-compatible read path");
            assertTrue(jrt.loadBytes("java/lang/Object") != null,
                    "runtime JRT core class lookup must remain available");
        }
    }

    @Test
    void runtimeProviderLoadsDesktopSerializationFragmentClasses() {
        try (JrtClassSource jrt = JrtClassSource.runtime()) {
            assertTrue(jrt.moduleOf("javax/swing/event/EventListenerList") != null,
                    "java.desktop must remain available for declared serialization fragments");
            assertTrue(jrt.loadBytes("javax/swing/event/EventListenerList") != null);
            assertTrue(jrt.loadBytes("javax/swing/undo/UndoManager") != null);
        }
    }

    @Test
    void packageIndexUsesCallerBudgetAndStopsBeforeFullImageFallback() {
        InputBudget policy = InputBudget.defaults().withArchiveLimits(
                32L * 1024L * 1024L, 32L * 1024L * 1024L, 32L * 1024L * 1024L,
                32L * 1024L * 1024L, 1, 2, 128);
        InputBudget.Tracker tracker = policy.tracker();
        try (JrtClassSource jrt = JrtClassSource.runtime(policy, tracker)) {
            assertTrue(jrt.moduleOf("javax/naming/InitialContext") != null,
                    "the first package lookup should consume the one-entry allowance");
            assertTrue(jrt.moduleOf("javax/swing/event/EventListenerList") == null,
                    "a second package lookup must not fall through to an unbounded module walk");
            assertFalse(jrt.completenessReasons().isEmpty(),
                    "budget exhaustion must remain visible as a typed completeness reason");
            assertTrue(tracker.entries() > policy.maxArchiveEntries(),
                    "the shared tracker retains the rejected package-index attempt");
        }
    }

    @Test
    void replacedClassEntryFailsClosed(@TempDir Path temp) throws Exception {
        Path classFile = temp.resolve("A.class");
        Files.write(classFile, new byte[] {0, 1, 2, 3});
        JrtClassSource.ClassEntrySnapshot snapshot =
                JrtClassSource.snapshotClassEntryForContract(classFile);
        assertTrue(snapshot.identityStrength() == ArchiveLimits.IdentityStrength.FILE_KEY_METADATA
                        || snapshot.identityStrength() == ArchiveLimits.IdentityStrength.METADATA_ONLY,
                "filesystem class entries must disclose the identity strength actually available");
        Files.write(classFile, new byte[] {0, 1, 2, 3, 4});
        IOException failure = assertThrows(IOException.class,
                () -> JrtClassSource.verifyClassEntryForContract(snapshot));
        assertTrue(failure.getMessage().contains("JDK_CLASS_CHANGED_DURING_READ"),
                failure.getMessage());
    }
}
