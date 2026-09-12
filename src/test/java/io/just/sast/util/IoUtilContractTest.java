package io.just.sast.util;

import io.just.sast.run.InputBudget;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystemNotFoundException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Contract for caller-owned aggregate accounting in the shared bounded stream reader. */
class IoUtilContractTest {

    @Test
    void callerTrackerCannotBeResetBetweenIndependentStreams() throws Exception {
        InputBudget budget = InputBudget.defaults().withArchiveLimits(
                1024, 1024, 5, 1024, 16, 2, 16);
        InputBudget.Tracker tracker = budget.tracker();

        byte[] first = IoUtil.readAll(new ByteArrayInputStream("abcd".getBytes(StandardCharsets.UTF_8)),
                1024, tracker);
        assertEquals("abcd", new String(first, StandardCharsets.UTF_8));
        assertThrows(IOException.class, () -> IoUtil.readAll(
                new ByteArrayInputStream("efgh".getBytes(StandardCharsets.UTF_8)),
                1024, tracker));
    }

    @Test
    void boundedReaderNeverRequestsMoreThanAggregateRemainingBytes() throws Exception {
        InputBudget budget = InputBudget.defaults().withArchiveLimits(
                1024, 1024, 5, 1024, 16, 2, 16);
        InputBudget.Tracker tracker = budget.tracker();
        AtomicInteger largestRequest = new AtomicInteger();
        InputStream input = new ByteArrayInputStream("hello".getBytes(StandardCharsets.UTF_8)) {
            @Override
            public int read(byte[] buffer, int offset, int length) {
                largestRequest.accumulateAndGet(length, Math::max);
                return super.read(buffer, offset, length);
            }
        };

        byte[] bytes = IoUtil.readAll(input, 1024, tracker);

        assertEquals("hello", new String(bytes, StandardCharsets.UTF_8));
        assertTrue(largestRequest.get() <= 5,
                "a bounded read must not materialize a buffer larger than aggregate budget");
        assertEquals(0, tracker.remainingReadBytes());
    }

    @Test
    void noFollowOpenUsesStrictProviderContract(@TempDir Path temp) throws Exception {
        Path file = temp.resolve("input.txt");
        Files.writeString(file, "bounded-input", StandardCharsets.UTF_8);
        try (var input = IoUtil.openNoFollow(file, "RULES")) {
            assertEquals("bounded-input", new String(IoUtil.readAll(input, 1024),
                    StandardCharsets.UTF_8));
        }
        assertThrows(IOException.class, () -> IoUtil.openNoFollow(null, "RULES"));
    }

    @Test
    void regularOpenExposesProviderCapabilityAndReadsBoundedFile(@TempDir Path temp)
            throws Exception {
        Path file = temp.resolve("input.txt");
        Files.writeString(file, "provider-aware", StandardCharsets.UTF_8);
        try (IoUtil.OpenedInput opened = IoUtil.openRegularFile(file, "RULES")) {
            assertNotNull(opened.capability());
            assertNotNull(opened.providerAtomicStatus());
            assertEquals(IoUtil.ProviderAtomicStatus.from(opened.capability()),
                    opened.providerAtomicStatus());
            assertEquals("provider-aware", new String(IoUtil.readAll(opened.stream(), 1024),
                    StandardCharsets.UTF_8));
        }
    }

    @Test
    void regularOpenRejectsFinalLinkBeforeProviderFallback(@TempDir Path temp) throws Exception {
        Path target = temp.resolve("target.txt");
        Path link = temp.resolve("link.txt");
        Files.writeString(target, "target", StandardCharsets.UTF_8);
        try {
            Files.createSymbolicLink(link, target.getFileName());
        } catch (UnsupportedOperationException | IOException | SecurityException unavailable) {
            Assumptions.assumeTrue(false, "symbolic links are unavailable: "
                    + unavailable.getClass().getSimpleName());
        }
        IOException failure = assertThrows(IOException.class,
                () -> IoUtil.openRegularFile(link, "RULES"));
        assertTrue(failure.getMessage().contains("RULES_LINK")
                        || failure.getMessage().contains("RULES_NOT_REGULAR"),
                failure.getMessage());
    }

    @Test
    void immutableJrtOpenUsesExplicitProviderCapability() throws Exception {
        try {
            Path object = FileSystems.getFileSystem(URI.create("jrt:/"))
                    .getPath("modules", "java.base", "java/lang/Object.class");
            try (IoUtil.OpenedInput opened = IoUtil.openImmutableProviderFile(object,
                    "JDK_CLASS")) {
                assertEquals(IoUtil.OpenCapability.IMMUTABLE_PROVIDER, opened.capability());
                assertEquals(IoUtil.ProviderAtomicStatus.IMMUTABLE_PROVIDER,
                        opened.providerAtomicStatus());
                assertTrue(opened.providerAtomicStatus().immutable());
                assertTrue(IoUtil.readAll(opened.stream(), 64 * 1024).length > 0);
            }
        } catch (FileSystemNotFoundException unavailable) {
            Assumptions.assumeTrue(false, "runtime JRT provider is unavailable");
        }
    }
}
