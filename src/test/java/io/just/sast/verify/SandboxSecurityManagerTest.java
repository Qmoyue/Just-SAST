package io.just.sast.verify;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.io.TempDir;

import java.io.FilePermission;
import java.io.SerializablePermission;
import java.lang.reflect.ReflectPermission;
import java.net.SocketPermission;
import java.net.NetPermission;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** JVM 探针权限契约：测试 deny-by-default 判定，不在测试 JVM 内安装全局 SecurityManager。 */
@SuppressWarnings("removal")
class SandboxSecurityManagerTest {

    @Test
    void deniesNetworkAndOutsideFileRead(@TempDir Path tmp) {
        SandboxSecurityManager manager = new SandboxSecurityManager(tmp, List.of(tmp));
        assertDoesNotThrow(() -> manager.checkPermission(
                new FilePermission(tmp.resolve("probe.txt").toString(), "read,write")));
        assertThrows(SecurityException.class, () -> manager.checkPermission(
                new FilePermission(Path.of(System.getProperty("user.dir")).resolve("outside.txt").toString(), "read")));
        assertThrows(SecurityException.class, () -> manager.checkPermission(
                new SocketPermission("example.invalid", "connect")));
        // URLClassPath may use this permission during trusted probe bootstrap, but an
        // arbitrary target frame must not be able to install a handler under the same JVM.
        assertThrows(SecurityException.class, () -> manager.checkPermission(
                new NetPermission("specifyStreamHandler")));
        assertThrows(SecurityException.class, () -> manager.checkPermission(
                new NetPermission("setProxySelector")));
        assertThrows(SecurityException.class, () -> manager.checkExec("echo"));
        assertThrows(SecurityException.class, () -> manager.checkLink("target.dll"));
    }

    @Test
    void rejectsReadableSymlinkThatEscapesRoot(@TempDir Path tmp) throws Exception {
        Path outside = Files.createTempDirectory("just-sandbox-outside-");
        try {
            try {
                Files.createSymbolicLink(tmp.resolve("escape"), outside);
            } catch (UnsupportedOperationException | java.io.IOException | SecurityException e) {
                Assumptions.assumeTrue(false, "symbolic links are unavailable on this host");
            }
            SandboxSecurityManager manager = new SandboxSecurityManager(tmp, List.of(tmp));
            assertThrows(SecurityException.class, () -> manager.checkPermission(
                    new FilePermission(tmp.resolve("escape").toString(), "read")));
        } finally {
            Files.deleteIfExists(outside);
        }
    }

    @Test
    void deniesReflectiveAndSerializationEscapeHatchesOutsideProbe(@TempDir Path tmp) {
        SandboxSecurityManager manager = new SandboxSecurityManager(tmp, List.of(tmp));
        assertThrows(SecurityException.class, () -> manager.checkPermission(
                new ReflectPermission("suppressAccessChecks")));
        assertThrows(SecurityException.class, () -> manager.checkPermission(
                new SerializablePermission("enableSubstitution")));
    }
}
