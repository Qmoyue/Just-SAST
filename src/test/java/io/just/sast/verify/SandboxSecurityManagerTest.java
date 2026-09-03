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
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
    void allowsReadThroughConfiguredSymlinkRootButNotOutside(@TempDir Path tmp) throws Exception {
        Path target = tmp.resolve("jdk-target");
        Files.createDirectories(target.resolve("lib"));
        Path resource = target.resolve("lib").resolve("tzdb.dat");
        Files.writeString(resource, "runtime-resource");
        Path link = tmp.resolve("jdk-default");
        try {
            Files.createSymbolicLink(link, target);
        } catch (UnsupportedOperationException | java.io.IOException | SecurityException e) {
            Assumptions.assumeTrue(false, "symbolic links are unavailable on this host");
        }
        SandboxSecurityManager manager = new SandboxSecurityManager(
                tmp.resolve("scratch"), List.of(link));
        assertDoesNotThrow(() -> manager.checkPermission(new FilePermission(
                link.resolve("lib").resolve("tzdb.dat").toString(), "read")));
        assertThrows(SecurityException.class, () -> manager.checkPermission(new FilePermission(
                tmp.resolve("outside").toString(), "read")));
    }

    @Test
    void deniesReflectiveAndSerializationEscapeHatchesOutsideProbe(@TempDir Path tmp) {
        SandboxSecurityManager manager = new SandboxSecurityManager(tmp, List.of(tmp));
        assertThrows(SecurityException.class, () -> manager.checkPermission(
                new ReflectPermission("suppressAccessChecks")));
        assertThrows(SecurityException.class, () -> manager.checkPermission(
                new SerializablePermission("enableSubstitution")));
    }

    @Test
    void allowsOnlyBootstrapCanaryPackageToLinkFromTarget(@TempDir Path tmp) {
        SandboxSecurityManager manager = new SandboxSecurityManager(tmp, List.of(tmp));
        assertDoesNotThrow(() -> manager.checkPackageAccess("io.just.sast.verify.boot"));
        assertDoesNotThrow(() -> manager.checkPackageAccess("io.just.sast.verify.boot.internal"));
        assertThrows(SecurityException.class,
                () -> manager.checkPackageAccess("io.just.sast.verify"));
        assertThrows(SecurityException.class,
                () -> manager.checkPackageAccess("io.just.sast.blackboard"));
    }

    @Test
    void subprocessEnforcesTheBoundary(@TempDir Path tmp) throws Exception {
        Path writable = tmp.resolve("scratch");
        Files.createDirectories(writable);
        Path outside = tmp.resolve("outside.txt");
        Files.writeString(outside, "host-secret");
        String javaName = System.getProperty("os.name", "").toLowerCase()
                .contains("win") ? "java.exe" : "java";
        String javaExe = Path.of(System.getProperty("java.home"), "bin", javaName).toString();
        String classpath = System.getProperty("java.class.path");
        List<String> command = new java.util.ArrayList<>();
        command.add(javaExe);
        // JDK 18–23 keep the legacy manager only behind an explicit opt-in.  The production
        // verifier already supplies this flag for its compatibility child; the standalone
        // contract child must use the same launch contract or CI on JDK 21 tests a different
        // process policy than the real verifier.
        int feature = Runtime.version().feature();
        if (feature >= 18 && feature < 24) {
            command.add("-Djava.security.manager=allow");
        }
        command.add("-cp");
        command.add(classpath);
        command.add("SandboxSecurityChild");
        command.add(writable.toString());
        command.add(outside.toString());
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        assertTrue(process.waitFor(15, TimeUnit.SECONDS), "sandbox child must terminate");
        String output = new String(process.getInputStream().readAllBytes(),
                java.nio.charset.StandardCharsets.UTF_8);
        assertEquals(0, process.exitValue(), output);
        assertTrue(output.contains("inside-write=ALLOWED"), output);
        assertTrue(output.contains("outside-read=DENIED"), output);
        assertTrue(output.contains("exec=DENIED"), output);
        assertTrue(output.contains("network=DENIED"), output);
        assertTrue(output.contains("CHILD_DONE"), output);
    }
}
