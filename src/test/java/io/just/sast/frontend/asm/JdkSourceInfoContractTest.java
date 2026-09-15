package io.just.sast.frontend.asm;

import io.just.sast.model.JdkSourceInfo;
import io.just.sast.report.ReportLayout;
import io.just.sast.report.ScanIdentityWriter;
import io.just.sast.run.InputBudget;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Runtime/target JDK source selection must be explicit and path-free for report consumers. */
class JdkSourceInfoContractTest {

    @Test
    void runtimeSourceReportsRuntimeImageWithoutPretendingTargetAccuracy() {
        try (JrtClassSource source = JrtClassSource.runtime()) {
            JdkSourceInfo info = source.sourceInfo();
            assertEquals(JdkSourceInfo.ImageKind.RUNTIME_JRT, info.imageKind());
            assertTrue(info.runtimeDelegated());
            assertFalse(info.targetImage());
            assertEquals("JRT", info.provider());
            assertTrue(info.feature() > 0);
        }
    }

    @Test
    void legacyTargetReportsRtJarImage(@TempDir Path temp) throws Exception {
        Path rt = temp.resolve("jre").resolve("lib").resolve("rt.jar");
        Files.createDirectories(rt.getParent());
        try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(rt))) {
            zip.putNextEntry(new ZipEntry("A.class"));
            zip.write(minimalClass());
            zip.closeEntry();
        }
        try (TargetJdkSource source = new TargetJdkSource(temp)) {
            JdkSourceInfo info = source.sourceInfo();
            assertEquals(JdkSourceInfo.ImageKind.TARGET_RT_JAR, info.imageKind());
            assertTrue(info.targetImage());
            assertFalse(info.runtimeDelegated());
            assertEquals("LEGACY_RT_JAR", info.provider());
        }
    }

    @Test
    void legacyTargetIdentityUsesTargetBytesInsteadOfRuntimeFeature(@TempDir Path temp)
            throws Exception {
        Path rt = temp.resolve("jre").resolve("lib").resolve("rt.jar");
        Files.createDirectories(rt.getParent());
        try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(rt))) {
            zip.putNextEntry(new ZipEntry("A.class"));
            zip.write(minimalClass());
            zip.closeEntry();
        }

        ReportLayout layout = ReportLayout.flat(temp.resolve("identity-report"));
        new ScanIdentityWriter().write(layout, "artifact", "dependencies", "inventory", null,
                temp, 52, false, "component", InputBudget.defaults(),
                InputBudget.defaults().tracker(),
                new JdkSourceInfo(JdkSourceInfo.ImageKind.TARGET_RT_JAR, 7));
        String identityJson = Files.readString(layout.meta().resolve("scan-identity.json"));

        assertTrue(identityJson.contains("\"jdk_identity\":\"legacy-sha256="), identityJson);
        assertFalse(identityJson.contains("runtime-feature="), identityJson);
    }

    @Test
    void scanIdentityPublishesTypedSourceEvidence(@TempDir Path temp) throws Exception {
        ReportLayout layout = ReportLayout.flat(temp.resolve("report"));
        JdkSourceInfo info = new JdkSourceInfo(JdkSourceInfo.ImageKind.TARGET_RT_JAR, 8);
        new ScanIdentityWriter().write(layout, "artifact", "dependencies", "inventory", null,
                null, 52, false, "component", InputBudget.defaults(),
                InputBudget.defaults().tracker(), info);
        String json = Files.readString(layout.meta().resolve("scan-identity.json"));
        assertTrue(json.contains("\"jdk_source_kind\":\"TARGET_RT_JAR\""));
        assertTrue(json.contains("\"jdk_provider\":\"LEGACY_RT_JAR\""));
        assertTrue(json.contains("\"jdk_runtime_delegated\":false"));
        assertTrue(json.contains("\"jdk_source_feature\":8"));
    }

    private static byte[] minimalClass() throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        DataOutputStream data = new DataOutputStream(output);
        data.writeInt(0xCAFEBABE);
        data.writeShort(0);
        data.writeShort(52);
        data.writeShort(5);
        writeUtf8(data, "A");
        data.writeByte(7);
        data.writeShort(1);
        writeUtf8(data, "java/lang/Object");
        data.writeByte(7);
        data.writeShort(3);
        data.writeShort(0x0021);
        data.writeShort(2);
        data.writeShort(4);
        data.writeShort(0);
        data.writeShort(0);
        data.writeShort(0);
        data.writeShort(0);
        data.writeShort(0);
        data.flush();
        return output.toByteArray();
    }

    private static void writeUtf8(DataOutputStream data, String value) throws Exception {
        byte[] bytes = value.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        data.writeByte(1);
        data.writeShort(bytes.length);
        data.write(bytes);
    }
}
