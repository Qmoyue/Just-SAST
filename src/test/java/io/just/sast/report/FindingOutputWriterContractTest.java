package io.just.sast.report;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FindingOutputWriterContractTest {

    @Test
    void writesCanonicalTypedSnapshotAtomically(@TempDir Path temp) throws Exception {
        Chain chain = new Chain("RULE-WRITER", "CODE_EXEC", "HIGH", "app/Entry",
                "readObject", "readObject", "java/lang/Runtime", "exec", List.of(
                new ChainHop("app/Entry", "readObject", "java/lang/Runtime", "exec",
                        HopKind.DIRECT_CALL, null, "terminal", "()V", null)), 0);
        FindingOutputReader.Snapshot snapshot = new FindingOutputReader().read(
                List.of(chain), Map.of(), Map.of(), null);

        Path output = new FindingOutputWriter().write(ReportLayout.create(temp), snapshot);
        assertTrue(output.getParent().getFileName().toString().equals("meta")
                && output.getFileName().toString().equals("finding-output.json"));
        String json = Files.readString(output);
        assertTrue(json.endsWith("\n"));
        assertTrue(json.contains("JUST-FINDING-OUTPUT-D004-V1"));
        assertTrue(json.contains("NO_APPLICATION_ENTRY"));
        try (var files = Files.list(output.getParent())) {
            assertFalse(files.anyMatch(path -> path.getFileName().toString()
                    .contains(".finding-output.json.tmp")));
        }
    }

}
