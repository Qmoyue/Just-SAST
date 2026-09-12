package io.just.sast.verify;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** P2.5 protocol contract: only authenticated, ordered, bound frames become evidence. */
class VerificationProtocolContractTest {

    @Test
    void legacyParserIgnoresDiagnosticsAndRequiresReadyBeforeTerminal() {
        String token = "token";
        VerificationProtocol.Evidence valid = VerificationProtocol.parseLegacy(
                "noise\nJUST_VERIFY_V1:" + token
                        + ":SANDBOX_READY: WINDOWS_JOB_OBJECT_JVM_POLICY|job=1|policy=p|attestation=a\n"
                        + "JUST_VERIFY_V1:" + token + ":SINK_BLOCKED: sink", token);
        assertTrue(valid.ready());
        assertTrue(valid.validOrder());
        assertEquals("WINDOWS_JOB_OBJECT_JVM_POLICY", valid.readyBackend());
        assertEquals("p", valid.readyPolicyDigest());
        assertTrue(valid.jobReady());
        assertEquals("SINK_BLOCKED: sink", valid.terminal());

        VerificationProtocol.Evidence invalid = VerificationProtocol.parseLegacy(
                "JUST_VERIFY_V1:" + token + ":SINK_BLOCKED: sink\n"
                        + "JUST_VERIFY_V1:" + token + ":SANDBOX_READY: backend", token);
        assertFalse(invalid.validOrder());
        assertNull(VerificationProtocol.authenticatedStatus("SINK_BLOCKED: sink", token));
    }

    @Test
    void v2ParserInvalidatesTamperedAndDuplicateTerminalFrames() {
        VerificationProtocol.Identity identity = new VerificationProtocol.Identity(
                "token", "run", "chain", "sink", "nonce", "artifact");
        String prefix = "JUST_VERIFY_V2:token:run:chain:sink:nonce:artifact:";
        VerificationProtocol.Evidence valid = VerificationProtocol.parse(
                prefix + "SANDBOX_READY: backend|job=1|policy=p|attestation=a\n"
                        + prefix + "SINK_BLOCKED: sink", identity);
        assertTrue(valid.bindingValid());
        assertTrue(valid.validOrder());
        assertEquals("a", valid.attestationVersion());

        VerificationProtocol.Evidence tampered = VerificationProtocol.parse(
                prefix + "SANDBOX_READY: backend\n"
                        + "JUST_VERIFY_V2:token:run:other:sink:nonce:artifact:PARTIAL_PATH:tampered\n"
                        + prefix + "SINK_BLOCKED: sink", identity);
        assertFalse(tampered.bindingValid());

        VerificationProtocol.Evidence duplicate = VerificationProtocol.parse(
                prefix + "SANDBOX_READY: backend\n"
                        + prefix + "SINK_BLOCKED: one\n"
                        + prefix + "SINK_BLOCKED: two", identity);
        assertFalse(duplicate.validOrder());
    }

    @Test
    void readyPayloadAndStatusVocabularyAreClosed() {
        VerificationProtocol.Ready ready = VerificationProtocol.readyPayload(
                "SANDBOX_READY: backend|job=true|policy=policy|attestation=v1|future=ignored");
        assertEquals("backend", ready.backend());
        assertEquals("policy", ready.policyDigest());
        assertTrue(ready.jobReady());
        assertEquals("v1", ready.attestationVersion());
        assertTrue(VerificationProtocol.isStatus("PARTIAL_PATH:bounded"));
        assertFalse(VerificationProtocol.isStatus("NOT_A_PROTOCOL_STATUS"));
    }
}
