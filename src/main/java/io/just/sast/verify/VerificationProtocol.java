package io.just.sast.verify;

import java.util.Objects;

/**
 * Typed parser for the authenticated parent/child verification protocol.
 *
 * <p>Only protocol frames are accepted as evidence.  Target diagnostics, process exit codes and
 * marker-file presence are deliberately ignored.  Readiness must precede exactly one terminal
 * frame, and a malformed/tampered bound frame invalidates the whole attempt.</p>
 */
public final class VerificationProtocol {

    public static final String V1_PREFIX = "JUST_VERIFY_V1:";
    public static final String V2_PREFIX = "JUST_VERIFY_V2:";

    private VerificationProtocol() {
    }

    /** Launcher-owned identities binding a result to one chain/sink/artifact attempt. */
    public record Identity(String token, String runId, String chainFingerprint,
                           String sinkFingerprint, String nonce, String artifactFingerprint) {
        public Identity {
            token = normalize(token);
            runId = normalize(runId);
            chainFingerprint = normalize(chainFingerprint);
            sinkFingerprint = normalize(sinkFingerprint);
            nonce = normalize(nonce);
            artifactFingerprint = normalize(artifactFingerprint);
        }

        private static String normalize(String value) {
            return value == null ? "" : value;
        }
    }

    /** Typed readiness/terminal evidence; it is not a positive sink-execution assertion. */
    public record Evidence(boolean ready, boolean validOrder, boolean bindingValid,
                           String readyBackend, String readyPolicyDigest, boolean jobReady,
                           String attestationVersion, String terminal) {
        public Evidence {
            readyBackend = normalize(readyBackend);
            readyPolicyDigest = normalize(readyPolicyDigest);
            attestationVersion = normalize(attestationVersion);
            terminal = terminal == null || terminal.isBlank() ? null : terminal;
        }

        private static String normalize(String value) {
            return value == null ? "" : value;
        }
    }

    /** Parsed SANDBOX_READY payload. */
    public record Ready(String backend, String policyDigest, boolean jobReady,
                        String attestationVersion) {
        public Ready {
            backend = backend == null ? "" : backend;
            policyDigest = policyDigest == null ? "" : policyDigest;
            attestationVersion = attestationVersion == null ? "" : attestationVersion;
        }
    }

    /** Parse the legacy V1 stream bound to one short-lived token. */
    public static Evidence parseLegacy(String output, String token) {
        boolean ready = false;
        boolean validOrder = true;
        String readyBackend = "";
        String readyPolicyDigest = "";
        boolean jobReady = false;
        String attestationVersion = "";
        String terminal = null;
        if (output == null) {
            return new Evidence(false, false, true, "", "", false, "", null);
        }
        for (String line : output.split("\\R")) {
            String status = authenticatedStatus(line.strip(), token);
            if (status == null) {
                continue;
            }
            if (status.startsWith("SANDBOX_READY")) {
                if (ready) {
                    validOrder = false;
                }
                ready = true;
                Ready payload = readyPayload(status);
                readyBackend = payload.backend();
                readyPolicyDigest = payload.policyDigest();
                jobReady = payload.jobReady();
                attestationVersion = payload.attestationVersion();
                continue;
            }
            if (!ready) {
                validOrder = false;
            }
            if (terminal == null) {
                terminal = status;
            }
        }
        return new Evidence(ready, validOrder, true, readyBackend, readyPolicyDigest,
                jobReady, attestationVersion, terminal);
    }

    /** Parse only V2 frames bound to the exact identity. */
    public static Evidence parse(String output, Identity expected) {
        boolean ready = false;
        boolean validOrder = true;
        boolean allFramesValid = true;
        String readyBackend = "";
        String readyPolicyDigest = "";
        boolean jobReady = false;
        String attestationVersion = "";
        String terminal = null;
        if (output == null || expected == null) {
            return new Evidence(false, false, false, "", "", false, "", null);
        }
        boolean sawBoundPrefix = false;
        for (String raw : output.split("\\R")) {
            String line = raw.strip();
            if (!line.startsWith(V2_PREFIX)) {
                continue;
            }
            sawBoundPrefix = true;
            String status = parseStatus(line, expected);
            if (status == null) {
                allFramesValid = false;
                continue;
            }
            if (status.startsWith("SANDBOX_READY")) {
                if (ready) {
                    validOrder = false;
                }
                ready = true;
                Ready payload = readyPayload(status);
                readyBackend = payload.backend();
                readyPolicyDigest = payload.policyDigest();
                jobReady = payload.jobReady();
                attestationVersion = payload.attestationVersion();
                continue;
            }
            if (!ready || terminal != null) {
                validOrder = false;
            }
            if (terminal == null) {
                terminal = status;
            }
        }
        return new Evidence(ready, validOrder, sawBoundPrefix && allFramesValid,
                readyBackend, readyPolicyDigest, jobReady, attestationVersion, terminal);
    }

    /** Return a protocol status only when the V1 frame carries the exact token. */
    public static String authenticatedStatus(String line, String token) {
        if (line == null || token == null || token.isBlank()) {
            return null;
        }
        String prefix = V1_PREFIX + token + ":";
        if (!line.startsWith(prefix)) {
            return null;
        }
        String status = line.substring(prefix.length());
        return isStatus(status) ? status : null;
    }

    public static Ready readyPayload(String status) {
        int colon = status == null ? -1 : status.indexOf(':');
        String payload = colon < 0 ? "" : status.substring(colon + 1).strip();
        String backend = "";
        String policy = "";
        boolean job = false;
        String attestation = "";
        String[] fields = payload.split("\\|", -1);
        if (fields.length > 0) {
            backend = fields[0].strip();
        }
        for (int i = 1; i < fields.length; i++) {
            int equals = fields[i].indexOf('=');
            if (equals <= 0) {
                continue;
            }
            String key = fields[i].substring(0, equals).strip();
            String value = fields[i].substring(equals + 1).strip();
            switch (key) {
                case "policy" -> policy = value;
                case "job" -> job = "1".equals(value) || "true".equalsIgnoreCase(value);
                case "attestation" -> attestation = value;
                default -> { }
            }
        }
        return new Ready(backend, policy, job, attestation);
    }

    public static boolean isStatus(String status) {
        if (status == null) {
            return false;
        }
        return status.startsWith("SANDBOX_READY") || status.startsWith("SINK_BLOCKED")
                || status.startsWith("SINK_TRIGGERED") || status.startsWith("SINK_EXECUTED_SAFE")
                || status.startsWith("JNI_EXECUTED_SAFE") || status.startsWith("SAFE_EFFECT_OBSERVED")
                || status.startsWith("CONCRETE_REACHED") || status.startsWith("EXECUTED")
                || status.startsWith("SANDBOX_UNAVAILABLE") || status.startsWith("UNTESTABLE")
                || status.startsWith("PARTIAL_PATH");
    }

    private static String parseStatus(String line, Identity expected) {
        String[] fields = line.substring(V2_PREFIX.length()).split(":", 7);
        if (fields.length != 7 || !Objects.equals(expected.token(), fields[0])
                || !Objects.equals(expected.runId(), fields[1])
                || !Objects.equals(expected.chainFingerprint(), fields[2])
                || !Objects.equals(expected.sinkFingerprint(), fields[3])
                || !Objects.equals(expected.nonce(), fields[4])
                || !Objects.equals(expected.artifactFingerprint(), fields[5])
                || !isStatus(fields[6])) {
            return null;
        }
        return fields[6];
    }
}
