package io.just.sast.verify.legacy;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.InvocationTargetException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.nio.charset.StandardCharsets;
import java.io.Serializable;
import java.security.GeneralSecurityException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Java 8-compatible fork-per-chain verifier. */
public final class LegacyChainVerifyProbe {

    private static final int MAX_SERIALIZED_BYTES = 8 * 1024 * 1024;
    private static final String PROTOCOL_PREFIX = "JUST_VERIFY_V1:";
    private static String protocolToken = "";
    private static String protocolRunId = "";
    private static String protocolChainFingerprint = "";
    private static String protocolSinkFingerprint = "";
    private static String protocolNonce = "";
    private static String protocolArtifactFingerprint = "";
    private static String isolationPolicyDigest = "";
    /** Captured before target code loads; the parent rejects an unknown proof protocol. */
    private static String attestationVersion = "";
    private static ClassLoader applicationLoader;
    /** Bounded diagnostic only; never upgrades an entry return to sink evidence. */
    private static String sourceAdapterDetail = "";
    /** Captured before target code loads; target classes cannot widen safe-exec properties. */
    private static String safeSinkMode = "BOUNDARY";
    private static String safeSinkDisposition = "CANARY_BOUNDARY";
    private static String safeSinkPolicyDigest = "";
    private static String safeScratchRoot = ".";
    /** Captured before target code loads; SAFE_REAL may start only this fixed executable. */
    private static Path safeJavaExecutable;
    /** One-time parent secret and probe-owned authenticated result file. */
    private static final String RESULT_CHANNEL_PREFIX = "JUST_VERIFY_RESULT_V1:";
    private static final int RESULT_SECRET_HEX_LENGTH = 64;
    private static String resultChannelSecret = "";
    private static java.io.OutputStream resultChannel;
    private static boolean resultChannelBroken;
    /** Whether the strict Linux child installed the requested kernel filesystem policy. */
    private static boolean landlockReady = true;

    /** Source-boundary callback shape shared with the Java 17 probe protocol. */
    private static final class SourceTrigger {
        private final String entryClass;
        private final String entryMethod;
        private final String callbackKind;
        private final String sourceOwner;
        private final String sourceMethod;
        private final String sourceDescriptor;
        private final String downstreamOwner;
        private final String downstreamMethod;

        private SourceTrigger(String entryClass, String entryMethod, String callbackKind,
                              String sourceOwner, String sourceMethod, String sourceDescriptor,
                              String downstreamOwner, String downstreamMethod) {
            this.entryClass = entryClass;
            this.entryMethod = entryMethod;
            this.callbackKind = callbackKind;
            this.sourceOwner = sourceOwner;
            this.sourceMethod = sourceMethod;
            this.sourceDescriptor = sourceDescriptor;
            this.downstreamOwner = downstreamOwner;
            this.downstreamMethod = downstreamMethod;
        }
    }

    private LegacyChainVerifyProbe() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("usage: LegacyChainVerifyProbe <entry|method|mode> [hops] [sink]");
            System.exit(2);
            return;
        }
        String[] entryParts = args[0].split("\\|", -1);
        if (entryParts.length < 2 || entryParts[0].length() == 0 || entryParts[1].length() == 0) {
            System.err.println("usage: LegacyChainVerifyProbe <entryClass|entryMethod|mode> [hops] [sink]");
            System.exit(2);
            return;
        }
        String entryClass = entryParts[0];
        String entryMethod = entryParts[1];
        String mode = entryParts.length > 2 ? entryParts[2] : "DIRECT";
        String entryDescriptor = entryParts.length > 3 ? entryParts[3] : "";
        protocolToken = args.length > 5 ? args[5] : "";
        protocolRunId = safeProperty("just.verify.run-id", "");
        protocolChainFingerprint = safeProperty("just.verify.chain-fingerprint", "");
        protocolSinkFingerprint = safeProperty("just.verify.sink-fingerprint", "");
        protocolNonce = safeProperty("just.verify.nonce", "");
        protocolArtifactFingerprint = safeProperty("just.verify.artifact-fingerprint", "");
        isolationPolicyDigest = safeProperty("just.verify.isolation-policy-digest", "");
        attestationVersion = safeProperty("just.verify.attestation-version", "");
        initializeResultChannel();
        if (!awaitIsolationReady()) {
            emit("SANDBOX_UNAVAILABLE: isolation-ready-timeout-or-missing");
            System.exit(3);
            return;
        }
        if (!strictOsAttestation()) {
            emit("SANDBOX_UNAVAILABLE: OS_ATTESTATION_FAILED");
            System.exit(3);
            return;
        }
        if (Boolean.parseBoolean(safeProperty("just.verify.landlock-required", "false"))) {
            landlockReady = installLandlock();
            if (!landlockReady) {
                emit("SANDBOX_UNAVAILABLE: LANDLOCK_ATTESTATION_FAILED");
                System.exit(3);
                return;
            }
        }
        List<String[]> fieldLinks = parseLinks(args.length > 1 ? args[1] : "");
        String[] sink = parseSink(args.length > 2 ? args[2] : "");
        String sinkClass = sink[0];
        String sinkMethod = sink[1];
        String sinkDescriptor = sink[2];
        SourceTrigger sourceTrigger = parseSourceTrigger(args.length > 4 ? args[4] : "");
        safeSinkMode = safeProperty("just.verify.sink-mode", "BOUNDARY");
        safeSinkDisposition = safeProperty("just.verify.sink-disposition", "CANARY_BOUNDARY");
        safeSinkPolicyDigest = safeProperty("just.verify.sink-policy-digest", "");
        safeScratchRoot = safeProperty("java.io.tmpdir", ".");
        safeJavaExecutable = locateSafeJavaExecutable();
        if ("SAFE_REAL".equals(safeSinkMode)
                && !"OS_STRICT".equals(safeProperty("just.verify.isolation-level", "NONE"))) {
            emit("SANDBOX_UNAVAILABLE: SAFE_REAL_REQUIRES_OS_STRICT");
            System.exit(3);
            return;
        }

        try {
            installApplicationLoader();
            try {
                LegacySandboxSecurityManager.install(Paths.get(System.getProperty("java.io.tmpdir", ".")));
            } catch (Throwable sandboxFailure) {
                emit("SANDBOX_UNAVAILABLE: " + sandboxFailure.getClass().getSimpleName());
                System.exit(3);
                return;
            }
            if (protocolToken.length() == 0
                    || !protocolToken.equals(safeProperty("just.verify.canary-token", ""))) {
                emit("UNTESTABLE: CANARY_AGENT_NOT_READY");
                System.exit(3);
                return;
            }
            if (!protocolBound()) {
                emit("UNTESTABLE: PROTOCOL_BINDING_NOT_READY");
                System.exit(3);
                return;
            }
            emit("SANDBOX_READY: " + safeProperty("just.verify.backend", "unknown")
                    + "|landlock=" + (Boolean.parseBoolean(
                    safeProperty("just.verify.landlock-required", "false"))
                    ? (landlockReady ? "1" : "0") : "na")
                    + "|attestation=" + attestationVersion);
            // The gate keeps its token in bootstrap memory; do not leave the attestation in the
            // mutable system-properties map where target code could read or replace it.
            System.clearProperty("just.verify.canary-token");
            // Keep stack formatting and collection initialization outside the gadget call. Some
            // old runtimes initialize these classes lazily and can otherwise obscure the result.
            try {
                load("java.util.IdentityHashMap");
            } catch (Throwable ignored) {
            }
            warmReflectionRuntime();

            Map<String, Object> instances = new HashMap<String, Object>();
            Class<?> entryType = load(entryClass);
            Method selectedEntry = findMethod(entryType, entryMethod, entryDescriptor);
            boolean staticEntry = selectedEntry != null
                    && Modifier.isStatic(selectedEntry.getModifiers());
            Object entryInstance;
            try {
                entryInstance = newInstance(entryType, isSerializationMode(mode));
            } catch (Exception constructionFailure) {
                if (!staticEntry) {
                    throw constructionFailure;
                }
                entryInstance = null;
            }
            if (entryInstance != null) {
                instances.put(entryClass, entryInstance);
            }

            Object sourceTriggerInstance = null;
            if (sourceTrigger != null) {
                try {
                    sourceTriggerInstance = newSourceTriggerInstance(sourceTrigger, instances);
                } catch (Throwable ignored) {
                    // The generic source adapter remains available; an unavailable callback
                    // receiver is reported as a normal partial path rather than widening the
                    // target classpath or executing an arbitrary constructor.
                }
            }

            // Materialize both ends. Reverse FIELD_FLOW paths commonly name an intermediate
            // owner only on the left side; creating both sides avoids a false partial result.
            for (String[] link : fieldLinks) {
                ensureInstance(instances, link[0], isSerializationMode(mode));
                ensureInstance(instances, link[2], isSerializationMode(mode));
            }

            List<String> unlinked = new ArrayList<String>();
            boolean serializedProbeGraph = isSerializationMode(mode) || sourceTrigger != null;
            for (String[] link : fieldLinks) {
                linkField(instances, entryInstance, link, unlinked, serializedProbeGraph);
            }
            fillSimpleFields(instances);
            if (sourceTrigger != null && sourceTriggerInstance != null) {
                // Field wiring is part of the trusted, inert source adapter. Keep the narrow
                // adapter scope active here as well as during serialization; otherwise the
                // deny-by-default manager rejects setAccessible, leaves _obj as the generic
                // String fallback, and the target quietly catches the resulting non-chain
                // error before any callback can reach the canary.
                LegacySandboxSecurityManager.beginSourceAdapter();
                try {
                    prepareSourceTrigger(sourceTrigger, sourceTriggerInstance);
                } finally {
                    LegacySandboxSecurityManager.endSourceAdapter();
                }
            }
            if (!unlinked.isEmpty()) {
                emit("PARTIAL_PATH: field-unlinked=" + unlinked.size());
                System.exit(0);
                return;
            }

            trigger(entryType, entryInstance, entryMethod, entryDescriptor, mode,
                    sourceTrigger, sourceTriggerInstance);
            if (reportLatchedCanary(sinkClass, sinkMethod)) return;
            if ("SERIAL".equals(mode) || "PROXY".equals(mode)
                    || mode.startsWith("TRIGGER_")) {
                emit("CONCRETE_REACHED: " + mode + ";canary="
                        + LegacySinkCanaryAgent.instrumentationSummary());
            } else {
                emit("EXECUTED:canary=" + LegacySinkCanaryAgent.instrumentationSummary()
                        + sourceAdapterSuffix());
            }
            System.exit(0);
        } catch (Throwable failure) {
            if (reportLatchedCanary(sinkClass, sinkMethod)) return;
            String marker = markerSpec(failure);
            if (marker != null && sameSink(marker, sinkClass, sinkMethod, sinkDescriptor)
                    && entryReached(failure, entryClass, entryMethod)) {
                emit("SINK_BLOCKED: " + sinkClass);
                System.err.println("SINK_REACHED: " + sinkClass + "." + sinkMethod + " (canary)");
                System.exit(1);
                return;
            }
            if (sinkDescriptor.length() == 0 && reachesSink(failure, sinkClass, sinkMethod)
                    && entryReached(failure, entryClass, entryMethod)) {
                emit("UNTESTABLE: sink-frame-without-canary");
                System.err.println("SINK_REACHED: " + sinkClass + "." + sinkMethod
                        + " without canary (not confirmed)");
                System.exit(0);
                return;
            }
            Throwable detailCause = failure;
            int causeDepth = 0;
            while (detailCause instanceof java.lang.reflect.InvocationTargetException
                    && detailCause.getCause() != null && causeDepth++ < 4) {
                detailCause = detailCause.getCause();
            }
            String detail = describeFailure(detailCause);
            if (detail == null) {
                detail = "";
            }
            detail = detail.replace('\n', ' ').replace("\r", "");
            if (detail.length() > 160) {
                detail = detail.substring(0, 160);
            }
            String cause = detailCause == failure ? ""
                    : " cause=" + detailCause.getClass().getSimpleName();
            emit("PARTIAL_PATH: " + failure.getClass().getSimpleName() + cause
                    + (detail.length() == 0 ? "" : ": " + detail));
            System.exit(0);
        }
    }

    /** Report the authenticated canary boundary, optionally after a fixed safe adapter effect. */
    private static boolean reportLatchedCanary(String sinkClass, String sinkMethod) {
        if (!io.just.sast.verify.boot.SinkCanaryGate.wasReached()) {
            return false;
        }
        Path scratch = null;
        try {
            scratch = Paths.get(safeScratchRoot);
        } catch (RuntimeException ignored) {
            // A malformed launcher property remains boundary-only.
        }
        LegacySafeSinkAdapter.Observation observation = LegacySafeSinkAdapter.observe(
                safeSinkMode, safeSinkDisposition, safeSinkPolicyDigest, scratch,
                safeJavaExecutable);
        if (observation.observed()) {
            emit("SAFE_EFFECT_OBSERVED: " + safeSinkDisposition + ";mode=" + safeSinkMode
                    + ";effect=" + observation.effect()
                    + ";effect_digest=" + LegacySafeSinkAdapter.effectDigest(observation.effect())
                    + ";parameters=FIXED_BY_JUST");
            System.err.println("SINK_REACHED: " + sinkClass + "." + sinkMethod
                    + " (canary-latched; safe effect observed; target body not entered)");
            return true;
        }
        emit("SINK_BLOCKED: " + sinkClass);
        System.err.println("SINK_REACHED: " + sinkClass + "." + sinkMethod
                + " (canary-latched)");
        return true;
    }

    private static Path locateSafeJavaExecutable() {
        try {
            Path home = Paths.get(System.getProperty("java.home", "."));
            String os = System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT);
            String executable = os.indexOf("win") >= 0 ? "java.exe" : "java";
            Path candidate = home.resolve("bin").resolve(executable).toAbsolutePath().normalize();
            if (!Files.isRegularFile(candidate)) {
                return null;
            }
            if (!Files.isRegularFile(candidate, java.nio.file.LinkOption.NOFOLLOW_LINKS)
                    || Files.isSymbolicLink(candidate)) {
                return null;
            }
            return candidate;
        } catch (RuntimeException ignored) {
            return null;
        }
    }

    private static void emit(String status) {
        String safeStatus = status == null ? "UNTESTABLE: null-status"
                : status.replace('\r', ' ').replace('\n', ' ');
        if (safeStatus.startsWith("SANDBOX_READY")) {
            safeStatus += "|policy=" + isolationPolicyDigest;
        }
        if (safeStatus.length() > 4096) {
            safeStatus = safeStatus.substring(0, 4096);
        }
        if (protocolRunId.length() > 0 && protocolChainFingerprint.length() > 0
                && protocolSinkFingerprint.length() > 0 && protocolNonce.length() > 0
                && protocolArtifactFingerprint.length() > 0) {
            String frame = "JUST_VERIFY_V2:" + (protocolToken == null ? "" : protocolToken)
                    + ":" + protocolRunId + ":" + protocolChainFingerprint + ":"
                    + protocolSinkFingerprint + ":" + protocolNonce + ":"
                    + protocolArtifactFingerprint + ":" + safeStatus;
            writeResultFrame(frame);
            System.out.println(frame);
            return;
        }
        System.out.println(PROTOCOL_PREFIX + (protocolToken == null ? "" : protocolToken)
                + ":" + safeStatus);
    }

    /** Establish the authenticated result channel before loading target classes. */
    private static void initializeResultChannel() {
        // Paths are allowed a larger bound than short protocol labels, but control characters
        // and unbounded values are still rejected before the probe creates its channel.
        String resultFile = boundedPathProperty("just.verify.result-file");
        if (resultFile == null || resultFile.length() == 0) {
            return;
        }
        try {
            String secret = readResultSecret();
            if (!validResultSecret(secret)) {
                resultChannelBroken = true;
                return;
            }
            Path path = Paths.get(resultFile).toAbsolutePath().normalize();
            resultChannel = Files.newOutputStream(path, StandardOpenOption.CREATE_NEW,
                    StandardOpenOption.WRITE);
            resultChannelSecret = secret;
        } catch (Exception failure) {
            resultChannelBroken = true;
            closeResultChannel();
        }
    }

    private static String readResultSecret() throws IOException {
        InputStream input = System.in;
        byte[] buffer = new byte[RESULT_SECRET_HEX_LENGTH + 2];
        int length = 0;
        try {
            while (length < buffer.length) {
                int value = input.read();
                if (value < 0 || value == '\n') {
                    break;
                }
                if (value != '\r') {
                    buffer[length++] = (byte) value;
                }
            }
        } finally {
            input.close();
        }
        if (length != RESULT_SECRET_HEX_LENGTH) {
            return "";
        }
        return new String(buffer, 0, length, StandardCharsets.US_ASCII);
    }

    private static boolean validResultSecret(String secret) {
        if (secret == null || secret.length() != RESULT_SECRET_HEX_LENGTH) {
            return false;
        }
        for (int i = 0; i < secret.length(); i++) {
            char value = secret.charAt(i);
            if (!((value >= '0' && value <= '9') || (value >= 'a' && value <= 'f')
                    || (value >= 'A' && value <= 'F'))) {
                return false;
            }
        }
        return true;
    }

    private static void writeResultFrame(String frame) {
        if (resultChannel == null || resultChannelBroken || !validResultSecret(resultChannelSecret)) {
            return;
        }
        try {
            String line = RESULT_CHANNEL_PREFIX + resultMac(frame) + ":" + frame + "\n";
            resultChannel.write(line.getBytes(StandardCharsets.UTF_8));
            resultChannel.flush();
        } catch (IOException | RuntimeException failure) {
            resultChannelBroken = true;
            closeResultChannel();
        }
    }

    private static String resultMac(String frame) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(resultChannelSecret.getBytes(StandardCharsets.US_ASCII),
                    "HmacSHA256"));
            byte[] digest = mac.doFinal(frame.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(digest.length * 2);
            for (byte value : digest) {
                hex.append(String.format(java.util.Locale.ROOT, "%02x", value & 0xff));
            }
            return hex.toString();
        } catch (GeneralSecurityException impossible) {
            return "";
        }
    }

    private static void closeResultChannel() {
        if (resultChannel == null) {
            return;
        }
        try {
            resultChannel.close();
        } catch (IOException ignored) {
            // The parent rejects an incomplete/unauthenticated channel.
        } finally {
            resultChannel = null;
        }
    }

    private static boolean protocolBound() {
        try {
            return io.just.sast.verify.boot.SinkCanaryGate.protocolBound(protocolRunId,
                    protocolChainFingerprint, protocolSinkFingerprint, protocolNonce,
                    protocolArtifactFingerprint);
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static String sourceAdapterSuffix() {
        return sourceAdapterDetail.length() == 0 ? "" : ";" + sourceAdapterDetail;
    }

    private static String compact(String value) {
        if (value == null || value.length() == 0) {
            return "";
        }
        String normalized = value.replace(';', '_').replace('|', '_')
                .replace('\n', ' ').replace('\r', ' ');
        return normalized.length() <= 96 ? normalized : normalized.substring(0, 96);
    }

    private static List<String[]> parseLinks(String encoded) {
        List<String[]> result = new ArrayList<String[]>();
        if (encoded == null || encoded.length() == 0) {
            return result;
        }
        if (encoded.startsWith("v2;")) {
            int cursor = 3;
            while (cursor < encoded.length()) {
                String[] values = new String[3];
                for (int i = 0; i < values.length; i++) {
                    int colon = encoded.indexOf(':', cursor);
                    if (colon <= cursor) {
                        return new ArrayList<String[]>();
                    }
                    int length;
                    try {
                        length = Integer.parseInt(encoded.substring(cursor, colon));
                    } catch (NumberFormatException malformed) {
                        return new ArrayList<String[]>();
                    }
                    int start = colon + 1;
                    int end = start + length;
                    if (length < 0 || end < start || end > encoded.length()) {
                        return new ArrayList<String[]>();
                    }
                    values[i] = encoded.substring(start, end);
                    cursor = end;
                }
                result.add(values);
            }
            return result;
        }
        for (String hop : encoded.split(",")) {
            int equal = hop.indexOf('=');
            if (equal < 0) {
                continue;
            }
            String left = hop.substring(0, equal);
            int dot = left.lastIndexOf('.');
            if (dot < 0) {
                continue;
            }
            result.add(new String[]{left.substring(0, dot), left.substring(dot + 1),
                    hop.substring(equal + 1)});
        }
        return result;
    }

    private static String[] parseSink(String encoded) {
        String target = encoded == null ? "" : encoded;
        String descriptor = "";
        int bar = target.lastIndexOf('|');
        if (bar > 0) {
            descriptor = target.substring(bar + 1);
            target = target.substring(0, bar);
        }
        int dot = target.lastIndexOf('.');
        if (dot <= 0) {
            return new String[]{"", "", descriptor};
        }
        return new String[]{target.substring(0, dot).replace('/', '.'), target.substring(dot + 1), descriptor};
    }

    private static void ensureInstance(Map<String, Object> instances, String internalName,
                                       boolean serializationMode) {
        String name = internalName.replace('/', '.');
        if (instances.containsKey(name)) {
            return;
        }
        try {
            instances.put(name, newInstance(load(name), serializationMode));
        } catch (Throwable ignored) {
            // Link phase records the missing owner/target as a partial path.
        }
    }

    private static void linkField(Map<String, Object> instances, Object entryInstance,
                                  String[] link, List<String> unlinked,
                                  boolean serializedProbeGraph) {
        String fromClass = link[0].replace('/', '.');
        String toClass = link[2].replace('/', '.');
        Object from = instances.get(fromClass);
        Object to = instances.get(toClass);
        if (from == null) {
            unlinked.add(fromClass + "." + link[1] + ":owner-missing");
            return;
        }
        Field field = findField(from.getClass(), link[1]);
        if (field == null) {
            unlinked.add(fromClass + "." + link[1] + ":field-missing");
            return;
        }
        try {
            field.setAccessible(true);
            if (to != null && field.getType().isInstance(to)
                    && (!serializedProbeGraph || to instanceof Serializable)) {
                field.set(from, to);
            } else if (field.getType() == Object.class) {
                // Keep generic Object fields useful for reflective chains: when the
                // inferred target is unavailable, a safe method-name value is more
                // faithful than recursively assigning the entry host itself.
                Object assigned = to;
                if (serializedProbeGraph && !(assigned instanceof Serializable)) {
                    assigned = null;
                }
                field.set(from, assigned == null ? "toString" : assigned);
            } else if (Map.class.isAssignableFrom(field.getType())
                    || Set.class.isAssignableFrom(field.getType())
                    || List.class.isAssignableFrom(field.getType())) {
                Object collection = newCollection(field.getType());
                if (collection == null || to == null) {
                    unlinked.add(fromClass + "." + link[1] + ":collection-unlinked");
                    return;
                }
                if (collection instanceof Map) {
                    ((Map<Object, Object>) collection).put(to, "echo CHAIN_OK");
                } else if (collection instanceof Set) {
                    ((Set<Object>) collection).add(to);
                } else {
                    ((List<Object>) collection).add(to);
                }
                field.set(from, collection);
            } else if (!field.getType().isPrimitive() && field.getType() != String.class
                    && !field.getType().isEnum()) {
                unlinked.add(fromClass + "." + link[1] + ":type-mismatch");
            }
        } catch (Throwable failure) {
            unlinked.add(fromClass + "." + link[1] + ":" + failure.getClass().getSimpleName());
        }
    }

    private static void fillSimpleFields(Map<String, Object> instances) {
        for (Object instance : instances.values()) {
            for (Class<?> type = instance.getClass(); type != null && type != Object.class;
                 type = type.getSuperclass()) {
                Field[] fields = type.getDeclaredFields();
                for (Field field : fields) {
                    if (Modifier.isStatic(field.getModifiers())) {
                        continue;
                    }
                    try {
                        field.setAccessible(true);
                        if (field.get(instance) != null) {
                            continue;
                        }
                        Class<?> fieldType = field.getType();
                        if (fieldType == String.class || fieldType == Object.class) {
                            field.set(instance, "toString");
                        } else if (fieldType.isArray()) {
                            field.set(instance, Array.newInstance(fieldType.getComponentType(), 0));
                        } else if (fieldType == int.class || fieldType == Integer.class) {
                            field.set(instance, Integer.valueOf(0));
                        } else if (fieldType == boolean.class || fieldType == Boolean.class) {
                            field.set(instance, Boolean.FALSE);
                        } else if (Map.class.isAssignableFrom(fieldType)
                                || Set.class.isAssignableFrom(fieldType)
                                || List.class.isAssignableFrom(fieldType)) {
                            Object collection = newCollection(fieldType);
                            if (collection != null) {
                                field.set(instance, collection);
                            }
                        }
                    } catch (Throwable ignored) {
                    }
                }
            }
        }
    }

    /**
     * Complete the first source callback receiver from the semantic downstream type list.
     * Interface owners are retained as the bean class while a bounded concrete implementation
     * is used as the object value. This mirrors the runtime's declared-type/receiver split and
     * keeps the adapter independent of any benchmark class name.
     */
    private static boolean prepareSourceTrigger(SourceTrigger trigger, Object triggerInstance) {
        if (trigger == null || triggerInstance == null
                || trigger.downstreamOwner == null || trigger.downstreamOwner.length() == 0) {
            return false;
        }
        String[] candidates = trigger.downstreamOwner.split(",");
        Class<?> declared = null;
        Class<?> concrete = null;
        for (String candidate : candidates) {
            if (candidate == null || candidate.length() == 0) {
                continue;
            }
            try {
                Class<?> type = load(candidate.replace('/', '.'));
                if (declared == null) {
                    declared = type;
                }
                if (!type.isInterface() && !Modifier.isAbstract(type.getModifiers())
                        && Serializable.class.isAssignableFrom(type)) {
                    concrete = type;
                    break;
                }
            } catch (Throwable ignored) {
                // An optional implementation must not disable other candidates.
            }
        }
        if (concrete == null) {
            return false;
        }
        try {
            Object downstream = newInstance(concrete, true);
            if (downstream == null || !setReferenceField(triggerInstance, downstream)) {
                return false;
            }
            if (!setClassField(triggerInstance, declared == null ? concrete : declared)) {
                return false;
            }
            if (declared == concrete) {
                return configureInertGetterValue(downstream);
            }
            return true;
        } catch (Throwable ignored) {
            // Source adaptation remains a bounded partial result on unsupported runtimes.
            return false;
        }
    }

    private static boolean configureInertGetterValue(Object wrapper) {
        try {
            // SimpleEntry is serializable but Kryo 4 cannot reflect its private JDK fields
            // on Java 17+ without opening java.base. String has a stable built-in serializer
            // and still exposes harmless JavaBeans getters for the reflective callback path.
            return setClassField(wrapper, String.class)
                    && setReferenceField(wrapper, "CHAIN_OK");
        } catch (Throwable ignored) {
            // Not every downstream object is a two-slot bean wrapper.
            return false;
        }
    }

    private static boolean setReferenceField(Object target, Object value) {
        if (target == null || value == null) {
            return false;
        }
        String[] preferred = {"_obj", "object", "delegate", "target", "value", "inner"};
        for (String name : preferred) {
            Field field = findField(target.getClass(), name);
            if (field != null && field.getType().isInstance(value) && setField(field, target, value)) {
                return true;
            }
        }
        for (Class<?> current = target.getClass(); current != null; current = current.getSuperclass()) {
            for (Field field : current.getDeclaredFields()) {
                if (!Modifier.isStatic(field.getModifiers())
                        && field.getType().isInstance(value) && setField(field, target, value)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean setClassField(Object target, Class<?> value) {
        if (target == null || value == null) {
            return false;
        }
        for (Class<?> current = target.getClass(); current != null; current = current.getSuperclass()) {
            for (Field field : current.getDeclaredFields()) {
                if (!Modifier.isStatic(field.getModifiers()) && field.getType() == Class.class
                        && setField(field, target, value)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean setField(Field field, Object target, Object value) {
        try {
            field.setAccessible(true);
            field.set(target, value);
            return true;
        } catch (IllegalAccessException | RuntimeException | LinkageError ignored) {
            return false;
        }
    }

    private static void trigger(Class<?> entryType, Object entry, String entryMethod,
                                String entryDescriptor, String mode,
                                SourceTrigger sourceTrigger, Object sourceTriggerInstance)
            throws Exception {
        if ("TRIGGER_HASH".equals(mode)) {
            new HashMap<Object, Object>().put(entry, "echo CHAIN_OK");
            return;
        }
        if ("TRIGGER_COMPARETO".equals(mode)) {
            java.util.TreeSet<Object> set = new java.util.TreeSet<Object>();
            set.add(newInstance(entryType, isSerializationMode(mode)));
            set.add(entry);
            return;
        }
        if ("TRIGGER_COMPARATOR".equals(mode)) {
            if (!(entry instanceof java.util.Comparator)) {
                throw new IllegalStateException("entry-not-comparator");
            }
            java.util.TreeMap<Object, Object> map = new java.util.TreeMap<Object, Object>(
                    (java.util.Comparator<Object>) entry);
            map.put("CHAIN_LEFT", "left");
            map.put("CHAIN_RIGHT", "right");
            return;
        }
        if ("TRIGGER_CONTAINS".equals(mode)) {
            List<Object> values = new ArrayList<Object>();
            values.add(new Object());
            values.contains(entry);
            return;
        }
        if ("PROXY".equals(mode)) {
            if (!java.lang.reflect.InvocationHandler.class.isAssignableFrom(entryType)) {
                throw new IllegalStateException("entry-not-handler");
            }
            LegacySandboxSecurityManager.beginProxyBootstrap();
            Object proxy;
            try {
                proxy = java.lang.reflect.Proxy.newProxyInstance(
                        applicationLoader, new Class[]{Runnable.class},
                        (java.lang.reflect.InvocationHandler) entry);
            } finally {
                LegacySandboxSecurityManager.endProxyBootstrap();
            }
            ((Runnable) proxy).run();
            return;
        }
        if ("SERIAL".equals(mode)) {
            LegacySandboxSecurityManager.beginSerializationBootstrap();
            try {
                ByteArrayOutputStream output = new ByteArrayOutputStream();
                ObjectOutputStream objectOutput = new ObjectOutputStream(output);
                objectOutput.writeObject(entry);
                objectOutput.close();
                byte[] bytes = output.toByteArray();
                if (bytes.length > MAX_SERIALIZED_BYTES) {
                    throw new IllegalStateException("serialized-object-too-large");
                }
                ObjectInputStream objectInput = new ApplicationObjectInputStream(new BoundedInputStream(
                        new ByteArrayInputStream(bytes), MAX_SERIALIZED_BYTES));
                try {
                    objectInput.readObject();
                } finally {
                    objectInput.close();
                }
            } finally {
                LegacySandboxSecurityManager.endSerializationBootstrap();
            }
            return;
        }
        Method method = findMethod(entryType, entryMethod, entryDescriptor);
        if (method == null) {
            throw new IllegalStateException("entry-method-missing");
        }
        method.setAccessible(true);
        if ("SOURCE".equals(mode)) {
            Class<?>[] types = method.getParameterTypes();
            Object[] values = new Object[types.length];
            byte[] adaptedPayload = sourcePayload(sourceTrigger, sourceTriggerInstance);
            for (int i = 0; i < types.length; i++) {
                values[i] = sourceValue(types[i], sourceTrigger, sourceTriggerInstance,
                        adaptedPayload);
            }
            LegacySandboxSecurityManager.beginSerializationBootstrap();
            try {
                Object returned = method.invoke(entry, values);
                if (returned == null) {
                    sourceAdapterDetail += ";entry-return=null";
                } else if (returned instanceof String) {
                    sourceAdapterDetail += ";entry-return=" + compact((String) returned);
                } else {
                    // Do not call an arbitrary target toString merely to print diagnostics.
                    sourceAdapterDetail += ";entry-return-type="
                            + compact(returned.getClass().getName());
                }
            } finally {
                LegacySandboxSecurityManager.endSerializationBootstrap();
            }
        } else if (method.getParameterTypes().length == 1
                && method.getParameterTypes()[0] == String.class) {
            method.invoke(entry, "echo CHAIN_OK");
        } else {
            method.invoke(entry);
        }
    }

    private static boolean isSerializationMode(String mode) {
        return "SERIAL".equals(mode) || mode.startsWith("TRIGGER_");
    }

    private static Object newInstance(Class<?> type, boolean serializationMode) throws Exception {
        if (serializationMode && java.io.Serializable.class.isAssignableFrom(type)) {
            Object allocated = allocateWithoutConstructor(type);
            if (allocated != null) {
                return allocated;
            }
            throw new IllegalStateException("constructor-free allocation unavailable: "
                    + type.getName());
        }
        Constructor<?>[] constructors = type.getDeclaredConstructors();
        Constructor<?> best = null;
        for (Constructor<?> constructor : constructors) {
            if (constructor.getParameterTypes().length == 0) {
                best = constructor;
                break;
            }
            if (best == null || constructor.getParameterTypes().length
                    < best.getParameterTypes().length) {
                best = constructor;
            }
        }
        if (best == null) {
            throw new IllegalStateException("no constructor: " + type.getName());
        }
        best.setAccessible(true);
        Class<?>[] parameterTypes = best.getParameterTypes();
        Object[] values = new Object[parameterTypes.length];
        for (int i = 0; i < parameterTypes.length; i++) {
            values[i] = defaultValue(parameterTypes[i]);
        }
        return best.newInstance(values);
    }

    private static Object allocateWithoutConstructor(Class<?> type) {
        boolean bootstrap = false;
        try {
            LegacySandboxSecurityManager.beginSerializationBootstrap();
            bootstrap = true;
            Class<?> unsafeType = ClassLoader.getSystemClassLoader().loadClass("sun.misc.Unsafe");
            Field field = unsafeType.getDeclaredField("theUnsafe");
            field.setAccessible(true);
            Object unsafe = field.get(null);
            Method allocate = unsafeType.getMethod("allocateInstance", Class.class);
            return allocate.invoke(unsafe, type);
        } catch (Throwable ignored) {
            return null;
        } finally {
            if (bootstrap) {
                LegacySandboxSecurityManager.endSerializationBootstrap();
            }
        }
    }

    private static Object defaultValue(Class<?> type) {
        if (type == String.class || type == Object.class) return "toString";
        if (type == int.class) return Integer.valueOf(0);
        if (type == long.class) return Long.valueOf(0L);
        if (type == short.class) return Short.valueOf((short) 0);
        if (type == byte.class) return Byte.valueOf((byte) 0);
        if (type == boolean.class) return Boolean.FALSE;
        if (type == char.class) return Character.valueOf('a');
        if (type == float.class) return Float.valueOf(0.0f);
        if (type == double.class) return Double.valueOf(0.0d);
        if (type.isArray()) return Array.newInstance(type.getComponentType(), 0);
        return null;
    }

    private static Object sourceValue(Class<?> type) {
        if (type == String.class || type == CharSequence.class) return "{}";
        if (type == Object.class) return new java.util.LinkedHashMap<Object, Object>();
        if (type == byte[].class) return "{}".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        if (type == char[].class) return "{}".toCharArray();
        if (InputStream.class.isAssignableFrom(type)) {
            return new ByteArrayInputStream("{}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }
        if (java.io.Reader.class.isAssignableFrom(type)) return new java.io.StringReader("{}");
        if (java.io.OutputStream.class.isAssignableFrom(type)) return new java.io.ByteArrayOutputStream();
        if (Map.class.isAssignableFrom(type)) return new HashMap<Object, Object>();
        if (Set.class.isAssignableFrom(type)) return new HashSet<Object>();
        if (List.class.isAssignableFrom(type)) return new ArrayList<Object>();
        if (type == Class.class) return Object.class;
        if (type.isArray()) return Array.newInstance(type.getComponentType(), 0);
        if (type.isPrimitive()) return defaultValue(type);
        if (type.isEnum()) {
            Object[] values = type.getEnumConstants();
            return values != null && values.length > 0 ? values[0] : null;
        }
        return null;
    }

    /** Prime legacy reflection accessors from the trusted probe frame. */
    private static void warmReflectionRuntime() {
        try {
            Method objectToString = Object.class.getMethod("toString");
            objectToString.invoke(new Object());
            Method stringToString = String.class.getMethod("toString");
            stringToString.invoke("CHAIN_WARMUP");
            Method classGetMethod = Class.class.getMethod("getMethod", String.class,
                    Class[].class);
            classGetMethod.invoke(Object.class, "toString", new Class<?>[0]);
        } catch (ReflectiveOperationException | RuntimeException ignored) {
            // Runtime-specific reflection limitations remain a bounded partial result.
        }
    }

    private static SourceTrigger parseSourceTrigger(String encoded) {
        if (encoded == null || encoded.length() == 0) {
            return null;
        }
        String[] parts = encoded.split("\\|", -1);
        if (parts.length < 6 || parts[0].length() == 0 || parts[1].length() == 0
                || parts[2].length() == 0 || parts[3].length() == 0
                || parts[4].length() == 0) {
            return null;
        }
        return new SourceTrigger(parts[0], parts[1], parts[2], parts[3], parts[4], parts[5],
                parts.length > 6 ? parts[6] : "", parts.length > 7 ? parts[7] : "");
    }

    private static Object sourceValue(Class<?> type, SourceTrigger trigger,
                                      Object triggerInstance, byte[] adaptedPayload)
            throws IOException {
        if (adaptedPayload != null && trigger != null) {
            if (type == String.class || type == CharSequence.class) {
                return java.util.Base64.getEncoder().encodeToString(adaptedPayload);
            }
            if (type == byte[].class) {
                return adaptedPayload;
            }
            if (type == ObjectInputStream.class) {
                return new ApplicationObjectInputStream(
                        new ByteArrayInputStream(adaptedPayload));
            }
            if ("com.esotericsoftware.kryo.Kryo".equals(type.getName())) {
                try {
                    return newKryoInstance();
                } catch (ReflectiveOperationException | LinkageError | RuntimeException ignored) {
                    // Fall through to the generic default; the source boundary will report
                    // the adapter capability limit if the method requires a Kryo instance.
                }
            }
            if ("com.esotericsoftware.kryo.io.Input".equals(type.getName())) {
                Object input = kryoInput(type, adaptedPayload);
                if (input != null) {
                    return input;
                }
            }
            if (InputStream.class.isAssignableFrom(type)) {
                return new ByteArrayInputStream(adaptedPayload);
            }
            if (type == Object.class || java.util.Collection.class.isAssignableFrom(type)) {
                Object seed = triggerInstance != null ? triggerInstance
                        : inertCallbackSeed(trigger.callbackKind);
                Object collection = sourceCollection(seed, trigger.callbackKind);
                if (type.isInstance(collection)) {
                    return collection;
                }
            }
            if (triggerInstance != null && type.isInstance(triggerInstance)) {
                return triggerInstance;
            }
        }
        return sourceValue(type);
    }

    private static byte[] sourcePayload(SourceTrigger trigger, Object triggerInstance)
            throws IOException {
        if (trigger == null) {
            return null;
        }
        sourceAdapterDetail = "source=" + compact(trigger.sourceOwner) + "#"
                + compact(trigger.sourceMethod) + ";callback=" + compact(trigger.callbackKind)
                + ";trigger=" + (triggerInstance == null ? "missing"
                : compact(triggerInstance.getClass().getName()))
                + ";downstream=" + compact(trigger.downstreamOwner);
        Object seed = triggerInstance != null ? triggerInstance
                : inertCallbackSeed(trigger.callbackKind);
        if (isKryoSource(trigger)) {
            byte[] payload = serializeKryoSource(seed, trigger.callbackKind);
            return payload;
        }
        if (!isObjectInputSource(trigger)) {
            return null;
        }
        LegacySandboxSecurityManager.beginSerializationBootstrap();
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            ObjectOutputStream output = new ObjectOutputStream(bytes);
            output.writeObject(sourceCollection(seed, trigger.callbackKind));
            output.close();
            if (bytes.size() > MAX_SERIALIZED_BYTES) {
                throw new IOException("source probe payload exceeds limit");
            }
            return bytes.toByteArray();
        } finally {
            LegacySandboxSecurityManager.endSerializationBootstrap();
        }
    }

    /** Build a bounded Kryo payload through the target application's serializer classes. */
    private static byte[] serializeKryoSource(Object value, String callbackKind)
            throws IOException {
        boolean bootstrap = false;
        try {
            LegacySandboxSecurityManager.beginSerializationBootstrap();
            bootstrap = true;
            LegacySandboxSecurityManager.beginSourceAdapter();
            warmKryoRuntime();
            Class<?> kryoType = load("com.esotericsoftware.kryo.Kryo");
            Object kryo = newKryoInstance();

            Object root = kryoSourceRoot(value, callbackKind);
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            Class<?> outputType = load("com.esotericsoftware.kryo.io.Output");
            Object output = outputType.getConstructor(java.io.OutputStream.class)
                    .newInstance(bytes);
            Method writer = kryoType.getMethod("writeClassAndObject", outputType, Object.class);
            writer.invoke(kryo, output, root);
            try {
                outputType.getMethod("flush").invoke(output);
            } finally {
                outputType.getMethod("close").invoke(output);
            }
            byte[] payload = bytes.toByteArray();
            if (payload.length > MAX_SERIALIZED_BYTES) {
                throw new IOException("kryo source probe payload exceeds limit");
            }
            return payload;
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause() == null ? e : e.getCause();
            throw new IOException("kryo source adapter failed: "
                    + describeFailure(cause), cause);
        } catch (ReflectiveOperationException | LinkageError | RuntimeException e) {
            throw new IOException("kryo source adapter failed: " + describeFailure(e), e);
        } finally {
            LegacySandboxSecurityManager.endSourceAdapter();
            if (bootstrap) {
                LegacySandboxSecurityManager.endSerializationBootstrap();
            }
        }
    }

    private static String describeFailure(Throwable failure) {
        if (failure == null) {
            return "unknown";
        }
        Throwable root = failure;
        int depth = 0;
        while (root.getCause() != null && root.getCause() != root && depth++ < 4) {
            root = root.getCause();
        }
        StringBuilder out = new StringBuilder();
        if (root != failure) {
            out.append(failure.getClass().getSimpleName()).append(" caused-by ");
        }
        out.append(root.getClass().getSimpleName());
        String message = root.getMessage();
        if (message != null && message.length() > 0) {
            out.append(": ").append(message.replace('\n', ' ').replace('\r', ' '));
        }
        if (out.length() > 160) {
            out.setLength(160);
        }
        return out.toString();
    }

    private static void invokeIfPresent(Class<?> owner, Object target, String method,
                                        Class<?> parameter, Object value)
            throws ReflectiveOperationException {
        try {
            owner.getMethod(method, parameter).invoke(target, value);
        } catch (NoSuchMethodException ignored) {
            // Kryo minor versions may omit an optional tuning setter.
        }
    }

    private static Object newKryoInstance() throws ReflectiveOperationException {
        Class<?> kryoType = load("com.esotericsoftware.kryo.Kryo");
        Object kryo = kryoType.getDeclaredConstructor().newInstance();
        invokeIfPresent(kryoType, kryo, "setReferences", boolean.class, Boolean.TRUE);
        invokeIfPresent(kryoType, kryo, "setRegistrationRequired", boolean.class, Boolean.FALSE);
        try {
            Class<?> strategyType = load("org.objenesis.strategy.StdInstantiatorStrategy");
            Object strategy = strategyType.getDeclaredConstructor().newInstance();
            Method setter = kryoType.getMethod("setInstantiatorStrategy",
                    load("org.objenesis.strategy.InstantiatorStrategy"));
            setter.invoke(kryo, strategy);
        } catch (ClassNotFoundException | NoSuchMethodException ignored) {
            // Optional Objenesis is not required for the bounded default serializer.
        }
        return kryo;
    }

    private static Object kryoInput(Class<?> type, byte[] payload) {
        try {
            Constructor<?> constructor = type.getConstructor(InputStream.class);
            return constructor.newInstance(new ByteArrayInputStream(payload));
        } catch (ReflectiveOperationException | LinkageError | RuntimeException ignored) {
            return null;
        }
    }

    private static Object kryoSourceRoot(Object value, String callbackKind) throws IOException {
        if ("compare".equals(callbackKind) && value instanceof java.util.Comparator) {
            java.util.Comparator<Object> comparator = (java.util.Comparator<Object>) value;
            java.util.TreeMap<Object, Object> map = new java.util.TreeMap<Object, Object>(comparator);
            map.put("CHAIN_LEFT", "left");
            map.put("CHAIN_RIGHT", "right");
            return map;
        }
        if ("compareTo".equals(callbackKind) && value instanceof Comparable) {
            java.util.TreeSet<Object> set = new java.util.TreeSet<Object>();
            Object peer = newInstanceQuietly(value.getClass());
            if (peer != null) {
                set.add(peer);
            }
            set.add(value);
            return set;
        }
        if ("hashCode".equals(callbackKind)) {
            // Kryo's MapSerializer calls put() while reading a HashMap.  HashSet is not a
            // safe substitute here: with StdInstantiatorStrategy Kryo 4 can allocate it
            // without running the constructor, leaving its internal map null and making the
            // target catch an NPE before the callback.  The raw map keeps the classic bounded
            // callback shape while MapSerializer itself restores a usable HashMap.
            return rawHashMap(value);
        }
        if ("equals".equals(callbackKind)) {
            Object peer = duplicateWithoutConstructor(value);
            return peer == null ? rawHashMap(value) : rawHashMap(value, peer);
        }
        ArrayList<Object> values = new ArrayList<Object>();
        values.add(value);
        return values;
    }

    private static Object newInstanceQuietly(Class<?> type) {
        try {
            return newInstance(type, true);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static void warmKryoRuntime() {
        String[] optionalTypes = {
                "java.time.Duration", "java.time.Instant", "java.time.LocalDate",
                "java.time.LocalTime", "java.time.LocalDateTime", "java.time.ZoneOffset",
                "java.time.ZoneId", "java.time.OffsetTime", "java.time.OffsetDateTime",
                "java.time.ZonedDateTime", "java.time.Year", "java.time.YearMonth",
                "java.time.MonthDay", "java.time.Period"
        };
        for (String name : optionalTypes) {
            try {
                Class.forName(name, true, null);
            } catch (ClassNotFoundException ignored) {
                // Optional JDK types are absent on older runtimes.
            } catch (LinkageError | RuntimeException failure) {
                // Do not let a poisoned optional class make the later Kryo failure look like
                // an unrelated "Could not initialize class". The caller will report the
                // precise bootstrap cause while the target remains outside this adapter scope.
                throw new IllegalStateException("optional Kryo runtime type unavailable: "
                        + name + ": " + describeFailure(failure), failure);
            }
        }
        try {
            Object.class.getDeclaredConstructor(String.class);
        } catch (NoSuchMethodException ignored) {
            // Initialize the JDK reflection error path before target code is entered.
        }
    }

    private static Object sourceCollection(Object value, String callbackKind)
            throws IOException {
        if ("hashCode".equals(callbackKind)) {
            return rawHashSet(value);
        }
        if ("equals".equals(callbackKind)) {
            Object peer = duplicateWithoutConstructor(value);
            return peer == null ? rawHashSet(value) : rawHashSet(value, peer);
        }
        List<Object> values = new ArrayList<Object>();
        values.add(value);
        return values;
    }

    private static Object inertCallbackSeed(String callbackKind) {
        if ("hashCode".equals(callbackKind) || "equals".equals(callbackKind)
                || "compareTo".equals(callbackKind) || "compare".equals(callbackKind)
                || "toString".equals(callbackKind)) {
            return new java.util.AbstractMap.SimpleEntry<String, String>("CHAIN_OK", "CHAIN_OK");
        }
        return new ArrayList<Object>();
    }

    private static boolean isObjectInputSource(SourceTrigger trigger) {
        if (trigger == null || !("readObject".equals(trigger.sourceMethod)
                || "readUnshared".equals(trigger.sourceMethod)
                || "readFields".equals(trigger.sourceMethod))) {
            return false;
        }
        if ("java/io/ObjectInputStream".equals(trigger.sourceOwner)) {
            return true;
        }
        try {
            return ObjectInputStream.class.isAssignableFrom(
                    load(trigger.sourceOwner.replace('/', '.')));
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static boolean isKryoSource(SourceTrigger trigger) {
        return trigger != null
                && trigger.sourceOwner.startsWith("com/esotericsoftware/kryo/")
                && trigger.sourceMethod.startsWith("read");
    }

    private static Object newSourceTriggerInstance(SourceTrigger trigger,
                                                   Map<String, Object> instances)
            throws ClassNotFoundException {
        String name = trigger.entryClass.replace('/', '.');
        Object existing = instances.get(name);
        if (existing != null) {
            return existing;
        }
        Class<?> type = load(name);
        if (type.isInterface() || Modifier.isAbstract(type.getModifiers())
                || (isObjectInputSource(trigger)
                && !Serializable.class.isAssignableFrom(type))) {
            return null;
        }
        Object result = allocateWithoutConstructor(type);
        if (result != null) {
            instances.put(name, result);
        }
        return result;
    }

    private static Object duplicateWithoutConstructor(Object value) {
        if (!(value instanceof Serializable)) {
            return null;
        }
        return allocateWithoutConstructor(value.getClass());
    }

    private static Object rawHashSet(Object... keys) throws IOException {
        try {
            HashSet<Object> set = new HashSet<Object>();
            unsafePutObject(probeUnsafe(), HashSet.class, set, "map", rawHashMap(keys));
            return set;
        } catch (ReflectiveOperationException | RuntimeException e) {
            throw new IOException("hash-set callback adapter unavailable: "
                    + e.getClass().getSimpleName(), e);
        }
    }

    private static Object rawHashMap(Object... keys) throws IOException {
        if (keys == null || keys.length == 0) {
            throw new IOException("hash callback adapter requires a key");
        }
        try {
            Object unsafe = probeUnsafe();
            Class<?> nodeType;
            try {
                nodeType = Class.forName("java.util.HashMap$Node", false, null);
            } catch (ClassNotFoundException unavailable) {
                nodeType = Class.forName("java.util.HashMap$Entry", false, null);
            }
            Object head = null;
            for (int i = keys.length - 1; i >= 0; i--) {
                Object node = unsafe.getClass().getMethod("allocateInstance", Class.class)
                        .invoke(unsafe, nodeType);
                unsafePutInt(unsafe, nodeType, node, "hash", 0);
                unsafePutObject(unsafe, nodeType, node, "key", keys[i]);
                unsafePutObject(unsafe, nodeType, node, "value", "CHAIN_OK");
                unsafePutObject(unsafe, nodeType, node, "next", head);
                head = node;
            }
            HashMap<Object, Object> map = new HashMap<Object, Object>();
            Object table = Array.newInstance(nodeType, 1);
            Array.set(table, 0, head);
            unsafePutObject(unsafe, HashMap.class, map, "table", table);
            unsafePutInt(unsafe, HashMap.class, map, "size", keys.length);
            return map;
        } catch (ReflectiveOperationException | RuntimeException e) {
            throw new IOException("hash callback adapter unavailable: "
                    + e.getClass().getSimpleName(), e);
        }
    }

    private static Object probeUnsafe() throws ReflectiveOperationException {
        Class<?> type = Class.forName("sun.misc.Unsafe", false,
                ClassLoader.getSystemClassLoader());
        Field field = type.getDeclaredField("theUnsafe");
        field.setAccessible(true);
        return field.get(null);
    }

    private static void unsafePutObject(Object unsafe, Class<?> owner, Object target,
                                        String fieldName, Object value)
            throws ReflectiveOperationException {
        Field field = findField(owner, fieldName);
        if (field == null) {
            throw new NoSuchFieldException(owner.getName() + "." + fieldName);
        }
        Class<?> type = unsafe.getClass();
        long offset = ((Long) type.getMethod("objectFieldOffset", Field.class)
                .invoke(unsafe, field)).longValue();
        type.getMethod("putObject", Object.class, long.class, Object.class)
                .invoke(unsafe, target, Long.valueOf(offset), value);
    }

    private static void unsafePutInt(Object unsafe, Class<?> owner, Object target,
                                      String fieldName, int value)
            throws ReflectiveOperationException {
        Field field = findField(owner, fieldName);
        if (field == null) {
            throw new NoSuchFieldException(owner.getName() + "." + fieldName);
        }
        Class<?> type = unsafe.getClass();
        long offset = ((Long) type.getMethod("objectFieldOffset", Field.class)
                .invoke(unsafe, field)).longValue();
        type.getMethod("putInt", Object.class, long.class, int.class)
                .invoke(unsafe, target, Long.valueOf(offset), Integer.valueOf(value));
    }

    private static Object newCollection(Class<?> type) {
        if (!Map.class.isAssignableFrom(type) && !Set.class.isAssignableFrom(type)
                && !List.class.isAssignableFrom(type)) return null;
        boolean abstractType = type.isInterface() || Modifier.isAbstract(type.getModifiers());
        if (!abstractType) {
            try {
                Constructor<?> constructor = type.getDeclaredConstructor();
                constructor.setAccessible(true);
                return constructor.newInstance();
            } catch (Throwable ignored) {
                return null;
            }
        }
        if (java.util.SortedMap.class.isAssignableFrom(type)) return new java.util.TreeMap<Object, Object>();
        if (Map.class.isAssignableFrom(type)) return new HashMap<Object, Object>();
        if (java.util.SortedSet.class.isAssignableFrom(type)) return new java.util.TreeSet<Object>();
        if (Set.class.isAssignableFrom(type)) return new HashSet<Object>();
        if (List.class.isAssignableFrom(type)) return new ArrayList<Object>();
        return null;
    }

    private static Class<?> load(String name) throws ClassNotFoundException {
        ClassLoader loader = applicationLoader != null
                ? applicationLoader : Thread.currentThread().getContextClassLoader();
        if (loader == null) {
            throw new ClassNotFoundException(name);
        }
        return loader.loadClass(name);
    }

    /**
     * The parent attaches the OS boundary before releasing this marker. Waiting here keeps
     * target class loading and static initialization out of the short pre-attachment window.
     */
    private static boolean awaitIsolationReady() {
        String marker = System.getProperty("just.verify.isolation-ready", "");
        String expected = System.getProperty("just.verify.isolation-token", "");
        if (marker.length() == 0 || expected.length() == 0 || expected.length() > 128) {
            return false;
        }
        Path markerPath;
        try {
            markerPath = Paths.get(marker).toAbsolutePath().normalize();
        } catch (RuntimeException invalidPath) {
            return false;
        }
        long deadline = System.nanoTime() + 5L * 1000000000L;
        while (System.nanoTime() < deadline) {
            try {
                if (Files.isRegularFile(markerPath) && Files.size(markerPath) <= 256L) {
                    String actual = new String(Files.readAllBytes(markerPath), "US-ASCII").trim();
                    if (expected.equals(actual)) {
                        return true;
                    }
                }
            } catch (IOException | RuntimeException ignored) {
                // The parent may still be creating/renaming the marker.
            }
            try {
                Thread.sleep(10L);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        return false;
    }

    /** Strict Linux readiness must be proven from inside the namespace before target loading. */
    private static boolean strictOsAttestation() {
        if (!"OS_STRICT".equals(safeProperty("just.verify.isolation-level", "NONE"))) {
            return true;
        }
        if (!System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT)
                .contains("linux")) {
            return false;
        }
        try {
            String[] namespaces = {"user", "mnt", "pid", "net", "ipc", "uts"};
            for (String namespace : namespaces) {
                if (!Files.exists(Paths.get("/proc/self/ns", namespace))) {
                    return false;
                }
            }
            String status = new String(Files.readAllBytes(Paths.get("/proc/self/status")),
                    "UTF-8");
            if (!status.matches("(?s).*\\nUid:\\s+65534(?:\\s|$).*")
                    || !status.matches("(?s).*\\nNoNewPrivs:\\s+1(?:\\s|$).*")
                    || !status.matches("(?s).*\\nSeccomp:\\s+[12](?:\\s|$).*")) {
                return false;
            }
            String controllers = new String(Files.readAllBytes(
                    Paths.get("/sys/fs/cgroup/cgroup.controllers")), "UTF-8");
            if (!(controllers.contains("cpu") && controllers.contains("memory")
                    && controllers.contains("pids"))) {
                return false;
            }
            if (!cgroupLimitsAttested()) {
                return false;
            }
            if ("true".equalsIgnoreCase(safeProperty("just.verify.loopback", "false"))) {
                return java.net.NetworkInterface.getByInetAddress(
                        java.net.InetAddress.getLoopbackAddress()) != null;
            }
            return true;
        } catch (IOException | RuntimeException ignored) {
            return false;
        }
    }

    /** Verify this Java 8 child is placed in a finite cgroup-v2, not only that controllers exist. */
    private static boolean cgroupLimitsAttested() {
        try {
            Path mount = Paths.get("/sys/fs/cgroup");
            Path cgroupFile = Paths.get("/proc/self/cgroup");
            if (!Files.isDirectory(mount) || !Files.isRegularFile(cgroupFile)) {
                return false;
            }
            String text = new String(Files.readAllBytes(cgroupFile), "UTF-8");
            String relative = "";
            String[] lines = text.split("\\r?\\n");
            for (String line : lines) {
                if (line.startsWith("0::")) {
                    relative = line.substring(3).trim();
                    break;
                }
            }
            if (relative.length() == 0) {
                return false;
            }
            Path group = mount.resolve(relative.startsWith("/")
                    ? relative.substring(1) : relative).normalize();
            if (!group.startsWith(mount) || !Files.isDirectory(group)) {
                return false;
            }
            String runtimeName = java.lang.management.ManagementFactory
                    .getRuntimeMXBean().getName();
            int at = runtimeName.indexOf('@');
            String pid = at > 0 ? runtimeName.substring(0, at) : runtimeName;
            String processes = new String(Files.readAllBytes(group.resolve("cgroup.procs")), "UTF-8");
            boolean member = false;
            for (String process : processes.split("\\r?\\n")) {
                if (pid.equals(process.trim())) {
                    member = true;
                    break;
                }
            }
            if (!member) {
                return false;
            }
            long memory = finiteCgroupValue(new String(
                    Files.readAllBytes(group.resolve("memory.max")), "UTF-8"));
            long pids = finiteCgroupValue(new String(
                    Files.readAllBytes(group.resolve("pids.max")), "UTF-8"));
            String[] cpu = new String(Files.readAllBytes(group.resolve("cpu.max")), "UTF-8")
                    .trim().split("\\s+");
            long quota = cpu.length > 0 && !"max".equals(cpu[0])
                    ? finiteCgroupValue(cpu[0]) : -1L;
            return memory > 0L && pids > 0L && quota > 0L;
        } catch (IOException | RuntimeException ignored) {
            return false;
        }
    }

    private static long finiteCgroupValue(String value) {
        if (value == null || value.trim().length() == 0 || "max".equals(value.trim())) {
            return -1L;
        }
        try {
            long parsed = Long.parseLong(value.trim());
            return parsed > 0L ? parsed : -1L;
        } catch (NumberFormatException ignored) {
            return -1L;
        }
    }

    /** Install the child-side Landlock filesystem policy before target class loading. */
    private static boolean installLandlock() {
        try {
            List<Path> writable = new ArrayList<Path>();
            Path temp = Paths.get(System.getProperty("java.io.tmpdir", "."))
                    .toAbsolutePath().normalize();
            if (Files.isDirectory(temp)) {
                writable.add(temp);
            }
            String resultFile = boundedPathProperty("just.verify.result-file");
            if (resultFile.length() > 0) {
                Path parent = Paths.get(resultFile).toAbsolutePath().normalize().getParent();
                if (parent != null && Files.isDirectory(parent) && !writable.contains(parent)) {
                    writable.add(parent);
                }
            }
            return LinuxLandlock.install(writable);
        } catch (RuntimeException failure) {
            return false;
        }
    }

    private static String safeProperty(String key, String fallback) {
        String value = System.getProperty(key, fallback);
        if (value == null || value.length() == 0 || value.length() > 96
                || value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0) {
            return fallback;
        }
        return value;
    }

    private static String boundedPathProperty(String key) {
        String value = System.getProperty(key, "");
        if (value == null || value.length() == 0 || value.length() > 4096
                || value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0) {
            return "";
        }
        return value;
    }

    /** Keep the legacy probe/agent loader out of the target application loader. */
    private static void installApplicationLoader() {
        if (applicationLoader != null) {
            return;
        }
        List<URL> urls = new ArrayList<URL>();
        String classPath = System.getProperty("just.verify.target-cp", "");
        if (classPath.length() == 0) {
            // Compatibility for manually launched legacy probes; production children pass a
            // target-only classpath so the system loader does not expose verifier classes.
            classPath = System.getProperty("java.class.path", "");
        }
        String probeJar = System.getProperty("just.verify.probe-jar", "");
        String normalizedProbe = probeJar.length() == 0 ? ""
                : Paths.get(probeJar).toAbsolutePath().normalize().toString();
        String[] entries = classPath.split(java.util.regex.Pattern.quote(
                java.io.File.pathSeparator));
        for (String entry : entries) {
            if (entry.length() == 0) {
                continue;
            }
            try {
                Path normalized = Paths.get(entry).toAbsolutePath().normalize();
                if (normalizedProbe.length() > 0 && normalized.toString().equals(normalizedProbe)) {
                    continue;
                }
                urls.add(normalized.toUri().toURL());
            } catch (RuntimeException | java.net.MalformedURLException ignored) {
                // A malformed optional entry must not widen the target loader.
            }
        }
        ClassLoader parent = ClassLoader.getSystemClassLoader().getParent();
        if (urls.isEmpty()) {
            applicationLoader = parent;
            return;
        }
        try {
            applicationLoader = new URLClassLoader(urls.toArray(new URL[urls.size()]), parent);
            Thread.currentThread().setContextClassLoader(applicationLoader);
        } catch (RuntimeException ignored) {
            applicationLoader = parent;
        }
    }

    private static Field findField(Class<?> type, String name) {
        for (Class<?> current = type; current != null; current = current.getSuperclass()) {
            try {
                return current.getDeclaredField(name);
            } catch (NoSuchFieldException ignored) {
            }
        }
        return null;
    }

    private static Method findMethod(Class<?> type, String name) {
        return findMethod(type, name, "");
    }

    /** Resolve serialized application classes through the isolated application loader. */
    private static final class ApplicationObjectInputStream extends ObjectInputStream {
        private ApplicationObjectInputStream(InputStream input) throws IOException {
            super(input);
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass descriptor)
                throws IOException, ClassNotFoundException {
            try {
                return resolveSerializedType(descriptor.getName());
            } catch (ClassNotFoundException missing) {
                return super.resolveClass(descriptor);
            }
        }

        @Override
        protected Class<?> resolveProxyClass(String[] interfaces)
                throws IOException, ClassNotFoundException {
            if (applicationLoader != null && interfaces != null) {
                Class<?>[] resolved = new Class<?>[interfaces.length];
                try {
                    for (int i = 0; i < interfaces.length; i++) {
                        resolved[i] = applicationLoader.loadClass(interfaces[i]);
                    }
                    return java.lang.reflect.Proxy.getProxyClass(applicationLoader, resolved);
                } catch (IllegalArgumentException | SecurityException ignored) {
                    // Fall through to ObjectInputStream's standard resolver for a JDK proxy.
                }
            }
            return super.resolveProxyClass(interfaces);
        }
    }

    private static Class<?> resolveSerializedType(String name) throws ClassNotFoundException {
        if (applicationLoader == null || name == null || name.length() == 0) {
            throw new ClassNotFoundException(name);
        }
        if (!name.startsWith("[")) {
            return applicationLoader.loadClass(name);
        }
        Class<?> component = resolveSerializedType(name.substring(1));
        return Array.newInstance(component, 0).getClass();
    }

    private static Method findMethod(Class<?> type, String name, String descriptor) {
        if (descriptor != null && descriptor.length() > 0) {
            Class<?>[] parameters = parameterTypes(descriptor);
            if (parameters == null) return null;
            try {
                Method publicMethod = type.getMethod(name, parameters);
                if (descriptor.equals(methodDescriptor(publicMethod))) return publicMethod;
            } catch (NoSuchMethodException ignored) {
            } catch (LinkageError ignored) {
                return null;
            }
            for (Class<?> current = type; current != null; current = current.getSuperclass()) {
                try {
                    Method method = current.getDeclaredMethod(name, parameters);
                    return descriptor.equals(methodDescriptor(method)) ? method : null;
                } catch (NoSuchMethodException ignored) {
                } catch (LinkageError ignored) {
                    return null;
                }
            }
            return null;
        }
        try {
            for (Method method : type.getMethods()) {
                if (method.getName().equals(name)) return method;
            }
            for (Class<?> current = type; current != null; current = current.getSuperclass()) {
                for (Method method : current.getDeclaredMethods()) {
                    if (method.getName().equals(name)) return method;
                }
            }
        } catch (LinkageError ignored) {
            // Without a descriptor, reflection cannot safely disambiguate a method after an
            // optional signature failed to resolve. Keep the result partial.
        }
        return null;
    }

    private static Class<?>[] parameterTypes(String descriptor) {
        if (descriptor.length() < 3 || descriptor.charAt(0) != '(') return null;
        List<Class<?>> result = new ArrayList<Class<?>>();
        int[] cursor = new int[]{1};
        try {
            while (cursor[0] < descriptor.length() && descriptor.charAt(cursor[0]) != ')') {
                result.add(descriptorType(descriptor, cursor));
            }
            if (cursor[0] >= descriptor.length() || descriptor.charAt(cursor[0]) != ')') return null;
            cursor[0]++;
            descriptorType(descriptor, cursor);
            return cursor[0] == descriptor.length()
                    ? result.toArray(new Class<?>[result.size()]) : null;
        } catch (ClassNotFoundException | LinkageError | RuntimeException ignored) {
            return null;
        }
    }

    private static Class<?> descriptorType(String descriptor, int[] cursor)
            throws ClassNotFoundException {
        if (cursor[0] >= descriptor.length()) throw new IllegalArgumentException("truncated descriptor");
        char marker = descriptor.charAt(cursor[0]++);
        switch (marker) {
            case 'B': return byte.class;
            case 'C': return char.class;
            case 'D': return double.class;
            case 'F': return float.class;
            case 'I': return int.class;
            case 'J': return long.class;
            case 'S': return short.class;
            case 'Z': return boolean.class;
            case 'V': return void.class;
            case 'L':
                int end = descriptor.indexOf(';', cursor[0]);
                if (end < 0) throw new IllegalArgumentException("unterminated object type");
                String binaryName = descriptor.substring(cursor[0], end).replace('/', '.');
                cursor[0] = end + 1;
                return load(binaryName);
            case '[':
                Class<?> component = descriptorType(descriptor, cursor);
                if (component == void.class) throw new IllegalArgumentException("void array");
                return Array.newInstance(component, 0).getClass();
            default: throw new IllegalArgumentException("unknown descriptor type: " + marker);
        }
    }

    private static boolean matchesDescriptor(Method method, String descriptor) {
        return descriptor == null || descriptor.length() == 0 || descriptor.equals(methodDescriptor(method));
    }

    private static String methodDescriptor(Method method) {
        StringBuilder out = new StringBuilder("(");
        for (Class<?> parameter : method.getParameterTypes()) out.append(typeDescriptor(parameter));
        return out.append(')').append(typeDescriptor(method.getReturnType())).toString();
    }

    private static String typeDescriptor(Class<?> type) {
        if (type.isArray()) return type.getName().replace('.', '/');
        if (!type.isPrimitive()) return "L" + type.getName().replace('.', '/') + ";";
        if (type == void.class) return "V";
        if (type == boolean.class) return "Z";
        if (type == byte.class) return "B";
        if (type == char.class) return "C";
        if (type == short.class) return "S";
        if (type == int.class) return "I";
        if (type == long.class) return "J";
        if (type == float.class) return "F";
        return "D";
    }

    private static String markerSpec(Throwable top) {
        int depth = 0;
        for (Throwable current = top; current != null && depth++ < 6; current = current.getCause()) {
            if (io.just.sast.verify.boot.SinkReachedError.class.getName()
                    .equals(current.getClass().getName())) {
                return current.getMessage();
            }
        }
        return null;
    }

    private static boolean sameSink(String spec, String sinkClass, String sinkMethod, String descriptor) {
        if (spec == null) return false;
        int first = spec.indexOf('#');
        if (first <= 0) return false;
        String methodAndDescriptor = spec.substring(first + 1);
        int second = methodAndDescriptor.indexOf('#');
        String method = second < 0 ? methodAndDescriptor : methodAndDescriptor.substring(0, second);
        String canaryDescriptor = second < 0 ? "" : methodAndDescriptor.substring(second + 1);
        return spec.substring(0, first).replace('/', '.').equals(sinkClass)
                && method.equals(sinkMethod)
                && (second < 0 || descriptor.length() == 0 || descriptor.equals(canaryDescriptor));
    }

    private static boolean entryReached(Throwable top, String entryClass, String entryMethod) {
        int depth = 0;
        for (Throwable current = top; current != null && depth++ < 6; current = current.getCause()) {
            for (StackTraceElement frame : current.getStackTrace()) {
                if (entryClass.equals(frame.getClassName()) && entryMethod.equals(frame.getMethodName())) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean reachesSink(Throwable top, String sinkClass, String sinkMethod) {
        if (sinkClass.length() == 0 || sinkMethod.length() == 0) return false;
        int depth = 0;
        for (Throwable current = top; current != null && depth++ < 6; current = current.getCause()) {
            StackTraceElement[] frames = current.getStackTrace();
            for (StackTraceElement frame : frames) {
                if (sinkClass.equals(frame.getClassName()) && sinkMethod.equals(frame.getMethodName())) {
                    return true;
                }
            }
            if (frames.length == 0 && getStackTrace(current).indexOf(
                    "at " + sinkClass + "." + sinkMethod + "(") >= 0) return true;
        }
        return false;
    }

    private static String getStackTrace(Throwable failure) {
        java.io.StringWriter writer = new java.io.StringWriter();
        failure.printStackTrace(new java.io.PrintWriter(writer));
        return writer.toString();
    }

    private static final class BoundedInputStream extends FilterInputStream {
        private final long limit;
        private long count;

        private BoundedInputStream(InputStream input, long limit) {
            super(input);
            this.limit = limit;
        }

        @Override
        public int read() throws IOException {
            if (count >= limit) return -1;
            int value = super.read();
            if (value >= 0) count++;
            return value;
        }

        @Override
        public int read(byte[] buffer, int offset, int length) throws IOException {
            if (count >= limit) return -1;
            int allowed = (int) Math.min((long) length, limit - count);
            int read = super.read(buffer, offset, allowed);
            if (read > 0) count += read;
            return read;
        }
    }
}
