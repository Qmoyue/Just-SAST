package io.just.sast.blackboard;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Typed coverage snapshot for the dynamic second-pass verifier.
 *
 * <p>The denominator is normalized application finding groups, never raw paths or a top-k
 * selection.  A group may reference more than one exact plan (for example, alternative object
 * constructions); each plan remains an independently auditable attempt.  This fact records the
 * distinction between a plan being selected and a controlled child actually being attempted so
 * a bounded budget cannot be presented as full coverage.</p>
 */
public record VerificationCoverage(
        String schemaVersion,
        Status status,
        int eligibleFindingGroups,
        int coveredFindingGroups,
        int confirmedGroups,
        int noObservationGroups,
        int uniquePlans,
        int attemptedPlans,
        Map<String, List<String>> chainsByGroup,
        Map<String, List<String>> plansByGroup,
        Map<String, List<String>> requiredSlotsByGroup,
        Map<String, List<String>> attemptedSlotsByGroup,
        Set<String> confirmedGroupIds,
        Set<String> noObservationGroupIds,
        Map<String, String> deferredReasons,
        String digest) implements BlackboardFact {

    public static final String SCHEMA_VERSION = "JUST-VERIFICATION-COVERAGE-V1";

    public enum Status {
        NOT_REQUESTED,
        COMPLETE,
        PARTIAL_DYNAMIC_BUDGET,
        PARTIAL_DYNAMIC_FAILURE,
        NO_ELIGIBLE_GROUP,
        ISOLATION_UNAVAILABLE,
        UNKNOWN
    }

    public VerificationCoverage {
        if (!SCHEMA_VERSION.equals(schemaVersion)) {
            throw new IllegalArgumentException("unsupported verification coverage schema: "
                    + schemaVersion);
        }
        status = status == null ? Status.UNKNOWN : status;
        eligibleFindingGroups = Math.max(0, eligibleFindingGroups);
        coveredFindingGroups = bounded(coveredFindingGroups, eligibleFindingGroups);
        confirmedGroups = bounded(confirmedGroups, coveredFindingGroups);
        noObservationGroups = bounded(noObservationGroups, coveredFindingGroups);
        uniquePlans = Math.max(0, uniquePlans);
        attemptedPlans = Math.min(Math.max(0, attemptedPlans), uniquePlans);
        chainsByGroup = immutableLists(chainsByGroup);
        plansByGroup = immutableLists(plansByGroup);
        requiredSlotsByGroup = immutableLists(requiredSlotsByGroup);
        attemptedSlotsByGroup = immutableLists(attemptedSlotsByGroup);
        confirmedGroupIds = immutableSet(confirmedGroupIds);
        noObservationGroupIds = immutableSet(noObservationGroupIds);
        deferredReasons = immutableStrings(deferredReasons);
        if (chainsByGroup.size() != eligibleFindingGroups) {
            throw new IllegalArgumentException("group map and eligible count disagree");
        }
        if (!confirmedGroupIds.stream().allMatch(chainsByGroup::containsKey)
                || !noObservationGroupIds.stream().allMatch(chainsByGroup::containsKey)) {
            throw new IllegalArgumentException("verification group state references unknown group");
        }
        if (!attemptedSlotsByGroup.keySet().stream().allMatch(requiredSlotsByGroup::containsKey)) {
            throw new IllegalArgumentException("attempted slots reference unknown group");
        }
        digest = normalizeDigest(digest);
    }

    public static VerificationCoverage empty(Status status) {
        return new VerificationCoverage(SCHEMA_VERSION, status, 0, 0, 0, 0, 0, 0,
                Map.of(), Map.of(), Map.of(), Map.of(), Set.of(), Set.of(), Map.of(), "UNKNOWN");
    }

    public boolean complete() {
        return status == Status.COMPLETE && eligibleFindingGroups == coveredFindingGroups;
    }

    /** Coverage in thousandths, retaining an exact zero denominator as 1000 only for no groups. */
    public int coveragePermille() {
        return eligibleFindingGroups == 0
                ? 1000
                : Math.min(1000, (coveredFindingGroups * 1000) / eligibleFindingGroups);
    }

    /**
     * Number of plans saved by sharing, in thousandths of selected/unique plans.
     *
     * <p>The current verifier still schedules exact chain plans one-for-one.  An
     * unattempted plan is budget/dependency deferral, not sharing, so it must not
     * inflate this metric.  Keep the value explicitly zero until the shared-plan
     * scheduler emits a typed reuse fact.</p>
     */
    public int planReusePermille() {
        return 0;
    }

    /** Stable JSON consumed by reports and acceptance tooling; no prose is used as state. */
    public String toCanonicalJson() {
        StringBuilder json = new StringBuilder(2048)
                .append("{\"schema_version\":\"").append(json(schemaVersion))
                .append("\",\"status\":\"").append(status)
                .append("\",\"eligible_finding_groups\":").append(eligibleFindingGroups)
                .append(",\"covered_finding_groups\":").append(coveredFindingGroups)
                .append(",\"confirmed_groups\":").append(confirmedGroups)
                .append(",\"no_observation_groups\":").append(noObservationGroups)
                .append(",\"unique_plans\":").append(uniquePlans)
                .append(",\"attempted_plans\":").append(attemptedPlans)
                .append(",\"coverage_permille\":").append(coveragePermille())
                .append(",\"plan_reuse_permille\":").append(planReusePermille())
                .append(",\"chains_by_group\":").append(listsJson(chainsByGroup))
                .append(",\"plans_by_group\":").append(listsJson(plansByGroup))
                .append(",\"required_slots_by_group\":").append(listsJson(requiredSlotsByGroup))
                .append(",\"attempted_slots_by_group\":").append(listsJson(attemptedSlotsByGroup))
                .append(",\"confirmed_group_ids\":").append(setJson(confirmedGroupIds))
                .append(",\"no_observation_group_ids\":").append(setJson(noObservationGroupIds))
                .append(",\"deferred_reasons\":").append(stringsJson(deferredReasons))
                .append(",\"digest\":\"").append(json(digest)).append("\"}");
        return json.toString();
    }

    /** Compute a digest after constructing the immutable snapshot with a placeholder digest. */
    public VerificationCoverage withComputedDigest() {
        VerificationCoverage unsigned = new VerificationCoverage(schemaVersion, status,
                eligibleFindingGroups, coveredFindingGroups, confirmedGroups, noObservationGroups,
                uniquePlans, attemptedPlans, chainsByGroup, plansByGroup, requiredSlotsByGroup,
                attemptedSlotsByGroup, confirmedGroupIds, noObservationGroupIds, deferredReasons,
                "UNKNOWN");
        return new VerificationCoverage(schemaVersion, status, eligibleFindingGroups,
                coveredFindingGroups, confirmedGroups, noObservationGroups, uniquePlans,
                attemptedPlans, chainsByGroup, plansByGroup, requiredSlotsByGroup,
                attemptedSlotsByGroup, confirmedGroupIds, noObservationGroupIds, deferredReasons,
                sha256(unsigned.toCanonicalJson()));
    }

    private static int bounded(int value, int maximum) {
        return Math.min(Math.max(0, value), Math.max(0, maximum));
    }

    private static Map<String, List<String>> immutableLists(Map<String, List<String>> source) {
        Map<String, List<String>> sorted = new TreeMap<>();
        if (source != null) {
            source.forEach((key, values) -> {
                if (key == null || key.isBlank()) {
                    return;
                }
                TreeSet<String> normalized = new TreeSet<>();
                if (values != null) {
                    values.stream().filter(value -> value != null && !value.isBlank())
                            .map(String::trim).forEach(normalized::add);
                }
                sorted.put(key, List.copyOf(normalized));
            });
        }
        return Collections.unmodifiableMap(sorted);
    }

    private static Set<String> immutableSet(Set<String> source) {
        TreeSet<String> sorted = new TreeSet<>();
        if (source != null) {
            source.stream().filter(value -> value != null && !value.isBlank())
                    .map(String::trim).forEach(sorted::add);
        }
        return Collections.unmodifiableSet(sorted);
    }

    private static Map<String, String> immutableStrings(Map<String, String> source) {
        Map<String, String> sorted = new TreeMap<>();
        if (source != null) {
            source.forEach((key, value) -> {
                if (key != null && !key.isBlank() && value != null && !value.isBlank()) {
                    sorted.put(key.trim(), value.trim());
                }
            });
        }
        return Collections.unmodifiableMap(sorted);
    }

    private static String normalizeDigest(String value) {
        if (value == null || value.isBlank() || "UNKNOWN".equalsIgnoreCase(value)) {
            return "UNKNOWN";
        }
        String normalized = value.trim().toUpperCase(java.util.Locale.ROOT);
        if (!normalized.matches("[0-9A-F]{64}")) {
            throw new IllegalArgumentException("coverage digest must be SHA-256 or UNKNOWN");
        }
        return normalized;
    }

    private static String listsJson(Map<String, List<String>> values) {
        StringBuilder json = new StringBuilder("{");
        int index = 0;
        for (Map.Entry<String, List<String>> entry : values.entrySet()) {
            if (index++ > 0) json.append(',');
            json.append('"').append(json(entry.getKey())).append("\":[");
            for (int i = 0; i < entry.getValue().size(); i++) {
                if (i > 0) json.append(',');
                json.append('"').append(json(entry.getValue().get(i))).append('"');
            }
            json.append(']');
        }
        return json.append('}').toString();
    }

    private static String setJson(Set<String> values) {
        StringBuilder json = new StringBuilder("[");
        int index = 0;
        for (String value : values) {
            if (index++ > 0) json.append(',');
            json.append('"').append(json(value)).append('"');
        }
        return json.append(']').toString();
    }

    private static String stringsJson(Map<String, String> values) {
        StringBuilder json = new StringBuilder("{");
        int index = 0;
        for (Map.Entry<String, String> entry : values.entrySet()) {
            if (index++ > 0) json.append(',');
            json.append('"').append(json(entry.getKey())).append("\":\"")
                    .append(json(entry.getValue())).append('"');
        }
        return json.append('}').toString();
    }

    private static String json(String value) {
        if (value == null) return "";
        StringBuilder result = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char current = value.charAt(i);
            switch (current) {
                case '"' -> result.append("\\\"");
                case '\\' -> result.append("\\\\");
                case '\n' -> result.append("\\n");
                case '\r' -> result.append("\\r");
                case '\t' -> result.append("\\t");
                default -> {
                    if (current < 0x20) result.append(String.format("\\u%04x", (int) current));
                    else result.append(current);
                }
            }
        }
        return result.toString();
    }

    private static String sha256(String value) {
        try {
            byte[] bytes = MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder result = new StringBuilder(64);
            for (byte current : bytes) {
                result.append(String.format(java.util.Locale.ROOT, "%02x", current & 0xff));
            }
            return result.toString().toUpperCase(java.util.Locale.ROOT);
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }
}
