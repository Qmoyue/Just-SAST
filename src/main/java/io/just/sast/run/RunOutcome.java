package io.just.sast.run;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.TreeSet;

/**
 * The single closed result contract for a Just invocation.
 *
 * <p>Semantic completeness, process exit, support availability and budget accounting are
 * deliberately separate axes.  A partial scan therefore remains a successful process (exit
 * code 0) while remaining non-cacheable and visibly incomplete.</p>
 */
public record RunOutcome(Status status, ExitReason exitReason, SupportStatus supportStatus,
                         InputBudgetResult inputBudgetResult, List<String> reasonCodes,
                         String detail) {

    public enum Status {
        SUCCESS,
        PARTIAL,
        FAILED,
        USAGE_ERROR,
        UNSUPPORTED,
        NOT_RUN
    }

    private static final String[] NEGATIVE_DYNAMIC_STATUSES = {
            "PARTIAL", "FAILED", "TIMEOUT", "UNTESTABLE", "UNKNOWN"
    };

    public RunOutcome {
        status = status == null ? Status.NOT_RUN : status;
        exitReason = exitReason == null ? ExitReason.INTERNAL : exitReason;
        supportStatus = supportStatus == null ? SupportStatus.UNKNOWN : supportStatus;
        inputBudgetResult = inputBudgetResult == null
                ? InputBudgetResult.unknown("MISSING_BUDGET_RESULT") : inputBudgetResult;
        TreeSet<String> normalizedReasons = new TreeSet<>();
        if (reasonCodes != null) {
            for (String reason : reasonCodes) {
                if (reason != null && !reason.isBlank()) {
                    normalizedReasons.add(normalizeReason(reason));
                }
            }
        }
        reasonCodes = List.copyOf(normalizedReasons);
        detail = detail == null ? "" : detail;
    }

    public int exitCode() {
        return exitReason.code();
    }

    public boolean processSucceeded() {
        return exitReason.processSucceeded();
    }

    /** A complete, supported, budget-valid run is the only reusable cache result. */
    public boolean cacheable() {
        return status == Status.SUCCESS
                && supportStatus == SupportStatus.SUPPORTED
                && inputBudgetResult.reusable()
                && reasonCodes.isEmpty();
    }

    public static RunOutcome success() {
        return new RunOutcome(Status.SUCCESS, ExitReason.OK, SupportStatus.SUPPORTED,
                InputBudgetResult.notRequested(), List.of(), "");
    }

    public static RunOutcome partial(SupportStatus support, InputBudgetResult budget,
                                     Collection<String> reasons, String detail) {
        return new RunOutcome(Status.PARTIAL, ExitReason.OK,
                support == null ? SupportStatus.PARTIAL : support,
                budget == null ? InputBudgetResult.unknown("MISSING_BUDGET_RESULT") : budget,
                reasons == null ? List.of("PARTIAL_RESULT") : new ArrayList<>(reasons), detail);
    }

    public static RunOutcome usage(String reasonCode, String detail) {
        return new RunOutcome(Status.USAGE_ERROR, ExitReason.USAGE,
                SupportStatus.NOT_APPLICABLE, InputBudgetResult.notRequested(),
                List.of(reasonCode == null ? "USAGE_ERROR" : reasonCode), detail);
    }

    public static RunOutcome failed(String reasonCode, String detail) {
        return new RunOutcome(Status.FAILED, ExitReason.INTERNAL, SupportStatus.UNKNOWN,
                InputBudgetResult.unknown("RUN_FAILED"),
                List.of(reasonCode == null ? "RUN_FAILED" : reasonCode), detail);
    }

    public static RunOutcome unsupported(String reasonCode, String detail) {
        return new RunOutcome(Status.UNSUPPORTED, ExitReason.UNSUPPORTED_RUNTIME,
                SupportStatus.UNSUPPORTED, InputBudgetResult.notRequested(),
                List.of(reasonCode == null ? "UNSUPPORTED_RUNTIME" : reasonCode), detail);
    }

    public static RunOutcome notRun(String reasonCode, String detail) {
        return new RunOutcome(Status.NOT_RUN, ExitReason.INTERNAL, SupportStatus.UNKNOWN,
                InputBudgetResult.unknown("NOT_RUN"),
                List.of(reasonCode == null ? "NOT_RUN" : reasonCode), detail);
    }

    /**
     * Classify a completed scan from its typed report axes.  This replaces cache/runner/report
     * copies of the old COMPLETE/PARTIAL/UNKNOWN string inference.
     */
    public static RunOutcome forScan(String completeness, String chainProofCompleteness,
                                     Collection<String> dynamicStatuses) {
        String complete = normalize(completeness);
        String proof = normalize(chainProofCompleteness);
        TreeSet<String> statuses = new TreeSet<>();
        if (dynamicStatuses != null) {
            for (String status : dynamicStatuses) {
                if (status != null && !status.isBlank()) {
                    statuses.add(normalize(status));
                }
            }
        }
        List<String> reasons = new ArrayList<>();
        boolean unknown = "UNKNOWN".equals(complete) || "UNKNOWN".equals(proof);
        boolean incomplete = !"COMPLETE".equals(complete) || !"COMPLETE".equals(proof);
        boolean dynamicIncomplete = statuses.stream().anyMatch(RunOutcome::negativeDynamicStatus);
        if (unknown) {
            reasons.add("ANALYSIS_STATUS_UNKNOWN");
        } else if (incomplete) {
            reasons.add("ANALYSIS_INCOMPLETE");
        }
        if (dynamicIncomplete) {
            reasons.add("DYNAMIC_INCOMPLETE");
        }
        if (reasons.isEmpty()) {
            return success();
        }
        return partial(unknown ? SupportStatus.UNKNOWN : SupportStatus.PARTIAL,
                InputBudgetResult.notRequested(), reasons,
                String.join(",", reasons));
    }

    /** Performance runner classification uses the same result owner as normal CLI runs. */
    public static RunOutcome forPerformance(boolean gatePassed, boolean samplesObserved) {
        if (!samplesObserved) {
            return notRun("NO_MEASURED_SAMPLES", "performance runner produced no samples");
        }
        return gatePassed ? success() : failed("PERFORMANCE_GATE_FAILED",
                "one or more performance gates failed");
    }

    public String toCanonicalJson() {
        StringBuilder out = new StringBuilder(320);
        out.append("{\"schema_version\":1,\"status\":\"").append(status.name())
                .append("\",\"exit_reason\":\"").append(exitReason.name())
                .append("\",\"exit_code\":").append(exitCode())
                .append(",\"support_status\":\"").append(supportStatus.name())
                .append("\",\"input_budget\":").append(inputBudgetResult.toCanonicalJson())
                .append(",\"reason_codes\":[");
        for (int i = 0; i < reasonCodes.size(); i++) {
            if (i > 0) {
                out.append(',');
            }
            out.append('\"').append(escape(reasonCodes.get(i))).append('\"');
        }
        out.append("],\"detail\":\"").append(escape(detail)).append("\"}");
        return out.toString();
    }

    private static boolean negativeDynamicStatus(String status) {
        for (String negative : NEGATIVE_DYNAMIC_STATUSES) {
            if (negative.equals(status)) {
                return true;
            }
        }
        return false;
    }

    private static String normalize(String value) {
        return value == null || value.isBlank() ? "UNKNOWN"
                : value.trim().toUpperCase(Locale.ROOT);
    }

    private static String normalizeReason(String value) {
        return normalize(value).replace(' ', '_');
    }

    private static String escape(String value) {
        return value == null ? "" : value.replace("\\", "\\\\")
                .replace("\"", "\\\"").replace("\r", "\\r").replace("\n", "\\n");
    }
}
