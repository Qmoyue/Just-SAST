package io.just.sast.util;

import io.just.sast.run.InputBudget;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Immutable evidence for the scan-boundary input digest check.
 *
 * <p>The first digest is computed before parsing and the second one after analysis.  The
 * second pass deliberately reuses the scan caller's tracker: an integrity check must not
 * obtain a fresh byte/time allowance that can hide an aggregate input-budget exhaustion.  A
 * failed after-check is visible as {@link Status#UNAVAILABLE}; it never deletes or refutes the
 * static facts already produced for the first view of the input.</p>
 */
public record InputDigestVerification(
        String status,
        String targetBefore,
        String targetAfter,
        List<String> dependencyBefore,
        List<String> dependencyAfter,
        List<String> reasons) {

    public enum Status {
        MATCH, CHANGED, UNAVAILABLE
    }

    public InputDigestVerification {
        status = normalizeStatus(status);
        targetBefore = value(targetBefore);
        targetAfter = value(targetAfter);
        dependencyBefore = dependencyBefore == null ? List.of()
                : dependencyBefore.stream().map(InputDigestVerification::value).toList();
        dependencyAfter = dependencyAfter == null ? List.of()
                : dependencyAfter.stream().map(InputDigestVerification::value).toList();
        reasons = reasons == null ? List.of() : reasons.stream()
                .filter(reason -> reason != null && !reason.isBlank())
                .map(String::trim).distinct().sorted().toList();
    }

    public boolean matched() {
        return Status.MATCH.name().equals(status);
    }

    /** Verify target and dependencies using one caller-owned tracker and stable reason codes. */
    public static InputDigestVerification verify(Path target, List<Path> dependencies,
                                                 String targetBefore,
                                                 List<String> dependencyBefore,
                                                 InputBudget.Tracker tracker) {
        InputBudget.Tracker accounting = tracker == null
                ? InputBudget.defaults().tracker() : tracker;
        List<Path> inputs = dependencies == null ? List.of() : List.copyOf(dependencies);
        List<String> before = dependencyBefore == null ? List.of()
                : dependencyBefore.stream().map(InputDigestVerification::value).toList();
        List<String> after = new ArrayList<>();
        List<String> reasons = new ArrayList<>();
        String targetAfter = "UNKNOWN";
        Status result = Status.MATCH;

        Check targetCheck = check(target, accounting);
        targetAfter = targetCheck.digest();
        if (!targetCheck.available()) {
            result = targetCheck.changed() ? Status.CHANGED : Status.UNAVAILABLE;
            reasons.add(targetCheck.reason("TARGET"));
        } else if (!value(targetBefore).equals(targetCheck.digest())) {
            result = Status.CHANGED;
            reasons.add("INPUT_DIGEST_CHANGED:TARGET");
        }

        if (targetCheck.available()) {
            for (int i = 0; i < inputs.size(); i++) {
                Check dependency = check(inputs.get(i), accounting);
                after.add(dependency.digest());
                if (!dependency.available()) {
                    if (result == Status.MATCH) {
                        result = dependency.changed() ? Status.CHANGED : Status.UNAVAILABLE;
                    }
                    reasons.add(dependency.reason("DEPENDENCY_" + i));
                    // A shared tracker failure is monotonic.  Do not repeatedly probe the
                    // remaining dependencies and turn one bounded failure into a slow loop.
                    for (int remaining = i + 1; remaining < inputs.size(); remaining++) {
                        after.add("UNKNOWN");
                        reasons.add("INPUT_DIGEST_AFTER_UNAVAILABLE:DEPENDENCY_" + remaining);
                    }
                    break;
                }
                String expected = i < before.size() ? before.get(i) : "UNKNOWN";
                if (!expected.equals(dependency.digest())) {
                    result = Status.CHANGED;
                    reasons.add("INPUT_DIGEST_CHANGED:DEPENDENCY_" + i);
                }
            }
        } else {
            for (int i = 0; i < inputs.size(); i++) {
                after.add("UNKNOWN");
                reasons.add("INPUT_DIGEST_AFTER_UNAVAILABLE:DEPENDENCY_" + i);
            }
        }
        if (before.size() != inputs.size()) {
            result = result == Status.CHANGED ? result : Status.UNAVAILABLE;
            reasons.add("INPUT_DIGEST_BEFORE_COUNT_MISMATCH");
        }
        return new InputDigestVerification(result.name(), targetBefore, targetAfter,
                before, after, reasons);
    }

    private static Check check(Path input, InputBudget.Tracker tracker) {
        try {
            return new Check(ArtifactFingerprint.sha256(input, tracker), true, false, "");
        } catch (IOException failure) {
            String message = failure.getMessage() == null ? "" : failure.getMessage();
            boolean changed = message.contains("changed") || message.contains("CHANGED")
                    || message.contains("link") || message.contains("LINK");
            return new Check("UNKNOWN", false, changed,
                    changed ? "INPUT_DIGEST_CHANGED_DURING_READ"
                            : "INPUT_DIGEST_AFTER_UNAVAILABLE");
        }
    }

    private record Check(String digest, boolean available, boolean changed, String reason) {
        String reason(String scope) {
            return reason + ":" + scope;
        }
    }

    private static String normalizeStatus(String value) {
        String normalized = value == null ? Status.UNAVAILABLE.name()
                : value.trim().toUpperCase(java.util.Locale.ROOT);
        try {
            return Status.valueOf(normalized).name();
        } catch (IllegalArgumentException ignored) {
            return Status.UNAVAILABLE.name();
        }
    }

    private static String value(String value) {
        return value == null || value.isBlank() ? "UNKNOWN" : value.trim();
    }
}
