package io.just.sast.model;

/**
 * Path-free evidence describing which JDK image backs a class source.  The frontend owns the
 * selection; downstream code consumes this immutable fact instead of inferring target accuracy
 * from a description string or from the current JVM version.
 */
public record JdkSourceInfo(ImageKind imageKind, int feature) {

    public enum ImageKind {
        RUNTIME_JRT,
        TARGET_JRT,
        TARGET_RT_JAR,
        UNKNOWN
    }

    public JdkSourceInfo {
        imageKind = imageKind == null ? ImageKind.UNKNOWN : imageKind;
        feature = Math.max(0, feature);
    }

    /** True only when the selected source is tied to the requested target JDK home. */
    public boolean targetImage() {
        return imageKind == ImageKind.TARGET_JRT || imageKind == ImageKind.TARGET_RT_JAR;
    }

    /** True only for the deliberate no-{@code --jdk-home} runtime-image delegation. */
    public boolean runtimeDelegated() {
        return imageKind == ImageKind.RUNTIME_JRT;
    }

    /** Stable provider label suitable for JSON/SARIF metadata and agent consumption. */
    public String provider() {
        return switch (imageKind) {
            case RUNTIME_JRT, TARGET_JRT -> "JRT";
            case TARGET_RT_JAR -> "LEGACY_RT_JAR";
            case UNKNOWN -> "UNKNOWN";
        };
    }
}
