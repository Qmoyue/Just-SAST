package io.just.sast.run;

/** Availability of the requested product path, independent from its semantic result. */
public enum SupportStatus {
    SUPPORTED,
    PARTIAL,
    UNSUPPORTED,
    UNKNOWN,
    NOT_APPLICABLE
}
