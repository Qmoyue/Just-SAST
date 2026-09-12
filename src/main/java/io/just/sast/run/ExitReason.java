package io.just.sast.run;

/** Stable process-exit reasons shared by the CLI and external runners. */
public enum ExitReason {
    OK(0),
    USAGE(2),
    INTERNAL(3),
    UNSUPPORTED_RUNTIME(78);

    private final int code;

    ExitReason(int code) {
        this.code = code;
    }

    public int code() {
        return code;
    }

    public boolean processSucceeded() {
        return code == 0;
    }

    /** Unknown process codes fail closed as an internal error. */
    public static ExitReason fromCode(int code) {
        for (ExitReason reason : values()) {
            if (reason.code == code) {
                return reason;
            }
        }
        return INTERNAL;
    }
}
