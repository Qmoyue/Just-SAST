package io.just.sast.verify.boot;

/** Bootstrap-visible marker raised before a verified sink body executes. */
public final class SinkReachedError extends Error {

    private static final long serialVersionUID = 1L;

    public SinkReachedError(String message) {
        super(message);
    }
}
