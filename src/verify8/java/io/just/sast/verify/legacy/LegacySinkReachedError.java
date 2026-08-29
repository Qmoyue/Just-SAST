package io.just.sast.verify.legacy;

/** Bootstrap-visible marker raised before a verified sink body executes. */
public final class LegacySinkReachedError extends Error {

    public LegacySinkReachedError(String message) {
        super(message);
    }
}
