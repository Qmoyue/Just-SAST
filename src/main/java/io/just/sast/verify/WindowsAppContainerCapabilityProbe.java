package io.just.sast.verify;

import io.just.sast.verify.boot.WindowsProcessAttestation;

/**
 * Verifier-owned child used only during Windows AppContainer capability selection.
 *
 * <p>The broker launches this class with the same security-capability process attributes that
 * protect a real verification child.  It has no target class path, no target input, and no
 * native fixture.  A zero exit code means the child observed both AppContainer membership and
 * Low Integrity through the token API; every other result keeps SAFE_REAL unavailable.</p>
 */
public final class WindowsAppContainerCapabilityProbe {

    private WindowsAppContainerCapabilityProbe() {
    }

    public static void main(String[] args) {
        System.exit(WindowsProcessAttestation.appContainerLow() ? 0 : 3);
    }
}
