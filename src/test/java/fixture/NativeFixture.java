package fixture;

/** Target-side contract fixture for the verifier-owned native callback test. */
public final class NativeFixture {
    public NativeFixture() {
    }

    private static native int value();

    public static int trigger() {
        System.loadLibrary("target-controlled-name");
        return value();
    }
}
