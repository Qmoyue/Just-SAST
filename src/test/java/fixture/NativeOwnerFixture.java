package fixture;

/** Native declaration used only to exercise the candidate-local cross-class index. */
public final class NativeOwnerFixture {
    private NativeOwnerFixture() {
    }

    public static native int value();
}
