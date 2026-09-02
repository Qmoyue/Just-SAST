package fixture;

/** Caller whose native owner is a different class. */
public final class NativeCallerFixture {
    private NativeCallerFixture() {
    }

    public static int call() {
        return NativeOwnerFixture.value();
    }
}
