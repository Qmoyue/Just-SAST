package fixture;

/** Target-side timeout fixture for the generic real-call tier fallback contract. */
public final class SlowRealSinkFixture {
    public String sink(String value, int count) {
        try {
            Thread.sleep(30_000L);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
        return value + count;
    }
}
