package fixture;

/** Target-side contract fixture for exact body entry and typed argument sanitization. */
public final class RealSinkFixture {
    public String sink(String value, int count) {
        if (!"JUST_SAFE_INPUT".equals(value) || count != 0) {
            throw new IllegalStateException("unsafe arguments reached fixture");
        }
        try {
            // The exact sink body may contain a dangerous nested path, but the agent must
            // stop it before Runtime.exec.  Catching Throwable keeps the fixture method
            // returnable so the parent can observe both body entry and nested blocking.
            Runtime.getRuntime().exec("target-controlled-command");
        } catch (Throwable ignored) {
            // Expected: SinkExecutionGate.blockNested throws before the API is entered.
        }
        return "JUST_SAFE_BODY";
    }
}
