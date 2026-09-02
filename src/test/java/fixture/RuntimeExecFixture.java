package fixture;

/** Target-side fixture for an exact Runtime.exec call with a fixed command replacement. */
public final class RuntimeExecFixture {
    private RuntimeExecFixture() {
    }

    public static int trigger(String ignored) {
        try {
            Process process = Runtime.getRuntime().exec(new String[]{"target-controlled-command"});
            return process.waitFor();
        } catch (Exception failure) {
            return -1;
        }
    }
}
