package fixture;

import java.io.FileOutputStream;

/** Exercises the generic pre-NEW guard for a nested file constructor. */
public final class RealSinkConstructorFixture {
    public String sink(String ignored) {
        try {
            new FileOutputStream("target-controlled-file").close();
        } catch (Throwable expected) {
            // The real verifier must stop the constructor before it reaches the host filesystem.
        }
        return "JUST_SAFE_CONSTRUCTOR_BODY";
    }
}
