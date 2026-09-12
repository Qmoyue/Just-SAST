package io.just.sast.cli;

import java.util.Locale;

/** Product scan scope.  The mode is explicit so a component cannot be reported as an application. */
public enum ScanMode {
    COMPONENT,
    APPLICATION;

    public static ScanMode parse(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("--mode must be component or application");
        }
        try {
            return valueOf(value.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException invalid) {
            throw new IllegalArgumentException("--mode must be component or application: " + value,
                    invalid);
        }
    }
}
