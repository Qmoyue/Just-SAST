package io.just.sast.chain;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/** 链稳定指纹。 */
public final class ChainIds {

    private ChainIds() {}

    public static String id(String key) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-1").digest(key.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest).substring(0, 8);
        } catch (NoSuchAlgorithmException e) {
            return Integer.toHexString(key.hashCode());
        }
    }

    /** Full content digest for compact evidence tables that must remain collision-resistant. */
    public static String sha256(String key) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest((key == null ? "" : key).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is mandatory in every supported JDK; keep a deterministic fallback for
            // unusual embedded runtimes rather than making report generation fail.
            return Integer.toHexString((key == null ? "" : key).hashCode());
        }
    }
}
