package io.just.sast.chain;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/** 链稳定指纹。 */
public final class ChainIds {

    private static final HexFormat HEX = HexFormat.of();
    /* MessageDigest construction is provider lookup, not a per-id operation. Reuse one digest
       per worker while retaining thread safety for parallel knowledge sources. */
    private static final ThreadLocal<MessageDigest> SHA1 = ThreadLocal.withInitial(
            () -> newDigest("SHA-1"));
    private static final ThreadLocal<MessageDigest> SHA256 = ThreadLocal.withInitial(
            () -> newDigest("SHA-256"));

    private ChainIds() {}

    public static String id(String key) {
        MessageDigest digest = SHA1.get();
        digest.reset();
        return HEX.formatHex(digest.digest(text(key).getBytes(StandardCharsets.UTF_8)))
                .substring(0, 8);
    }

    /** Full content digest for compact evidence tables that must remain collision-resistant. */
    public static String sha256(String key) {
        MessageDigest digest = SHA256.get();
        digest.reset();
        return HEX.formatHex(digest.digest(text(key).getBytes(StandardCharsets.UTF_8)));
    }

    private static String text(String value) {
        return value == null ? "" : value;
    }

    private static MessageDigest newDigest(String algorithm) {
        try {
            return MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("required digest unavailable: " + algorithm, impossible);
        }
    }
}
