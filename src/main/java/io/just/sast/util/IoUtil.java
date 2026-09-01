package io.just.sast.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/** IO 工具。 */
public final class IoUtil {

    /** 单条目读取上限（64MB）：防 zip 炸弹单条目 OOM。 */
    private static final long MAX_ENTRY_BYTES = ArchiveLimits.MAX_ENTRY_UNCOMPRESSED_BYTES;

    private IoUtil() {}

    public static byte[] readAll(InputStream in) throws IOException {
        return readAll(in, MAX_ENTRY_BYTES);
    }

    /** Read one stream with an explicit byte budget. */
    public static byte[] readAll(InputStream in, long limit) throws IOException {
        if (in == null || limit < 0) {
            throw new IllegalArgumentException("input and non-negative limit are required");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream(4096);
        byte[] buffer = new byte[8192];
        long total = 0;
        while (true) {
            int n = in.read(buffer);
            if (n < 0) {
                break;
            }
            if (n == 0) {
                // InputStream is allowed to make a zero-byte progress report. Fall back to
                // one byte so a hostile/custom stream cannot spin this bounded reader forever.
                int one = in.read();
                if (one < 0) {
                    break;
                }
                if (total >= limit) {
                    throw new IOException("条目超过单条目上限 " + limit + " 字节");
                }
                out.write(one);
                total++;
                continue;
            }
            if (n > limit - total) {
                throw new IOException("条目超过单条目上限 " + limit + " 字节");
            }
            out.write(buffer, 0, n);
            total += n;
        }
        return out.toByteArray();
    }
}
