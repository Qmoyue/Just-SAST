package io.just.sast.verify;

import io.just.sast.util.JustLogger;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

/**
 * V8 子进程验证：把构造好的序列化对象在新 JVM 里反序列化，
 * 捕获 stack trace 以确认 sink 是否真实触发。
 * 
 * 轻量设计：每个链一个子进程，5 秒超时，失败即降级不阻塞。
 */
public final class VerifyRunner {

    public record VerifyResult(String status, String detail) {
        public static final VerifyResult TIMEOUT = new VerifyResult("TIMEOUT", "5s");
        public static final VerifyResult SKIP = new VerifyResult("SKIP", "not-runnable");
    }

    private static final int TIMEOUT_SECONDS = 5;
    private final Path targetJar;

    public VerifyRunner(Path targetJar) {
        this.targetJar = targetJar;
    }

    /** 在子进程中反序列化 payload 字节，检查是否触发异常（= 链生效的证据）。 */
    public VerifyResult verify(byte[] serializedPayload) {
        if (serializedPayload == null || serializedPayload.length == 0) {
            return VerifyResult.SKIP;
        }
        try {
            // 写 payload 到临时文件
            Path payloadFile = Files.createTempFile("just-payload", ".ser");
            Files.write(payloadFile, serializedPayload);
            // 构造子进程命令
            String javaHome = System.getProperty("java.home");
            String java = javaHome + "/bin/java";
            ProcessBuilder pb = new ProcessBuilder(
                    java, "-cp", targetJar.toAbsolutePath().toString(),
                    "io.just.sast.verify.DeserializeProbe",
                    payloadFile.toAbsolutePath().toString());
            pb.redirectErrorStream(true);
            Process proc = pb.start();
            // 读输出
            String output = new String(proc.getInputStream().readAllBytes());
            boolean finished = proc.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            Files.deleteIfExists(payloadFile);
            if (!finished) {
                proc.destroyForcibly();
                return VerifyResult.TIMEOUT;
            }
            int exit = proc.exitValue();
            if (exit == 0) {
                return new VerifyResult("VERIFIED", output.trim());
            }
            // 非零退出 = 反序列化触发异常 → 链可能生效
            return new VerifyResult("TRIGGERED", "exit=" + exit + " " + output.trim());
        } catch (Exception e) {
            return new VerifyResult("ERROR", e.getMessage());
        }
    }
}
