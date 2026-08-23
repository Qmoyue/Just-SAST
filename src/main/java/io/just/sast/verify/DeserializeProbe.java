package io.just.sast.verify;

import java.io.*;

/** 子进程探针：反序列化 payload，触发则退出非零（链生效证据）。 */
public final class DeserializeProbe {
    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("usage: DeserializeProbe <payload-file>");
            System.exit(2);
        }
        try (ObjectInputStream in = new ObjectInputStream(new FileInputStream(args[0]))) {
            Object result = in.readObject();
            System.out.println("deserialized: " + (result != null ? result.getClass().getName() : "null"));
        } catch (Exception e) {
            // 异常 = 反序列化触发了链（readObject 内的 gadget 执行）
            System.err.println("triggered: " + e.getClass().getName() + ": " + e.getMessage());
            e.printStackTrace();
            System.exit(1); // 非零退出 = 链触发
        }
        System.exit(0); // 正常退出 = 链未触发
    }
}
