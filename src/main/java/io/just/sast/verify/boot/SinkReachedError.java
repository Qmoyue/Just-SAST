package io.just.sast.verify.boot;

/**
 * sink canary 标记异常：插桩后的 sink 方法入口抛出（构造参数 = "内部类名#方法名"）。
 * 必须位于 bootstrap classloader（插桩 java.base 类时其引用对 bootstrap 可见），
 * 由 ParallelVerifier 生成的最小 bootstrap jar 承载、agent premain 挂载。
 *
 * 继承 Error 而非 Exception：gadget 链中大量 catch(Exception)（如 wagTail）不会吞掉标记，
 * 标记可穿透到探针顶层判定。
 */
public class SinkReachedError extends Error {

    private static final long serialVersionUID = 1L;

    public SinkReachedError(String spec) {
        super(spec);
    }
}
