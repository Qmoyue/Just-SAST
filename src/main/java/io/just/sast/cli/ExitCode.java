package io.just.sast.cli;

import io.just.sast.run.ExitReason;

/** 退出码。 */
public enum ExitCode {
    /** 扫描成功 */
    OK(ExitReason.OK),
    /** 参数/配置错误 */
    USAGE(ExitReason.USAGE),
    /** 内部错误 */
    INTERNAL(ExitReason.INTERNAL),
    /** 当前运行时不受支持 */
    UNSUPPORTED_RUNTIME(ExitReason.UNSUPPORTED_RUNTIME);

    private final ExitReason reason;

    ExitCode(ExitReason reason) {
        this.reason = reason;
    }

    public int code() {
        return reason.code();
    }

    public ExitReason reason() {
        return reason;
    }
}
