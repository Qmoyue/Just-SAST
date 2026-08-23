package io.just.sast.cli;

import picocli.CommandLine;
import picocli.CommandLine.Command;

/** Just 主入口。 */
@Command(name = "just-sast",
        description = "轻量字节码 SAST：挖掘 Java 反序列化 gadget 链",
        subcommands = {ScanCommand.class, DiffCommand.class},
        mixinStandardHelpOptions = true, version = "just-sast 0.2.0")
public final class JustMain implements Runnable {

    @CommandLine.Spec
    CommandLine.Model.CommandSpec spec;

    @Override
    public void run() {
        // 无子命令：用法错误（退出码 2）
        throw new CommandLine.ParameterException(spec.commandLine(), "缺少子命令，用法见 --help");
    }

    public static void main(String[] args) {
        int code = new CommandLine(new JustMain()).execute(args);
        System.exit(code);
    }
}
