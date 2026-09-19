# Just 架构

Just 是一个 static-only 的 Java 字节码分析器。它从 JAR、WAR、Spring Boot fat JAR、class 目录、依赖和目标 JDK 中建立可追溯事实，分析反序列化 gadget chain 的机制能力与应用暴露面。

## 数据流

```text
输入制品 / 显式依赖 / POM / 目标 JDK
                ↓
      artifact closure + provenance
                ↓
          ASM 字节码事实
                ↓
   typed values / objects / calls / controls
                ↓
       共享约束求解器与有界分发
          ↙                     ↘
 component 机制能力       application 真实入口
          ↘                     ↙
       冻结 evidence graph / projection
                ↓
          report.json + report.md
```

每层只消费上一层的稳定模型；求解器不读取 WP、题名、路径、digest 或报告文本来改变结论。

## Owner 边界

| 层 | 负责 | 不负责 |
| --- | --- | --- |
| Input/closure | 读取归档、nested JAR、POM、显式依赖和 JDK；记录 hash、来源、角色和缺口 | 猜版本、生成临时 POM、静默补依赖 |
| ASM frontend | 生成 class、method、call、field、bootstrap 和 descriptor facts | 加载或执行目标类 |
| Typed model | 保存 slot、对象 identity、类型、字段、控制条件和 artifact provenance | 用同名文本合并不同对象 |
| Rules | 声明 entry、site、source、callback、bridge、terminal 的 API 语义 | 为某个题目或包名写特判 |
| Solver | 做 forward flow、bounded dispatch、约束组合和 component/application 分流 | 由排序或报告格式制造事实 |
| Projection | 从同一冻结结果生成 JSON 和 Markdown | 重新求解、补链或隐藏重要缺口 |

## 两种模式

`component` 从公开 API、反序列化入口或其他机制触发点分析可复用能力；它不代表某个应用已经暴露漏洞。

`application` 先确认目标制品定义的真实 `main(String[])`，再确认实际调用边、HTTP site 或其他外部输入，最后把入口正向流与 terminal 反向约束相交。没有 verified entry/site 时返回 `NO_APPLICATION_ENTRY`，不启动全局 sink 枚举。

## Typed bridge

JNDI/Reference、JDBC/JAAS、Proxy/DirContext/Hessian 等跨 API 连接都使用同一类 typed bridge fact。每条 bridge 至少保留：

- producer、consumer 和物理 call site；
- receiver/argument/return slot 与准确 descriptor；
- value/object identity、类型和 artifact provenance；
- `PROVED`、`PARTIAL` 或 `UNKNOWN` 及可解释原因。

同名不同 identity、descriptor 不匹配、缺少 concrete implementer 或缺少依赖时，不猜测连接；只保留边界和限制。

## 输入与依赖

根 class、`BOOT-INF/lib`、`WEB-INF/lib` 和 `lib` 中的 nested JAR 直接读取，不解压到仓库临时目录。无 POM 的自包含 fat JAR 可以在 `--offline` 下扫描；缺失类型、duplicate class、版本歧义和未知 JDK API 进入 coverage/limits，而不是静默选择。

Just 自身使用 JDK 17 运行；`--jdk-home` 只提供被分析的目标 JDK 字节码，不进入目标应用执行路径。依赖解析、分析、报告和总耗时分别记录。

## 报告

JSON 和 Markdown 来自同一个 projection，公共合同为 `JUST-REPORT-V2`。报告保留：

```text
entry → site/input → callback/bridge → impact/terminal
```

`COMPLETE` 表示静态必要跳点已证明，不表示代码运行；`PARTIAL` 表示有明确的静态缺口；`UNKNOWN` 表示信息不足。报告不包含 payload、动态验证结果或 `RCE_CONFIRMED`。

## 安全边界

Just 不加载、初始化、构造或反射调用目标类，不反序列化攻击流，不启动目标服务或进程，不执行 payload/callback，也不生成可投递攻击字节流。内部错误直接失败；不使用 catch-all、空结果、重试或静默降级掩盖错误。
