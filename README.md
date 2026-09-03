# Just

Just 是一个面向 Java JAR、WAR 和 class 目录的轻量级反序列化链扫描器。它从字节码中提取入口、字段、调用、控制流和 sink 事实，组合出可解释的候选链，并输出可供人工或工具继续处理的证据。

## 工作流

```text
JAR / WAR / class 目录 + 可选依赖 + 目标 JDK
                    │
                    ▼
             ASM 字节码前端
                    │  Just model
                    ▼
          CPG / CFG / 调用图 / 类型层次
                    │
                    ▼
                 Blackboard
       规则、污点、框架语义、链组合与校准
                    │
                    ▼
          规范化链结果与可选动态验证
                    │
                    ▼
       CSV / JSON / SARIF / HTML / Markdown
```

## 主要功能

- 支持普通 JAR、嵌套 JAR、Spring Boot fat JAR、WAR、class 目录和显式依赖。
- 分析 Java 原生序列化入口及规则描述的替代反序列化框架入口。
- 建立调用、控制流、异常、继承、字段、数组、容器元素、反射、代理和 lambda 关系。
- 使用 forward/backward taint、对象图、source/sink 规则和链校准组合候选链。
- 每条链保留 `rule_id`、entry、sink、逐跳 edge、字段依赖、校准状态和完整性原因。
- 默认动态验证在 Windows Job Object 子 JVM 中运行。可证明的精确 sink/body 使用固定安全参数真实调用；高风险终点只确认到最终危险操作之前，并在报告中区分范围。
- Windows Job Object 限制进程树、内存、进程数、CPU time、墙钟时间并在关闭时回收子进程；它是 process/resource containment，不声明完整文件系统或系统网络控制。
- SAFE_REAL 仅支持类型和 descriptor 可证明的安全调用：命令使用 Just 自有 JDK 的固定 `-version`，文件使用 scratch，网络和 native/类加载等高风险终点不进入最终调用。该状态表示安全可调用性，不表示 RCE。
- 通过 `KnowledgeSource`、Blackboard、YAML 规则和 ServiceLoader 扩展分析语义。

## 构建与运行

需要 JDK 17+ 和 Maven 3.6+。

```bash
mvn package -DskipTests
java -jar target/just-sast-0.2.0.jar scan \
  --jar app.jar \
  --jdk-home /path/to/jdk \
  --output just-out
```

补充依赖：

```bash
java -jar target/just-sast-0.2.0.jar scan \
  --jar app.jar \
  --deps lib/a.jar,lib/b.jar \
  --output just-out
```

常用参数：

| 参数 | 作用 |
| --- | --- |
| `--jar=<path>` | 目标 JAR、WAR 或 class 目录 |
| `--deps=<path,...>` | 补充依赖路径 |
| `--jdk-home=<path>` | 目标 JDK；Java 8 使用 `rt.jar`，Java 9+ 使用 `jrt-fs` |
| `--output=<path>` | 报告目录，默认 `just-out` |
| `--rules=<path>` | 自定义 YAML 规则 |
| `--verify-budget=<N>` | 动态验证候选预算，默认 `20` |
| `--stats` | 输出阶段统计 |
| `--fast` | 减少 JDK 运行库加载，适合快速预览 |
| `--no-verify` | 只执行静态分析 |

完整扫描通常使用默认参数；`--fast` 和 `--no-verify` 会改变分析或动态验证范围。

## 输出

```text
just-out/
├─ index.md
├─ findings/       # 主发现及 CSV/JSON/SARIF/HTML/Markdown
├─ verification/   # 动态状态与安全构造计划
├─ evidence/       # 链、边、sink、校准和依赖证据
└─ meta/           # 扫描身份、阶段统计和元数据
```

动态状态含义：

| 状态 | 含义 |
| --- | --- |
| `SINK_BLOCKED` | 真实前置链抵达精确 sink 边界，canary 阻断方法体 |
| `PRE_SINK_CONFIRMED` | 高风险终点前的完整前置链已确认，最终危险调用未进入 |
| `SINK_EXECUTED_SAFE` | 固定安全参数下的精确 API/body 正常返回，带 `sink_distorted=true` |
| `JNI_EXECUTED_SAFE` | Just 自有 native fixture 完成受约束的 load、callback 和正常返回；不代表目标 JAR 的 native load |
| `CONCRETE_REACHED` | 运行到安全观察点，但未形成精确 sink 证据 |
| `PARTIAL` | 只完成部分构造或触发 |
| `TIMEOUT` | 达到动态时间预算 |
| `UNTESTABLE` | 依赖、JDK、权限或 OS runner 能力不足 |

`payload.md/json` 只描述对象图、字段、触发和证据计划，不包含可直接投递的攻击字节流。Just 不输出 `RCE_CONFIRMED`。

动态结果还会记录 `verification_scope`、`sink_risk`、`terminal_executed`、`stop_reason` 和
`last_confirmed_stage`，用于区分边界 canary、高风险前置确认和安全终点闭环。

## 扩展

新增静态语义时，实现 `KnowledgeSource`，声明 `phase()`、`priority()` 和 `interests()`，通过 Blackboard 交换事实和事件，并使用 ServiceLoader 注册。攻击面和调用模型优先写入 `src/main/resources/rules/default-rules.yaml`；知识源不直接调用其他知识源，也不按样本或包名添加分支。

## 验证

```bash
mvn test
mvn package -DskipTests
```

Gleipner evaluator 作为外部语义回归使用；其输入、truth、评测脚本和结果不属于生产代码。架构约定见 [docs/architecture.md](docs/architecture.md)，需求契约见 [docs/requirements.md](docs/requirements.md)。

推送形如 `vX.Y.Z` 的 tag，或手动运行 release workflow，会在 JDK17 上重新测试并构建主 JAR
与目标 JDK 兼容验证器，生成 `SHA256SUMS` 和 GitHub 构建证明；发布前仍应由维护者检查变更和
生成的 release notes。

许可证为 GPLv3，见 [LICENSE](LICENSE)。
