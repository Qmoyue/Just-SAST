# Just 需求契约

版本：2026-09-04。本文件定义当前产品的功能、结果、安全和性能契约。

## 1. 目标与范围

Just 面向 Java JAR、WAR 和 class 目录，分析反序列化入口到 gadget/sink 的静态可达关系，
输出可解释链、证据和动态状态。产品以单 CLI JAR 交付，主程序使用 JDK17，目标 JDK 仍可通过
`--jdk-home` 指定。

Just 不生成可直接投递的攻击字节流，不把静态命中或固定安全参数调用写成 RCE 结论。

## 2. 功能需求

### 2.1 输入与前端

| ID | 要求 |
| --- | --- |
| FR-01 | 接受普通 JAR、嵌套 JAR、Spring Boot fat JAR、WAR 和 class 目录。 |
| FR-02 | 接受显式依赖路径，并区分应用、依赖和 JDK class。 |
| FR-03 | 使用 ASM 解析 classfile，生成类、方法、字段、指令、异常和类型事实。 |
| FR-04 | 根据目标 classfile 版本选择 Java 8 `rt.jar` 或 Java 9+ `jrt-fs` 模块源。 |
| FR-05 | 对嵌套深度、条目数量、解压大小、压缩比、classfile 大小和链接/reparse point 设置边界。 |
| FR-06 | 读取失败、依赖缺失、模块不可读和版本不匹配保留为结构化完整性状态。 |

### 2.2 静态语义

| ID | 要求 |
| --- | --- |
| FR-07 | 覆盖原生序列化回调及其继承、代理和框架桥接入口。 |
| FR-08 | 通过 YAML 描述替代反序列化入口、source、sink、框架桥接和调用模型。 |
| FR-09 | 支持调用图、CFG、异常边、类型层次、字段写入、数组、容器、receiver、反射、代理和 lambda。 |
| FR-10 | 支持 forward/backward taint、字段/返回值/receiver/容器来源、对象图和链组合。 |
| FR-11 | 对 JNI、JRMP、模块、类加载和动态反射保留边界事实；未知目标不得扩展为任意调用。 |
| FR-12 | 链校准区分类型、序列化、控制流、字段约束、触发条件和安全配置。 |
| FR-13 | 每条链携带 `rule_id`、entry、sink、逐跳 edge、机制、字段依赖、风险和完整性原因。 |

### 2.3 Blackboard 与扩展

| ID | 要求 |
| --- | --- |
| FR-14 | Blackboard 按 phase 和 `KnowledgeSource.priority()` 调度知识源并建立阶段屏障。 |
| FR-15 | 知识源之间不得直接调用，通过 Blackboard 事实和事件协作。 |
| FR-16 | `KnowledgeSource` 声明 `phase()`、`priority()`、`interests()`，并通过 ServiceLoader 注册。 |
| FR-17 | 规则文件负责攻击面数据，分析引擎负责通用语义；不得使用样本、包名或结果文本特判。 |
| FR-18 | 统一链存储管理 chain identity、语义合并、校准状态和注记。 |

### 2.4 动态确认

| ID | 要求 |
| --- | --- |
| FR-19 | 默认动态流程使用独立子 JVM 和 Windows Job Object；可证明的安全终点执行固定安全调用，其他终点停在边界。 |
| FR-20 | 子 JVM 在认证 ready 后才加载目标类；真实调用和 canary 都必须绑定同一 attempt、chain、sink、artifact 和策略 identity。 |
| FR-21 | `SAFE_CALLABLE`/`CONTROLLED_EFFECT` 只允许 descriptor、receiver、参数、调用前后观察点和副作用均可约束的终点。 |
| FR-22 | 固定安全参数不得继承目标命令、路径、URL、类名、脚本、序列化数据或不透明对象。 |
| FR-23 | `SINK_EXECUTED_SAFE` 必须具备精确调用、固定参数、正常返回/受控效果和认证 Job Object evidence，并标记 `sink_distorted=true`。 |
| FR-24 | native/JNI/FFM load、任意类加载/定义/初始化、攻击性反序列化、脚本/eval、远端 lookup、非固定网络和不可控外部进程只允许 `PRE_SINK_CONFIRMED`。 |
| FR-25 | 普通 stdout/stderr、属性、环境变量、异常文本和退出码不能单独形成正向动态证据。 |
| FR-26 | 结果必须结构化记录 `requested_mode`、`effective_mode`、`fallback`、`verification_scope`、`sink_risk`、`terminal_executed`、`stop_reason` 和 `last_confirmed_stage`。 |

### 2.5 进程边界

| ID | 要求 |
| --- | --- |
| FR-27 | Windows 默认 runner 使用普通用户可建立的 Job Object，配置进程树、per-process user CPU time、内存、active-process、kill-on-close、墙钟和独立 scratch。 |
| FR-28 | 父进程必须真实创建/配置/附加 Job Object，并在 ready/terminal 协议中认证该边界；子进程自报不能替代父进程证据。 |
| FR-29 | Job Object 不声明完整文件系统或系统网络控制；无法建立时返回明确的 `UNTESTABLE`，不得启动未约束的真实终点。 |
| FR-30 | Linux 保留 backend 接口和不可用结果，不把普通子 JVM 能力写成隔离能力。 |

### 2.6 结果与报告

| ID | 要求 |
| --- | --- |
| FR-31 | 所有报告由同一规范化结果模型生成，包含 findings、evidence、calibration、verification、metadata、dependencies 和 payload plan。 |
| FR-32 | CSV、JSON、SARIF、HTML、Markdown 使用同一字段语义、风险分组和排序。 |
| FR-33 | 报告分为互斥的 `real_safe_terminal`、`prefix_confirmed_high_risk` 和 `boundary_only` 集合。 |
| FR-34 | payload plan 只描述对象图、字段、触发和证据计划，不包含攻击字节流。 |
| FR-35 | 结果记录 artifact、JDK、规则、参数、预算、阶段耗时、完整性、动态能力和 canonical digest。 |
| FR-36 | diff、baseline 和 suppression 使用稳定 chain identity，不改变扫描语义。 |

## 3. 状态契约

| 状态 | 定义 |
| --- | --- |
| `SINK_BLOCKED` | 精确 sink 边界已到达，canary 阻断方法体 |
| `PRE_SINK_CONFIRMED` | 高风险终点前的完整前置链已确认，终点未进入 |
| `SINK_EXECUTED_SAFE` | 固定安全参数下精确 API/body 正常返回 |
| `SAFE_EFFECT_OBSERVED` | 只观察到 Just 自有 adapter 效果 |
| `CONCRETE_REACHED` | 到达安全观察点但尚无精确 sink 证据 |
| `PARTIAL` | 分析、构造或依赖只完成一部分 |
| `TIMEOUT` | 达到明确时间预算 |
| `UNTESTABLE` | 缺少依赖、JDK 或所需进程边界能力 |

以上状态均不等价于 RCE；Just 不输出 `RCE_CONFIRMED`。

## 4. 非功能需求

| ID | 要求 |
| --- | --- |
| NFR-01 | 核心交付保持单 JAR；主 CLI 使用 JDK17；`--jdk-home` 可选择目标 JDK。 |
| NFR-02 | 大工件采用流式读取、冻结索引、按需 CFG/CPG、共享 immutable summary 和有界缓存。 |
| NFR-03 | 静态、动态、runner startup、class-load、真实调用/prefix-stop、queue 和 cleanup 分段计时。 |
| NFR-04 | 优化不得减少规则、扫描深度、链覆盖、完整性或确定性。 |
| NFR-05 | 固定配置下记录静态和动态 cold/warm p50/p95；动态门禁以候选结果 duration 为主，并保留整次 verify 阶段；超时样本保留在分位数计算中。 |
| NFR-06 | 并行度、缓存、验证预算、输出和资源限制有界；默认不自动重复超时。 |
| NFR-07 | 相同输入和配置的串行、并行、重复运行产生相同链集合、原因、排序、状态和 digest。 |
| NFR-08 | 测试覆盖 CLI、报告、恶意工件、协议、进程边界、确定性、超时/OOM 和性能。 |
| NFR-09 | 控制流直接、模块职责单一；不使用宽泛 fallback 掩盖能力缺失。 |

## 5. CLI 契约

```text
just-sast scan --jar=<path> [--deps=<path,...>]
                 [--jdk-home=<path>] [--output=<path>]
                 [--rules=<path>] [--verify-budget=<N>]
                 [--stats] [--fast] [--no-verify]
```

`--fast` 和 `--no-verify` 会改变扫描或验证范围。退出码为：`0` 成功，`2` 参数或输入错误，
`3` 扫描内部错误。

## 6. 验收

验收顺序为 focused contract、single-JAR 构建、CLI smoke、完整测试、外部语义回归、确定性和
固定性能门。Gleipner 的输入、truth、脚本和评分口径与生产代码分离。
