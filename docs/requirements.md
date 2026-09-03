# Just 需求契约

版本：2026-09-03。本文件定义 Just 的功能、接口、安全和性能要求。

## 1. 目标与范围

Just 面向 Java JAR、WAR 和 class 目录，分析反序列化入口到 gadget/sink 的静态可达关系，并以可解释的链、证据和动态状态输出结果。产品以单 CLI JAR 交付，默认不依赖网络服务。

Just 不生成可直接投递的攻击字节流，不执行危险命令或任意目标 native，不以静态命中直接给出 RCE 结论。

## 2. 功能需求

### 2.1 输入与前端

| ID | 要求 |
| --- | --- |
| FR-01 | 接受普通 JAR、嵌套 JAR、Spring Boot fat JAR、WAR 和 class 目录。 |
| FR-02 | 接受显式依赖路径，并区分应用、依赖和 JDK class。 |
| FR-03 | 使用 ASM 解析 classfile，生成类、方法、字段、指令、调用、异常和类型事实。 |
| FR-04 | 根据目标 classfile 版本选择 Java 8 `rt.jar` 或 Java 9+ `jrt-fs` 模块源。 |
| FR-05 | 对嵌套深度、条目数量、压缩/解压大小、压缩比、classfile 大小和链接/reparse point 设置边界。 |
| FR-06 | 读取失败、依赖缺失、模块不可读和版本不匹配必须保留为结构化完整性状态。 |

### 2.2 静态语义

| ID | 要求 |
| --- | --- |
| FR-07 | 覆盖 `readObject`、`readObjectNoData`、`readExternal`、`readResolve`、`resolveClass`、`resolveProxyClass`、`readUnshared` 和继承回调。 |
| FR-08 | 通过 YAML 描述替代反序列化入口、source、sink、框架桥接和调用模型。 |
| FR-09 | 支持调用图、CFG、异常边、类型层次、字段写入、数组、容器元素、receiver、反射、代理和 lambda 关系。 |
| FR-10 | 支持 forward/backward taint、字段/返回值/receiver/容器来源、对象图和链组合。 |
| FR-11 | 对 JNI、JRMP、模块、类加载和动态反射保留边界事实；未知目标不能扩展为任意调用。 |
| FR-12 | 链校准必须区分类型、序列化、控制流、字段约束、触发条件和安全配置。 |
| FR-13 | 每条链必须携带 `rule_id`、entry、sink、逐跳 edge、机制、字段依赖和完整性原因。 |

### 2.3 Blackboard 与扩展

| ID | 要求 |
| --- | --- |
| FR-14 | Blackboard 按 phase 和 `KnowledgeSource.priority()` 调度知识源，并在 phase 间建立屏障。 |
| FR-15 | 知识源之间不得直接调用；通过 Blackboard 事实和事件协作。 |
| FR-16 | `KnowledgeSource` 必须声明 `phase()`、`priority()`、`interests()`，并通过 ServiceLoader 注册。 |
| FR-17 | 规则文件负责攻击面数据，分析引擎负责通用语义；不得使用样本、包名或类名特判。 |
| FR-18 | 链 identity、语义合并、校准状态和注记由统一链存储管理。 |

### 2.4 动态确认

| ID | 要求 |
| --- | --- |
| FR-19 | 默认动态模式使用独立子 JVM 和 canary，在精确 sink 边界停止方法体。 |
| FR-20 | SAFE_REAL 必须显式开启 `--safe-real-sink --require-os-isolation`，并在 OS_STRICT ready 后才加载目标类。 |
| FR-21 | SAFE_REAL 只允许 descriptor 可证明的类型、receiver 和固定安全参数；未知对象、数组、脚本、模板、远端命名和任意 native 必须拒绝。 |
| FR-22 | 命令只允许 Just 自有 JDK 的固定 `-version`；文件只允许 scratch；网络只允许固定 loopback。 |
| FR-23 | `SINK_EXECUTED_SAFE` 必须同时具备精确调用、固定参数、API/body 正常返回和绑定 attempt 证据，并标记 `sink_distorted=true`。 |
| FR-24 | `JNI_EXECUTED_SAFE` 只允许 Just 自有、固定摘要、格式和架构匹配的 fixture，且必须具备 load、callback 和正常返回事件。 |
| FR-25 | 普通 stdout/stderr、属性、环境变量、异常文本和退出码不能单独形成正向动态证据。 |

### 2.5 OS 隔离

| ID | 要求 |
| --- | --- |
| FR-26 | Linux strict 使用固定 root image/digest、namespace、只读输入、scratch、cgroup v2、seccomp、NoNewPrivs、Landlock 和 parent-death 策略。 |
| FR-27 | Windows strict 使用 target 创建前的 AppContainer、Low Integrity、zero capability、restricted handle list、Job Object 和 per-run package SID ACL。 |
| FR-28 | Job Object、JVM 权限门、Security Manager 或 child 自报不能单独声明 OS_STRICT。 |
| FR-29 | 缺少隔离组件、权限、root、profile service、JDK 或 native ABI 时必须返回 `UNTESTABLE` 和唯一可审计原因。 |
| FR-30 | 子进程必须通过平台 API、策略摘要、身份绑定和 ready/terminal 协议进行认证。 |

### 2.6 结果与报告

| ID | 要求 |
| --- | --- |
| FR-31 | 所有报告由同一规范化结果模型生成，包含 findings、全路径 evidence、calibration、verification、metadata、dependencies 和 payload plan。 |
| FR-32 | 输出支持 CSV、JSON、SARIF、HTML 和 Markdown，并保持字段和排序一致。 |
| FR-33 | payload plan 只描述对象图、字段、触发和证据计划，不包含攻击字节流。 |
| FR-34 | 支持扫描结果 diff、baseline 和 suppression，并按稳定链 identity 比较。 |
| FR-35 | 结果必须记录 artifact、JDK、规则、参数、预算、阶段耗时、完整性、动态能力和 canonical digest。 |

## 3. 状态契约

| 状态 | 定义 |
| --- | --- |
| `SINK_BLOCKED` | 精确 sink 边界已到达，canary 阻断方法体 |
| `SINK_EXECUTED_SAFE` | 固定安全参数下精确 API/body 正常返回 |
| `JNI_EXECUTED_SAFE` | Just-owned native fixture 完成完整安全事件序列 |
| `SAFE_EFFECT_OBSERVED` | 只观察到 Just 自有 adapter 效果 |
| `CONCRETE_REACHED` | 到达安全观察点，但尚无精确 sink 证据 |
| `PARTIAL` | 分析、构造或依赖只完成一部分 |
| `TIMEOUT` | 达到明确的时间预算 |
| `UNTESTABLE` | 缺少依赖、JDK、权限或隔离能力 |

以上状态均不等价于 RCE。Just 不输出 `RCE_CONFIRMED`。

## 4. 非功能需求

| ID | 要求 |
| --- | --- |
| NFR-01 | 核心交付保持单 JAR；可选 JNA 或平台 runner 缺失时能力必须显式可见。 |
| NFR-02 | 大工件采用流式读取、冻结索引、按需 CFG/CPG、共享 immutable summary 和有界缓存。 |
| NFR-03 | 静态阶段与动态阶段分别计量，记录 frontend、CPG/CFG、hierarchy、forward、backward、composition、calibration、verify 和 runner 分段耗时。 |
| NFR-04 | 性能优化不得减少规则、扫描深度、链覆盖、完整性或确定性。 |
| NFR-05 | 固定输入、JDK、规则、预算和参数下，静态 wall time 使用 p50/p95 门；动态 startup、class-load、native、queue 和 cleanup 独立计量。 |
| NFR-06 | 并行度、缓存和动态预算有界；默认不自动重试 timeout，显式重试必须计入总预算。 |
| NFR-07 | 同一输入和配置下，串行、并行和重复运行的链集合、reason、排序、状态和 digest 一致。 |
| NFR-08 | 测试覆盖 CLI、报告、恶意工件、状态协议、隔离边界、跨 JDK、确定性、超时/OOM 和性能。 |
| NFR-09 | 代码保持低耦合、高内聚和直接控制流，不用 catch-and-continue 或复制状态机掩盖错误。 |

## 5. CLI 契约

```text
just-sast scan --jar=<path> [--deps=<path,...>]
                 [--jdk-home=<path>] [--output=<path>]
                 [--rules=<path>] [--verify-budget=<N>]
                 [--stats] [--fast] [--no-verify]
```

`--fast` 和 `--no-verify` 会改变扫描范围或动态验证范围。退出码为：`0` 成功，`2` 参数或输入错误，`3` 扫描内部错误。

## 6. 验收

验收顺序为快速契约、`mvn test`、single-JAR 构建、静态/动态报告检查、Gleipner evaluator 外部语义回归、确定性和固定性能门。Gleipner 的输入、truth、评测脚本和评分口径与生产代码分离。
