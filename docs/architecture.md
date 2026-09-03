# Just 架构设计

版本：2026-09-03。本文件描述 Just 的产品边界、模块职责、数据流和结果契约。

## 1. 产品边界

Just 是面向 Java JAR、WAR 和 class 目录的字节码分析工具，重点分析反序列化入口到 gadget/sink 的可达关系。交付形态为单 CLI JAR，静态分析和报告生成不依赖外部服务。

动态验证是静态结果的补充。默认模式在精确 sink 边界使用 canary；显式 `SAFE_REAL` 模式只对类型、descriptor、参数和 receiver 均可证明的安全调用执行确认，并要求 OS_STRICT。动态结果表示可调用性或边界事件，不表示 RCE。

## 2. 核心不变量

1. ASM 只在 frontend 使用；后续层只消费 Just model。
2. 规则描述攻击面，知识源实现语义；不按样本、包名、类名或结果文本添加分支。
3. 静态候选、扫描完整性、校准结果、动态能力和动态状态彼此独立。
4. 并行只改变调度顺序，不改变链 identity、规则归因、证据、状态或排序。
5. 结果中的正向动态证据必须绑定 attempt、chain、sink、artifact 和 policy identity。
6. 任何动态失败都保留静态候选，并以结构化原因表达。

## 3. 分层与职责

```text
输入工件 / 依赖 / 目标 JDK
          │
          ▼
frontend.asm：读取、ASM、嵌套工件、JDK source
          │  immutable model facts
          ▼
model / CPG / CFG / hierarchy / summaries
          │
          ▼
Blackboard：阶段、事实、事件、链 identity
          │
          ▼
knowledge：分析、组合、校准、验证调度
          │
          ▼
verify：独立 child、OS runner、probe、事件认证
          │
          ▼
report：统一结果模型 → 多种输出格式
```

| 模块 | 职责 | 不承担 |
| --- | --- | --- |
| `frontend.asm` | 读取 JAR/WAR/class 目录，解析字节码并生成事实 | 污点推理、链排序、报告格式 |
| `model` | 保存类、方法、字段、调用、指令和类型事实 | 全局运行时状态 |
| `cpg` / `analysis` | CPG/CFG、调用/字段/类型索引和需求驱动求解 | sink 执行、最终报告 |
| `blackboard` | 阶段屏障、事实事件、稳定合并和统一链存储 | 某个攻击面的私有语义 |
| `knowledge` | 通过 `KnowledgeSource` 提供 source、sink、回调、组合和校准 | 直接调用其他知识源 |
| `verify` | 候选选择、独立子 JVM、隔离、probe 和安全化真实调用 | exploit、任意 native、危险副作用 |
| `report` | 从规范化模型生成 CSV/JSON/SARIF/HTML/Markdown | 重新推导或改写结论 |

依赖方向为 `frontend → model/analysis → blackboard/knowledge → verify/report`，禁止反向依赖。

## 4. 工件与静态模型

`JarReader` 流式读取普通 JAR、fat JAR、WAR 和嵌套工件，并对递归深度、条目数量、大小、压缩比、classfile 大小以及链接/reparse point 进行边界控制。解析失败进入完整性原因，不伪造方法体。

`JdkClassSelector` 根据 classfile major 选择目标 JDK：Java 8 使用 `rt.jar`，Java 9 及以上使用 `jrt-fs` 模块源。缺失依赖、模块不可读和版本不匹配保留为结构化状态。

CPG 使用语义核心图和按需关系：核心保存方法、调用、分发、lambda、字段写入和类型层次；CFG、异常边、def-use、receiver、数组和容器元素 provenance 按分析需求展开。共享索引和冻结摘要减少重复解析。

静态知识包括：

- `readObject`、`readObjectNoData`、`readExternal`、`readResolve`、`resolveClass`、`resolveProxyClass`、`readUnshared` 及继承回调；
- YAML 描述的替代反序列化入口、source、sink 和调用模型；
- forward/backward taint、字段/返回值/receiver/数组/容器元素来源；
- CHA、可见性、接口和传递子类型、异常边、lambda、代理、反射、模板/类加载、JNI 和 JRMP 边界；
- 类型、序列化、控制流、字段约束和触发条件校准。

未知目标不扩展为 wildcard，不能证明的事实进入 `PARTIAL` 或 `UNTESTABLE`。

## 5. Blackboard 与知识源

Blackboard 按 `Phase` 和 `KnowledgeSource.priority()` 调度知识源，并在阶段之间建立屏障：

- `ANALYSIS`：入口、sink、调用、污点和框架事实；
- `COMPOSITION`：字段、对象图、片段和语义链组合；
- `CALIBRATION`：类型、可控性、触发、序列化和安全配置校准；
- `VERIFY`：候选选择、动态验证和状态汇总。

`ChainStore` 独占链的 semantic key、稳定替换、校准状态和注记；Blackboard 负责扫描级事实和事件。阶段内可以并行生成局部 delta，提交时按稳定 key 合并。

扩展知识源实现 `KnowledgeSource`，声明 `phase()`、`priority()`、`interests()`，通过 Blackboard 通信并由 ServiceLoader 注册。规则文件负责数据，知识源负责语义。

## 6. 动态验证

验证器采用 fork-per-chain 的独立子 JVM。父进程生成一次性 attempt identity、链/sink/artifact fingerprint、结果文件和策略摘要；子进程在 ready 之前完成 probe、agent 和隔离绑定，目标类只在边界准备完成后加载。

动态路径分为四层：

1. `CANARY`：执行真实前置路径，在精确 sink 边界阻断方法体；
2. `SAFE_EXEC`：只观察 Just 自有 inert adapter 的效果；
3. `SAFE_REAL`：在 OS_STRICT 下以固定安全参数调用允许的 API/body；
4. `JNI_EXECUTED_SAFE`：只加载 Just 自有、固定摘要、匹配格式和架构的 native fixture，并要求 load、callback 和正常返回事件绑定同一 attempt。

SAFE_REAL 的参数由方法 descriptor 驱动。命令仅允许 Just 自有 JDK 的固定 `-version`，文件仅允许 scratch，网络仅允许固定 loopback，任意目标参数、脚本、模板、远端命名、未知对象和目标 native 均拒绝。

## 7. OS 边界

Linux strict runner 由固定 root image/digest、namespace、只读输入、scratch、cgroup v2、seccomp、NoNewPrivs、Landlock 和 parent-death 策略组成；缺少任一生产前置时只返回 `UNTESTABLE`。

Windows strict runner 以 target 创建前的 AppContainer token 为主边界，并结合 Low Integrity、zero capability、restricted handle list、Job Object 和 per-run package SID ACL。Job Object、JVM 权限门、Security Manager 或 child 自报单独都不构成 OS_STRICT。

子进程通过平台 API 和绑定结果文件进行身份、策略和生命周期认证。普通 stdout/stderr、属性、环境变量和退出码不能单独产生正向证据。

## 8. 结果与报告

所有输出由一个规范化结果模型派生：

- findings：折叠后的主链；
- evidence：全路径、逐跳边、sink、校准和依赖；
- verification：动态能力、状态、attempt 和证据 tuple；
- meta：artifact、JDK、规则、参数、阶段统计和结果 digest；
- payload plan：对象图、字段、触发和验证计划，不是攻击字节流。

状态语义如下：

| 状态 | 语义 |
| --- | --- |
| `SINK_BLOCKED` | 精确 sink 边界被 canary 阻断 |
| `SINK_EXECUTED_SAFE` | 固定安全参数下的 API/body 正常返回，且标记参数失真 |
| `JNI_EXECUTED_SAFE` | Just-owned native fixture 完成完整安全事件序列 |
| `CONCRETE_REACHED` | 运行到安全观察点 |
| `PARTIAL` | 构造、依赖或分析只完成一部分 |
| `TIMEOUT` | 达到明确的时间预算 |
| `UNTESTABLE` | 缺少依赖、JDK、权限或 OS runner 能力 |

## 9. 性能与确定性

性能关键路径采用流式工件读取、按需 CFG/CPG、共享 immutable summary、source/sink 需求范围、有界缓存、候选级 native index、统一批量 deadline 和有限动态预算。静态阶段与动态阶段分别计量。

确定性由稳定 key、semantic merge、输入序号结果槽、固定排序、规范化 reason 和 findings/evidence 双 digest 保证。优化不能通过减少规则、扫描深度、完整性或动态能力换取速度。

## 10. 外部回归

Gleipner evaluator 用于外部语义回归。评测输入、truth、脚本和评分口径与生产代码分离，不作为运行时依赖，也不改变 Just 的规则和结果模型。
