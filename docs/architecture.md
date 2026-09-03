# Just 架构设计

版本：2026-09-04。本文件描述当前实现的模块边界、数据流和动态结果语义。

## 1. 定位

Just 是面向 Java JAR、WAR 和 class 目录的轻量字节码扫描器，重点分析反序列化入口、
gadget 组合和 sink 可达性。发布形态是单个 CLI JAR；静态扫描不依赖外部服务。

动态验证只补充静态证据：可完全约束的终点在 Windows Job Object 子 JVM 中以固定安全参数
真实调用；高风险终点在最终危险操作之前停止。任何动态结果都不等价于 RCE。

## 2. 设计不变量

1. ASM 只在 frontend 使用，后续层只消费 Just model。
2. 规则描述攻击面数据，知识源实现通用语义，不按样本、包名或结果文本分支。
3. 静态候选、完整性、校准、动态能力和报告投影彼此独立。
4. 并行只改变调度顺序，不改变链 identity、证据、状态或排序。
5. 正向动态证据绑定 attempt、chain、sink、artifact 和 policy identity。
6. 未知依赖、receiver、字段、模块或反射目标保留为结构化不确定性。

## 3. 分层

```text
输入工件 / 依赖 / 目标 JDK
          │
          ▼
frontend.asm：读取、ASM、嵌套工件、JDK source
          │ immutable facts
          ▼
model / CPG / CFG / hierarchy / summaries
          │
          ▼
Blackboard：阶段、事实、事件、链 identity
          │
          ▼
knowledge：source、sink、污点、对象图、校准、验证调度
          │
          ▼
verify：子 JVM、Job Object、probe、事件认证
          │
          ▼
report：规范化模型 → CSV/JSON/SARIF/HTML/Markdown
```

| 模块 | 负责 | 不负责 |
| --- | --- | --- |
| `frontend.asm` | 读取工件并生成类、方法、字段、调用、异常和类型事实 | 污点推理、排序、报告 |
| `model` / `analysis` | 保存 CPG/CFG、调用关系、类型层次、字段和摘要 | 动态执行 |
| `blackboard` | 阶段屏障、事实事件、稳定合并和链存储 | 攻击面私有语义 |
| `knowledge` | source、sink、回调、组合、构造和校准 | 直接调用其他知识源 |
| `verify` | 候选选择、子 JVM、进程边界、probe 和安全终点调用 | 危险副作用、exploit 生成 |
| `report` | 将统一模型投影到各格式 | 重新推导扫描结论 |

依赖方向为 `frontend → model/analysis → blackboard/knowledge → verify/report`。

## 4. 静态模型

`JarReader` 流式处理普通 JAR、fat JAR、WAR 和嵌套工件，并记录递归深度、条目数量、解压大小、
压缩比、classfile 大小和链接/reparse point 边界。失败不伪造方法体，而是进入完整性原因。

`JdkClassSelector` 根据 classfile major 选择目标 JDK 的 `rt.jar` 或 `jrt-fs` 模块源。主程序
使用 JDK17；`--jdk-home` 用于选择目标字节码、JRT 和验证子 JVM 所需的 JDK。

CPG 保存方法、调用、分发、lambda、字段写入和类型层次；CFG、异常边、def-use、receiver、
数组和容器 provenance 按 sink/entry 查询按需展开。局部摘要、冻结索引和稳定 identity 用于
避免重复解析，同时不丢弃未知边。

静态知识覆盖原生序列化回调、规则声明的替代框架入口、forward/backward taint、字段/返回值/
receiver/数组/容器来源、CHA、反射、代理、lambda、模块、JNI 和 JRMP 边界。无法证明的事实
保留 `PARTIAL` 或 `UNTESTABLE` 原因。

## 5. Blackboard 与扩展

Blackboard 依据 `Phase` 和 `KnowledgeSource.priority()` 调度知识源并建立阶段屏障。分析、
组合、校准和验证阶段通过事实与事件交换数据；知识源之间不直接调用。

扩展实现 `KnowledgeSource`，声明 `phase()`、`priority()`、`interests()`，并通过 ServiceLoader
注册。规则文件负责攻击面和调用模型数据，分析引擎负责通用语义。链由稳定 semantic key 合并，
每条链保留 `rule_id`、entry、sink、逐跳 edge、字段依赖、风险和完整性原因。

## 6. 动态验证

验证器为每条候选链启动独立子 JVM。父进程生成 attempt、chain/sink/artifact fingerprint、
结果文件和策略摘要；Windows Job Object 配置并附加到该子进程后，子进程才发送认证 ready 事件。

动态范围只有以下三类：

| 范围 | 执行内容 | 终点 |
| --- | --- | --- |
| `BOUNDARY_ONLY` | 完整前缀抵达精确 sink canary | 不进入 sink body |
| `PREFIX_ONLY` | 完整前缀到达高风险终点前的最后观察点 | 不执行危险终点 |
| `TERMINAL_EXECUTED_SAFE` | 用固定、安全、类型正确的参数真实调用可控 body/API，并观察正常返回或受控效果 | 仅执行可控安全终点 |

结果中同时记录 `requested_mode`、`effective_mode`、`fallback`、`verification_scope`、
`sink_risk`、`terminal_executed`、`stop_reason` 和 `last_confirmed_stage`。三类结果在报告中
互斥分组：`boundary_only`、`prefix_confirmed_high_risk`、`real_safe_terminal`。

终点风险元数据为 `SAFE_CALLABLE`、`CONTROLLED_EFFECT` 和 `HIGH_RISK_TERMINAL`。native/JNI/FFM
加载、任意类加载/定义/初始化、攻击性反序列化、脚本/eval、远端 lookup、非固定网络、不可控
外部进程和不可证明的文件操作只输出前置确认；Just-owned native fixture 只用于验证器自身的
基础设施契约，不代表目标 native 执行。

## 7. Windows 进程边界

Windows runner 使用普通用户可建立的 Job Object 和独立子 JVM，限制进程树、per-process user
CPU time、内存、active-process 数量、墙钟时间和 kill-on-close；scratch、净化环境、结果身份
绑定和父进程清理共同构成动态验证边界。该边界只声明 process/resource containment，不声明
完整文件系统、token 或系统网络控制。

Linux 保留 backend 接口和明确的不可用结果，当前不把普通子 JVM 的能力写成 OS 隔离能力。

## 8. 报告模型

统一模型包含 findings、全路径 evidence、calibration、verification、metadata、dependencies
和 payload plan。`payload plan` 只描述对象图、字段、触发和验证计划，不生成攻击字节流。

状态含义：

| 状态 | 含义 |
| --- | --- |
| `SINK_BLOCKED` | 精确 sink 边界已到达，canary 阻断 body |
| `PRE_SINK_CONFIRMED` | 高风险终点前的完整前置链已确认 |
| `SINK_EXECUTED_SAFE` | 固定安全参数下精确 body/API 正常返回，结果带失真标记 |
| `SAFE_EFFECT_OBSERVED` | 只观察到 Just 自有 adapter 效果 |
| `CONCRETE_REACHED` | 到达安全观察点但尚无精确 sink 证据 |
| `PARTIAL` / `TIMEOUT` / `FAILED` | 分析、构造或执行未完整结束 |
| `UNTESTABLE` | 缺少依赖、JDK 或所需进程边界能力 |

## 9. 性能与确定性

静态关键路径使用流式读取、按需 CFG/CPG、共享 immutable summary、有限缓存和候选级预算；
动态关键路径分别计量选择、队列、child startup、class-load、真实调用或 prefix-stop、cleanup；
性能工具同时按候选结果记录动态调用 duration，避免把并行候选总耗时当作单候选门禁。
固定输入、JDK、规则、预算和策略下，稳定 key、规范化 reason、固定 tie-break 和结果槽保证
串行/并行结果可复现。任何以减少链覆盖、完整性或确定性换时间的优化不合入。

## 10. 外部语义回归

Gleipner evaluator 作为外部语义回归使用；输入、truth、脚本和评分口径与生产代码分离，不
作为运行时依赖，也不改变 Just 的规则和结果模型。
