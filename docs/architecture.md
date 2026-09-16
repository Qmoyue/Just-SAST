# Just 架构

产品契约：`JUST-LIGHT-MINING-V3`。

Just 采用面向证据的分层静态分析架构：输入准备建立制品与依赖身份，ASM 前端生成程序事实，共享求解器组合组件链或应用链，报告层从一个冻结快照导出所有结果。

## 1. 用户流程

```text
CLI 配置
  │  输入 / 模式 / 依赖 / POM / 仓库 / 离线 / 目标 JDK / 输出
  ▼
输入准备与 provenance
  │  制品、依赖图、缓存、下载、hash、目标 JDK
  ▼
ASM 字节码前端
  │  不可变类、方法、字段、位置和制品事实
  ▼
共享静态求解器
  │  入口、站点、类型、字段、控制、回调、反射、桥和终点
  ├─ 有界静态筛选
  ▼
链证据与导出策略
  ▼
统一报告快照
  ├─ report.md / report.json
  ├─ index.md
  ├─ evidence/
  └─ meta/
```

依赖下载属于输入准备；有界筛选属于分析内部操作。规则提供事实与语义数据，求解器、约束、控制和组合逻辑保持通用。

## 2. 层次与所有权

| 层 | 主要职责 | 所有权边界 |
| --- | --- | --- |
| CLI | 解析参数、模式和输出策略 | 生成一次明确配置，不保存隐式全局状态 |
| 输入准备 | 读取制品、解析依赖、取得目标 JDK、建立 provenance | 负责输入身份、来源、hash、缓存和网络计时 |
| ASM 前端 | 读取 class/JAR/WAR/JDK 字节码 | 只生成程序事实，不执行目标代码 |
| 程序模型 | 保存类、方法、字段、调用、CFG、类型、异常和位置 | 提供稳定不可变事实，携带制品身份 |
| 入口与来源索引 | 识别 application entry、component trigger、site、origin 和对象关系 | 各类来源由明确索引负责，不互相隐藏求解 |
| 共享求解器 | 执行传播、分发、约束、桥接和链组合 | 只消费模型与规则数据，产出结构化证据 |
| 有界筛选 | 计算局部有限域、证明和 UNKNOWN | 只在完整矛盾时阻断，不负责排名或漏洞确认 |
| 导出策略 | 区分 component 与 application 的完整性和暴露要求 | 不把组件候选声明为应用漏洞 |
| 报告层 | 生成 Markdown、JSON、索引、证据和元数据 | 只消费冻结快照，不重新求解 |

典型实现入口包括 `ScanCommand`、`ScanPipeline`、`BytecodeFrontend`、`ArtifactProvenance`、`ApplicationEntryIndex`、`ForwardEngine`、`FilterAnalysis`、`FindingState` 和 `ConciseReportWriter`。新增模块需要明确消费者、生命周期、缓存键和失败语义。

## 3. 输入与依赖模型

输入准备区分应用类、组件根、内置库、显式依赖和目标 JDK。读取 Boot/WAR 嵌套路径时保留每个制品身份，避免把嵌套库误作应用入口。

POM 模型解析父 POM、属性、BOM、`dependencyManagement`、scope、optional、exclusions、classifier、type、传递关系和 Maven 版本仲裁。内置与显式字节码优先；POM 推导依赖携带来源和条件，不能直接代表实际部署。

依赖记录包含坐标、具体版本、来源、SHA-256、引入边和仲裁原因。重复类、重定位、classloader 顺序或缺失元数据会在 provenance 与报告中披露。`--offline` 禁止网络；缓存只发布完整制品和完整报告，任何预检、恢复或写入错误都直接失败。

目标 JDK 作为输入字节码来源读取。主程序使用 JDK 17，目标 JDK 的 `rt.jar` 或 JRT 布局通过 `--jdk-home` 独立解析，相关绝对路径、版本和 digest 进入运行元数据。

## 4. 共享求解器与两种模式

ASM 完成事实提取后，传播、接收者分发、CFG/摘要、字段对象关系、类型层次和桥接逻辑由共享求解器消费。

- `component` 从反序列化机制、触发器或规则入口开始，沿 gadget、对象、控制、依赖和终点求解。
- `application` 从真实执行边界与可控输入开始，连接站点、依赖/JDK、必要 bridge 和最终影响。

lookup、connect、构造器、解码和二次解析是可能的桥。桥证据需要对象、协议、制品和控制条件；危险 API 名称本身不构成终点。`EntryChainJoinEvidence` 与 `BridgeEvidence` 必须由可解析的结构化关系构成。

## 5. 有界静态筛选

筛选输入是支持的 Just 自有操作、常量或保持关联的完整有限域、程序位置和局部预算。求值在进程内完成，不加载、初始化、构造、反射调用或执行目标类，不执行目标 decode、序列化或 native 代码。

结果分为：

| 状态 | 作用 |
| --- | --- |
| `PROVABLY_UNREACHABLE` | 局部完整矛盾证明，唯一可以阻断路径 |
| `PROVEN_RETAINED` | 局部事实支持保留，不证明完整链 |
| `UNKNOWN` | 事实不足，保留候选 |
| `BUDGET_EXCEEDED` | 达到局部限制，保留候选并标记完整性 |

筛选预算按 proof/site 管理，记录操作数、域规模、评估数、保留数、拒绝数、原因和语义 digest。求值异常遵循分析语义；内部不变量错误直接失败。筛选尽量在高扇出展开前介入，无法精确判断时保留相关性并延迟组合。

## 6. 证据与报告

每个 hop 保存制品、精确方法/指令位置、连接依据、字段/对象关系和控制条件。链的完整性、结构可行性、控制状态、应用暴露和分析完整性彼此独立；排名只影响展示顺序。

报告流水线使用一个规范快照：

```text
analysis snapshot
  ├─ report.md       人工阅读
  ├─ report.json     机器消费
  ├─ index.md        摘要与计时
  ├─ evidence/       依赖与图证据
  └─ meta/           finding、digest、身份和运行条件
```

Markdown 与 JSON 共享链身份、证据、计数和排序。公共数据边界包括 concise report、finding output、rules、input digest 和 evidence-graph telemetry。动态筛选状态属于统一分析结果，不创建第二套报告状态。

依赖解析、网络、analysis、report 和 total 使用独立计时；筛选成本计入 analysis。缺失依赖、未知条件、预算、截断、取消和写入错误保留在相应状态中，不产生伪完整结果。

## 7. 安全、扩展与交付

Just 的安全边界是静态读取和受限求值：目标代码不执行，不启动目标进程，不访问目标 sink，不生成攻击 payload。外部输入在 CLI、输入准备和资源预算边界校验；内部错误直接暴露。

规则通过 YAML 数据和 `KnowledgeSource`/ServiceLoader 扩展。知识源通过 Blackboard 交换事实和事件，不直接调用其他知识源；样本名称、路径、SHA-256、预期答案和 benchmark 结果不进入求解分支。

行为测试覆盖组件与应用模式、依赖补齐与离线、目标不执行、有限域筛选、报告同源、资源限制和错误暴露。`tools/` 与 `benchmark/` 是开发验证支持，不是运行时依赖，也不参与 launcher 的用户使用路径。
