# Just 架构设计

本文描述 Just 的稳定模块边界、数据流、分析契约和安全边界。它面向贡献者和需要评估扫描结果的使用者；性能数字和回归结论以仓库当前代码和 CI 为准，不把单次机器测量当成架构保证。

## 1. 产品边界

Just 的核心任务是：从 JAR/WAR/class 目录中提取 Java 字节码事实，建立可解释的调用与数据流关系，组合反序列化入口到危险 sink 的候选链，再通过校准和安全 canary 给出分层证据。

核心不变量：

1. ASM 只存在于 frontend；分析层只依赖 Just 自有 model。
2. 规则描述攻击面，知识源实现通用语义；不得为 benchmark、题目、包名或某条 WP 链增加分支。
3. 分析阶段可并行，跨线程事实只能通过局部 delta 和稳定顺序合并。
4. 静态候选、动态证据和完整性状态互相独立；动态失败不能静默变成“无链”。
5. 所有链带有 `rule_id`、入口、sink、逐跳路径和可追溯的拒绝/截断原因。
6. 动态验证只允许安全 canary 观测，不执行命令、网络访问、native 加载或可直接武器化 payload。

## 2. 分层与数据流

```text
输入工件 / 依赖 / 目标 JDK
              │
              ▼
      frontend.asm（ASM、嵌套工件、JDK source）
              │  immutable model facts
              ▼
        cpg/build + analysis indexes
              │  frozen graph / lazy CFG / hierarchy
              ▼
              Blackboard
       ┌──────┴──────────────────┐
       │                         │
       │ ANALYSIS                │ COMPOSITION
       │ backward taint          │ object graph
       │ forward taint           │ fragments
       │ OIS callbacks           │ semantic composer
       │ framework bridge        │
       └──────────────┬──────────┘
                      ▼
                 CALIBRATION
          validate → prune → safe config
          patterns → dynamic verification
                      │
                      ▼
     CSV / JSON / SARIF / HTML / Markdown / plan
```

模块依赖方向为 `frontend → model → cpg/analysis → blackboard/knowledge → report/verify`。report 只消费已合并的事实和证据；verify 不反向改变静态图。

### 2.1 所有权边界

| 模块 | 唯一职责 | 不应拥有的职责 |
| --- | --- | --- |
| `frontend.asm` | 读取工件、解析 ASM、选择目标 JDK、生成事实 | 污点推理、链排序、报告格式 |
| `model` | 保存类、方法、字段、调用和指令事实 | 类路径扫描和全局缓存策略 |
| `cpg` / `analysis` | 图索引、CFG、层次、来源传播和可达性 | 直接写最终报告 |
| `blackboard` | 事实、链、事件、阶段屏障和确定性合并 | 解释某个攻击面的细节 |
| `knowledge` | 以知识源形式提供 source/sink/回调/组合/校准语义 | 直接调用另一个知识源 |
| `verify` | 独立子 JVM 中构造和观察安全触发 | 替代静态分析或执行 exploit |
| `report` | 将结果持久化为稳定格式 | 重新推导链或修改置信度事实 |

## 3. Frontend 与代码图

### 3.1 工件读取

`JarReader` 以流式方式读取目标工件和显式依赖，识别普通 JAR、Spring Boot fat JAR、WAR 以及嵌套 JAR。递归展开有深度、条目数量和单条目大小上限；失败或上限会进入完整性原因。

`JdkClassSelector` 根据目标 class 的 major version 选择兼容的 JDK source：Java 8 读取 `rt.jar`，Java 9+ 通过目标 JDK 的 `jrt-fs.jar` 访问模块类。应用类优先于依赖，依赖优先于 JDK；缺少类不会伪造空方法体。

### 3.2 ASM 到 Just model

`BytecodeFrontend` 和 `FactsExtractor` 将 ASM 事件收敛为：

- 类、父类、接口、访问标志和序列化能力；
- 方法签名、访问标志、首行号、指令和异常表；
- 调用、字段读写、对象分配、数组操作、方法句柄和 lambda 事实；
- 不保留跨阶段不必要的原始 class byte 数组。

ASM 不穿透到 knowledge 层。这样可以替换或测试推理语义，而不把 ASM visitor 状态扩散到整个系统。

### 3.3 图表示：面向 Java 字节码的混合 CPG

Just 采用“语义核心图 + 按需关系”的混合 CPG，而不是把每条指令、每个抽象状态都物化成重型图对象。核心图冻结后主要保存 METHOD/CALL 节点、调用/分发/lambda 边、字段写入索引和类层次索引；`CpgIndex` 为方法维护紧凑的调用、字段、控制流语义切片，`Cfg`、异常边、值/字段关系和污点摘要按查询需要展开并共享。

这使图仍然可以表达 CPG 所需的 AST/CFG/数据关系，但适合没有源码、直接分析 JAR/WAR 的场景：ASM 只负责产生稳定字节码事实，查询层按需提供 containment、CFG、call、def-use、field、type、exception 和 taint 关系。全量预建指令图会放大对象数量和内存峰值，不符合 Just 的轻量目标。

设计重点：

- 邻接和调用索引采用稳定键，避免 worker 观察到不同遍历顺序；
- CPG 查询使用方法键和紧凑 offset/id 索引；同一个方法的 CFG 和语义切片在分析阶段复用，避免每个知识源重复重建图；
- 类层次闭包按需记忆化；可见性、`private`、`static` 和跨包 package-private 约束在分发前应用；
- JSR/RET、异常边、fall-through 和 lambda 目标在 CFG/调用图中保持显式语义；
- `DISPATCH_CAP`、实现者展开、路径和证明预算触顶时记录 `PARTIAL` 原因；
- 图构建与调度分离。CPU worker 可并行计算局部结果，但黑板只接受稳定合并后的 delta。

GPU 不属于默认后端。当前热路径是分支密集的对象/字段来源、反射和路径状态，不满足无条件搬运到 GPU 的同构数据条件；只有 profile 证明 bitset 可达性或 SCC 内核是主要成本，并通过 CPU 等价回归，才考虑可选实验后端。

本轮采用的研究依据包括：[CPG 原始模型](https://www.ieee-security.org/TC/SP2014/papers/ModelingandDiscoveringVulnerabilitieswithCodePropertyGraphs.pdf) 对 AST/CFG/PDG 合一查询的定义，[图可达性/IFDS 基础](https://www.sciencedirect.com/science/article/pii/S0950584998000937)，面向大 Java 程序的按需 access-path 分析[研究](https://arxiv.org/abs/2103.16240)，以及 Java 上下文敏感 points-to 的 [Qilin ECOOP 论文](https://drops.dagstuhl.de/storage/00lipics/lipics-vol222-ecoop2022/LIPIcs.ECOOP.2022.30/LIPIcs.ECOOP.2022.30.pdf)。它们共同支持“按需求解、共享摘要、在精度/时间边界内展开”的取舍，而不是盲目增加图规模。

## 4. Blackboard 与知识源

Controller 按 `Phase` 和 `KnowledgeSource.priority()` 调度，阶段内使用屏障：

- `ANALYSIS`：互相独立的知识源并行运行；
- `COMPOSITION`：按优先级消费分析事实，构造对象图和语义链；
- `CALIBRATION`：按优先级做可行性校准、剪枝、模式标注和动态验证。

跨阶段事件延迟投递，避免在生产者尚未完成时消费不完整事实。知识源只通过 Blackboard 合作，禁止互相持有和调用实现类。

| 知识源 | 阶段 | 责任 |
| --- | --- | --- |
| `BackwardTaintAnalysis` | ANALYSIS | 从 sink 反向寻找入口、字段和可控 receiver |
| `ForwardTaintKnowledgeSource` | ANALYSIS | 方法摘要不动点和对象来源传播 |
| `DeserializationCallbackKnowledgeSource` | ANALYSIS | OIS 回调、`readUnshared`、继承回调 |
| `FrameworkBridgeKnowledgeSource` | ANALYSIS | YAML source 与替代反序列化框架桥接 |
| `ObjectGraphEntryKnowledgeSource` | COMPOSITION | 字段类型和 `readResolve` 对象图重根 |
| `FragmentKnowledgeSource` | COMPOSITION | 声明式公开链片段 |
| `ChainComposerKnowledgeSource` | COMPOSITION | INVOKE、TRIGGER、TEMPLATE、DESER 和 source-host 组合 |
| `ChainValidatorKnowledgeSource` | CALIBRATION | 类型流、序列化、约束和 catch 可行性 |
| `ChainPrunerKnowledgeSource` | CALIBRATION | 触发上下文、深链结构和软预算校准 |
| `SafeConfigKnowledgeSource` | CALIBRATION | 对调用点实参求值后应用安全配置抑制 |
| `GadgetPatternKnowledgeSource` | CALIBRATION | 已知集合/链模式标注和证据因子 |
| `VerifyKnowledgeSource` | CALIBRATION | 构造可行性、子 JVM 动态验证和汇总 |

## 5. 静态语义

### 5.1 入口、source 与 sink

原生序列化入口包括 `readObject`、`readObjectNoData`、`readExternal`、`readResolve`、`resolveClass` 和 `resolveProxyClass`。替代框架入口由 YAML `source` 规则声明，并由框架桥接知识源连接到通用对象图/触发语义。

sink 规则描述危险能力和 tainted 参数，例如命令执行、JNDI、文件、网络、反射、类加载、表达式和模板。命中 sink 不等于形成漏洞链；必须有从入口到 sink 的可解释路径和必要的可控性证据。

### 5.2 来源传播与可达性

前向分析通过模型规则、字段读写、数组元素、返回值、receiver 和调用点敏感性传播来源；后向分析从 sink 按入口距离调度回溯。两者的结果通过稳定链 key 合并，互不以对方的临时状态作为隐藏前置条件。

反射、代理和框架桥接遵循“已解析优先、未知保留为不确定证据”的原则：

- `getMethod`/`getDeclaredMethod` 只有在类、方法名和参数类型有证据时扩展精确目标；
- `Method.invoke` 的目标需要 receiver/Method 来源约束；
- 动态代理需要接口方法、handler 和 receiver 兼容；
- 框架供给只由 source 规则派生包前缀和 JavaBean 形态控制，不把任意 public 方法泛化成外部输入；
- JNI 和 JRMP/RMI 作为能力转换/边界节点保留静态证据，不假设 native 或远端行为已经发生。

### 5.3 触发器与组合

组合器把后段 gadget 和反序列化源宿主连接起来。集合触发器要求声明类型和入口方法兼容：`HashMap` 对应 `hashCode`，有序容器对应 `compareTo`/`compare`，线性集合对应 `equals`。每条桥接边保留机制标签和 provenance，便于报告解释和动态段归因。

## 6. 校准、置信度与完整性

校准不是简单删链，而是将静态证据拆成可检查的约束：PASM/类型流、构造和序列化可行性、catch 可达性、receiver 兼容、字段依赖和 sink 路径。未知条件不会被当作已证伪；只有可证明不满足时才拒绝。

完整性状态独立记录以下原因：

- JDK 未挂载或版本不兼容；
- class、嵌套工件或依赖解析失败；
- 调用者/实现者/分发、路径、对象图、事件或证明预算触顶；
- 动态验证缺类、超时、权限、native 或运行时能力不可用。

`COMPLETE`/`PARTIAL` 描述扫描覆盖，不描述漏洞是否存在。`FEASIBLE`/`DEGRADED`/`NOT_FEASIBLE` 描述链校准；动态状态描述运行时证据，三者不能互相替代。

## 7. 动态验证架构

动态验证由 `VerifyKnowledgeSource` 选择候选，由 `ParallelVerifier` 管理 fork-per-chain 子 JVM，由 `ChainVerifyProbe` 构造和触发对象图，由 Java agent 在精确 sink 处安装 canary。

单条验证流程：

```text
静态链
  → 候选选择（入口覆盖 + sink family + 证据排序）
  → 独立 JVM / 隔离 cwd、tmp、超时、内存
  → 反射构造字段依赖图
  → 触发模式（SERIAL / HASH / COMPARE / EQUALS / PROXY / DIRECT）
  → canary 检查入口帧和 sink 全等匹配
  → 持久化状态、原因、证据、尝试次数和耗时
```

验证状态：

| 状态 | 语义 |
| --- | --- |
| `SINK_BLOCKED` | 真实序列化/触发链到达精确 sink 边界，canary 阻断危险方法体；最高动态证据 |
| `CONCRETE_REACHED` | 真实触发前缀到达安全观察点，但尚未到达精确 sink 边界 |
| `EXECUTED` | 入口调用成功，但没有 sink 到达证据 |
| `PARTIAL` | 构造/触发只完成一部分，保留静态链 |
| `FAILED` | 验证进程失败或非零退出，属于弱否定证据 |
| `UNTESTABLE` | 缺类、JDK、权限、native 或其它运行时能力导致无法测试 |

JVM deny-by-default 权限门只能减少 Java 层能力，不能隔离任意不可信代码。生产使用必须叠加 OS/容器/虚拟机、低权限账户、只读输入和无网络策略；JDK 24+ 不能把 Security Manager 当作可用的 OS 隔离。

## 8. 报告与稳定性

报告由独立 reporter 生成，并按阅读任务分类：

```text
just-out/
├── index.md
├── findings/       findings.csv/json/sarif/html/md
├── verification/   payload.md/json、dynamic-verification.json
├── evidence/       chains.csv、edges.csv、sinks.csv、calibrations.csv、dormant.md
└── meta/           scan-metadata.json、payload-plan.json
```

所有格式从同一份规范化链路视图渲染；Markdown 面向人读，JSON 面向 agent，CSV/SARIF 面向导入和审计，旁车证据不重新推导静态结论。

`findings.csv` 是折叠后的主链，`chains.csv` 保留路径变体；`edges.csv` 负责解释逐跳语义；`calibrations.csv` 让拒绝原因可审计。动态和完整性旁车文件不改变既有 findings JSON 数组契约。

payload writer 输出确定性的对象图、字段依赖、触发模式、危险能力和验证证据计划。`verification/payload.md` 以“反序列化入口 → 触发器 → gadget → sink 边界”的逐跳形式展示，`verification/payload.json` 以稳定字段供人和 agent 消费；两者都是安全计划和证据视图，不是可直接执行的攻击 payload。

## 9. 性能与内存原则

当前实现使用流式输入、原始字节早释放、冻结只读索引、按需 CPG/CFG、局部来源状态、共享摘要和自适应 CPU 并行。性能优化必须同时满足：

1. 链身份、sink、规则归因和完整性原因不变或有解释；
2. 结果合并与报告排序确定；
3. 预算截断不污染跨上下文死胡同缓存；
4. 以同一 JAR/JDK/规则测量 wall time、报告时 live heap 和 OS RSS；
5. 没有 profile 和等价回归时，不引入 GPU 或额外运行时依赖。

`scan-metadata.json` 中的 `heap_used_mb` 是报告时 JVM live heap，不是 RSS 峰值。大型工件的真实内存发布门槛必须用外部进程采样器验证，不能从一个结束时快照推导峰值。

## 10. 扩展方式

新增攻击面优先增加 YAML 规则：

```yaml
rules:
  - id: EXAMPLE-SINK
    kind: sink
    category: CODE_EXEC
    severity: HIGH
    match:
      call: {owner: "java/lang/Runtime", name: "exec"}
    tainted: [{arg: 0}]
```

需要新的分析语义时，实现 `KnowledgeSource` 并声明 `phase()`、`priority()`、`interests()`；用 Blackboard 事实和事件通信，通过 ServiceLoader 注册。不要在 CLI、报告器或其它 knowledge source 中硬编码攻击面，也不要为单个工件写条件分支。

## 11. 当前验证与已知限制

当前仓库验证基线：

- `mvn test`：146 项通过，0 失败，2 项环境跳过；
- Gleipner 全量使用 `evidence/chains.csv` 的全路径变体：块级 `TP=219, FP=22`，按 `(块, 入口类)` 去重 `TP=126, FP=17`；Windows JNI evaluator 的 native 加载路径限制单独记录，不折算成扫描器分数；
- 指定 WP 语料的安全动态结果为：`demo=2/3/15`、`demo2=2/3/15`、`babychain=1/0/19`、`n1cat=1/0/19`、`qiao=3/0/17`（`SINK_BLOCKED/CONCRETE_REACHED+EXECUTED/PARTIAL`）；
- `javamix` 当前工件产生 21,544 条静态候选，动态选择 20 条且均为 `PARTIAL`；它不含 WP 文档所述的 `InternalDataServiceImpl.processTask`，不能用另一份工件的结果替代；
- 大型工件的 live heap 仍然较高，不能宣称已经满足严格低内存发布门槛；
- 复杂框架真实输入、代理、JNI/JRMP 和 JDK 版本差异仍可能产生 `PARTIAL`/`UNTESTABLE`；
- 安全 payload plan、JVM 权限门和 canary 都不等价于生产级 exploit runner 或 OS sandbox。

动态验证的设计参考 [JDD](https://zxlfd.github.io/papers/jdd.pdf) 的 bottom-up gadget search 与 dataflow-aided object construction 思路，并参考 [FLASH（USENIX Security 2025）](https://www.usenix.org/system/files/usenixsecurity25-zhang-yiheng.pdf) 对反序列化引导调用图和按需可控性分析的讨论。Just 只借鉴其“真实前置链 + 按需可控性”原则，不执行最终危险能力，也不把论文中的完整 exploit 生成器带入默认 CLI。

这些限制必须进入报告和版本说明，不能通过增加参数、降低扫描深度、删除动态验证或 benchmark 特判来掩盖。
