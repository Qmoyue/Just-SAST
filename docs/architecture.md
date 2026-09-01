# Just 架构设计

本文描述 Just 的稳定模块边界、数据流、分析契约和安全边界。它面向贡献者和需要评估扫描结果的使用者；性能数字和回归结论以仓库当前代码和 CI 为准，不把单次机器测量当成架构保证。

## 1. 产品边界

Just 的核心任务是：从 JAR/WAR/class 目录中提取 Java 字节码事实，建立可解释的调用与数据流关系，组合反序列化入口到危险 sink 的候选链，再通过校准和安全 canary 给出分层证据。

核心不变量：

1. ASM 只存在于 frontend；分析层只依赖 Just 自有 model。
2. 规则描述攻击面，知识源实现通用语义；不得为测试样本、题目、包名或某条 WP 链增加分支。
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
| `blackboard` | 事实、事件、阶段屏障和确定性合并；由私有 `ChainStore` 独占链身份、合并、校准和注记状态 | 解释某个攻击面的细节 |
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

Blackboard 不再同时维护链列表、语义身份索引、校准表和注记表。`ChainStore` 将这些必须一起变更的状态作为一个私有 cohesive owner：等价链替换时同步转移 key、calibration 和 notes，读取时只暴露不可变快照。Blackboard 仍拥有事实、事件和扫描级状态，因此知识源的公开协作接口不变，也不会因并行链发现顺序改变事件发布边界。

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

动态状态先由 `ConfidenceScorer.statusFromNotes` 对历史注记做兼容归一化，再由 `ChainRanking` 统一生成排序证据；CSV、SARIF、多格式报告和验证候选选择不能各自解释 `confirmed`、safe adapter 或 prefix。缺失或损坏的扩展注记按“无额外证据”处理，不得使报告失败或把弱证据升格。

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

## 10.1 本轮优化计划与设计决策（2026-08-30）

本轮目标不是降低扫描深度换取更短耗时，而是在相同规则、JDK、预算和输入下减少调度、对象和重复查询开销，并让所有降级都成为可审计证据。实施顺序固定为：

1. **性能基线与前端调度**：记录阶段耗时、类/方法/节点/边数量、CFG 命中、分析预算和动态验证能力；前端扫描会话复用并行 worker，禁止按小批次反复创建线程池。
2. **紧凑图与 CFG**：保持现有 CPG 查询契约，逐步以稳定整数 offset/id 和压缩邻接关系承载热路径；先保证 CFG 标签、异常语义和结果排序等价，再删除重复对象。大型图不能以完整指令对象图为默认存储。
3. **按需精度与公平预算**：在 sink 附近引入可解释的局部上下文/receiver 约束，优化反射/JNI 候选索引和异常边；全局预算采用每个 sink 的最低保障与剩余预算公平分配，不能由固定遍历顺序决定谁被扫描。
4. **动态安全与证据**：动态验证保持 fork-per-chain 和 sink canary 边界；加入结构化状态、精确 JDK/能力/原因，子进程只获得最小环境。Java 层权限门不宣称为 OS 沙箱；JDK 24+ 若无法启用等价能力必须 fail closed。
5. **报告与测试**：以规范化验证结果生成 JSON/JSONL、Markdown、CSV、SARIF，分离扫描完整性、链证明完整性和动态能力；补充子进程 E2E、跨 JDK/平台、恶意工件边界、确定性和性能回归。

研究取舍：CPG 论文证明 AST/CFG/PDG 的联合查询适合漏洞路径表达，但 Just 面向无源码 JAR，因此采用字节码语义 CPG，不物化无用 AST 节点；Qilin 的细粒度上下文敏感和增量 worklist 支持“局部按需”而非全程序重型 points-to；FLASH 的反序列化引导调用图支持优先分析可控 receiver；JDD 的动态对象构造思想用于验证真实前置链。上述资料只作为通用设计依据，规则和代码不依赖任何测试样本名称或 WP 结构。

本轮验收条件：

- 同一输入、JDK、规则和预算下，串行/并行结果链身份、规则归因、完整性原因一致；
- 不因前端批处理或图存储优化跳过 class、method、sink、异常边或规则；
- 所有预算、能力、fallback、超时、native 缺失和解析失败均进入结构化报告；
- 动态验证只能证明真实触发前缀到达 canary 边界，不能把 sink body 执行或 payload bytes 写入产物；
- 代表性回归工件、外部语义评测器和 Maven 全量测试均已执行；动态状态仍按 `SINK_BLOCKED/SAFE_EFFECT_OBSERVED/CONCRETE/PARTIAL/TIMEOUT` 如实记录，不能把静态候选数当作 WP 动态确认。未具备等价隔离能力的平台只记录为平台限制，不把未执行的跨平台结果写成通过项。

## 10.2 动态隔离与图优化增量设计（2026-08-30）

本轮对 JDD 的迁移限定在其真正解决的问题：从 sink 向上抽取可复用的 gadget fragment，用字段间输入/输出依赖描述对象构造，并在候选链上保留控制依赖和不确定性。JDD 论文没有提供可直接复用的 Windows/OS 沙箱；因此 Just 不把 JDD 的动态对象构造误称为隔离能力，也不把目标 JAR 放入扫描器进程内执行。

动态验证的安全协议分三层：

1. **进程边界**：每个候选链使用独立子 JVM、独立工作目录和临时目录、清洗后的环境、固定资源上限、超时递归清理和最小 classpath；目标代码不获得 probe 的应用类加载路径。
2. **Java 能力门**：在当前 JDK 能提供的范围内 deny-by-default，明确拒绝网络、进程、native/link、任意写入、动态 classloader 和退出；不支持可靠能力门时 fail closed，不把“进程启动成功”当作安全验证。
3. **证据协议**：父进程只接受 probe 生成且带有本次尝试认证标记的结构化终态；目标工件的 stdout/stderr、异常文本和非零退出只能作为诊断，不能单独升级为 sink 证据。canary 命中后立即抛出边界异常，危险 sink 方法体不继续执行。

验证只确认真实的入口、触发器、gadget 前缀和精确 sink 边界可达；不执行最终 sink，不加载目标 native，不连接网络，不生成可直接投递的攻击字节流。外部评测器若需要 JNI，仅允许在独立 loader/broker 中对经过路径和内容校验的测试库做环境验证，不能改变 Just 默认安全边界。

图优化采用可逆、可核对的顺序：先用 profile 区分前端解析、CFG/CPG 构建、调用图、污点传播、组合和验证调度，再把热路径迁移到 primitive offset/id、CSR/紧凑 slice、可复用 bottom-up fragment summary 和按需 worklist。任何剪枝必须由类型/控制/字段约束证明并记录为完整性事实；不能以 `fast` 默认、固定包名、题目类名或 WP 结构替代通用规则。GPU 只作为未来可选后端：没有稳定的同构数据内核、CPU 等价结果和资源自适应门控时，不加入默认运行时依赖。

本轮实现优先级为：

1. 修复验证状态协议和 native/link 拒绝，降低子进程对伪造输出和隐式能力的信任面；
2. 将字段依赖计划整理为确定性、去重、可复用的底向上对象构造摘要；
3. 优化不改变语义的 indexed CFG 构建，避免先创建临时 `CfgEdge` 对象再压缩；
4. 以代表性回归工件检查真实前缀到 sink 边界的证据，并运行外部语义评测器找出通用语义缺口；
5. 只有全量等价回归通过后，才更新性能结论；单次 wall time 不能证明提速。

## 11. 当前验证与已知限制

本轮收口验证：

- `mvn test` 通过，包含语义、契约、子进程边界、恶意工件边界和报告回归；`mvn package -DskipTests` 成功；
- 代表性回归工件和外部语义评测器均完成扫描；评测器逐项保留 TP/FP、跳过、超时、依赖缺失和平台能力原因，不把不可用环境折算为通过或失败；
- 安全动态结果统一使用 `SINK_BLOCKED/SAFE_EFFECT_OBSERVED/CONCRETE_REACHED/PARTIAL/TIMEOUT` 等状态。边界或 inert adapter 证据不代表真实 RCE，静态候选数也不等同于动态确认；
- 报告保留 `scan-metadata`、findings、链/边/sink/calibration evidence、对象图计划和动态验证结果；完整性触顶、依赖缺失、字段未链接和 JDK 模块限制均保持为结构化降级状态；
- 静态性能门按固定输入的历史基线 `×1.5` 验收；动态子进程成本单独报告，不能用关闭验证掩盖静态分析回退；
- `ObjectGraphPlan`、JVM policy、Job Object、bubblewrap 骨架、canary 和 safe-exec 不等价于生产级 exploit runner 或完整 OS sandbox；各平台的系统能力仍需在对应隔离 runner 中复验；
- 真实危险 sink、命令、网络、任意文件写、native 和可投递 payload 均不执行；`SAFE_EFFECT_OBSERVED` 始终带 `sink_distorted=true`。

动态验证的设计参考 [JDD](https://zxlfd.github.io/papers/jdd.pdf) 的 bottom-up gadget search 与 dataflow-aided object construction 思路，并参考 [FLASH（USENIX Security 2025）](https://www.usenix.org/system/files/usenixsecurity25-zhang-yiheng.pdf) 对反序列化引导调用图和按需可控性分析的讨论。Just 只借鉴其“真实前置链 + 按需可控性”原则，不执行最终危险能力，也不把论文中的完整 exploit 生成器带入默认 CLI。

这些限制必须进入报告和版本说明，不能通过增加参数、降低扫描深度、删除动态验证或测试样本特判来掩盖。

## 12. 2026-09 安全、确定性与产品化增量

### 12.1 研究结论与 Just 的边界

JDD（IEEE S&P 2024）的有效可迁移部分是 bottom-up gadget fragment、IOCD 字段依赖、
支配关系反馈和只改变 sink 相关字段的对象构造调度；JDD 不是宿主机 OS sandbox，不能把
它的动态 fuzz 设计写成隔离能力。[JDD 论文](https://yuanxzhang.github.io/paper/jdd-oakland24.pdf)
和其[公开实现](https://github.com/fdu-sec/JDD)均应按“对象构造/可利用性研究”理解。

FLASH（USENIX Security 2025）给出的可迁移原则是以反序列化可控 receiver 驱动调用图，
对可控对象采用较宽的 CHA/代理展开、对不可控对象采用更精确的 points-to 约束，并对反射
边做需求驱动恢复。[FLASH 论文](https://www.usenix.org/system/files/usenixsecurity25-zhang-yiheng.pdf)
支持 Just 的 source/sink 导向范围，但不授权把未知反射目标升级为确定调用。

GCMiner、ODDFUZZ、Gadgecy 和 Sleeping Giants 分别提示：对象生成需要遵循运行时覆盖反馈，
依赖版本存在前置条件，休眠 gadget 会随依赖/入口变化被激活。因此 Just 将这些研究迁移为
字段/控制约束、可解释的动态候选调度、dependency inventory 和 baseline/diff 方向；不迁移
攻击 payload 生成或真实 sink 执行。

### 12.2 隔离后端的能力模型

`OsIsolation.Backend` 的 `available` 只表示后端可以被调用，不表示它已经达到生产安全边界。
实现和报告应区分：

| 能力级别 | 最低语义 | 可否作为生产级动态前置条件 |
| --- | --- | --- |
| `NONE` | 没有可验证的外部边界 | 否，必须 `UNTESTABLE` |
| `PROCESS_RESOURCE` | 独立进程、进程树和资源限制 | 否，只能作为风险降低信息 |
| `OS_NAMESPACE` | namespace/只读挂载/独立 scratch/进程树 | 仍需 seccomp、cgroup 和文件策略证据 |
| `OS_STRICT` | OS namespace + cgroup + syscall allowlist + 文件/网络策略 + readiness/cleanup 证明 | 是，且必须在目标 runner 验收 |

Linux 的严格后端优先调用预配置的 nsjail 或等价 runner，并要求 private user/mount/pid/net/
ipc/uts namespace、只读输入、受限 scratch、cgroup v2 的 memory/pids/cpu、seccomp allowlist、
`no_new_privs` 和可用时的 Landlock。nsjail 的 namespace/cgroup/seccomp 能力见其[官方仓库](https://github.com/google/nsjail)。
bubblewrap 是低层 namespace 工具；其[官方文档](https://github.com/containers/bubblewrap)
明确提示安全性取决于调用参数和挂载资源，故无 seccomp/cgroup/文件策略证明时只能报告
`OS_NAMESPACE`，不能报告 `OS_STRICT`。

Just 的 nsjail strict 适配还要求部署者提供准备好的只读 root image 及其外部 digest（配置键
`JUST_NSAJAIL_ROOT`/`JUST_NSAJAIL_ROOT_DIGEST`，或等价 JVM 属性），不会把宿主机 `/` 当作
“只读即安全”的根目录；JDK、probe、目标和 scratch 作为显式挂载进入该 image。子 probe 在
加载目标类之前复核 namespace、nobody uid、`no_new_privs`、seccomp 和 cgroup controller，任一
证明缺失即 `UNTESTABLE`。bubblewrap 只接受显式 namespace opt-in，且仍不升级为 strict。

seccomp 只缩小 syscall 集，Linux 文档明确指出它不是完整 sandbox；Landlock 是可继承、可叠加
的文件/网络权限边界；cgroup v2 负责资源与进程数量，不替代身份和文件策略。[seccomp](https://www.kernel.org/doc/html/v6.6/userspace-api/seccomp_filter.html)、
[Landlock](https://docs.kernel.org/userspace-api/landlock.html) 和[cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)
必须作为独立能力分别探测，任何一项缺失都不得静默降级为严格隔离。

Windows 的 Job Object 只管理进程树和资源，不能单独限制 token、ACL 或网络。[Job Object 文档](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
和[AppContainer/受限进程接口](https://learn.microsoft.com/en-us/windows/win32/secauthz/createprocessinsandbox)
要求 restricted token/低完整性、默认拒绝 ACL、能力白名单和网络策略共同成立。Just 的 Windows
进程资源后端因此不会冒充生产 OS sandbox；strict dynamic 必须由可验证的外部 Windows runner
提供。JDK Security Manager 只属于 Java 层兼容门，JDK 24+ 不能依赖它作为 OS 隔离。

### 12.3 动态证据向量

置信度不再把所有“动态运行过”合并为一个正向加分，而是由以下五个正交维度组成：

```text
confidence = static structure
           + construction/field constraints
           + runtime observation
           + isolation strength
           - unresolved/completeness penalties
```

其中 `SINK_BLOCKED` 是“同一 entry/sink 绑定的真实前置链抵达精确 canary 边界”；
`SAFE_EFFECT_OBSERVED` 只说明 Just 自有 inert/mock adapter 观察到了失真效果，必须低于
真实边界且保留 `sink_distorted=true`；`CONCRETE_REACHED` 和 `EXECUTED` 只能作为前缀或入口
返回证据。隔离级别不足时，不得因为有终态文本而抬高动态可信度。`FAILED/TIMEOUT/UNTESTABLE`
不删除静态候选，只降低对应维度并保留原因。

### 12.4 确定性与性能

所有有界遍历在消耗预算前使用 `ValueOrigin`、调用点、字段、dispatch、chain 和 note 的
canonical key 排序；黑板在阶段屏障输出 canonical snapshot。动态验证默认不自动重试 timeout，
重试必须显式开启并计入预算，避免动态进程启动成本掩盖静态优化。

产品化能力采用同一身份模型：`artifact digest + dependency digests + rules digest + target
JDK + engine version + parameters`。增量 cache 只能恢复相同身份的规范化报告；baseline/suppression
按语义链身份匹配且默认只标记不删除 evidence；依赖输出提供坐标、版本、hash、direct/nested
关系和 SBOM 兼容结构，但没有外部漏洞数据库时不生成 CVE 结论。发布构建固定输出时间并提供
可选签名 profile，密钥不进入仓库，缺少密钥时不宣称签名成功。`--cache` 是显式报告级缓存：
命中前校验 artifact/dependency/rules/JDK/参数身份，只有 `COMPLETE` 且没有失败、超时、不可测
或截断动态终态的报告才可写入缓存；缓存不与 baseline/suppression 组合，以免复用错误的差异策略。

这些能力的测试采用“快速契约 → Maven → 平台/语料阶段门 → 最终全量”的顺序。跨平台只在
对应 runner 实际提供权限和能力时标记通过；否则必须以 `UNTESTABLE`/平台限制写入报告。
