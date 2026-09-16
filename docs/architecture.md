# Just 架构

产品契约：JUST-LIGHT-MINING-V3。

Just 是一个证据驱动的静态分析器。它先冻结输入制品、依赖和目标 JDK 的身份，再由 ASM 前端建立不可变程序事实，最后用共享求解器组合 component 或 application 链。报告层只消费一次冻结快照，不重新求解、不执行目标代码。

## 1. 唯一用户流程

~~~text
CLI
  │  input / mode / dependencies / target JDK / output
  ▼
Input preparation
  │  artifact + dependency graph + provenance + cache/network identity
  ▼
ASM frontend
  │  classes + methods + fields + calls + CFG + locations
  ▼
Shared static solver
  │  origins + types + fields + callbacks + control + bridges + terminals
  ├─ bounded finite filtering
  ▼
Frozen finding snapshot
  ├─ report.json  agent entry
  ├─ report.md    human entry and Gadget graph
  ├─ evidence/    drill-down facts
  └─ meta/        identity and diagnostics
~~~

没有 index.md、findings/ 或动态验证旁路参与默认产品流程。扫描元数据写入 meta/run.json，事务状态写入 meta/transaction.json；二者都只服务于追溯和安全发布，不是用户报告。

## 2. Owner boundaries

| Owner | 负责 | 不负责 |
| --- | --- | --- |
| CLI | 解析参数，生成一次明确配置 | 保存运行状态、求解链或决定报告结论 |
| Input preparation | 读取制品、POM、依赖、缓存、仓库和目标 JDK，记录 provenance | 猜版本、执行 Maven 插件或加载目标类 |
| ASM frontend | 读取 class/JAR/WAR/JDK，生成方法、调用、字段、CFG 和位置事实 | 解释 payload、调用目标代码或反序列化流 |
| Program model | 保存稳定、不可变、带制品身份的程序事实 | 修改输入身份或隐藏缺失事实 |
| Entry/origin indexes | 识别 component trigger、application entry/site、来源和对象关系 | 直接调用其他知识源或将共现升级为可达 |
| Shared solver | 传播、分发、约束、控制、callback、bridge 和链组合 | 使用题名、路径、SHA 或 benchmark 答案特判 |
| Bounded filter | 对有限域做受限精确求值，输出证明/保留/UNKNOWN/预算 | 执行目标方法、排名或确认漏洞 |
| Finding snapshot | 冻结候选、状态、证据和稳定 ID | 为每个格式重新求解或丢弃重要变体 |
| Report writer | 从同一 snapshot 生成 JSON、Markdown 和显式附加证据 | 写动态结果、生成 payload 或制造第三种主入口 |

一个事实只有一个 owner。跨层数据使用 typed model、digest、ID 和 provenance，不通过自由文本或隐式全局状态传递。

## 3. 输入、依赖和 JDK

输入准备按实际优先级处理内置制品、显式依赖、准确 POM、完整缓存和远程制品。Maven Model/Resolver 负责父 POM、属性、BOM、dependencyManagement、scope、optional、exclusions、classifier、type、传递依赖和版本仲裁。缺失、冲突、不确定版本和下载失败进入结果状态，不换版本、不静默重试。

JDK 17 运行 Just；--jdk-home 只提供被分析的目标字节码和运行库。Java 8 读取 rt.jar，Java 9 及以上读取 JRT/JDK 布局。目标 JDK 不进入 Just 的应用执行 classpath，因为目标应用根本不启动。

所有制品记录逻辑名或坐标、角色、版本、来源、SHA-256、大小和引入关系。依赖解析、网络墙钟、分析、筛选、报告和 total 计时分开；筛选耗时属于分析子集。

## 4. 共享求解器和两种模式

ASM 事实进入共享程序模型后，由传播、类型层次、字段 alias、CFG、调用分发、对象图和 bridge 逻辑组合链。

- component 从机制触发点开始，要求 gadget、对象关系、控制条件、依赖/JDK 条件和真正 terminal。
- application 从真实应用执行边界和可控输入开始，要求 site、entry join、必要桥和 terminal suffix；EntryChainJoinEvidence 与 BridgeEvidence 必须可以从结构化图重建。

lookup、connect、构造器、解码、二次解析和类定义可能是 bridge，不自动是终点。只到中间 API 的候选应保留断点和状态，不能被报告为完整影响。

## 5. 静态边界和有限筛选

所有模式都只读取输入并进行受限静态求值。禁止加载/初始化/构造目标类和对象，禁止反射调用目标方法、反序列化攻击流、启动应用、访问危险 sink、执行目标 native 或构建插件。内部错误直接失败。

筛选 owner 只处理可证明的有限字符串、算术、比较、分支和有限名称。状态如下：

| 状态 | 后续动作 |
| --- | --- |
| PROVABLY_UNREACHABLE | 有完整局部矛盾，允许剪枝 |
| PROVEN_RETAINED | 保留候选，不证明完整链 |
| UNKNOWN | 保留候选并披露缺口 |
| BUDGET_EXCEEDED | 保留候选并披露边界 |

筛选必须保持值之间的关联性，并记录位置、域摘要、语义 digest、预算、评估/保留/拒绝/展开数和自身耗时。一次采样成功、目标异常或未知值都不能当作全域反证。

## 6. Snapshot 和公开报告

FindingOutputReader 在报告边界生成一次 typed snapshot。它保存稳定 finding ID、chain key、导出状态、entry/sink、链状态、对象关系、hop provenance、application trace、筛选状态和 notes。排序只决定展示顺序，不改变证据。

ConciseReportWriter 从同一 snapshot 写出：

~~~text
report.json
  ├─ all candidates and important variants
  ├─ outcome / coverage / per-chain completeness
  ├─ entry, site, bridge, terminal and constraints
  ├─ node/edge graph and precise hop provenance
  └─ dependency/JDK/filter evidence references

report.md
  ├─ concise outcome and coverage limitation
  ├─ primary chain Gadget graph
  ├─ object/control/bridge/terminal explanation
  └─ compact alternatives with JSON/evidence references
~~~

report.json 是 agent 入口，不能因 Markdown 展示上限丢候选；report.md 是人的入口，不能把 ranking、telemetry 和全部内部状态堆在首屏。两者必须共享 chain identity、计数、顺序和 graph projection。详细链展示之外，Markdown 还要汇总 capability boundary，让被截到候选表后的反射断点仍然可见。

公开状态拆为：

- outcome：有没有可审阅的结果，或发生失败/参数/运行库错误；
- coverage：静态分析 COMPLETE、BOUNDED 或 UNKNOWN；
- chain completeness：单条链的证据完整性；
- feasibility：单条链的 SAT、UNSAT 或 UNKNOWN。

内部 RunOutcome.PARTIAL 仍可表达不可缓存或不完整扫描，但不能被解释为动态测试。

## 7. Gadget 图和 demo

图使用 entry、site、callback、bridge、terminal 角色节点以及有方向的 typed edge。文本图比图片更稳定，适合 Markdown、终端和 agent 读取；精确 descriptor、offset、字段和 artifact provenance 保存在 JSON/evidence。

demo.jar 的静态主链必须由真实字节码和 WP 共同支持：

~~~text
DogController#importDogs
  → ObjectInputStream#readObject
  → Dog#hashCode
  → DogModel#wagTail
  → Method#invoke
  → TemplatesImpl#newTransformer
~~~

WP 外部恶意类的 Runtime.getRuntime().exec 不在 demo.jar 内，另一个手工对象图方案中的 invoke → Runtime.exec 也不由应用 JAR 自动证明。输入制品真实调用 java/lang/Runtime#exec 时，规则正常产生 sink；没有该字节码时，报告只能写制品外后续影响说明，不能伪造 terminal。

## 8. 事务、缓存和错误

ReportTransaction 先在唯一 staging 目录写完整报告，确认状态后发布，避免两个运行的文件混合。最终布局只需要两个 report 文件及有内容的 evidence/meta；扫描元数据 `meta/run.json` 与事务 marker `meta/transaction.json` 由各自 owner 写入，根目录不放第三个状态入口。空的 findings/ 不再是事务完整性的前置条件。staging、backup、失败状态和缓存错误必须显式可诊断，不能自动把不完整目录当成功。

缓存只接受完整输入身份和完整静态报告。报告、缓存、依赖和 JDK 身份变化会使相关结果失效；不隐藏缺依赖、预算或 UNKNOWN。

## 9. 扩展和质量

规则是 YAML 数据；知识源通过既有 Blackboard/ServiceLoader 边界交换 typed facts，不直接互调。ServiceLoader provider 的枚举、实例化或契约元数据错误会让扫描显式失败，不能跳过后伪装成完整；已成功装配的知识源在分析阶段运行失败则由 Controller 隔离，并把 PRODUCT/SOURCE failure 写入完整性状态。新增字段必须声明 owner、消费者、缓存键、失败语义和测试。

质量保护按用户能力而不是类数量组织：两模式、真实 entry/site/join/bridge/terminal、8 组 WP、Apache 正负、依赖/offline、未知/预算、无目标执行、报告同源、错误/恢复和发布资产。测试要优先验证公开 JSON/Markdown/目录和真实无害 fixture，避免私有实现快照、字符串堆砌和重复 fake。
