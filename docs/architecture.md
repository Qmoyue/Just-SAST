# Just 目标架构

契约：JUST-LIGHT-MINING-V3，2026-09-13。本文是开发前目标设计，不是已完成的实现说明。保留稳定分析实现，沿真实能力缺口逐步迁移，最终发布前按实际代码再次校准。

## 1. 用户流程与分层

三个直接流程：输入组件得到条件明确的gadget链；输入应用得到真实入口到最终影响的链；通过--offline复用本地依赖完成同类分析。

```text
CLI：mode / input / deps / pom / repository / offline / target JDK
  → 输入准备：实际制品 + 有效依赖图 + 缓存/下载 + provenance
  → frontend：ASM读取目标、依赖和JDK，生成不可变程序事实
  → 共享分析：按需入口/站点/类型/字段/控制/回调/反射/桥求解
       ↳ 高成本或高噪声位置的有界具体求值
  → 链证据与模式导出政策：完整性、结构、控制和应用暴露
  → 一个报告快照 → report.md / report.json
```

依赖下载是输入准备，bounded static filtering 是分析内部操作，两者不拥有另一套求解器。框架规则是分析知识，不能替代目标实际版本字节码。

主扫描的最简公开入口是 jar、mode、deps/pom/repository、offline、jdk-home、output 和 rules，
overwrite 只负责输出安全。verify、no-verify、verify-budget、safe-exec、safe-real-sink 和
require-os-isolation 不属于产品接口；stats、fast、baseline、suppressions、cache 必须有独立
消费者和测试后才能作为高级工作流出现。CLI help 不描述已删除的目标执行、Job Object 或 payload。

## 2. 所有权和迁移入口

| 职责 | 当前可用入口 | 目标边界 |
|---|---|---|
| CLI选项与模式 | ScanCommand、ScanPipeline、ModeDemandPolicy | CLI只组装明确配置；mode一处决定需求根和导出政策 |
| 制品/依赖身份 | frontend输入、ArtifactProvenance、DependencyInventoryWriter、ScanCache | 输入准备是依赖图/制品身份的唯一owner；report只消费，不再次推导 |
| 依赖解析/下载（新增） | 现有--deps/嵌套读取可复用 | 有效POM→确定图→精确bytes；不执行构建，不隐式读settings |
| 字节码与运行库 | BytecodeFrontend、JarReader、TargetJdkSource/JrtClassSource | ASM仅frontend；目标--jdk-home读取与主JVM执行分离 |
| 程序事实 | model、analysis、Graph/CFG/类型/字段 | 稳定不可变模型，含artifact和位置；重复类/ownership显式 |
| 来源与需求索引 | ApplicationEntryIndex、OriginSupport、ForwardOrigins | entry/site、值/字段/对象身份和摘要各有明确owner，无全局暗状态 |
| 通用求解 | ForwardEngine、ForwardDispatch、ChainComposerKnowledgeSource | 按需扩展、单语义路径；不机械拆类、不复制知识源 |
| 有界筛选与证据 | FilterAnalysis、OriginSupport、ForwardConstraintPropagation | 统一输出局部 proof/unknown/budget；只在完整矛盾时阻断，不负责排名和全链确认 |
| 筛选 telemetry | OriginSupport counters、analysis snapshot、evidence-graph telemetry | 记录 kind/site/reason/domain digest、评估/保留/拒绝、预算和成本；不创建 verifier owner |
| 结果政策 | FindingState、ExportPolicy及现有chain/evidence | component/app完整性分开；分数不影响可达性证明 |
| 报告 | ConciseReportWriter与相关规范数据 | 单快照、共享证据；不重新求解或创建另一状态owner |

新增抽象必须说明替代哪个路径、消费者、生命周期/缓存键、失败语义与删除旧路径的批次。无真实第二消费者或测量收益时优先直接函数/现有模块，不预建平台。

## 3. 依赖输入模型

先识别真实输入角色：主应用类、内置lib、显式deps、JDK；普通组件根与应用根由mode处理。读取Boot/WAR嵌套路径保留每个制品身份，不把嵌套库误作应用入口。
依赖图解析支持父POM、BOM、属性、管理版本、scope、排除和正常Maven仲裁；评估嵌入官方model/resolver必要模块，避免外部Maven运行和自造错误解析器。
根元数据可能多个或被shading改写，不能任取第一个POM作为完整部署事实。--pom可提供明确根；class目录无根信息就显式未解析，不凭类名猜包。
实际内置字节码优先。POM解析的依赖环境带推导来源，provided/optional、容器库和shaded裁剪分别建模；不能把下载来的库认作部署必然存在。
每个依赖记录坐标/具体版本/type/classifier、来源、hash、引入边及仲裁原因；重复类/重定位/classloader顺序不明时显示受影响范围，不静默覆盖。
默认远程Maven Central，显式--repository扩展；--offline禁止任何联网。目标POM里的repositories不是可执行网络授权。下载器只取得元数据和归档；不运行插件/extensions/.mvn或目标类。
本地缓存保存完整制品；必要单文件原子提交防止半包入缓存，不建设事务平台。并发同制品有单一发布owner；失效由坐标/制品和语义依赖决定，版本/规则/JDK/模式等相关变化不得复用旧链。
阶段性补齐失败不是另选版本的触发器；明确记录失败，不无限重试、不静默离线降级。无关已完整结果可保留，但整次输入完整性如实。

## 4. 共享静态求解与 bounded filtering

ASM解析事实后，后续层只消费模型。应用模式从真实execution boundary与可控输入延伸到站点；组件模式从机制触发和结构条件延伸。两模式共用传播、约束、桥与证据模型。
需求交集、按需CFG/摘要/接收者分发减少前置物化。JNDI/RMI、JDBC/XML、二次反序列化等桥连接需对象/协议/制品条件，不因危险API名而截断。
筛选只在测量确认的成本高或噪声高位置启用；输入为支持的操作、常量/完整关联有限域、位置和预算，输出为精确值/局部条件证明或明确未定。
Decision 至少区分 PROVABLY_UNREACHABLE、PROVEN_RETAINED、UNKNOWN 和 BUDGET_EXCEEDED。
PROVABLY_UNREACHABLE 是唯一可以阻断路径的状态；其余状态保留候选。PROVEN_RETAINED
不能被误写成完整链 SAT，UNKNOWN 也不能被排名或报告层隐式拒绝。
目标字节码只能作为被解析的数据；执行的是Just自有操作，不加载/反射调用目标方法，不构造对象、不执行目标decode/序列化/native。
穷尽证明只允许裁剪对应不成立分支；不能由部分采样、一处SAT或运行异常推断整个链。算术溢出、空值/类型语义及异常边需与分析的JDK/指令语义一致。
求值开销计入analysis，设操作数/域基数/长度等明确工作量界限；相关域和语义版本入缓存键，超限保留未定。预算以 proof/site 为粒度，运行级预算状态只用于完整性统计，不能污染其他 site 的候选等级。内部bug直接失败，不catch-all转UNKNOWN。
筛选要在高扇出展开前或过程中介入。精确 site 域不可得时，使用延迟组合、语义等价去重或未解析端点保存相关性，
而不是与全局目标集合做笛卡尔积，也不能把未知误写成拒绝。固定输入、规则、依赖和目标 JDK 上必须同时测量
保留的 WP/重要变体、候选展开量、unknown/budget、filter 成本、RSS 和人工审查负担。
旧VerificationPlanner/Plan/Scheduler若有可用去重/预算逻辑，先去执行耦合和空值兜底再并入现有owner，不整个模块改名保存。FieldDependencyPlan等静态关系按实际消费者保留。
旧verifier/verify8/payload/canary/Job Object/SM、子进程认证/scratch/Java agent/native路径在职责迁移后删除；进程内筛选不需要OS隔离平台。Job Object 不能证明静态路径，也不能解决组合噪声；若未来需要独立分析 worker，必须是新的显式架构，不能成为 scan 的隐藏 fallback。
每次优化固定输入与配置做链/证据/误报和资源A/B，无有效收益删除，不维持永久双实现。

## 5. 证据与报告

每个hop保留artifact、精确方法/指令位置和连接依据；字段对象关系和控制条件明确。EntryChainJoinEvidence/BridgeEvidence必须可解析，不可由调用图共现或文字说明补造。
链是否完整、结构可行性、控制、应用暴露和分析完整性独立；ranking只排序不证明，UNKNOWN不变SAT；组件候选不生成应用漏洞结论。
生成一个规范报告快照，report.md/json共享ID/证据/计数/排序。JSON包含发现的有效候选和重要变体，Markdown前10展开，其余简表；displayLimit与searchBudget各自说明。
schema边界保持最小且单向：公共 schema 只描述 concise report、finding output、rules、input digest 和 evidence-graph telemetry；动态验证/运行信任边界与 v1/v2 shadow schema 不再是产品契约。动态筛选状态由分析模型和同一报告快照承载，不另写验证目录或兼容旁路。
旧 payload/verification writer、verify phase 和 Job Object 文案在迁移完成前只能列为残留，不得进入 README、help、稳定缓存身份或发布报告。
依赖解析与网络墙钟在输入准备计时；analysis包括filter；report和total单列。并行下载的request duration汇总不当墙钟相加。首次有用结果在报告可消费时记录。
缺失依赖、未知条件、截断/取消及写入错误直接影响相应状态；不能产生伪COMPLETE，不为美化报告隐藏难例。

## 6. 错误、资源和工程取舍

禁止兜底和防御性编程：内部不变量和错误状态直接暴露，不重复null检查/默认值归一化，不吞异常/猜值/自动降级/静默重试。
外部输入校验、未知域、网络错误和用户取消是必须声明的产品边界，由对应owner处理一次。已知目标异常是被分析语义；实现bug是失败，两者不能混用。
保留实际有用的归档/压缩比/路径/POM/YAML/class预算和输出碰撞保护；不因“精简”引入任意目标执行、路径逃逸或破坏已有报告。
缓存/并发仅在实测瓶颈需要时增加，写清语义依赖与生命周期；不加无界缓存、常驻服务、数据库、重复状态协议。
规则/框架入口/sink/callback/摘要是数据，求解/约束/控制/组合是通用语义，禁止样本名、SHA、路径、预期答案分支。

## 7. 验证与发布边界

行为测试保护真实扫描、依赖补齐/offline、两模式、不执行目标、相关域筛选、报告和错误暴露；端到端使用无害fixture，网络用小型受控仓库加公共制品smoke，不mock掉解析与求解核心。
八组CTF完整WP链、低误报Q-01、Apache正负/相关Gleipner与性能联合验收；不能以实现结构或测试数量证明产品正确。
ai-slop-taste和test-doctor在开发全程及最终全面检查：所有权/状态/兜底/表面复杂度、能力→测试映射、重复/脆弱/高成本测试；所有本轮问题落实修复。
开发前目标设计、过程中实际变化同步、最后requirements/architecture/README一致；本地commit贯穿。
Release验证与发布职责分开：Windows/JDK17只读校验同一提交和产物，必要检查成功后最小权限publish job创建tag和Release；不假设tag事件会再触发发布、不重新构建未验产物，不上传旧probe或通配JAR。最终核对远程SHA/资产hash/下载可用性。

实现时参考：[Maven Resolver职责边界](https://maven.apache.org/components/resolver/how-resolver-works.html)（还需Maven模型/描述提供方完成POM语义）、[GitHub workflow触发规则](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow)（不要依赖发布token创建tag后再触发另一次发布）。
