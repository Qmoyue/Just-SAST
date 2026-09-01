# Just 需求与验收

本文件定义 Just 作为 Java 反序列化 gadget 链扫描器的用户可见契约、质量门槛和已知边界。实现可以演进，但不能静默改变这些契约；如果一次扫描不完整，必须把原因写入报告。

## 1. 产品范围

Just 面向两类输入：

1. 真实开源 JAR/WAR 的依赖与代码审计；
2. CTF/研究语料中的反序列化入口、gadget 链和安全验证校准。

交付形态是单 CLI JAR。核心流程是字节码分析、规则驱动的链发现、可解释校准和安全 canary 验证。它不承担运行时防护、任意应用动态 fuzz 或可直接武器化 payload 生成。

## 2. 功能需求

### 2.1 输入与前端

| ID | 需求 |
| --- | --- |
| FR-01 | 接受 JAR、WAR 和 class 目录，并支持 `--deps` 补充依赖 |
| FR-02 | 解析 Spring Boot `BOOT-INF`、WAR `WEB-INF` 和嵌套 JAR；展开有深度、条目数和条目大小上限 |
| FR-03 | ASM 只在 frontend 使用，输出稳定的 Just model；模型包含类、方法、字段、调用、指令、异常表、lambda 和行号事实 |
| FR-04 | 通过 `--jdk-home` 按目标 major version 选择 JDK；Java 8 使用 `rt.jar`，Java 9+ 使用 `jrt-fs` |
| FR-05 | 缺失类、字节码错误、JDK 未挂载和嵌套工件失败必须诊断并进入完整性状态 |

### 2.2 图与数据流

| ID | 需求 |
| --- | --- |
| FR-06 | 建立冻结的字节码语义 CPG 核心和调用/分发/lambda/字段/类型索引；方法 CFG、异常和 def-use 关系按需计算并复用 |
| FR-07 | 支持可见性、传递子类型、接口、lambda、异常边、JSR/RET 和反射目标约束 |
| FR-08 | 支持前向方法摘要不动点和后向 sink 导向回溯；数组元素、字段、返回值、receiver 和调用点来源必须可传播 |
| FR-09 | 预算、分发上限、路径上限和证明上限必须有界；截断不能伪装成完整扫描，也不能污染不相容上下文的缓存 |
| FR-10 | 规则和图事实合并必须确定性：同一输入、JDK、规则和预算下链身份、规则归因和排序稳定 |

### 2.3 反序列化与框架语义

| ID | 需求 |
| --- | --- |
| FR-11 | 覆盖 `ObjectInputStream`、`readObject`、`readObjectNoData`、`readExternal`、`readResolve`、`resolveClass`、`resolveProxyClass` 和 `readUnshared` |
| FR-12 | 通过 YAML source 规则支持替代反序列化框架；安全配置只在调用点实参满足声明值时抑制 |
| FR-13 | 支持集合触发、字段依赖、JavaBean setter、动态代理 handler、反射 Method/Constructor、模板/类加载、JNI/native 和 JRMP/RMI 边界 |
| FR-14 | 代理、反射、框架桥接和 CHA 扩展必须使用 receiver、类型、方法签名或规则来源约束；未知目标只能形成不确定证据，不能泛化为任意调用 |
| FR-15 | 支持 `chain-fragment` 声明式片段，并将入口、桥接机制、gadget 和 sink 组装为可读路径 |

### 2.4 校准、验证与报告

| ID | 需求 |
| --- | --- |
| FR-16 | 链校准包含类型流、PASM、序列化可行性、catch 可达性、字段依赖和约束矛盾检查；校准不能替代静态证据 |
| FR-17 | 动态验证默认开启，采用 fork-per-chain 子 JVM、真实序列化/反序列化前置链、对象图构造、真实触发模式和 sink canary；`--no-verify` 显式关闭 |
| FR-18 | 动态状态至少区分 `SINK_BLOCKED`、`SAFE_EFFECT_OBSERVED`、`CONCRETE_REACHED`、`EXECUTED`、`PARTIAL`、`FAILED`、`UNTESTABLE`；`SINK_BLOCKED` 必须有入口归因的 canary/精确 sink 边界证据，`SAFE_EFFECT_OBSERVED` 必须绑定安全 adapter 的 policy/效果证据，且危险 sink 方法体不继续执行 |
| FR-19 | 动态验证必须持久化候选选择、能力、状态、证据、尝试次数、耗时和失败原因；静态候选不能因动态失败而消失 |
| FR-20 | 输出分类目录、`index.md`、CSV、JSON、SARIF 2.1.0、HTML、Markdown、扫描元数据、动态汇总，以及人/agent 可读且不可直接执行的 payload 视图和 plan |
| FR-21 | `diff` 依据规则、入口和 sink 的语义身份比较扫描，不依赖并行顺序和变体编号 |
| FR-22 | 退出码为：`0` 成功，`2` 参数/输入错误，`3` 扫描内部错误 |

## 3. 规则与扩展契约

默认规则文件为 `src/main/resources/rules/default-rules.yaml`，规则类型固定为：

- `sink`：危险能力和 tainted 参数；
- `magic-entry`：原生序列化和特殊回调入口；
- `source`：替代反序列化框架和安全配置；
- `model`：参数、返回值、receiver 和容器传播；
- `chain-fragment`：公开、可复用的链片段。

需要新的程序语义时，实现 `KnowledgeSource`，声明 `phase`、`priority` 和 `interests`，用 Blackboard 事实/事件通信并通过 ServiceLoader 注册。知识源不得直接调用其它知识源，不得按题目名、JAR 名、包名、类名、规则编号或 WP 文本特判。

## 4. 非功能需求

| ID | 需求 |
| --- | --- |
| NFR-01 | 默认交付不依赖外部服务；运行时依赖保持为 ASM、picocli、SnakeYAML |
| NFR-02 | 大工件采用流式读取、原始字节早释放、冻结只读索引、按需 CPG/CFG、共享摘要和有界缓存；必须同时记录报告时 live heap 与完整性边界 |
| NFR-03 | `heap_used_mb` 明确表示报告时 JVM live heap，不得冒充 OS RSS 峰值；真实内存门槛须用外部采样验证 |
| NFR-04 | 并行采用有界、自适应 worker 和局部结果合并，保留桌面资源；线程数不是性能验收指标 |
| NFR-05 | 性能优化不得牺牲扫描深度、规则覆盖、链身份、规则归因或确定性；没有 profile 和等价回归不得默认引入 GPU |
| NFR-06 | 动态验证使用最小 JVM 权限和独立进程；生产不可信工件必须叠加 OS/容器/虚拟机、低权限和无网络边界 |
| NFR-07 | 工具本身不通过原生 `ObjectInputStream` 读取旁车文件，不把动态验证结果跨扫描隐式缓存 |
| NFR-08 | 日志走 stderr；正常结果文件不混入调试输出；临时报告、JVM dump 和 evaluator 快照不进入版本库 |
| NFR-09 | 测试优先保护 CLI、报告、确定性、完整性、动态安全和扩展边界，不为偶然内部实现形状建立脆弱断言 |
| NFR-10 | 性能是发布门槛：在固定输入、JDK、规则、预算和 CLI 参数下，最终版本不得以降低扫描深度、规则覆盖、动态能力或完整性标记换取提速；同一基线的最终 wall time 目标不超过 `1.5x`，开发中间态不得超过 `2x` 而不记录阻断原因 |
| NFR-11 | 每次扫描必须记录 frontend、CPG/CFG、hierarchy、forward、backward、composition、calibration、verify 的阶段耗时，以及报告时 live heap、外部 RSS 峰值（若可采样）、缓存命中率、预算消耗和完整性状态；优化必须有 profile 和语义等价回归 |

## 5. 输出与状态语义

扫描输出目录至少包含：

```text
index.md                         扫描导航和摘要
findings/findings.csv            折叠后的主链
findings/findings.json           机器消费的链数据
findings/findings.sarif          SARIF 2.1.0
findings/findings.html/.md       人工审查报告
verification/dynamic-verification.json 动态候选、状态和证据
verification/payload.md/json     人/agent 可读的安全 payload 视图
evidence/chains.csv              所有路径变体
evidence/edges.csv               逐跳关系
evidence/sinks.csv               sink 裁决
evidence/calibrations.csv        校准拒绝/降级原因
evidence/dormant.md              可达但未成链的入口
meta/scan-metadata.json           输入、JDK、阶段、预算和完整性
meta/payload-plan.json            安全、确定性的对象图/字段依赖计划
```

`COMPLETE`/`PARTIAL` 表示扫描覆盖；`FEASIBLE`/`DEGRADED`/`NOT_FEASIBLE` 表示静态校准；动态状态表示运行时证据。三套状态必须同时保留，不能互相覆盖。

## 6. 安全边界

验证器中的 deny-by-default 权限门、临时目录、超时、内存上限和 sink canary 是 Java 层的风险降低措施，不是 OS 沙箱。JDK 24+ 不能假设 Security Manager 提供有效隔离。探针在 canary 命中后不进入危险 sink 方法体，不加载 native、不连接远程服务、不执行命令；显式 `--safe-exec` 只允许 Just 自己执行固定 inert command 记录、scratch marker、内存 loopback 或 fake data，不转发目标参数，也不把结果当作真实 sink/RCE 证据。生产环境必须由外部隔离层兜底。

payload writer 只输出构造计划和证据，不生成可直接投递的攻击字节流。任何面向具体框架的后续适配器都必须单独定义授权边界、输入约束和安全测试。

## 7. 当前验收基线

截至本轮收口：

- 最近一次完整 `mvn test` 通过，包含语义、契约、子进程边界、恶意工件边界和报告回归；`mvn package -DskipTests` 成功；
- 代表性回归工件和外部语义评测器均完成扫描；每个评测单元保留 TP/FP、跳过、超时、依赖缺失和平台能力原因，不把不可用环境折算为通过或失败；
- 安全动态结果统一使用 `SINK_BLOCKED/SAFE_EFFECT_OBSERVED/CONCRETE_REACHED/PARTIAL/TIMEOUT` 等状态；这些是安全边界或 inert adapter 证据，不代表真实 RCE；
- 每次扫描均生成 metadata、findings、evidence、对象图计划和 dynamic verification；所有完整性、依赖、字段链接、JDK 模块和预算问题保留为 `PARTIAL/TIMEOUT/UNTESTABLE` 等结构化状态；
- 默认动态 backend 只宣称实际启用的进程与 JVM 能力；Linux namespace/cgroup/seccomp 和 Windows restricted token/ACL/firewall 必须在具备相应权限的隔离 runner 中复验，不能以 JVM 权限门冒充 OS 沙箱；
- 静态性能按固定输入的历史同输入基线 `×1.5` 验收；默认 end-to-end 的动态子进程成本单独报告，不能用关闭验证掩盖静态分析回退；
- 负收益实验已撤回：容量、缓存和 sink 上限实验若不优于当前方案或破坏链集合等价，不进入默认路径；不执行真实危险 sink、命令、网络、任意写、native 或可投递 payload。

## 8. 发布检查清单

本轮 final3 已执行并留存证据；后续版本仍须重复以下清单：

1. `mvn test` 和 `mvn package -DskipTests`；
2. 检查 `git diff --check`，确认无临时文件、日志、构建目录、JDK 路径和本地 evaluator 输出；
3. 用目标 JDK 对代表性 JAR/WAR 做默认扫描，确认完整性、动态汇总和报告文件存在；
4. 运行完整外部语义评测器，逐项记录 TP/FP/跳过或截断原因；
5. 在具备真实 OS 隔离的容器/低权限/无网络环境执行不可信工件的安全化动态验证；当前 Windows 结果只宣称 Job Object + JVM policy；
6. 检查新增规则/知识源没有目标特判，更新本文件和用户可见契约。

## 9. 本轮优化验收要求

| ID | 要求 |
| --- | --- |
| NFR-12 | 前端并行资源按扫描会话复用；并行度变化只影响调度，不改变静态链集合、规则归因、链身份或排序 |
| NFR-13 | CPG/CFG 的紧凑表示必须保留调用、字段、控制流、异常、lambda、分发和完整性语义；所有删除的冗余结构有等价回归 |
| NFR-14 | 分析预算必须按 sink/阶段记录消耗和截断；`COMPLETE` 不得由单条链状态推导，扫描覆盖、链证明和动态能力必须独立输出 |
| NFR-15 | 动态验证必须 fail closed，结构化记录精确 JDK、sandbox/canary 能力、终止原因、子进程清理和 native 状态；不执行最终危险 sink |
| NFR-16 | 报告格式从同一规范化结果模型派生，支持大工件流式写出和稳定 schema；人读 Markdown 与 agent JSON 不得各自重新推导结论 |
| NFR-17 | 测试覆盖真实子进程边界、跨 JDK/平台、敌意 Jar、确定性、超时/OOM/输出溢出和性能退化；回归语料只作为外部校准，不进入生产特判 |
| NFR-18 | 固定静态扫描基线的性能目标为同输入历史基线的 `<=1.5x`；默认 end-to-end 动态成本必须单独报告，不能用关闭验证隐藏静态回退 |
| NFR-19 | 性能优化采用 source/sink 导向的需求驱动范围、方法/类型/字段/控制约束键控的有界缓存、稳定索引和可取消预算；不得因“命中测试样本”写入包名、类名、WP 或单条链特判 |
| NFR-20 | 性能验收必须记录固定输入/JDK/规则/参数、阶段 wall time、链/规则/完整性等价、动态状态、live heap 和可用时的外部 RSS；阶段回归先快速契约、后代表性回归工件与外部评测器，不以单次 wall time 或结束时 heap 关闭性能门 |

## 10. 本轮动态与图优化设计约束

| ID | 约束 |
| --- | --- |
| SEC-01 | 动态验证的可信终态必须来自 probe 的认证协议；目标 JAR 任意 stdout/stderr 文本、异常消息和普通退出码不能单独形成 `SINK_BLOCKED` 或 `CONCRETE_REACHED` 证据 |
| SEC-02 | 子 JVM 维持 fork-per-chain、最小环境、独立 cwd/tmp、资源上限、递归清理和 Java deny-by-default；`checkLink`/native load、网络、exec、任意写入和最终 sink 执行均拒绝 |
| SEC-03 | JDD 只迁移 bottom-up fragment、字段依赖和控制约束思想；它不被当作 OS 沙箱。没有可靠隔离能力时动态验证必须 fail closed |
| SEC-04 | 验证只证明真实路径到精确 sink 边界，canary 命中后不执行 sink body，不加载目标 native，不连接网络，不生成可直接投递 payload |
| PERF-01 | indexed CFG/CPG 的存储优化必须保持普通边、跳转、switch、异常、JSR/RET、lambda 和遍历顺序语义等价；删除临时对象前必须有 CFG/扫描回归 |
| PERF-02 | 任何 fragment summary、worklist、并行或缓存优化必须以方法/类型/字段/控制约束为键，不能按测试样本、WP、包名或具体类名特判；截断必须进入完整性状态 |
| PERF-03 | GPU 不进入默认依赖或默认路径；只有 profile 证明适合的同构内核、CPU 等价回归和资源自适应门控全部具备时，才允许作为可选实验后端 |
| PERF-04 | 性能结论必须同时记录阶段 wall time、报告时 live heap、外部 RSS 峰值（若有）和扫描完整性；不能用减少扫描深度、关闭验证或单次测量宣称最终提速；当前首轮样本仅用于开发门 |
| PERF-05 | 前向/后向分析优先从反序列化入口和有效 sink 反向交集构造需求范围；全图闭包只能作为有界 fallback，不能让无 sink 下游的普通效果反复展开 provenance |
| PERF-06 | 同一探索上下文内的候选路径、模型参数来源和返回摘要允许按语义键及 `factVersion` 做失效安全的 memoization；事实版本变化、截断或取消时不得复用旧结论 |
| PERF-07 | 备选 provenance 必须懒加载并只在 sink、状态性字段/返回消费等确需区分上下文的位置展开；primary summary 的快路径和有限 frontier 的准确性都要有等价回归 |
| PERF-08 | 性能回归以固定命令的中位/分位 wall time 和阶段分解验收；不能只看一次运行、线程数、报告条数或结束时 heap，也不能以 `--no-verify` 掩盖静态分析回退 |
| PERF-09 | 扫描级摘要缓存必须有明确容量和不可变输入边界；命中只复用同一方法/同一分析版本的完整摘要，超限可重新解释但不得改变结果，且必须记录命中/解释/淘汰指标 |
| PERF-10 | 反向 sink worker 可在同一扫描会话的多个 sink 间复用有界 immutable 方法摘要，禁止缓存中断/失败结果；容量、淘汰、命中和重解释必须可观察，且不得跨规则/JDK/图实例复用 |
| PERF-11 | 开发回归分为快速契约层和阶段全量层：代码变更先运行受影响单测/夹具，只有阶段门运行代表性回归工件与外部评测器；快速层不得替代阶段全量层，阶段全量层必须固定 JAR、JDK、规则、预算和参数 |
