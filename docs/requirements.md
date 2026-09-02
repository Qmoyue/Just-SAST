# Just 需求与验收

版本：2026-09-03。本文件是脱敏的用户可见契约，不包含本地路径、benchmark 名称、题目、WP、flag 或机器信息。

## 1. 产品目标与非目标

Just 是单 JAR、轻量、快速的 Java 反序列化 gadget 链扫描器。它对 JAR/WAR/class 目录做字节码静态分析，优先产出具有入口、字段/receiver 控制、精确 sink 和校准证据的高价值候选；动态部分默认使用 canary，显式 SAFE_REAL 才在 OS_STRICT 中执行经过固定化的真实 target sink/body。

Just 不承担运行时防护、任意应用 fuzz、未授权真实 RCE、可直接投递的攻击 payload 或仅凭外部 CVE 数据库下漏洞结论。CVE/依赖数据库属于可选外部产品集成，不是 gadget 发现和安全化 sink 验证的前置条件。

## 2. 功能需求

### 2.1 输入、JDK 与前端

| ID | 需求 |
| --- | --- |
| FR-01 | 接受 JAR、WAR 和 class 目录，并支持显式依赖。 |
| FR-02 | 解析普通工件、fat JAR、WAR 和嵌套 JAR；递归深度、条目数、物理大小、解压大小、压缩比和单 class 大小有界。 |
| FR-03 | ASM 只在 frontend 使用，输出稳定的 Just facts：类、方法、字段、访问标志、调用、指令、异常表、lambda、方法句柄和行号。 |
| FR-04 | 按目标 classfile major 选择兼容 JDK source：Java 8 使用 `rt.jar`，Java 9+ 使用 `jrt-fs`/模块源；支持显式目标 JDK。 |
| FR-05 | 缺失类、损坏字节码、JDK/模块不可读和嵌套工件失败必须进入诊断和完整性状态，不能伪造空实现。 |
| FR-06 | 输入、规则、依赖和目标 JDK 的语义 identity 可复现；不把本地绝对路径写进可移植结果。 |

### 2.2 CPG、CFG、控制流与污点

| ID | 需求 |
| --- | --- |
| FR-07 | 建立冻结的调用、字段、类型、分发、lambda 和方法索引；CFG/异常边/def-use 按需求展开并复用。 |
| FR-08 | 保留 fall-through、switch、异常、JSR/RET、lambda 和方法句柄语义；压缩表示不得删除可影响路径的关系。 |
| FR-09 | 支持可见性、接口、传递子类型、CHA/dispatch、receiver、数组、字段、返回值和调用点约束。 |
| FR-10 | 支持 forward method summary 不动点和 backward sink-directed trace；预算、路径、实现者、证明和对象图展开有界。 |
| FR-11 | 截断必须报告为 `PARTIAL`/完整性原因；缓存不能跨不兼容 fact version、规则、JDK、context 或截断状态复用。 |
| FR-12 | 相同输入/规则/JDK/预算下，串行、并行和重复运行的链 identity、规则归因、reason、证据和排序一致。 |

### 2.3 反序列化与框架语义

| ID | 需求 |
| --- | --- |
| FR-13 | 覆盖 `ObjectInputStream` 及 `readObject`、`readObjectNoData`、`readExternal`、`readResolve`、`resolveClass`、`resolveProxyClass`、`readUnshared` 和继承回调。 |
| FR-14 | 通过 YAML source 规则支持替代反序列化框架；安全配置只在调用点实参和类型证据满足时应用。 |
| FR-15 | 支持集合触发、字段依赖、JavaBean setter、动态代理 handler、反射 Method/Constructor、模板/类加载、JNI/native 和 JRMP/RMI 边界。 |
| FR-16 | 反射、Proxy、CHA 和框架桥接优先使用精确 receiver/type/name/descriptor；未知目标不得 wildcard 为任意调用。 |
| FR-17 | `KnowledgeSource` 通过 phase/priority/interests 和 ServiceLoader 扩展；知识源不直接调用其它知识源，规则不按样本特判。 |

### 2.4 动态验证与真实安全 sink

| ID | 需求 |
| --- | --- |
| FR-18 | 默认动态验证使用 fork-per-chain 子 JVM、真实入口/前置链/对象图/触发模式和精确 sink canary；`--no-verify` 显式关闭。 |
| FR-19 | `SINK_BLOCKED` 只表示认证的精确 canary 边界命中，目标 sink body 未进入；它不是 body/RCE 证据。 |
| FR-20 | `SAFE_REAL` 必须显式开启并同时要求 OS_STRICT；它必须调用精确 target API/body，而不是调用 Just adapter 冒充 target。 |
| FR-21 | SAFE_REAL 只接受有明确 owner/name/JVM descriptor 策略的 sink。String/primitive 参数、合法 receiver、数组/对象和返回值类型必须按策略处理；未知 overload/对象/数组 fail closed。 |
| FR-22 | command 只允许 verifier-owned JDK `-version`；file 只允许 child scratch；network 只允许明确 loopback 且有 runner policy；reflection 只允许固定 String/noop/safe constructor；远端命名、脚本、模板、任意类加载和任意 native 不进入真实模式。 |
| FR-23 | application body 的正向证据必须有 `body=1` 和 `body_returned=1`；精确 API 必须有 `attempted=1`、`call=1`（成功 afterCall）；beforeCall/request 不能单独升级。 |
| FR-24 | target body 内再次执行 command/file/network/reflection/class-loading/native 等危险能力必须在调用或 `NEW` 前阻断并记录；构造器改写必须通过 JVM verifier。 |
| FR-25 | `SINK_EXECUTED_SAFE` 表示真实 API/body 在固定参数下成功，不表示原始 target 参数、原始副作用或 exploitability；结果必须 `sink_distorted=true`。 |

### 2.5 JNI 与 native 证据

| ID | 需求 |
| --- | --- |
| FR-26 | SAFE_REAL 不从 target JAR 提取或加载 native；只 materialize Just 自有、固定 SHA-256、大小/格式/架构已校验的 fixture。 |
| FR-27 | `System.load/loadLibrary` 只能映射到 child scratch 内 verifier-owned absolute path；JAR URI、target basename、外部同名库、reparse/link 和路径穿越拒绝。 |
| FR-28 | native index 按候选涉及的 owner/name/descriptor 有界延迟扫描；caller 与 native owner 分离时仍能精确插桩，未知 callback 不升格。 |
| FR-29 | `JNI_EXECUTED_SAFE` 必须同时具有 load success、native method normal return、Java callback/调用事件、attempt identity 和 fixture digest；只 load request 不算成功。 |
| FR-30 | 每个支持的平台/JDK 都必须有正/负 native fixture；没有对应平台实机证据时状态只能为 `UNTESTABLE`。 |

### 2.6 OS 隔离与 JDK 矩阵

| ID | 需求 |
| --- | --- |
| FR-31 | Linux strict 需要固定 root image/digest、nsjail、user/mount/pid/net/ipc/uts namespace、cgroup v2、seccomp、NoNewPrivs、Landlock、只读输入、scratch 和 parent-death；缺一项不得标 strict。 |
| FR-32 | Linux child ready 前实证 uid、namespace、NoNewPrivs、seccomp、cgroup、Landlock 和文件/网络 policy；必须有 host read/write、非 loopback、设备/fd、fork、超时和父死负向测试。 |
| FR-33 | Windows strict 需要 target 创建前 AppContainer profile/SID、zero capability、Low IL、restricted handle list、Job Object、package-SID ACL allowlist 和无 network capability；Job/SM/property 单独不算 strict。 |
| FR-34 | Windows child 通过 Win32 token 查询实证 AppContainer + Low IL；ACL 拒绝 reparse/link escape，目录权限正确继承，失败恢复原 ACL；外部 runner 需验证用户目录/registry/device/pipe/host handle/子进程/资源负向。 |
| FR-35 | JDK 8/11/17/21/24+ 与 Windows/Linux 矩阵必须分别记录启动、classfile/module、reflection、Proxy/lambda、JNI/JRMP/缺依赖和动态状态；JDK 24+ 不能依赖 Security Manager。 |
| FR-36 | 缺少 strict runner、root、profile service、权限、JDK 或 native ABI 时返回 `UNTESTABLE` 和原因，不自动降级为“已验证”。 |

### 2.7 置信度、报告与产品能力

| ID | 需求 |
| --- | --- |
| FR-37 | 置信度至少区分静态可行性、扫描完整性、canary boundary、safe adapter、safe-real body/API、safe JNI、入口返回和不可测状态。 |
| FR-38 | 高置信度排序必须以完整静态链、精确 sink、完整动态 evidence tuple、适用 OS_STRICT、无关键 unknown/partial 和稳定 identity 为条件；safe-real 仍不等于真实利用。 |
| FR-39 | 输出包含 findings、全路径 edges/chains、calibration、dynamic verification、payload plan、metadata、dependencies、baseline/diff，并由一个规范化结果模型渲染。 |
| FR-40 | `payload` 只输出对象图/字段/触发/证据计划，不输出可直接执行或投递的攻击字节流。 |
| FR-41 | `--cache`、baseline/suppression 和依赖清单按 artifact/dependency/rules/JDK/engine/parameters identity 工作；失败/partial/timeout/不完整动态结果不能写成功缓存。 |
| FR-42 | 依赖清单可输出 SPDX/CycloneDX 兼容坐标、版本、hash 和 nested 关系；没有外部漏洞数据库时不生成 CVE 结论。 |
| FR-43 | 退出码、日志 stderr、临时文件清理、结果 schema 和单 JAR 交付可复现；发布签名只在显式密钥配置下报告成功。 |

严格能力前置失败时，逐链动态结果还必须保留选定 backend、policy digest、运行时选择和“未启动”清理状态；这保证 `UNTESTABLE` 的原因和边界可复核，不产生 `UNKNOWN` 证据字段。

## 3. 非功能需求

| ID | 需求 |
| --- | --- |
| NFR-01 | 默认核心交付为单 JAR，不依赖网络服务；可选平台 runner/ JNA 缺失时能力显式可见。 |
| NFR-02 | 大工件使用流式读取、冻结索引、按需 CFG/CPG、共享摘要和有界 cache；不保留不必要的原始 class bytes。 |
| NFR-03 | 记录 frontend、CPG/CFG、hierarchy、forward、backward、composition、calibration、verify 及 runner 分段耗时；live heap 不冒充 RSS 峰值。 |
| NFR-04 | 性能优化不得减少规则、扫描深度、链覆盖、动态能力、完整性或确定性；禁止以 `--no-verify` 掩盖静态回退。 |
| NFR-05 | 固定输入/JDK/规则/预算/参数的静态 wall p50/p95 目标不超过历史基线的 1.5x；动态 startup/class-load/native/queue/cleanup 单独给出 p50/p95。 |
| NFR-06 | 并行度有界、自适应，worker/cache 会话内复用；serial/parallel/repeat 的链集合、reason、排序、digest 完全一致。 |
| NFR-07 | 任何 cache 必须有不可变 identity、容量、失效、命中/淘汰指标；失败、取消、timeout、partial 不缓存。 |
| NFR-08 | 默认动态不自动重试 timeout；显式重试必须计入总预算并记录 attempt/cost。 |
| NFR-09 | 测试优先保护用户契约、安全边界、恶意工件、跨 JDK/平台、超时/OOM/输出上限、确定性和性能门，不绑定偶然内部实现。 |
| NFR-10 | 编程保持直接、低耦合、高内聚；不以大量 catch-and-continue、防御性 fallback、全局状态或复制状态机掩盖设计缺口。 |

## 4. 验收矩阵

| 层级 | 必须通过 |
| --- | --- |
| 快速契约 | sanitizer 类型/descriptor、body/API return、nested block、JNI digest/load/callback、协议伪造、恶意工件和状态映射 |
| 项目回归 | `mvn test`、单 JAR package、报告 schema、静态链集合和既有语义回归 |
| 平台回归 | Linux nsjail/root/seccomp/cgroup/Landlock 和 Windows AppContainer/token/ACL/Job 的真实正负测试；不具备条件则 `UNTESTABLE` |
| JDK 回归 | 8/11/17/21/24+ 的启动、classfile/module、反射、Proxy/lambda、JNI/JRMP 和缺依赖结果 |
| 语料回归 | 只按原始 evaluator/truth/WP/脚本评测外部语料；不修改输入、不删失败、不写特判 |
| 性能回归 | 固定 runner 的阶段 wall p50/p95、live heap、可用 RSS、链/状态/canonical digest 等价 |
| 发布回归 | 清理中间产物，源码/规则/文档脱敏，单 JAR 可复现；TODO、根因记录、benchmark 输出和本地路径不提交 |

## 5. 动态结果解释

`SINK_BLOCKED` 是最强的默认 canary 边界证据；`SINK_EXECUTED_SAFE` 和 `JNI_EXECUTED_SAFE` 是在固定输入、失真参数和 strict 隔离下的安全可调用性证据；`SAFE_EFFECT_OBSERVED` 只属于 Just adapter；`CONCRETE_REACHED`/`EXECUTED` 只说明前缀/入口运行。任何一种状态都不能单独推出真实 RCE。`PARTIAL`、`TIMEOUT` 和 `UNTESTABLE` 必须与静态 findings 共存。

## 6. 研究和实现取舍

JDD/IOCD 用于 bottom-up fragment、字段依赖和对象构造；GCMiner/GadgetBuilder 用于结构化 gadget、trampoline 和 source/sink 分层；FLASH/GadgetHunter 用于 controllability、CHA/points-to 和约束精度；演化语料与动态校准研究用于回归设计；nsjail/Landlock/AppContainer 用于 OS 边界。它们的研究结论不能直接替代 Just 的平台实证，也不能授权执行真实危险 sink。
