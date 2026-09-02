# Just 架构设计

版本：2026-09-03。本文是脱敏的稳定架构契约，面向贡献者和结果审查者。它不包含本地路径、benchmark 名称、题目、WP、flag 或一次性机器数据。

## 1. 产品边界

Just 是面向 Java JAR/WAR/class 目录的轻量字节码 SAST，重点是反序列化入口到 gadget/sink 的可解释链。它以 ASM 解析字节码和 CFG，以 Blackboard 协调知识源，以统一结果模型生成报告，并把静态候选和动态证据严格分层。

产品交付是单 CLI JAR。它不是运行时防护器，也不生成可直接投递的攻击 payload；`SAFE_REAL` 只在显式授权、严格 OS runner 和固定安全参数下执行精确 target sink/body 的可调用性确认。它永远不把该确认写成真实 RCE。

核心不变量：

1. ASM 只存在 frontend；knowledge、blackboard、verify 和 report 只消费 Just 自有事实模型。
2. 规则描述攻击面，知识源实现通用语义；禁止按样本、包名、类名、WP 或 flag 加分支。
3. 静态候选、扫描完整性、链校准、动态能力和动态状态是独立维度；动态失败不能静默删除静态链。
4. 并行只改变调度，不改变链 identity、规则归因、reason、证据 tuple 和排序。
5. target stdout/stderr、属性、环境和普通退出码不具备证据权限；正向动态证据来自绑定 attempt 的 probe 协议/结果文件。

## 2. 分层与数据流

```text
JAR/WAR/class 目录 + 显式依赖 + 目标 JDK
                    │
                    ▼
      frontend.asm：流式读取、ASM、嵌套工件、JDK source
                    │ immutable bytecode facts
                    ▼
       model / CPG index / lazy CFG / hierarchy / summaries
                    │
                    ▼
                 Blackboard
          ┌─────────┴─────────┐
          │                   │
       ANALYSIS          COMPOSITION
  forward/backward       sources / fields /
  taint / dispatch      fragments / object graph
          └─────────┬─────────┘
                    ▼
                CALIBRATION
        type / PASM / serialization /
        receiver / catch / constraints
                    │
                    ▼
     VerifyKnowledgeSource → ParallelVerifier
                    │
      OS runner → child probe → bytecode agent
                    │             │
                    │       canary or REAL_SANITIZED gate
                    ▼             ▼
              authenticated dynamic result
                    │
                    ▼
      one normalized result model → all report formats
```

依赖方向是 `frontend → model/CPG → blackboard/knowledge → calibration → verify/report`。report 不反向修改分析事实；verify 不替代静态推理。

## 3. 模块 ownership

| 模块 | 唯一职责 | 明确不拥有 |
| --- | --- | --- |
| `frontend.asm` | 读取工件、ASM、CFG 原始事实、嵌套 JAR/WAR 和 JDK source | 污点结论、链排序、报告格式 |
| `model` | 保存类/方法/字段/调用/指令等不可变事实 | 运行时策略、全局可变缓存 |
| `cpg` / `analysis` | 调用/字段/类型/CFG/来源索引和需求驱动求解 | sink 执行、最终报告 |
| `blackboard` | 阶段、事件、事实和确定性 delta 合并；统一链 identity owner | 某个攻击面的私有实现 |
| `knowledge` | 通过 `KnowledgeSource` 提供 source/sink/回调/组合/校准语义 | 直接调用另一个知识源 |
| `verify` | 候选选择、独立 child、OS runner、事件认证和安全化 real sink | exploit、任意 native 或无限制 payload |
| `report` | 将规范化结果投影为 CSV/JSON/SARIF/HTML/Markdown/metadata | 重新推导链或自行改变置信度 |

知识源通过 `phase()`、`priority()`、`interests()` 和 ServiceLoader 扩展；同阶段按声明的优先级和屏障运行，禁止知识源之间形成直接依赖。

## 4. Frontend、CPG 和静态分析

`JarReader` 以流式方式读取普通 JAR、fat JAR、WAR 和嵌套工件。深度、条目数量、物理大小、解压大小、压缩比、符号链接/reparse point 和 classfile 大小都有界；失败进入完整性原因，不伪造空方法体。

`JdkClassSelector` 按 classfile major 选择目标 JDK：Java 8 使用兼容的 `rt.jar`，Java 9+ 使用 `jrt-fs` 模块源。缺失依赖、模块不可读和 JDK 不兼容会产生 `PARTIAL/UNTESTABLE` 等结构化结果。

Just 使用“语义核心图 + 按需关系”的混合 CPG：核心保存 METHOD/CALL、调用/分发/lambda、字段写入和层次索引；CFG、异常边、def-use、receiver、数组和 provenance 仅在 sink/入口需求范围内展开并复用。这样保留字节码 CPG 的调用、控制流、字段和数据关系，同时避免把每条指令和每个抽象状态都物化成重型对象。

静态语义包括：

- 原生 OIS 的 `readObject`、`readObjectNoData`、`readExternal`、`readResolve`、`resolveClass`、`resolveProxyClass`、`readUnshared` 和继承回调；替代框架由 YAML source 规则桥接。
- forward summary 与 backward sink-directed tracing；字段、返回值、receiver、数组元素、调用点和集合触发保持关系。
- CHA/接口/可见性/传递子类型、lambda、异常边、JSR/RET、反射 Method/Constructor、Proxy、模板/类加载、JNI/native 和 JRMP/RMI 边界。
- 反射、代理和框架桥接优先使用精确 class/name/descriptor/receiver；未知目标保留不确定性，不 wildcard 成任意调用。
- 每条链保留 `rule_id`、entry、sink、hop、机制、字段依赖、校准结果和完整性原因。

所有实现者展开、路径、方法、证明和对象图工作都受预算控制。预算触顶是可审计的截断，不是成功或无漏洞。

## 5. 动态验证与真实 sink

### 5.1 两种模式

`BOUNDARY` 是默认模式：fork-per-chain child 构造有限前置链，Java agent 在精确 owner/name/descriptor 的 sink boundary 注入 canary；canary 在危险 body 前停止。它证明“边界可达”，不执行 sink body。

`SAFE_REAL` 是显式模式：必须同时要求 `--require-os-isolation`，且 parent 选择并认证 `OS_STRICT`。target class 通过独立 application loader 加载；agent 的 `REAL_SANITIZED` gate 只允许当前 attempt 的 exact entry/sink，先固定所有类型参数和合法 receiver，再调用真实 target API/body。成功事件写为 `sink_distorted=true`，因为输入已被安全化。

### 5.2 可执行的安全化 sink 家族

| 家族 | 真实调用 | 固定约束 | 证明 |
| --- | --- | --- | --- |
| command | `Runtime.exec` / `ProcessBuilder.start` | 仅 verifier-owned JDK `-version`；target command、env、cwd 不保留 | API before/after，进程由 runner 清理 |
| file | `Files.newOutputStream`、有限文件构造器 | path/file 固定到 child scratch，选项固定；不接受 target path | API 正常返回和 scratch 边界 |
| network | 有限 URL/Socket API | 只接受显式 loopback 形态；无 loopback policy 则不可测 | API 正常返回；不表示外网能力 |
| reflection | `Class`、`Method`、`Constructor` 的有限 overload | 固定 `String.class`、bootstrap loader、Just-owned noop/safe constructor、空 args | 精确 API 正常返回 |
| application body | 非平台类 exact method | 只允许 String/primitive 参数和 scalar return；固定 typed 值；数组/任意对象拒绝 | `body=1` 且 `body_returned=1` |
| native | `System.load/loadLibrary` | 只映射 Just 自有固定 digest fixture 到 scratch；不加载 target native | load success + native callback + digest |

未列入表中的 JNDI/RMI/JRMP、脚本、模板、任意类加载、任意 MethodHandle、数据库写入和未知 native 保持 canary 或 `UNTESTABLE`。真实 body 内部再次触达命令、文件、网络、反射、类加载、native 等危险调用时，agent 在调用/`NEW` 前抛出不可忽略的 gate error，并记录 `nested_blocked`。

### 5.3 证据状态

| 状态 | 证据语义 |
| --- | --- |
| `SINK_BLOCKED` | 认证的精确 canary 边界命中，target body 未进入 |
| `SINK_EXECUTED_SAFE` | target API 成功返回或 exact body 正常返回；固定参数，失真，非 RCE |
| `JNI_EXECUTED_SAFE` | 固定 fixture load、native 正常返回、Java 事件和 digest 全部存在 |
| `SAFE_EFFECT_OBSERVED` | Just-owned adapter effect，target body 未运行 |
| `CONCRETE_REACHED` | 具体安全前缀到达但没有 exact sink 证据 |
| `EXECUTED` | entry 正常返回但没有 sink 证据 |
| `PARTIAL`/`TIMEOUT`/`UNTESTABLE` | 构造、依赖、权限、资源或平台能力不足，静态候选仍保留 |

`beforeCall`/load request/普通退出码不能单独形成正向状态。parent 要验证 terminal 的字段、身份、事件顺序和策略绑定；不完整的 authenticated frame 也必须降为 `UNTESTABLE`。

严格能力前置失败时，验证器在加载 target classpath 或构造对象图之前直接生成有界的 `UNTESTABLE` 结果；每条结果仍携带选定 backend、policy digest、运行时选择和 `NOT_STARTED` 清理状态。这样“没有执行”本身可审计，也不会把 preflight 的 `UNKNOWN` 元数据误读成真实动态证据。

## 6. OS 隔离

### Linux

严格后端要求部署提供固定 digest 的 root image、nsjail、seccomp profile、user/mount/pid/net/ipc/uts namespace、uid/no_new_privs、cgroup v2、只读 runtime/classpath、scratch、Landlock 和 parent-death。缺任一生产前置能力时返回 `UNTESTABLE`，不能用 bubblewrap、Java 权限或属性冒充 strict。child 在 ready 前检查内核可观察状态；外部 runner 还必须做 host read/write、非 loopback、device/fd、fork、父死和超时负向测试。

### Windows

严格后端在 target 创建前建立唯一 AppContainer profile/SID，通过 `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` 使用零 capability 和低完整性 token，受限句柄清单创建 target，并由 Job Object 负责进程树和资源。包 SID 只获得显式的 classpath read/execute 或 per-run scratch write ACL；目录继承，reparse/link 和 access-tree 上限 fail closed，异常路径恢复原 ACL。child 通过 Win32 token 查询实证 AppContainer + Low IL，不能相信 property/环境自报。

AppContainer 的 restricted-token/default-deny 语义和 package-SID allowlist是 Windows 主边界；单独 restricted token 或 Job Object 不构成生产 strict，也不能替代无 network capability 和 filesystem policy。loopback 若平台没有独立、可认证的放行策略则保持不可测。

JDK 8–23 的 SecurityManager 只是第二道 Java 层限制；JDK 24+ 只能在已认证 OS_STRICT 下进入 SAFE_REAL。

## 7. 置信度、排序与报告

静态可行性、扫描完整性、动态状态和 exploitability 是独立字段。高置信度候选至少需要：完整或可解释的静态事实、精确 entry/sink/descriptor、无未解析 receiver/依赖关键缺口、构造/序列化/触发校准通过、认证动态证据和完整的 evidence tuple。`SINK_EXECUTED_SAFE/JNI_EXECUTED_SAFE` 只能进入“安全可调用性”维度；`sink_distorted=true` 阻止其被解释为真实利用或 RCE。

所有输出格式从同一规范化结果模型派生：主链 findings、全路径 evidence、dynamic verification、calibration、dependency inventory、payload plan、metadata、baseline/diff。payload 文件只有对象图/字段/触发计划和证据，不是攻击字节流。

链 identity 由规则、entry、sink、hop/机制和规范化约束组成；并行完成顺序、变体编号和失败顺序不参与 identity。reason 集合、状态归一化和 canonical sort 只有一个 owner。

## 8. 性能原则

速率是和准确率、安全性同等的发布指标：

1. frontend/CPG/CFG/hierarchy/forward/backward/composition/calibration/verify 分段计时；动态 runner startup、class load、native materialization、queue、cleanup 单独计时。
2. source/sink 导向的 demand-driven workset 优先；无 sink 的普通下游不反复展开。SAFE_REAL 只对稳定选择的候选执行。
3. agent 使用 cheap prefilter 和单次 ASM parse；不逐条重写 JDK/Just bootstrap。native index 只检查候选涉及的 owner，容量有界且不缓存失败。
4. cache 必须以不可变 artifact/rules/JDK/engine/参数和语义 context 为键，有界、可失效、可观察；失败、取消、timeout、partial 不进入成功缓存。
5. 固定输入和配置的静态 wall 目标不超过历史基线 `1.5x`；动态额外成本单独公布，不能用 `--no-verify` 掩盖静态回退。p50/p95 同时审查 live heap 和可用 RSS。
6. serial/parallel/repeat 的链集合、reason、状态、payload plan、digest 和排序必须相同；性能优化不能通过减少规则、深度、覆盖或完整性来换取。

严格 runner 不可用时的探测成本单独计入 dynamic/runner 阶段。Windows capability probe 的超时路径必须终止 broker、避免阻塞读取遗留管道，并允许可信 API 预热与静态分析重叠；预热不能直接授予 `OS_STRICT` 能力。

全局无界 cache、全 JDK 预热、GPU 默认依赖、按 benchmark 调阈值和机械复制 fallback 均不属于默认架构。

## 9. 扩展和验证

新增攻击面优先修改 `src/main/resources/rules/default-rules.yaml`；新增语义实现 `KnowledgeSource` 并通过 ServiceLoader 注册。知识源不能直接互调，规则不能编码样本。

开发验证顺序是受影响的快速契约、`mvn test`、`mvn package -DskipTests`、抽象真实 sink/JNI fixture、外部语料和原始 evaluator。跨平台/JDK 只有在对应 runner 实际创建、attest 和通过负向测试时才记为通过；否则报告 `UNTESTABLE`，不折算为成功。
