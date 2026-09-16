# Just 产品要求

产品契约：JUST-LIGHT-MINING-V3。

本文定义可发布版本必须提供的用户能力、输出格式、静态安全边界和验收条件。它不把历史运行结果、旧动态验证或单纯的文件存在当成能力证明。

## 1. 用户和主流程

Just 服务于三类场景：

1. 审计 Apache 组件及其依赖中的反序列化 gadget 链。
2. 审计完整 Java 应用从真实入口到最终影响的应用暴露链。
3. 阅读 CTF JAR/WAR/class 目录及其 WP 对应的静态链。

唯一主流程是：

~~~text
scan → report.json / report.md → evidence/meta 按需追溯
~~~

report.json 面向 agent，必须是完整且可解析的机器入口；report.md 面向人，必须先显示结论、主链图、对象/控制条件和阻断点。不能要求用户先打开第三份索引或内部快照才能理解结果。

## 2. 输入和运行环境

- 主程序和构建使用 JDK 17；Maven 3.6 或更高版本。
- 输入支持普通 JAR、WAR、Spring Boot fat JAR、嵌套归档、多版本归档和 class 目录。
- 依赖可以来自制品内置内容、显式 --deps、显式 POM、完整本地缓存或准确的远程 Maven 补齐。
- --jdk-home 指定目标字节码/JDK 运行库来源。Java 8 使用 rt.jar，Java 9 及以上使用 JRT/JDK 布局。主程序 JDK 和目标 JDK 不混用。
- 不根据类名、最新版或替代包猜测依赖。不运行目标 Maven 生命周期、插件、extensions、应用或 helper。
- 每个实际制品记录坐标或逻辑名、版本、来源、SHA-256、大小和引入关系；依赖冲突、缺失、版本不确定和缓存损坏必须显式披露。
- 默认可联网补齐准确依赖；--offline 必须阻止网络请求，只使用显式输入和完整缓存。网络、解析、分析、报告和 total 计时分开记录。

## 3. 分析模式

| 模式 | 起点 | 必须证明 |
| --- | --- | --- |
| component（默认） | 机制触发点 → gadget → 最终影响 | 触发、对象关系、控制条件、依赖/JDK 条件和终点 |
| application | 真实应用入口 → site → 必要 bridge/依赖/JDK → 最终影响 | application ownership、entry/site、可控输入、EntryChainJoinEvidence、BridgeEvidence、对象/控制关系和完整 terminal |

两种模式共享字节码事实、类型/字段/控制传播、有限筛选、桥接和报告模型。component 候选没有应用入口也可以有效；component 候选不能伪称 application 漏洞。

危险 API 名称本身不是完整链。lookup、connect、构造器、解码、类定义和二次解析可能是中间 bridge；不能继续证明时必须保留断点和缺口。

## 4. 静态安全边界

Just 只读取输入制品和目标 JDK，并执行受限、有限、可解释的静态求值。它不得：

- 加载、初始化或构造目标类/目标对象；
- 反射调用目标方法或执行目标 callback；
- 反序列化攻击流、启动目标进程或访问目标 sink；
- 执行目标构建插件、外部 helper、native 代码或通用解释器；
- 生成 payload、投递字节流或输出 RCE_CONFIRMED。

该边界属于产品安全契约，但报告不再输出 target_code_executed 这类动态测试式字段。报告只标注分析类型为 STATIC_ONLY；详细安全说明放在本文和 CLI help 中。

## 5. 有界静态筛选

筛选只服务于高成本或高噪声位置，限于 Just 自有的字符串、算术、比较、分支和有限名称等操作。它必须在高扇出展开前或过程中运行，并保持输入值之间的相关性。

| 状态 | 语义 |
| --- | --- |
| PROVABLY_UNREACHABLE | 完整有限域矛盾证明；唯一允许剪枝 |
| PROVEN_RETAINED | 局部事实支持保留；不能单独证明完整链 |
| UNKNOWN | 信息不足；候选和证据保留 |
| BUDGET_EXCEEDED | 局部预算耗尽；候选和证据保留 |

每个筛选点记录操作类型、位置、理由、域/语义 digest、预算、评估数、保留数、拒绝数、展开数和自身耗时。内部错误必须失败，不能通过 catch-all、空集合或静默 fallback 变成 UNKNOWN。

## 6. 报告契约

### 6.1 文件布局

默认输出：

~~~text
out/
├─ report.json       # agent 唯一主入口
├─ report.md         # 人唯一主入口
├─ evidence/         # 静态逐跳、依赖、桥和可选格式
└─ meta/             # provenance、digest、诊断、run.json 和 transaction.json
~~~

不得默认创建空 findings/，不得生成重复的 index.md 主报告，不得生成 verification/、payload 或动态测试旁路。`meta/run.json` 是扫描元数据，`meta/transaction.json` 是事务状态；它们都是内部追溯文件，不是第三个报告入口。

### 6.2 JSON

report.json 必须：

- 来自一次冻结 snapshot，并与 report.md 使用同一 chain identity、计数、排序和证据；
- 保留所有去重候选、重要对象/控制/入口/终点变体，不能用 Markdown 显示上限裁剪；
- 提供 entry、site、callback、bridge、terminal、精确方法/descriptor/bytecode offset、对象关系、控制条件、依赖/JDK provenance、筛选证据和必要缺口；
- 将结果可用性、分析 coverage 和单链 completeness 分开；
- 对 UNKNOWN、预算、缺依赖、未解析端点和受限边界给出可机器消费的原因；
- 不包含动态执行结果、攻击字节流或 RCE_CONFIRMED。

建议的公开状态轴：

| 字段 | 值 |
| --- | --- |
| outcome | FINDINGS_AVAILABLE、NO_FINDINGS、FAILED、USAGE_ERROR、UNSUPPORTED、NOT_RUN |
| coverage | COMPLETE、BOUNDED、UNKNOWN |
| chain completeness | COMPLETE、PARTIAL、UNKNOWN |
| feasibility | SAT、UNSAT、UNKNOWN |

内部 RunOutcome.PARTIAL 可以继续支持 exit/cache；它只表达静态覆盖或证明边界，不表达动态测试。

### 6.3 Markdown

report.md 第一屏只保留：

1. 本次结果和可审阅链数量；
2. coverage 限制（若有）；
3. 第一条主链的 Gadget 图；
4. 入口/site、对象/控制条件、terminal 和阻断点；
5. report.json 和 evidence 的追溯位置。

长 ranking 解释、筛选 telemetry、完整 reason code、descriptor 表和低优先级候选放入折叠详情或 JSON/evidence。主链图使用稳定文本，不依赖图片服务：

~~~text
HTTP entry
    │
    ▼
DogController#importDogs
    │ deserialization
    ▼
ObjectInputStream#readObject
    │ callback
    ▼
Dog#hashCode → DogModel#wagTail
    │ reflection
    ▼
Method#invoke
    │
    ▼
TemplatesImpl#newTransformer
~~~

## 7. demo 验收口径

demo/demo2 必须以 WP 与实际 JAR 字节码交叉核对。demo.jar 的制品内最短主链是：

~~~text
DogController#importDogs
→ ObjectInputStream#readObject
→ Dog#hashCode
→ DogModel#wagTail
→ Method#invoke
→ TemplatesImpl#newTransformer
~~~

WP 外部恶意类中的 Runtime.getRuntime().exec 不在 demo.jar 内；另一个手工 payload 对象图的 invoke → Runtime.exec 也不能仅凭 demo.jar 自动证明。若扫描输入自身含有 java/lang/Runtime#exec 调用，Runtime sink 必须可发现；否则只能将制品外后续影响作为边界说明，不能伪造为制品内静态 terminal。

## 8. 质量门槛

- 八组固定 WP：demo、demo2、n1cat、babychain、babygadget、javamix、qiao、jdbc-master，主链 8/8。
- 逐案低误报 Q-01、固定负锚点、Apache 正负和 held-out 结果按冻结输入验收。
- 不能用类名 grep、CSV 行数、exit 0、少搜、少报或只显示预期链达标。
- 报告五问必须可回答：入口/site、对象/条件、终点/bridge、阻断位置、精确方法/位置。
- 任何历史 PASS 必须在受影响代码变化后重新验证；NOT_RUN 不能视为通过。

## 9. CLI

公开扫描接口：

~~~text
scan --jar <jar|war|class-dir>
     [--mode component|application]
     [--deps <jar|dir,...>] [--pom <pom.xml>]
     [--repository <url>] [--offline]
     [--jdk-home <path>] [--output <path>] [--rules <path>]
     [--overwrite]
~~~

stats、fast、baseline、suppressions 和 cache 只在有真实消费者、失败语义和回归测试时保留。参数错误、依赖/缓存失败、输出冲突和内部错误必须有明确退出状态。

知识源通过 ServiceLoader 装配。provider 枚举、实例化或版本/元数据校验失败必须使扫描失败；知识源已经启动后的单源错误才由 Controller 隔离并在 coverage/completeness 中披露。

## 10. 交付

发布包至少包含可运行 shaded JAR、SHA-256、LICENSE 和 THIRD-PARTY-NOTICES.md。发布前清理生成的 target、cache、tmp、staging 和本轮中间产物；从最终提交重建并核对 manifest、入口、哈希、许可和独立静态 smoke。只有同一提交通过远程 CI/Release 并得到 tag、Release URL、资产 hash 和下载回执才算发布完成。
