# Just 产品需求

契约：JUST-LIGHT-MINING-V3，2026-09-13。状态：按当前实现校准；完整语料、远程 CI 和发布仍必须以唯一执行清单中的实际证据关闭。本文定义产品行为，不替代验收证据。

## 1. 定位与交付

Just 是轻量、准确、快速的 Java 反序列化链分析工具，用于 Apache 开源组件与完整应用的辅助漏洞挖掘，以及 CTF JAR/WAR/class目录分析。帮助人和 agent 缩小阅读范围，定位应用入口、关键调用/字段关系、漏洞成立条件和最终影响。
正式运行环境为 Windows/JDK17，发布一个可直接运行的 launcher JAR；不要求用户安装 Maven、容器、外部solver或常驻服务。已有Linux能力可保留，不新增Linux发布门禁。
目标输入包括普通JAR、Boot fat JAR、WAR、class目录、显式依赖与所选JDK运行库。目标应用不需要启动。

## 2. 两种模式与准确性

| 模式 | 结果对象 | 成立要求 |
|---|---|---|
| component（默认） | 机制触发→gadget→最终影响 | 允许无应用入口，列出触发、对象构造、控制、依赖/版本/配置条件 |
| application（显式） | 应用入口→站点→依赖/JDK→最终影响 | 真实应用ownership、可控输入、逐段join/bridge、对象身份和完整终点后缀 |

两模式共享分析引擎与证据模型。组件存在gadget不能直接证明应用暴露；classpath共存、类名匹配和调用图共现不能代替值流/对象/控制连接。
覆盖原生反序列化及真实样本需要的Fastjson/Jackson、Kryo、Hessian、代理/反射、JNDI/RMI、JDBC/XML、二次解析等语义；不宣称所有框架版本均覆盖。
危险API可能是桥。lookup/connect/构造器/解码之后须继续到最终影响，无法连接则说明缺口。排名不能把UNKNOWN变为SAT，完整链不得隐藏关键未证明条件。
完整性、应用暴露、链进度、结构可行性和控制状态分别表达。输入不完整可保留独立完整链，但受缺失影响的链不能称完整。输出不等于已确认漏洞，不输出RCE_CONFIRMED或可投递攻击字节流。

## 3. 默认依赖补齐

默认从准确依赖声明取得缺失依赖，优先目标内置、显式输入和已有有效缓存。依赖图需处理父POM、属性、BOM/dependencyManagement、传递关系、scope、optional/exclusions、classifier/type及Maven版本仲裁。
内置依赖和shaded/relocated实际字节码优先，不能用下载版本静默覆盖。test/build-plugin不进入目标运行分析；provided、system和可选功能依赖不能被随意补入以证明实际应用漏洞。
无POM/坐标或版本不可确定时明确说明，不按类名搜索猜包、不换最新版兜底。版本范围/SNAPSHOT若不能确定和固定具体制品须明确不支持。
读取POM仅为数据解析，不运行目标Maven生命周期、插件、extensions或目标代码。默认使用固定Maven Central；其他仓库由用户显式配置，不自动使用不可信POM中的仓库地址，不隐式读取用户settings/凭据。
下载失败、缺包、解析歧义/冲突必须可见，报告依赖环境及受影响范围。POM推导的依赖不是实际部署证据，相关结果说明条件。
保存精确坐标、获选版本、来源、SHA256及仲裁原因，记录embedded/explicit/cache/remote来源；离线复用与依赖更新后的失效正确。缓存不接受半成品，SHA256表示身份，不单独证明来源可信。
输入参数目标：
```text
scan --jar <jar|war|class-dir>
     [--mode component|application]
     [--deps <jar|dir,...>] [--pom <pom.xml>]
     [--repository <url>] [--offline]
     [--jdk-home <path>] [--output <path>] [--rules <path>]
```
--repository允许重复；--offline禁止包括元数据解析在内的网络请求，只使用明确输入和缓存。预算/诊断等已有参数只在有实际用途且语义清楚时保留，help准确说明范围。
当前 CLI 已实现上述最简接口；`--stats`、`--fast`、`--baseline`、`--suppressions` 和 `--cache` 是有独立消费者的高级选项。`--cache` 与 baseline/suppressions 互斥，缓存异常直接失败。

主扫描接口不保留 no-verify、verify-budget、safe-exec、safe-real-sink 或
require-os-isolation。动态测试已经退役；静态筛选由分析阶段统一决定，不用一个旧 verifier
开关或独立验证预算切换。传入退役选项必须返回 usage exit 2，不得被忽略或映射为动态执行。

每次显式 jdk-home 测试和报告必须记录解析后的绝对路径、目标 Java 版本、java.exe 摘要、
JDK home/release 或实际运行库 digest；这只是目标字节码来源，不改变 Just 主程序的 JDK17。

## 4. 动态筛选与执行边界

所有扫描选项不执行目标代码：不把目标加入可执行classloader，不初始化/构造/调用目标类，不反序列化攻击流，不启动目标进程，不访问目标漏洞终点。
静态扫描在高成本或高噪声位置按需进行有限具体求值，用工具自身受限操作计算字符串、算术、比较、分支、有限反射名称等；优先在昂贵扩展前或过程中介入。
只对已知值或完整穷尽且保留值间关联的有限域证明矛盾，UNKNOWN/预算/不支持不能否定静态候选；一个成功输入也不证明全链成立。
已知操作异常必须尊重目标异常控制流，不能统一转换成false。工具内部错误直接暴露，不能catch-all后变UNKNOWN。
不建设通用JVM解释器、外部SMT或目标执行沙箱。当前使用进程内有界求值；移除旧verifier、verify8、payload、canary、Job Object/SecurityManager及无消费者原生依赖。
筛选决策是封闭的 typed evidence：PROVABLY_UNREACHABLE 只表示该局部路径有完整矛盾证明；
PROVEN_RETAINED 表示局部事实支持但不证明完整链；UNKNOWN 和 BUDGET_EXCEEDED 必须保留候选。
未知或预算不得被排名转换为 SAT，也不得作为静态拒绝理由。
每个热点记录筛选 kind、位置、reason、有限域/语义 digest、预算、评估数、保留数和拒绝数；
预算属于具体 proof/site，不以一次全局耗尽标记污染所有后续候选。筛选 evidence 进入统一报告，
不创建 verification 目录或第二套旁路 schema。
筛选应尽量在高扇出展开前介入；无法精确裁剪时使用延迟组合、语义去重或未解析端点保留相关性，
不能用少报候选冒充降噪。
选择性复用旧字段/类型/构造约束、预算/确定性/证据和测试职责；每个热点用固定输入/规则/JDK
做A/B，必须同时证明有效主链/重要变体保留以及筛选成本或审查负担收益，无收益不保留。
泛化验收保留未用于调优的制品首次结果，再按通用根因修复；不将样本名称、路径、摘要或答案写入规则和求解控制。
必要行为保护包括：完整相关域反证、非穷尽域保留、局部预算耗尽不影响其他热点、目标异常边、证据确定性、报告同源和目标不执行。旧动态测试按职责迁移，不能仅删除失败断言或用源码文本匹配代替行为测试。

## 5. 输出与耗时

默认主入口为同一规范快照生成的report.md和report.json，同时生成可追溯的 index.md、evidence/ 和 meta/ sidecar；日志写 stderr，stdout 只用于明确约定的机器输出，详细诊断显式开启。
Markdown按价值展示前10组代表链并列出其他候选概要；JSON保留去重有效候选、重要变体和共享证据，所有引用可解析。不同对象身份/触发/条件/终点不可被错误合并。
报告提供精确方法签名/字节码位置、逐跳依据、对象字段连接、类型/控制/构造/过滤/JDK条件、依赖来源、关键假设与未解决点。没有源码行号则不捏造。
展示限制、搜索预算、结果截断分别说明，不能静默少报或把片段计入完整链。默认不输出payload计划、verification目录或旧五格式。
公共契约只保留 concise report、finding output、rules、input digest 和 evidence-graph telemetry；动态验证披露、运行信任边界和 v1/v2 shadow schema 已退役。动态筛选的局部状态属于分析结果与统一报告的一部分，不再创建第二套验证报告或旁路 schema。
实现不得生成旧 verification/payload 文件、verification phase 或动态信任边界文案；它们不能写入 README、help、稳定缓存身份或下游消费契约。
计时分别记录依赖解析、网络下载墙钟、静态analysis、report、total；dynamicFilter是analysis子耗时。并发请求时间总和单列，不能与墙钟混用或重复相加。下载时间不得混入扫描性能。
首次有用结果以完整链可由消费者读取为准，不能用内存命中或旧缓存时间代替。

## 6. 验收标准

固定八组CTF/WP逐案准确输出完整原始主链、所有必要桥和对象/控制条件，8/8全部通过；全部冻结负锚点通过。Apache固定组件/应用正负例按实际版本/部署环境通过，相关Gleipner官方语义回归无未解释退步。
低误报验收Q-01：每案默认前min(10,N)高价值组的证据支持比例至少90%，UNKNOWN计入分母而不计支持，明确矛盾和伪完整为0；原始WP主链位于前10，N=0失败。
前列以外固定种子审查至多20组并要求同样至少90%支持；全部COMPLETE组做结构与证据完整性校验。抽样不能冒充全体精确率，必须列范围/分母/未知/误报；禁止通过隐藏结果或按答案调排名达标。
报告消费入口/站点、对象关系/条件、最终影响、阻断位置、精确方法五问必须5/5；agent自评明确标注，不捏造人工审计收益。
通常五分钟内有用是体验目标，组件/CTF优先低延迟；统一analysis预算按实测冻结，下载单列。冷1暖3记录各次值与中位数、RSS和首次有用结果，不凭小样本报告p95。
对每个优化同时衡量准确性、资源成本和审查负担，不能降低语义强度换速度。

## 7. 工程与发布

禁止兜底和防御性编程：不吞异常、静默默认/降级、无依据兼容或自动重试；内部不变量错误直接失败。外部输入校验、资源预算和声明的未知结果在唯一边界处理，不能用来掩盖内部bug。
ASM限于frontend；后续使用稳定不可变模型和artifact provenance，每层事实一个owner；规则是数据，求解与约束是通用语义，无样本名/hash/路径特判。
开发全程及最终全面使用ai-slop-taste和test-doctor，围绕真实用户流程控制复杂度和测试成本；不为删行数重写稳定代码，不为测试镜像实现。
开发前写需求/架构，过程中同步真实变化，最后按验收行为修订需求/架构/README。验证通过的批次本地commit，日常不push。
最终全部本地任务通过后，Release workflow 以手动指定的已验证 branch/commit 为输入，在 JDK17 上重跑测试、打包、两模式 online/offline smoke、版本/tag 冲突和 checksum/许可检查；全部通过后由同一 job 创建唯一 `v<version>` tag 并发布 shaded launcher、SHA256SUMS、LICENSE 和第三方说明。构建只读权限，发布最小权限，失败阻断发布；必须核对真实远程回执和资产，不能以 workflow 存在或 RELEASE_READY 冒充已发布。
