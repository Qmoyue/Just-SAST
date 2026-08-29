# Just

Just 是一个面向 Java JAR/WAR 的轻量字节码分析器，专注于发现反序列化 gadget 利用链。
它把 ASM 前端、可解释的调用/控制流分析、规则驱动的知识源、链校准和安全动态验证组合成一个可直接运行的 CLI JAR。

Just 的输出目标是一条可审计的证据链：

```text
反序列化入口 → 触发机制 → gadget 片段 → 数据/字段流 → 危险 sink
```

它适合真实开源依赖审计、CTF 题目分析和研究型回归。它不是运行时防护产品，也不会默认生成或执行武器化 payload。

## 当前能力

| 能力 | 说明 |
| --- | --- |
| 输入 | JAR、WAR、class 目录；支持 Spring Boot `BOOT-INF`、WAR `WEB-INF` 和嵌套依赖 |
| 静态分析 | ASM 字节码事实、调用图、方法内 CFG、字段流、前/后向污点、反射、lambda、数组和继承回调 |
| 反序列化语义 | 原生 `ObjectInputStream`、`readObject`/`readObjectNoData`/`readExternal`/`readResolve`，以及 Kryo、Fastjson、Jackson、Hessian 系等替代框架入口 |
| 链语义 | 集合触发、动态代理、JavaBean setter、反射调用、模板/类加载、JNI/native 和 JRMP/RMI 能力边界 |
| 规则 | sink、source、magic-entry、model、chain-fragment 五类 YAML 规则；通过 ServiceLoader 扩展知识源 |
| 动态验证 | 每条候选链独立子 JVM、对象图构造、真实触发模式和 sink canary；确认时在危险 sink 方法体前停止 |
| 输出 | CSV、JSON、SARIF 2.1.0、HTML、Markdown，以及扫描完整性、动态汇总和安全 payload plan |

### 设计取舍

- **轻量交付**：单模块、单 CLI JAR，不依赖外部服务；运行时依赖为 ASM、picocli 和 SnakeYAML。
- **静态与动态分层**：静态分析负责覆盖和解释，动态验证只增加可观察证据，不会把验证失败当成静态否定。
- **规则即数据**：新增或调整攻击面优先修改 YAML；分析引擎只负责通用语义。
- **确定性**：任务键、路径代表和报告排序都有稳定全序；并行不会改变链身份或结果顺序。
- **目标 JDK 保真**：通过 `--jdk-home` 挂载与目标字节码匹配的 JDK，Java 8 使用 `rt.jar`，Java 9+ 使用 `jrt-fs`。
- **安全默认值**：动态验证只使用 canary 和默认输入，不发送网络请求、不加载 native 库、不执行命令，也不输出可直接使用的攻击字节流。

## 快速开始

### 构建

需要 JDK 17+ 和 Maven 3.6+：

```bash
mvn package -DskipTests
java -jar target/just-sast-0.2.0.jar --help
```

Windows + Jabba 示例：

```powershell
jabba ls
java -jar target/just-sast-0.2.0.jar scan `
  --jar path\to\app.jar `
  --jdk-home C:\Users\<user>\.jabba\jdk\<matching-jdk> `
  --output just-out
```

### 扫描

默认扫描会加载目标 JDK，并对高置信度候选执行有界动态验证：

```bash
java -jar target/just-sast-0.2.0.jar scan --jar app.jar
```

常用补充：

```bash
# 目标依赖不在工件内时补充 classpath
java -jar target/just-sast-0.2.0.jar scan \
  --jar app.jar --deps lib/a.jar,lib/b.jar

# 指定目标 JDK；生产审计建议显式指定
java -jar target/just-sast-0.2.0.jar scan \
  --jar app.jar --jdk-home /opt/jdk8 --stats

# 仅在受限环境或诊断时使用；可能降低完整性
java -jar target/just-sast-0.2.0.jar scan --jar app.jar --fast

# 关闭动态验证，只保留静态报告
java -jar target/just-sast-0.2.0.jar scan --jar app.jar --no-verify
```

`--fast` 和 `--no-verify` 都不是默认路径。前者跳过 JDK 全量加载，后者会失去动态证据；两者产生的报告都应结合完整性状态阅读。

输入支持：

- 普通 JAR、Spring Boot fat JAR、WAR；
- `BOOT-INF/classes`、`BOOT-INF/lib`、`WEB-INF/classes`、`WEB-INF/lib` 的嵌套内容；
- 已展开的 class 目录；
- `--deps` 指定的外部 JAR 或目录。

解析优先级为目标工件、显式依赖、目标 JDK。缺失类、解析失败、展开上限和分析预算会记录到完整性报告，而不是静默当作“没有漏洞”。

### 对比扫描

```bash
java -jar target/just-sast-0.2.0.jar diff old-output new-output
```

`diff` 以 `rule_id + 入口 + sink` 组成链身份，不依赖并行顺序或变体序号；它会报告新增、消失、变更和不变链。

## CLI 选项

| 选项 | 默认值 | 用途 |
| --- | --- | --- |
| `--jar <path>` | 必填 | JAR/WAR/class 目录 |
| `--deps <path,...>` | 无 | 补充依赖 classpath |
| `--jdk-home <dir>` | 当前运行时 JDK | 指定目标 JDK/JRE |
| `--output <dir>` | `just-out` | 输出目录 |
| `--rules <file>` | 内置规则 | 自定义 YAML 规则 |
| `--verify-budget <N>` | `20` | 动态验证候选数上限 |
| `--fast` | 关闭 | 跳过 JDK 全量加载 |
| `--no-verify` | 关闭 | 关闭子进程动态验证 |
| `--stats` | 关闭 | 将阶段统计写入 stderr |

退出码：`0` 成功，`2` 参数/输入错误，`3` 扫描内部错误。

## 分析管线

```text
JAR/WAR/classpath
       │
       ▼
JarReader → ASM frontend → Just model
                              │
                              ▼
             冻结的调用/层次/字段索引 + 按需 CFG
                              │
                              ▼
                     Blackboard 调度
              ┌───────────────┴───────────────┐
              │                               │
       ANALYSIS（并行）                 COMPOSITION
   backward / forward / OIS          object graph / fragments /
   framework bridge                  semantic composer
              └───────────────┬───────────────┘
                              ▼
                         CALIBRATION
                  validate / prune / safe-config /
                  patterns / dynamic verification
                              │
                              ▼
                   CSV / JSON / SARIF / HTML / MD
```

边界是单向的：ASM 只出现在 frontend；知识源通过 Blackboard 共享事实和事件；知识源之间不直接调用；规则描述攻击面，engine 实现通用推理。

静态层包含：

- 可见性约束和传递子类型分发；
- 反射目标解析、JavaBean 读写方法、动态代理 handler 和 lambda 实现；
- 方法内 CFG、异常边、数组元素、字段来源和 receiver 类型约束；
- `readObject` 家族、`resolveClass`/`resolveProxyClass`、框架反序列化 source；
- 入口距离调度、路径代表稳定化、预算截断和完整性原因。

分析结果不是“命中一个危险 API 就报警”。每条链都保留入口、sink、规则 ID、逐跳路径、字段流、未解析跳和校准原因。

## 动态验证与安全边界

动态验证是安全 canary 验证器，不是通用 exploit runner：

1. 从静态证据中选择有限候选，同一入口类最多两条；
2. 每条链 fork 独立 JVM，使用隔离工作目录/tmp、超时和内存限制；
3. 依据链上的字段流构造对象图，并使用 `HashMap`、`TreeSet`、`List.contains`、序列化往返或代理等对应触发模式；
4. 通过 Java agent 在精确 sink 入口插入 canary；命中后抛出门卫异常，危险 sink 方法体不继续执行；
5. 将每条链的状态、证据、尝试次数、失败原因和能力限制写入报告。

状态含义：

| 状态 | 含义 |
| --- | --- |
| `CONFIRMED` | canary 或带入口归因的精确 sink 栈帧命中 |
| `EXECUTED` | 入口被实际调用并返回，但没有 sink 命中证据 |
| `PARTIAL` | 对象构造或触发路径只完成了一部分 |
| `FAILED` | 验证进程失败；不能推翻静态候选 |
| `UNTESTABLE` | 缺类、JDK/权限/native/运行时能力等导致无法测试 |

JVM 权限门不是 OS 沙箱。扫描不可信 JAR 时，应额外使用容器或虚拟机、低权限账户、只读输入和无网络环境。JDK 24+ 不应依赖已移除的 Security Manager 提供进程隔离。Just 不会为了验证真实漏洞而执行命令、连接远端、加载 native 库或生成可直接武器化 payload。

## 输出契约

| 文件 | 内容 |
| --- | --- |
| `findings.csv` | 折叠后的主链，按验证状态和证据分数排序 |
| `chains.csv` | 未折叠的完整路径变体 |
| `edges.csv` | 每条链逐跳调用、字段流和桥接边 |
| `sinks.csv` | 每个 sink 的裁决、规则和截断原因 |
| `calibrations.csv` | 被校准拒绝或降级的候选及原因 |
| `findings.json` | 机器消费的链与证据数据 |
| `findings.sarif` | SARIF 2.1.0，可接入代码扫描平台 |
| `findings.html` / `findings.md` | 人工阅读和审查用报告 |
| `scan-metadata.json` | 输入、JDK、阶段统计、完整性和资源信息 |
| `dynamic-verification.json` | 动态能力、候选选择、每链状态和证据 |
| `payload-plan.json` | 不可直接执行的对象图/字段依赖/触发计划 |
| `dormant.md` | 可达但尚未形成完整链的入口信息 |

重要判读：`PARTIAL` 表示扫描或验证边界被触发，不表示“没有漏洞”；`EXECUTED` 不等于 sink 到达；只有 `CONFIRMED` 才表示安全 canary 观察到精确 sink。

## 规则与扩展

规则文件位于 `src/main/resources/rules/default-rules.yaml`。规则分五类：

- `sink`：危险调用点及其 tainted 参数；
- `magic-entry`：序列化回调和特殊入口；
- `source`：替代反序列化框架入口及安全配置；
- `model`：声明式参数、返回值和 receiver 传递；
- `chain-fragment`：可复用的公开链片段。

最小示例：

```yaml
rules:
  - id: EXAMPLE-EXEC
    kind: sink
    category: CODE_EXEC
    severity: HIGH
    match:
      call: {owner: "java/lang/Runtime", name: "exec"}
    tainted: [{arg: 0}]

  - id: EXAMPLE-MODEL
    kind: model
    match:
      call: {owner: "java/util/Map", name: "put"}
    actions: {this: [arg1]}
```

新增知识源实现 `KnowledgeSource`，声明 `phase`、`priority` 和 `interests`，再通过 ServiceLoader 注册。规则和知识源都必须使用通用语义，不得按题目名、JAR 名、包名、类名或 WP 文本增加分支。

## 当前验证状态

仓库当前回归基线：

- `mvn test`：143 项通过，0 失败，2 项环境跳过；
- Gleipner 全量：块级 `TP=219, FP=22`，入口去重 `TP=126, FP=17`；
- 默认全量 WP 语料：`demo`、`demo2`、`babychain`、`n1cat`、`qiao` 已有静态证据和安全动态确认；
- 当前 `javamix` 工件不含 WP 文档所述的 `InternalDataServiceImpl.processTask`，因此不伪造确认结果；
- 报告中的 `heap_used_mb` 是 JVM 报告时 live heap，不是 OS RSS 峰值，大型工件的内存优化仍需独立峰值采样验证。

Gleipner 本地基准和 CTF 语料属于开发者本地资产，不随仓库发布。Windows 上 native evaluator 缺失对应 `.eval.txt` 时，结果会如实标记为环境限制。

## 已知边界

- 静态分析在大型、强反射、深层对象图和复杂框架输入下会触发有界预算；报告会公开截断原因。
- 动态验证需要匹配的 JDK、依赖和可加载类；框架入口、JNI/JRMP、复杂代理可能只能得到 `PARTIAL` 或 `UNTESTABLE`。
- 安全 payload plan 只描述构造约束，不是 ysoserial 风格的可执行 payload 生成器。
- 生产部署必须提供 OS/容器级隔离；JVM 内权限门不能替代它。

## 开发

```bash
mvn test
mvn package -DskipTests
```

项目结构和模块边界见 [docs/architecture.md](docs/architecture.md)，需求、验收和安全边界见 [docs/requirements.md](docs/requirements.md)，协作约束见 [AGENTS.md](AGENTS.md)。

许可证为 GPLv3，见 [LICENSE](LICENSE)；第三方依赖见 [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)。
