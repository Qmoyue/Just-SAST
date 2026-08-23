# Just

轻量字节码 SAST，挖掘 Java 反序列化 gadget 利用链。

覆盖原生 ObjectInputStream 与 12 种替代框架（Kryo / SnakeYAML / XStream / Hessian / Fastjson / Gson / Jackson / BlazeDS AMF / Burlap / Castor / JsonIO / JYAML）。

## 安装

```bash
mvn package -DskipTests
```

构建产物：`target/just-sast-0.2.0.jar`（约 1.2 MB，含全部依赖，可直接 `java -jar` 运行）。

target/ 下另有两个同名系列文件，无需关心：`original-*.jar` 是 shade 前的纯净包备份（仅项目自身类）；`*-shaded.jar` 是 shade 插件写出 fat JAR 时的中间副本（与主产物逐字节相同）。

环境要求：JDK 17+，Maven 3.6+。

## 使用

### 扫描

```bash
# 基本扫描
java -jar target/just-sast-0.2.0.jar scan --jar app.jar

# 指定输出目录
java -jar target/just-sast-0.2.0.jar scan --jar app.jar --output my-results

# 附加依赖 jar（classpath 不完整时补充）
java -jar target/just-sast-0.2.0.jar scan --jar app.jar --deps lib1.jar,lib2.jar

# 指定目标 JDK 版本（推荐——避免用运行时 JDK 产生假阳）
java -jar target/just-sast-0.2.0.jar scan --jar app.jar --jdk-home /path/to/jdk8

# 快速模式（跳过 JDK 全量加载，链可能不完整但速度更快）
java -jar target/just-sast-0.2.0.jar scan --jar app.jar --fast

# 输出扫描统计
java -jar target/just-sast-0.2.0.jar scan --jar app.jar --stats

# 使用自定义规则
java -jar target/just-sast-0.2.0.jar scan --jar app.jar --rules my-rules.yaml
```

支持的输入格式：
- `.jar`（含 Spring Boot fat jar，自动解析 `BOOT-INF/lib` 嵌套 jar）
- `.war`（自动解析 `WEB-INF/classes` + `WEB-INF/lib`）
- `.class` 目录

### 对比两次扫描

```bash
java -jar target/just-sast-0.2.0.jar diff old-output/ new-output/
```

输出新增链、消失链、变更链——适用于版本升级后检查新引入的 gadget 风险。

### 退出码

| 退出码 | 含义 |
|---|---|
| 0 | 扫描成功 |
| 2 | 参数错误 |
| 3 | 扫描内部错误 |

## 参数

| 参数 | 说明 | 默认 |
|---|---|---|
| `--jar <path>` | 目标 JAR/WAR/目录（必填） | — |
| `--deps <paths>` | 附加依赖，逗号分隔 | 无 |
| `--jdk-home <dir>` | 目标 JDK 主目录 | 运行时 JDK |
| `--output <dir>` | 输出目录 | `just-out` |
| `--rules <file>` | 自定义规则 YAML | 内置规则 |
| `--fast` | 跳过 JDK 全量加载 | 关 |
| `--stats` | 输出扫描统计到 stderr | 关 |

动态验证无需开关：扫描结束自动对高置信链执行子进程链级验证（有界预算，见下文「动态验证」）。

## 输出文件

扫描完成后在 `--output` 目录生成以下文件：

| 文件 | 说明 |
|---|---|
| `findings.csv` | 候选链汇总（置信度降序，含链路径、证据因子分解、模式标注） |
| `edges.csv` | 每条链的每跳明细（调用/字段流转/桥接类型） |
| `sinks.csv` | 每个 sink 的分析裁决（CHAIN / TRUNCATED / NO_PATH 等） |
| `chains.csv` | 全变体链（同入口/sink 的不同路径独立成行） |
| `calibrations.csv` | 被拒绝的链与拒绝理由（PASM / 类型流 / 序列化 / 约束矛盾 / 卫式等） |
| `findings.sarif` | SARIF 2.1.0 格式（可上传 GitHub Code Scanning） |
| `findings.json` | JSON 格式（机器消费） |
| `findings.html` | HTML 可视化报告（暗色主题，浏览器直接打开） |
| `findings.md` | Markdown 格式（适用于 PR comment） |

### findings.csv 字段

| 列 | 说明 |
|---|---|
| chain_id | 链唯一标识 |
| rule_id | 命中的 sink 规则 ID |
| category / severity | 风险类别与严重度 |
| confidence | FEASIBLE / DEGRADED(原因) / NOT_FEASIBLE |
| confidence_score | 证据分值 |
| entry_class / entry_method / entry_kind | 入口类、方法、类型（readObject / hashCode / proxyInvoke 等） |
| sink_class / sink_method | sink 类与方法 |
| chain_length / unresolved_hops | 链跳数与未解析跳数 |
| variant_count | 同入口/sink 的路径变体数 |
| patterns | 命中的已知 gadget 模式（CC1 / CC6 / Spring1 等） |
| path | 人读链路径（`A.hashCode --[field]--> B.method -> C.sink`） |
| evidence | 证据因子分解（逐项可核对计分） |
| verify | 动态验证结果（`CONFIRMED;...` 开头表示子进程验证确认） |

findings.csv 排序：子进程验证 **CONFIRMED 的链置顶**，其后按证据分值降序、链长升序。

### 动态验证（自动）

CALIBRATION 阶段末尾自动执行，无需参数：

1. 按证据分值选出验证候选，**同一入口类最多 2 条**（预算覆盖不同入口）；
2. 每条链起一个子 JVM 进程，沿链的 FIELD_FLOW 跳**构造完整对象图**（自底向上实例化 + 字段链接），再触发入口方法；
3. 三级判定：**SINK_TRIGGERED**（堆栈中真实出现 sink 类，最高置信）/ EXECUTED（链执行完成）/ PARTIAL_PATH（中途异常，链保留但降级）；
4. 预算有界（默认 20 条、4 路并行），对大语料只增加秒级开销。

## 规则系统

5 种规则类型，全部在 YAML 中声明，改规则零代码：

```yaml
rules:
  # sink：危险调用点
  - id: MY-SINK
    kind: sink
    category: CODE_EXEC
    severity: HIGH
    match:
      call: { owner: "java/lang/Runtime", name: "exec" }
    tainted: [{arg: 0}]

  # magic-entry：OIS 机制入口
  - id: MY-ENTRY
    kind: magic-entry
    entryKind: readObject
    match:
      method: { name: "readObject", descriptor: "(Ljava/io/ObjectInputStream;)V", access: private }
      class: { implements: "java/io/Serializable" }

  # source：替代反序列化框架入口（可附安全配置抑制）
  - id: MY-SOURCE
    kind: source
    bridge: deserialize
    match:
      call: { owner: "com/example/Framework", name: "load" }
    safe-config: { owner: "com/example/Framework", methods: [lock] }

  # model：声明式污点透传
  - id: MY-MODEL
    kind: model
    match:
      call: { owner: "java/util/Map", name: "put" }
    actions: { this: [arg1] }

  # chain-fragment：已知链片段（锚点类全在图中才生效）
  - id: MY-FRAGMENT
    kind: chain-fragment
    entryClass: "com/example/Entry"
    entryKind: readObject
    hops:
      - { class: "com/example/Mid", method: "process", field: "handler" }
    sinkOwner: "java/lang/reflect/Method"
    sinkName: "invoke"
```

## 效果

- 典型 Spring Boot 应用（~17000 类）：**约 50 秒**完成全量扫描；4 万+ 类大语料（如混合依赖加固包）亦可在默认堆下完成
- 输出包含完整链路径、逐跳明细、拒绝理由——每条链可追溯到触发规则
- 内置 Gleipner 基准（FSE 2025）：链覆盖 **106/122**，FP 块 22/47
- 支持 12 种反序列化框架 + 原生 ObjectInputStream
- 六种输出格式覆盖 CLI / CI/CD / IDE 场景
