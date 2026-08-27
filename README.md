# Just

轻量字节码 SAST，挖掘 Java 反序列化 gadget 利用链。以 GPLv3 开源。

覆盖原生 ObjectInputStream 与 12+ 种替代反序列化框架，内置 177 条规则，单 JAR 交付，零外部服务。

## 设计

- **轻量**：运行时依赖仅 ASM / picocli / SnakeYAML，构建产物约 1.3 MB，`java -jar` 直接运行
- **双引擎交叉**：前向污点不动点（GadgetInspector 式方法摘要）+ 反向按需回溯（入口距离导向调度），互为补充
- **可扩展**：黑板架构，12 个知识源经 ServiceLoader 插件化注册，互不直接调用；新增分析能力零改动调度层
- **规则即数据**：sink / source / magic-entry / model / chain-fragment 五种规则类型全部在 YAML 声明，新增攻击面零代码
- **完整链输出**：反序列化源宿主（OIS / Kryo / fastjson 等 13 框架入口）经容器触发桥直接组装到 gadget 链——扫描输出即"入口方法 → 框架机制 → gadget → 危险 sink"的完整攻击路径，SafeConfig 按实参求值不误报已加固目标
- **确定性**：同一输入在预算内多次扫描输出一致（事实替换按全序取最小）
- **动静结合**：静态链自动进入子进程链级动态验证——构造完整对象图、触发入口方法、
  sink canary 插桩（ASM 注入门卫调用，入口帧归因）主动判定 sink 是否真实到达；
  命中的 sink 方法体不执行（exec/defineClass 类危险副作用被解除）
- **跨版本保真**：`--jdk-home` 真实挂载目标 JDK 镜像（Java 8 读 rt.jar，Java 9+ 走 jrt-fs），分析语义与目标运行时一致

## 安装

```bash
mvn package -DskipTests
```

构建产物：`target/just-sast-0.2.0.jar`（shaded fat JAR，可直接 `java -jar` 运行）。

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

# 关闭子进程动态验证（CI / 不可执行环境）
java -jar target/just-sast-0.2.0.jar scan --jar app.jar --no-verify

# 使用自定义规则
java -jar target/just-sast-0.2.0.jar scan --jar app.jar --rules my-rules.yaml

# 输出扫描统计
java -jar target/just-sast-0.2.0.jar scan --jar app.jar --stats
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
| `--no-verify` | 关闭子进程链级动态验证 | 关 |
| `--verify-budget <N>` | 动态验证链数预算 | 20 |
| `--stats` | 输出扫描统计到 stderr | 关 |

动态验证默认开启：扫描结束自动对高置信链执行子进程验证（有界预算，同一入口类最多 2 条、共 20 条、4 路并行）。注意验证子进程会以当前用户权限真实执行入口方法，扫描不可信工件时建议在隔离环境运行或使用 `--no-verify`。

## 输出文件

| 文件 | 说明 |
|---|---|
| `findings.csv` | 链汇总（置信度降序，含链路径、证据因子分解、模式标注） |
| `edges.csv` | 每条链的逐跳明细（调用 / 字段流转 / 桥接类型） |
| `sinks.csv` | 每个 sink 的裁决（CHAIN / TRUNCATED / NO_PATH 等） |
| `chains.csv` | 全变体链（同入口/sink 的不同路径独立成行） |
| `calibrations.csv` | 被拒绝的链与拒绝理由 |
| `findings.sarif` | SARIF 2.1.0（含入口方法行号，可上传 GitHub Code Scanning） |
| `findings.json` | JSON（机器消费，含 path / verify 字段） |
| `findings.html` | HTML 可视化报告 |
| `findings.md` | Markdown（适用于 PR comment） |

findings.csv 排序：动态验证 CONFIRMED 的链置顶，其后按证据分值降序、链长升序。

### 动态验证

扫描结束自动执行，无需参数：

1. 按证据分值选出验证候选，同一入口类最多 2 条——预算优先覆盖入口多样性；
2. 每条链起一个子 JVM 进程，沿链的字段流转跳构造完整对象图（自底向上反射实例化 + 字段链接），再触发入口方法；
3. 三级判定：**SINK_TRIGGERED**（堆栈帧中 sink 类名与方法名全等匹配——真到达 sink）/ EXECUTED（入口方法真实调用且正常返回）/ PARTIAL_PATH（中途异常，链保留但降级）；
4. 子进程 classpath 含目标 jar 与全部 `--deps`；先 waitFor 超时再读输出。

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

内置规则构成：94 sink（JNDI / XXE / SSRF / 命令注入 / 文件读写 / 反射 / 表达式引擎 / 模板 / SQL）+ 42 source（Kryo / SnakeYAML / XStream / Hessian 系（含 dubbo 分叉）/ Fastjson / Gson / Jackson / BlazeDS AMF / Burlap / Castor / JsonIO / JYAML / Red5 / Coherence / Jabsorb 等）+ 21 model（JDK 集合与字符串污点透传）+ 14 magic-entry（序列化机制回调全类）+ 6 chain-fragment（经典公开链）。

规则装载校验：未知 kind、缺失 id、重复 id、缺失 match 均报错。

## 跑分

Gleipner 基准（FSE 2025）：

- 链覆盖 **106/122**，误报块 **22/47**（evaluator 块计数 TP=148 / FP=22）
- 能力面：multipath 10/10、depth 18/20、polymorphism 20/20
- 9 语料回归全通过；典型 Spring Boot 应用（~11000 类）60-90 秒完成全量扫描

## 开发

```bash
mvn test        # 单元 / 契约 / 端到端回归（70 项）
```

分层规范见 [AGENTS.md](AGENTS.md)，架构细节见 [docs/architecture.md](docs/architecture.md)，需求与验收见 [docs/requirements.md](docs/requirements.md)。

许可证：GPLv3（见 [LICENSE](LICENSE)），第三方依赖声明见 [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)。
