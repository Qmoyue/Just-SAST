# Just

Just 是面向 Java JAR、WAR 和 class 目录的轻量级静态反序列化链分析器。它从字节码、依赖和目标 JDK 中提取可追溯事实，组合出带有入口、条件、逐跳依据和最终影响的候选链，辅助 Apache 组件、Java 应用和 CTF 制品审计。

## 特性

- 支持普通 JAR、WAR、Spring Boot fat JAR、嵌套归档、class 目录和显式依赖。
- 提供 `component` 与 `application` 两种分析模式，共享静态求解器和证据模型。
- 建模调用、控制流、字段、类型、异常、反射、代理、lambda、对象关系和跨协议桥。
- 支持 POM 依赖解析、精确制品来源、SHA-256、目标 JDK 和运行条件记录。
- 在高成本或高噪声位置执行有界静态筛选，保留 UNKNOWN 与预算信息。
- 生成同一快照的 Markdown、JSON、索引、证据和元数据，便于人工阅读与自动消费。
- 扫描过程不加载、初始化、构造、调用或反序列化目标代码，不生成可投递 payload。

## 快速开始

构建需要 JDK 17 和 Maven 3.6+：

```bash
mvn -B test
mvn -B package -DskipTests
```

扫描一个组件或应用：

```bash
java -jar target/just-sast-0.2.0-shaded.jar scan \
  --jar app.jar \
  --jdk-home /path/to/target-jdk \
  --output just-out
```

应用入口分析、离线依赖和显式依赖示例：

```bash
java -jar target/just-sast-0.2.0-shaded.jar scan \
  --jar app.jar \
  --mode application \
  --deps lib/a.jar,lib/b.jar \
  --offline \
  --jdk-home /path/to/target-jdk \
  --output just-out
```

## 扫描参数

| 参数 | 作用 |
| --- | --- |
| `--jar` | 输入 JAR、WAR 或 class 目录 |
| `--mode` | `component`（默认）或 `application` |
| `--deps` | 逗号分隔的依赖 JAR 或目录 |
| `--pom` | 显式 Maven 根 POM |
| `--repository` | 显式 Maven 仓库，可重复使用 |
| `--offline` | 只使用输入与完整本地缓存，禁止联网 |
| `--jdk-home` | 目标 JDK；用于解析目标字节码与运行库 |
| `--output` | 输出目录 |
| `--rules` | 自定义 YAML 规则 |
| `--overwrite` | 允许覆盖既有输出目录 |
| `--stats` | 输出扫描统计与分段耗时 |
| `--fast` | 减少目标 JDK 库加载，结果可能不完整 |
| `--baseline` | 标记相对于基线的链变化 |
| `--suppressions` | 按链身份、SHA-256 或规则标记抑制项 |
| `--cache` | 使用完整报告增量缓存 |

`--repository` 需要配合 `--pom`；`--cache` 与 `--baseline`、`--suppressions` 互斥。依赖解析失败、缓存不完整、输出冲突和内部错误会明确返回失败状态。

## 分析模式

- `component` 从机制触发点开始，分析 gadget、对象关系、控制条件、依赖条件和最终影响。结果可以没有应用入口。
- `application` 要求真实应用入口、可控输入、站点连接、必要桥接证据、对象/控制条件以及完整终点。组件中存在 gadget 不等于应用暴露。

两种模式都只使用静态证据。lookup、connect、构造器和解码等位置作为桥继续求解，只有抵达可解释的最终影响才形成完整链。

## 输出

```text
just-out/
├─ report.md       # 人和 agent 的主阅读入口
├─ report.json     # 机器可读的同源报告
├─ index.md        # 摘要、依赖来源和计时
├─ evidence/       # 依赖与可追溯证据
└─ meta/            # finding、输入摘要、应用证据和运行元数据
```

筛选状态包括：

| 状态 | 含义 |
| --- | --- |
| `PROVABLY_UNREACHABLE` | 局部有限域存在完整矛盾证明，可阻断该路径 |
| `PROVEN_RETAINED` | 局部事实支持路径，不能单独证明完整链 |
| `UNKNOWN` | 信息不足，候选保留并披露缺口 |
| `BUDGET_EXCEEDED` | 有界求值达到限制，候选保留并披露完整性影响 |

报告不输出 `RCE_CONFIRMED` 或可投递攻击字节流。`report.md`、`report.json`、`index.md`、`evidence/` 和 `meta/` 来自同一冻结快照。

## 开发

```bash
mvn -B test
mvn -B package -DskipTests
java -jar target/just-sast-0.2.0-shaded.jar --help
```

`tools/` 与 `benchmark/` 用于开发、验证和基准测试，不是用户运行时依赖，也不属于发布 launcher 的运行入口。用户运行只需要构建产物及其明确的输入、依赖和目标 JDK。

架构说明见 [docs/architecture.md](docs/architecture.md)，产品要求见 [docs/requirements.md](docs/requirements.md)。

许可证为 GPLv3，见 [LICENSE](LICENSE)。
