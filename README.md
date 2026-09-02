# Just

Just 是面向 Java JAR/WAR 的轻量级反序列化 gadget 链扫描器，目标是用较低的运行成本提供可解释、可复核的漏洞挖掘结果。

## 能力与架构

```text
JAR/WAR/class 目录
        ↓
JarReader + ASM 前端
        ↓
语义 CPG / CFG / 调用图 / 数据流索引
        ↓
Blackboard 知识源（规则、污点、框架语义、链组合）
        ↓
链校准与安全动态前缀验证
        ↓
CSV / JSON / SARIF / HTML / Markdown
```

- 支持普通 JAR、Spring Boot fat JAR、WAR、class 目录和外部依赖。
- 覆盖 Java 原生序列化及常见替代反序列化框架，分析字段流、回调、反射、代理、lambda、继承和 sink 可达性。
- 规则位于 `src/main/resources/rules/default-rules.yaml`；知识源通过 `KnowledgeSource`、Blackboard 和 ServiceLoader 扩展。
- 动态验证在独立子 JVM 中执行真实前置触发链；默认在精确 sink 边界由 canary 阻断。显式使用 `--safe-real-sink --require-os-isolation` 时，只有具备完整类型签名和固定安全参数的 target API/body 才会真实调用；命令只固定为 Just 自有 JDK 的 `-version`，文件只写 scratch，网络只允许固定 loopback，JNI 只加载 Just 自有且摘要/架构匹配的 fixture。该模式证明可调用性与完整返回，不证明 RCE。

## 构建与快速使用

需要 JDK 17+ 和 Maven 3.6+：

```bash
mvn package -DskipTests
java -jar target/just-sast-0.2.0.jar scan --jar app.jar --jdk-home /path/to/jdk
```

Windows + Jabba 示例：

```powershell
java -jar target\just-sast-0.2.0.jar scan `
  --jar app.jar `
  --jdk-home C:\Users\<user>\.jabba\jdk\<matching-jdk> `
  --output just-out
```

目标依赖不在工件内时：

```bash
java -jar target/just-sast-0.2.0.jar scan \
  --jar app.jar --deps lib/a.jar,lib/b.jar --output just-out
```

## CLI 参数

根命令：

| 参数 | 作用 |
| --- | --- |
| `-h`, `--help` | 显示帮助 |
| `-V`, `--version` | 显示版本 |

### `scan`

用法：`just-sast scan --jar=<jar|dir> [选项]`

| 参数 | 默认值 | 作用 |
| --- | --- | --- |
| `--jar=<jar|dir>` | 必填 | 目标 JAR、WAR 或 class 目录；支持 Spring Boot fat JAR |
| `--deps=<jar|dir,...>` | 无 | 补充依赖，多个路径以逗号分隔 |
| `--jdk-home=<dir>` | 当前运行时 JDK | 指定目标 JDK/JRE；Java 8 使用 `rt.jar`，Java 9+ 使用 `jrt-fs` |
| `--output=<dir>` | `just-out` | 报告输出目录 |
| `--rules=<file>` | 内置规则 | 指定自定义规则 YAML |
| `--verify-budget=<N>` | `20` | 动态验证候选链数量预算；同一入口类最多验证 2 条 |
| `--stats` | 关闭 | 将阶段统计写入 stderr |
| `--fast` | 关闭 | 不加载目标 JDK 运行库全量；可能导致链不完整 |
| `--no-verify` | 关闭 | 关闭子进程动态验证，只保留静态结果 |

完整审计建议保留默认扫描，不使用 `--fast` 或 `--no-verify`。退出码为：`0` 成功，`2` 参数/输入错误，`3` 扫描内部错误。

### `diff`

```bash
java -jar target/just-sast-0.2.0.jar diff <old-dir> <new-dir>
```

| 参数 | 作用 |
| --- | --- |
| `<old-dir>` | 旧扫描输出目录 |
| `<new-dir>` | 新扫描输出目录 |

`diff` 按 `rule_id + 入口 + sink` 对比链的新增、消失、变化和不变状态。

## 输出与动态状态

```text
just-out/
├─ index.md
├─ findings/       # 主发现及 CSV/JSON/SARIF/HTML/Markdown
├─ verification/   # 动态汇总与 payload.md/json
├─ evidence/       # 链、边、sink 和校准证据
└─ meta/           # 扫描元数据与构造计划
```

- `SINK_BLOCKED`：真实前置链抵达精确 sink 边界，canary 已阻断 sink 方法体。
- `SINK_EXECUTED_SAFE`：精确 target API 或 application body 以固定安全参数正常返回，并带 `sink_distorted=true`；不是恶意参数可利用性证明。
- `JNI_EXECUTED_SAFE`：Just 自有、固定摘要且匹配当前平台架构的 native fixture 完成 load 与 native callback；不是 target native 或 RCE 证明。
- `CONCRETE_REACHED`：抵达安全观察点，但尚未观察到精确 sink 边界。
- `PARTIAL`：只完成部分构造或触发，不能据此否定静态候选。
- `UNTESTABLE`：缺类、JDK、权限或运行时能力导致无法验证。

`payload.md/json` 是人和 agent 可读的安全构造计划与证据视图，不是可执行 exploit。JVM 权限门不等价于 OS 沙箱；处理不可信工件时仍应使用低权限账户、无网络环境及容器或虚拟机隔离。

## 外部回归

外部 evaluator、CTF-like JAR 和其他外部语料只作为本地校准输入，不进入生产规则，也不修改 truth/WP。回归输出、题目名称、绝对路径和中间产物不随仓库发布；请以 `docs/architecture.md` 与 `docs/requirements.md` 中的协议和验收口径为准。

## 开发

```bash
mvn test
mvn package -DskipTests
```

架构与安全边界见 [docs/architecture.md](docs/architecture.md)，需求与验收见 [docs/requirements.md](docs/requirements.md)，协作规范见 [AGENTS.md](AGENTS.md)。许可证为 GPLv3，见 [LICENSE](LICENSE)。
