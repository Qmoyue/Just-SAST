# Just

Just 是一个面向 Java JAR、WAR 和 class 目录的轻量级反序列化链扫描器。它从字节码中提取入口、字段、调用、控制流和 sink 事实，组合出可解释的候选链，并输出可供人工或工具继续处理的证据。

本仓库正在按 V3 重构。下述最简参数、报告布局和四态筛选是本轮目标契约；CLI/help、旧输出清理及筛选证据仍在迁移，具体可用选项须核对当前构建的 `scan --help`。文档更新不代表这些迁移已验收。

## 工作流

```text
JAR / WAR / class 目录 + 可选依赖 + 目标 JDK
                    │
                    ▼
             ASM 字节码前端
                    │  Just model
                    ▼
          CPG / CFG / 调用图 / 类型层次
                    │
                    ▼
          Blackboard
       规则、污点、框架语义、链组合与校准
                    │
                    ▼
       分析过程中在高成本/高噪声位置有界筛选
                    │
                    ▼
          同一规范报告快照
             report.md/report.json
```

## 主要功能

- 支持普通 JAR、嵌套 JAR、Spring Boot fat JAR、WAR、class 目录和显式依赖。
- 分析 Java 原生序列化入口及规则描述的替代反序列化框架入口。
- 建立调用、控制流、异常、继承、字段、数组、容器元素、反射、代理和 lambda 关系。
- 使用 forward/backward taint、对象图、source/sink 规则和链校准组合候选链。
- 每条链保留 `rule_id`、entry、sink、逐跳 edge、字段依赖、校准状态和完整性原因。
- 静态筛选只在高成本或高噪声位置求值 Just 自有的有限操作；它不加载、初始化、构造或调用目标代码。
- 只有完整有限域证明的矛盾可以剪枝；UNKNOWN、预算耗尽和缺依赖均保留静态候选并在报告中说明。
- 不使用 Job Object、SecurityManager、子 JVM、canary 或 payload 验证路径；资源风险由输入、图扩展、筛选和报告预算处理。
- 通过 `KnowledgeSource`、Blackboard、YAML 规则和 ServiceLoader 扩展分析语义。

## 构建与运行

主程序使用 JDK 17 和 Maven 3.6+。

```bash
mvn package -DskipTests
java -jar target/just-sast-0.2.0-shaded.jar scan \
  --jar app.jar \
  --jdk-home /path/to/jdk \
  --output just-out
```

补充依赖：

```bash
java -jar target/just-sast-0.2.0-shaded.jar scan \
  --jar app.jar \
  --deps lib/a.jar,lib/b.jar \
  --output just-out
```

常用参数：

| 参数 | 作用 |
| --- | --- |
| --jar | 目标 JAR、WAR 或 class 目录 |
| --mode | component（默认）或真实 application 入口分析 |
| --deps | 补充依赖路径 |
| --pom | 显式 Maven 根 POM，只解析模型 |
| --repository | 显式扩展 Maven 仓库，可重复 |
| --offline | 禁止联网，只使用明确输入和完整缓存 |
| --jdk-home | 目标 JDK；Java 8 使用 rt.jar，Java 9+ 使用实际 JRT/JDK 布局 |
| --output | 报告目录，默认 just-out |
| --rules | 自定义 YAML 规则 |
| --overwrite | 显式允许替换既有输出目录 |

no-verify、verify-budget、safe-exec、safe-real-sink 和 require-os-isolation 已从目标契约退役，现存接口残留需在本轮清理，不应重新加入主扫描接口。动态测试已经删除，静态筛选不通过参数切换。
stats、fast、baseline、suppressions 和 cache 只有在有独立消费者和测试后才作为高级工作流保留。

## 输出

```text
just-out/
├─ report.md       # 人和 agent 的主阅读入口
└─ report.json     # 与 report.md 同源的机器入口
```

旧 verification、payload、动态信任边界和运行时隔离字段不是稳定报告接口。迁移期间若旧代码仍产生这些文件，它们只能作为待清理残留，不能作为能力证明或下游输入。

静态筛选状态：

| 状态 | 含义 |
| --- | --- |
| PROVABLY_UNREACHABLE | 有完整局部证明，可阻断对应路径 |
| PROVEN_RETAINED | 有局部事实支持，保留路径但不证明完整链 |
| UNKNOWN | 事实不足，保留候选并披露缺口 |
| BUDGET_EXCEEDED | 有界求值停止，保留候选并披露完整性影响 |

UNKNOWN 和 BUDGET_EXCEEDED 不能作为拒绝理由，也不能被排名转换成 SAT。

## 扩展

新增静态语义时，实现 `KnowledgeSource`，声明 `phase()`、`priority()` 和 `interests()`，通过 Blackboard 交换事实和事件，并使用 ServiceLoader 注册。攻击面和调用模型优先写入 `src/main/resources/rules/default-rules.yaml`；知识源不直接调用其他知识源，也不按样本或包名添加分支。

## 验证

~~~powershell
mvn test
mvn package -DskipTests
~~~

架构约定见 [docs/architecture.md](docs/architecture.md)，需求契约见 [docs/requirements.md](docs/requirements.md)。

日常只做本地 commit，不 push/tag。最终发布由 Release 流程在同一提交上完成 Windows/JDK17
校验、目标 JDK 兼容 smoke、SHA256、许可证和可用版本核对。

许可证为 GPLv3，见 [LICENSE](LICENSE)。
