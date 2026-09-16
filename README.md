# Just

Just 是一个面向 Java JAR、WAR、Spring Boot fat JAR 和 class 目录的静态反序列化链分析器。它从真实字节码、依赖和目标 JDK 中提取可追溯事实，帮助审计者快速回答：

- 哪个入口接收了输入？
- 反序列化、callback、字段和控制条件如何连接？
- 哪些依赖、版本、配置和 JDK 条件成立？
- 静态证据能到达哪个最终影响？
- 哪些部分仍然未知或受分析边界限制？

## 项目边界

Just 聚焦组件 gadget 链和应用暴露链，不是通用漏洞扫描平台。

扫描是静态的：Just 不启动目标应用，不加载或初始化目标类，不构造目标对象，不调用目标方法，不反序列化攻击流，不访问危险终点，也不生成可投递 payload。结果是可审计的静态证据，不是运行时利用确认。

## 快速开始

构建需要 JDK 17 和 Maven 3.6 或更高版本：

~~~bash
mvn -B test
mvn -B package -DskipTests
~~~

扫描组件：

~~~bash
java -jar target/just-sast-0.2.0-shaded.jar scan \
  --jar component.jar \
  --jdk-home /path/to/target-jdk \
  --output just-out
~~~

扫描应用并使用准确的 Maven 依赖：

~~~bash
java -jar target/just-sast-0.2.0-shaded.jar scan \
  --jar app.jar \
  --mode application \
  --pom pom.xml \
  --jdk-home /path/to/target-jdk \
  --output just-out
~~~

使用已准备好的依赖进行离线扫描：

~~~bash
java -jar target/just-sast-0.2.0-shaded.jar scan \
  --jar app.jar \
  --mode application \
  --deps lib \
  --pom pom.xml \
  --offline \
  --jdk-home /path/to/target-jdk \
  --output just-out
~~~

## 扫描模式

| 模式 | 起点 | 导出条件 |
| --- | --- | --- |
| component（默认） | 机制触发点 → gadget → 最终影响 | 触发、对象、控制、依赖和终点证据可解释 |
| application | 真实应用入口 → site → bridge/依赖/JDK → 最终影响 | 必须有 entry、site、EntryChainJoinEvidence、必要 BridgeEvidence、对象/控制关系和完整 terminal |

组件中存在 gadget 不等于应用暴露。类名共现、classpath 共存和调用图共现不能替代值流、对象身份或控制关系。

## 输出

一次扫描的公开入口只有两个：

~~~text
just-out/
├─ report.json       # agent 的机器可读主报告，包含全部候选和重要变体
├─ report.md         # 人的主报告，结论、主链和 Gadget 图
├─ evidence/         # 可选的静态逐跳、依赖和桥证据
└─ meta/             # provenance、digest、诊断、run.json 和 transaction.json
~~~

默认不生成空 findings/、重复的 index.md、verification/ 或 payload 文件。CSV、SARIF 等格式如果有明确消费者，只作为 evidence/ 下的附加导出，不替代两个主报告。

report.json 与 report.md 来自同一个冻结快照。JSON 不截断候选；Markdown 先展示主链和重要变体，详细位置、descriptor、字段关系、预算和 provenance 可以继续在 JSON/evidence 中追溯。

主链图采用稳定的文本形式。下面是阅读格式示意；具体 entry/site、节点角色和证据以本次 report.json 为准：

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

## 结果状态

公开 JSON 使用相互独立的状态轴：

| 字段 | 含义 |
| --- | --- |
| outcome | 本次是否有可供审阅的结果，或发生失败/参数/运行库错误 |
| coverage | 静态覆盖是否完整、受边界限制或未知 |
| chain completeness | 单条链的证据是否完整 |
| feasibility | 单条链的结构/约束可行性 |

旧内部状态 PARTIAL 表示静态分析受到预算、未知分支、解析诊断、JDK 近似或搜索边界影响，不表示动态测试。未知和预算候选会保留；只有完整的 PROVABLY_UNREACHABLE 矛盾可以剪枝。没有发现链也不等于制品安全。

## demo 的阅读口径

对 benchmark/demo/demo.jar，制品内可静态重建的最短主链是：

~~~text
DogController#importDogs
  → ObjectInputStream#readObject
  → Dog#hashCode
  → DogModel#wagTail
  → Method#invoke
  → TemplatesImpl#newTransformer
~~~

WP 中外部恶意类的 Runtime.getRuntime().exec 不属于 demo.jar 字节码；另一个手工构造对象图中的 invoke → Runtime.exec 也不能凭应用 JAR 自动证明。只有输入制品实际包含 java/lang/Runtime#exec 调用时，Just 才将它作为静态 sink 报告。外部 payload 后果可以作为边界说明，但不会冒充制品内链或运行时确认。

## 参数

| 参数 | 作用 |
| --- | --- |
| --jar | 输入 JAR、WAR 或 class 目录 |
| --mode | component（默认）或 application |
| --deps | 附加依赖 JAR 或目录，逗号分隔 |
| --pom | 显式 Maven 根 POM |
| --repository | 显式 Maven 仓库，可重复 |
| --offline | 禁止网络，只使用显式输入和完整缓存 |
| --jdk-home | 目标 JDK/JRE，用于读取目标字节码与运行库 |
| --output | 输出目录 |
| --rules | 自定义规则 YAML |
| --overwrite | 显式替换既有输出 |

stats、fast、baseline、suppressions 和 cache 是高级工作流选项；它们不能改变静态安全边界，也不能用少报结果换取速度。参数错误、缺依赖、缓存损坏和内部错误必须显式失败。

## 开发与发布

~~~bash
mvn -B test
mvn -B package -DskipTests
java -jar target/just-sast-0.2.0-shaded.jar --help
~~~

tools/ 和 benchmark/ 只用于开发验证、真实制品和基准，不属于用户运行时或发布 launcher 的隐式依赖。发布资产必须包含可用 shaded JAR、SHA-256、LICENSE 和第三方声明，并由同一提交的 CI/Release 流程验证。

详细设计见 [docs/architecture.md](docs/architecture.md)，产品契约见 [docs/requirements.md](docs/requirements.md)。

许可证为 GPLv3，见 [LICENSE](LICENSE)。
