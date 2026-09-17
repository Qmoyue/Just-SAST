# Just

Just 是一个面向 Java 字节码的静态反序列化链分析器。它分析 JAR、WAR、Spring Boot fat JAR 和 class 目录，结合目标 JDK、依赖和应用入口，输出可追溯的 gadget 链与应用暴露链证据。

Just 只进行静态分析，不启动目标应用，不初始化或构造目标类，不执行反射调用、反序列化流或 payload，也不生成可投递攻击字节流。

## 能力概览

- 从真实字节码中识别反序列化入口、callback、对象关系、控制条件和最终影响。
- 分析独立组件 gadget 链，或从真实应用入口追踪到依赖/JDK 中的链。
- 支持 JAR、WAR、嵌套归档、多版本归档和 class 目录。
- 使用显式依赖、Maven POM、本地缓存和目标 JDK 建立可复核的输入 provenance。
- 以 report.json 和 report.md 作为两个主报告入口，并在报告中展示 typed Gadget graph。

## 安装

从 [GitHub Releases](https://github.com/Qmoyue/Just-SAST/releases) 下载 shaded JAR。运行时需要 JDK 17。

~~~bash
java -jar just-sast-<version>-shaded.jar --help
~~~

从源码构建：

~~~bash
mvn -B test
mvn -B package -DskipTests
~~~

生成的 launcher 位于 target/just-sast-<version>-shaded.jar。

## 快速开始

### 组件模式

组件模式从机制触发点开始分析，不代表宿主应用已经暴露该链：

~~~bash
java -jar just-sast-<version>-shaded.jar scan \
  --jar component.jar \
  --jdk-home /path/to/target-jdk \
  --output just-out
~~~

### 应用模式

应用模式从真实应用入口开始分析，需要提供准确的 Maven POM 或依赖：

~~~bash
java -jar just-sast-<version>-shaded.jar scan \
  --jar app.jar \
  --mode application \
  --pom pom.xml \
  --jdk-home /path/to/target-jdk \
  --output just-out
~~~

使用显式依赖进行离线分析：

~~~bash
java -jar just-sast-<version>-shaded.jar scan \
  --jar app.jar \
  --mode application \
  --deps lib \
  --pom pom.xml \
  --offline \
  --jdk-home /path/to/target-jdk \
  --output just-out
~~~

## 分析模式

| 模式 | 分析起点 | 结论要求 |
| --- | --- | --- |
| component | 机制触发点 → gadget → terminal | 触发、对象关系、控制条件、依赖/JDK 条件和 terminal 有静态证据 |
| application | 真实入口 → site → bridge/依赖/JDK → terminal | 额外要求 entry、site、入口与链的连接证据、必要 bridge、对象/控制关系和完整 terminal |

类名共现、classpath 共存或调用图共现不能替代对象关系、值流和控制条件。组件模式中的 gadget 不能直接称为应用漏洞。

## 输出

output 指向的目录包含：

~~~text
just-out/
├── report.json       # 完整的机器可读报告
├── report.md         # 面向人的摘要和 Gadget 图
├── evidence/         # 逐跳、依赖、bridge 和可选格式证据
└── meta/             # 输入 provenance、digest、诊断和事务元数据
~~~

默认不创建空的 findings/ 目录，不生成重复的索引主报告，也不生成 verification、payload 或动态测试文件。

report.json 保留全部候选和重要变体，适合 agent 或其他程序消费。report.md 先展示结论、主链、阻断点和能力边界，适合人工快速阅读。两个报告来自同一个冻结结果。

报告中的 Gadget 图使用稳定的文本节点和 typed edge，例如：

~~~text
ENTRY  DogController#importDogs
  │
  ▼
STEP   ObjectInputStream#readObject
  │
  ▼
STEP   Dog#hashCode → DogModel#wagTail
  │
  ▼
BOUNDARY  Method#invoke
  │
  ▼
TERMINAL  TemplatesImpl#newTransformer
~~~

如果反射目标无法由输入字节码静态确定，Just 会保留 Method.invoke 这样的 capability boundary，不会把未证明的后续行为当成 terminal。

## 状态含义

报告将不同问题分开表示：

- outcome：本次是否产生可审阅结果，或发生参数、输入、依赖或内部错误。
- coverage：静态覆盖是否完整、受边界限制或未知。
- chain completeness：单条链的证据是否完整。
- feasibility：单条链的结构和约束是否可行。

PARTIAL 只表示静态覆盖或单条链证明受到预算、未知分支、解析诊断、JDK 近似或搜索边界影响，不表示动态测试结果。未知和预算候选会被保留。

## 架构概览

~~~text
输入制品 / POM / 依赖 / 目标 JDK
              │
              ▼
      字节码与 provenance frontend
              │
              ▼
      类型、字段、控制和对象事实模型
              │
              ▼
       component/application 求解器
              │
              ▼
      冻结结果 → report.json / report.md
              │
              ▼
        evidence/ 与 meta/ 追溯文件
~~~

ASM 只负责前端解析。后续模块消费稳定的 typed facts；入口、callback、bridge、terminal、对象关系和控制条件是数据，求解和组合逻辑不依赖题目名称或路径。

## 静态安全边界

Just 不会：

- 加载、初始化或构造目标类和目标对象；
- 反射调用目标方法或执行目标 callback；
- 反序列化攻击流、启动目标进程或访问目标 sink；
- 执行目标构建插件、外部 helper、native 代码或通用解释器；
- 生成 payload、投递字节流或输出运行时利用确认。

offline 会禁止网络请求，只使用显式输入和完整缓存。依赖缺失、版本不确定、缓存损坏和解析错误会在结果中明确披露或使扫描失败。

## Demo 链口径

对于包含 DogController#importDogs 的 demo，静态主链可以表示为：

~~~text
DogController#importDogs
  → ObjectInputStream#readObject
  → Dog#hashCode
  → DogModel#wagTail
  → Method#invoke
  → TemplatesImpl#newTransformer
~~~

WP 中外部恶意类的 Runtime.getRuntime().exec 不属于该 demo 应用字节码。只有输入制品本身包含到 java/lang/Runtime#exec 的静态调用时，Just 才会报告该 terminal；外部 payload 后果不会被冒充为应用内部链。

## 常用参数

| 参数 | 作用 |
| --- | --- |
| --jar | 输入 JAR、WAR 或 class 目录 |
| --mode | component（默认）或 application |
| --deps | 附加依赖 JAR 或目录，逗号分隔 |
| --pom | 显式 Maven 根 POM |
| --repository | 显式 Maven 仓库，可重复 |
| --offline | 禁止联网，只使用显式输入和缓存 |
| --jdk-home | 目标 JDK/JRE 字节码来源 |
| --output | 报告输出目录 |
| --rules | 自定义规则 YAML |
| --overwrite | 显式替换已有输出 |

更多设计约束见 [产品要求](docs/requirements.md) 和 [架构说明](docs/architecture.md)。

## 许可证

Just 使用 GPLv3-only，详见 [LICENSE](LICENSE) 和 [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)。
