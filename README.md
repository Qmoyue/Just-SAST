# Just

Just 是一个面向 Java JAR、WAR、Spring Boot fat JAR 和 class 目录的静态反序列化链分析器。它从字节码、依赖和目标 JDK 中提取可验证的入口、对象关系、控制条件与最终影响，帮助人和 agent 判断一条 gadget chain 是否真实存在、是否由应用暴露。

Just 不运行目标应用，不初始化或构造目标类，不执行反序列化流、反射调用或 payload，也不生成可投递的攻击字节流。

## 快速使用

运行环境是 JDK 17。目标制品可以使用 `--jdk-home` 指定对应的 JDK/JRE 字节码来源。

从 [GitHub Releases](https://github.com/Qmoyue/Just-SAST/releases) 下载 JAR：

```bash
curl -L -o just-sast-0.2.1-shaded.jar \
  https://github.com/Qmoyue/Just-SAST/releases/download/v0.2.1/just-sast-0.2.1-shaded.jar
java -jar just-sast-0.2.1-shaded.jar --help
```

分析独立组件：

```bash
java -jar just-sast-0.2.1-shaded.jar scan \
  --jar component.jar \
  --mode component \
  --jdk-home /path/to/target-jdk \
  --output just-out
```

从真实应用入口分析，并使用 Maven POM 补齐应用依赖：

```bash
java -jar just-sast-0.2.1-shaded.jar scan \
  --jar app.jar \
  --mode application \
  --pom pom.xml \
  --jdk-home /path/to/target-jdk \
  --output just-out
```

需要离线分析时，显式提供依赖目录并追加 `--offline`：

```bash
java -jar just-sast-0.2.1-shaded.jar scan \
  --jar app.jar --mode application --pom pom.xml --deps lib \
  --offline --jdk-home /path/to/target-jdk --output just-out
```

一次扫描生成：

```text
just-out/
├── report.json       # 完整机器可读结果，适合 agent 和工具消费
├── report.md         # 人类可读摘要、结论和 Gadget 图
├── evidence/         # 逐跳、依赖和应用连接证据
└── meta/             # 输入摘要、来源和分析元数据
```

不会生成空的 `findings/` 目录，也不会生成重复的索引报告、动态测试或 payload 文件。

## Just 的优点

- **静态且安全**：分析过程不执行目标代码，适合在 CI、代码审计和离线环境中使用。
- **区分组件能力与应用暴露**：`component` 模式分析独立 gadget 机制；`application` 模式必须从真实应用入口连接到依赖/JDK 中的完整链，避免把“类在 classpath 中”误报成应用漏洞。
- **结论可追溯**：每个结论关联入口、callback、bridge、terminal、对象/控制关系以及输入依赖和 JDK 来源。
- **同时服务人和 agent**：`report.json` 保留完整候选和结构化证据；`report.md` 用稳定的文本图快速展示主链、阻断点和边界。
- **保守表达不确定性**：未知条件、预算边界和不完整静态证明会明确标记为 `UNKNOWN` 或 `PARTIAL`，不会被伪装成运行时验证结果。

## 架构

```text
JAR/WAR/class  依赖/POM  目标 JDK
        │          │          │
        └──────────┴──────────┘
                   ▼
       输入解析与 provenance 记录
                   ▼
          ASM 字节码前端
                   ▼
        稳定的 typed facts 模型
   (入口、callback、对象、控制、bridge、terminal)
                   ▼
          共享静态链求解器
       ┌───────────┴───────────┐
       ▼                       ▼
 component：机制触发点      application：真实入口
       │                       │
       └───────────┬───────────┘
                   ▼
        冻结结果与同源报告生成
             ├── report.json
             ├── report.md
             ├── evidence/
             └── meta/
```

ASM 只负责把字节码转换为事实；后续求解器不依赖题名、路径或 benchmark 名称。组件模式的发现不能直接称为应用漏洞，应用模式还必须证明入口、站点、必要连接证据、对象/控制条件和完整 terminal。

报告中的 Gadget 图使用稳定节点和有类型的边，示意如下：

```text
ENTRY     DogController#importDogs
   │
   ▼
CALL      ObjectInputStream#readObject
   │
   ▼
CALL      Dog#hashCode → DogModel#wagTail
   │
   ▼
BOUNDARY  Method#invoke
   │
   ▼
TERMINAL  TemplatesImpl#newTransformer
```

当反射目标无法从输入字节码中静态确定时，报告会保留 `Method#invoke` 这样的能力边界，不把未证明的后续行为写成 terminal。

## 许可证

Just 使用 GPLv3-only，详见 [LICENSE](LICENSE) 和 [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)。
